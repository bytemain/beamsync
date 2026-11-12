import http from "node:http";
import path from "node:path";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, stat, unlink } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { WebSocketServer, type WebSocket } from "ws";
import {
  bytesToHex,
  constantTimeEqual,
  MAX_SIGNALING_MESSAGE_BYTES,
  randomBytes,
  utf8Bytes,
  verifyEdgeRelayHeartbeat,
  type CreateManagedLeaseRequest,
  type EdgeRelayHeartbeatPayload,
  type EdgeRelayNodeInfo,
} from "@beamsync/protocol";
import {
  CoordinatorEngine,
  R2PresignedStorageDriver,
  SignedHttpStorageDriver,
  signHttpObjectToken,
  type PackStorageDriver,
  type R2StorageConfig,
} from "@beamsync/coordinator";
import { FileWalPersistence } from "./persistence.js";
import { startUdpStunServer, type RunningStunServer } from "./stunServer.js";

export interface ObjectStoreHookEvent {
  method: "PUT" | "GET";
  storageKey: string;
  sizeBytes: number;
  timestampMs: number;
}

export interface BeamSyncServerConfig {
  port?: number;
  host?: string;
  publicUrl?: string; // e.g. https://sync.example.com
  dataDir?: string;
  stunPort?: number | null; // null disables built-in UDP STUN; 0 picks ephemeral port
  publicStunHost?: string;
  extraStunServers?: string[];
  relayAuthSecret?: string;
  /** Grace period before a peer without a signaling socket is reported as PEER_LOST (default 45 s). */
  peerLossGraceMs?: number;
  initialEdgeRelays?: EdgeRelayNodeInfo[];
  /**
   * When set, creating or joining a pairing and creating a managed lease require
   * `Authorization: Bearer <apiToken>`. Without it those endpoints are open to anyone who
   * can reach the server.
   */
  apiToken?: string;
  /** Sessions held at once, pending pairings included (default 5000). */
  maxSessions?: number;
  /** Total memory for un-acknowledged signaling messages kept for resume (default 512 MiB). */
  maxReplayLogBytesTotal?: number;
  r2?: R2StorageConfig;
  builtinPutDelayMs?: number; // Test hook to observe concurrent upload/download overlap
  onObjectStoreEvent?: (event: ObjectStoreHookEvent) => void;
}

export interface RunningBeamSyncServer {
  httpUrl: string;
  wsBaseUrl: string;
  port: number;
  stunPort: number | null;
  stunUrl: string | null;
  coordinator: CoordinatorEngine;
  close(): Promise<void>;
}

export async function startBeamSyncServer(
  config: BeamSyncServerConfig = {},
): Promise<RunningBeamSyncServer> {
  const host = config.host ?? "0.0.0.0";
  const requestedPort = config.port ?? 8787;
  const dataDir = path.resolve(config.dataDir ?? "./data");
  const packsDir = path.join(dataDir, "packs");
  await mkdir(packsDir, { recursive: true });

  let stunServer: RunningStunServer | null = null;
  if (config.stunPort !== null) {
    stunServer = await startUdpStunServer(config.stunPort ?? 3478, host);
  }

  const signingSecret = randomBytes(32);
  let builtinDriver: SignedHttpStorageDriver | null = null;
  let storageDriver: PackStorageDriver;

  if (config.r2) {
    storageDriver = new R2PresignedStorageDriver(config.r2);
  } else {
    builtinDriver = new SignedHttpStorageDriver({
      publicBaseUrl: config.publicUrl ?? `http://127.0.0.1:${requestedPort}`,
      signingSecret,
      onDeleteObjects: async (keys) => {
        await Promise.allSettled(
          keys.map(async (k) => {
            const diskPath = safePackDiskPath(packsDir, k);
            await unlink(diskPath);
          }),
        );
      },
    });
    storageDriver = builtinDriver;
  }

  const stunHost =
    config.publicStunHost ??
    (config.publicUrl ? new URL(config.publicUrl).hostname : "127.0.0.1");
  const stunServers: string[] = [];
  if (stunServer) {
    stunServers.push(`stun:${stunHost}:${stunServer.port}`);
  }
  if (config.extraStunServers) {
    stunServers.push(...config.extraStunServers);
  }
  if (stunServers.length === 0) {
    stunServers.push("stun:stun.cloudflare.com:3478");
  }

  const relayAuthSecret =
    config.relayAuthSecret?.trim() || bytesToHex(randomBytes(32));
  const persistence = new FileWalPersistence(dataDir);
  const coordinator = new CoordinatorEngine({
    storageDriver,
    stunServers,
    relayAuthSecret,
    initialEdgeRelays: config.initialEdgeRelays,
    peerLossGraceMs: config.peerLossGraceMs,
    persistence,
    maxSessions: config.maxSessions,
    maxReplayLogBytesTotal: config.maxReplayLogBytesTotal,
  });
  await coordinator.init();

  const server = http.createServer(async (req, res) => {
    try {
      const reqUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const method = req.method ?? "GET";

      if (method === "GET" && reqUrl.pathname === "/healthz") {
        sendJson(res, 200, {
          ok: true,
          service: "beamsync-server",
          version: "0.1.0",
          ...coordinator.getStats(),
        });
        return;
      }

      if (method === "GET" && reqUrl.pathname === "/v1/edge-relays") {
        sendJson(res, 200, {
          edgeRelays: coordinator.listActiveEdgeRelays(),
        });
        return;
      }

      if (method === "POST" && reqUrl.pathname === "/v1/edge-relays/heartbeat") {
        const body = await readJsonBody<EdgeRelayHeartbeatPayload>(req);
        if (
          !body.relayId ||
          !body.region ||
          !body.httpUrl ||
          !body.wsUrl ||
          !body.signature ||
          !verifyEdgeRelayHeartbeat(relayAuthSecret, body)
        ) {
          sendJson(res, 401, { error: "INVALID_RELAY_SIGNATURE" });
          return;
        }
        coordinator.upsertEdgeRelay(
          {
            relayId: body.relayId,
            region: body.region,
            httpUrl: body.httpUrl,
            wsUrl: body.wsUrl,
            stunUrl: body.stunUrl,
            certSha256: body.certSha256,
            noSni: body.noSni,
          },
          false,
        );
        sendJson(res, 200, { ok: true });
        return;
      }

      if (method === "POST" && reqUrl.pathname === "/v1/pairings") {
        if (!isAuthorized(req, config.apiToken)) {
          sendUnauthorized(res);
          return;
        }
        const body = await readJsonBody<{
          scopeNamespace?: string;
          customSlotCode?: string;
        }>(req);
        const wsBase = deriveWsBaseUrl(req, config.publicUrl);
        const created = coordinator.createPairingSession({
          wsBaseUrl: wsBase,
          scopeNamespace: body.scopeNamespace,
          customSlotCode: body.customSlotCode,
        });
        sendJson(res, 200, created);
        return;
      }

      if (method === "POST" && reqUrl.pathname === "/v1/pairings/join") {
        if (!isAuthorized(req, config.apiToken)) {
          sendUnauthorized(res);
          return;
        }
        const body = await readJsonBody<{ slotCode: string }>(req);
        if (!body.slotCode) {
          sendJson(res, 400, { error: "MISSING_SLOT_CODE" });
          return;
        }
        const wsBase = deriveWsBaseUrl(req, config.publicUrl);
        const joined = coordinator.joinPairingSession({
          slotCode: body.slotCode,
          wsBaseUrl: wsBase,
        });
        sendJson(res, 200, joined);
        return;
      }

      if (method === "POST" && reqUrl.pathname === "/v1/leases") {
        if (!isAuthorized(req, config.apiToken)) {
          sendUnauthorized(res);
          return;
        }
        const body = await readJsonBody<CreateManagedLeaseRequest>(req);
        const wsBase = deriveWsBaseUrl(req, config.publicUrl);
        const lease = coordinator.createManagedLease({
          scopeNamespace: body.scopeNamespace ?? "default",
          wsBaseUrl: wsBase,
          expiresInSeconds: body.expiresInSeconds,
        });
        sendJson(res, 200, lease);
        return;
      }

      if (
        builtinDriver &&
        reqUrl.pathname.startsWith("/v1/packs/") &&
        (method === "PUT" || method === "GET")
      ) {
        const encodedKey = reqUrl.pathname.slice("/v1/packs/".length);
        const storageKey = decodeURIComponent(encodedKey);
        const exp = Number.parseInt(reqUrl.searchParams.get("exp") ?? "0", 10);
        const sig = reqUrl.searchParams.get("sig") ?? "";

        if (!exp || exp < Date.now()) {
          sendJson(res, 403, { error: "URL_EXPIRED" });
          return;
        }
        const expectedSig = signHttpObjectToken(
          signingSecret,
          method,
          storageKey,
          exp,
        );
        if (
          !constantTimeEqual(utf8Bytes(sig), utf8Bytes(expectedSig))
        ) {
          sendJson(res, 403, { error: "SIGNATURE_MISMATCH" });
          return;
        }

        const diskPath = safePackDiskPath(packsDir, storageKey);
        if (method === "PUT") {
          await mkdir(path.dirname(diskPath), { recursive: true });
          const tmpPath = `${diskPath}.part-${process.hrtime.bigint()}`;
          await pipeline(req, createWriteStream(tmpPath));
          if (config.builtinPutDelayMs && config.builtinPutDelayMs > 0) {
            await new Promise((r) => setTimeout(r, config.builtinPutDelayMs));
          }
          await rename(tmpPath, diskPath);
          const st = await stat(diskPath);
          config.onObjectStoreEvent?.({
            method: "PUT",
            storageKey,
            sizeBytes: st.size,
            timestampMs: Date.now(),
          });
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, sizeBytes: st.size }));
          return;
        }

        // GET
        let st;
        try {
          st = await stat(diskPath);
        } catch {
          sendJson(res, 404, { error: "PACK_NOT_FOUND" });
          return;
        }
        config.onObjectStoreEvent?.({
          method: "GET",
          storageKey,
          sizeBytes: st.size,
          timestampMs: Date.now(),
        });
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "content-length": String(st.size),
        });
        await pipeline(createReadStream(diskPath), res);
        return;
      }

      sendJson(res, 404, { error: "NOT_FOUND" });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.startsWith("SERVER_BUSY")) {
        sendJson(res, 503, { error: message }, { "retry-after": "30" });
        return;
      }
      const status = message.startsWith("PAIRING_NOT_FOUND")
        ? 404
        : message.startsWith("SLOT_IN_USE")
          ? 409
          : 400;
      sendJson(res, status, { error: message });
    }
  });

  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_SIGNALING_MESSAGE_BYTES,
  });

  server.on("upgrade", (req, socket, head) => {
    const reqUrl = new URL(req.url ?? "/", "http://localhost");
    if (!reqUrl.pathname.startsWith("/v1/ws/")) {
      socket.destroy();
      return;
    }
    const sessionId = decodeURIComponent(reqUrl.pathname.slice("/v1/ws/".length));
    wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
      const handle = {
        send: (payload: string) => {
          if (ws.readyState === ws.OPEN) {
            ws.send(payload);
          }
        },
        close: (code?: number, reason?: string) => {
          ws.close(code, reason);
        },
        bufferedAmount: () => ws.bufferedAmount,
        terminate: () => ws.terminate(),
      };

      ws.on("message", (data) => {
        const str = typeof data === "string" ? data : data.toString("utf8");
        void coordinator.handleWsMessage(sessionId, handle, str);
      });

      // Protocol violations (an oversized frame, invalid UTF-8, ...) surface as "error" before
      // "close". Without a listener they would be uncaught and take the whole process down.
      // The ws library answers with the matching close code (1009, 1007, ...) on its own.
      ws.on("error", () => {});

      ws.on("close", () => {
        coordinator.detachSocket(sessionId, handle);
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  const boundPort =
    typeof addr === "object" && addr ? addr.port : requestedPort;
  const resolvedPublicHttp = (
    config.publicUrl ?? `http://127.0.0.1:${boundPort}`
  ).replace(/\/+$/, "");
  const resolvedWsBase = resolvedPublicHttp.replace(/^http/, "ws");

  if (builtinDriver) {
    builtinDriver.setPublicBaseUrl(resolvedPublicHttp);
  }

  const gcTimer = setInterval(() => {
    void coordinator.runGarbageCollection();
  }, 60_000);
  gcTimer.unref();

  const wsPingTimer = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.readyState === ws.OPEN) {
        ws.ping();
      }
    }
  }, 20_000);
  wsPingTimer.unref();

  return {
    httpUrl: resolvedPublicHttp,
    wsBaseUrl: resolvedWsBase,
    port: boundPort,
    stunPort: stunServer ? stunServer.port : null,
    stunUrl: stunServer ? `stun:${stunHost}:${stunServer.port}` : null,
    coordinator,
    close: async () => {
      clearInterval(gcTimer);
      clearInterval(wsPingTimer);
      coordinator.dispose();
      for (const client of wss.clients) {
        client.terminate();
      }
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (stunServer) {
        await stunServer.close();
      }
    },
  };
}

function safePackDiskPath(packsDir: string, storageKey: string): string {
  const cleaned = storageKey
    .split("/")
    .filter((s) => s && s !== "." && s !== "..")
    .join(path.sep);
  const resolved = path.resolve(packsDir, cleaned);
  if (!resolved.startsWith(path.resolve(packsDir) + path.sep)) {
    throw new Error("Unsafe storage key");
  }
  return resolved;
}

function deriveWsBaseUrl(
  req: http.IncomingMessage,
  configuredPublicUrl?: string,
): string {
  if (configuredPublicUrl) {
    return configuredPublicUrl.replace(/\/+$/, "").replace(/^http/, "ws");
  }
  const protoHeader = req.headers["x-forwarded-proto"];
  const proto =
    (Array.isArray(protoHeader) ? protoHeader[0] : protoHeader) === "https"
      ? "wss"
      : "ws";
  const host = req.headers.host ?? "127.0.0.1:8787";
  return `${proto}://${host}`;
}

/** True when no API token is configured, or the request carries it as a bearer token. */
function isAuthorized(
  req: http.IncomingMessage,
  apiToken: string | undefined,
): boolean {
  if (!apiToken) return true;
  const auth = req.headers.authorization ?? "";
  if (!/^Bearer /i.test(auth)) return false;
  const provided = auth.slice("Bearer ".length).trim();
  return constantTimeEqual(utf8Bytes(provided), utf8Bytes(apiToken));
}

function sendUnauthorized(res: http.ServerResponse): void {
  sendJson(res, 401, { error: "UNAUTHORIZED" }, { "www-authenticate": "Bearer" });
}

async function readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > 2 * 1024 * 1024) {
      throw new Error("JSON body too large");
    }
    chunks.push(buf);
  }
  if (chunks.length === 0) return {} as T;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  payload: unknown,
  extraHeaders: Record<string, string> = {},
): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(body)),
    ...extraHeaders,
  });
  res.end(body);
}
