import dgram from "node:dgram";
import { readFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import type tls from "node:tls";
import { WebSocketServer, WebSocket } from "ws";
import {
  signEdgeRelayHeartbeat,
  verifyEdgeRelayTicket,
  type EdgeRelayHeartbeatPayload,
  type EdgeRelayNodeInfo,
} from "@beamsync/protocol";
import {
  computeCertPemSha256,
  getOrCreateSelfSignedTlsMaterial,
} from "./selfSignedTls.js";

const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE = 0x0101;
const STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

const RELAY_PAIRED_SIGNAL = Buffer.from([0x01]);
const HIGH_WATERMARK_BYTES = 4 * 1024 * 1024;
const LOW_WATERMARK_BYTES = 1 * 1024 * 1024;

interface RelayRoom {
  sessionId: string;
  source: WebSocket | null;
  target: WebSocket | null;
  pairedNotified: boolean;
  createdAt: number;
  bytesForwarded: number;
}

export interface EdgeRelayServerConfig {
  relayId: string;
  region: string;
  authSecret: string;
  port?: number;
  host?: string;
  /**
   * Public URL (e.g. `https://sgp-relay.example.com` or `https://101.132.x.x:8443`).
   * If omitted and `publicIp` is provided with `tlsMode: "self-signed"`, automatically
   * builds `https://<publicIp>:<port>` for domainless/ICP-free deployment.
   */
  publicUrl?: string;
  publicIp?: string;
  tlsMode?: "off" | "self-signed" | "custom";
  tlsCertPem?: string;
  tlsKeyPem?: string;
  tlsCertFile?: string;
  tlsKeyFile?: string;
  tlsCacheFile?: string;
  noSni?: boolean;
  stunPort?: number | null; // null disables UDP STUN; 0 picks ephemeral port
  publicStunHost?: string;
  coordinatorUrl?: string; // Optional central coordinator URL for auto-registration heartbeats
  heartbeatIntervalMs?: number;
  probeDelayMs?: number; // Test hook to simulate regional network latency
}

export interface RunningEdgeRelayServer {
  relayId: string;
  region: string;
  httpUrl: string;
  wsUrl: string;
  port: number;
  stunPort: number | null;
  stunUrl: string | undefined;
  certSha256: string | undefined;
  noSni: boolean;
  nodeInfo: EdgeRelayNodeInfo;
  getStats(): {
    relayId: string;
    region: string;
    activeRooms: number;
    totalRelayedBytes: number;
    totalRelayedFrames: number;
    observedTlsSniHostnames: string[];
  };
  dropActiveSessionsForTest(): void;
  close(): Promise<void>;
}

async function startEmbeddedStun(
  port: number,
  host: string,
): Promise<{ port: number; close(): Promise<void> }> {
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg, rinfo) => {
    if (msg.length < 20) return;
    if (
      msg.readUInt16BE(0) !== STUN_BINDING_REQUEST ||
      msg.readUInt32BE(4) !== STUN_MAGIC_COOKIE
    ) {
      return;
    }
    const ipParts = rinfo.address.split(".").map((x) => Number.parseInt(x, 10));
    if (ipParts.length !== 4 || ipParts.some((n) => Number.isNaN(n))) return;

    const attr = Buffer.alloc(12);
    attr.writeUInt16BE(STUN_ATTR_XOR_MAPPED_ADDRESS, 0);
    attr.writeUInt16BE(8, 2);
    attr[4] = 0x00;
    attr[5] = 0x01;
    attr.writeUInt16BE((rinfo.port ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff, 6);
    const cookieBytes = Buffer.alloc(4);
    cookieBytes.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
    for (let i = 0; i < 4; i++) {
      attr[8 + i] = (ipParts[i] ^ cookieBytes[i]) & 0xff;
    }

    const header = Buffer.alloc(20);
    header.writeUInt16BE(STUN_BINDING_SUCCESS_RESPONSE, 0);
    header.writeUInt16BE(attr.length, 2);
    header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
    msg.subarray(8, 20).copy(header, 8);
    sock.send(Buffer.concat([header, attr]), rinfo.port, rinfo.address);
  });

  await new Promise<void>((resolve, reject) => {
    sock.once("error", reject);
    sock.bind(port, host, () => {
      sock.removeListener("error", reject);
      resolve();
    });
  });

  const addr = sock.address();
  const boundPort = typeof addr === "string" ? port : addr.port;
  return {
    port: boundPort,
    close: () => new Promise<void>((r) => sock.close(() => r())),
  };
}

/**
 * Starts a stateless regional Edge Relay & UDP STUN server (`@beamsync/edge-relay`).
 * Supports both domain HTTPS/WSS behind reverse proxies AND raw IP + self-signed TLS
 * with SHA-256 certificate pinning and SNI suppression (for domestic / Shanghai cloud VMs
 * with zero domain and zero ICP filing).
 */
export async function startEdgeRelayServer(
  config: EdgeRelayServerConfig,
): Promise<RunningEdgeRelayServer> {
  const host = config.host ?? "0.0.0.0";
  const requestedPort = config.port ?? 8788;
  const rooms = new Map<string, RelayRoom>();
  let totalRelayedBytes = 0;
  let totalRelayedFrames = 0;
  const observedTlsSniHostnames: string[] = [];

  let stun: { port: number; close(): Promise<void> } | null = null;
  if (config.stunPort !== null) {
    stun = await startEmbeddedStun(config.stunPort ?? 3478, host);
  }

  const tlsMode =
    config.tlsMode ??
    (config.tlsCertPem || config.tlsCertFile ? "custom" : "off");

  let tlsCertPem: string | undefined;
  let tlsKeyPem: string | undefined;
  let certSha256: string | undefined;

  if (tlsMode === "self-signed") {
    const generated = await getOrCreateSelfSignedTlsMaterial({
      commonName: `beamsync-relay-${config.region}`,
      ipSan: config.publicIp,
      cacheFilePath: config.tlsCacheFile,
    });
    tlsCertPem = generated.certPem;
    tlsKeyPem = generated.keyPem;
    certSha256 = generated.certSha256;
  } else if (tlsMode === "custom") {
    tlsCertPem =
      config.tlsCertPem ??
      (config.tlsCertFile ? await readFile(config.tlsCertFile, "utf8") : undefined);
    tlsKeyPem =
      config.tlsKeyPem ??
      (config.tlsKeyFile ? await readFile(config.tlsKeyFile, "utf8") : undefined);
    if (!tlsCertPem || !tlsKeyPem) {
      throw new Error("Custom TLS mode requires tlsCertPem/tlsKeyPem or tlsCertFile/tlsKeyFile");
    }
    certSha256 = computeCertPemSha256(tlsCertPem);
  }

  const requestHandler: http.RequestListener = async (req, res) => {
    const reqUrl = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "localhost"}`,
    );

    if (req.method === "GET" && reqUrl.pathname === "/probe") {
      if (config.probeDelayMs && config.probeDelayMs > 0) {
        await new Promise((r) => setTimeout(r, config.probeDelayMs));
      }
      res.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
      });
      res.end(
        JSON.stringify({
          ok: true,
          relayId: config.relayId,
          region: config.region,
          ts: Date.now(),
        }),
      );
      return;
    }

    if (req.method === "GET" && reqUrl.pathname === "/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          service: "beamsync-edge-relay",
          relayId: config.relayId,
          region: config.region,
          tlsEnabled: tlsMode !== "off",
          certSha256,
          activeRooms: rooms.size,
          totalRelayedBytes,
          totalRelayedFrames,
        }),
      );
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "NOT_FOUND" }));
  };

  const server: http.Server | https.Server =
    tlsCertPem && tlsKeyPem
      ? https.createServer({ cert: tlsCertPem, key: tlsKeyPem }, requestHandler)
      : http.createServer(requestHandler);

  if (server instanceof https.Server) {
    server.on("secureConnection", (tlsSock: tls.TLSSocket) => {
      const sni = (tlsSock as unknown as { servername?: string | null }).servername;
      if (sni) {
        observedTlsSniHostnames.push(sni);
      }
    });
  }

  const wss = new WebSocketServer({ noServer: true, maxPayload: 32 * 1024 * 1024 });

  server.on("upgrade", (req, socket, head) => {
    const reqUrl = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "localhost"}`,
    );
    const match = /^\/v1\/relay\/([^/]+)$/.exec(reqUrl.pathname);
    if (!match) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    const sessionId = decodeURIComponent(match[1]);
    const relayId = reqUrl.searchParams.get("relayId") ?? "";
    const role = reqUrl.searchParams.get("role");
    const exp = Number.parseInt(reqUrl.searchParams.get("exp") ?? "0", 10);
    const ticket = reqUrl.searchParams.get("ticket") ?? "";

    if (
      relayId !== config.relayId ||
      (role !== "source" && role !== "target") ||
      !verifyEdgeRelayTicket({
        authSecret: config.authSecret,
        relayId: config.relayId,
        sessionId,
        role,
        expiresAtMs: exp,
        ticket,
      })
    ) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      attachRelayPeer(sessionId, role, ws);
    });
  });

  function attachRelayPeer(
    sessionId: string,
    role: "source" | "target",
    ws: WebSocket,
  ): void {
    let room = rooms.get(sessionId);
    if (!room) {
      room = {
        sessionId,
        source: null,
        target: null,
        pairedNotified: false,
        createdAt: Date.now(),
        bytesForwarded: 0,
      };
      rooms.set(sessionId, room);
    }

    if (role === "source") {
      if (room.source) room.pairedNotified = false;
      room.source?.close(1000, "replaced");
      room.source = ws;
    } else {
      if (room.target) room.pairedNotified = false;
      room.target?.close(1000, "replaced");
      room.target = ws;
    }

    const rawSock = (ws as unknown as { _socket?: net.Socket })._socket;
    rawSock?.setNoDelay?.(true);

    const getPeer = (): WebSocket | null => {
      const current = rooms.get(sessionId);
      if (!current) return null;
      return role === "source" ? current.target : current.source;
    };

    ws.on("message", (data, isBinary) => {
      const peer = getPeer();
      if (!peer || peer.readyState !== WebSocket.OPEN) return;

      const buf = Buffer.isBuffer(data)
        ? data
        : Array.isArray(data)
          ? Buffer.concat(data)
          : Buffer.from(data);

      totalRelayedBytes += buf.byteLength;
      totalRelayedFrames += 1;
      room!.bytesForwarded += buf.byteLength;

      if (peer.bufferedAmount > HIGH_WATERMARK_BYTES && rawSock) {
        rawSock.pause();
        const checkDrain = setInterval(() => {
          if (
            peer.readyState !== WebSocket.OPEN ||
            peer.bufferedAmount < LOW_WATERMARK_BYTES
          ) {
            clearInterval(checkDrain);
            rawSock.resume();
          }
        }, 10);
      }

      peer.send(buf, { binary: isBinary });
    });

    const cleanup = () => {
      const current = rooms.get(sessionId);
      if (!current) return;
      if (role === "source" && current.source === ws) {
        current.source = null;
        if (current.target?.readyState === WebSocket.OPEN) {
          current.target.close(1001, "source_disconnected");
        }
      } else if (role === "target" && current.target === ws) {
        current.target = null;
        if (current.source?.readyState === WebSocket.OPEN) {
          current.source.close(1001, "target_disconnected");
        }
      }
      if (!current.source && !current.target) {
        rooms.delete(sessionId);
      }
    };

    ws.on("close", cleanup);
    ws.on("error", cleanup);

    if (
      room.source?.readyState === WebSocket.OPEN &&
      room.target?.readyState === WebSocket.OPEN &&
      !room.pairedNotified
    ) {
      room.pairedNotified = true;
      room.source.send(RELAY_PAIRED_SIGNAL, { binary: true });
      room.target.send(RELAY_PAIRED_SIGNAL, { binary: true });
    }
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  const boundPort = typeof addr === "object" && addr ? addr.port : requestedPort;
  const scheme = tlsMode !== "off" ? "https" : "http";
  const connectHost =
    config.publicIp ??
    (host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host);
  const httpUrl = (
    config.publicUrl ?? `${scheme}://${connectHost}:${boundPort}`
  ).replace(/\/+$/, "");

  const parsedHttp = new URL(httpUrl);
  const wsProto = parsedHttp.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsProto}//${parsedHttp.host}`;
  const stunHost = config.publicStunHost ?? config.publicIp ?? parsedHttp.hostname;
  const stunUrl = stun ? `stun:${stunHost}:${stun.port}` : undefined;

  const isRawIpHost = net.isIP(parsedHttp.hostname) !== 0;
  const effectiveNoSni =
    config.noSni ?? (tlsMode === "self-signed" || (tlsMode !== "off" && isRawIpHost));

  const nodeInfo: EdgeRelayNodeInfo = {
    relayId: config.relayId,
    region: config.region,
    httpUrl,
    wsUrl,
    stunUrl,
    certSha256,
    noSni: effectiveNoSni || undefined,
  };

  const wsPingTimer = setInterval(() => {
    for (const room of rooms.values()) {
      if (room.source?.readyState === WebSocket.OPEN) {
        room.source.ping();
      }
      if (room.target?.readyState === WebSocket.OPEN) {
        room.target.ping();
      }
    }
  }, 20_000);
  wsPingTimer.unref();

  let hbTimer: ReturnType<typeof setInterval> | null = null;
  const sendHeartbeat = async () => {
    if (!config.coordinatorUrl) return;
    const timestampMs = Date.now();
    const unsigned = {
      relayId: config.relayId,
      region: config.region,
      httpUrl,
      wsUrl,
      stunUrl,
      certSha256,
      noSni: effectiveNoSni || undefined,
      timestampMs,
    };
    const payload: EdgeRelayHeartbeatPayload = {
      ...unsigned,
      signature: signEdgeRelayHeartbeat(config.authSecret, unsigned),
    };
    try {
      await fetch(
        `${config.coordinatorUrl.replace(/\/+$/, "")}/v1/edge-relays/heartbeat`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        },
      );
    } catch {
      // Coordinator temporarily unreachable; retry next interval
    }
  };

  if (config.coordinatorUrl) {
    await sendHeartbeat();
    hbTimer = setInterval(
      () => void sendHeartbeat(),
      config.heartbeatIntervalMs ?? 15_000,
    );
  }

  return {
    relayId: config.relayId,
    region: config.region,
    httpUrl,
    wsUrl,
    port: boundPort,
    stunPort: stun?.port ?? null,
    stunUrl,
    certSha256,
    noSni: effectiveNoSni,
    nodeInfo,
    getStats: () => ({
      relayId: config.relayId,
      region: config.region,
      activeRooms: rooms.size,
      totalRelayedBytes,
      totalRelayedFrames,
      observedTlsSniHostnames: [...observedTlsSniHostnames],
    }),
    dropActiveSessionsForTest: () => {
      for (const room of rooms.values()) {
        room.source?.terminate();
        room.target?.terminate();
      }
      rooms.clear();
    },
    close: async () => {
      clearInterval(wsPingTimer);
      if (hbTimer) clearInterval(hbTimer);
      for (const room of rooms.values()) {
        room.source?.terminate();
        room.target?.terminate();
      }
      rooms.clear();
      await new Promise<void>((r) => wss.close(() => r()));
      await new Promise<void>((r) => server.close(() => r()));
      if (stun) await stun.close();
    },
  };
}
