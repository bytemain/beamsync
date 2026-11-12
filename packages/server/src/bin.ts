#!/usr/bin/env node
import type { EdgeRelayNodeInfo } from "@beamsync/protocol";
import { startBeamSyncServer } from "./server.js";

function parseStaticEdgeRelays(raw: string | undefined): EdgeRelayNodeInfo[] {
  if (!raw?.trim()) return [];
  // Format: region=https://101.132.x.x:8443|stun:101.132.x.x:3478#sha256=<hex>,...
  const list: EdgeRelayNodeInfo[] = [];
  for (const item of raw.split(",")) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx <= 0) continue;
    const region = trimmed.slice(0, eqIdx).trim();
    const [restBeforeHash, hashFragment] = trimmed.slice(eqIdx + 1).trim().split("#");
    const [httpUrlRaw, stunUrlRaw] = restBeforeHash.split("|");
    const httpUrl = httpUrlRaw.trim().replace(/\/+$/, "");
    const u = new URL(httpUrl);
    const wsProto = u.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProto}//${u.host}`;
    let certSha256: string | undefined;
    let noSni: boolean | undefined;
    if (hashFragment) {
      const params = new URLSearchParams(hashFragment);
      certSha256 = params.get("sha256")?.trim().toLowerCase() || undefined;
      if (params.get("nosni") === "1" || params.get("nosni") === "true" || certSha256) {
        noSni = true;
      }
    }
    list.push({
      relayId: `static-${region}`,
      region,
      httpUrl,
      wsUrl,
      stunUrl: stunUrlRaw?.trim() || undefined,
      certSha256,
      noSni,
    });
  }
  return list;
}

function parsePositiveInt(name: string): number | undefined {
  const raw = process.env[name]?.trim();
  if (!raw) return undefined;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return value;
}

async function main(): Promise<void> {
  const port = Number.parseInt(process.env.PORT ?? "8787", 10);
  const host = process.env.HOST ?? "0.0.0.0";
  const publicUrl = process.env.PUBLIC_URL?.trim() || undefined;
  const dataDir = process.env.DATA_DIR?.trim() || "./data";
  const stunDisabled = process.env.STUN_DISABLED === "true";
  const stunPort = stunDisabled
    ? null
    : Number.parseInt(process.env.STUN_PORT ?? "3478", 10);
  const publicStunHost = process.env.PUBLIC_STUN_HOST?.trim() || undefined;
  const apiToken = process.env.BEAMSYNC_API_TOKEN?.trim() || undefined;
  const relayAuthSecret = process.env.RELAY_AUTH_SECRET?.trim() || undefined;
  const maxSessions = parsePositiveInt("MAX_SESSIONS");
  const maxReplayBufferMb = parsePositiveInt("MAX_REPLAY_BUFFER_MB");
  const initialEdgeRelays = parseStaticEdgeRelays(process.env.EDGE_RELAYS);

  const r2Bucket = process.env.R2_BUCKET_NAME?.trim();
  const r2AccessKeyId = process.env.R2_ACCESS_KEY_ID?.trim();
  const r2SecretAccessKey = process.env.R2_SECRET_ACCESS_KEY?.trim();
  const r2AccountId = process.env.R2_ACCOUNT_ID?.trim();
  const r2Endpoint = process.env.R2_ENDPOINT?.trim();

  const r2 =
    r2Bucket && r2AccessKeyId && r2SecretAccessKey && (r2AccountId || r2Endpoint)
      ? {
          accountId: r2AccountId,
          endpoint: r2Endpoint,
          bucket: r2Bucket,
          accessKeyId: r2AccessKeyId,
          secretAccessKey: r2SecretAccessKey,
          region: process.env.R2_REGION?.trim() || "auto",
        }
      : undefined;

  const running = await startBeamSyncServer({
    port,
    host,
    publicUrl,
    dataDir,
    stunPort,
    publicStunHost,
    relayAuthSecret,
    initialEdgeRelays,
    apiToken,
    maxSessions,
    maxReplayLogBytesTotal:
      maxReplayBufferMb === undefined ? undefined : maxReplayBufferMb * 1024 * 1024,
    r2,
  });

  console.log(
    JSON.stringify({
      event: "beamsync_server_started",
      httpUrl: running.httpUrl,
      wsBaseUrl: running.wsBaseUrl,
      port: running.port,
      stunUrl: running.stunUrl,
      storageMode: r2 ? "r2-presigned" : "builtin-http",
      dataDir,
      pairingAuth: apiToken ? "api-token" : "open",
    }),
  );

  const shutdown = async () => {
    await running.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

main().catch((err) => {
  console.error("Failed to start beamsync-server:", err);
  process.exit(1);
});
