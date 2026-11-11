#!/usr/bin/env node
import { startBeamSyncServer } from "./server.js";

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
    apiToken,
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
