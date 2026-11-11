#!/usr/bin/env node
import os from "node:os";
import { startEdgeRelayServer } from "./relayServer.js";

async function main(): Promise<void> {
  const region = process.env.REGION?.trim() || "default";
  const relayId =
    process.env.RELAY_ID?.trim() || `${region}-${os.hostname().slice(0, 12)}`;
  const authSecret = process.env.RELAY_AUTH_SECRET?.trim();
  if (!authSecret) {
    throw new Error("RELAY_AUTH_SECRET environment variable is required");
  }

  const port = Number.parseInt(process.env.PORT ?? "8788", 10);
  const host = process.env.HOST ?? "0.0.0.0";
  const publicIp = process.env.PUBLIC_IP?.trim() || undefined;
  const publicUrl = process.env.PUBLIC_RELAY_URL?.trim() || undefined;
  const tlsCertFile = process.env.TLS_CERT_FILE?.trim() || undefined;
  const tlsKeyFile = process.env.TLS_KEY_FILE?.trim() || undefined;
  const tlsCacheFile =
    process.env.TLS_CACHE_FILE?.trim() || "/tmp/beamsync-derp-tls.json";

  // Default to self-signed IP+TLS whenever PUBLIC_IP is provided without PUBLIC_RELAY_URL
  // (e.g. ICP-free Shanghai / domestic cloud VM mode), or when TLS_MODE=self-signed
  const rawTlsMode = process.env.TLS_MODE?.trim().toLowerCase();
  const tlsMode: "off" | "self-signed" | "custom" =
    rawTlsMode === "self-signed" || process.env.TLS_SELF_SIGNED === "true"
      ? "self-signed"
      : rawTlsMode === "custom" || Boolean(tlsCertFile && tlsKeyFile)
        ? "custom"
        : rawTlsMode === "off"
          ? "off"
          : publicIp && !publicUrl
            ? "self-signed"
            : "off";

  const stunDisabled = process.env.STUN_DISABLED === "true";
  const stunPort = stunDisabled
    ? null
    : Number.parseInt(process.env.STUN_PORT ?? "3478", 10);
  const publicStunHost = process.env.PUBLIC_STUN_HOST?.trim() || undefined;
  const coordinatorUrl = process.env.COORDINATOR_URL?.trim() || undefined;

  const running = await startEdgeRelayServer({
    relayId,
    region,
    authSecret,
    port,
    host,
    publicIp,
    publicUrl,
    tlsMode,
    tlsCertFile,
    tlsKeyFile,
    tlsCacheFile,
    stunPort,
    publicStunHost,
    coordinatorUrl,
  });

  console.log(
    JSON.stringify({
      event: "beamsync_edge_relay_started",
      relayId: running.relayId,
      region: running.region,
      httpUrl: running.httpUrl,
      wsUrl: running.wsUrl,
      stunUrl: running.stunUrl,
      certSha256: running.certSha256,
      noSni: running.noSni,
      coordinatorUrl: coordinatorUrl ?? "static",
      staticEdgeRelayConfigHint: running.certSha256
        ? `${running.region}=${running.httpUrl}${running.stunUrl ? `|${running.stunUrl}` : ""}#sha256=${running.certSha256}`
        : `${running.region}=${running.httpUrl}${running.stunUrl ? `|${running.stunUrl}` : ""}`,
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
  console.error("Failed to start beamsync-edge-relay:", err);
  process.exit(1);
});
