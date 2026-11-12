#!/usr/bin/env node
import type { TransportTier } from "@beamsync/protocol";
import { ignoreOptionsFromArgs, parseArgs } from "./cliArgs.js";
import { listIgnoredPaths } from "./stateIndex.js";
import { receiveDirectory, runDoctor, sendDirectory } from "./syncClient.js";

function printUsage(): void {
  console.log(`BeamSync CLI — streaming incremental directory sync & migration

Usage:
  beamsync send <source-dir> [--server <url>] [--scope <namespace>] [--code <words>] [options]
  beamsync receive <target-dir> --code <pairing-code> [--server <url>] [options]
  beamsync ignored <source-dir> [ignore options] [--json]   List what a send would skip
  beamsync doctor [--server <url>]

Ignore options (send, ignored) — patterns use .gitignore syntax:
  --ignore <pattern>       Skip matching paths; repeatable; highest precedence
  --ignore-file <name>     Also read ignore files with this name in every directory,
                           e.g. --ignore-file .raftmigrationignore; repeatable
  --respect-gitignore      Also honour .gitignore files (off by default)
  --ignore-from <path>     Read root-anchored rules from a file outside the workspace; repeatable
  .beamsyncignore files are always read, in every directory.

Send options:
  --max-mbps <mbps>        Cap upload bandwidth on network tiers
  --prefer-edge-relay      Use the Edge Relay regardless of transfer size
  --force-tier <tier>      LOCAL_IPC | P2P_DIRECT | EDGE_RELAY | STREAM_RELAY | R2_PIPELINE
  --no-optimistic-relay    Wait for direct-path probing instead of starting on the Edge Relay
  --no-udp-mtu-probe       Keep conservative 1150-byte UDP chunks

Receive options:
  --delete-ignored         Delete target paths the sender ignored (default: keep them)

Options for both sides:
  --disable-edge-relay     Never use an Edge Relay
  --no-port-mapping        Do not ask the local gateway for a UDP port mapping (NAT-PMP)

Environment:
  BEAMSYNC_SERVER_URL   Default coordinator server URL (default: http://127.0.0.1:8787)
  BEAMSYNC_PROXY        Outbound proxy (http://, https://, socks5://); overrides HTTPS_PROXY / HTTP_PROXY / ALL_PROXY
  BEAMSYNC_NO_PROXY     Hosts that bypass the proxy (same syntax as NO_PROXY)
  BEAMSYNC_IGNORE_FILES Comma-separated extra ignore file names (same as repeating --ignore-file)
`);
}

async function main(): Promise<void> {
  const { positional, flags, multi } = parseArgs(process.argv.slice(2));
  const cmd = positional[0];
  const serverUrl =
    (typeof flags.server === "string" ? flags.server : undefined) ??
    process.env.BEAMSYNC_SERVER_URL ??
    "http://127.0.0.1:8787";

  if (!cmd || flags.help || cmd === "help") {
    printUsage();
    return;
  }

  if (cmd === "send") {
    const sourceDir = positional[1];
    if (!sourceDir) {
      throw new Error("Missing <source-dir>. Usage: beamsync send <source-dir>");
    }
    const forceTier =
      typeof flags["force-tier"] === "string"
        ? (flags["force-tier"] as TransportTier)
        : undefined;
    const scopeNamespace =
      typeof flags.scope === "string" ? flags.scope : undefined;
    const customWords =
      typeof flags.code === "string" ? flags.code : undefined;
    const maxBandwidthMbps =
      typeof flags["max-mbps"] === "string"
        ? Number.parseFloat(flags["max-mbps"])
        : undefined;

    const result = await sendDirectory({
      serverUrl,
      sourceDir,
      scopeNamespace,
      customSecretWords: customWords,
      preferEdgeRelay: Boolean(flags["prefer-edge-relay"]),
      disableEdgeRelay: Boolean(flags["disable-edge-relay"]),
      disableOptimisticRelay: Boolean(flags["no-optimistic-relay"]),
      disablePortMapping: Boolean(flags["no-port-mapping"]),
      disableUdpMtuProbe: Boolean(flags["no-udp-mtu-probe"]),
      maxBandwidthMbps,
      forceTier,
      ...ignoreOptionsFromArgs(flags, multi),
      onPairingCode: (code) => {
        console.log(`\nPairing ready. Run on target machine:\n`);
        console.log(`  beamsync receive <target-dir> --code ${code} --server ${serverUrl}\n`);
      },
      onProgress: (ev) => {
        console.log(`[${ev.phase}] tier=${ev.tier ?? "-"} ${ev.detail ?? ""}`);
      },
    });

    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (cmd === "receive") {
    const targetDir = positional[1];
    const code = typeof flags.code === "string" ? flags.code : undefined;
    if (!targetDir || !code) {
      throw new Error(
        "Usage: beamsync receive <target-dir> --code <pairing-code>",
      );
    }

    const result = await receiveDirectory({
      serverUrl,
      targetDir,
      pairingCode: code,
      deleteIgnored: Boolean(flags["delete-ignored"]),
      disableEdgeRelay: Boolean(flags["disable-edge-relay"]),
      disablePortMapping: Boolean(flags["no-port-mapping"]),
      onProgress: (ev) => {
        console.log(`[${ev.phase}] tier=${ev.tier ?? "-"} ${ev.detail ?? ""}`);
      },
    });

    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (cmd === "ignored") {
    const sourceDir = positional[1];
    if (!sourceDir) {
      throw new Error("Missing <source-dir>. Usage: beamsync ignored <source-dir>");
    }
    const report = await listIgnoredPaths(sourceDir, ignoreOptionsFromArgs(flags, multi));
    if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    for (const item of report.ignored) {
      const reason = item.pattern ? `${item.source}: ${item.pattern}` : (item.source ?? "");
      console.log(`${item.relPath}${item.isDirectory ? "/" : ""}\t${reason}`);
    }
    console.error(
      `${report.ignored.length} ignored, ${report.includedEntries} included; ` +
        `ignore files: ${report.ignoreFilesLoaded.join(", ") || "none"}`,
    );
    return;
  }

  if (cmd === "doctor") {
    const report = await runDoctor(serverUrl);
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  throw new Error(`Unknown command "${cmd}"`);
}

main().catch((err) => {
  console.error("beamsync error:", err instanceof Error ? err.message : err);
  process.exit(1);
});
