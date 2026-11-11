#!/usr/bin/env node
import type { TransportTier } from "@beamsync/protocol";
import { receiveDirectory, runDoctor, sendDirectory } from "./syncClient.js";

function parseArgs(argv: string[]): {
  positional: string[];
  flags: Record<string, string | boolean>;
} {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

function printUsage(): void {
  console.log(`BeamSync CLI — streaming incremental directory sync & migration

Usage:
  beamsync send <source-dir> [--server <url>] [--scope <namespace>] [--code <words>] [--force-tier <tier>]
  beamsync receive <target-dir> --code <pairing-code> [--server <url>]
  beamsync doctor [--server <url>]

Environment:
  BEAMSYNC_SERVER_URL   Default coordinator server URL (default: http://127.0.0.1:8787)
`);
}

async function main(): Promise<void> {
  const { positional, flags } = parseArgs(process.argv.slice(2));
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

    const result = await sendDirectory({
      serverUrl,
      sourceDir,
      scopeNamespace,
      customSecretWords: customWords,
      forceTier,
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
    });

    console.log(JSON.stringify(result, null, 2));
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
