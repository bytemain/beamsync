import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import WebSocket from "ws";
import { MAX_SIGNALING_MESSAGE_BYTES } from "@beamsync/protocol";
import { startBeamSyncServer, type RunningBeamSyncServer } from "@beamsync/server";
import { receiveDirectory, sendDirectory } from "@beamsync/cli";

describe("workspaces with very many entries", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-large-"));
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      publicStunHost: "127.0.0.1",
      dataDir: path.join(tmpRoot, "server-data"),
      peerLossGraceMs: 300,
    });
  });

  afterEach(async () => {
    await server.close();
    await rm(tmpRoot, { recursive: true, force: true });
  });

  it("the Coordinator survives a signaling frame above its size limit", async () => {
    const wsUrl = `${server.httpUrl.replace(/^http/, "ws")}/v1/ws/no-such-session`;
    const closeCode = await new Promise<number>((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      ws.on("open", () => ws.send("x".repeat(MAX_SIGNALING_MESSAGE_BYTES + 1024)));
      ws.on("close", (code) => resolve(code));
      ws.on("error", () => {});
      setTimeout(() => reject(new Error("socket was not closed")), 10_000);
    });
    expect(closeCode).toBe(1009);

    // Still serving: a complete transfer works afterwards
    const sourceDir = path.join(tmpRoot, "src");
    await mkdir(sourceDir, { recursive: true });
    await writeFile(path.join(sourceDir, "a.txt"), "a\n");
    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendPromise = sendDirectory({
      serverUrl: server.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "large-host",
      onPairingCode: resolveCode,
    });
    const received = await receiveDirectory({
      serverUrl: server.httpUrl,
      targetDir: path.join(tmpRoot, "dst"),
      pairingCode: await codePromise,
      cacheDir: path.join(tmpRoot, "c2"),
      hostIdOverride: "large-host",
    });
    expect(received.rootTreeDigest).toBe((await sendPromise).rootTreeDigest);
  });

  it("fails fast with an ignore hint when the plan does not fit in one signaling message, and works once the bulk is ignored", async () => {
    const sourceDir = path.join(tmpRoot, "src");
    const deps = path.join(sourceDir, "node_modules", "pkg");
    await mkdir(deps, { recursive: true });
    for (let i = 0; i < 300; i++) {
      await writeFile(path.join(deps, `module-${i}.js`), `// ${i}\n`);
    }
    await writeFile(path.join(sourceDir, "main.ts"), "main\n");

    const run = async (extraIgnoreRules: string[], targetName: string) => {
      let resolveCode!: (code: string) => void;
      const codePromise = new Promise<string>((r) => {
        resolveCode = r;
      });
      const progress: string[] = [];
      const sendPromise = sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        cacheDir: path.join(tmpRoot, "c1"),
        hostIdOverride: "large-host",
        // Stand-in for the 32 MiB limit so the test does not need 200k files
        maxSignalingMessageBytes: 16 * 1024,
        extraIgnoreRules,
        onPairingCode: resolveCode,
        onProgress: (ev) => progress.push(ev.phase),
      });
      sendPromise.catch(() => {});
      const receivePromise = receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir: path.join(tmpRoot, targetName),
        pairingCode: await codePromise,
        cacheDir: path.join(tmpRoot, "c2"),
        hostIdOverride: "large-host",
      });
      receivePromise.catch(() => {});
      return { sendPromise, receivePromise, progress };
    };

    const startedAt = Date.now();
    const tooLarge = await run([], "dst-too-large");
    await expect(tooLarge.sendPromise).rejects.toThrow(
      /MANIFEST_TOO_LARGE: the transfer plan lists 301 entries.*ignore rules/s,
    );
    expect(Date.now() - startedAt).toBeLessThan(10_000);
    // Refused locally: the socket was never dropped and resumed
    expect(tooLarge.progress).not.toContain("signaling_resumed");
    // The waiting receiver is told the sender is gone instead of hanging
    await expect(tooLarge.receivePromise).rejects.toThrow(/PEER_LOST/);
    expect((await readdir(tmpRoot)).filter((n) => n.includes("dst-too-large"))).toEqual([]);

    const trimmed = await run(["node_modules/"], "dst-trimmed");
    const sent = await trimmed.sendPromise;
    const received = await trimmed.receivePromise;
    expect(sent.ignoredPaths).toBe(1);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
    expect(await readdir(path.join(tmpRoot, "dst-trimmed"))).toEqual([".beamsync", "main.ts"]);
  });
});
