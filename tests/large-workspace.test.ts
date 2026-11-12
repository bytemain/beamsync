import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import WebSocket from "ws";
import {
  MAX_SIGNALING_MESSAGE_BYTES,
  blake3Hex,
  decodePack,
  encodePack,
} from "@beamsync/protocol";
import { startBeamSyncServer, type RunningBeamSyncServer } from "@beamsync/server";
import {
  receiveDirectory,
  scanWorkspace,
  sendDirectory,
  zstdCompress,
  zstdDecompress,
} from "@beamsync/cli";

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

  it("packs more small blobs than a function call can take arguments", async () => {
    const blobs = Array.from({ length: 200_000 }, (_, i) => {
      const data = new Uint8Array([i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff]);
      return { hash: blake3Hex(data), data };
    });
    const packKey = new Uint8Array(32).fill(3);
    const pack = await encodePack(blobs, {
      compression: "zstd",
      encryption: "chacha20-poly1305",
      packKey,
      zstdCompressFn: zstdCompress,
    });
    expect(pack.blobCount).toBe(200_000);
    const decoded = await decodePack(pack.wireBytes, {
      expectedPackId: pack.packId,
      packKey,
      zstdDecompressFn: zstdDecompress,
    });
    expect(decoded.blobs.length).toBe(200_000);
    expect(Array.from(decoded.blobs[199_999].data)).toEqual(Array.from(blobs[199_999].data));
  });

  it("splits a tree of tiny files into several packs instead of one pack per 8 MiB", async () => {
    const sourceDir = path.join(tmpRoot, "src");
    await mkdir(sourceDir, { recursive: true });
    for (let i = 0; i < 1000; i++) {
      await writeFile(path.join(sourceDir, `f-${i}.txt`), `tiny ${i}\n`);
    }
    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendPromise = sendDirectory({
      serverUrl: server.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "large-host",
      maxBlobsPerPack: 300,
      onPairingCode: resolveCode,
    });
    const received = await receiveDirectory({
      serverUrl: server.httpUrl,
      targetDir: path.join(tmpRoot, "dst"),
      pairingCode: await codePromise,
      cacheDir: path.join(tmpRoot, "c2"),
      hostIdOverride: "large-host",
    });
    const sent = await sendPromise;
    expect(sent.packCount).toBe(4);
    expect(received.packsApplied).toBe(4);
    expect(received.committedFiles).toBe(1000);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
  });

  it("a cancelled scan stops walking and leaves no index behind", async () => {
    const dir = path.join(tmpRoot, "scan-src");
    const cacheDir = path.join(tmpRoot, "scan-cache");
    await mkdir(dir, { recursive: true });
    for (let i = 0; i < 400; i++) await writeFile(path.join(dir, `f${i}.txt`), `c${i}\n`);

    const abort = new AbortController();
    const scan = scanWorkspace(dir, { cacheDir, signal: abort.signal });
    abort.abort();
    await expect(scan).rejects.toThrow(/SCAN_ABORTED/);
    expect(await readdir(cacheDir)).toEqual([]);

    const full = await scanWorkspace(dir, { cacheDir, signal: new AbortController().signal });
    expect(full.manifest.entries.length).toBe(400);
    expect(full.hashedFiles).toBe(400);
  });
});
