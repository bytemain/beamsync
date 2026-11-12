import { afterEach, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import net from "node:net";
import { mkdir, mkdtemp, open, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  FastCdcStreamChunker,
  blake3Hex,
  fastCdcChunk,
  type ContentChunkRef,
  type FastCdcOptions,
} from "@beamsync/protocol";
import { FramedSocketChannel, chunkFileStreaming, scanWorkspace } from "@beamsync/cli";

/** xorshift32: the same bytes on every run and every machine. */
function deterministicBytes(seed: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed >>> 0;
  for (let i = 0; i < length; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

const refs = (chunks: ReadonlyArray<ContentChunkRef>) =>
  chunks.map((c) => [c.offset, c.length, c.hash] as const);

const fingerprint = (chunks: ReadonlyArray<ContentChunkRef>) =>
  blake3Hex(new TextEncoder().encode(JSON.stringify(refs(chunks))));

function streamChunks(
  data: Uint8Array,
  options: FastCdcOptions | undefined,
  nextPieceLength: () => number,
): ContentChunkRef[] {
  const chunker = new FastCdcStreamChunker(options);
  const out: ContentChunkRef[] = [];
  let at = 0;
  while (at < data.length) {
    const n = Math.max(1, Math.min(data.length - at, nextPieceLength()));
    out.push(...chunker.push(data.subarray(at, at + n)));
    at += n;
  }
  out.push(...chunker.finish());
  return out;
}

const SMALL_CDC: FastCdcOptions = { minSize: 1024, avgSize: 4096, maxSize: 16384 };

describe("content-defined chunking of files of any size", () => {
  // Fingerprints of the chunk lists produced by the whole-buffer chunker before streaming
  // existed. Changing a boundary would invalidate every index cache and every stored chunk.
  const PINNED = [
    {
      name: "1 MiB, small chunk sizes",
      data: () => deterministicBytes(0x1234567, 1024 * 1024),
      options: SMALL_CDC as FastCdcOptions | undefined,
      count: 217,
      fingerprint: "e1cc1324bc3b4954bc1a3bb0a4143c20b62ed9f20dddf9db4451713bab3cb407",
    },
    {
      name: "40 MiB, default chunk sizes",
      data: () => deterministicBytes(0xdeadbeef, 40 * 1024 * 1024 + 12345),
      options: undefined,
      count: 8,
      fingerprint: "f78d457039a82d24d3b4fb768c27ddbceb4245690e21b3886a4e7b4b41c87d0f",
    },
    {
      name: "100,000 zero bytes",
      data: () => new Uint8Array(100000),
      options: SMALL_CDC as FastCdcOptions | undefined,
      count: 7,
      fingerprint: "ef4911b4d18a06739c3d59f6e55af933aa4c9f9ed74ed804b79661d0c75c95f4",
    },
  ];

  for (const pin of PINNED) {
    it(`keeps the chunk boundaries of earlier versions: ${pin.name}`, () => {
      const data = pin.data();
      const whole = fastCdcChunk(data, pin.options);
      expect(whole.length).toBe(pin.count);
      expect(fingerprint(whole)).toBe(pin.fingerprint);

      const streamed = streamChunks(data, pin.options, () => 1_000_003);
      expect(streamed.length).toBe(pin.count);
      expect(fingerprint(streamed)).toBe(pin.fingerprint);
    });
  }

  it("streams to the same chunks as the whole-buffer chunker for any sizes and any way of slicing the input", () => {
    const optionSets: FastCdcOptions[] = [
      SMALL_CDC,
      { minSize: 64, avgSize: 256, maxSize: 1024 },
      { minSize: 1, avgSize: 300, maxSize: 301 },
      { minSize: 500, avgSize: 500, maxSize: 500 },
      // Degenerate: the minimum is not below the maximum
      { minSize: 2000, avgSize: 1024, maxSize: 1500 },
      { minSize: 4096, avgSize: 512, maxSize: 4096 },
    ];
    const rnd = crypto.createHash("sha256").update("beamsync-large-file").digest();
    let r = rnd.readUInt32LE(0);
    const next = (bound: number) => {
      r ^= r << 13;
      r >>>= 0;
      r ^= r >>> 17;
      r ^= r << 5;
      r >>>= 0;
      return r % bound;
    };

    let compared = 0;
    for (const options of optionSets) {
      const min = options.minSize!;
      const max = options.maxSize!;
      const lengths = new Set<number>([0, 1, min - 1, min, min + 1, max - 1, max, max + 1]);
      lengths.add(2 * max).add(2 * max + 1).add(max + min).add(max + min + 1);
      for (let i = 0; i < 12; i++) lengths.add(next(40 * max));
      for (const length of lengths) {
        if (length < 0) continue;
        // Low-entropy content makes boundaries land on the forced maximum as well
        const data =
          length % 3 === 0
            ? new Uint8Array(length).fill(next(256))
            : deterministicBytes(next(1 << 30) + 1, length);
        const whole = refs(fastCdcChunk(data, options));
        for (const piece of [
          () => 1,
          () => 7,
          () => max,
          () => max + 1,
          () => 10 * max,
          () => 1 + next(3 * max),
        ]) {
          expect(refs(streamChunks(data, options, piece))).toEqual(whole);
          compared++;
        }
        // The chunk list covers the content exactly once, in order
        let at = 0;
        for (const [offset, len, hash] of whole) {
          expect(offset).toBe(at);
          expect(len).toBeGreaterThan(0);
          expect(hash).toBe(blake3Hex(data.subarray(offset, offset + len)));
          at += len;
        }
        expect(at).toBe(length);
      }
    }
    expect(compared).toBeGreaterThan(500);
  });

  it("buffers a bounded amount no matter how much content passes through", () => {
    const chunker = new FastCdcStreamChunker(SMALL_CDC);
    const piece = deterministicBytes(99, 50_000);
    let emittedBytes = 0;
    let maxBuffered = 0;
    for (let i = 0; i < 400; i++) {
      for (const c of chunker.push(piece)) emittedBytes += c.length;
      maxBuffered = Math.max(maxBuffered, chunker.bufferedBytes);
    }
    for (const c of chunker.finish()) emittedBytes += c.length;
    expect(emittedBytes).toBe(400 * 50_000);
    expect(maxBuffered).toBeLessThanOrEqual(SMALL_CDC.maxSize!);
    expect(chunker.bufferedBytes).toBe(0);
    expect(() => chunker.push(piece)).toThrow(/after finish/);
  });

  describe("on disk", () => {
    let tmpRoot: string;

    beforeEach(async () => {
      tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-bigfile-"));
    });

    afterEach(async () => {
      await rm(tmpRoot, { recursive: true, force: true });
    });

    it("chunks a file read in blocks exactly as if it had been loaded whole", async () => {
      const data = deterministicBytes(4242, 700_001);
      const file = path.join(tmpRoot, "blob.bin");
      await writeFile(file, data);
      const whole = refs(fastCdcChunk(data, SMALL_CDC));
      expect(whole.length).toBeGreaterThan(50);

      for (const readBlockBytes of [999, 4096, 16384, 16385, 1 << 20]) {
        const streamed = await chunkFileStreaming(file, { cdcOptions: SMALL_CDC, readBlockBytes });
        expect(refs(streamed)).toEqual(whole);
      }

      const short = path.join(tmpRoot, "short.bin");
      await writeFile(short, data.subarray(0, 40_000));
      expect(
        refs(await chunkFileStreaming(short, { cdcOptions: SMALL_CDC, readBlockBytes: 1 })),
      ).toEqual(refs(fastCdcChunk(data.subarray(0, 40_000), SMALL_CDC)));

      const empty = path.join(tmpRoot, "empty.bin");
      await writeFile(empty, new Uint8Array(0));
      expect(await chunkFileStreaming(empty, { cdcOptions: SMALL_CDC })).toEqual([]);
    });

    it("a workspace scan records the same chunks whatever the read block size, and reuses them from the index", async () => {
      const dir = path.join(tmpRoot, "ws");
      await mkdir(path.join(dir, "sub"), { recursive: true });
      const big = deterministicBytes(77, 300_000);
      await writeFile(path.join(dir, "sub", "big.bin"), big);
      await writeFile(path.join(dir, "small.txt"), "hello\n");
      const expected = fastCdcChunk(big, SMALL_CDC).map((c) => ({
        hash: c.hash,
        offset: c.offset,
        length: c.length,
      }));

      const digests = new Set<string>();
      for (const readBlockBytes of [777, 65536, undefined]) {
        const scan = await scanWorkspace(dir, {
          cacheDir: path.join(tmpRoot, `cache-${readBlockBytes}`),
          smallFileThresholdBytes: 4096,
          cdcOptions: SMALL_CDC,
          readBlockBytes,
        });
        const entry = scan.manifest.entries.find((e) => e.relPath === "sub/big.bin");
        expect(entry).toMatchObject({ kind: "file", size: 300_000 });
        expect((entry as { chunks?: unknown }).chunks).toEqual(expected);
        expect(scan.hashedFiles).toBe(2);
        for (const c of expected) {
          expect(scan.blobSlices.get(c.hash)).toMatchObject({ offset: c.offset, length: c.length });
        }
        digests.add(scan.rootTreeDigest);
      }
      expect(digests.size).toBe(1);

      const again = await scanWorkspace(dir, {
        cacheDir: path.join(tmpRoot, "cache-777"),
        smallFileThresholdBytes: 4096,
        cdcOptions: SMALL_CDC,
      });
      expect(again.hashedFiles).toBe(0);
      expect(again.cachedFileHits).toBe(2);
      expect(again.rootTreeDigest).toBe([...digests][0]);
    });

    it("cancelling stops in the middle of a large file", async () => {
      const file = path.join(tmpRoot, "blob.bin");
      await writeFile(file, deterministicBytes(5, 200_000));
      let checks = 0;
      const signal = {
        get aborted() {
          checks++;
          return checks > 3;
        },
      } as unknown as AbortSignal;
      await expect(
        chunkFileStreaming(file, { cdcOptions: SMALL_CDC, readBlockBytes: 10_000, signal }),
      ).rejects.toThrow(/SCAN_ABORTED/);
      // Three blocks were read, the fourth check stopped it; the file has twenty
      expect(checks).toBe(4);
    });

    // About 2.2 GiB are hashed, which takes minutes with the pure-JS hash: opt in with
    // BEAMSYNC_HEAVY_TESTS=1
    it.skipIf(!process.env.BEAMSYNC_HEAVY_TESTS)(
      "scans a file larger than 2 GiB with flat memory use",
      async () => {
        const dir = path.join(tmpRoot, "ws");
        await mkdir(dir, { recursive: true });
        const file = path.join(dir, "disk.img");
        const size = 2 * 1024 * 1024 * 1024 + 200 * 1024 * 1024 + 4321;
        // Sparse, with real content at the start, across the 2 GiB mark, and at the end
        const islands: Array<[number, Uint8Array]> = [
          [0, deterministicBytes(1, 3_000_000)],
          [2 * 1024 * 1024 * 1024 - 1_500_000, deterministicBytes(2, 3_000_000)],
          [size - 2_000_000, deterministicBytes(3, 2_000_000)],
        ];
        const fh = await open(file, "w");
        try {
          await fh.truncate(size);
          for (const [offset, bytes] of islands) await fh.write(bytes, 0, bytes.length, offset);
        } finally {
          await fh.close();
        }
        expect((await stat(file)).size).toBe(size);

        const rssBefore = process.memoryUsage().rss;
        let rssPeak = rssBefore;
        const sampler = setInterval(() => {
          rssPeak = Math.max(rssPeak, process.memoryUsage().rss);
        }, 50);
        let scan;
        try {
          scan = await scanWorkspace(dir, { cacheDir: path.join(tmpRoot, "cache") });
        } finally {
          clearInterval(sampler);
        }
        const entry = scan.manifest.entries.find((e) => e.relPath === "disk.img") as {
          size: number;
          chunks: Array<{ hash: string; offset: number; length: number }>;
        };
        expect(entry.size).toBe(size);
        let at = 0;
        for (const c of entry.chunks) {
          expect(c.offset).toBe(at);
          at += c.length;
        }
        expect(at).toBe(size);

        // Chunks that overlap real content hash to what is on disk at their offsets
        const rfh = await open(file, "r");
        try {
          let verified = 0;
          for (const c of entry.chunks) {
            const touchesIsland = islands.some(
              ([o, b]) => c.offset < o + b.length && o < c.offset + c.length,
            );
            if (!touchesIsland) continue;
            const buf = Buffer.alloc(c.length);
            await rfh.read(buf, 0, c.length, c.offset);
            expect(blake3Hex(buf)).toBe(c.hash);
            verified++;
          }
          expect(verified).toBeGreaterThanOrEqual(3);
        } finally {
          await rfh.close();
        }

        console.log(
          JSON.stringify({
            chunks: entry.chunks.length,
            rssBeforeMiB: Math.round(rssBefore / 2 ** 20),
            rssPeakMiB: Math.round(rssPeak / 2 ** 20),
          }),
        );
        expect(rssPeak - rssBefore).toBeLessThan(400 * 1024 * 1024);
      },
      20 * 60 * 1000,
    );
  });

  it("reads a whole small file the same way as before", async () => {
    const tmp = await mkdtemp(path.join(os.tmpdir(), "beamsync-bigfile-small-"));
    try {
      const content = deterministicBytes(8, 5000);
      await writeFile(path.join(tmp, "a.bin"), content);
      const scan = await scanWorkspace(tmp, { cacheDir: path.join(tmp, ".cache-outside") });
      const entry = scan.manifest.entries.find((e) => e.relPath === "a.bin") as {
        blobHash?: string;
        chunks?: unknown;
      };
      expect(entry.blobHash).toBe(blake3Hex(content));
      expect(entry.chunks).toBeUndefined();
      expect(blake3Hex(await readFile(path.join(tmp, "a.bin")))).toBe(entry.blobHash);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });
});

describe("a direct stream that carries many packs", () => {
  it("does not accumulate socket listeners while it waits for the receiver", async () => {
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as net.AddressInfo).port;
    const acceptedPromise = new Promise<net.Socket>((resolve) => server.once("connection", resolve));
    const clientSock = net.connect(port, "127.0.0.1");
    await new Promise<void>((resolve) => clientSock.once("connect", resolve));
    const serverSock = await acceptedPromise;

    try {
      const sender = new FramedSocketChannel(clientSock);
      const receiver = new FramedSocketChannel(serverSock);
      const baseline = {
        error: clientSock.listenerCount("error"),
        drain: clientSock.listenerCount("drain"),
        close: clientSock.listenerCount("close"),
      };

      const frames = 40;
      // Larger than the loopback socket buffers, so most writes have to wait for the receiver
      const body = new Uint8Array(4 * 1024 * 1024).fill(7);
      let backpressuredWrites = 0;
      const realWrite = clientSock.write.bind(clientSock);
      clientSock.write = ((...args: unknown[]) => {
        const ok = (realWrite as (...a: unknown[]) => boolean)(...args);
        if (!ok) backpressuredWrites++;
        return ok;
      }) as typeof clientSock.write;

      let maxErrorListeners = 0;
      const receiving = (async () => {
        for (let i = 0; i < frames; i++) {
          const frame = await receiver.nextFrame(20_000);
          expect(frame.type).toBe(0x10);
          expect(frame.body.length).toBe(body.length);
        }
      })();
      for (let i = 0; i < frames; i++) {
        const pending = sender.sendFrame(0x10, body);
        maxErrorListeners = Math.max(maxErrorListeners, clientSock.listenerCount("error"));
        await pending;
      }
      await receiving;

      // The scenario really exercised the wait-for-drain path, many times
      expect(backpressuredWrites).toBeGreaterThanOrEqual(20);
      expect(maxErrorListeners).toBeLessThanOrEqual(baseline.error + 1);
      expect(clientSock.listenerCount("error")).toBe(baseline.error);
      expect(clientSock.listenerCount("drain")).toBe(baseline.drain);
      expect(clientSock.listenerCount("close")).toBe(baseline.close);
    } finally {
      clientSock.destroy();
      serverSock.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("a send that is waiting for the receiver fails when the connection goes away", async () => {
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as net.AddressInfo).port;
    const acceptedPromise = new Promise<net.Socket>((resolve) => server.once("connection", resolve));
    const clientSock = net.connect(port, "127.0.0.1");
    await new Promise<void>((resolve) => clientSock.once("connect", resolve));
    const serverSock = await acceptedPromise;
    serverSock.pause();

    try {
      const sender = new FramedSocketChannel(clientSock);
      // Far more than the kernel buffers hold while nobody reads
      const pending = sender.sendFrame(0x10, new Uint8Array(32 * 1024 * 1024));
      const outcome = pending.then(
        () => "resolved",
        (err: Error) => `rejected: ${err.message}`,
      );
      await new Promise((resolve) => setTimeout(resolve, 100));
      serverSock.destroy();
      clientSock.destroy();
      expect(await outcome).toMatch(/^rejected: /);
      expect(clientSock.listenerCount("drain")).toBe(0);
    } finally {
      clientSock.destroy();
      serverSock.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
