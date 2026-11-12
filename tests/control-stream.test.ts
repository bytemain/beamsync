import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import WebSocket from "ws";
import {
  CONTROL_STREAM_SEGMENT_BYTES,
  ControlStreamLineSplitter,
  HaveBlobsStreamAssembler,
  ManifestStreamAssembler,
  blake3Hex,
  canonicalizeManifest,
  computeRootTreeDigest,
  controlStreamSegmentBytesFor,
  haveBlobsStreamRecords,
  manifestStreamRecords,
  openControlStreamSegment,
  sealControlStreamSegment,
  utf8Bytes,
  type ClientToServerWsMessage,
  type ControlStreamName,
  type ManifestEntry,
  type ServerToClientWsMessage,
  type TreeManifest,
} from "@beamsync/protocol";
import { CoordinatorEngine, R2PresignedStorageDriver } from "@beamsync/coordinator";
import { startBeamSyncServer, type RunningBeamSyncServer } from "@beamsync/server";
import {
  readControlStream,
  receiveDirectory,
  sendDirectory,
  writeControlStream,
  zstdCompress,
  zstdDecompress,
  type ControlStreamSignaling,
} from "@beamsync/cli";

type ChunkMsg = Extract<ServerToClientWsMessage, { type: "control_stream_chunk" }>;

const SESSION_ID = "11111111-2222-3333-4444-555555555555";
const CONTROL_KEY = new Uint8Array(32).fill(7);

/**
 * Two signaling endpoints joined in memory. `intercept` sees every message crossing the link and
 * returns what should be delivered instead (nothing, the same message, or several).
 */
function createLink(
  opts: {
    intercept?: (
      from: "writer" | "reader",
      msg: ServerToClientWsMessage,
    ) => ServerToClientWsMessage[];
    ackDelayMs?: number;
  } = {},
) {
  const listeners = { writer: new Set<(m: ServerToClientWsMessage) => void>(), reader: new Set<(m: ServerToClientWsMessage) => void>() };
  let sentSegments = 0;
  let ackedSegments = 0;
  let maxInFlight = 0;
  const sentToReader: ServerToClientWsMessage[] = [];

  const deliver = (to: "writer" | "reader", msg: ServerToClientWsMessage, delayMs = 0) => {
    setTimeout(() => {
      if (to === "writer" && msg.type === "control_stream_ack") {
        ackedSegments = Math.max(ackedSegments, msg.index + 1);
      }
      for (const fn of [...listeners[to]]) fn(msg);
    }, delayMs);
  };

  const endpoint = (self: "writer" | "reader"): ControlStreamSignaling => ({
    send(msg: ClientToServerWsMessage) {
      const other = self === "writer" ? "reader" : "writer";
      // The Coordinator relays these two message types unchanged
      const forwarded = msg as unknown as ServerToClientWsMessage;
      if (self === "writer" && msg.type === "control_stream_chunk") {
        sentSegments++;
        maxInFlight = Math.max(maxInFlight, sentSegments - ackedSegments);
        sentToReader.push(forwarded);
      }
      const out = opts.intercept ? opts.intercept(self, forwarded) : [forwarded];
      for (const m of out) {
        deliver(other, m, self === "reader" ? opts.ackDelayMs ?? 0 : 0);
      }
    },
    subscribe(fn) {
      listeners[self].add(fn);
      return () => listeners[self].delete(fn);
    },
  });

  return {
    writer: endpoint("writer"),
    reader: endpoint("reader"),
    inject: (to: "writer" | "reader", msg: ServerToClientWsMessage) => deliver(to, msg),
    stats: () => ({ sentSegments, maxInFlight }),
    sentToReader,
  };
}

function syntheticManifest(entryCount: number): TreeManifest {
  const entries: ManifestEntry[] = [];
  let total = 0;
  for (let i = 0; i < entryCount; i++) {
    const dir = `packages/pkg-${i % 97}/src/模块-${i % 13}`;
    if (i % 50 === 0) {
      entries.push({ kind: "symlink", relPath: `${dir}/link-${i}`, linkTarget: `file-${i}.ts`, mtimeMs: 1 });
    } else if (i % 211 === 0) {
      entries.push({ kind: "dir", relPath: `${dir}/empty-${i}`, mode: 0o755, mtimeMs: 2 });
    } else {
      const size = 100 + (i % 4000);
      total += size;
      entries.push({
        kind: "file",
        relPath: `${dir}/file-${i}-😀.ts`,
        size,
        mode: i % 7 === 0 ? 0o755 : 0o644,
        mtimeMs: 1_700_000_000_000 + i,
        blobHash: blake3Hex(utf8Bytes(`blob-${i}`)),
      });
    }
  }
  return canonicalizeManifest({ version: "beamsync-tree/v1", totalLogicalBytes: total, entries });
}

async function roundTripManifest(
  manifest: TreeManifest,
  segmentBytes: number,
  link = createLink(),
  windowSegments?: number,
) {
  const digest = computeRootTreeDigest(manifest);
  const assembler = new ManifestStreamAssembler();
  const reader = readControlStream({
    sig: link.reader,
    stream: "manifest",
    controlKey: CONTROL_KEY,
    sessionId: SESSION_ID,
    onRecord: (r) => assembler.acceptRecord(r),
  });
  const written = await writeControlStream({
    sig: link.writer,
    stream: "manifest",
    controlKey: CONTROL_KEY,
    sessionId: SESSION_ID,
    segmentBytes,
    windowSegments,
    records: manifestStreamRecords(manifest, digest),
  });
  const read = await reader.done;
  return { written, read, digest, received: assembler.finish(), link };
}

describe("sealed control stream codec", () => {
  const ctx = {
    controlKey: CONTROL_KEY,
    sessionId: SESSION_ID,
    stream: "manifest" as ControlStreamName,
    index: 3,
    final: false,
  };

  it("opens only at the exact position, stream, session and key it was sealed for", async () => {
    const raw = utf8Bytes('{"relPath":"src/secret-project/main.ts"}\n'.repeat(200));
    const sealed = await sealControlStreamSegment(ctx, raw, zstdCompress);
    expect(Buffer.from(sealed).includes("secret-project")).toBe(false);
    expect(sealed.byteLength).toBeLessThan(raw.byteLength / 4);

    const opened = await openControlStreamSegment(ctx, sealed, zstdDecompress);
    expect(Buffer.from(opened).equals(Buffer.from(raw))).toBe(true);

    const flipped = Uint8Array.from(sealed);
    flipped[flipped.length - 20] ^= 0x01;
    const wrong: Array<[string, typeof ctx, Uint8Array]> = [
      ["index", { ...ctx, index: 4 }, sealed],
      ["final flag", { ...ctx, final: true }, sealed],
      ["stream", { ...ctx, stream: "have_blobs" }, sealed],
      ["session", { ...ctx, sessionId: "another-session" }, sealed],
      ["key", { ...ctx, controlKey: new Uint8Array(32).fill(8) }, sealed],
      ["ciphertext", ctx, flipped],
    ];
    for (const [what, badCtx, bytes] of wrong) {
      await expect(
        openControlStreamSegment(badCtx, bytes, zstdDecompress),
        `wrong ${what} must not open`,
      ).rejects.toThrow(/CONTROL_STREAM_INTEGRITY/);
    }
  });

  it("splits records identically no matter where segments are cut, including inside a UTF-8 sequence", () => {
    const lines = ["", "plain", "路径/文件-😀.ts", "x".repeat(700), '{"a":"é"}', "尾"];
    const bytes = Buffer.from(`${lines.join("\n")}\n`, "utf8");
    for (const cut of [1, 2, 3, 5, 7, 64, 699, 4096]) {
      const out: string[] = [];
      const splitter = new ControlStreamLineSplitter();
      for (let off = 0; off < bytes.length; off += cut) {
        splitter.push(bytes.subarray(off, off + cut), (l) => out.push(l));
      }
      splitter.finish();
      expect(out, `cut every ${cut} bytes`).toEqual(lines);
    }

    const truncated = new ControlStreamLineSplitter();
    truncated.push(Buffer.from("complete\nincompl"), () => {});
    expect(() => truncated.finish()).toThrow(/middle of a record/);
  });

  it("sizes segments so even incompressible data fits the signaling message limit", async () => {
    for (const limit of [2048, 16 * 1024, 300 * 1024, 2 * 1024 * 1024]) {
      const segmentBytes = controlStreamSegmentBytesFor(limit);
      expect(segmentBytes).toBeLessThanOrEqual(CONTROL_STREAM_SEGMENT_BYTES);
      const sealed = await sealControlStreamSegment(
        { ...ctx, index: 123_456_789 },
        crypto.randomBytes(segmentBytes),
        zstdCompress,
      );
      const wire = JSON.stringify({
        type: "control_stream_chunk",
        stream: "have_blobs",
        index: 123_456_789,
        final: false,
        payloadBase64: Buffer.from(sealed).toString("base64"),
        cseq: 1_000_000_000,
      });
      expect(Buffer.byteLength(wire), `limit ${limit}`).toBeLessThanOrEqual(limit);
      // No more than a third is lost to base64, sealing and the envelope
      if (segmentBytes < CONTROL_STREAM_SEGMENT_BYTES) {
        expect(Buffer.byteLength(wire)).toBeGreaterThan(limit * 0.6);
      }
    }
    expect(controlStreamSegmentBytesFor(64 * 1024 * 1024)).toBe(CONTROL_STREAM_SEGMENT_BYTES);
    expect(controlStreamSegmentBytesFor(64 * 1024 * 1024, 4096)).toBe(4096);
    expect(() => controlStreamSegmentBytesFor(600)).toThrow(/too small/);
  });

  it("rejects manifests and blob lists that do not match what their header announces", () => {
    const manifest = syntheticManifest(5);
    const records = [...manifestStreamRecords(manifest, "d".repeat(64))];

    const complete = new ManifestStreamAssembler();
    records.forEach((r) => complete.acceptRecord(r));
    expect(complete.finish().manifest).toEqual(manifest);

    const short = new ManifestStreamAssembler();
    records.slice(0, -1).forEach((r) => short.acceptRecord(r));
    expect(() => short.finish()).toThrow(/carried 4 of 5 entries/);

    const long = new ManifestStreamAssembler();
    records.forEach((r) => long.acceptRecord(r));
    expect(() => long.acceptRecord(records[1])).toThrow(/more than the announced 5/);

    expect(() => new ManifestStreamAssembler().acceptRecord(records[1])).toThrow(/header/);
    expect(() => new ManifestStreamAssembler().finish()).toThrow(/before its header/);
    const bad = new ManifestStreamAssembler();
    bad.acceptRecord(records[0]);
    expect(() => bad.acceptRecord('{"kind":"file"}')).toThrow(/malformed manifest entry/);
    expect(() => bad.acceptRecord("not json")).toThrow(/not valid JSON/);

    const hashes = [blake3Hex(utf8Bytes("a")), blake3Hex(utf8Bytes("b"))];
    const have = new HaveBlobsStreamAssembler();
    [...haveBlobsStreamRecords(hashes, 2)].forEach((r) => have.acceptRecord(r));
    expect([...have.finish()]).toEqual(hashes);

    const missing = new HaveBlobsStreamAssembler();
    [...haveBlobsStreamRecords(hashes.slice(0, 1), 2)].forEach((r) => missing.acceptRecord(r));
    expect(() => missing.finish()).toThrow(/carried 1 of 2 hashes/);
    const badHash = new HaveBlobsStreamAssembler();
    badHash.acceptRecord("1");
    expect(() => badHash.acceptRecord("../../etc/passwd")).toThrow(/malformed blob hash/);
    expect(() => new HaveBlobsStreamAssembler().acceptRecord("many")).toThrow(/malformed have_blobs/);
  });
});

describe("root tree digest", () => {
  /** The digest as originally defined: one JSON document of the whole projection. */
  function referenceDigest(manifest: TreeManifest): string {
    const projection = canonicalizeManifest(manifest).entries.map((entry) => {
      if (entry.kind === "file") {
        return {
          k: "f",
          p: entry.relPath,
          s: entry.size,
          m: entry.mode & 0o777,
          b: entry.blobHash ?? null,
          c: entry.chunks ?? null,
          h: entry.hardlinkGroupId ?? null,
        };
      }
      if (entry.kind === "symlink") return { k: "l", p: entry.relPath, t: entry.linkTarget };
      return { k: "d", p: entry.relPath, m: entry.mode & 0o777 };
    });
    return blake3Hex(utf8Bytes(JSON.stringify(projection)));
  }

  it("is unchanged by hashing in batches, at every batch boundary", () => {
    for (const n of [0, 1, 2, 4095, 4096, 4097, 8192, 8193, 10_000]) {
      const manifest = syntheticManifest(n);
      if (n > 3) {
        const withChunks = manifest.entries.find((e) => e.kind === "file");
        if (withChunks?.kind === "file") {
          delete withChunks.blobHash;
          withChunks.chunks = [{ hash: blake3Hex(utf8Bytes("c")), offset: 0, length: 9 }];
          withChunks.hardlinkGroupId = "g\"1";
        }
      }
      expect(computeRootTreeDigest(manifest), `${n} entries`).toBe(referenceDigest(manifest));
    }
    // Order-independent, as before
    const shuffled = syntheticManifest(5000);
    const digest = computeRootTreeDigest(shuffled);
    shuffled.entries.reverse();
    expect(computeRootTreeDigest(shuffled)).toBe(digest);
  });
});

describe("sealed control stream transport", () => {
  it("carries a manifest across many segments, including a record larger than a segment", async () => {
    const manifest = syntheticManifest(4000);
    // One file with 3,000 chunk references: a single ~200 KiB record
    const big = manifest.entries.find((e) => e.kind === "file")!;
    if (big.kind === "file") {
      delete big.blobHash;
      big.chunks = Array.from({ length: 3000 }, (_, i) => ({
        hash: blake3Hex(utf8Bytes(`chunk-${i}`)),
        offset: i * 1024,
        length: 1024,
      }));
    }

    const { written, read, digest, received } = await roundTripManifest(manifest, 8 * 1024);
    expect(written.segments).toBeGreaterThan(50);
    expect(read).toEqual(written);
    expect(written.records).toBe(4001);
    expect(received.manifest).toEqual(manifest);
    expect(received.header.entryCount).toBe(4000);
    expect(computeRootTreeDigest(received.manifest)).toBe(digest);
    // Paths repeat, hashes do not: still well under the JSON size
    expect(written.sealedBytes).toBeLessThan(written.rawBytes * 0.7);
  });

  it("sends an empty tree as one final segment and fills segments exactly at the boundary", async () => {
    const empty = await roundTripManifest(syntheticManifest(0), 4096);
    expect(empty.written.segments).toBe(1);
    expect(empty.received.manifest.entries).toEqual([]);

    // Records sized so the stream is an exact multiple of the segment size
    const link = createLink();
    const got: string[] = [];
    const reader = readControlStream({
      sig: link.reader,
      stream: "have_blobs",
      controlKey: CONTROL_KEY,
      sessionId: SESSION_ID,
      onRecord: (r) => got.push(r),
    });
    const records = Array.from({ length: 8 }, (_, i) => String(i).repeat(63));
    const written = await writeControlStream({
      sig: link.writer,
      stream: "have_blobs",
      controlKey: CONTROL_KEY,
      sessionId: SESSION_ID,
      segmentBytes: 128,
      records,
    });
    await reader.done;
    expect(written.rawBytes).toBe(8 * 64);
    expect(written.segments).toBe(4);
    expect(got).toEqual(records);
  });

  it("never has more than the window in flight, so the Coordinator cannot be made to buffer the manifest", async () => {
    const link = createLink({ ackDelayMs: 3 });
    const { written } = await roundTripManifest(syntheticManifest(1500), 2048, link, 3);
    expect(written.segments).toBeGreaterThan(100);
    expect(link.stats().sentSegments).toBe(written.segments);
    expect(link.stats().maxInFlight).toBe(3);
  });

  const tamperCases: Array<{
    name: string;
    intercept: (state: { seen: ChunkMsg[] }, msg: ChunkMsg) => ServerToClientWsMessage[];
    expectComplete?: boolean;
    error: RegExp;
  }> = [
    {
      name: "a dropped segment",
      intercept: (_s, m) => (m.index === 4 ? [] : [m]),
      error: /expected segment 4 of "manifest", received 5/,
    },
    {
      name: "two segments swapped",
      intercept: (s, m) => {
        if (m.index === 4) return [];
        if (m.index === 5) return [m, s.seen.find((x) => x.index === 4)!];
        return [m];
      },
      error: /expected segment 4 of "manifest", received 5/,
    },
    {
      name: "a replayed segment",
      intercept: (_s, m) => (m.index === 4 ? [m, m] : [m]),
      error: /expected segment 5 of "manifest", received 4/,
    },
    {
      name: "a segment renumbered to hide a drop",
      intercept: (_s, m) => (m.index === 4 ? [] : m.index === 5 ? [{ ...m, index: 4 }] : [m]),
      error: /segment 4 of "manifest" failed authentication/,
    },
    {
      name: "an early end-of-stream marker (truncation)",
      intercept: (_s, m) => (m.index === 4 ? [{ ...m, final: true }] : [m]),
      error: /segment 4 of "manifest" failed authentication/,
    },
    {
      name: "a final segment that never arrives before the plan",
      intercept: (_s, m) => (m.final ? [] : [m]),
      expectComplete: true,
      error: /ended after \d+ segments without its final segment/,
    },
    {
      name: "altered ciphertext",
      intercept: (_s, m) => {
        if (m.index !== 4) return [m];
        const bytes = Buffer.from(m.payloadBase64, "base64");
        bytes[bytes.length - 1] ^= 0x80;
        return [{ ...m, payloadBase64: bytes.toString("base64") }];
      },
      error: /segment 4 of "manifest" failed authentication/,
    },
  ];

  for (const tc of tamperCases) {
    it(`a Coordinator cannot get away with ${tc.name}`, async () => {
      const state = { seen: [] as ChunkMsg[] };
      const link = createLink({
        intercept: (from, msg) => {
          if (from !== "writer" || msg.type !== "control_stream_chunk") return [msg];
          state.seen.push(msg);
          return tc.intercept(state, msg);
        },
      });
      const manifest = syntheticManifest(300);
      const assembler = new ManifestStreamAssembler();
      const reader = readControlStream({
        sig: link.reader,
        stream: "manifest",
        controlKey: CONTROL_KEY,
        sessionId: SESSION_ID,
        onRecord: (r) => assembler.acceptRecord(r),
      });
      reader.done.catch(() => {});
      const writing = writeControlStream({
        sig: link.writer,
        stream: "manifest",
        controlKey: CONTROL_KEY,
        sessionId: SESSION_ID,
        segmentBytes: 2048,
        // Wide enough that the writer finishes even though the reader stops acknowledging
        windowSegments: 1000,
        records: manifestStreamRecords(manifest, computeRootTreeDigest(manifest)),
      });
      const written = await writing;
      expect(written.segments).toBeGreaterThan(8);
      if (tc.expectComplete) {
        await new Promise((r) => setTimeout(r, 20));
        reader.expectComplete();
      }
      await expect(reader.done).rejects.toThrow(tc.error);
      expect(() => assembler.finish()).toThrow(/MANIFEST_INTEGRITY/);
    });
  }

  it("does not accept segments recorded from another session or another stream", async () => {
    const recorded = createLink();
    const hashes = Array.from({ length: 40 }, (_, i) => blake3Hex(utf8Bytes(`h${i}`)));
    const recordedReader = readControlStream({
      sig: recorded.reader,
      stream: "have_blobs",
      controlKey: CONTROL_KEY,
      sessionId: SESSION_ID,
      onRecord: () => {},
    });
    await writeControlStream({
      sig: recorded.writer,
      stream: "have_blobs",
      controlKey: CONTROL_KEY,
      sessionId: SESSION_ID,
      segmentBytes: 1024,
      records: haveBlobsStreamRecords(hashes, hashes.length),
    });
    await recordedReader.done;
    const first = recorded.sentToReader[0] as ChunkMsg;

    for (const [sessionId, stream] of [
      ["other-session", "have_blobs"],
      [SESSION_ID, "manifest"],
    ] as Array<[string, ControlStreamName]>) {
      const link = createLink();
      const reader = readControlStream({
        sig: link.reader,
        stream,
        controlKey: CONTROL_KEY,
        sessionId,
        onRecord: () => {},
      });
      link.inject("reader", { ...first, stream });
      await expect(reader.done).rejects.toThrow(/failed authentication/);
    }
  });

  it("a writer blocked on the window fails with the session error instead of hanging", async () => {
    // The reader side never answers
    const link = createLink({ intercept: (from, msg) => (from === "writer" ? [] : [msg]) });
    const manifest = syntheticManifest(500);
    const writing = writeControlStream({
      sig: link.writer,
      stream: "manifest",
      controlKey: CONTROL_KEY,
      sessionId: SESSION_ID,
      segmentBytes: 1024,
      windowSegments: 2,
      records: manifestStreamRecords(manifest, computeRootTreeDigest(manifest)),
    });
    writing.catch(() => {});
    await new Promise((r) => setTimeout(r, 30));
    expect(link.stats().sentSegments).toBe(2);
    link.inject("writer", {
      type: "session_error",
      code: "PEER_LOST",
      message: "The other peer disconnected",
    });
    await expect(writing).rejects.toThrow(/PEER_LOST/);
    expect(link.stats().sentSegments).toBe(2);

    const reader = readControlStream({
      sig: link.reader,
      stream: "manifest",
      controlKey: CONTROL_KEY,
      sessionId: SESSION_ID,
      onRecord: () => {},
    });
    link.inject("reader", { type: "session_error", code: "PEER_LOST", message: "gone" });
    await expect(reader.done).rejects.toThrow(/PEER_LOST/);
  });
});

describe("Coordinator relaying of control streams", () => {
  it("forwards segments only from the stream's owner, acknowledgements only from its reader, and nothing before key confirmation", async () => {
    const engine = new CoordinatorEngine({
      storageDriver: new R2PresignedStorageDriver({
        accountId: "test",
        bucket: "b",
        accessKeyId: "a",
        secretAccessKey: "s",
      }),
    });
    const created = engine.createPairingSession({ wsBaseUrl: "ws://localhost:8787" });
    const joined = engine.joinPairingSession({
      slotCode: created.slotCode,
      wsBaseUrl: "ws://localhost:8787",
    });
    const inbox = {
      source: [] as Array<Record<string, unknown>>,
      target: [] as Array<Record<string, unknown>>,
    };
    const socketFor = (role: "source" | "target") => ({
      send: (json: string) => inbox[role].push(JSON.parse(json) as Record<string, unknown>),
      close: () => {},
    });
    const sockets = { source: socketFor("source"), target: socketFor("target") };
    const cseq = { source: 0, target: 0 };
    const send = (role: "source" | "target", msg: Record<string, unknown>) =>
      engine.handleWsMessage(
        created.sessionId,
        sockets[role],
        JSON.stringify(msg.type === "hello" ? msg : { ...msg, cseq: ++cseq[role] }),
      );
    const forwarded = (role: "source" | "target", type: string) =>
      inbox[role].filter((m) => m.type === type);
    const chunk = (stream: string, index: number) => ({
      type: "control_stream_chunk",
      stream,
      index,
      final: false,
      payloadBase64: "AAAA",
    });

    await send("source", { type: "hello", role: "source", peerToken: created.peerToken });
    await send("target", { type: "hello", role: "target", peerToken: joined.peerToken });

    // Paired but not yet confirmed: a joiner that only guessed the slot cannot push data
    await send("source", chunk("manifest", 0));
    await send("target", chunk("have_blobs", 0));
    expect(forwarded("target", "control_stream_chunk")).toEqual([]);
    expect(forwarded("source", "control_stream_chunk")).toEqual([]);

    for (const role of ["source", "target"] as const) {
      await send(role, {
        type: "pake_confirm",
        confirmMacHex: "ab",
        hostFingerprint: role,
        candidates: [],
      });
    }

    await send("source", chunk("manifest", 0));
    await send("target", chunk("have_blobs", 0));
    expect(forwarded("target", "control_stream_chunk")).toMatchObject([
      { stream: "manifest", index: 0, final: false, payloadBase64: "AAAA" },
    ]);
    expect(forwarded("source", "control_stream_chunk")).toMatchObject([
      { stream: "have_blobs", index: 0 },
    ]);

    // Wrong direction, unknown stream, malformed index
    await send("target", chunk("manifest", 1));
    await send("source", chunk("have_blobs", 1));
    await send("source", chunk("something_else", 1));
    await send("source", { ...chunk("manifest", 1), index: "1" });
    await send("source", { ...chunk("manifest", 1), payloadBase64: { nested: true } });
    expect(forwarded("target", "control_stream_chunk")).toHaveLength(1);
    expect(forwarded("source", "control_stream_chunk")).toHaveLength(1);

    await send("target", { type: "control_stream_ack", stream: "manifest", index: 0 });
    await send("source", { type: "control_stream_ack", stream: "have_blobs", index: 0 });
    // A writer cannot acknowledge its own stream
    await send("source", { type: "control_stream_ack", stream: "manifest", index: 0 });
    await send("target", { type: "control_stream_ack", stream: "have_blobs", index: 0 });
    expect(forwarded("source", "control_stream_ack")).toMatchObject([{ stream: "manifest", index: 0 }]);
    expect(forwarded("target", "control_stream_ack")).toMatchObject([{ stream: "have_blobs", index: 0 }]);

    // The plan no longer has anywhere to put a manifest or ignore rules
    await send("source", {
      type: "source_transfer_plan",
      manifestEntryCount: 3,
      rootTreeDigest: "d".repeat(64),
      missingBlobCount: 0,
      missingBytesEstimate: 0,
      selectedTier: "R2_PIPELINE",
      manifest: { entries: [{ relPath: "leak.ts" }] },
      ignoreSpec: { version: 1, layers: [] },
    });
    const plan = forwarded("target", "source_transfer_plan")[0];
    expect(plan).toMatchObject({ manifestEntryCount: 3, selectedTier: "R2_PIPELINE" });
    expect(plan).not.toHaveProperty("manifest");
    expect(plan).not.toHaveProperty("ignoreSpec");
    engine.dispose();
  });
});

/** TCP forwarder whose live connections can be severed on demand (simulated network drop). */
async function startFlakyForwarder() {
  let upstreamPort = 0;
  const live = new Set<net.Socket>();
  const server = net.createServer((client) => {
    const upstream = net.connect({ host: "127.0.0.1", port: upstreamPort });
    for (const s of [client, upstream]) {
      live.add(s);
      s.on("error", () => {});
      s.once("close", () => live.delete(s));
    }
    client.pipe(upstream);
    upstream.pipe(client);
    client.once("close", () => upstream.destroy());
    upstream.once("close", () => client.destroy());
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as net.AddressInfo).port;
  return {
    port,
    setUpstreamPort: (p: number) => {
      upstreamPort = p;
    },
    severAll: () => {
      const n = live.size;
      for (const s of live) s.destroy();
      return n;
    },
    close: async () => {
      for (const s of live) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

async function writeNumberedFiles(
  dir: string,
  count: number,
  body: (i: number) => string,
  name: (i: number) => string = (i) => `module-${i}.ts`,
): Promise<void> {
  await mkdir(dir, { recursive: true });
  for (let i = 0; i < count; i += 64) {
    await Promise.all(
      Array.from({ length: Math.min(64, count - i) }, (_, k) =>
        writeFile(path.join(dir, name(i + k)), body(i + k)),
      ),
    );
  }
}

describe("transfers whose control data spans many signaling messages", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer | undefined;
  const cleanups: Array<() => Promise<void>> = [];

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-ctl-"));
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await server?.close();
    server = undefined;
    for (const fn of cleanups.splice(0)) await fn();
    await rm(tmpRoot, { recursive: true, force: true });
  });

  const startServer = async (extra: Record<string, unknown> = {}) => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      publicStunHost: "127.0.0.1",
      dataDir: path.join(tmpRoot, "server-data"),
      ...extra,
    });
    return server;
  };

  it("keeps file names and ignore rules out of everything the Coordinator relays", async () => {
    await startServer();
    const sourceDir = path.join(tmpRoot, "src");
    await writeNumberedFiles(
      path.join(sourceDir, "project-nightingale"),
      40,
      (i) => `export const v${i} = ${i};\n`,
      (i) => `acquisition-plan-${i}.ts`,
    );
    await writeFile(path.join(sourceDir, "notes.confidential"), "skip me\n");

    const frames: string[] = [];
    const realSend = WebSocket.prototype.send;
    vi.spyOn(WebSocket.prototype, "send").mockImplementation(function (
      this: WebSocket,
      ...args: unknown[]
    ) {
      const data = args[0];
      frames.push(typeof data === "string" ? data : Buffer.from(data as Buffer).toString("latin1"));
      return (realSend as (...a: unknown[]) => void).apply(this, args);
    });

    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendPromise = sendDirectory({
      serverUrl: server!.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "ctl-host",
      extraIgnoreRules: ["*.confidential"],
      controlStreamSegmentBytes: 1024,
      onPairingCode: resolveCode,
    });
    const received = await receiveDirectory({
      serverUrl: server!.httpUrl,
      targetDir: path.join(tmpRoot, "dst"),
      pairingCode: await codePromise,
      cacheDir: path.join(tmpRoot, "c2"),
      hostIdOverride: "ctl-host",
    });
    const sent = await sendPromise;

    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
    expect(sent.manifestEntries).toBe(40);
    expect(received.manifestEntries).toBe(40);
    expect(sent.manifestSegments).toBeGreaterThan(3);
    expect(received.manifestSegments).toBe(sent.manifestSegments);
    expect(sent.ignoredPaths).toBe(1);
    expect((await readdir(path.join(tmpRoot, "dst", "project-nightingale"))).length).toBe(40);

    const all = frames.join("\n");
    const types = new Set(
      frames.flatMap((f) => {
        try {
          return [(JSON.parse(f) as { type?: string }).type];
        } catch {
          return [];
        }
      }),
    );
    // The spy really sees the signaling traffic of both peers and the Coordinator
    expect(types).toContain("control_stream_chunk");
    expect(types).toContain("control_stream_ack");
    expect(types).toContain("source_transfer_plan");
    expect(types).toContain("peer_confirmed");
    expect(types).not.toContain("target_have_blobs");
    // Besides the frames as sent, look inside every relayed payload the way a curious relay
    // could: base64-decoded, and decompressed in case it was only compressed
    const views: string[] = [all];
    let payloads = 0;
    for (const frame of frames) {
      let payloadBase64: unknown;
      try {
        payloadBase64 = (JSON.parse(frame) as { payloadBase64?: unknown }).payloadBase64;
      } catch {
        continue;
      }
      if (typeof payloadBase64 !== "string") continue;
      payloads++;
      const bytes = Buffer.from(payloadBase64, "base64");
      views.push(bytes.toString("latin1"));
      for (const candidate of [bytes, bytes.subarray(12)]) {
        try {
          views.push(Buffer.from(await zstdDecompress(candidate)).toString("latin1"));
        } catch {
          // Not a zstd frame, as expected for sealed data
        }
      }
    }
    expect(payloads).toBeGreaterThan(3);
    for (const secret of ["nightingale", "acquisition-plan", "confidential", "relPath", "blobHash"]) {
      expect(
        views.some((v) => v.includes(secret)),
        `"${secret}" must not be readable by the Coordinator`,
      ).toBe(false);
    }
  });

  it("refuses a plan the Coordinator rewrote so it no longer matches the sealed manifest, before touching the target", async () => {
    await startServer({ peerLossGraceMs: 300 });
    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    await writeNumberedFiles(sourceDir, 30, (i) => `new ${i}\n`);
    await mkdir(targetDir, { recursive: true });
    await writeFile(path.join(targetDir, "keep.txt"), "old\n");

    let rewritten = 0;
    const realSend = WebSocket.prototype.send;
    vi.spyOn(WebSocket.prototype, "send").mockImplementation(function (
      this: WebSocket,
      ...args: unknown[]
    ) {
      const data = args[0];
      // Coordinator -> target copy of the plan (server frames carry `sseq`)
      if (
        typeof data === "string" &&
        data.includes('"type":"source_transfer_plan"') &&
        data.includes('"sseq"')
      ) {
        const plan = JSON.parse(data) as { rootTreeDigest: string };
        plan.rootTreeDigest = "0".repeat(64);
        args[0] = JSON.stringify(plan);
        rewritten++;
      }
      return (realSend as (...a: unknown[]) => void).apply(this, args);
    });

    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendPromise = sendDirectory({
      serverUrl: server!.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "ctl-host",
      onPairingCode: resolveCode,
    });
    sendPromise.catch(() => {});
    await expect(
      receiveDirectory({
        serverUrl: server!.httpUrl,
        targetDir,
        pairingCode: await codePromise,
        cacheDir: path.join(tmpRoot, "c2"),
        hostIdOverride: "ctl-host",
      }),
    ).rejects.toThrow(/MANIFEST_INTEGRITY: the transfer plan does not match/);
    expect(rewritten).toBe(1);
    // The sender is not left waiting: its direct channel closes, or it is told the peer left
    await expect(sendPromise).rejects.toThrow(/PEER_LOST|closed/);
    expect(await readdir(targetDir)).toEqual(["keep.txt"]);
    expect((await readdir(tmpRoot)).filter((n) => n.includes("staging"))).toEqual([]);
  });

  it("stops right after pairing when the other side or the Coordinator does not speak this protocol version", async () => {
    await startServer({ peerLossGraceMs: 300 });
    const sourceDir = path.join(tmpRoot, "src");
    await writeNumberedFiles(sourceDir, 3, (i) => `v${i}\n`);

    // What an older Coordinator does: relay the confirmation without a version
    const realSend = WebSocket.prototype.send;
    vi.spyOn(WebSocket.prototype, "send").mockImplementation(function (
      this: WebSocket,
      ...args: unknown[]
    ) {
      const data = args[0];
      if (typeof data === "string" && data.includes('"type":"peer_confirmed"')) {
        const msg = JSON.parse(data) as { peerProtocolVersion?: number };
        expect(msg.peerProtocolVersion).toBe(2);
        delete msg.peerProtocolVersion;
        args[0] = JSON.stringify(msg);
      }
      return (realSend as (...a: unknown[]) => void).apply(this, args);
    });

    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const startedAt = Date.now();
    const sendPromise = sendDirectory({
      serverUrl: server!.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "ctl-host",
      onPairingCode: resolveCode,
    });
    sendPromise.catch(() => {});
    const receivePromise = receiveDirectory({
      serverUrl: server!.httpUrl,
      targetDir: path.join(tmpRoot, "dst"),
      pairingCode: await codePromise,
      cacheDir: path.join(tmpRoot, "c2"),
      hostIdOverride: "ctl-host",
    });
    receivePromise.catch(() => {});
    await expect(sendPromise).rejects.toThrow(/PROTOCOL_VERSION_MISMATCH.*older build/);
    await expect(receivePromise).rejects.toThrow(/PROTOCOL_VERSION_MISMATCH.*older build/);
    expect(Date.now() - startedAt).toBeLessThan(5000);
    expect((await readdir(tmpRoot)).filter((n) => n.startsWith("dst"))).toEqual([]);
  });

  it("transfers a tree whose manifest is several times the signaling message limit", async () => {
    await startServer({ peerLossGraceMs: 300 });
    const sourceDir = path.join(tmpRoot, "src");
    await writeNumberedFiles(path.join(sourceDir, "node_modules", "pkg"), 1200, (i) => `// ${i}\n`);
    await writeFile(path.join(sourceDir, "main.ts"), "main\n");

    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendPhases: string[] = [];
    const sendPromise = sendDirectory({
      serverUrl: server!.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "ctl-host",
      // Stand-in for the 32 MiB limit: the ~250 KiB manifest is 15x one message
      maxSignalingMessageBytes: 16 * 1024,
      onPairingCode: resolveCode,
      onProgress: (ev) => sendPhases.push(ev.phase),
    });
    const received = await receiveDirectory({
      serverUrl: server!.httpUrl,
      targetDir: path.join(tmpRoot, "dst"),
      pairingCode: await codePromise,
      cacheDir: path.join(tmpRoot, "c2"),
      hostIdOverride: "ctl-host",
      maxSignalingMessageBytes: 16 * 1024,
    });
    const sent = await sendPromise;

    expect(sent.manifestEntries).toBe(1201);
    expect(sent.manifestSegments).toBeGreaterThanOrEqual(15);
    expect(received.manifestSegments).toBe(sent.manifestSegments);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
    expect(received.committedFiles).toBe(1201);
    expect(sent.signalingReconnects).toBe(0);
    expect(received.signalingReconnects).toBe(0);
    expect(sendPhases).toContain("manifest_sent");
    expect((await readdir(path.join(tmpRoot, "dst", "node_modules", "pkg"))).length).toBe(1200);
    expect(await readFile(path.join(tmpRoot, "dst", "node_modules", "pkg", "module-1199.ts"), "utf8")).toBe(
      "// 1199\n",
    );
  });

  it("reports what the target already has across many segments, so only new blobs are sent", async () => {
    await startServer();
    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    const body = (i: number) => `unique content ${i} ${"x".repeat(i % 50)}\n`;
    await writeNumberedFiles(sourceDir, 900, body);
    // The target already holds 700 of the 900 blobs, plus 150 the source does not have
    await writeNumberedFiles(targetDir, 700, body);
    await writeNumberedFiles(targetDir, 150, (i) => `stale ${i}\n`, (i) => `stale-${i}.ts`);

    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendDetails: string[] = [];
    const receiveDetails = new Map<string, string>();
    const sendPromise = sendDirectory({
      serverUrl: server!.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "c1"),
      hostIdOverride: "ctl-host",
      onPairingCode: resolveCode,
      onProgress: (ev) => {
        if (ev.phase === "streaming") sendDetails.push(ev.detail ?? "");
      },
    });
    const received = await receiveDirectory({
      serverUrl: server!.httpUrl,
      targetDir,
      pairingCode: await codePromise,
      cacheDir: path.join(tmpRoot, "c2"),
      hostIdOverride: "ctl-host",
      controlStreamSegmentBytes: 2048,
      controlStreamWindowSegments: 2,
      onProgress: (ev) => receiveDetails.set(ev.phase, ev.detail ?? ""),
    });
    const sent = await sendPromise;

    const haveBlobs = /blobs=(\d+) segments=(\d+)/.exec(receiveDetails.get("have_blobs_sent") ?? "");
    expect(haveBlobs, receiveDetails.get("have_blobs_sent")).not.toBeNull();
    expect(Number(haveBlobs![1])).toBe(850);
    // 850 hashes x 65 bytes in 2 KiB segments
    expect(Number(haveBlobs![2])).toBeGreaterThanOrEqual(27);
    expect(sendDetails[0]).toMatch(/^missing=200 blobs/);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
    const names = await readdir(targetDir);
    expect(names.filter((n) => n.startsWith("module-")).length).toBe(900);
    expect(names.filter((n) => n.startsWith("stale-")).length).toBe(0);
    expect(await readFile(path.join(targetDir, "module-899.ts"), "utf8")).toBe(body(899));
  });

  it("resumes a signaling connection severed while the manifest is in flight without losing or repeating a segment", async () => {
    const forwarder = await startFlakyForwarder();
    cleanups.push(forwarder.close);
    await startServer({
      stunPort: null,
      publicUrl: `http://127.0.0.1:${forwarder.port}`,
      peerLossGraceMs: 2000,
    });
    forwarder.setUpstreamPort(server!.port);
    const viaForwarder = `http://127.0.0.1:${forwarder.port}`;

    const sourceDir = path.join(tmpRoot, "src");
    await writeNumberedFiles(sourceDir, 2500, (i) => `// file ${i}\n`);

    const phrase = "manifest-resume-test";
    let manifestSent = false;
    let seversDuringManifest = 0;
    const [sent, received] = await Promise.all([
      sendDirectory({
        serverUrl: viaForwarder,
        sourceDir,
        cacheDir: path.join(tmpRoot, "c1"),
        customSecretWords: phrase,
        forceTier: "R2_PIPELINE",
        controlStreamSegmentBytes: 512,
        controlStreamWindowSegments: 2,
        onProgress: (ev) => {
          if (ev.phase === "manifest_sending") {
            for (const delayMs of [15, 90, 180]) {
              setTimeout(() => {
                if (manifestSent) return;
                seversDuringManifest++;
                forwarder.severAll();
              }, delayMs);
            }
          } else if (ev.phase === "manifest_sent") {
            manifestSent = true;
          }
        },
      }),
      receiveDirectory({
        serverUrl: viaForwarder,
        targetDir: path.join(tmpRoot, "dst"),
        cacheDir: path.join(tmpRoot, "c2"),
        pairingCode: phrase,
        controlStreamSegmentBytes: 512,
      }),
    ]);

    // The sever landed while segments were still outstanding, not before or after the stream
    expect(seversDuringManifest).toBeGreaterThanOrEqual(1);
    expect(sent.signalingReconnects).toBeGreaterThanOrEqual(1);
    expect(received.signalingReconnects).toBeGreaterThanOrEqual(1);
    expect(sent.manifestSegments).toBeGreaterThan(500);
    expect(received.manifestSegments).toBe(sent.manifestSegments);
    expect(received.manifestEntries).toBe(2500);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
    expect((await readdir(path.join(tmpRoot, "dst"))).filter((n) => n.startsWith("module-")).length).toBe(2500);
  });
});
