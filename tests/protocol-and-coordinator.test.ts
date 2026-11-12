import { describe, expect, it } from "vitest";
import {
  blake3Hex,
  decodePack,
  encodePack,
  evaluateSessionEquilibrium,
  fastCdcChunk,
  PakeHandshake,
  parsePairingPhrase,
  presignR2Url,
  randomBytes,
  utf8Bytes,
  type PackReceiptRow,
} from "@beamsync/protocol";
import {
  CoordinatorEngine,
  R2PresignedStorageDriver,
} from "@beamsync/coordinator";
import { zstdCompress, zstdDecompress } from "@beamsync/cli";

describe("BeamSync protocol primitives & coordinator equilibrium", () => {
  it("completes PAKE key exchange on matching phrases and rejects mismatches", () => {
    const parsed = parsePairingPhrase("105-amber-falcon-river");
    expect(parsed.slotCode).toBe("105");
    expect(parsed.secretPhrase).toBe("amber-falcon-river");

    const source = new PakeHandshake("source", "sess-1", parsed.secretPhrase);
    const target = new PakeHandshake("target", "sess-1", parsed.secretPhrase);

    const sFin = source.finish(target.getPublicMessage());
    const tFin = target.finish(source.getPublicMessage());

    expect(sFin.myConfirmMacHex).toBe(tFin.expectedPeerConfirmMacHex);
    expect(tFin.myConfirmMacHex).toBe(sFin.expectedPeerConfirmMacHex);
    expect(Buffer.from(sFin.keys.packKey).equals(Buffer.from(tFin.keys.packKey))).toBe(true);

    const wrongTarget = new PakeHandshake("target", "sess-1", "amber-falcon-stone");
    const sWrong = source.finish(wrongTarget.getPublicMessage());
    const wFin = wrongTarget.finish(source.getPublicMessage());
    expect(wFin.myConfirmMacHex).not.toBe(sWrong.expectedPeerConfirmMacHex);
  });

  it("preserves unchanged FastCDC chunks when modifying the middle of a large file", () => {
    const size = 2 * 1024 * 1024;
    const original = new Uint8Array(size);
    // Deterministic pseudo-random fill
    let seed = 0x12345678;
    for (let i = 0; i < size; i++) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      original[i] = seed & 0xff;
    }

    const cdcOpts = { minSize: 64 * 1024, avgSize: 256 * 1024, maxSize: 512 * 1024 };
    const chunksBefore = fastCdcChunk(original, cdcOpts);
    expect(chunksBefore.length).toBeGreaterThanOrEqual(4);

    const modified = new Uint8Array(original);
    const mid = Math.floor(size / 2);
    modified.set(utf8Bytes("MODIFIED_MIDDLE_REGION_PAYLOAD"), mid);

    const chunksAfter = fastCdcChunk(modified, cdcOpts);
    const beforeHashes = new Set(chunksBefore.map((c) => c.hash));
    let reusedBytes = 0;
    for (const ch of chunksAfter) {
      if (beforeHashes.has(ch.hash)) {
        reusedBytes += ch.length;
      }
    }
    expect(reusedBytes).toBeGreaterThan(size * 0.55);
  });

  it("encodes, compresses, encrypts, decodes, and detects tampering in BMSP packs", async () => {
    const key = randomBytes(32);
    const b1 = utf8Bytes("export const hello = 'world';\n".repeat(100));
    const b2 = utf8Bytes("function sum(a: number, b: number) { return a + b; }\n".repeat(80));

    const encoded = await encodePack(
      [
        { hash: blake3Hex(b1), data: b1 },
        { hash: blake3Hex(b2), data: b2 },
      ],
      {
        compression: "zstd",
        encryption: "chacha20-poly1305",
        packKey: key,
        zstdCompressFn: zstdCompress,
      },
    );

    expect(encoded.wireBytes.length).toBeLessThan(encoded.uncompressedBytes / 3);

    const decoded = await decodePack(encoded.wireBytes, {
      expectedPackId: encoded.packId,
      packKey: key,
      zstdDecompressFn: zstdDecompress,
    });
    expect(decoded.blobs).toHaveLength(2);
    expect(Buffer.from(decoded.blobs[0].data).equals(Buffer.from(b1))).toBe(true);
    expect(Buffer.from(decoded.blobs[1].data).equals(Buffer.from(b2))).toBe(true);

    // Flip 1 bit in ciphertext: must fail digest & AEAD authentication
    const tampered = new Uint8Array(encoded.wireBytes);
    tampered[tampered.length - 5] ^= 0x01;
    await expect(
      decodePack(tampered, {
        expectedPackId: encoded.packId,
        packKey: key,
        zstdDecompressFn: zstdDecompress,
      }),
    ).rejects.toThrow();
  });

  it("signs offline Cloudflare R2 SigV4 URLs with auto region", async () => {
    const url = presignR2Url({
      method: "PUT",
      endpoint: "https://acct123.r2.cloudflarestorage.com",
      bucket: "beamsync-packs",
      key: "cas/v1/devbox/packs/abcdef0123",
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      expiresInSeconds: 900,
      now: new Date("2026-11-12T00:00:00Z"),
    });

    const parsed = new URL(url);
    expect(parsed.host).toBe("acct123.r2.cloudflarestorage.com");
    expect(parsed.pathname).toBe("/beamsync-packs/cas/v1/devbox/packs/abcdef0123");
    expect(parsed.searchParams.get("X-Amz-Algorithm")).toBe("AWS4-HMAC-SHA256");
    expect(parsed.searchParams.get("X-Amz-Credential")).toContain("/20261112/auto/s3/aws4_request");
    expect(parsed.searchParams.get("X-Amz-Signature")).toMatch(/^[0-9a-f]{64}$/);

    const driver = new R2PresignedStorageDriver({
      accountId: "acct123",
      bucket: "beamsync-packs",
      accessKeyId: "k",
      secretAccessKey: "s",
    });
    const getUrl = await driver.mintGetUrl("ephemeral/v1/p1");
    expect(getUrl).toContain("X-Amz-Signature=");
  });

  it("evaluates bilateral receipt equilibrium only when manifest is finalized and both receipts exist", () => {
    const receipts = new Map<string, PackReceiptRow>([
      [
        "p1",
        {
          packId: "p1",
          storageKey: "k1",
          sizeBytes: 100,
          blobCount: 2,
          sourceReceiptAt: 1000,
          targetReceiptAt: 1050,
        },
      ],
      [
        "p2",
        {
          packId: "p2",
          storageKey: "k2",
          sizeBytes: 200,
          blobCount: 3,
          sourceReceiptAt: 1010,
          targetReceiptAt: null,
        },
      ],
    ]);

    const incomplete = evaluateSessionEquilibrium({
      manifestFinalized: true,
      rootTreeDigest: "root123",
      requiredPackIds: ["p1", "p2"],
      receipts,
    });
    expect(incomplete.equilibriumReached).toBe(false);
    expect(incomplete.missingTargetPackIds).toEqual(["p2"]);

    receipts.get("p2")!.targetReceiptAt = 1090;
    const unfinalized = evaluateSessionEquilibrium({
      manifestFinalized: false,
      rootTreeDigest: "root123",
      requiredPackIds: ["p1", "p2"],
      receipts,
    });
    expect(unfinalized.equilibriumReached).toBe(false);

    const complete = evaluateSessionEquilibrium({
      manifestFinalized: true,
      rootTreeDigest: "root123",
      requiredPackIds: ["p1", "p2"],
      receipts,
    });
    expect(complete.equilibriumReached).toBe(true);
    expect(complete.sourceReadyCount).toBe(2);
    expect(complete.targetAppliedCount).toBe(2);
  });

  it("consumes pairing slot on join so a second attacker cannot hijack the slot", () => {
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
    expect(joined.sessionId).toBe(created.sessionId);

    expect(() =>
      engine.joinPairingSession({
        slotCode: created.slotCode,
        wsBaseUrl: "ws://localhost:8787",
      }),
    ).toThrow(/PAIRING_NOT_FOUND/);
  });

  it("slides the session TTL on signaling activity so a long transfer is not garbage-collected, and reports PEER_LOST once per vanished peer", async () => {
    const engine = new CoordinatorEngine({
      storageDriver: new R2PresignedStorageDriver({
        accountId: "test",
        bucket: "b",
        accessKeyId: "a",
        secretAccessKey: "s",
      }),
      sessionTtlMs: 300,
      peerLossGraceMs: 80,
    });
    const created = engine.createPairingSession({ wsBaseUrl: "ws://localhost:8787" });
    const joined = engine.joinPairingSession({
      slotCode: created.slotCode,
      wsBaseUrl: "ws://localhost:8787",
    });
    const inbox = { source: [] as Array<Record<string, unknown>>, target: [] as Array<Record<string, unknown>> };
    const socketFor = (role: "source" | "target") => ({
      send: (json: string) => inbox[role].push(JSON.parse(json) as Record<string, unknown>),
      close: () => {},
    });
    const sourceSocket = socketFor("source");
    const targetSocket = socketFor("target");
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const send = (socket: ReturnType<typeof socketFor>, msg: Record<string, unknown>) =>
      engine.handleWsMessage(created.sessionId, socket, JSON.stringify(msg));

    await send(sourceSocket, { type: "hello", role: "source", peerToken: created.peerToken });
    await send(targetSocket, { type: "hello", role: "target", peerToken: joined.peerToken });
    expect(inbox.source.some((m) => m.type === "peer_joined")).toBe(true);

    // Keepalive pings for twice the TTL: the session must survive garbage collection
    for (let i = 0; i < 6; i++) {
      await sleep(100);
      await send(sourceSocket, { type: "ping", ts: Date.now() });
      expect((await engine.runGarbageCollection()).prunedSessions).toBe(0);
    }

    // The target drops and resumes inside the grace period: nobody is told anything
    engine.detachSocket(created.sessionId, targetSocket);
    await sleep(30);
    const resumedTargetSocket = socketFor("target");
    await send(resumedTargetSocket, {
      type: "hello",
      role: "target",
      peerToken: joined.peerToken,
      resumeFromSeq: 0,
    });
    await sleep(120);
    expect(inbox.source.some((m) => m.type === "session_error")).toBe(false);

    // The target drops for good: the source hears PEER_LOST after the grace period
    engine.detachSocket(created.sessionId, resumedTargetSocket);
    await sleep(160);
    const errors = inbox.source.filter((m) => m.type === "session_error");
    expect(errors).toHaveLength(1);
    expect(errors[0].code).toBe("PEER_LOST");

    // With no further activity the session finally expires
    await sleep(350);
    expect((await engine.runGarbageCollection()).prunedSessions).toBe(1);
    engine.dispose();
  });
});
