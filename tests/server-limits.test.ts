import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CoordinatorEngine, R2PresignedStorageDriver } from "@beamsync/coordinator";
import { startBeamSyncServer, type RunningBeamSyncServer } from "@beamsync/server";
import { receiveDirectory, sendDirectory } from "@beamsync/cli";

const WS_BASE = "ws://localhost:8787";

function newEngine(
  options: Partial<ConstructorParameters<typeof CoordinatorEngine>[0]> = {},
): CoordinatorEngine {
  return new CoordinatorEngine({
    storageDriver: new R2PresignedStorageDriver({
      accountId: "test",
      bucket: "b",
      accessKeyId: "a",
      secretAccessKey: "s",
    }),
    ...options,
  });
}

interface FakeSocket {
  inbox: Array<Record<string, unknown>>;
  buffered: number;
  terminated: number;
  send(json: string): void;
  close(): void;
  bufferedAmount(): number;
  terminate(): void;
}

function fakeSocket(): FakeSocket {
  const socket: FakeSocket = {
    inbox: [],
    buffered: 0,
    terminated: 0,
    send: (json) => socket.inbox.push(JSON.parse(json) as Record<string, unknown>),
    close: () => {},
    bufferedAmount: () => socket.buffered,
    terminate: () => {
      socket.terminated++;
    },
  };
  return socket;
}

/** A paired session whose peers have exchanged key confirmations, so control streams are relayed. */
async function openSession(engine: CoordinatorEngine) {
  const created = engine.createPairingSession({ wsBaseUrl: WS_BASE });
  const joined = engine.joinPairingSession({ slotCode: created.slotCode, wsBaseUrl: WS_BASE });
  const source = fakeSocket();
  const target = fakeSocket();
  let cseq = 0;
  const send = (socket: FakeSocket, msg: Record<string, unknown>) =>
    engine.handleWsMessage(created.sessionId, socket, JSON.stringify(msg));
  await send(source, { type: "hello", role: "source", peerToken: created.peerToken });
  await send(target, { type: "hello", role: "target", peerToken: joined.peerToken });
  for (const socket of [source, target]) {
    await send(socket, {
      type: "pake_confirm",
      confirmMacHex: "ab",
      hostFingerprint: socket === source ? "host-a" : "host-b",
      candidates: [],
      protocolVersion: 2,
    });
  }
  let index = 0;
  return {
    sessionId: created.sessionId,
    targetToken: joined.peerToken,
    source,
    target,
    send,
    /** The source relays one manifest segment of `bytes` base64 characters to the target. */
    relaySegment: (bytes: number) =>
      send(source, {
        type: "control_stream_chunk",
        stream: "manifest",
        index: index++,
        final: false,
        payloadBase64: "A".repeat(bytes),
        cseq: ++cseq,
      }),
  };
}

function lastSeq(socket: FakeSocket): number {
  const seqs = socket.inbox.map((m) => m.sseq).filter((s): s is number => typeof s === "number");
  return seqs.length > 0 ? Math.max(...seqs) : 0;
}

describe("Coordinator resource limits", () => {
  it("refuses new sessions with SERVER_BUSY at the session limit and accepts them again once old ones expire", async () => {
    const engine = newEngine({ maxSessions: 3, pairingTtlMs: 60 });
    engine.createPairingSession({ wsBaseUrl: WS_BASE });
    engine.createPairingSession({ wsBaseUrl: WS_BASE });
    engine.createManagedLease({ scopeNamespace: "team", wsBaseUrl: WS_BASE, expiresInSeconds: 3600 });
    expect(engine.getStats().activeSessions).toBe(3);

    expect(() => engine.createPairingSession({ wsBaseUrl: WS_BASE })).toThrow(/SERVER_BUSY/);
    expect(() =>
      engine.createManagedLease({ scopeNamespace: "team", wsBaseUrl: WS_BASE }),
    ).toThrow(/SERVER_BUSY/);
    expect(engine.getStats().refusedSessions).toBe(2);
    expect(engine.getStats().activeSessions).toBe(3);

    // The two unjoined pairings expire after 60 ms; the lease stays
    await new Promise((r) => setTimeout(r, 90));
    engine.createPairingSession({ wsBaseUrl: WS_BASE });
    engine.createPairingSession({ wsBaseUrl: WS_BASE });
    expect(engine.getStats().activeSessions).toBe(3);
    expect(() => engine.createPairingSession({ wsBaseUrl: WS_BASE })).toThrow(/SERVER_BUSY/);
    engine.dispose();
  });

  it("keeps a failed session only for the linger period instead of the full session TTL", async () => {
    const engine = newEngine({
      sessionTtlMs: 60 * 60 * 1000,
      peerLossGraceMs: 30,
      finishedSessionLingerMs: 5_000,
    });
    const s = await openSession(engine);
    const before = engine.getSessionSnapshot(s.sessionId)!.expiresAt;
    expect(before).toBeGreaterThan(Date.now() + 50 * 60 * 1000);

    engine.detachSocket(s.sessionId, s.target);
    await new Promise((r) => setTimeout(r, 80));
    expect(s.source.inbox.some((m) => m.code === "PEER_LOST")).toBe(true);

    const after = engine.getSessionSnapshot(s.sessionId)!.expiresAt;
    expect(after).toBeLessThanOrEqual(Date.now() + 5_000);
    expect((await engine.runGarbageCollection(Date.now() + 4_000)).prunedSessions).toBe(0);
    expect((await engine.runGarbageCollection(Date.now() + 6_000)).prunedSessions).toBe(1);
    expect(engine.getStats().activeSessions).toBe(0);
    expect(engine.getStats().replayLogBytes).toBe(0);
    engine.dispose();
  });

  it("holds the memory kept for resume within the global budget, evicting from the peers that never acknowledge", async () => {
    const budget = 1024 * 1024;
    const engine = newEngine({ maxReplayLogBytesTotal: budget });
    const quiet = await openSession(engine);
    const acking = await openSession(engine);
    const silentA = await openSession(engine);
    const silentB = await openSession(engine);

    // One small un-acknowledged segment: this peer must keep its resume history
    await quiet.relaySegment(20_000);
    const quietSeq = lastSeq(quiet.target);

    let peak = 0;
    for (let round = 0; round < 40; round++) {
      await acking.relaySegment(100_000);
      await acking.send(acking.target, {
        type: "ping",
        ts: Date.now(),
        ackSeq: lastSeq(acking.target),
      });
      await silentA.relaySegment(100_000);
      await silentB.relaySegment(100_000);
      peak = Math.max(peak, engine.getStats().replayLogBytes);
    }

    // 8 MB went to the two silent peers; no more than the budget is retained
    const stats = engine.getStats();
    expect(peak).toBeLessThanOrEqual(budget);
    expect(stats.replayLogBytes).toBeLessThanOrEqual(budget);
    expect(stats.evictedReplayBytes).toBeGreaterThan(6_000_000);

    // The two silent peers were levelled against each other, not one of them emptied
    const backlogA = engine.getSessionSnapshot(silentA.sessionId)!.target.outLogBytes;
    const backlogB = engine.getSessionSnapshot(silentB.sessionId)!.target.outLogBytes;
    expect(backlogA).toBeGreaterThan(300_000);
    expect(backlogB).toBeGreaterThan(300_000);
    expect(Math.abs(backlogA - backlogB)).toBeLessThanOrEqual(200_200);

    // Every segment was still delivered to its live socket
    expect(silentA.target.inbox.filter((m) => m.type === "control_stream_chunk")).toHaveLength(40);
    expect(acking.target.inbox.filter((m) => m.type === "control_stream_chunk")).toHaveLength(40);

    // A silent peer that reconnects asking for what it never acknowledged is told about the gap
    const silentResume = fakeSocket();
    engine.detachSocket(silentA.sessionId, silentA.target);
    await silentA.send(silentResume, {
      type: "hello",
      role: "target",
      peerToken: silentA.targetToken,
      resumeFromSeq: 2,
    });
    expect(silentResume.inbox.map((m) => m.code)).toContain("RESUME_GAP");

    // The peer with the small backlog was not evicted and resumes with its segment replayed
    const quietResume = fakeSocket();
    engine.detachSocket(quiet.sessionId, quiet.target);
    await quiet.send(quietResume, {
      type: "hello",
      role: "target",
      peerToken: quiet.targetToken,
      resumeFromSeq: quietSeq - 1,
    });
    expect(quietResume.inbox[0].type).toBe("resumed");
    const replayed = quietResume.inbox.filter((m) => m.type === "control_stream_chunk");
    expect(replayed).toHaveLength(1);
    expect((replayed[0].payloadBase64 as string).length).toBe(20_000);
    engine.dispose();
  });

  it("releases the accounted replay bytes when messages are acknowledged", async () => {
    const engine = newEngine();
    const s = await openSession(engine);
    const baseline = engine.getStats().replayLogBytes;
    for (let i = 0; i < 5; i++) {
      await s.relaySegment(50_000);
    }
    expect(engine.getStats().replayLogBytes).toBeGreaterThan(baseline + 250_000);
    await s.send(s.target, { type: "ping", ts: Date.now(), ackSeq: lastSeq(s.target) });
    await s.send(s.source, { type: "ping", ts: Date.now(), ackSeq: lastSeq(s.source) });
    expect(engine.getStats().replayLogBytes).toBe(0);
    expect(engine.getStats().evictedReplayBytes).toBe(0);
    engine.dispose();
  });

  it("disconnects a peer that stopped reading instead of queueing more, and replays what it missed on resume", async () => {
    const engine = newEngine({ maxSocketBufferedBytes: 1_000_000 });
    const s = await openSession(engine);
    await s.relaySegment(1_000);
    const deliveredBefore = s.target.inbox.filter((m) => m.type === "control_stream_chunk").length;
    expect(deliveredBefore).toBe(1);
    const ackedSeq = lastSeq(s.target);

    s.target.buffered = 2_000_000;
    await s.relaySegment(2_000);
    expect(s.target.terminated).toBe(1);
    expect(s.target.inbox.filter((m) => m.type === "control_stream_chunk")).toHaveLength(1);
    expect(engine.getStats().slowConsumerDisconnects).toBe(1);

    engine.detachSocket(s.sessionId, s.target);
    const resumed = fakeSocket();
    await s.send(resumed, {
      type: "hello",
      role: "target",
      peerToken: s.targetToken,
      resumeFromSeq: ackedSeq,
    });
    const replayed = resumed.inbox.filter((m) => m.type === "control_stream_chunk");
    expect(replayed).toHaveLength(1);
    expect((replayed[0].payloadBase64 as string).length).toBe(2_000);
    engine.dispose();
  });
});

describe("Coordinator API token and capacity over HTTP", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer | null = null;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-limits-"));
  });

  afterEach(async () => {
    if (server) {
      await server.close();
      server = null;
    }
    await rm(tmpRoot, { recursive: true, force: true });
  });

  async function post(
    pathname: string,
    body: unknown,
    token?: string,
  ): Promise<{ status: number; json: Record<string, unknown>; headers: Headers }> {
    const res = await fetch(`${server!.httpUrl}${pathname}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    });
    return {
      status: res.status,
      json: (await res.json()) as Record<string, unknown>,
      headers: res.headers,
    };
  }

  it("requires the API token to create a pairing, join one, and create a lease once a token is configured", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      dataDir: path.join(tmpRoot, "data"),
      stunPort: null,
      apiToken: "s3cret-token",
    });

    for (const token of [undefined, "wrong-token", "s3cret-toke", "s3cret-token-x"]) {
      const res = await post("/v1/pairings", {}, token);
      expect(res.status).toBe(401);
      expect(res.json.error).toBe("UNAUTHORIZED");
      expect((await post("/v1/leases", { scopeNamespace: "x" }, token)).status).toBe(401);
    }
    const health = (await (await fetch(`${server.httpUrl}/healthz`)).json()) as Record<string, unknown>;
    expect(health.activeSessions).toBe(0);

    const created = await post("/v1/pairings", {}, "s3cret-token");
    expect(created.status).toBe(200);
    const slotCode = created.json.slotCode as string;

    // An unauthenticated join is rejected and does not consume the pairing slot
    for (let i = 0; i < 5; i++) {
      expect((await post("/v1/pairings/join", { slotCode })).status).toBe(401);
    }
    const joined = await post("/v1/pairings/join", { slotCode }, "s3cret-token");
    expect(joined.status).toBe(200);
    expect(joined.json.sessionId).toBe(created.json.sessionId);

    expect((await post("/v1/leases", { scopeNamespace: "x" }, "s3cret-token")).status).toBe(200);
  });

  it("leaves pairing open when no API token is configured", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      dataDir: path.join(tmpRoot, "data"),
      stunPort: null,
    });
    const created = await post("/v1/pairings", {});
    expect(created.status).toBe(200);
    const joined = await post("/v1/pairings/join", { slotCode: created.json.slotCode });
    expect(joined.status).toBe(200);
  });

  it("answers 503 with Retry-After at the session limit", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      dataDir: path.join(tmpRoot, "data"),
      stunPort: null,
      maxSessions: 2,
    });
    expect((await post("/v1/pairings", {})).status).toBe(200);
    expect((await post("/v1/pairings", {})).status).toBe(200);
    const refused = await post("/v1/pairings", {});
    expect(refused.status).toBe(503);
    expect(refused.json.error).toMatch(/^SERVER_BUSY/);
    expect(refused.headers.get("retry-after")).toBe("30");
    const health = (await (await fetch(`${server.httpUrl}/healthz`)).json()) as Record<string, unknown>;
    expect(health.activeSessions).toBe(2);
    expect(health.maxSessions).toBe(2);
    expect(health.refusedSessions).toBe(1);
  });

  it("transfers a directory through a token-protected server, and explains the failure when the token is missing", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      dataDir: path.join(tmpRoot, "data"),
      stunPort: null,
      apiToken: "devbox-fleet-token",
    });
    const srcDir = path.join(tmpRoot, "src");
    const dstDir = path.join(tmpRoot, "dst");
    await mkdir(path.join(srcDir, "pkg"), { recursive: true });
    await mkdir(dstDir, { recursive: true });
    await writeFile(path.join(srcDir, "pkg", "main.ts"), "export const answer = 42;\n");

    await expect(
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir: srcDir,
        cacheDir: path.join(tmpRoot, "cache-src-denied"),
      }),
    ).rejects.toThrow(/HTTP 401.*BEAMSYNC_API_TOKEN/);

    let resolveCode: (code: string) => void = () => {};
    const codePromise = new Promise<string>((resolve) => (resolveCode = resolve));
    const sendPromise = sendDirectory({
      serverUrl: server.httpUrl,
      apiToken: "devbox-fleet-token",
      sourceDir: srcDir,
      cacheDir: path.join(tmpRoot, "cache-src"),
      onPairingCode: (code) => resolveCode(code),
    });
    const pairingCode = await codePromise;

    await expect(
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir: dstDir,
        pairingCode,
        cacheDir: path.join(tmpRoot, "cache-dst-denied"),
      }),
    ).rejects.toThrow(/HTTP 401.*BEAMSYNC_API_TOKEN/);

    const [sent, received] = await Promise.all([
      sendPromise,
      receiveDirectory({
        serverUrl: server.httpUrl,
        apiToken: "devbox-fleet-token",
        targetDir: dstDir,
        pairingCode,
        cacheDir: path.join(tmpRoot, "cache-dst"),
      }),
    ]);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);
    expect(received.sessionId).toBe(sent.sessionId);
    expect(await readFile(path.join(dstDir, "pkg", "main.ts"), "utf8")).toBe(
      "export const answer = 42;\n",
    );
  });
});
