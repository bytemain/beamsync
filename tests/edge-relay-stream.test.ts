import { afterEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import net from "node:net";
import WebSocket from "ws";
import { mintEdgeRelayTicket } from "@beamsync/protocol";
import {
  startEdgeRelayServer,
  unmaskInPlace,
  type RunningEdgeRelayServer,
} from "@beamsync/edge-relay";

const SECRET = "stream-test-relay-secret";
const RELAY_ID = "relay-stream-1";
const MIB = 1024 * 1024;

function relayPath(sessionId: string, role: "source" | "target"): string {
  const exp = Date.now() + 60_000;
  const ticket = mintEdgeRelayTicket({
    authSecret: SECRET,
    relayId: RELAY_ID,
    sessionId,
    role,
    expiresAtMs: exp,
  });
  return `/v1/relay/${sessionId}?relayId=${RELAY_ID}&role=${role}&exp=${exp}&ticket=${ticket}`;
}

interface TestPeer {
  ws: WebSocket;
  messages: Array<{ data: Buffer; isBinary: boolean }>;
  closed: Promise<{ code: number; reason: string }>;
  nextMessage(): Promise<{ data: Buffer; isBinary: boolean }>;
}

async function connectPeer(
  relay: RunningEdgeRelayServer,
  sessionId: string,
  role: "source" | "target",
): Promise<TestPeer> {
  const ws = new WebSocket(`${relay.wsUrl}${relayPath(sessionId, role)}`, {
    rejectUnauthorized: false,
    maxPayload: 64 * MIB,
  });
  const messages: Array<{ data: Buffer; isBinary: boolean }> = [];
  const waiters: Array<(m: { data: Buffer; isBinary: boolean }) => void> = [];
  ws.on("message", (data, isBinary) => {
    const msg = { data: data as Buffer, isBinary };
    const waiter = waiters.shift();
    if (waiter) waiter(msg);
    else messages.push(msg);
  });
  const closed = new Promise<{ code: number; reason: string }>((resolve) => {
    ws.on("close", (code, reason) => resolve({ code, reason: reason.toString() }));
  });
  ws.on("error", () => {});
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
  });
  return {
    ws,
    messages,
    closed,
    nextMessage: () =>
      messages.length > 0
        ? Promise.resolve(messages.shift()!)
        : new Promise((resolve) => waiters.push(resolve)),
  };
}

/** Connects both peers and consumes the one-byte "paired" notification on each. */
async function connectPair(
  relay: RunningEdgeRelayServer,
  sessionId: string,
): Promise<{ source: TestPeer; target: TestPeer }> {
  const target = await connectPeer(relay, sessionId, "target");
  const source = await connectPeer(relay, sessionId, "source");
  for (const peer of [source, target]) {
    const paired = await peer.nextMessage();
    expect(paired.isBinary).toBe(true);
    expect([...paired.data]).toEqual([0x01]);
  }
  return { source, target };
}

function sendAsync(
  ws: WebSocket,
  data: Buffer | string,
  options: { binary?: boolean; fin?: boolean } = {},
): Promise<void> {
  return new Promise((resolve, reject) =>
    ws.send(data, options, (err) => (err ? reject(err) : resolve())),
  );
}

/** Opens a raw socket and completes the WebSocket upgrade by hand, for malformed-frame tests. */
async function rawUpgrade(
  relay: RunningEdgeRelayServer,
  sessionId: string,
  role: "source" | "target",
): Promise<{ socket: net.Socket; received: Buffer[]; ended: Promise<void> }> {
  const socket = net.connect(relay.port, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  socket.on("error", () => {});
  socket.write(
    `GET ${relayPath(sessionId, role)} HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${relay.port}\r\n` +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString("base64")}\r\n` +
      "Sec-WebSocket-Version: 13\r\n\r\n",
  );
  const received: Buffer[] = [];
  let headerDone = false;
  let pending = Buffer.alloc(0);
  const upgraded = new Promise<void>((resolve, reject) => {
    socket.on("data", (chunk) => {
      if (headerDone) {
        received.push(chunk);
        return;
      }
      pending = Buffer.concat([pending, chunk]);
      const idx = pending.indexOf("\r\n\r\n");
      if (idx < 0) return;
      const head = pending.subarray(0, idx).toString("latin1");
      if (!head.startsWith("HTTP/1.1 101")) {
        reject(new Error(`Upgrade failed: ${head.split("\r\n")[0]}`));
        return;
      }
      headerDone = true;
      const rest = pending.subarray(idx + 4);
      if (rest.length > 0) received.push(rest);
      resolve();
    });
  });
  const ended = new Promise<void>((resolve) => socket.once("close", () => resolve()));
  await upgraded;
  return { socket, received, ended };
}

/** Parses unmasked server-to-client frames out of raw bytes. */
function parseServerFrames(raw: Buffer): Array<{ opcode: number; fin: boolean; payload: Buffer }> {
  const frames: Array<{ opcode: number; fin: boolean; payload: Buffer }> = [];
  let off = 0;
  while (off + 2 <= raw.length) {
    const fin = (raw[off] & 0x80) !== 0;
    const opcode = raw[off] & 0x0f;
    let len = raw[off + 1] & 0x7f;
    let headerLen = 2;
    if (len === 126) {
      len = raw.readUInt16BE(off + 2);
      headerLen = 4;
    } else if (len === 127) {
      len = Number(raw.readBigUInt64BE(off + 2));
      headerLen = 10;
    }
    if (off + headerLen + len > raw.length) break;
    frames.push({ opcode, fin, payload: raw.subarray(off + headerLen, off + headerLen + len) });
    off += headerLen + len;
  }
  return frames;
}

describe("Edge Relay streaming WebSocket forwarding", () => {
  const relays: RunningEdgeRelayServer[] = [];
  const peers: TestPeer[] = [];

  async function startRelay(
    overrides: { tls?: boolean; forwardHighWatermarkBytes?: number } = {},
  ): Promise<RunningEdgeRelayServer> {
    const relay = await startEdgeRelayServer({
      relayId: RELAY_ID,
      region: "test",
      authSecret: SECRET,
      port: 0,
      host: "127.0.0.1",
      publicIp: "127.0.0.1",
      tlsMode: overrides.tls ? "self-signed" : "off",
      stunPort: null,
      forwardHighWatermarkBytes: overrides.forwardHighWatermarkBytes,
    });
    relays.push(relay);
    return relay;
  }

  async function pair(relay: RunningEdgeRelayServer, sessionId: string) {
    const p = await connectPair(relay, sessionId);
    peers.push(p.source, p.target);
    return p;
  }

  afterEach(async () => {
    for (const p of peers.splice(0, peers.length)) {
      p.ws.terminate();
    }
    while (relays.length > 0) {
      await relays.pop()!.close();
    }
  });

  it("unmasks any slice the same way as the byte-by-byte definition", () => {
    const backing = crypto.randomBytes(4096);
    for (let round = 0; round < 400; round++) {
      const start = Math.floor(Math.random() * 64);
      const length = Math.floor(Math.random() * 200);
      const maskPos = Math.floor(Math.random() * 4);
      const mask = crypto.randomBytes(4);
      const original = Buffer.from(backing.subarray(start, start + length));
      const expected = Buffer.from(original);
      for (let i = 0; i < expected.length; i++) {
        expected[i] ^= mask[(maskPos + i) & 3];
      }
      const slice = backing.subarray(start, start + length);
      unmaskInPlace(slice, mask, maskPos);
      expect(slice.equals(expected)).toBe(true);
      original.copy(backing, start);
    }
  });

  for (const tls of [false, true]) {
    it(`delivers large and small messages unchanged in both directions (${tls ? "TLS" : "plain"})`, async () => {
      const relay = await startRelay({ tls });
      const { source, target } = await pair(relay, `s-roundtrip-${tls}`);

      const big = crypto.randomBytes(8 * MIB + 12_345);
      await sendAsync(source.ws, big, { binary: true });
      const gotBig = await target.nextMessage();
      expect(gotBig.isBinary).toBe(true);
      expect(gotBig.data.length).toBe(big.length);
      expect(gotBig.data.equals(big)).toBe(true);

      const sizes = [0, 1, 125, 126, 127, 65_535, 65_536, 65_537, 300_000];
      const sent: Buffer[] = [];
      for (const size of sizes) {
        const body = crypto.randomBytes(size);
        sent.push(body);
        await sendAsync(target.ws, body, { binary: true });
      }
      for (const body of sent) {
        const got = await source.nextMessage();
        expect(got.isBinary).toBe(true);
        expect(got.data.equals(body)).toBe(true);
      }

      await sendAsync(source.ws, "héllo relay ✓", { binary: false });
      const text = await target.nextMessage();
      expect(text.isBinary).toBe(false);
      expect(text.data.toString("utf8")).toBe("héllo relay ✓");

      // 8 MiB + 12,345 bytes, the small ones, and the text message
      const expectedBytes =
        big.length + sizes.reduce((a, b) => a + b, 0) + Buffer.byteLength("héllo relay ✓");
      expect(relay.getStats().totalRelayedBytes).toBe(expectedBytes);
      expect(relay.getStats().totalRelayedFrames).toBe(1 + sizes.length + 1);
    });
  }

  it("joins a message the sender split into fragments, and answers a ping sent in between", async () => {
    const relay = await startRelay();
    const { source, target } = await pair(relay, "s-fragments");

    const parts = [crypto.randomBytes(70_000), Buffer.alloc(0), crypto.randomBytes(5), crypto.randomBytes(200_000)];
    await sendAsync(source.ws, parts[0], { binary: true, fin: false });
    const pong = new Promise<Buffer>((resolve) => source.ws.once("pong", (d) => resolve(d)));
    source.ws.ping(Buffer.from("mid-message"));
    expect((await pong).toString()).toBe("mid-message");
    await sendAsync(source.ws, parts[1], { binary: true, fin: false });
    await sendAsync(source.ws, parts[2], { binary: true, fin: false });
    await sendAsync(source.ws, parts[3], { binary: true, fin: true });

    const got = await target.nextMessage();
    expect(got.data.equals(Buffer.concat(parts))).toBe(true);
    expect(relay.getStats().totalRelayedFrames).toBe(1);
  });

  it("stops reading from the sender while the receiver is not reading, then delivers everything", async () => {
    const relay = await startRelay({ forwardHighWatermarkBytes: 256 * 1024 });
    const { source, target } = await pair(relay, "s-backpressure");

    const targetSocket = (target.ws as unknown as { _socket: net.Socket })._socket;
    targetSocket.pause();

    const messageCount = 12;
    const body = crypto.randomBytes(8 * MIB);
    const totalBytes = messageCount * body.length;
    const sends: Promise<void>[] = [];
    for (let i = 0; i < messageCount; i++) {
      sends.push(sendAsync(source.ws, body, { binary: true }));
    }

    // Wait until the relay has stopped making progress.
    let last = -1;
    let stableRounds = 0;
    while (stableRounds < 5) {
      await new Promise((r) => setTimeout(r, 100));
      const now = relay.getStats().totalRelayedBytes;
      stableRounds = now === last ? stableRounds + 1 : 0;
      last = now;
    }
    // What the relay accepted is bounded by its watermark plus the kernel socket buffers
    // towards the paused receiver, far below the 96 MiB the sender queued.
    expect(last).toBeGreaterThan(0);
    expect(last).toBeLessThan(totalBytes / 3);
    expect(target.messages.length).toBe(0);

    targetSocket.resume();
    await Promise.all(sends);
    for (let i = 0; i < messageCount; i++) {
      const got = await target.nextMessage();
      expect(got.data.length).toBe(body.length);
      expect(got.data.equals(body)).toBe(true);
    }
    expect(relay.getStats().totalRelayedBytes).toBe(totalBytes);
  }, 60_000);

  it("closes the receiver without delivering a message the sender abandoned halfway", async () => {
    const relay = await startRelay();
    const { source, target } = await pair(relay, "s-abandoned");

    await sendAsync(source.ws, crypto.randomBytes(100_000), { binary: true, fin: false });
    await new Promise((r) => setTimeout(r, 50));
    source.ws.terminate();

    const closed = await target.closed;
    expect(closed.code).toBe(1001);
    expect(closed.reason).toBe("source_disconnected");
    expect(target.messages.length).toBe(0);
    await new Promise((r) => setTimeout(r, 50));
    expect(relay.getStats().activeRooms).toBe(0);
  });

  it("drops messages sent before the peer joined and forwards the ones sent after", async () => {
    const relay = await startRelay();
    const source = await connectPeer(relay, "s-early", "source");
    peers.push(source);
    await sendAsync(source.ws, Buffer.from("too early"), { binary: true });
    await new Promise((r) => setTimeout(r, 50));

    const target = await connectPeer(relay, "s-early", "target");
    peers.push(target);
    expect([...(await target.nextMessage()).data]).toEqual([0x01]);
    expect([...(await source.nextMessage()).data]).toEqual([0x01]);

    await sendAsync(source.ws, Buffer.from("on time"), { binary: true });
    expect((await target.nextMessage()).data.toString()).toBe("on time");
    expect(relay.getStats().totalRelayedBytes).toBe("on time".length);
  });

  it("answers a close frame with the same status and tells the peer", async () => {
    const relay = await startRelay();
    const { source, target } = await pair(relay, "s-close");
    await sendAsync(source.ws, Buffer.from("last words"), { binary: true });
    source.ws.close(4001, "done");
    expect((await source.closed).code).toBe(4001);
    expect((await target.nextMessage()).data.toString()).toBe("last words");
    const closed = await target.closed;
    expect(closed).toEqual({ code: 1001, reason: "source_disconnected" });
  });

  it("rejects unmasked frames (1002) and messages above the size limit (1009)", async () => {
    const relay = await startRelay();

    const unmasked = await rawUpgrade(relay, "s-unmasked", "source");
    unmasked.socket.write(Buffer.from([0x82, 0x03, 1, 2, 3]));
    await unmasked.ended;
    const unmaskedFrames = parseServerFrames(Buffer.concat(unmasked.received));
    expect(unmaskedFrames).toHaveLength(1);
    expect(unmaskedFrames[0].opcode).toBe(0x8);
    expect(unmaskedFrames[0].payload.readUInt16BE(0)).toBe(1002);

    const oversized = await rawUpgrade(relay, "s-oversized", "source");
    const header = Buffer.alloc(14);
    header[0] = 0x82;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(32 * MIB + 1), 2);
    oversized.socket.write(header);
    await oversized.ended;
    const oversizedFrames = parseServerFrames(Buffer.concat(oversized.received));
    expect(oversizedFrames).toHaveLength(1);
    expect(oversizedFrames[0].opcode).toBe(0x8);
    expect(oversizedFrames[0].payload.readUInt16BE(0)).toBe(1009);

    // A message that only crosses the limit across several fragments is rejected as well.
    const split = await rawUpgrade(relay, "s-split-oversized", "source");
    const fragHeader = (opcode: number, fin: boolean, len: number): Buffer => {
      const h = Buffer.alloc(14);
      h[0] = (fin ? 0x80 : 0) | opcode;
      h[1] = 0x80 | 127;
      h.writeBigUInt64BE(BigInt(len), 2);
      return h;
    };
    split.socket.write(fragHeader(0x2, false, 20 * MIB));
    split.socket.write(Buffer.alloc(20 * MIB));
    split.socket.write(fragHeader(0x0, true, 13 * MIB));
    await split.ended;
    const splitFrames = parseServerFrames(Buffer.concat(split.received));
    expect(splitFrames).toHaveLength(1);
    expect(splitFrames[0].payload.readUInt16BE(0)).toBe(1009);

    expect(relay.getStats().activeRooms).toBe(0);
  });

  it("refuses an upgrade without a valid WebSocket key", async () => {
    const relay = await startRelay();
    const socket = net.connect(relay.port, "127.0.0.1");
    await new Promise<void>((resolve) => socket.once("connect", () => resolve()));
    socket.write(
      `GET ${relayPath("s-badkey", "source")} HTTP/1.1\r\nHost: x\r\n` +
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: short\r\nSec-WebSocket-Version: 13\r\n\r\n",
    );
    const chunks: Buffer[] = [];
    socket.on("data", (c) => chunks.push(c));
    await new Promise<void>((resolve) => socket.once("close", () => resolve()));
    expect(Buffer.concat(chunks).toString("latin1")).toMatch(/^HTTP\/1\.1 400 /);
    expect(relay.getStats().activeRooms).toBe(0);
  });
});
