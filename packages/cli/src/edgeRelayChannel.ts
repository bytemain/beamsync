import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import WebSocket from "ws";
import {
  concatBytes,
  constantTimeEqual,
  hmacSha256,
  randomBytes,
  utf8Bytes,
  type EdgeRelayNodeInfo,
} from "@beamsync/protocol";
import {
  attachCertPinCheck,
  createProxyTunnelAgent,
  resolveProxyForUrl,
} from "./proxy.js";

const RELAY_PAIRED_SIGNAL_BYTE = 0x01;
const FRAME_AUTH_INIT = 0x01;
const FRAME_AUTH_REPLY = 0x02;
const FRAME_PACK_DATA = 0x10;
const FRAME_PACK_ACK = 0x11;
const FRAME_STREAM_END = 0x1f;

const WS_SEND_HIGH_WATERMARK = 8 * 1024 * 1024;

/**
 * Builds an `https.Agent` implementing raw X.509 certificate SHA-256
 * pinning (`certSha256`) and SNI suppression (`noSni: true`, `servername: ""`).
 * Enables zero-domain, ICP-free raw IP + TLS Edge Relay nodes (e.g. Shanghai VMs)
 * while strictly rejecting any MITM certificate that does not match `certSha256`.
 */
export function createEdgeRelayHttpsAgent(params: {
  certSha256?: string;
  noSni?: boolean;
}): https.Agent | undefined {
  const expectedPin = params.certSha256?.trim().toLowerCase();
  if (!expectedPin && !params.noSni) {
    return undefined;
  }

  const agent = new https.Agent({ keepAlive: false });
  const origCreateConnection = agent.createConnection.bind(agent) as (
    opts: tls.ConnectionOptions,
  ) => tls.TLSSocket;

  (agent as unknown as { createConnection: (opts: tls.ConnectionOptions) => tls.TLSSocket }).createConnection =
    (options: tls.ConnectionOptions) => {
      const tlsOpts: tls.ConnectionOptions = {
        ...options,
        rejectUnauthorized: expectedPin ? false : true,
      };
      if (params.noSni) {
        // Omit TLS SNI extension completely so domain-inspection walls are never triggered
        tlsOpts.servername = "";
      }

      const sock = origCreateConnection(tlsOpts);
      if (expectedPin) {
        // Prepend listener so pin verification executes before any buffered HTTP/WS write flushes
        attachCertPinCheck(sock, expectedPin);
      }

      return sock;
    };

  return agent;
}

/**
 * Picks the outbound agent for an HTTP(S)/WS(S) URL: a proxy tunnel when
 * `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `BEAMSYNC_PROXY` applies (pinning and
 * SNI-free mode are preserved end-to-end inside the tunnel), otherwise the pinned
 * direct agent, otherwise Node's default.
 */
export function selectTransportAgent(
  targetUrl: string | URL,
  pin: { certSha256?: string; noSni?: boolean } = {},
  opts: { keepAlive?: boolean } = {},
): http.Agent | undefined {
  const u = typeof targetUrl === "string" ? new URL(targetUrl) : targetUrl;
  const secure = u.protocol === "https:" || u.protocol === "wss:";
  const proxy = resolveProxyForUrl(u);
  if (proxy) {
    return createProxyTunnelAgent({
      proxy,
      secure,
      certSha256: pin.certSha256,
      noSni: pin.noSni,
      keepAlive: opts.keepAlive,
    });
  }
  return secure ? createEdgeRelayHttpsAgent(pin) : undefined;
}

async function httpProbeOnce(
  node: EdgeRelayNodeInfo,
  timeoutMs: number,
): Promise<number> {
  const probeUrl = new URL(`${node.httpUrl.replace(/\/+$/, "")}/probe`);
  const isHttps = probeUrl.protocol === "https:";
  const agent = selectTransportAgent(probeUrl, {
    certSha256: node.certSha256,
    noSni: node.noSni,
  });

  const t0 = performance.now();
  await new Promise<void>((resolve, reject) => {
    const lib = isHttps ? https : http;
    const req = lib.request(
      probeUrl,
      {
        method: "GET",
        headers: {
          "cache-control": "no-store",
          host: probeUrl.host,
        },
        agent,
        timeout: timeoutMs,
      },
      (res) => {
        res.on("data", () => {});
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(new Error(`HTTP ${res.statusCode ?? 0}`));
          }
        });
      },
    );

    req.once("timeout", () => {
      req.destroy(new Error("Probe timeout"));
    });
    req.once("error", reject);
    req.end();
  });

  return Math.max(0.1, Math.round((performance.now() - t0) * 10) / 10);
}

/**
 * Probes all candidate Edge Relay nodes in parallel via HTTP/HTTPS `/probe`
 * (honoring pinned self-signed `certSha256` and `noSni` for IP-only relays)
 * and returns `relayId -> RTT (ms)` for reachable nodes.
 */
export async function probeEdgeRelayRtts(
  relays: EdgeRelayNodeInfo[] | undefined,
  timeoutMs = 1200,
): Promise<Record<string, number>> {
  const results: Record<string, number> = {};
  if (!relays || relays.length === 0) {
    return results;
  }

  await Promise.allSettled(
    relays.map(async (node) => {
      try {
        results[node.relayId] = await httpProbeOnce(node, timeoutMs);
      } catch {
        // Unreachable or pin-mismatched relay node is omitted from RTT report
      }
    }),
  );

  return results;
}

export class EdgeRelayBinaryChannel {
  private readonly ws: WebSocket;
  private pairedReady = false;
  private pairedWaiter: {
    resolve: () => void;
    reject: (err: Error) => void;
  } | null = null;
  private readonly pendingFrames: Uint8Array[] = [];
  private readonly frameWaiters: Array<{
    resolve: (frame: Uint8Array) => void;
    reject: (err: Error) => void;
  }> = [];
  private closedError: Error | null = null;

  constructor(ws: WebSocket) {
    this.ws = ws;

    ws.on("message", (data) => {
      const buf = Buffer.isBuffer(data)
        ? data
        : Array.isArray(data)
          ? Buffer.concat(data)
          : Buffer.from(data);

      if (!this.pairedReady && buf.length === 1 && buf[0] === RELAY_PAIRED_SIGNAL_BYTE) {
        this.pairedReady = true;
        if (this.pairedWaiter) {
          const w = this.pairedWaiter;
          this.pairedWaiter = null;
          w.resolve();
        }
        return;
      }

      if (buf.length < 5) {
        this.failAll(new Error("Malformed binary frame on Edge Relay channel"));
        ws.close(1002, "malformed_frame");
        return;
      }

      const declaredLen = buf.readUInt32BE(0);
      if (declaredLen + 4 !== buf.length) {
        this.failAll(new Error("Length mismatch on Edge Relay binary frame"));
        ws.close(1002, "length_mismatch");
        return;
      }

      const payload = new Uint8Array(buf.buffer, buf.byteOffset + 4, declaredLen);
      const waiter = this.frameWaiters.shift();
      if (waiter) {
        waiter.resolve(payload);
      } else {
        this.pendingFrames.push(payload);
      }
    });

    ws.on("close", (code, reason) => {
      this.failAll(
        new Error(
          `Edge Relay WebSocket closed (${code}: ${reason.toString() || "closed"})`,
        ),
      );
    });

    ws.on("error", (err) => {
      this.failAll(err instanceof Error ? err : new Error(String(err)));
    });
  }

  private failAll(err: Error): void {
    if (!this.closedError) {
      this.closedError = err;
    }
    if (this.pairedWaiter) {
      const pw = this.pairedWaiter;
      this.pairedWaiter = null;
      pw.reject(this.closedError);
    }
    while (this.frameWaiters.length > 0) {
      const w = this.frameWaiters.shift()!;
      w.reject(this.closedError);
    }
  }

  async waitForPeerPaired(timeoutMs = 10_000): Promise<void> {
    if (this.pairedReady) return;
    if (this.closedError) throw this.closedError;

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pairedWaiter = null;
        reject(new Error("Timed out waiting for peer to join Edge Relay room"));
      }, timeoutMs);

      this.pairedWaiter = {
        resolve: () => {
          clearTimeout(timer);
          resolve();
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      };
    });
  }

  async sendFrame(typeByte: number, body: Uint8Array): Promise<void> {
    if (this.closedError) throw this.closedError;
    if (this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("Edge Relay WebSocket is not open");
    }

    while (this.ws.bufferedAmount > WS_SEND_HIGH_WATERMARK) {
      if (this.closedError || this.ws.readyState !== WebSocket.OPEN) {
        throw this.closedError ?? new Error("Edge Relay WebSocket closed during backpressure");
      }
      await new Promise((r) => setTimeout(r, 10));
    }

    const len = 1 + body.byteLength;
    const packet = Buffer.allocUnsafe(4 + len);
    packet.writeUInt32BE(len, 0);
    packet[4] = typeByte & 0xff;
    Buffer.from(body.buffer, body.byteOffset, body.byteLength).copy(packet, 5);

    await new Promise<void>((resolve, reject) => {
      this.ws.send(packet, { binary: true }, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async nextFrame(timeoutMs = 30_000): Promise<{ type: number; body: Uint8Array }> {
    if (this.pendingFrames.length > 0) {
      const raw = this.pendingFrames.shift()!;
      return { type: raw[0], body: raw.subarray(1) };
    }
    if (this.closedError) throw this.closedError;

    const raw = await new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.frameWaiters.findIndex((w) => w.resolve === wrappedResolve);
        if (idx >= 0) this.frameWaiters.splice(idx, 1);
        reject(new Error("Timed out waiting for Edge Relay frame"));
      }, timeoutMs);

      const wrappedResolve = (frame: Uint8Array) => {
        clearTimeout(timer);
        resolve(frame);
      };
      const wrappedReject = (err: Error) => {
        clearTimeout(timer);
        reject(err);
      };
      this.frameWaiters.push({ resolve: wrappedResolve, reject: wrappedReject });
    });

    if (raw.length < 1) {
      throw new Error("Empty Edge Relay frame");
    }
    return { type: raw[0], body: raw.subarray(1) };
  }

  destroy(): void {
    try {
      this.ws.close(1000, "done");
    } catch {
      this.ws.terminate();
    }
  }
}

/**
 * Connects to a regional Edge Relay WebSocket room using a Coordinator-minted ticket,
 * validates optional SHA-256 certificate pin (`certSha256`) + SNI-free mode (`noSni`),
 * waits for peer attachment (`0x01`), and performs an end-to-end mutual HMAC handshake
 * with `transportKey` so the zero-knowledge relay cannot MITM or spoof either peer.
 */
export async function connectEdgeRelayBinaryChannel(params: {
  wsRelayUrl: string;
  role: "source" | "target";
  transportKey: Uint8Array;
  sessionId: string;
  certSha256?: string;
  noSni?: boolean;
  connectTimeoutMs?: number;
}): Promise<EdgeRelayBinaryChannel> {
  const timeoutMs = params.connectTimeoutMs ?? 8_000;
  const parsed = new URL(params.wsRelayUrl);
  const agent = selectTransportAgent(parsed, {
    certSha256: params.certSha256,
    noSni: params.noSni,
  });

  const ws = new WebSocket(params.wsRelayUrl, {
    maxPayload: 32 * 1024 * 1024,
    agent,
    headers: { host: parsed.host },
  });

  // Attach message/error listeners BEFORE awaiting `open` so a [0x01] paired signal
  // arriving in the same TCP read buffer as HTTP 101 Switching Protocols is never missed.
  const channel = new EdgeRelayBinaryChannel(ws);

  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.terminate();
        reject(new Error("Timed out connecting to Edge Relay WebSocket"));
      }, timeoutMs);

      ws.once("open", () => {
        clearTimeout(timer);
        resolve();
      });
      ws.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    await channel.waitForPeerPaired(timeoutMs);

    if (params.role === "source") {
      const sourceNonce = randomBytes(32);
      const sourceMac = hmacSha256(
        params.transportKey,
        concatBytes(utf8Bytes(`edge-source-init:${params.sessionId}:`), sourceNonce),
      );
      await channel.sendFrame(FRAME_AUTH_INIT, concatBytes(sourceNonce, sourceMac));

      const reply = await channel.nextFrame(5000);
      if (reply.type !== FRAME_AUTH_REPLY || reply.body.length !== 64) {
        throw new Error("Invalid Edge Relay peer auth reply");
      }
      const targetNonce = reply.body.subarray(0, 32);
      const targetMac = reply.body.subarray(32, 64);
      const expectedTargetMac = hmacSha256(
        params.transportKey,
        concatBytes(
          utf8Bytes(`edge-target-reply:${params.sessionId}:`),
          sourceNonce,
          targetNonce,
        ),
      );
      if (!constantTimeEqual(targetMac, expectedTargetMac)) {
        throw new Error("Mutual Edge Relay peer authentication failed on source");
      }
    } else {
      const init = await channel.nextFrame(5000);
      if (init.type !== FRAME_AUTH_INIT || init.body.length !== 64) {
        throw new Error("Invalid Edge Relay peer auth init");
      }
      const sourceNonce = init.body.subarray(0, 32);
      const sourceMac = init.body.subarray(32, 64);
      const expectedSourceMac = hmacSha256(
        params.transportKey,
        concatBytes(utf8Bytes(`edge-source-init:${params.sessionId}:`), sourceNonce),
      );
      if (!constantTimeEqual(sourceMac, expectedSourceMac)) {
        throw new Error("Mutual Edge Relay peer authentication failed on target");
      }

      const targetNonce = randomBytes(32);
      const targetMac = hmacSha256(
        params.transportKey,
        concatBytes(
          utf8Bytes(`edge-target-reply:${params.sessionId}:`),
          sourceNonce,
          targetNonce,
        ),
      );
      await channel.sendFrame(FRAME_AUTH_REPLY, concatBytes(targetNonce, targetMac));
    }

    return channel;
  } catch (err) {
    channel.destroy();
    throw err;
  }
}

/**
 * Streams encrypted packs over an established Edge Relay channel using a
 * sliding window of up to `maxInFlight` concurrent packs so high-latency WAN links
 * stay saturated without stalling on per-pack RTT.
 */
export async function streamPackBatchesOverEdgeRelay(params: {
  channel: EdgeRelayBinaryChannel;
  totalBatches: number;
  maxInFlight?: number;
  simulateDropAfterPacks?: number;
  paceBytes?: (byteCount: number) => Promise<void>;
  /**
   * Polled at every pack boundary. Returning `true` stops feeding new packs, drains
   * the in-flight window, and ends the relay stream cleanly so the caller can move
   * the remaining batches onto a better path (hot upgrade to P2P).
   */
  shouldHandOff?: () => boolean;
  producePackAt: (batchIndex: number) => Promise<{ packId: string; wireBytes: Uint8Array }>;
}): Promise<{
  allPackIds: Array<string | undefined>;
  ackedBatchIndices: Set<number>;
  ackedPackIds: string[];
  wireBytesSent: number;
  interrupted: boolean;
  handedOff: boolean;
}> {
  const maxInFlight =
    params.simulateDropAfterPacks !== undefined
      ? 1
      : Math.max(1, params.maxInFlight ?? 4);

  const allPackIds = new Array<string | undefined>(params.totalBatches);
  const packIdToBatchIdx = new Map<string, number>();
  const ackedBatchIndices = new Set<number>();
  const ackedPackIds: string[] = [];
  let wireBytesSent = 0;
  let inFlight = 0;
  let streamError: Error | null = null;
  let notifySlot = null as (() => void) | null;
  let handedOff = false;

  const decoder = new TextDecoder();

  const ackReaderPromise = (async () => {
    while (ackedBatchIndices.size < params.totalBatches && !streamError) {
      try {
        // Generous: a bandwidth-capped sender may pause for a whole pack interval between ACKs
        const frame = await params.channel.nextFrame(120_000);
        if (frame.type !== FRAME_PACK_ACK) {
          throw new Error(`Unexpected Edge Relay ACK frame type: ${frame.type}`);
        }
        const ackedId = decoder.decode(frame.body);
        const batchIdx = packIdToBatchIdx.get(ackedId);
        if (batchIdx !== undefined && !ackedBatchIndices.has(batchIdx)) {
          ackedBatchIndices.add(batchIdx);
          ackedPackIds.push(ackedId);
          inFlight = Math.max(0, inFlight - 1);
          notifySlot?.();
        }
      } catch (err) {
        streamError = err instanceof Error ? err : new Error(String(err));
        notifySlot?.();
        break;
      }
    }
  })();

  for (let i = 0; i < params.totalBatches; i++) {
    while (inFlight >= maxInFlight && !streamError) {
      await new Promise<void>((r) => {
        notifySlot = r;
      });
    }
    if (streamError) break;

    if (params.shouldHandOff?.()) {
      handedOff = true;
      break;
    }

    if (
      params.simulateDropAfterPacks !== undefined &&
      i >= params.simulateDropAfterPacks
    ) {
      streamError = new Error("Simulated Edge Relay connection drop");
      params.channel.destroy();
      break;
    }

    const pack = await params.producePackAt(i);
    allPackIds[i] = pack.packId;
    packIdToBatchIdx.set(pack.packId, i);
    inFlight += 1;

    const idBytes = utf8Bytes(pack.packId);
    const idLen = new Uint8Array([idBytes.length]);
    try {
      await params.paceBytes?.(pack.wireBytes.length);
      await params.channel.sendFrame(
        FRAME_PACK_DATA,
        concatBytes(idLen, idBytes, pack.wireBytes),
      );
      wireBytesSent += pack.wireBytes.length;
    } catch (err) {
      streamError = err instanceof Error ? err : new Error(String(err));
      params.channel.destroy();
      break;
    }
  }

  if (handedOff && !streamError) {
    // Drain the in-flight window so every pack already on the relay is acknowledged,
    // then end the relay stream; un-fed batches continue on the upgraded path.
    const drainDeadline = Date.now() + 15_000;
    while (inFlight > 0 && !streamError && Date.now() < drainDeadline) {
      await new Promise<void>((r) => {
        notifySlot = r;
        setTimeout(r, 250);
      });
    }
    try {
      await params.channel.sendFrame(FRAME_STREAM_END, new Uint8Array(0));
    } catch {
      // Relay already gone; unacknowledged batches are resent on the new path
    }
    params.channel.destroy();
    await ackReaderPromise;
    return {
      allPackIds,
      ackedBatchIndices,
      ackedPackIds,
      wireBytesSent,
      interrupted: false,
      handedOff: true,
    };
  }

  if (streamError) {
    params.channel.destroy();
  }
  await ackReaderPromise;

  if (!streamError && ackedBatchIndices.size === params.totalBatches) {
    try {
      await params.channel.sendFrame(FRAME_STREAM_END, new Uint8Array(0));
    } catch (err) {
      streamError = err instanceof Error ? err : new Error(String(err));
    }
  }

  return {
    allPackIds,
    ackedBatchIndices,
    ackedPackIds,
    wireBytesSent,
    interrupted: Boolean(streamError) || ackedBatchIndices.size < params.totalBatches,
    handedOff: false,
  };
}

export async function receivePacksFromEdgeRelay(
  channel: EdgeRelayBinaryChannel,
  onPack: (packId: string, wireBytes: Uint8Array) => Promise<void>,
): Promise<void> {
  const decoder = new TextDecoder();
  while (true) {
    const frame = await channel.nextFrame(120_000);
    if (frame.type === FRAME_STREAM_END) {
      return;
    }
    if (frame.type !== FRAME_PACK_DATA || frame.body.length < 2) {
      throw new Error(`Unexpected Edge Relay pack frame: ${frame.type}`);
    }
    const idLen = frame.body[0];
    const packId = decoder.decode(frame.body.subarray(1, 1 + idLen));
    const wireBytes = frame.body.subarray(1 + idLen);
    await onPack(packId, wireBytes);
    await channel.sendFrame(FRAME_PACK_ACK, utf8Bytes(packId));
  }
}
