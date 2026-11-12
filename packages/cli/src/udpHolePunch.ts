import dgram from "node:dgram";
import {
  aeadDecrypt,
  aeadEncrypt,
  concatBytes,
  utf8Bytes,
  type EndpointCandidate,
  type NatMappingBehavior,
} from "@beamsync/protocol";
import { listLanIpv4Addresses } from "./framedStream.js";
import {
  acquirePortMapping,
  type ActivePortMapping,
  type NatPmpMapping,
  type PortMappingGateway,
} from "./portMapping.js";
import { classifyNatMappingBehavior } from "./stunClient.js";

const UDP_MAGIC = new Uint8Array([0x42, 0x4d, 0x55, 0x31]); // "BMU1"
const PKT_PUNCH_HELLO = 0x01;
const PKT_PUNCH_ACK = 0x02;
const PKT_DATA_CHUNK = 0x10;
const PKT_DATA_ACK = 0x11;
const PKT_PACK_DONE = 0x12;
const PKT_PACK_DONE_ACK = 0x13;
const PKT_STREAM_FIN = 0x1f;
const PKT_STREAM_FIN_ACK = 0x20;

const PKT_KEEPALIVE = 0x30;
const PKT_MTU_PROBE = 0x31;
const PKT_MTU_PROBE_ACK = 0x32;

/** Conservative chunk payload that fits a 1280-byte path MTU (IPv6 minimum / most tunnels). */
export const DEFAULT_UDP_CHUNK_PAYLOAD_BYTES = 1150;
/**
 * Larger payload sizes tried by path-MTU probing, biggest first. Each maps to an IPv4 packet of
 * `payload + 73` bytes (20 IP + 8 UDP + 4 magic + 28 AEAD + 1 type + 12 chunk header):
 * 1420 -> 1493 (Ethernet/PPPoE), 1340 -> 1413 (WireGuard-style 1420 tunnels), 1232 -> 1305.
 */
export const UDP_MTU_PROBE_PAYLOAD_SIZES = [1420, 1380, 1340, 1300, 1232];
const CHUNK_HEADER_BYTES = 12;
const UDP_KEEPALIVE_INTERVAL_MS = 5_000;
const INITIAL_CWND_CHUNKS = 64;
const MIN_CWND_CHUNKS = 32;
const MAX_CWND_CHUNKS = 256; // ~294 KiB max in-flight window per pack stream

export interface PreparedUdpPunchEndpoint {
  socket: dgram.Socket;
  candidates: EndpointCandidate[];
  natMapping: NatMappingBehavior;
  portStride: number;
  hasSequentialPrediction: boolean;
  /** Gateway port mapping (NAT-PMP) held for this socket, if the router granted one. */
  portMapping: NatPmpMapping | null;
  close(): Promise<void>;
}

export interface UdpPortMappingOptions {
  /** Skip the gateway port-mapping request entirely. */
  disabled?: boolean;
  /** Explicit NAT-PMP gateway (otherwise the default IPv4 gateway is discovered). */
  gateway?: PortMappingGateway;
  timeoutMs?: number;
}

export async function prepareUdpPunchEndpoint(
  stunServers: string[],
  includeLoopbackForTest = false,
  portMappingOptions: UdpPortMappingOptions = {},
): Promise<PreparedUdpPunchEndpoint> {
  const socket = dgram.createSocket("udp4");
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, "0.0.0.0", () => {
      socket.removeListener("error", reject);
      resolve();
    });
  });

  const localAddr = socket.address();
  const localPort = typeof localAddr === "object" ? localAddr.port : 0;
  const candidates: EndpointCandidate[] = [];
  const seen = new Set<string>();

  const addCandidate = (ip: string, port: number) => {
    if (port <= 0 || port > 65535) return;
    const key = `${ip}:${port}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({ kind: "udp_punch", address: ip, port });
  };

  // Ask the gateway for an explicit port mapping while STUN runs, so a router that does not
  // speak NAT-PMP costs no extra time on top of NAT classification.
  const portMappingPromise: Promise<ActivePortMapping | null> = portMappingOptions.disabled
    ? Promise.resolve(null)
    : acquirePortMapping({
        protocol: "udp",
        internalPort: localPort,
        gateway: portMappingOptions.gateway,
        timeoutMs: portMappingOptions.timeoutMs ?? 250,
      }).catch(() => null);

  // Query up to 2 STUN servers on the exact same bound UDP socket to preserve NAT port mapping
  // AND classify Endpoint-Independent (Cone) vs Symmetric NAT + sequential port stride.
  const natInfo = await classifyNatMappingBehavior(socket, stunServers, 600);
  for (const ep of natInfo.endpoints) {
    if (ep.family === 4) {
      addCandidate(ep.ip, ep.port);
    }
  }

  let hasSequentialPrediction = false;
  if (
    natInfo.natMapping === "symmetric" &&
    natInfo.endpoints.length >= 2 &&
    Math.abs(natInfo.portStride) >= 1 &&
    Math.abs(natInfo.portStride) <= 8
  ) {
    const latest = natInfo.endpoints[natInfo.endpoints.length - 1];
    if (latest.family === 4) {
      hasSequentialPrediction = true;
      for (let step = 1; step <= 3; step++) {
        const predictedPort = latest.port + natInfo.portStride * step;
        if (predictedPort >= 1024 && predictedPort <= 65535) {
          addCandidate(latest.ip, predictedPort);
        }
      }
    }
  }

  for (const lanIp of listLanIpv4Addresses()) {
    addCandidate(lanIp, localPort);
  }

  if (includeLoopbackForTest) {
    addCandidate("127.0.0.1", localPort);
  }

  // Hole punching already works behind an endpoint-independent NAT, so there the mapping is
  // not waited for (and is handed back if the gateway grants it later). Behind a symmetric NAT,
  // or when STUN gave no verdict, the mapped endpoint is the one stable public ip:port the
  // peer can dial.
  let portMapping: ActivePortMapping | null = null;
  if (natInfo.natMapping === "endpoint_independent") {
    void portMappingPromise.then((m) => m?.release().catch(() => {}));
  } else {
    portMapping = await portMappingPromise;
    if (portMapping) {
      const key = `${portMapping.mapping.externalIp}:${portMapping.mapping.externalPort}`;
      if (!seen.has(key)) {
        seen.add(key);
        // First in the list: the mapped endpoint is the most likely one to be reachable
        candidates.unshift({
          kind: "udp_punch",
          address: portMapping.mapping.externalIp,
          port: portMapping.mapping.externalPort,
        });
      }
    }
  }

  return {
    socket,
    candidates,
    natMapping: natInfo.natMapping,
    portStride: natInfo.portStride,
    hasSequentialPrediction,
    portMapping: portMapping?.mapping ?? null,
    close: async () => {
      await portMapping?.release().catch(() => {});
      await new Promise<void>((resolve) => {
        try {
          socket.close(() => resolve());
        } catch {
          resolve();
        }
      });
    },
  };
}

export class UdpHolePunchChannel {
  private readonly socket: dgram.Socket;
  private readonly transportKey: Uint8Array;
  private readonly sessionAad: Uint8Array;
  private peerAddress: string;
  private peerPort: number;
  private closed = false;
  private srttMs = 40;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private lastSendAt = 0;
  private outboundFilter: ((datagramBytes: number) => boolean) | null = null;
  /** Payload bytes per data chunk; raised by `probeUdpPathPayloadSize` when the path allows. */
  chunkPayloadBytes = DEFAULT_UDP_CHUNK_PAYLOAD_BYTES;
  private readonly listeners = new Set<
    (pktType: number, body: Uint8Array, rinfo: dgram.RemoteInfo) => void
  >();

  constructor(params: {
    socket: dgram.Socket;
    transportKey: Uint8Array;
    sessionId: string;
    peerAddress: string;
    peerPort: number;
  }) {
    this.socket = params.socket;
    this.transportKey = params.transportKey;
    this.sessionAad = utf8Bytes(`udp:${params.sessionId}`);
    this.peerAddress = params.peerAddress;
    this.peerPort = params.peerPort;

    this.socket.on("message", this.onRawDatagram);
  }

  updateRttSample(sampleMs: number): void {
    const clamped = Math.max(1, Math.min(2000, sampleMs));
    this.srttMs = this.srttMs * 0.8 + clamped * 0.2;
  }

  getAdaptiveRtoMs(): number {
    return Math.max(35, Math.min(600, Math.round(this.srttMs * 2.5)));
  }

  private readonly onRawDatagram = (
    msg: Buffer,
    rinfo: dgram.RemoteInfo,
  ): void => {
    if (this.closed || msg.length < 33) return;
    for (let i = 0; i < 4; i++) {
      if (msg[i] !== UDP_MAGIC[i]) return;
    }
    try {
      const sealed = new Uint8Array(
        msg.buffer,
        msg.byteOffset + 4,
        msg.byteLength - 4,
      );
      const plain = aeadDecrypt(this.transportKey, sealed, this.sessionAad);
      if (plain.length < 1) return;
      // Authenticated peer packet: dynamically update peer address/port for NAT rebinding
      this.peerAddress = rinfo.address;
      this.peerPort = rinfo.port;
      const pktType = plain[0];
      const body = plain.subarray(1);
      // Keepalives carry no payload but still reach listeners so receivers count them as liveness
      if (pktType === PKT_MTU_PROBE && body.length >= 2) {
        // Echo the probed payload size back in a tiny datagram that always fits
        this.sendEncrypted(PKT_MTU_PROBE_ACK, body.subarray(0, 2));
        return;
      }
      for (const fn of [...this.listeners]) {
        fn(pktType, body, rinfo);
      }
    } catch {
      // Ignore unauthenticated/STUN stray datagrams
    }
  };

  sendEncrypted(
    pktType: number,
    body: Uint8Array,
    addr = this.peerAddress,
    port = this.peerPort,
  ): void {
    if (this.closed) return;
    const inner = concatBytes(new Uint8Array([pktType & 0xff]), body);
    const sealed = aeadEncrypt(this.transportKey, inner, this.sessionAad);
    const wire = Buffer.from(concatBytes(UDP_MAGIC, sealed));
    if (this.outboundFilter && !this.outboundFilter(wire.length)) {
      return; // simulated path drop (tests)
    }
    this.lastSendAt = Date.now();
    try {
      this.socket.send(wire, port, addr, () => {});
    } catch {
      // Socket already closed during teardown
    }
  }

  /**
   * Keeps the NAT pinhole open while the channel is established but idle (for example
   * while the session is still streaming over an Edge Relay before a hot upgrade).
   */
  startKeepalive(): void {
    if (this.keepaliveTimer || this.closed) return;
    // Checked every second so the gap between datagrams never exceeds ~UDP_KEEPALIVE_INTERVAL_MS,
    // well inside the receiver's 10 s inactivity timeout (e.g. while the sender is being paced).
    this.keepaliveTimer = setInterval(() => {
      if (Date.now() - this.lastSendAt >= UDP_KEEPALIVE_INTERVAL_MS - 1000) {
        this.sendEncrypted(PKT_KEEPALIVE, new Uint8Array(0));
      }
    }, 1000);
    this.keepaliveTimer.unref();
  }

  /** Test hook: return `false` to drop an outbound datagram of the given size (simulated MTU). */
  setOutboundDatagramFilterForTest(
    filter: ((datagramBytes: number) => boolean) | null,
  ): void {
    this.outboundFilter = filter;
  }

  onPacket(
    fn: (pktType: number, body: Uint8Array, rinfo: dgram.RemoteInfo) => void,
  ): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  destroy(): void {
    this.closed = true;
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = null;
    }
    this.socket.off("message", this.onRawDatagram);
  }
}

/**
 * Simultaneous bidirectional UDP hole punching across all peer `udp_punch` candidates.
 * Both endpoints fire AEAD-authenticated `PKT_PUNCH_HELLO` probes every 50ms so stateful
 * NAT firewalls open return pinholes on both sides, completing once mutual `PKT_PUNCH_ACK`
 * is confirmed.
 */
export async function establishUdpHolePunch(params: {
  socket: dgram.Socket;
  transportKey: Uint8Array;
  sessionId: string;
  peerUdpCandidates: EndpointCandidate[];
  timeoutMs?: number;
  /** Cancels a long-running background punch (session finished or path no longer needed). */
  signal?: AbortSignal;
}): Promise<UdpHolePunchChannel> {
  const udpCands = params.peerUdpCandidates.filter(
    (c) => c.kind === "udp_punch" && c.port,
  );
  if (udpCands.length === 0) {
    throw new Error("No peer UDP candidates available for hole punching");
  }

  const channel = new UdpHolePunchChannel({
    socket: params.socket,
    transportKey: params.transportKey,
    sessionId: params.sessionId,
    peerAddress: udpCands[0].address,
    peerPort: udpCands[0].port!,
  });

  const timeoutMs = params.timeoutMs ?? 1200;
  const punchStartedAt = performance.now();

  return new Promise<UdpHolePunchChannel>((resolve, reject) => {
    let gotPeerHello = false;
    let gotPeerAck = false;
    let settled = false;

    const finishOk = () => {
      if (settled) return;
      settled = true;
      channel.updateRttSample(Math.min(400, performance.now() - punchStartedAt));
      clearTimeout(probeTimer);
      clearTimeout(timer);
      params.signal?.removeEventListener("abort", onAbort);
      unsub();
      channel.startKeepalive();
      resolve(channel);
    };

    const finishErr = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(probeTimer);
      clearTimeout(timer);
      params.signal?.removeEventListener("abort", onAbort);
      unsub();
      channel.destroy();
      reject(err);
    };

    const unsub = channel.onPacket((pktType, _body, rinfo) => {
      if (pktType === PKT_PUNCH_HELLO) {
        gotPeerHello = true;
        // Echo both HELLO and ACK so a peer that attached slightly after us completes in 1 RTT
        channel.sendEncrypted(
          PKT_PUNCH_HELLO,
          new Uint8Array(0),
          rinfo.address,
          rinfo.port,
        );
        channel.sendEncrypted(
          PKT_PUNCH_ACK,
          new Uint8Array(0),
          rinfo.address,
          rinfo.port,
        );
        if (gotPeerHello && gotPeerAck) finishOk();
      } else if (pktType === PKT_PUNCH_ACK) {
        gotPeerAck = true;
        if (gotPeerHello) {
          channel.sendEncrypted(
            PKT_PUNCH_ACK,
            new Uint8Array(0),
            rinfo.address,
            rinfo.port,
          );
          finishOk();
        }
      }
    });

    const fireProbes = () => {
      for (const c of udpCands) {
        channel.sendEncrypted(
          PKT_PUNCH_HELLO,
          new Uint8Array(0),
          c.address,
          c.port!,
        );
        if (gotPeerHello) {
          channel.sendEncrypted(
            PKT_PUNCH_ACK,
            new Uint8Array(0),
            c.address,
            c.port!,
          );
        }
      }
    };

    const onAbort = () => finishErr(new Error("UDP hole punch aborted"));
    if (params.signal?.aborted) {
      queueMicrotask(onAbort);
    } else {
      params.signal?.addEventListener("abort", onAbort, { once: true });
    }

    // Aggressive 50ms probing for the first 2s, then 250ms so a long background punch
    // (kept alive while data already flows over an Edge Relay) stays cheap.
    let probeTimer: ReturnType<typeof setTimeout>;
    const scheduleProbe = () => {
      const elapsed = performance.now() - punchStartedAt;
      probeTimer = setTimeout(() => {
        if (settled) return;
        fireProbes();
        scheduleProbe();
      }, elapsed < 2000 ? 50 : 250);
    };
    fireProbes();
    scheduleProbe();
    const timer = setTimeout(
      () => finishErr(new Error("UDP hole punch timed out")),
      timeoutMs,
    );
  });
}

/**
 * Probe-based path payload sizing (in the spirit of RFC 8899 DPLPMTUD, search-down only).
 * Sends padded probes for every candidate size, waits for authenticated echoes, and raises
 * `channel.chunkPayloadBytes` to the largest size that survived the path. If nothing larger
 * gets through, the conservative 1150-byte default is kept, so probing can only help.
 */
export async function probeUdpPathPayloadSize(
  channel: UdpHolePunchChannel,
  opts: { candidates?: number[]; rounds?: number; waitMs?: number } = {},
): Promise<number> {
  const candidates = [...(opts.candidates ?? UDP_MTU_PROBE_PAYLOAD_SIZES)]
    .filter((n) => n > DEFAULT_UDP_CHUNK_PAYLOAD_BYTES && n <= 8192)
    .sort((a, b) => b - a);
  if (candidates.length === 0) return channel.chunkPayloadBytes;

  const rounds = Math.max(1, opts.rounds ?? 3);
  const waitMs = opts.waitMs ?? Math.max(120, Math.min(600, channel.getAdaptiveRtoMs() * 2));
  const confirmed = new Set<number>();

  const unsub = channel.onPacket((pktType, body) => {
    if (pktType === PKT_MTU_PROBE_ACK && body.length >= 2) {
      confirmed.add((body[0] << 8) | body[1]);
    }
  });

  try {
    for (let round = 0; round < rounds; round++) {
      for (const size of candidates) {
        if (confirmed.has(size)) continue;
        // Same on-wire size as a full data chunk carrying `size` payload bytes
        const probe = new Uint8Array(CHUNK_HEADER_BYTES + size);
        probe[0] = (size >> 8) & 0xff;
        probe[1] = size & 0xff;
        channel.sendEncrypted(PKT_MTU_PROBE, probe);
      }
      await new Promise((r) => setTimeout(r, Math.ceil(waitMs / rounds)));
      if (confirmed.has(candidates[0])) break;
    }
  } finally {
    unsub();
  }

  const best = candidates.find((size) => confirmed.has(size));
  if (best !== undefined) {
    channel.chunkPayloadBytes = best;
  }
  return channel.chunkPayloadBytes;
}

export async function sendPackOverUdp(
  channel: UdpHolePunchChannel,
  packSeq: number,
  packId: string,
  wireBytes: Uint8Array,
): Promise<void> {
  // Snapshot per pack: the receiver reassembles by chunk index, so the size only has
  // to stay constant within one pack and may differ between packs.
  const chunkPayloadBytes = channel.chunkPayloadBytes;
  const totalChunks = Math.max(
    1,
    Math.ceil(wireBytes.length / chunkPayloadBytes),
  );
  const acked = new Uint8Array(totalChunks);
  const firstSentAt = new Float64Array(totalChunks);
  const txCount = new Uint16Array(totalChunks);
  let ackedCount = 0;

  await new Promise<void>((resolve, reject) => {
    let base = 0;
    let retries = 0;
    let cwnd = INITIAL_CWND_CHUNKS;
    let retransmitTimer: ReturnType<typeof setTimeout> | null = null;

    const markChunkAcked = (idx: number, now: number): boolean => {
      if (idx < 0 || idx >= totalChunks || acked[idx]) return false;
      acked[idx] = 1;
      ackedCount++;
      if (txCount[idx] === 1 && firstSentAt[idx] > 0) {
        channel.updateRttSample(now - firstSentAt[idx]);
      }
      return true;
    };

    const scheduleRto = () => {
      if (retransmitTimer) clearTimeout(retransmitTimer);
      retransmitTimer = setTimeout(() => {
        retries++;
        if (retries > 45) {
          unsub();
          reject(new Error("UDP pack stream exceeded retransmission limit"));
          return;
        }
        // Multiplicative decrease on loss/timeout
        cwnd = Math.max(MIN_CWND_CHUNKS, Math.floor(cwnd / 2));
        sendWindow(true);
        scheduleRto();
      }, channel.getAdaptiveRtoMs());
    };

    const unsub = channel.onPacket((pktType, body) => {
      if (pktType === PKT_DATA_ACK && body.length >= 8) {
        const view = new DataView(
          body.buffer,
          body.byteOffset,
          body.byteLength,
        );
        const rxPackSeq = view.getUint32(0, false);
        if (rxPackSeq !== packSeq) return;

        const now = performance.now();
        const chunkIdx = view.getUint32(4, false);
        let newlyAcked = 0;
        if (markChunkAcked(chunkIdx, now)) {
          newlyAcked++;
        }

        // Process optional cumulative base + 64-bit SACK bitmap (20-byte ACK frame)
        if (body.length >= 20) {
          const peerBase = Math.min(totalChunks, view.getUint32(8, false));
          for (let c = base; c < peerBase; c++) {
            if (markChunkAcked(c, now)) newlyAcked++;
          }
          const sackHi = view.getUint32(12, false);
          const sackLo = view.getUint32(16, false);
          for (let bit = 0; bit < 64; bit++) {
            const isSet =
              bit < 32
                ? ((sackLo >>> bit) & 1) === 1
                : ((sackHi >>> (bit - 32)) & 1) === 1;
            if (isSet && markChunkAcked(peerBase + bit, now)) {
              newlyAcked++;
            }
          }
        }

        if (newlyAcked > 0) {
          retries = 0;
          // Additive / slow-start increase up to MAX_CWND_CHUNKS
          cwnd = Math.min(MAX_CWND_CHUNKS, cwnd + Math.min(4, newlyAcked));
          while (base < totalChunks && acked[base]) {
            base++;
          }
          if (ackedCount === totalChunks) {
            if (retransmitTimer) clearTimeout(retransmitTimer);
            unsub();
            resolve();
            return;
          }
          sendWindow(false);
          scheduleRto();
        }
      }
    });

    const sendChunk = (idx: number) => {
      const start = idx * chunkPayloadBytes;
      const end = Math.min(wireBytes.length, start + chunkPayloadBytes);
      const slice = wireBytes.subarray(start, end);
      const header = new Uint8Array(12);
      const dv = new DataView(header.buffer);
      dv.setUint32(0, packSeq, false);
      dv.setUint32(4, idx, false);
      dv.setUint32(8, totalChunks, false);
      if (txCount[idx] === 0) {
        firstSentAt[idx] = performance.now();
      }
      txCount[idx]++;
      channel.sendEncrypted(PKT_DATA_CHUNK, concatBytes(header, slice));
    };

    let highestSent = -1;
    const sendWindow = (retransmitUnacked: boolean) => {
      const winEnd = Math.min(totalChunks, base + cwnd);
      for (let i = base; i < winEnd; i++) {
        if (!acked[i] && (retransmitUnacked || i > highestSent)) {
          sendChunk(i);
          if (i > highestSent) highestSent = i;
        }
      }
    };

    sendWindow(false);
    scheduleRto();
  });

  // Confirm full pack assembly on receiver
  const idBytes = utf8Bytes(packId);
  const doneHeader = new Uint8Array(4);
  new DataView(doneHeader.buffer).setUint32(0, packSeq, false);
  const donePayload = concatBytes(doneHeader, idBytes);

  await new Promise<void>((resolve, reject) => {
    let attempts = 0;
    const unsub = channel.onPacket((pktType, body) => {
      if (pktType === PKT_PACK_DONE_ACK && body.length >= 4) {
        const seq = new DataView(
          body.buffer,
          body.byteOffset,
          body.byteLength,
        ).getUint32(0, false);
        if (seq === packSeq) {
          clearInterval(timer);
          unsub();
          resolve();
        }
      }
    });

    channel.sendEncrypted(PKT_PACK_DONE, donePayload);
    const timer = setInterval(() => {
      attempts++;
      if (attempts > 45) {
        clearInterval(timer);
        unsub();
        reject(new Error("UDP PACK_DONE confirmation timed out"));
        return;
      }
      channel.sendEncrypted(PKT_PACK_DONE, donePayload);
    }, channel.getAdaptiveRtoMs());
  });
}

export async function finishUdpStream(
  channel: UdpHolePunchChannel,
): Promise<void> {
  await new Promise<void>((resolve) => {
    let attempts = 0;
    const unsub = channel.onPacket((pktType) => {
      if (pktType === PKT_STREAM_FIN_ACK) {
        clearInterval(timer);
        unsub();
        resolve();
      }
    });
    channel.sendEncrypted(PKT_STREAM_FIN, new Uint8Array(0));
    const timer = setInterval(() => {
      attempts++;
      if (attempts > 20) {
        clearInterval(timer);
        unsub();
        resolve();
        return;
      }
      channel.sendEncrypted(PKT_STREAM_FIN, new Uint8Array(0));
    }, 50);
  });
}

export async function receivePacksFromUdp(
  channel: UdpHolePunchChannel,
  onPack: (packId: string, wireBytes: Uint8Array) => Promise<void>,
): Promise<void> {
  const decoder = new TextDecoder();
  const buffersBySeq = new Map<
    number,
    {
      totalChunks: number;
      chunks: Array<Uint8Array | undefined>;
      received: number;
      rxBase: number;
    }
  >();
  const deliveredSeqs = new Set<number>();

  return new Promise<void>((resolve, reject) => {
    let processingChain = Promise.resolve();
    let idleTimer = setTimeout(() => {
      unsub();
      reject(new Error("UDP receiver timed out due to inactivity"));
    }, 10_000);

    const resetIdle = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        unsub();
        reject(new Error("UDP receiver timed out due to inactivity"));
      }, 10_000);
    };

    const unsub = channel.onPacket((pktType, body) => {
      resetIdle();
      if (pktType === PKT_PUNCH_HELLO) {
        channel.sendEncrypted(PKT_PUNCH_ACK, new Uint8Array(0));
        return;
      }

      if (pktType === PKT_DATA_CHUNK && body.length >= 12) {
        const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
        const packSeq = dv.getUint32(0, false);
        const chunkIdx = dv.getUint32(4, false);
        const totalChunks = dv.getUint32(8, false);
        const slice = new Uint8Array(body.subarray(12));

        let state = buffersBySeq.get(packSeq);
        if (!state) {
          state = {
            totalChunks,
            chunks: new Array(totalChunks),
            received: 0,
            rxBase: 0,
          };
          buffersBySeq.set(packSeq, state);
        }
        if (chunkIdx < totalChunks && !state.chunks[chunkIdx]) {
          state.chunks[chunkIdx] = slice;
          state.received++;
          while (state.rxBase < totalChunks && state.chunks[state.rxBase]) {
            state.rxBase++;
          }
        }

        // 20-byte cumulative + 64-bit SACK ACK frame
        const ackBuf = new Uint8Array(20);
        const ackDv = new DataView(ackBuf.buffer);
        ackDv.setUint32(0, packSeq, false);
        ackDv.setUint32(4, chunkIdx, false);
        const rxBase = state.rxBase;
        ackDv.setUint32(8, rxBase, false);

        let sackLo = 0;
        let sackHi = 0;
        for (let bit = 0; bit < 64; bit++) {
          const targetIdx = rxBase + bit;
          if (targetIdx >= totalChunks) break;
          if (state.chunks[targetIdx]) {
            if (bit < 32) {
              sackLo = (sackLo | (1 << bit)) >>> 0;
            } else {
              sackHi = (sackHi | (1 << (bit - 32))) >>> 0;
            }
          }
        }
        ackDv.setUint32(12, sackHi, false);
        ackDv.setUint32(16, sackLo, false);
        channel.sendEncrypted(PKT_DATA_ACK, ackBuf);
        return;
      }

      if (pktType === PKT_PACK_DONE && body.length >= 5) {
        const packSeq = new DataView(
          body.buffer,
          body.byteOffset,
          body.byteLength,
        ).getUint32(0, false);
        const packId = decoder.decode(body.subarray(4));

        const state = buffersBySeq.get(packSeq);
        if (deliveredSeqs.has(packSeq)) {
          const ack = new Uint8Array(4);
          new DataView(ack.buffer).setUint32(0, packSeq, false);
          channel.sendEncrypted(PKT_PACK_DONE_ACK, ack);
          return;
        }

        if (state && state.received === state.totalChunks) {
          deliveredSeqs.add(packSeq);
          const fullBytes = concatBytes(...(state.chunks as Uint8Array[]));
          buffersBySeq.delete(packSeq);

          processingChain = processingChain
            .then(async () => {
              await onPack(packId, fullBytes);
              const ack = new Uint8Array(4);
              new DataView(ack.buffer).setUint32(0, packSeq, false);
              channel.sendEncrypted(PKT_PACK_DONE_ACK, ack);
            })
            .catch((err) => {
              clearTimeout(idleTimer);
              unsub();
              reject(err instanceof Error ? err : new Error(String(err)));
            });
        }
        return;
      }

      if (pktType === PKT_STREAM_FIN) {
        channel.sendEncrypted(PKT_STREAM_FIN_ACK, new Uint8Array(0));
        processingChain
          .then(() => {
            clearTimeout(idleTimer);
            unsub();
            resolve();
          })
          .catch((err) => {
            clearTimeout(idleTimer);
            unsub();
            reject(err instanceof Error ? err : new Error(String(err)));
          });
      }
    });
  });
}
