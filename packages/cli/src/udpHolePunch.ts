import dgram from "node:dgram";
import {
  aeadDecrypt,
  aeadEncrypt,
  concatBytes,
  utf8Bytes,
  type EndpointCandidate,
} from "@beamsync/protocol";
import { listLanIpv4Addresses } from "./framedStream.js";
import { queryStunReflexiveAddress } from "./stunClient.js";

const UDP_MAGIC = new Uint8Array([0x42, 0x4d, 0x55, 0x31]); // "BMU1"
const PKT_PUNCH_HELLO = 0x01;
const PKT_PUNCH_ACK = 0x02;
const PKT_DATA_CHUNK = 0x10;
const PKT_DATA_ACK = 0x11;
const PKT_PACK_DONE = 0x12;
const PKT_PACK_DONE_ACK = 0x13;
const PKT_STREAM_FIN = 0x1f;
const PKT_STREAM_FIN_ACK = 0x20;

const CHUNK_PAYLOAD_BYTES = 1150; // Safe below standard 1280/1500 UDP MTU
const WINDOW_SIZE = 32;

export interface PreparedUdpPunchEndpoint {
  socket: dgram.Socket;
  candidates: EndpointCandidate[];
  close(): Promise<void>;
}

export async function prepareUdpPunchEndpoint(
  stunServers: string[],
  includeLoopbackForTest = false,
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
    const key = `${ip}:${port}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({ kind: "udp_punch", address: ip, port });
  };

  // Query STUN servers on the exact same bound UDP socket to preserve NAT port mapping
  for (const stunUrl of stunServers.slice(0, 2)) {
    const reflexive = await queryStunReflexiveAddress(socket, stunUrl, 600);
    if (reflexive) {
      addCandidate(reflexive.ip, reflexive.port);
      break;
    }
  }

  for (const lanIp of listLanIpv4Addresses()) {
    addCandidate(lanIp, localPort);
  }

  if (includeLoopbackForTest) {
    addCandidate("127.0.0.1", localPort);
  }

  return {
    socket,
    candidates,
    close: () =>
      new Promise<void>((resolve) => {
        try {
          socket.close(() => resolve());
        } catch {
          resolve();
        }
      }),
  };
}

export class UdpHolePunchChannel {
  private readonly socket: dgram.Socket;
  private readonly transportKey: Uint8Array;
  private readonly sessionAad: Uint8Array;
  private peerAddress: string;
  private peerPort: number;
  private closed = false;
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
      for (const fn of this.listeners) {
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
    this.socket.send(wire, port, addr);
  }

  onPacket(
    fn: (pktType: number, body: Uint8Array, rinfo: dgram.RemoteInfo) => void,
  ): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  destroy(): void {
    this.closed = true;
    this.socket.off("message", this.onRawDatagram);
  }
}

/**
 * Simultaneous bidirectional UDP hole punching across all peer `udp_punch` candidates.
 * Both endpoints fire AEAD-authenticated `PKT_PUNCH_HELLO` probes every 60ms so stateful
 * NAT firewalls open return pinholes on both sides, completing once mutual `PKT_PUNCH_ACK`
 * is confirmed.
 */
export async function establishUdpHolePunch(params: {
  socket: dgram.Socket;
  transportKey: Uint8Array;
  sessionId: string;
  peerUdpCandidates: EndpointCandidate[];
  timeoutMs?: number;
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

  return new Promise<UdpHolePunchChannel>((resolve, reject) => {
    let gotPeerHello = false;
    let gotPeerAck = false;
    let settled = false;

    const finishOk = () => {
      if (settled) return;
      settled = true;
      clearInterval(probeInterval);
      clearTimeout(timer);
      unsub();
      resolve(channel);
    };

    const finishErr = (err: Error) => {
      if (settled) return;
      settled = true;
      clearInterval(probeInterval);
      clearTimeout(timer);
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

    fireProbes();
    const probeInterval = setInterval(fireProbes, 50);
    const timer = setTimeout(
      () => finishErr(new Error("UDP hole punch timed out")),
      timeoutMs,
    );
  });
}

export async function sendPackOverUdp(
  channel: UdpHolePunchChannel,
  packSeq: number,
  packId: string,
  wireBytes: Uint8Array,
): Promise<void> {
  const totalChunks = Math.max(
    1,
    Math.ceil(wireBytes.length / CHUNK_PAYLOAD_BYTES),
  );
  const acked = new Uint8Array(totalChunks);
  let ackedCount = 0;

  await new Promise<void>((resolve, reject) => {
    let base = 0;
    let retries = 0;

    const unsub = channel.onPacket((pktType, body) => {
      if (pktType === PKT_DATA_ACK && body.length >= 8) {
        const view = new DataView(
          body.buffer,
          body.byteOffset,
          body.byteLength,
        );
        const rxPackSeq = view.getUint32(0, false);
        const chunkIdx = view.getUint32(4, false);
        if (rxPackSeq === packSeq && chunkIdx < totalChunks && !acked[chunkIdx]) {
          acked[chunkIdx] = 1;
          ackedCount++;
          retries = 0;
          while (base < totalChunks && acked[base]) {
            base++;
          }
          if (ackedCount === totalChunks) {
            clearInterval(retransmitTimer);
            unsub();
            resolve();
            return;
          }
          sendWindow(false);
        }
      }
    });

    const sendChunk = (idx: number) => {
      const start = idx * CHUNK_PAYLOAD_BYTES;
      const end = Math.min(wireBytes.length, start + CHUNK_PAYLOAD_BYTES);
      const slice = wireBytes.subarray(start, end);
      const header = new Uint8Array(12);
      const dv = new DataView(header.buffer);
      dv.setUint32(0, packSeq, false);
      dv.setUint32(4, idx, false);
      dv.setUint32(8, totalChunks, false);
      channel.sendEncrypted(PKT_DATA_CHUNK, concatBytes(header, slice));
    };

    let highestSent = -1;
    const sendWindow = (retransmitUnacked: boolean) => {
      const winEnd = Math.min(totalChunks, base + WINDOW_SIZE);
      for (let i = base; i < winEnd; i++) {
        if (!acked[i] && (retransmitUnacked || i > highestSent)) {
          sendChunk(i);
          if (i > highestSent) highestSent = i;
        }
      }
    };

    sendWindow(false);
    const retransmitTimer = setInterval(() => {
      retries++;
      if (retries > 40) {
        clearInterval(retransmitTimer);
        unsub();
        reject(new Error("UDP pack stream exceeded retransmission limit"));
        return;
      }
      sendWindow(true);
    }, 60);
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
      if (attempts > 40) {
        clearInterval(timer);
        unsub();
        reject(new Error("UDP PACK_DONE confirmation timed out"));
        return;
      }
      channel.sendEncrypted(PKT_PACK_DONE, donePayload);
    }, 60);
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
    { totalChunks: number; chunks: Array<Uint8Array | undefined>; received: number }
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
          };
          buffersBySeq.set(packSeq, state);
        }
        if (chunkIdx < totalChunks && !state.chunks[chunkIdx]) {
          state.chunks[chunkIdx] = slice;
          state.received++;
        }

        const ackBuf = new Uint8Array(8);
        const ackDv = new DataView(ackBuf.buffer);
        ackDv.setUint32(0, packSeq, false);
        ackDv.setUint32(4, chunkIdx, false);
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
