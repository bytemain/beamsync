import net from "node:net";
import { chmod, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  bytesToHex,
  concatBytes,
  constantTimeEqual,
  hmacSha256,
  randomBytes,
  utf8Bytes,
  type EndpointCandidate,
} from "@beamsync/protocol";

const FRAME_AUTH_INIT = 0x01;
const FRAME_AUTH_REPLY = 0x02;
const FRAME_PACK_DATA = 0x10;
const FRAME_PACK_ACK = 0x11;
const FRAME_STREAM_END = 0x1f;

export class FramedSocketChannel {
  private readonly socket: net.Socket;
  private buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  private readonly pendingFrames: Uint8Array[] = [];
  private readonly frameWaiters: Array<{
    resolve: (frame: Uint8Array) => void;
    reject: (err: Error) => void;
  }> = [];
  private closedError: Error | null = null;

  constructor(socket: net.Socket) {
    this.socket = socket;
    this.socket.setNoDelay?.(true);

    socket.on("data", (chunk: Buffer) => {
      this.buffer =
        this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
      this.drainFrames();
    });

    const failAll = (err: Error) => {
      if (!this.closedError) {
        this.closedError = err;
      }
      while (this.frameWaiters.length > 0) {
        const w = this.frameWaiters.shift()!;
        w.reject(this.closedError);
      }
    };

    socket.on("error", (err) => failAll(err));
    socket.on("close", () => failAll(new Error("FramedSocketChannel closed")));
  }

  private drainFrames(): void {
    while (this.buffer.length >= 4) {
      const len = this.buffer.readUInt32BE(0);
      if (len > 64 * 1024 * 1024) {
        this.socket.destroy(new Error("Frame exceeds maximum 64 MiB limit"));
        return;
      }
      if (this.buffer.length < 4 + len) {
        return;
      }
      const payload = new Uint8Array(this.buffer.subarray(4, 4 + len));
      this.buffer = this.buffer.subarray(4 + len);
      const waiter = this.frameWaiters.shift();
      if (waiter) {
        waiter.resolve(payload);
      } else {
        this.pendingFrames.push(payload);
      }
    }
  }

  async sendFrame(typeByte: number, body: Uint8Array): Promise<void> {
    if (this.closedError) throw this.closedError;
    const len = 1 + body.length;
    const header = Buffer.allocUnsafe(5);
    header.writeUInt32BE(len, 0);
    header[4] = typeByte & 0xff;
    const packet = Buffer.concat([
      header,
      Buffer.from(body.buffer, body.byteOffset, body.byteLength),
    ]);

    await new Promise<void>((resolve, reject) => {
      // Listeners are removed as soon as the write settles: a long transfer waits for
      // "drain" on almost every pack and must not pile up one listener per wait
      let waitingForDrain = false;
      const settle = (err?: Error | null) => {
        if (waitingForDrain) {
          this.socket.removeListener("drain", onDrain);
          this.socket.removeListener("error", onError);
          this.socket.removeListener("close", onClose);
          waitingForDrain = false;
        }
        if (err) reject(err);
        else resolve();
      };
      const onDrain = () => settle();
      const onError = (err: Error) => settle(err);
      const onClose = () => settle(this.closedError ?? new Error("FramedSocketChannel closed"));
      const canContinue = this.socket.write(packet, (err) => {
        if (err) settle(err);
        else if (canContinue) settle();
      });
      if (!canContinue) {
        waitingForDrain = true;
        this.socket.once("drain", onDrain);
        this.socket.once("error", onError);
        this.socket.once("close", onClose);
      }
    });
  }

  async nextFrame(timeoutMs = 15_000): Promise<{ type: number; body: Uint8Array }> {
    if (this.pendingFrames.length > 0) {
      const raw = this.pendingFrames.shift()!;
      return { type: raw[0], body: raw.subarray(1) };
    }
    if (this.closedError) throw this.closedError;

    const raw = await new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.frameWaiters.findIndex((w) => w.resolve === wrappedResolve);
        if (idx >= 0) this.frameWaiters.splice(idx, 1);
        reject(new Error("Timed out waiting for socket frame"));
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
      throw new Error("Empty socket frame");
    }
    return { type: raw[0], body: raw.subarray(1) };
  }

  destroy(): void {
    this.socket.destroy();
  }
}

/**
 * Mutual challenge-response handshake using `transportKey` so that even on a shared
 * `0666` `/tmp` Unix domain socket or LAN port, any unauthenticated third-party
 * process is rejected before a single metadata or file byte is exchanged.
 */
export async function authenticateClientChannel(
  channel: FramedSocketChannel,
  transportKey: Uint8Array,
  sessionId: string,
  timeoutMs = 4000,
): Promise<void> {
  const clientNonce = randomBytes(32);
  const clientMac = hmacSha256(
    transportKey,
    concatBytes(utf8Bytes(`client-init:${sessionId}:`), clientNonce),
  );
  await channel.sendFrame(FRAME_AUTH_INIT, concatBytes(clientNonce, clientMac));

  const reply = await channel.nextFrame(timeoutMs);
  if (reply.type !== FRAME_AUTH_REPLY || reply.body.length !== 64) {
    throw new Error("Invalid server auth reply");
  }
  const serverNonce = reply.body.subarray(0, 32);
  const serverMac = reply.body.subarray(32, 64);
  const expectedServerMac = hmacSha256(
    transportKey,
    concatBytes(
      utf8Bytes(`server-reply:${sessionId}:`),
      clientNonce,
      serverNonce,
    ),
  );
  if (!constantTimeEqual(serverMac, expectedServerMac)) {
    throw new Error("Mutual transport authentication failed on client");
  }
}

export async function authenticateServerChannel(
  channel: FramedSocketChannel,
  transportKey: Uint8Array,
  sessionId: string,
): Promise<void> {
  const init = await channel.nextFrame(4000);
  if (init.type !== FRAME_AUTH_INIT || init.body.length !== 64) {
    throw new Error("Invalid client auth init frame");
  }
  const clientNonce = init.body.subarray(0, 32);
  const clientMac = init.body.subarray(32, 64);
  const expectedClientMac = hmacSha256(
    transportKey,
    concatBytes(utf8Bytes(`client-init:${sessionId}:`), clientNonce),
  );
  if (!constantTimeEqual(clientMac, expectedClientMac)) {
    throw new Error("Unauthorized local/LAN client rejected");
  }

  const serverNonce = randomBytes(32);
  const serverMac = hmacSha256(
    transportKey,
    concatBytes(
      utf8Bytes(`server-reply:${sessionId}:`),
      clientNonce,
      serverNonce,
    ),
  );
  await channel.sendFrame(FRAME_AUTH_REPLY, concatBytes(serverNonce, serverMac));
}

export interface TargetDirectListeners {
  candidates: EndpointCandidate[];
  waitForAuthenticatedChannel(timeoutMs?: number): Promise<{
    channel: FramedSocketChannel;
    kind: EndpointCandidate["kind"];
  }>;
  closeAll(): Promise<void>;
}

export async function createTargetDirectListeners(params: {
  sessionId: string;
  transportKey: Uint8Array;
  enableLocalIpc: boolean;
  enableLanTcp: boolean;
  /** Test hook: advertise 127.0.0.1 as a `lan_tcp` candidate on hosts without a LAN NIC. */
  includeLoopbackTcpForTest?: boolean;
  rejectedAttemptCounter?: { count: number };
}): Promise<TargetDirectListeners> {
  const candidates: EndpointCandidate[] = [];
  const servers: net.Server[] = [];
  let unixSockPath: string | null = null;

  let resolvedChannel: {
    channel: FramedSocketChannel;
    kind: EndpointCandidate["kind"];
  } | null = null;
  let channelWaiter: ((val: {
    channel: FramedSocketChannel;
    kind: EndpointCandidate["kind"];
  }) => void) | null = null;

  const acceptedSockets = new Set<net.Socket>();

  const acceptSocket = (
    rawSock: net.Socket,
    kind: EndpointCandidate["kind"],
  ) => {
    const ch = new FramedSocketChannel(rawSock);
    acceptedSockets.add(rawSock);
    rawSock.once("close", () => acceptedSockets.delete(rawSock));
    void authenticateServerChannel(ch, params.transportKey, params.sessionId)
      .then(() => {
        if (resolvedChannel) {
          ch.destroy();
          return;
        }
        resolvedChannel = { channel: ch, kind };
        if (channelWaiter) {
          const w = channelWaiter;
          channelWaiter = null;
          w(resolvedChannel);
        }
      })
      .catch(() => {
        if (params.rejectedAttemptCounter) {
          params.rejectedAttemptCounter.count += 1;
        }
        ch.destroy();
      });
  };

  if (params.enableLocalIpc) {
    if (process.platform !== "win32") {
      unixSockPath = path.join(
        os.tmpdir(),
        `beamsync-${bytesToHex(randomBytes(8))}.sock`,
      );
      const unixServer = net.createServer((sock) =>
        acceptSocket(sock, "unix_socket"),
      );
      try {
        await new Promise<void>((resolve, reject) => {
          unixServer.once("error", reject);
          unixServer.listen(unixSockPath!, () => {
            unixServer.removeListener("error", reject);
            resolve();
          });
        });
        // Mode 0666 enables User A and User B on the same host to connect across UIDs
        // while mutual HMAC authentication on frame 0 prevents unauthorized access.
        await chmod(unixSockPath, 0o666);
        servers.push(unixServer);
        candidates.push({ kind: "unix_socket", address: unixSockPath });
      } catch {
        unixSockPath = null;
      }
    }

    const loServer = net.createServer((sock) =>
      acceptSocket(sock, "loopback_tcp"),
    );
    await new Promise<void>((resolve, reject) => {
      loServer.once("error", reject);
      loServer.listen(0, "127.0.0.1", () => {
        loServer.removeListener("error", reject);
        resolve();
      });
    });
    const loAddr = loServer.address();
    if (loAddr && typeof loAddr === "object") {
      servers.push(loServer);
      candidates.push({
        kind: "loopback_tcp",
        address: "127.0.0.1",
        port: loAddr.port,
      });
    }
  }

  if (params.enableLanTcp) {
    const discovered = discoverDirectIpAddresses();
    if (params.includeLoopbackTcpForTest) {
      discovered.push({
        address: "127.0.0.1",
        family: 4,
        category: "lan",
        interfaceName: "lo",
      });
    }
    const ipv4List = discovered.filter((d) => d.family === 4);
    const ipv6List = discovered.filter((d) => d.family === 6);

    let ipv4Port: number | null = null;
    if (ipv4List.length > 0) {
      const lanServerV4 = net.createServer((sock) =>
        acceptSocket(sock, "lan_tcp"),
      );
      await new Promise<void>((resolve, reject) => {
        lanServerV4.once("error", reject);
        lanServerV4.listen(0, "0.0.0.0", () => {
          lanServerV4.removeListener("error", reject);
          resolve();
        });
      });
      const lanAddrV4 = lanServerV4.address();
      if (lanAddrV4 && typeof lanAddrV4 === "object") {
        servers.push(lanServerV4);
        ipv4Port = lanAddrV4.port;
      }
    }

    let ipv6Port: number | null = null;
    if (ipv6List.length > 0) {
      const lanServerV6 = net.createServer((sock) =>
        acceptSocket(sock, "lan_tcp"),
      );
      try {
        await new Promise<void>((resolve, reject) => {
          lanServerV6.once("error", reject);
          lanServerV6.listen({ port: 0, host: "::", ipv6Only: true }, () => {
            lanServerV6.removeListener("error", reject);
            resolve();
          });
        });
        const lanAddrV6 = lanServerV6.address();
        if (lanAddrV6 && typeof lanAddrV6 === "object") {
          servers.push(lanServerV6);
          ipv6Port = lanAddrV6.port;
        }
      } catch {
        // Host kernel has IPv6 disabled or unsupported; skip IPv6 listener cleanly
      }
    }

    // Emit candidates in priority order (overlay -> global IPv6 -> LAN IPv4 / ULA IPv6)
    for (const item of discovered) {
      const port = item.family === 6 ? ipv6Port : ipv4Port;
      if (port) {
        candidates.push({
          kind: "lan_tcp",
          address: item.address,
          port,
        });
      }
    }
  }

  return {
    candidates,
    waitForAuthenticatedChannel: (timeoutMs = 5000) => {
      if (resolvedChannel) return Promise.resolve(resolvedChannel);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          channelWaiter = null;
          reject(new Error("Timed out waiting for direct socket connection"));
        }, timeoutMs);
        channelWaiter = (val) => {
          clearTimeout(timer);
          resolve(val);
        };
      });
    },
    closeAll: async () => {
      // Destroy accepted-but-unused direct sockets (for example a TCP path that won the
      // race after the session already completed over an Edge Relay) so close() can finish.
      for (const sock of acceptedSockets) {
        sock.destroy();
      }
      acceptedSockets.clear();
      await Promise.all(
        servers.map(
          (srv) =>
            new Promise<void>((resolve) => {
              srv.close(() => resolve());
            }),
        ),
      );
      if (unixSockPath) {
        await unlink(unixSockPath).catch(() => {});
      }
    },
  };
}

export async function connectToCandidate(
  candidate: EndpointCandidate,
  transportKey: Uint8Array,
  sessionId: string,
  timeoutMs = 1200,
  signal?: AbortSignal,
): Promise<FramedSocketChannel> {
  if (signal?.aborted) {
    throw new Error("Candidate attempt aborted");
  }
  const startedAt = performance.now();
  const rawSocket = await new Promise<net.Socket>((resolve, reject) => {
    const sock =
      candidate.kind === "unix_socket"
        ? net.createConnection({ path: candidate.address })
        : net.createConnection({
            host: candidate.address,
            port: candidate.port!,
          });

    const onAbort = () => {
      clearTimeout(timer);
      sock.destroy();
      reject(new Error("Candidate attempt aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      sock.destroy();
      reject(new Error(`Connect timeout for ${candidate.kind}`));
    }, timeoutMs);

    sock.once("connect", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(err);
    });
  });

  const channel = new FramedSocketChannel(rawSocket);
  const onChannelAbort = () => channel.destroy();
  signal?.addEventListener("abort", onChannelAbort, { once: true });
  try {
    const remainingMs = Math.max(
      150,
      timeoutMs - Math.round(performance.now() - startedAt),
    );
    await authenticateClientChannel(
      channel,
      transportKey,
      sessionId,
      remainingMs,
    );
    return channel;
  } catch (err) {
    channel.destroy();
    throw err;
  } finally {
    signal?.removeEventListener("abort", onChannelAbort);
  }
}

export async function sendPackOverSocket(
  channel: FramedSocketChannel,
  packId: string,
  wireBytes: Uint8Array,
): Promise<void> {
  const idBytes = utf8Bytes(packId);
  const idLen = new Uint8Array([idBytes.length]);
  await channel.sendFrame(
    FRAME_PACK_DATA,
    concatBytes(idLen, idBytes, wireBytes),
  );
  const ack = await channel.nextFrame(20_000);
  if (ack.type !== FRAME_PACK_ACK) {
    throw new Error(`Unexpected socket ACK frame type: ${ack.type}`);
  }
  const ackedId = new TextDecoder().decode(ack.body);
  if (ackedId !== packId) {
    throw new Error(`Out-of-sync socket ACK: expected ${packId}, got ${ackedId}`);
  }
}

export async function finishSocketStream(
  channel: FramedSocketChannel,
): Promise<void> {
  await channel.sendFrame(FRAME_STREAM_END, new Uint8Array(0));
}

export async function receivePacksFromSocket(
  channel: FramedSocketChannel,
  onPack: (packId: string, wireBytes: Uint8Array) => Promise<void>,
): Promise<void> {
  const decoder = new TextDecoder();
  while (true) {
    // Generous inter-pack wait: a bandwidth-capped sender may pause for a whole pack interval.
    // A dead TCP peer is detected by the socket closing, not by this timer.
    const frame = await channel.nextFrame(120_000);
    if (frame.type === FRAME_STREAM_END) {
      return;
    }
    if (frame.type !== FRAME_PACK_DATA || frame.body.length < 2) {
      throw new Error(`Unexpected socket pack frame: ${frame.type}`);
    }
    const idLen = frame.body[0];
    const packId = decoder.decode(frame.body.subarray(1, 1 + idLen));
    const wireBytes = frame.body.subarray(1 + idLen);
    await onPack(packId, wireBytes);
    await channel.sendFrame(FRAME_PACK_ACK, utf8Bytes(packId));
  }
}

/**
 * RFC 8305 Happy Eyeballs staggered parallel candidate racer.
 * Launches the next candidate every `staggerMs` (default 100ms) while prior attempts
 * are still connecting, resolves immediately with the first mutually authenticated
 * channel, cancels unstarted stagger timers, and destroys any late-finishing sockets.
 */
export async function raceCandidatesHappyEyeballs(
  candidates: EndpointCandidate[],
  transportKey: Uint8Array,
  sessionId: string,
  options?: {
    staggerMs?: number;
    perAttemptTimeoutMs?: number;
  },
): Promise<FramedSocketChannel | null> {
  if (candidates.length === 0) return null;
  const staggerMs = options?.staggerMs ?? 100;
  const perAttemptTimeoutMs = options?.perAttemptTimeoutMs ?? 900;

  return new Promise<FramedSocketChannel | null>((resolve) => {
    let settled = false;
    let remaining = candidates.length;
    const timers: Array<ReturnType<typeof setTimeout>> = [];
    const controllers = candidates.map(() => new AbortController());

    const finishWinner = (winner: FramedSocketChannel, winnerIdx: number) => {
      if (settled) {
        winner.destroy();
        return;
      }
      settled = true;
      for (const t of timers) clearTimeout(t);
      controllers.forEach((ctrl, i) => {
        if (i !== winnerIdx) ctrl.abort();
      });
      resolve(winner);
    };

    const markFailed = () => {
      remaining--;
      if (!settled && remaining <= 0) {
        settled = true;
        for (const t of timers) clearTimeout(t);
        resolve(null);
      }
    };

    candidates.forEach((cand, idx) => {
      const launch = () => {
        if (settled) return;
        connectToCandidate(
          cand,
          transportKey,
          sessionId,
          perAttemptTimeoutMs,
          controllers[idx].signal,
        )
          .then((ch) => finishWinner(ch, idx))
          .catch(() => markFailed());
      };

      if (idx === 0 || staggerMs <= 0) {
        launch();
      } else {
        const t = setTimeout(launch, idx * staggerMs);
        timers.push(t);
      }
    });
  });
}

export interface DiscoveredDirectAddress {
  address: string;
  family: 4 | 6;
  category: "overlay" | "global_ipv6" | "lan";
  interfaceName: string;
}

const CONTAINER_BRIDGE_IFACE_RE =
  /^(docker\d*|br-[0-9a-f]+|veth[0-9a-z]*|cni\d*|virbr\d*|flannel\.\d+|cali[0-9a-z]+|kube-ipvs\d*|podman\d*)$/i;
const OVERLAY_IFACE_RE = /^(tailscale\d*|wg\d*|zt[0-9a-z]+|nebula\d*)$/i;

function isCgnatOrOverlayIpv4(ip: string): boolean {
  const parts = ip.split(".").map((x) => Number.parseInt(x, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  // 100.64.0.0/10 (RFC 6598 CGNAT — used by Tailscale, Headscale, NetBird, etc.)
  return parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127;
}

function isLinkLocalIpv4(ip: string): boolean {
  return ip.startsWith("169.254.");
}

function classifyIpv6Address(rawAddr: string): "overlay" | "global_ipv6" | "lan" | null {
  // Strip any `%iface` zone suffix and skip link-local fe80::/10 (not portable across remote peers)
  const clean = rawAddr.split("%")[0].toLowerCase();
  if (!clean || clean === "::1" || clean.startsWith("fe8") || clean.startsWith("fe9") || clean.startsWith("fea") || clean.startsWith("feb")) {
    return null;
  }
  // Tailscale ULA prefix fd7a:115c:a1e0::/48
  if (clean.startsWith("fd7a:115c:a1e0:")) {
    return "overlay";
  }
  // Global Unicast 2000::/3 (starts with hex digit 2 or 3)
  if (clean.startsWith("2") || clean.startsWith("3")) {
    return "global_ipv6";
  }
  // Unique Local fc00::/7 (starts with fc or fd)
  if (clean.startsWith("fc") || clean.startsWith("fd")) {
    return "lan";
  }
  return null;
}

export function discoverDirectIpAddresses(
  customNets?: NodeJS.Dict<os.NetworkInterfaceInfo[]>,
): DiscoveredDirectAddress[] {
  const nets = customNets ?? os.networkInterfaces();
  const found: DiscoveredDirectAddress[] = [];
  const seen = new Set<string>();

  for (const [ifaceName, entries] of Object.entries(nets)) {
    if (!entries || CONTAINER_BRIDGE_IFACE_RE.test(ifaceName)) {
      continue;
    }
    const isOverlayIface =
      OVERLAY_IFACE_RE.test(ifaceName) || /^utun\d+$/i.test(ifaceName);

    for (const info of entries) {
      if (info.internal || !info.address) continue;

      if (info.family === "IPv4") {
        if (isLinkLocalIpv4(info.address)) continue;
        if (seen.has(info.address)) continue;
        seen.add(info.address);

        const isOverlay =
          OVERLAY_IFACE_RE.test(ifaceName) ||
          (isOverlayIface && isCgnatOrOverlayIpv4(info.address)) ||
          isCgnatOrOverlayIpv4(info.address);
        found.push({
          address: info.address,
          family: 4,
          category: isOverlay ? "overlay" : "lan",
          interfaceName: ifaceName,
        });
      } else if (info.family === "IPv6") {
        const cleanAddr = info.address.split("%")[0];
        const v6Class = classifyIpv6Address(cleanAddr);
        if (!v6Class || seen.has(cleanAddr)) continue;
        seen.add(cleanAddr);

        found.push({
          address: cleanAddr,
          family: 6,
          category: OVERLAY_IFACE_RE.test(ifaceName) ? "overlay" : v6Class,
          interfaceName: ifaceName,
        });
      }
    }
  }

  const rank: Record<DiscoveredDirectAddress["category"], number> = {
    overlay: 0,
    global_ipv6: 1,
    lan: 2,
  };
  found.sort((a, b) => rank[a.category] - rank[b.category]);
  return found;
}

export function listLanIpv4Addresses(): string[] {
  return discoverDirectIpAddresses()
    .filter((d) => d.family === 4)
    .map((d) => d.address);
}

