import { afterEach, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import dgram from "node:dgram";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  startBeamSyncServer,
  type ObjectStoreHookEvent,
  type RunningBeamSyncServer,
} from "@beamsync/server";
import {
  startEdgeRelayServer,
  type RunningEdgeRelayServer,
} from "@beamsync/edge-relay";
import {
  DEFAULT_UDP_CHUNK_PAYLOAD_BYTES,
  acquirePortMapping,
  establishUdpHolePunch,
  finishUdpStream,
  isHostBypassedByNoProxy,
  parseLinuxDefaultGateway,
  prepareUdpPunchEndpoint,
  probeUdpPathPayloadSize,
  receiveDirectory,
  receivePacksFromUdp,
  resetHttpProxyAgents,
  resolveProxyForUrl,
  sendDirectory,
  sendPackOverUdp,
} from "@beamsync/cli";

const RELAY_SECRET = "test-resilience-relay-secret-2026";

/** Incompressible files so zstd cannot shrink packs below the pacing budget. */
async function populateRandomWorkspace(
  rootDir: string,
  fileCount: number,
  bytesPerFile: number,
): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>();
  await mkdir(path.join(rootDir, "src"), { recursive: true });
  for (let i = 0; i < fileCount; i++) {
    const rel = path.join("src", `blob-${i}.bin`);
    const body = crypto.randomBytes(bytesPerFile);
    files.set(rel, body);
    await writeFile(path.join(rootDir, rel), body);
  }
  return files;
}

async function expectIdenticalTree(targetDir: string, files: Map<string, Buffer>) {
  for (const [rel, body] of files) {
    const copied = await readFile(path.join(targetDir, rel));
    expect(copied.equals(body), `mismatch in ${rel}`).toBe(true);
  }
}

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

/** Minimal HTTP CONNECT proxy that records tunnel targets and optionally enforces Basic auth. */
async function startHttpConnectProxy(requiredAuth?: string) {
  const connectTargets: string[] = [];
  let rejectedAuth = 0;
  const live = new Set<net.Socket>();
  const server = net.createServer((client) => {
    live.add(client);
    client.on("error", () => {});
    client.once("close", () => live.delete(client));
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx < 0) return;
      client.off("data", onData);
      const lines = head.subarray(0, idx).toString("latin1").split("\r\n");
      const rest = head.subarray(idx + 4);
      const m = lines[0].match(/^CONNECT (\S+) HTTP\/1\.1$/);
      if (!m) {
        client.end("HTTP/1.1 405 Method Not Allowed\r\n\r\n");
        return;
      }
      if (requiredAuth) {
        const expected = `Basic ${Buffer.from(requiredAuth).toString("base64")}`;
        const got = lines.find((l) => /^proxy-authorization:/i.test(l))?.split(/:\s*/)[1];
        if (got !== expected) {
          rejectedAuth++;
          client.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
          return;
        }
      }
      connectTargets.push(m[1]);
      const sep = m[1].lastIndexOf(":");
      const upstream = net.connect({
        host: m[1].slice(0, sep).replace(/^\[|\]$/g, ""),
        port: Number(m[1].slice(sep + 1)),
      });
      live.add(upstream);
      upstream.on("error", () => client.destroy());
      upstream.once("close", () => {
        live.delete(upstream);
        client.destroy();
      });
      client.once("close", () => upstream.destroy());
      upstream.once("connect", () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (rest.length > 0) upstream.write(rest);
        client.pipe(upstream);
        upstream.pipe(client);
      });
    };
    client.on("data", onData);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: (server.address() as net.AddressInfo).port,
    connectTargets,
    getRejectedAuth: () => rejectedAuth,
    close: async () => {
      for (const s of live) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

/** Minimal SOCKS5 proxy (RFC 1928 CONNECT + RFC 1929 username/password). */
async function startSocks5Proxy(user: string, pass: string) {
  const connectTargets: string[] = [];
  const live = new Set<net.Socket>();
  const server = net.createServer((client) => {
    live.add(client);
    client.on("error", () => {});
    client.once("close", () => live.delete(client));
    let buf = Buffer.alloc(0);
    let stage: "greeting" | "auth" | "request" | "piping" = "greeting";
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (stage === "greeting") {
          if (buf.length < 2 || buf.length < 2 + buf[1]) return;
          const methods = buf.subarray(2, 2 + buf[1]);
          buf = buf.subarray(2 + buf[1]);
          if (!methods.includes(0x02)) {
            client.end(Buffer.from([0x05, 0xff]));
            return;
          }
          client.write(Buffer.from([0x05, 0x02]));
          stage = "auth";
        } else if (stage === "auth") {
          if (buf.length < 2) return;
          const ulen = buf[1];
          if (buf.length < 3 + ulen) return;
          const plen = buf[2 + ulen];
          if (buf.length < 3 + ulen + plen) return;
          const u = buf.subarray(2, 2 + ulen).toString();
          const p = buf.subarray(3 + ulen, 3 + ulen + plen).toString();
          buf = buf.subarray(3 + ulen + plen);
          if (u !== user || p !== pass) {
            client.end(Buffer.from([0x01, 0x01]));
            return;
          }
          client.write(Buffer.from([0x01, 0x00]));
          stage = "request";
        } else if (stage === "request") {
          if (buf.length < 5) return;
          const atyp = buf[3];
          let host: string;
          let need: number;
          if (atyp === 0x01) {
            need = 10;
            if (buf.length < need) return;
            host = Array.from(buf.subarray(4, 8)).join(".");
          } else if (atyp === 0x03) {
            need = 7 + buf[4];
            if (buf.length < need) return;
            host = buf.subarray(5, 5 + buf[4]).toString();
          } else {
            client.end(Buffer.from([0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]));
            return;
          }
          const port = buf.readUInt16BE(need - 2);
          const rest = buf.subarray(need);
          stage = "piping";
          client.off("data", onData);
          connectTargets.push(`${host}:${port}`);
          const upstream = net.connect({ host, port });
          live.add(upstream);
          upstream.on("error", () => client.destroy());
          upstream.once("close", () => {
            live.delete(upstream);
            client.destroy();
          });
          client.once("close", () => upstream.destroy());
          upstream.once("connect", () => {
            client.write(Buffer.from([0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]));
            if (rest.length > 0) upstream.write(rest);
            client.pipe(upstream);
            upstream.pipe(client);
          });
          return;
        } else {
          return;
        }
      }
    };
    client.on("data", onData);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: (server.address() as net.AddressInfo).port,
    connectTargets,
    close: async () => {
      for (const s of live) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

/** Mock NAT-PMP gateway (RFC 6886) that records requests and tracks live mappings. */
async function startNatPmpGateway(opts: { externalIp: string; externalPortOffset: number; refuse?: boolean }) {
  const socket = dgram.createSocket("udp4");
  const mappings = new Map<string, { externalPort: number; lifetimeSec: number }>();
  const requests: Array<{ opcode: number; internalPort?: number; lifetimeSec?: number }> = [];
  socket.on("message", (msg, rinfo) => {
    if (msg.length < 2 || msg[0] !== 0) return;
    const opcode = msg[1];
    if (opcode === 0) {
      requests.push({ opcode });
      const res = Buffer.alloc(12);
      res[1] = 128;
      res.writeUInt32BE(1234, 4);
      Buffer.from(opts.externalIp.split(".").map(Number)).copy(res, 8);
      socket.send(res, rinfo.port, rinfo.address);
      return;
    }
    if ((opcode === 1 || opcode === 2) && msg.length >= 12) {
      const internalPort = msg.readUInt16BE(4);
      const lifetimeSec = msg.readUInt32BE(8);
      requests.push({ opcode, internalPort, lifetimeSec });
      const res = Buffer.alloc(16);
      res[1] = 128 + opcode;
      res.writeUInt32BE(1234, 4);
      res.writeUInt16BE(internalPort, 8);
      const key = `${opcode}:${internalPort}`;
      if (opts.refuse) {
        res.writeUInt16BE(2, 2); // Not Authorized/Refused
      } else if (lifetimeSec === 0) {
        mappings.delete(key);
      } else {
        const externalPort = ((internalPort + opts.externalPortOffset) % 60000) + 1024;
        mappings.set(key, { externalPort, lifetimeSec });
        res.writeUInt16BE(externalPort, 10);
        res.writeUInt32BE(lifetimeSec, 12);
      }
      socket.send(res, rinfo.port, rinfo.address);
    }
  });
  await new Promise<void>((r) => socket.bind(0, "127.0.0.1", () => r()));
  return {
    gateway: { address: "127.0.0.1", port: socket.address().port },
    mappings,
    requests,
    close: () => new Promise<void>((r) => socket.close(() => r())),
  };
}

const PROXY_ENV_KEYS = [
  "BEAMSYNC_PROXY",
  "BEAMSYNC_NO_PROXY",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "https_proxy",
  "http_proxy",
  "all_proxy",
  "no_proxy",
];

describe("Network resilience (hot upgrade, signaling resume, proxies, UDP payload sizing)", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer | null = null;
  const relays: RunningEdgeRelayServer[] = [];
  const cleanups: Array<() => Promise<void>> = [];
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-resilience-"));
    for (const k of PROXY_ENV_KEYS) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(async () => {
    for (const k of PROXY_ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
    resetHttpProxyAgents();
    while (relays.length > 0) await relays.pop()!.close();
    if (server) {
      await server.close();
      server = null;
    }
    while (cleanups.length > 0) await cleanups.pop()!();
    await rm(tmpRoot, { recursive: true, force: true });
  });

  async function startServerWithRelay(objectEvents: ObjectStoreHookEvent[]) {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      dataDir: path.join(tmpRoot, "server-data"),
      relayAuthSecret: RELAY_SECRET,
      onObjectStoreEvent: (ev) => objectEvents.push(ev),
    });
    const relay = await startEdgeRelayServer({
      relayId: "relay-sgp-1",
      region: "sgp",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      coordinatorUrl: server.httpUrl,
    });
    relays.push(relay);
    return relay;
  }

  for (const channel of ["tcp", "udp"] as const) {
    it(`starts on the Edge Relay immediately and hot-upgrades to direct ${channel.toUpperCase()} at a pack boundary without touching R2`, async () => {
      const objectEvents: ObjectStoreHookEvent[] = [];
      const relay = await startServerWithRelay(objectEvents);

      const sourceDir = path.join(tmpRoot, "src");
      const targetDir = path.join(tmpRoot, "dst");
      const files = await populateRandomWorkspace(sourceDir, 16, 32 * 1024);

      const pathOpts =
        channel === "tcp"
          ? { allowLoopbackTcpForTest: true, disableP2pUdp: true }
          : { allowLoopbackUdpForTest: true, disableP2pTcp: true };
      const phrase = `hot-upgrade-${channel}`;
      const sourcePhases: string[] = [];

      const [tx, rx] = await Promise.all([
        sendDirectory({
          serverUrl: server!.httpUrl,
          sourceDir,
          customSecretWords: phrase,
          hostIdOverride: "upgrade-host-a",
          disableLocalIpc: true,
          targetPackBytes: 64 * 1024,
          maxBandwidthMbps: 2.5, // ~312 KB/s keeps the 512 KiB stream alive for well over 1s
          simulateDirectReadyDelayMs: 500, // direct path shows up after the relay already carries packs
          onProgress: (ev) => sourcePhases.push(ev.phase),
          ...pathOpts,
        }),
        receiveDirectory({
          serverUrl: server!.httpUrl,
          targetDir,
          pairingCode: phrase,
          hostIdOverride: "upgrade-host-b",
          disableLocalIpc: true,
          ...pathOpts,
        }),
      ]);

      expect(tx.upgradedToDirect).toBe(true);
      expect(rx.upgradedToDirect).toBe(true);
      expect(tx.selectedTier).toBe("P2P_DIRECT");
      expect(rx.selectedTier).toBe("P2P_DIRECT");
      expect(tx.fallbackToR2Triggered).toBe(false);
      expect(rx.fallbackToR2Triggered).toBe(false);
      expect(sourcePhases).toContain("upgraded_to_direct");

      // Both paths carried real packs, and together they carried every pack exactly once
      expect(tx.packsViaEdgeRelay).toBeGreaterThanOrEqual(1);
      expect(tx.packsViaDirect).toBeGreaterThanOrEqual(1);
      expect(tx.packsViaEdgeRelay + tx.packsViaDirect).toBe(tx.packCount);
      expect(rx.packsApplied).toBe(tx.packCount);
      expect(relay.getStats().totalRelayedBytes).toBeGreaterThan(0);
      expect(relay.getStats().totalRelayedBytes).toBeLessThan(tx.wireBytesSent);
      expect(objectEvents).toHaveLength(0);

      expect(rx.rootTreeDigest).toBe(tx.rootTreeDigest);
      await expectIdenticalTree(targetDir, files);
    });
  }

  it("uses the direct path from the first pack when it wins the grace window (no relay bytes), and reads the channel the source chose when both TCP and UDP are viable", async () => {
    const objectEvents: ObjectStoreHookEvent[] = [];
    const relay = await startServerWithRelay(objectEvents);

    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    const files = await populateRandomWorkspace(sourceDir, 8, 32 * 1024);

    const both = {
      disableLocalIpc: true,
      allowLoopbackTcpForTest: true,
      allowLoopbackUdpForTest: true,
    };
    const phrase = "direct-wins-grace-window";
    const t0 = performance.now();
    const [tx, rx] = await Promise.all([
      sendDirectory({
        serverUrl: server!.httpUrl,
        sourceDir,
        customSecretWords: phrase,
        hostIdOverride: "direct-host-a",
        targetPackBytes: 64 * 1024,
        ...both,
      }),
      receiveDirectory({
        serverUrl: server!.httpUrl,
        targetDir,
        pairingCode: phrase,
        hostIdOverride: "direct-host-b",
        ...both,
      }),
    ]);
    const elapsedMs = performance.now() - t0;

    expect(tx.selectedTier).toBe("P2P_DIRECT");
    expect(rx.selectedTier).toBe("P2P_DIRECT");
    expect(tx.upgradedToDirect).toBe(false);
    expect(tx.packsViaEdgeRelay).toBe(0);
    expect(tx.packsViaDirect).toBe(tx.packCount);
    expect(tx.fallbackToR2Triggered).toBe(false);
    expect(rx.fallbackToR2Triggered).toBe(false);
    expect(relay.getStats().totalRelayedBytes).toBe(0);
    expect(objectEvents).toHaveLength(0);
    // A target that waited on the wrong channel would stall for seconds before falling back
    expect(elapsedMs).toBeLessThan(3000);
    await expectIdenticalTree(targetDir, files);
  });

  it("transparently resumes signaling after the network path is severed mid-transfer (no lost or duplicated control messages)", async () => {
    const forwarder = await startFlakyForwarder();
    cleanups.push(forwarder.close);
    const objectEvents: ObjectStoreHookEvent[] = [];
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-data"),
      // Every client connection (REST, signaling WebSocket, object PUT/GET) crosses the forwarder
      publicUrl: `http://127.0.0.1:${forwarder.port}`,
      // A peer that resumes in time must not be reported lost (the transfer outlives this grace)
      peerLossGraceMs: 1000,
      onObjectStoreEvent: (ev) => objectEvents.push(ev),
    });
    forwarder.setUpstreamPort(server.port);
    const viaForwarder = `http://127.0.0.1:${forwarder.port}`;

    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    const files = await populateRandomWorkspace(sourceDir, 16, 32 * 1024);

    const phrase = "signaling-resume-test";
    let severedConnections = 0;
    let severRounds = 0;
    const [tx, rx] = await Promise.all([
      sendDirectory({
        serverUrl: viaForwarder,
        sourceDir,
        customSecretWords: phrase,
        forceTier: "R2_PIPELINE",
        targetPackBytes: 64 * 1024,
        uploadConcurrency: 1,
        maxBandwidthMbps: 3, // stretch the upload so drops land mid-transfer
        onProgress: (ev) => {
          if (ev.phase === "streaming") {
            for (const delayMs of [60, 450, 900]) {
              setTimeout(() => {
                severRounds++;
                severedConnections += forwarder.severAll();
              }, delayMs);
            }
          }
        },
      }),
      receiveDirectory({
        serverUrl: viaForwarder,
        targetDir,
        pairingCode: phrase,
      }),
    ]);

    expect(severRounds).toBeGreaterThanOrEqual(1);
    expect(severedConnections).toBeGreaterThanOrEqual(2);
    expect(tx.signalingReconnects).toBeGreaterThanOrEqual(1);
    expect(rx.signalingReconnects).toBeGreaterThanOrEqual(1);
    expect(tx.selectedTier).toBe("R2_PIPELINE");
    expect(rx.rootTreeDigest).toBe(tx.rootTreeDigest);
    expect(rx.packsApplied).toBe(tx.packCount);
    // Replay must not make the Coordinator allocate or accept any pack twice
    const putKeys = objectEvents.filter((e) => e.method === "PUT").map((e) => e.storageKey);
    expect(new Set(putKeys).size).toBe(tx.packCount);
    await expectIdenticalTree(targetDir, files);
  });

  it("fails with SIGNALING_LOST instead of hanging when the Coordinator stays unreachable past the reconnect budget", async () => {
    const forwarder = await startFlakyForwarder();
    cleanups.push(forwarder.close);
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-data"),
      publicUrl: `http://127.0.0.1:${forwarder.port}`,
    });
    forwarder.setUpstreamPort(server.port);

    const sourceDir = path.join(tmpRoot, "src");
    await populateRandomWorkspace(sourceDir, 2, 8 * 1024);

    const t0 = performance.now();
    const sendPromise = sendDirectory({
      serverUrl: `http://127.0.0.1:${forwarder.port}`,
      sourceDir,
      customSecretWords: "signaling-lost-test",
      signalingReconnectBudgetMs: 600,
      onPairingCode: () => {
        // Once the sender is attached and waiting for a peer, blackhole the Coordinator for good
        setTimeout(() => {
          forwarder.setUpstreamPort(1);
          forwarder.severAll();
        }, 300);
      },
    });
    await expect(sendPromise).rejects.toThrow(/SIGNALING_LOST.*could not be resumed within 600 ms/);
    expect(performance.now() - t0).toBeLessThan(8000);
  });

  it("tells the surviving peer PEER_LOST when the other side dies mid-session, instead of leaving it waiting", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-data"),
      peerLossGraceMs: 400,
    });
    const sourceDir = path.join(tmpRoot, "src");
    await populateRandomWorkspace(sourceDir, 4, 16 * 1024);
    // The receiver's target path sits below a regular file, so it crashes while preparing to write
    await writeFile(path.join(tmpRoot, "not-a-dir"), "x");

    const t0 = performance.now();
    const [tx, rx] = await Promise.allSettled([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        customSecretWords: "peer-lost-test",
        forceTier: "R2_PIPELINE",
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir: path.join(tmpRoot, "not-a-dir", "dst"),
        pairingCode: "peer-lost-test",
      }),
    ]);
    const elapsedMs = performance.now() - t0;

    expect(rx.status).toBe("rejected");
    expect(tx.status).toBe("rejected");
    expect(String((tx as PromiseRejectedResult).reason)).toMatch(/PEER_LOST.*target peer disconnected/);
    expect(elapsedMs).toBeLessThan(6000);
  });

  it("keeps a bandwidth-capped UDP direct stream alive across a pause longer than the receiver's 10 s inactivity timeout", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-data"),
    });
    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    const files = await populateRandomWorkspace(sourceDir, 1, 64 * 1024);
    const opts = {
      disableLocalIpc: true,
      disableP2pTcp: true,
      allowLoopbackUdpForTest: true,
      disablePortMapping: true,
    };
    const t0 = performance.now();
    const [tx, rx] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        customSecretWords: "paced-udp-liveness",
        hostIdOverride: "paced-host-a",
        maxBandwidthMbps: 0.045, // ~5.6 kB/s: the single 64 KiB pack is held back for ~11.6 s
        ...opts,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir,
        pairingCode: "paced-udp-liveness",
        hostIdOverride: "paced-host-b",
        ...opts,
      }),
    ]);
    expect(performance.now() - t0).toBeGreaterThan(10_500);
    expect(tx.selectedTier).toBe("P2P_DIRECT");
    expect(tx.fallbackToR2Triggered).toBe(false);
    expect(rx.fallbackToR2Triggered).toBe(false);
    await expectIdenticalTree(targetDir, files);
  }, 30_000);

  it("tunnels REST, signaling, R2 objects, and a pinned IP+TLS Edge Relay through an authenticated HTTP CONNECT proxy", async () => {
    const objectEvents: ObjectStoreHookEvent[] = [];
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-data"),
      relayAuthSecret: RELAY_SECRET,
      onObjectStoreEvent: (ev) => objectEvents.push(ev),
    });
    const pinnedRelay = await startEdgeRelayServer({
      relayId: "relay-sha-ip",
      region: "sha",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      publicIp: "127.0.0.1",
      tlsMode: "self-signed",
      tlsCacheFile: path.join(tmpRoot, "relay-tls.json"),
      stunPort: null,
      coordinatorUrl: server.httpUrl,
    });
    relays.push(pinnedRelay);
    const relayPort = Number(new URL(pinnedRelay.httpUrl).port);

    const proxy = await startHttpConnectProxy("devbox:s3cret");
    cleanups.push(proxy.close);
    process.env.BEAMSYNC_PROXY = `http://devbox:s3cret@127.0.0.1:${proxy.port}`;

    // 1) Edge Relay (wss:// to a bare IP with a pinned self-signed certificate) through the proxy
    const relaySrc = path.join(tmpRoot, "relay-src");
    const relayDst = path.join(tmpRoot, "relay-dst");
    const relayFiles = await populateRandomWorkspace(relaySrc, 6, 16 * 1024);
    const [relayTx] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir: relaySrc,
        customSecretWords: "proxy-edge-relay",
        hostIdOverride: "proxy-host-a",
        disableLocalIpc: true,
        disableP2p: true,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir: relayDst,
        pairingCode: "proxy-edge-relay",
        hostIdOverride: "proxy-host-b",
        disableLocalIpc: true,
        disableP2p: true,
      }),
    ]);
    expect(relayTx.selectedTier).toBe("EDGE_RELAY");
    expect(relayTx.fallbackToR2Triggered).toBe(false);
    await expectIdenticalTree(relayDst, relayFiles);
    expect(proxy.connectTargets).toContain(`127.0.0.1:${relayPort}`);
    expect(proxy.connectTargets).toContain(`127.0.0.1:${server.port}`);

    // 2) R2 pipeline (presigned PUT/GET) through the proxy
    const before = proxy.connectTargets.length;
    const r2Src = path.join(tmpRoot, "r2-src");
    const r2Dst = path.join(tmpRoot, "r2-dst");
    const r2Files = await populateRandomWorkspace(r2Src, 6, 16 * 1024);
    const [r2Tx] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir: r2Src,
        customSecretWords: "proxy-r2-pipeline",
        forceTier: "R2_PIPELINE",
        targetPackBytes: 32 * 1024,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir: r2Dst,
        pairingCode: "proxy-r2-pipeline",
      }),
    ]);
    expect(r2Tx.selectedTier).toBe("R2_PIPELINE");
    expect(objectEvents.filter((e) => e.method === "PUT").length).toBe(r2Tx.packCount);
    expect(proxy.connectTargets.length).toBeGreaterThan(before);
    await expectIdenticalTree(r2Dst, r2Files);
    expect(proxy.getRejectedAuth()).toBe(0);

    // 3) Wrong proxy credentials fail loudly rather than silently bypassing the proxy
    resetHttpProxyAgents();
    process.env.BEAMSYNC_PROXY = `http://devbox:wrong@127.0.0.1:${proxy.port}`;
    await expect(
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir: r2Src,
        customSecretWords: "proxy-bad-credentials",
      }),
    ).rejects.toThrow(/PROXY_CONNECT_FAILED.*407/);
    expect(proxy.getRejectedAuth()).toBeGreaterThanOrEqual(1);

    // 4) NO_PROXY bypasses the proxy entirely
    process.env.NO_PROXY = "127.0.0.1";
    const afterBypass = proxy.connectTargets.length;
    const bypassDst = path.join(tmpRoot, "bypass-dst");
    await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir: r2Src,
        customSecretWords: "proxy-bypassed",
        forceTier: "R2_PIPELINE",
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir: bypassDst,
        pairingCode: "proxy-bypassed",
      }),
    ]);
    expect(proxy.connectTargets.length).toBe(afterBypass);
    await expectIdenticalTree(bypassDst, r2Files);
  });

  it("tunnels a full transfer through a SOCKS5 proxy with username/password auth", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-data"),
    });
    const socks = await startSocks5Proxy("beam", "sync");
    cleanups.push(socks.close);
    process.env.ALL_PROXY = `socks5://beam:sync@127.0.0.1:${socks.port}`;

    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    const files = await populateRandomWorkspace(sourceDir, 6, 16 * 1024);
    const [tx] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        customSecretWords: "socks5-transfer",
        forceTier: "R2_PIPELINE",
        targetPackBytes: 32 * 1024,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir,
        pairingCode: "socks5-transfer",
      }),
    ]);
    expect(tx.selectedTier).toBe("R2_PIPELINE");
    expect(socks.connectTargets.length).toBeGreaterThanOrEqual(4);
    expect(new Set(socks.connectTargets)).toEqual(new Set([`127.0.0.1:${server.port}`]));
    await expectIdenticalTree(targetDir, files);
  });

  it("resolves proxy environment variables with standard precedence and NO_PROXY rules", () => {
    const env = {
      HTTPS_PROXY: "http://secure-proxy.corp:3128",
      http_proxy: "http://plain-proxy.corp:8080",
      NO_PROXY: "localhost,.internal.example.com,10.0.0.0/8,relay.example.net:8443",
    };
    expect(resolveProxyForUrl("https://sync.example.com/v1", env)?.display).toBe(
      "http://secure-proxy.corp:3128",
    );
    expect(resolveProxyForUrl("wss://sync.example.com/v1/ws/x", env)?.host).toBe("secure-proxy.corp");
    expect(resolveProxyForUrl("ws://sync.example.com/v1/ws/x", env)?.port).toBe(8080);
    expect(resolveProxyForUrl("https://api.internal.example.com/x", env)).toBeNull();
    expect(resolveProxyForUrl("http://localhost:8787/healthz", env)).toBeNull();
    expect(resolveProxyForUrl("https://10.42.7.9:443/pack", env)).toBeNull();
    expect(resolveProxyForUrl("https://11.42.7.9:443/pack", env)).not.toBeNull();
    expect(resolveProxyForUrl("wss://relay.example.net:8443/relay", env)).toBeNull();
    expect(resolveProxyForUrl("wss://relay.example.net:9443/relay", env)).not.toBeNull();

    const override = { ...env, BEAMSYNC_PROXY: "socks5://u:p%40ss@127.0.0.1:1080" };
    const socks = resolveProxyForUrl("https://sync.example.com", override);
    expect(socks?.protocol).toBe("socks5");
    expect(socks?.password).toBe("p@ss");
    expect(socks?.display).not.toContain("p@ss");

    expect(isHostBypassedByNoProxy("anything.example", 443, "*")).toBe(true);
    expect(isHostBypassedByNoProxy("example.com", 443, "notexample.com")).toBe(false);
    expect(resolveProxyForUrl("https://sync.example.com", {})).toBeNull();
    expect(() => resolveProxyForUrl("https://x.example", { ALL_PROXY: "ftp://nope" })).toThrow(
      /Unsupported proxy scheme/,
    );
  });

  it("advertises a gateway-mapped UDP endpoint during a real session when STUN gives no verdict, and releases it afterwards", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null, // no STUN -> NAT type unknown -> the mapping is requested and waited for
      dataDir: path.join(tmpRoot, "server-data"),
    });
    const gw = await startNatPmpGateway({ externalIp: "203.0.113.9", externalPortOffset: 3 });
    cleanups.push(gw.close);

    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    const files = await populateRandomWorkspace(sourceDir, 4, 16 * 1024);
    const targetProgress: string[] = [];
    const opts = {
      disableLocalIpc: true,
      disableP2pTcp: true,
      allowLoopbackUdpForTest: true,
    };
    const [tx] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        customSecretWords: "gateway-port-mapping",
        hostIdOverride: "pmp-host-a",
        disablePortMapping: true,
        ...opts,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir,
        pairingCode: "gateway-port-mapping",
        hostIdOverride: "pmp-host-b",
        portMappingGateway: gw.gateway,
        onProgress: (ev) => targetProgress.push(`${ev.phase} ${ev.detail ?? ""}`),
        ...opts,
      }),
    ]);

    // The mapped endpoint is unroutable here; the loopback candidate next to it still connects
    expect(tx.selectedTier).toBe("P2P_DIRECT");
    expect(
      targetProgress.some((p) => /^port_mapped udp 203\.0\.113\.9:\d+ via 127\.0\.0\.1/.test(p)),
    ).toBe(true);
    expect(gw.requests.filter((r) => r.opcode === 1 && r.lifetimeSec === 7200)).toHaveLength(1);
    expect(gw.mappings.size).toBe(0);
    await expectIdenticalTree(targetDir, files);
  });

  it("asks the gateway for a UDP port mapping (NAT-PMP), advertises the mapped endpoint first, and deletes the mapping on close", async () => {
    const gw = await startNatPmpGateway({ externalIp: "203.0.113.7", externalPortOffset: 7 });
    cleanups.push(gw.close);

    // No STUN servers -> NAT type unknown -> the mapping is waited for and advertised
    const prep = await prepareUdpPunchEndpoint([], false, { gateway: gw.gateway });
    const localPort = prep.socket.address().port;
    const expectedExternalPort = ((localPort + 7) % 60000) + 1024;
    expect(prep.portMapping).toMatchObject({
      protocol: "udp",
      internalPort: localPort,
      externalIp: "203.0.113.7",
      externalPort: expectedExternalPort,
      lifetimeSec: 7200,
    });
    expect(prep.candidates[0]).toEqual({
      kind: "udp_punch",
      address: "203.0.113.7",
      port: expectedExternalPort,
    });
    expect(gw.mappings.get(`1:${localPort}`)?.externalPort).toBe(expectedExternalPort);

    await prep.close();
    expect(gw.mappings.size).toBe(0);
    expect(gw.requests.at(-1)).toEqual({ opcode: 1, internalPort: localPort, lifetimeSec: 0 });

    // Opt-out sends nothing to the gateway
    const before = gw.requests.length;
    const optedOut = await prepareUdpPunchEndpoint([], false, { gateway: gw.gateway, disabled: true });
    expect(optedOut.portMapping).toBeNull();
    await optedOut.close();
    expect(gw.requests.length).toBe(before);

    // A gateway that refuses, and one that never answers, both degrade to "no mapping" quickly
    const refusing = await startNatPmpGateway({ externalIp: "203.0.113.8", externalPortOffset: 1, refuse: true });
    cleanups.push(refusing.close);
    expect(
      await acquirePortMapping({ protocol: "udp", internalPort: 40000, gateway: refusing.gateway }),
    ).toBeNull();

    const silent = dgram.createSocket("udp4");
    await new Promise<void>((r) => silent.bind(0, "127.0.0.1", () => r()));
    cleanups.push(() => new Promise<void>((r) => silent.close(() => r())));
    const t0 = performance.now();
    const none = await prepareUdpPunchEndpoint([], false, {
      gateway: { address: "127.0.0.1", port: silent.address().port },
    });
    expect(none.portMapping).toBeNull();
    expect(performance.now() - t0).toBeLessThan(600);
    await none.close();

    // Default-gateway discovery from the Linux routing table (little-endian hex)
    expect(
      parseLinuxDefaultGateway(
        [
          "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
          "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0",
          "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
        ].join("\n"),
      ),
    ).toBe("192.168.1.1");
    expect(parseLinuxDefaultGateway("Iface\tDestination\tGateway\tFlags\n")).toBeNull();
  });

  it("sizes UDP chunks by probing the path: full-size on a clean path, stepped down behind a smaller MTU, default when nothing larger survives", async () => {
    const transportKey = crypto.randomBytes(32);
    const sessionId = "mtu-probe-session";

    async function openPair() {
      const a = dgram.createSocket("udp4");
      const b = dgram.createSocket("udp4");
      await Promise.all(
        [a, b].map((s) => new Promise<void>((r) => s.bind(0, "127.0.0.1", () => r()))),
      );
      cleanups.push(async () => {
        for (const s of [a, b]) {
          try {
            s.close();
          } catch {
            // already closed
          }
        }
      });
      const [sender, receiver] = await Promise.all([
        establishUdpHolePunch({
          socket: a,
          transportKey,
          sessionId,
          peerUdpCandidates: [{ kind: "udp_punch", address: "127.0.0.1", port: b.address().port }],
          timeoutMs: 3000,
        }),
        establishUdpHolePunch({
          socket: b,
          transportKey,
          sessionId,
          peerUdpCandidates: [{ kind: "udp_punch", address: "127.0.0.1", port: a.address().port }],
          timeoutMs: 3000,
        }),
      ]);
      return { sender, receiver };
    }

    // Clean path: the largest candidate is confirmed
    const clean = await openPair();
    expect(clean.sender.chunkPayloadBytes).toBe(DEFAULT_UDP_CHUNK_PAYLOAD_BYTES);
    expect(await probeUdpPathPayloadSize(clean.sender)).toBe(1420);
    clean.sender.destroy();
    clean.receiver.destroy();

    // Path that silently drops datagrams above 1400 bytes (e.g. a tunnel): steps down to 1340
    const tunnel = await openPair();
    const sentSizes: number[] = [];
    tunnel.sender.setOutboundDatagramFilterForTest((bytes) => {
      sentSizes.push(bytes);
      return bytes <= 1400;
    });
    expect(await probeUdpPathPayloadSize(tunnel.sender)).toBe(1340);

    // Packs sent with the probed size arrive bit-exact and no datagram exceeds the simulated MTU
    sentSizes.length = 0;
    const wire = crypto.randomBytes(300_000);
    const received: Array<{ packId: string; bytes: Buffer }> = [];
    const rxDone = receivePacksFromUdp(tunnel.receiver, async (packId, bytes) => {
      received.push({ packId, bytes: Buffer.from(bytes) });
    });
    await sendPackOverUdp(tunnel.sender, 0, "pack-mtu-1", wire);
    await finishUdpStream(tunnel.sender);
    await rxDone;
    expect(received).toHaveLength(1);
    expect(received[0].packId).toBe("pack-mtu-1");
    expect(received[0].bytes.equals(wire)).toBe(true);
    expect(Math.max(...sentSizes)).toBe(1340 + 45);
    expect(Math.max(...sentSizes)).toBeLessThanOrEqual(1400);
    // 300000 / 1340 -> 224 chunks instead of 261 at the 1150-byte default
    expect(sentSizes.filter((n) => n > 1000).length).toBeLessThan(261);
    tunnel.sender.destroy();
    tunnel.receiver.destroy();

    // Very small path MTU: every probe is lost, so the conservative default is kept
    const tiny = await openPair();
    tiny.sender.setOutboundDatagramFilterForTest((bytes) => bytes <= 1250);
    expect(await probeUdpPathPayloadSize(tiny.sender, { waitMs: 150 })).toBe(
      DEFAULT_UDP_CHUNK_PAYLOAD_BYTES,
    );
    tiny.sender.destroy();
    tiny.receiver.destroy();
  });
});
