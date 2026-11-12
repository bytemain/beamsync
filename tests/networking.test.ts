import crypto from "node:crypto";
import dgram from "node:dgram";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createTargetDirectListeners,
  discoverDirectIpAddresses,
  prepareUdpPunchEndpoint,
  queryStunReflexiveAddress,
  raceCandidatesHappyEyeballs,
  receiveDirectory,
  sendDirectory,
} from "@beamsync/cli";
import { startBeamSyncServer, type RunningBeamSyncServer } from "@beamsync/server";

const STUN_MAGIC_COOKIE = 0x2112a442;

async function startCustomMockStunIpv4(
  mappedIp: string,
  mappedPort: number,
): Promise<{ url: string; close: () => Promise<void> }> {
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg, rinfo) => {
    if (msg.length < 20) return;
    const txId = msg.subarray(8, 20);
    const octets = mappedIp.split(".").map((x) => Number.parseInt(x, 10));

    const attr = Buffer.alloc(12);
    attr.writeUInt16BE(0x0020, 0); // XOR-MAPPED-ADDRESS
    attr.writeUInt16BE(8, 2);
    attr[4] = 0x00;
    attr[5] = 0x01; // IPv4
    attr.writeUInt16BE((mappedPort ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff, 6);

    const cookieBytes = Buffer.alloc(4);
    cookieBytes.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
    for (let i = 0; i < 4; i++) {
      attr[8 + i] = (octets[i] ^ cookieBytes[i]) & 0xff;
    }

    const header = Buffer.alloc(20);
    header.writeUInt16BE(0x0101, 0);
    header.writeUInt16BE(attr.length, 2);
    header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
    txId.copy(header, 8);

    sock.send(Buffer.concat([header, attr]), rinfo.port, rinfo.address);
  });

  await new Promise<void>((resolve, reject) => {
    sock.once("error", reject);
    sock.bind(0, "127.0.0.1", () => {
      sock.removeListener("error", reject);
      resolve();
    });
  });

  const addr = sock.address();
  const port = typeof addr === "object" ? addr.port : 0;
  return {
    url: `stun:127.0.0.1:${port}`,
    close: () => new Promise<void>((r) => sock.close(() => r())),
  };
}

describe("Networking Stack Primitives (NIC Discovery, Happy Eyeballs, Multi-STUN NAT, IPv6, Bandwidth Pacing)", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer | null = null;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-net-test-"));
  });

  afterEach(async () => {
    if (server) {
      await server.close();
      server = null;
    }
    await rm(tmpRoot, { recursive: true, force: true });
  });

  it("filters container bridges & link-local IPs while ranking Overlay > Global IPv6 > LAN", () => {
    const fakeInterfaces: NodeJS.Dict<os.NetworkInterfaceInfo[]> = {
      docker0: [
        {
          address: "172.17.0.1",
          netmask: "255.255.0.0",
          family: "IPv4",
          mac: "02:42:ac:11:00:01",
          internal: false,
          cidr: "172.17.0.1/16",
        },
      ],
      "br-9f8e7d6c": [
        {
          address: "172.18.0.1",
          netmask: "255.255.0.0",
          family: "IPv4",
          mac: "02:42:ac:12:00:01",
          internal: false,
          cidr: "172.18.0.1/16",
        },
      ],
      eth0: [
        {
          address: "192.168.1.50",
          netmask: "255.255.255.0",
          family: "IPv4",
          mac: "aa:bb:cc:dd:ee:01",
          internal: false,
          cidr: "192.168.1.50/24",
        },
        {
          address: "169.254.10.20",
          netmask: "255.255.0.0",
          family: "IPv4",
          mac: "aa:bb:cc:dd:ee:01",
          internal: false,
          cidr: "169.254.10.20/16",
        },
        {
          address: "fe80::1%eth0",
          netmask: "ffff:ffff:ffff:ffff::",
          family: "IPv6",
          mac: "aa:bb:cc:dd:ee:01",
          internal: false,
          cidr: "fe80::1/64",
          scopeid: 2,
        },
        {
          address: "2408:8207:1234::10",
          netmask: "ffff:ffff:ffff:ffff::",
          family: "IPv6",
          mac: "aa:bb:cc:dd:ee:01",
          internal: false,
          cidr: "2408:8207:1234::10/64",
          scopeid: 0,
        },
      ],
      tailscale0: [
        {
          address: "100.101.102.103",
          netmask: "255.255.255.255",
          family: "IPv4",
          mac: "00:00:00:00:00:00",
          internal: false,
          cidr: "100.101.102.103/32",
        },
        {
          address: "fd7a:115c:a1e0::abcd",
          netmask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
          family: "IPv6",
          mac: "00:00:00:00:00:00",
          internal: false,
          cidr: "fd7a:115c:a1e0::abcd/128",
          scopeid: 0,
        },
      ],
    };

    const discovered = discoverDirectIpAddresses(fakeInterfaces);
    const addrs = discovered.map((d) => d.address);

    // Container bridges & link-local addresses must be completely excluded
    expect(addrs).not.toContain("172.17.0.1");
    expect(addrs).not.toContain("172.18.0.1");
    expect(addrs).not.toContain("169.254.10.20");
    expect(addrs.some((a) => a.startsWith("fe80"))).toBe(false);

    // Priority order: Overlay (Tailscale v4 & v6) -> Global IPv6 -> RFC1918 LAN IPv4
    expect(discovered[0].category).toBe("overlay");
    expect(discovered[1].category).toBe("overlay");
    expect(discovered[2]).toMatchObject({
      address: "2408:8207:1234::10",
      family: 6,
      category: "global_ipv6",
    });
    expect(discovered[3]).toMatchObject({
      address: "192.168.1.50",
      family: 4,
      category: "lan",
    });
  });

  it("races candidates with RFC 8305 Happy Eyeballs stagger instead of blocking serially on blackholed sockets", async () => {
    // Create 3 stalling TCP servers that accept TCP SYN/ACK and then hang silently without speaking auth
    const blackholes: net.Server[] = [];
    const blackholeSockets: net.Socket[] = [];
    const blackholePorts: number[] = [];
    for (let i = 0; i < 3; i++) {
      const srv = net.createServer((sock) => {
        blackholeSockets.push(sock);
        sock.on("error", () => {});
      });
      await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
      blackholes.push(srv);
      blackholePorts.push((srv.address() as net.AddressInfo).port);
    }

    const transportKey = crypto.randomBytes(32);
    const sessionId = "happy-eyeballs-test-session";
    const targetListeners = await createTargetDirectListeners({
      sessionId,
      transportKey,
      enableLocalIpc: true,
      enableLanTcp: false,
    });

    try {
      const realLoopbackCand = targetListeners.candidates.find(
        (c) => c.kind === "loopback_tcp",
      )!;
      const mixedCandidates = [
        ...blackholePorts.map((port) => ({
          kind: "lan_tcp" as const,
          address: "127.0.0.1",
          port,
        })),
        realLoopbackCand,
      ];

      const t0 = performance.now();
      const [winner, accepted] = await Promise.all([
        raceCandidatesHappyEyeballs(mixedCandidates, transportKey, sessionId, {
          staggerMs: 60,
          perAttemptTimeoutMs: 1500,
        }),
        targetListeners.waitForAuthenticatedChannel(3000),
      ]);
      const elapsedMs = performance.now() - t0;

      expect(winner).not.toBeNull();
      expect(accepted.kind).toBe("loopback_tcp");
      // Serial attempts would block > 4500ms; staggered Happy Eyeballs wins around ~180ms!
      expect(elapsedMs).toBeLessThan(800);

      winner?.destroy();
      accepted.channel.destroy();
    } finally {
      await targetListeners.closeAll();
      for (const s of blackholeSockets) s.destroy();
      await Promise.all(
        blackholes.map((s) => new Promise<void>((r) => s.close(() => r()))),
      );
    }
  });

  it("classifies Symmetric NAT + sequential port stride across 2 STUN servers and predicts candidate ports", async () => {
    const stun1 = await startCustomMockStunIpv4("203.0.113.42", 41000);
    const stun2 = await startCustomMockStunIpv4("203.0.113.42", 41002);

    try {
      const prep = await prepareUdpPunchEndpoint([stun1.url, stun2.url]);
      try {
        expect(prep.natMapping).toBe("symmetric");
        expect(prep.portStride).toBe(2);
        expect(prep.hasSequentialPrediction).toBe(true);

        const ports = prep.candidates
          .filter((c) => c.address === "203.0.113.42")
          .map((c) => c.port);
        // Observed ports (41000, 41002) + sequential stride predictions (41004, 41006, 41008)
        expect(ports).toEqual(
          expect.arrayContaining([41000, 41002, 41004, 41006, 41008]),
        );
      } finally {
        await prep.close();
      }
    } finally {
      await stun1.close();
      await stun2.close();
    }
  });

  it("decodes RFC 5389 IPv6 XOR-MAPPED-ADDRESS (family 0x02) responses", async () => {
    // Mock IPv6 STUN responder over localhost IPv4 transport returning an IPv6 XOR-MAPPED-ADDRESS
    const responder = dgram.createSocket("udp4");
    const expectedV6Bytes = Buffer.from([
      0x24, 0x08, 0x82, 0x07, 0x00, 0x01, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
    ]);
    const expectedPort = 52443;

    responder.on("message", (msg, rinfo) => {
      const txId = msg.subarray(8, 20);
      const mask = Buffer.alloc(16);
      mask.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
      txId.copy(mask, 4);

      const attr = Buffer.alloc(24);
      attr.writeUInt16BE(0x0020, 0); // XOR-MAPPED-ADDRESS
      attr.writeUInt16BE(20, 2);
      attr[4] = 0x00;
      attr[5] = 0x02; // IPv6
      attr.writeUInt16BE(
        (expectedPort ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff,
        6,
      );
      for (let i = 0; i < 16; i++) {
        attr[8 + i] = (expectedV6Bytes[i] ^ mask[i]) & 0xff;
      }

      const header = Buffer.alloc(20);
      header.writeUInt16BE(0x0101, 0);
      header.writeUInt16BE(attr.length, 2);
      header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
      txId.copy(header, 8);

      responder.send(Buffer.concat([header, attr]), rinfo.port, rinfo.address);
    });

    await new Promise<void>((r) => responder.bind(0, "127.0.0.1", () => r()));
    const port = (responder.address() as net.AddressInfo).port;
    const client = dgram.createSocket("udp4");
    await new Promise<void>((r) => client.bind(0, "127.0.0.1", () => r()));

    try {
      const res = await queryStunReflexiveAddress(
        client,
        `stun:127.0.0.1:${port}`,
        600,
      );
      expect(res).not.toBeNull();
      expect(res?.family).toBe(6);
      expect(res?.port).toBe(expectedPort);
      expect(res?.ip).toBe("2408:8207:1:2:0:0:0:1234");
    } finally {
      await new Promise<void>((r) => client.close(() => r()));
      await new Promise<void>((r) => responder.close(() => r()));
    }
  });

  it("enforces maxBandwidthMbps on every network tier (direct, stream relay, R2) but not on same-host IPC, with bit-exact delivery", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: null,
      dataDir: path.join(tmpRoot, "server-pace"),
    });

    const sourceDir = path.join(tmpRoot, "src");
    await mkdir(sourceDir, { recursive: true });
    // Incompressible 300 KiB payload: at 2 Mbps (250 kB/s) the wire bytes need ~1.2s
    const randomBlob = crypto.randomBytes(300 * 1024);
    await writeFile(path.join(sourceDir, "random.bin"), randomBlob);

    let runIndex = 0;
    async function timedTransfer(
      extra: Partial<Parameters<typeof sendDirectory>[0]>,
      targetExtra: Partial<Parameters<typeof receiveDirectory>[0]> = {},
    ) {
      const phrase = `bandwidth-pacer-test-${runIndex++}`;
      const targetDir = path.join(tmpRoot, `dst-${runIndex}`);
      const t0 = performance.now();
      const [tx] = await Promise.all([
        sendDirectory({
          serverUrl: server!.httpUrl,
          sourceDir,
          customSecretWords: phrase,
          ...extra,
        }),
        receiveDirectory({
          serverUrl: server!.httpUrl,
          targetDir,
          pairingCode: phrase,
          ...targetExtra,
        }),
      ]);
      const elapsedMs = performance.now() - t0;
      const copied = await readFile(path.join(targetDir, "random.bin"));
      expect(copied.equals(randomBlob)).toBe(true);
      return { tier: tx.selectedTier, elapsedMs };
    }

    const loopbackTcp = {
      disableLocalIpc: true,
      disableP2pUdp: true,
      allowLoopbackTcpForTest: true,
      hostIdOverride: "pace-host-a",
    };
    const loopbackTcpTarget = { ...loopbackTcp, hostIdOverride: "pace-host-b" };

    for (const [expectedTier, extra, targetExtra] of [
      ["STREAM_RELAY", { forceTier: "STREAM_RELAY" }, {}],
      ["R2_PIPELINE", { forceTier: "R2_PIPELINE" }, {}],
      ["P2P_DIRECT", loopbackTcp, loopbackTcpTarget],
    ] as const) {
      const unpaced = await timedTransfer(extra, targetExtra);
      const paced = await timedTransfer({ ...extra, maxBandwidthMbps: 2 }, targetExtra);
      expect(unpaced.tier).toBe(expectedTier);
      expect(paced.tier).toBe(expectedTier);
      // 307 kB at 250 kB/s minus the 50 ms burst credit is ~1.18s; unpaced loopback takes ~0.1s
      expect(paced.elapsedMs, `${expectedTier} paced`).toBeGreaterThanOrEqual(1000);
      expect(paced.elapsedMs - unpaced.elapsedMs, `${expectedTier} delta`).toBeGreaterThanOrEqual(700);
    }

    // Same-host IPC never leaves the machine, so the bandwidth cap is intentionally not applied
    const ipc = await timedTransfer({ maxBandwidthMbps: 2 });
    expect(ipc.tier).toBe("LOCAL_IPC");
    expect(ipc.elapsedMs).toBeLessThan(900);
  });
});
