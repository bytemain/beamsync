import { afterEach, beforeEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import WebSocket from "ws";
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
  connectEdgeRelayBinaryChannel,
  receiveDirectory,
  runDoctor,
  sendDirectory,
} from "@beamsync/cli";

async function populateCodeWorkspace(
  rootDir: string,
  fileCount = 30,
  payloadBytes = 12_000,
): Promise<void> {
  await mkdir(path.join(rootDir, "packages", "core"), { recursive: true });
  for (let i = 0; i < fileCount; i++) {
    const body = Buffer.alloc(payloadBytes);
    for (let j = 0; j < payloadBytes; j++) {
      body[j] = (i * 31 + j * 17) & 0xff;
    }
    await writeFile(
      path.join(rootDir, "packages", "core", `mod-${i}.bin`),
      body,
    );
  }
}

describe("Stateless Multi-Region Edge Relay (@beamsync/edge-relay)", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer | null = null;
  const relays: RunningEdgeRelayServer[] = [];
  const RELAY_SECRET = "test-edge-relay-shared-hmac-secret-2026";

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-edge-e2e-"));
  });

  afterEach(async () => {
    while (relays.length > 0) {
      const r = relays.pop()!;
      await r.close();
    }
    if (server) {
      await server.close();
      server = null;
    }
    await rm(tmpRoot, { recursive: true, force: true });
  });

  it("auto-registers regional Edge Relay nodes via signed heartbeats, selects minimum-RTT region (sgp < tyo), and streams with zero R2 writes", async () => {
    const objectEvents: ObjectStoreHookEvent[] = [];
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      dataDir: path.join(tmpRoot, "server-data"),
      relayAuthSecret: RELAY_SECRET,
      onObjectStoreEvent: (ev) => objectEvents.push(ev),
    });

    const tyoRelay = await startEdgeRelayServer({
      relayId: "relay-tyo-1",
      region: "tyo",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      coordinatorUrl: server.httpUrl,
      probeDelayMs: 90,
    });
    relays.push(tyoRelay);

    const sgpRelay = await startEdgeRelayServer({
      relayId: "relay-sgp-1",
      region: "sgp",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      coordinatorUrl: server.httpUrl,
      probeDelayMs: 2,
    });
    relays.push(sgpRelay);

    // Doctor check should discover both Edge Relays, classify local Cone NAT across multiple STUN servers, and measure lower RTT to sgp
    const doc = await runDoctor(server.httpUrl);
    expect(doc.edgeRelayRttMs["relay-sgp-1"]).toBeDefined();
    expect(doc.edgeRelayRttMs["relay-tyo-1"]).toBeDefined();
    expect(doc.edgeRelayRttMs["relay-sgp-1"]).toBeLessThan(
      doc.edgeRelayRttMs["relay-tyo-1"],
    );
    expect(doc.natMapping).toBe("endpoint_independent");

    const sourceDir = path.join(tmpRoot, "src");
    const targetDir = path.join(tmpRoot, "dst");
    await populateCodeWorkspace(sourceDir, 25, 10_000);

    let pairingCode = "";
    const sendPromise = sendDirectory({
      serverUrl: server.httpUrl,
      sourceDir,
      hostIdOverride: "devbox-sgp-a",
      disableLocalIpc: true,
      disableP2p: true, // Simulate Symmetric NAT + UDP-blocked corporate firewall
      onPairingCode: (code) => {
        pairingCode = code;
      },
    });

    while (!pairingCode) {
      await new Promise((r) => setTimeout(r, 15));
    }

    const recvPromise = receiveDirectory({
      serverUrl: server.httpUrl,
      targetDir,
      pairingCode,
      hostIdOverride: "devbox-sgp-b",
      disableLocalIpc: true,
      disableP2p: true,
    });

    const [sendSummary, recvSummary] = await Promise.all([
      sendPromise,
      recvPromise,
    ]);

    expect(sendSummary.selectedTier).toBe("EDGE_RELAY");
    expect(sendSummary.selectedEdgeRelayRegion).toBe("sgp");
    expect(recvSummary.selectedTier).toBe("EDGE_RELAY");
    expect(recvSummary.selectedEdgeRelayRegion).toBe("sgp");
    expect(sendSummary.fallbackToR2Triggered).toBe(false);

    // Zero object-store / R2 writes occurred; traffic cut through sgp Edge Relay node only
    expect(objectEvents).toHaveLength(0);
    expect(sgpRelay.getStats().totalRelayedBytes).toBeGreaterThan(0);
    expect(tyoRelay.getStats().totalRelayedBytes).toBe(0);

    const srcSample = await readFile(
      path.join(sourceDir, "packages", "core", "mod-7.bin"),
    );
    const dstSample = await readFile(
      path.join(targetDir, "packages", "core", "mod-7.bin"),
    );
    expect(dstSample.equals(srcSample)).toBe(true);
  });

  it("supports ICP-free Shanghai IP + self-signed TLS mode (SHA-256 cert pinning + zero TLS SNI)", async () => {
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      dataDir: path.join(tmpRoot, "server-sha"),
      relayAuthSecret: RELAY_SECRET,
    });

    // Domainless IP + self-signed TLS node (Shanghai VM scenario: zero domain, zero ICP filing)
    const shaRelay = await startEdgeRelayServer({
      relayId: "relay-sha-ip",
      region: "sha",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      publicIp: "127.0.0.1",
      tlsMode: "self-signed",
      tlsCacheFile: path.join(tmpRoot, "sha-edge-relay-tls.json"),
      stunPort: 0,
      coordinatorUrl: server.httpUrl,
    });
    relays.push(shaRelay);

    expect(shaRelay.httpUrl.startsWith("https://127.0.0.1:")).toBe(true);
    expect(shaRelay.wsUrl.startsWith("wss://127.0.0.1:")).toBe(true);
    expect(shaRelay.certSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(shaRelay.noSni).toBe(true);

    const sourceDir = path.join(tmpRoot, "sha-src");
    const targetDir = path.join(tmpRoot, "sha-dst");
    await populateCodeWorkspace(sourceDir, 20, 8_000);

    const sharedPhrase = "shanghai-ip-edge-relay-test";
    const [sendSummary, recvSummary] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        customSecretWords: sharedPhrase,
        hostIdOverride: "sha-host-1",
        disableLocalIpc: true,
        disableP2p: true,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir,
        pairingCode: sharedPhrase,
        hostIdOverride: "sha-host-2",
        disableLocalIpc: true,
        disableP2p: true,
      }),
    ]);

    expect(sendSummary.selectedTier).toBe("EDGE_RELAY");
    expect(sendSummary.selectedEdgeRelayRegion).toBe("sha");
    expect(recvSummary.selectedTier).toBe("EDGE_RELAY");
    expect(shaRelay.getStats().totalRelayedBytes).toBeGreaterThan(0);

    // Crucial ICP-free verification: TLS ClientHello sent ZERO SNI server_name extension
    expect(shaRelay.getStats().observedTlsSniHostnames).toEqual([]);

    const srcSample = await readFile(
      path.join(sourceDir, "packages", "core", "mod-0.bin"),
    );
    const dstSample = await readFile(
      path.join(targetDir, "packages", "core", "mod-0.bin"),
    );
    expect(dstSample.equals(srcSample)).toBe(true);
  });

  it("strictly rejects forged relay tickets (HTTP 403) and MITM certificate pin mismatches", async () => {
    const shaRelay = await startEdgeRelayServer({
      relayId: "relay-sec-1",
      region: "sha",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      publicIp: "127.0.0.1",
      tlsMode: "self-signed",
      stunPort: null,
    });
    relays.push(shaRelay);

    // 1. Forged ticket must be rejected with HTTP 403 before WebSocket upgrade
    await expect(
      new Promise<void>((resolve, reject) => {
        const ws = new WebSocket(
          `${shaRelay.wsUrl}/v1/relay/fake-session?relayId=relay-sec-1&role=source&exp=${Date.now() + 60_000}&ticket=deadbeef`,
          { rejectUnauthorized: false },
        );
        ws.once("open", () => {
          ws.close();
          resolve();
        });
        ws.once("error", reject);
      }),
    ).rejects.toThrow(/403/);

    // 2. Wrong SHA-256 certificate pin must abort TLS connection with EDGE_RELAY_CERT_PIN_MISMATCH
    const bogusPin = "f".repeat(64);
    await expect(
      connectEdgeRelayBinaryChannel({
        wsRelayUrl: `${shaRelay.wsUrl}/v1/relay/fake-session?relayId=relay-sec-1&role=source&exp=${Date.now() + 60_000}&ticket=deadbeef`,
        role: "source",
        transportKey: crypto.randomBytes(32),
        sessionId: "fake-session",
        certSha256: bogusPin,
        noSni: true,
      }),
    ).rejects.toThrow(/EDGE_RELAY_CERT_PIN_MISMATCH/);
  });

  it("seamlessly falls back from EDGE_RELAY to R2_PIPELINE mid-transfer if the Edge Relay node drops", async () => {
    const objectEvents: ObjectStoreHookEvent[] = [];
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      dataDir: path.join(tmpRoot, "server-fallback"),
      relayAuthSecret: RELAY_SECRET,
      onObjectStoreEvent: (ev) => objectEvents.push(ev),
    });

    const edgeRelay = await startEdgeRelayServer({
      relayId: "relay-hkg-1",
      region: "hkg",
      authSecret: RELAY_SECRET,
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      coordinatorUrl: server.httpUrl,
    });
    relays.push(edgeRelay);

    const sourceDir = path.join(tmpRoot, "fb-src");
    const targetDir = path.join(tmpRoot, "fb-dst");
    // 24 files * 16 KB = ~384 KB -> ~8 packs at 48 KB targetPackBytes
    await populateCodeWorkspace(sourceDir, 24, 16_384);

    const phrase = "edge-relay-fallback-r2-test";
    const [sendSummary, recvSummary] = await Promise.all([
      sendDirectory({
        serverUrl: server.httpUrl,
        sourceDir,
        customSecretWords: phrase,
        hostIdOverride: "hkg-src",
        disableLocalIpc: true,
        disableP2p: true,
        targetPackBytes: 48 * 1024,
        simulateEdgeRelayDropAfterPacks: 2,
      }),
      receiveDirectory({
        serverUrl: server.httpUrl,
        targetDir,
        pairingCode: phrase,
        hostIdOverride: "hkg-dst",
        disableLocalIpc: true,
        disableP2p: true,
      }),
    ]);

    expect(sendSummary.fallbackToR2Triggered).toBe(true);
    expect(recvSummary.fallbackToR2Triggered).toBe(true);
    expect(sendSummary.selectedTier).toBe("R2_PIPELINE");
    expect(sendSummary.selectedEdgeRelayRegion).toBe("hkg");
    expect(sendSummary.packCount).toBeGreaterThan(3);

    // First 2 packs went over Edge Relay; only remaining packs hit object storage
    const putEvents = objectEvents.filter((e) => e.method === "PUT");
    expect(putEvents.length).toBe(sendSummary.packCount - 2);
    expect(edgeRelay.getStats().totalRelayedBytes).toBeGreaterThan(0);

    for (const idx of [0, 11, 23]) {
      const a = await readFile(
        path.join(sourceDir, "packages", "core", `mod-${idx}.bin`),
      );
      const b = await readFile(
        path.join(targetDir, "packages", "core", `mod-${idx}.bin`),
      );
      expect(b.equals(a)).toBe(true);
    }
  });
});
