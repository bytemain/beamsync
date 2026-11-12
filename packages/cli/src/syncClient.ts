import { open } from "node:fs/promises";
import WebSocket from "ws";
import {
  bytesToHex,
  collectRequiredBlobHashes,
  constantTimeEqual,
  decodePack,
  deriveRendezvousSlot,
  deriveSessionKeyMaterial,
  encodePack,
  formatPairingPhrase,
  generateSecretWords,
  hexToBytes,
  PakeHandshake,
  parsePairingPhrase,
  randomBytes,
  type AllocatedUploadSlot,
  type ClientToServerWsMessage,
  type CreateManagedLeaseResponse,
  type CreatePairingResponse,
  type EdgeRelayNodeInfo,
  type EndpointCandidate,
  type FastCdcOptions,
  type JoinPairingResponse,
  type NatMappingBehavior,
  type PackBlobInput,
  type ServerToClientWsMessage,
  type SessionKeyMaterial,
  type TransportTier,
} from "@beamsync/protocol";
import {
  connectEdgeRelayBinaryChannel,
  probeEdgeRelayRtts,
  receivePacksFromEdgeRelay,
  streamPackBatchesOverEdgeRelay,
  type EdgeRelayBinaryChannel,
} from "./edgeRelayChannel.js";
import {
  createTargetDirectListeners,
  discoverDirectIpAddresses,
  finishSocketStream,
  raceCandidatesHappyEyeballs,
  receivePacksFromSocket,
  sendPackOverSocket,
  type DiscoveredDirectAddress,
  type FramedSocketChannel,
} from "./framedStream.js";
import { buildSessionHostFingerprint } from "./hostIdentity.js";
import { AtomicWorkspaceMaterializer } from "./materializer.js";
import { scanWorkspace, type BlobDiskSlice } from "./stateIndex.js";
import {
  establishUdpHolePunch,
  finishUdpStream,
  prepareUdpPunchEndpoint,
  receivePacksFromUdp,
  sendPackOverUdp,
  type UdpHolePunchChannel,
} from "./udpHolePunch.js";
import { zstdCompress, zstdDecompress } from "./zstdCodec.js";

export interface TransferCommonOptions {
  serverUrl: string;
  cacheDir?: string;
  hostIdOverride?: string;
  disableLocalIpc?: boolean;
  disableP2p?: boolean;
  disableP2pTcp?: boolean;
  disableP2pUdp?: boolean;
  disableEdgeRelay?: boolean;
  preferEdgeRelay?: boolean;
  edgeRelayMaxBytes?: number;
  maxBandwidthMbps?: number;
  allowLoopbackUdpForTest?: boolean;
  forceTier?: TransportTier;
  targetPackBytes?: number;
  streamRelayThresholdBytes?: number;
  uploadConcurrency?: number;
  downloadConcurrency?: number;
  smallFileThresholdBytes?: number;
  cdcOptions?: FastCdcOptions;
  onProgress?: (event: {
    phase: string;
    tier?: TransportTier;
    detail?: string;
  }) => void;
}

export interface SendDirectoryOptions extends TransferCommonOptions {
  sourceDir: string;
  scopeNamespace?: string;
  customSlotCode?: string;
  customSecretWords?: string;
  extraIgnoreRules?: string[];
  simulateP2pDropAfterPacks?: number;
  simulateEdgeRelayDropAfterPacks?: number;
  onPairingCode?: (pairingCode: string, sessionId: string) => void;
}

export interface ReceiveDirectoryOptions extends TransferCommonOptions {
  targetDir: string;
  pairingCode: string;
  rejectedDirectAttemptCounter?: { count: number };
}

export interface SendTransferSummary {
  sessionId: string;
  pairingCode?: string;
  selectedTier: TransportTier;
  selectedEdgeRelayRegion?: string;
  fallbackToR2Triggered: boolean;
  rootTreeDigest: string;
  logicalBytes: number;
  dedupSavedBytes: number;
  wireBytesSent: number;
  packCount: number;
  casSkippedPacks: number;
  cachedIndexHits: number;
  hashedFiles: number;
  committedFiles: number;
  sourceAllPacksUploadedAtMs: number;
  durationMs: number;
}

export interface ReceiveTransferSummary {
  sessionId: string;
  selectedTier: TransportTier;
  selectedEdgeRelayRegion?: string;
  fallbackToR2Triggered: boolean;
  rootTreeDigest: string;
  committedFiles: number;
  packsApplied: number;
  firstPackAppliedAtMs: number | null;
  durationMs: number;
}

const DEFAULT_TARGET_PACK_BYTES = 8 * 1024 * 1024; // 8 MiB
const DEFAULT_STREAM_RELAY_THRESHOLD_BYTES = 8 * 1024 * 1024; // 8 MiB
const DEFAULT_EDGE_RELAY_MAX_BYTES = 512 * 1024 * 1024; // 512 MiB default Edge Relay cut-through cap before R2_PIPELINE
const RELAY_FRAME_SLICE_BYTES = 256 * 1024; // 256 KiB per WS frame

function createBandwidthPacer(
  maxBandwidthMbps?: number,
): ((byteCount: number) => Promise<void>) | undefined {
  if (
    typeof maxBandwidthMbps !== "number" ||
    !Number.isFinite(maxBandwidthMbps) ||
    maxBandwidthMbps <= 0
  ) {
    return undefined;
  }
  // Convert Mbps (megabits/sec) -> bytes/ms
  const bytesPerMs = (maxBandwidthMbps * 1_000_000) / 8 / 1000;
  let nextAllowedTimeMs = performance.now();

  return async (byteCount: number) => {
    if (byteCount <= 0) return;
    const now = performance.now();
    // Allow up to 50ms of idle credit accumulation so small frames do not stall
    const floorTime = now - 50;
    const startSlot = Math.max(nextAllowedTimeMs, floorTime);
    const durationMs = byteCount / bytesPerMs;
    nextAllowedTimeMs = startSlot + durationMs;
    const waitMs = nextAllowedTimeMs - now;
    if (waitMs >= 2) {
      await new Promise((r) => setTimeout(r, Math.ceil(waitMs)));
    }
  };
}

export async function sendDirectory(
  options: SendDirectoryOptions,
): Promise<SendTransferSummary> {
  const baseHttp = options.serverUrl.replace(/\/+$/, "");

  let customSlotCode = options.customSlotCode;
  let secretWords: string;
  let displayPairingCode: string;

  if (options.customSecretWords && !options.customSlotCode) {
    // Symmetric user-chosen phrase: derive zero-knowledge rendezvous slot so both peers can type the exact same `--code`
    const derived = deriveRendezvousSlot(options.customSecretWords);
    customSlotCode = derived.slotCode;
    secretWords = derived.secretPhrase;
    displayPairingCode = derived.secretPhrase;
  } else {
    secretWords = generateSecretWords(randomBytes(3), 3);
    displayPairingCode = "";
  }

  const createRes = await httpPostJson<CreatePairingResponse>(
    `${baseHttp}/v1/pairings`,
    {
      scopeNamespace: options.scopeNamespace,
      customSlotCode,
    },
  );

  const pairingCode =
    displayPairingCode || formatPairingPhrase(createRes.slotCode, secretWords);
  options.onPairingCode?.(pairingCode, createRes.sessionId);

  return runSourceSession({
    options,
    sessionId: createRes.sessionId,
    peerToken: createRes.peerToken,
    wsUrl: createRes.wsUrl,
    stunServers: createRes.stunServers,
    edgeRelays: createRes.edgeRelays,
    mode: { kind: "pake", secretPhrase: secretWords, pairingCode },
  });
}

export async function receiveDirectory(
  options: ReceiveDirectoryOptions,
): Promise<ReceiveTransferSummary> {
  const parsed = parsePairingPhrase(options.pairingCode);
  const baseHttp = options.serverUrl.replace(/\/+$/, "");
  const isSymmetricRendezvous = parsed.slotCode.startsWith("k");
  const deadline = Date.now() + (isSymmetricRendezvous ? 15_000 : 0);

  let joinRes: JoinPairingResponse | null = null;
  while (true) {
    try {
      joinRes = await httpPostJson<JoinPairingResponse>(
        `${baseHttp}/v1/pairings/join`,
        { slotCode: parsed.slotCode },
      );
      break;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isSymmetricRendezvous && msg.includes("PAIRING_NOT_FOUND") && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 200));
        continue;
      }
      throw err;
    }
  }

  return runTargetSession({
    options,
    sessionId: joinRes.sessionId,
    peerToken: joinRes.peerToken,
    wsUrl: joinRes.wsUrl,
    stunServers: joinRes.stunServers,
    edgeRelays: joinRes.edgeRelays,
    mode: { kind: "pake", secretPhrase: parsed.secretPhrase },
  });
}

export async function createServerManagedLease(params: {
  serverUrl: string;
  scopeNamespace: string;
  apiToken?: string;
}): Promise<CreateManagedLeaseResponse> {
  return httpPostJson<CreateManagedLeaseResponse>(
    `${params.serverUrl.replace(/\/+$/, "")}/v1/leases`,
    { scopeNamespace: params.scopeNamespace },
    params.apiToken,
  );
}

export async function sendWithManagedLease(params: {
  options: Omit<SendDirectoryOptions, "onPairingCode">;
  lease: {
    sessionId: string;
    sourceToken: string;
    leaseSecretHex: string;
    scopeCasKeyHex?: string;
    wsUrl: string;
    stunServers: string[];
    edgeRelays?: EdgeRelayNodeInfo[];
  };
}): Promise<SendTransferSummary> {
  return runSourceSession({
    options: params.options,
    sessionId: params.lease.sessionId,
    peerToken: params.lease.sourceToken,
    wsUrl: params.lease.wsUrl,
    stunServers: params.lease.stunServers,
    edgeRelays: params.lease.edgeRelays,
    mode: {
      kind: "lease",
      leaseSecretHex: params.lease.leaseSecretHex,
      scopeCasKeyHex: params.lease.scopeCasKeyHex,
    },
  });
}

export async function receiveWithManagedLease(params: {
  options: Omit<ReceiveDirectoryOptions, "pairingCode">;
  lease: {
    sessionId: string;
    targetToken: string;
    leaseSecretHex: string;
    scopeCasKeyHex?: string;
    wsUrl: string;
    stunServers: string[];
    edgeRelays?: EdgeRelayNodeInfo[];
  };
}): Promise<ReceiveTransferSummary> {
  return runTargetSession({
    options: { ...params.options, pairingCode: "" },
    sessionId: params.lease.sessionId,
    peerToken: params.lease.targetToken,
    wsUrl: params.lease.wsUrl,
    stunServers: params.lease.stunServers,
    edgeRelays: params.lease.edgeRelays,
    mode: {
      kind: "lease",
      leaseSecretHex: params.lease.leaseSecretHex,
      scopeCasKeyHex: params.lease.scopeCasKeyHex,
    },
  });
}

class SignalingClient {
  private readonly ws: WebSocket;
  private readonly listeners = new Set<(msg: ServerToClientWsMessage) => void>();
  private readonly buffered: ServerToClientWsMessage[] = [];
  private closedError: Error | null = null;
  private readonly keepaliveTimer: ReturnType<typeof setInterval>;

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.on("message", (raw) => {
      const str = typeof raw === "string" ? raw : raw.toString("utf8");
      const parsed = JSON.parse(str) as ServerToClientWsMessage;
      if (parsed.type === "pong") {
        return;
      }
      if (this.listeners.size === 0) {
        this.buffered.push(parsed);
      } else {
        for (const fn of [...this.listeners]) {
          fn(parsed);
        }
      }
    });
    ws.on("close", (_code, reason) => {
      clearInterval(this.keepaliveTimer);
      this.closedError = new Error(
        `Signaling WebSocket closed: ${reason.toString() || "closed"}`,
      );
    });
    ws.on("error", (err) => {
      clearInterval(this.keepaliveTimer);
      this.closedError = err;
    });

    // Periodic 20s keepalive prevents NAT gateways / reverse proxies (60-100s idle timeout)
    // from dropping the signaling socket during multi-minute bulk transfers.
    this.keepaliveTimer = setInterval(() => {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.send({ type: "ping", ts: Date.now() });
      }
    }, 20_000);
    this.keepaliveTimer.unref();
  }

  static async connect(wsUrl: string): Promise<SignalingClient> {
    const ws = new WebSocket(wsUrl);
    const client = new SignalingClient(ws);
    await new Promise<void>((resolve, reject) => {
      ws.once("open", () => resolve());
      ws.once("error", reject);
    });
    return client;
  }

  send(msg: ClientToServerWsMessage): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  subscribe(fn: (msg: ServerToClientWsMessage) => void): () => void {
    this.listeners.add(fn);
    while (this.buffered.length > 0) {
      const m = this.buffered.shift()!;
      fn(m);
    }
    return () => this.listeners.delete(fn);
  }

  waitFor<T extends ServerToClientWsMessage["type"]>(
    expectedType: T,
    timeoutMs = 30_000,
  ): Promise<Extract<ServerToClientWsMessage, { type: T }>> {
    return new Promise((resolve, reject) => {
      if (this.closedError) {
        reject(this.closedError);
        return;
      }
      const timer = setTimeout(() => {
        unsub();
        reject(new Error(`Timed out waiting for signaling message "${expectedType}"`));
      }, timeoutMs);

      const unsub = this.subscribe((msg) => {
        if (msg.type === "session_error") {
          clearTimeout(timer);
          unsub();
          reject(new Error(`${msg.code}: ${msg.message}`));
          return;
        }
        if (msg.type === expectedType) {
          clearTimeout(timer);
          unsub();
          resolve(msg as Extract<ServerToClientWsMessage, { type: T }>);
        }
      });
    });
  }

  close(): void {
    clearInterval(this.keepaliveTimer);
    this.ws.close();
  }
}

async function runSourceSession(params: {
  options: SendDirectoryOptions;
  sessionId: string;
  peerToken: string;
  wsUrl: string;
  stunServers: string[];
  edgeRelays?: EdgeRelayNodeInfo[];
  mode:
    | { kind: "pake"; secretPhrase: string; pairingCode: string }
    | { kind: "lease"; leaseSecretHex: string; scopeCasKeyHex?: string };
}): Promise<SendTransferSummary> {
  const startedAt = Date.now();
  const { options, sessionId, wsUrl, stunServers, edgeRelays } = params;
  const sig = await SignalingClient.connect(wsUrl);
  let udpPrep: Awaited<ReturnType<typeof prepareUdpPunchEndpoint>> | null = null;
  let directSock: FramedSocketChannel | null = null;
  let udpChan: UdpHolePunchChannel | null = null;
  let edgeChan: EdgeRelayBinaryChannel | null = null;
  const paceBytes = createBandwidthPacer(options.maxBandwidthMbps);
  const allStunServers = [
    ...stunServers,
    ...(edgeRelays ?? [])
      .map((r) => r.stunUrl)
      .filter((u): u is string => Boolean(u)),
  ];

  try {
    // Start scanning source workspace and probing Edge Relay RTTs immediately in parallel
    const sourceScanPromise = scanWorkspace(options.sourceDir, {
      cacheDir: options.cacheDir,
      extraIgnoreRules: options.extraIgnoreRules,
      smallFileThresholdBytes: options.smallFileThresholdBytes,
      cdcOptions: options.cdcOptions,
    });
    const relayRttPromise = options.disableEdgeRelay
      ? Promise.resolve<Record<string, number>>({})
      : probeEdgeRelayRtts(edgeRelays, 1000);

    const pake =
      params.mode.kind === "pake"
        ? new PakeHandshake("source", sessionId, params.mode.secretPhrase)
        : null;

    const peerJoinedPromise = sig.waitFor("peer_joined", 120_000);
    sig.send({
      type: "hello",
      role: "source",
      peerToken: params.peerToken,
      pakePublicHex: pake?.getPublicMessage(),
    });

    const peerJoined = await peerJoinedPromise;

    let keys: SessionKeyMaterial;
    let myConfirmMacHex: string;
    let expectedPeerMacHex: string;

    let convergentPacks = false;
    if (pake) {
      if (!peerJoined.peerPakePublicHex) {
        throw new Error("Missing peer PAKE public message");
      }
      const fin = pake.finish(peerJoined.peerPakePublicHex);
      keys = fin.keys;
      myConfirmMacHex = fin.myConfirmMacHex;
      expectedPeerMacHex = fin.expectedPeerConfirmMacHex;
    } else {
      const leaseMode = params.mode as {
        kind: "lease";
        leaseSecretHex: string;
        scopeCasKeyHex?: string;
      };
      const secret = hexToBytes(leaseMode.leaseSecretHex);
      keys = deriveSessionKeyMaterial(secret, sessionId, "managed-lease");
      if (leaseMode.scopeCasKeyHex) {
        keys = { ...keys, packKey: hexToBytes(leaseMode.scopeCasKeyHex) };
        convergentPacks = true;
      }
      myConfirmMacHex = bytesToHex(keys.confirmKeySource);
      expectedPeerMacHex = bytesToHex(keys.confirmKeyTarget);
    }

    const hostFingerprint = await buildSessionHostFingerprint(
      keys.hostFingerprintKey,
      options.hostIdOverride,
    );

    const enableUdp =
      !options.disableP2p &&
      !options.disableP2pUdp &&
      (!options.forceTier || options.forceTier === "P2P_DIRECT");

    if (enableUdp) {
      udpPrep = await prepareUdpPunchEndpoint(
        allStunServers,
        Boolean(options.allowLoopbackUdpForTest),
      );
    }

    const relayRttMs = await relayRttPromise;
    const peerConfirmedPromise = sig.waitFor("peer_confirmed", 20_000);
    const targetBlobsPromise = sig.waitFor("target_have_blobs", 60_000);

    sig.send({
      type: "pake_confirm",
      confirmMacHex: myConfirmMacHex,
      hostFingerprint,
      candidates: udpPrep ? udpPrep.candidates : [],
      relayRttMs,
      natMapping: udpPrep?.natMapping,
    });

    const peerConfirmed = await peerConfirmedPromise;
    if (
      !constantTimeEqual(
        hexToBytes(peerConfirmed.peerConfirmMacHex),
        hexToBytes(expectedPeerMacHex),
      )
    ) {
      throw new Error("PAKE_AUTH_FAILED: Pairing phrase mismatch");
    }

    const [sourceScan, targetHaveMsg] = await Promise.all([
      sourceScanPromise,
      targetBlobsPromise,
    ]);

    const targetKnownSet = new Set(targetHaveMsg.knownBlobHashes);
    const allRequiredHashes = collectRequiredBlobHashes(sourceScan.manifest);
    let totalRequiredBytes = 0;
    let missingBytesEstimate = 0;
    const missingHashes: string[] = [];

    for (const hash of allRequiredHashes) {
      const slice = sourceScan.blobSlices.get(hash);
      const len = slice?.length ?? 0;
      totalRequiredBytes += len;
      if (!targetKnownSet.has(hash)) {
        missingHashes.push(hash);
        missingBytesEstimate += len;
      }
    }
    const dedupSavedBytes = Math.max(0, totalRequiredBytes - missingBytesEstimate);

    // Negotiate transport tier
    let selectedTier: TransportTier = "R2_PIPELINE";
    let selectedEdgeRelayRegion: string | undefined;
    const relayThreshold =
      options.streamRelayThresholdBytes ?? DEFAULT_STREAM_RELAY_THRESHOLD_BYTES;
    const edgeRelayMaxBytes =
      options.edgeRelayMaxBytes ?? DEFAULT_EDGE_RELAY_MAX_BYTES;

    if (missingHashes.length === 0) {
      selectedTier = options.forceTier ?? "STREAM_RELAY";
    } else if (options.forceTier) {
      selectedTier = options.forceTier;
      if (selectedTier === "LOCAL_IPC") {
        directSock = await tryConnectCandidates(
          peerConfirmed.peerCandidates.filter(
            (c) => c.kind === "unix_socket" || c.kind === "loopback_tcp",
          ),
          keys.transportKey,
          sessionId,
        );
        if (!directSock) {
          throw new Error("Forced LOCAL_IPC tier failed to connect");
        }
      } else if (selectedTier === "P2P_DIRECT") {
        if (!options.disableP2pTcp) {
          directSock = await tryConnectCandidates(
            peerConfirmed.peerCandidates.filter((c) => c.kind === "lan_tcp"),
            keys.transportKey,
            sessionId,
          );
        }
        if (!directSock && udpPrep) {
          udpChan = await establishUdpHolePunch({
            socket: udpPrep.socket,
            transportKey: keys.transportKey,
            sessionId,
            peerUdpCandidates: peerConfirmed.peerCandidates,
            timeoutMs: 2000,
          });
        }
        if (!directSock && !udpChan) {
          throw new Error("Forced P2P_DIRECT tier failed to establish");
        }
      } else if (selectedTier === "EDGE_RELAY") {
        if (!peerConfirmed.selectedEdgeRelay) {
          throw new Error("Forced EDGE_RELAY tier requested, but no Edge Relay is registered");
        }
        selectedEdgeRelayRegion = peerConfirmed.selectedEdgeRelay.region;
      }
    } else {
      // Automatic 5-Tier Happy Eyeballs Negotiation:
      // 1. Same-host LOCAL_IPC
      if (peerConfirmed.sameHostMatch && !options.disableLocalIpc) {
        directSock = await tryConnectCandidates(
          peerConfirmed.peerCandidates.filter(
            (c) => c.kind === "unix_socket" || c.kind === "loopback_tcp",
          ),
          keys.transportKey,
          sessionId,
        );
        if (directSock) {
          selectedTier = "LOCAL_IPC";
        }
      }

      // 2. P2P_DIRECT (LAN TCP -> STUN UDP Hole Punch)
      if (!directSock && !options.disableP2p) {
        if (!options.disableP2pTcp) {
          directSock = await tryConnectCandidates(
            peerConfirmed.peerCandidates.filter((c) => c.kind === "lan_tcp"),
            keys.transportKey,
            sessionId,
          );
          if (directSock) {
            selectedTier = "P2P_DIRECT";
          }
        }
        // Skip futile 1.5s UDP hole-punch delay when BOTH peers are behind unpredicted
        // Symmetric NAT and an Edge Relay or R2 fallback is available.
        const bothUnpredictedSymmetricNat =
          udpPrep?.natMapping === "symmetric" &&
          !udpPrep.hasSequentialPrediction &&
          peerConfirmed.peerNatMapping === "symmetric";

        if (
          !directSock &&
          udpPrep &&
          !bothUnpredictedSymmetricNat &&
          peerConfirmed.peerCandidates.some((c) => c.kind === "udp_punch")
        ) {
          try {
            udpChan = await establishUdpHolePunch({
              socket: udpPrep.socket,
              transportKey: keys.transportKey,
              sessionId,
              peerUdpCandidates: peerConfirmed.peerCandidates,
              timeoutMs: 1500,
            });
            selectedTier = "P2P_DIRECT";
          } catch {
            udpChan = null;
          }
        }
      }

      // 3. EDGE_RELAY (multi-region binary cut-through WSS / IP+TLS)
      //    vs 4. Micro-delta STREAM_RELAY vs 5. Bulk CAS R2_PIPELINE
      if (!directSock && !udpChan) {
        if (
          !options.disableEdgeRelay &&
          peerConfirmed.selectedEdgeRelay &&
          (options.preferEdgeRelay || missingBytesEstimate <= edgeRelayMaxBytes)
        ) {
          selectedTier = "EDGE_RELAY";
          selectedEdgeRelayRegion = peerConfirmed.selectedEdgeRelay.region;
        } else {
          selectedTier =
            missingBytesEstimate <= relayThreshold
              ? "STREAM_RELAY"
              : "R2_PIPELINE";
        }
      }
    }

    options.onProgress?.({
      phase: "streaming",
      tier: selectedTier,
      detail: `missing=${missingHashes.length} blobs (${missingBytesEstimate} B)${selectedEdgeRelayRegion ? ` relay=${selectedEdgeRelayRegion}` : ""}`,
    });

    const committedPromise = sig.waitFor("session_committed", 120_000);

    sig.send({
      type: "source_transfer_plan",
      manifest: sourceScan.manifest,
      rootTreeDigest: sourceScan.rootTreeDigest,
      missingBlobCount: missingHashes.length,
      missingBytesEstimate,
      selectedTier,
      selectedEdgeRelayRegion,
    });

    const targetPackBytes = options.targetPackBytes ?? DEFAULT_TARGET_PACK_BYTES;
    const requiredPackIds: string[] = [];
    let wireBytesSent = 0;
    let casSkippedPacks = 0;
    let fallbackToR2Triggered = false;

    const batches = buildMissingBlobBatches(
      missingHashes,
      sourceScan.blobSlices,
      targetPackBytes,
    );

    if (selectedTier === "LOCAL_IPC" && directSock) {
      for (const batchHashes of batches) {
        const blobs = await readBlobBatch(batchHashes, sourceScan.blobSlices);
        const pack = await encodePack(blobs, {
          compression: "none",
          encryption: "none",
        });
        requiredPackIds.push(pack.packId);
        wireBytesSent += pack.wireBytes.length;
        await sendPackOverSocket(directSock, pack.packId, pack.wireBytes);
      }
      await finishSocketStream(directSock);
    } else if (selectedTier === "P2P_DIRECT" && (directSock || udpChan)) {
      const ackedOnDirect: string[] = [];
      let failedBatchStartIndex = -1;

      for (let i = 0; i < batches.length; i++) {
        if (
          options.simulateP2pDropAfterPacks !== undefined &&
          i >= options.simulateP2pDropAfterPacks
        ) {
          failedBatchStartIndex = i;
          directSock?.destroy();
          udpChan?.destroy();
          break;
        }

        const blobs = await readBlobBatch(batches[i], sourceScan.blobSlices);
        const pack = await encodePack(blobs, {
          compression: "zstd",
          encryption: "chacha20-poly1305",
          packKey: keys.packKey,
          zstdCompressFn: zstdCompress,
        });

        try {
          await paceBytes?.(pack.wireBytes.length);
          if (directSock) {
            await sendPackOverSocket(directSock, pack.packId, pack.wireBytes);
          } else if (udpChan) {
            await sendPackOverUdp(udpChan, i, pack.packId, pack.wireBytes);
          }
          requiredPackIds.push(pack.packId);
          ackedOnDirect.push(pack.packId);
          wireBytesSent += pack.wireBytes.length;
        } catch {
          failedBatchStartIndex = i;
          break;
        }
      }

      if (failedBatchStartIndex === -1) {
        if (directSock) await finishSocketStream(directSock);
        if (udpChan) await finishUdpStream(udpChan);
      } else {
        // Seamless mid-flight fallback to R2_PIPELINE for remaining batches
        fallbackToR2Triggered = true;
        selectedTier = "R2_PIPELINE";
        const fallbackActivatedPromise = sig.waitFor(
          "fallback_to_r2_activated",
          10_000,
        );
        sig.send({
          type: "fallback_to_r2",
          reason: "P2P stream interrupted; switching remaining packs to R2_PIPELINE",
          targetReceivedPackIds: ackedOnDirect,
        });
        await fallbackActivatedPromise;

        const remainingBatches = batches.slice(failedBatchStartIndex);
        const r2Stats = await uploadPackBatchesToR2({
          batches: remainingBatches,
          blobSlices: sourceScan.blobSlices,
          packKey: keys.packKey,
          convergent: convergentPacks,
          sig,
          concurrency: options.uploadConcurrency ?? 8,
          paceBytes,
        });
        requiredPackIds.push(...r2Stats.packIds);
        wireBytesSent += r2Stats.wireBytesUploaded;
        casSkippedPacks += r2Stats.casSkippedPacks;
      }
    } else if (selectedTier === "EDGE_RELAY" && peerConfirmed.selectedEdgeRelay) {
      const alloc = peerConfirmed.selectedEdgeRelay;
      let ackedPackIds: string[] = [];
      let unackedBatches: string[][] = [];

      try {
        edgeChan = await connectEdgeRelayBinaryChannel({
          wsRelayUrl: alloc.wsRelayUrl,
          role: "source",
          transportKey: keys.transportKey,
          sessionId,
          certSha256: alloc.certSha256,
          noSni: alloc.noSni,
        });

        const streamRes = await streamPackBatchesOverEdgeRelay({
          channel: edgeChan,
          totalBatches: batches.length,
          simulateDropAfterPacks: options.simulateEdgeRelayDropAfterPacks,
          paceBytes,
          producePackAt: async (idx) => {
            const blobs = await readBlobBatch(batches[idx], sourceScan.blobSlices);
            return encodePack(blobs, {
              compression: "zstd",
              encryption: "chacha20-poly1305",
              packKey: keys.packKey,
              zstdCompressFn: zstdCompress,
            });
          },
        });

        wireBytesSent += streamRes.wireBytesSent;
        ackedPackIds = streamRes.ackedPackIds;
        if (!streamRes.interrupted) {
          for (const pid of streamRes.allPackIds) {
            if (pid) requiredPackIds.push(pid);
          }
        } else {
          requiredPackIds.push(...ackedPackIds);
          unackedBatches = batches.filter(
            (_, idx) => !streamRes.ackedBatchIndices.has(idx),
          );
        }
      } catch (err) {
        if (
          options.forceTier === "EDGE_RELAY" &&
          err instanceof Error &&
          err.message.includes("EDGE_RELAY_CERT_PIN_MISMATCH")
        ) {
          throw err;
        }
        unackedBatches = batches;
      }

      if (unackedBatches.length > 0) {
        fallbackToR2Triggered = true;
        selectedTier = "R2_PIPELINE";
        const fallbackActivatedPromise = sig.waitFor(
          "fallback_to_r2_activated",
          10_000,
        );
        sig.send({
          type: "fallback_to_r2",
          reason: "Edge Relay stream interrupted; switching remaining packs to R2_PIPELINE",
          targetReceivedPackIds: ackedPackIds,
        });
        await fallbackActivatedPromise;

        const r2Stats = await uploadPackBatchesToR2({
          batches: unackedBatches,
          blobSlices: sourceScan.blobSlices,
          packKey: keys.packKey,
          convergent: convergentPacks,
          sig,
          concurrency: options.uploadConcurrency ?? 8,
          paceBytes,
        });
        requiredPackIds.push(...r2Stats.packIds);
        wireBytesSent += r2Stats.wireBytesUploaded;
        casSkippedPacks += r2Stats.casSkippedPacks;
      }
    } else if (selectedTier === "STREAM_RELAY") {
      for (const batchHashes of batches) {
        const blobs = await readBlobBatch(batchHashes, sourceScan.blobSlices);
        const pack = await encodePack(blobs, {
          compression: "zstd",
          encryption: "chacha20-poly1305",
          packKey: keys.packKey,
          zstdCompressFn: zstdCompress,
        });
        requiredPackIds.push(pack.packId);
        wireBytesSent += pack.wireBytes.length;

        const totalChunks = Math.max(
          1,
          Math.ceil(pack.wireBytes.length / RELAY_FRAME_SLICE_BYTES),
        );
        for (let seq = 0; seq < totalChunks; seq++) {
          const slice = pack.wireBytes.subarray(
            seq * RELAY_FRAME_SLICE_BYTES,
            Math.min(pack.wireBytes.length, (seq + 1) * RELAY_FRAME_SLICE_BYTES),
          );
          await paceBytes?.(slice.byteLength);
          sig.send({
            type: "relay_pack_frame",
            packId: pack.packId,
            seq,
            totalChunks,
            payloadBase64: Buffer.from(slice).toString("base64"),
          });
        }
      }
    } else {
      // R2_PIPELINE: parallel zstd compression + concurrent presigned PUT + instant source receipts
      const r2Stats = await uploadPackBatchesToR2({
        batches,
        blobSlices: sourceScan.blobSlices,
        packKey: keys.packKey,
        convergent: convergentPacks,
        sig,
        concurrency: options.uploadConcurrency ?? 8,
        paceBytes,
      });
      requiredPackIds.push(...r2Stats.packIds);
      wireBytesSent += r2Stats.wireBytesUploaded;
      casSkippedPacks += r2Stats.casSkippedPacks;
    }

    const sourceAllPacksUploadedAtMs = Date.now();
    sig.send({
      type: "finalize_source_manifest",
      rootTreeDigest: sourceScan.rootTreeDigest,
      requiredPackIds,
      logicalBytes: sourceScan.manifest.totalLogicalBytes,
      dedupSavedBytes,
    });

    const committed = await committedPromise;

    return {
      sessionId,
      pairingCode:
        params.mode.kind === "pake" ? params.mode.pairingCode : undefined,
      selectedTier,
      selectedEdgeRelayRegion,
      fallbackToR2Triggered,
      rootTreeDigest: sourceScan.rootTreeDigest,
      logicalBytes: sourceScan.manifest.totalLogicalBytes,
      dedupSavedBytes,
      wireBytesSent,
      packCount: requiredPackIds.length,
      casSkippedPacks,
      cachedIndexHits: sourceScan.cachedFileHits,
      hashedFiles: sourceScan.hashedFiles,
      committedFiles: committed.committedFiles,
      sourceAllPacksUploadedAtMs,
      durationMs: Date.now() - startedAt,
    };
  } finally {
    edgeChan?.destroy();
    directSock?.destroy();
    udpChan?.destroy();
    await udpPrep?.close();
    sig.close();
  }
}

async function runTargetSession(params: {
  options: ReceiveDirectoryOptions;
  sessionId: string;
  peerToken: string;
  wsUrl: string;
  stunServers: string[];
  edgeRelays?: EdgeRelayNodeInfo[];
  mode:
    | { kind: "pake"; secretPhrase: string }
    | { kind: "lease"; leaseSecretHex: string; scopeCasKeyHex?: string };
}): Promise<ReceiveTransferSummary> {
  const startedAt = Date.now();
  const { options, sessionId, wsUrl, stunServers, edgeRelays } = params;
  const sig = await SignalingClient.connect(wsUrl);
  let directListeners: Awaited<
    ReturnType<typeof createTargetDirectListeners>
  > | null = null;
  let udpPrep: Awaited<ReturnType<typeof prepareUdpPunchEndpoint>> | null = null;
  let udpChan = null as UdpHolePunchChannel | null;
  let edgeChan = null as EdgeRelayBinaryChannel | null;
  let materializer: AtomicWorkspaceMaterializer | null = null;
  const allStunServers = [
    ...stunServers,
    ...(edgeRelays ?? [])
      .map((r) => r.stunUrl)
      .filter((u): u is string => Boolean(u)),
  ];

  try {
    // Scan existing target directory and probe Edge Relay RTTs in parallel
    const existingTargetScanPromise = scanWorkspace(options.targetDir, {
      cacheDir: options.cacheDir,
      smallFileThresholdBytes: options.smallFileThresholdBytes,
      cdcOptions: options.cdcOptions,
    }).catch(() => null);
    const relayRttPromise = options.disableEdgeRelay
      ? Promise.resolve<Record<string, number>>({})
      : probeEdgeRelayRtts(edgeRelays, 1000);

    const pake =
      params.mode.kind === "pake"
        ? new PakeHandshake("target", sessionId, params.mode.secretPhrase)
        : null;

    const peerJoinedPromise = sig.waitFor("peer_joined", 120_000);
    sig.send({
      type: "hello",
      role: "target",
      peerToken: params.peerToken,
      pakePublicHex: pake?.getPublicMessage(),
    });

    const peerJoined = await peerJoinedPromise;

    let keys: SessionKeyMaterial;
    let myConfirmMacHex: string;
    let expectedPeerMacHex: string;

    if (pake) {
      if (!peerJoined.peerPakePublicHex) {
        throw new Error("Missing peer PAKE public message");
      }
      const fin = pake.finish(peerJoined.peerPakePublicHex);
      keys = fin.keys;
      myConfirmMacHex = fin.myConfirmMacHex;
      expectedPeerMacHex = fin.expectedPeerConfirmMacHex;
    } else {
      const leaseMode = params.mode as {
        kind: "lease";
        leaseSecretHex: string;
        scopeCasKeyHex?: string;
      };
      const secret = hexToBytes(leaseMode.leaseSecretHex);
      keys = deriveSessionKeyMaterial(secret, sessionId, "managed-lease");
      if (leaseMode.scopeCasKeyHex) {
        keys = { ...keys, packKey: hexToBytes(leaseMode.scopeCasKeyHex) };
      }
      myConfirmMacHex = bytesToHex(keys.confirmKeyTarget);
      expectedPeerMacHex = bytesToHex(keys.confirmKeySource);
    }

    const hostFingerprint = await buildSessionHostFingerprint(
      keys.hostFingerprintKey,
      options.hostIdOverride,
    );

    const enableLocalIpc =
      !options.disableLocalIpc &&
      (!options.forceTier || options.forceTier === "LOCAL_IPC");
    const enableLanTcp =
      !options.disableP2p &&
      !options.disableP2pTcp &&
      (!options.forceTier || options.forceTier === "P2P_DIRECT");
    const enableUdp =
      !options.disableP2p &&
      !options.disableP2pUdp &&
      (!options.forceTier || options.forceTier === "P2P_DIRECT");

    directListeners = await createTargetDirectListeners({
      sessionId,
      transportKey: keys.transportKey,
      enableLocalIpc,
      enableLanTcp,
      rejectedAttemptCounter: options.rejectedDirectAttemptCounter,
    });

    if (enableUdp) {
      udpPrep = await prepareUdpPunchEndpoint(
        allStunServers,
        Boolean(options.allowLoopbackUdpForTest),
      );
    }

    const relayRttMs = await relayRttPromise;
    const peerConfirmedPromise = sig.waitFor("peer_confirmed", 20_000);
    sig.send({
      type: "pake_confirm",
      confirmMacHex: myConfirmMacHex,
      hostFingerprint,
      candidates: [
        ...directListeners.candidates,
        ...(udpPrep ? udpPrep.candidates : []),
      ],
      relayRttMs,
      natMapping: udpPrep?.natMapping,
    });

    const peerConfirmed = await peerConfirmedPromise;
    if (
      !constantTimeEqual(
        hexToBytes(peerConfirmed.peerConfirmMacHex),
        hexToBytes(expectedPeerMacHex),
      )
    ) {
      throw new Error("PAKE_AUTH_FAILED: Pairing phrase mismatch");
    }

    let pendingUdpPunchPromise: Promise<UdpHolePunchChannel | null> | null = null;
    if (
      !peerConfirmed.sameHostMatch &&
      udpPrep &&
      peerConfirmed.peerCandidates.some((c) => c.kind === "udp_punch")
    ) {
      pendingUdpPunchPromise = establishUdpHolePunch({
        socket: udpPrep.socket,
        transportKey: keys.transportKey,
        sessionId,
        peerUdpCandidates: peerConfirmed.peerCandidates,
        timeoutMs: 3500,
      }).catch(() => null);
    }

    const existingScan = await existingTargetScanPromise;
    const existingBlobs =
      existingScan?.blobSlices ?? new Map<string, BlobDiskSlice>();

    // Subscribe to transfer plan, R2 pack notifications, relay frames, and commit grant BEFORE sending target_have_blobs
    const r2Queue: Array<{ packId: string; getUrl: string }> = [];
    let notifyR2Queue = null as (() => void) | null;
    const relayChunks = new Map<
      string,
      { total: number; parts: Array<Buffer | undefined>; count: number }
    >();
    const relayReadyPacks: Array<{ packId: string; bytes: Uint8Array }> = [];
    let notifyRelayReady = null as (() => void) | null;

    let fallbackToR2Triggered = false;
    let notifyFallback = null as (() => void) | null;

    let grantCommitReceived = false;
    let notifyGrantCommit = null as (() => void) | null;
    let sessionFatalError = null as Error | null;

    const unsubTransfer = sig.subscribe((msg) => {
      if (msg.type === "session_error") {
        sessionFatalError = new Error(`${msg.code}: ${msg.message}`);
        notifyR2Queue?.();
        notifyRelayReady?.();
        notifyGrantCommit?.();
        notifyFallback?.();
        return;
      }
      if (msg.type === "pack_available") {
        r2Queue.push({ packId: msg.packId, getUrl: msg.getUrl });
        notifyR2Queue?.();
      } else if (msg.type === "relay_pack_frame") {
        let entry = relayChunks.get(msg.packId);
        if (!entry) {
          entry = {
            total: msg.totalChunks,
            parts: new Array(msg.totalChunks),
            count: 0,
          };
          relayChunks.set(msg.packId, entry);
        }
        if (!entry.parts[msg.seq]) {
          entry.parts[msg.seq] = Buffer.from(msg.payloadBase64, "base64");
          entry.count++;
        }
        if (entry.count === entry.total) {
          const full = Buffer.concat(entry.parts as Buffer[]);
          relayChunks.delete(msg.packId);
          relayReadyPacks.push({
            packId: msg.packId,
            bytes: new Uint8Array(full.buffer, full.byteOffset, full.byteLength),
          });
          notifyRelayReady?.();
        }
      } else if (msg.type === "fallback_to_r2_activated") {
        fallbackToR2Triggered = true;
        notifyFallback?.();
        notifyR2Queue?.();
      } else if (msg.type === "grant_atomic_commit") {
        grantCommitReceived = true;
        notifyGrantCommit?.();
        notifyR2Queue?.();
        notifyRelayReady?.();
      }
    });

    const planPromise = sig.waitFor("source_transfer_plan", 60_000);
    sig.send({
      type: "target_have_blobs",
      knownBlobHashes: Array.from(existingBlobs.keys()),
    });

    const plan = await planPromise;

    let selectedTier = plan.selectedTier;
    materializer = new AtomicWorkspaceMaterializer({
      targetDir: options.targetDir,
      sessionId,
      manifest: plan.manifest,
      rootTreeDigest: plan.rootTreeDigest,
      existingBlobs,
    });
    await materializer.prepareStaging();

    const appliedPackIds = new Set<string>();
    let firstPackAppliedAtMs: number | null = null;

    const applyPackWireBytes = async (
      packId: string,
      wireBytes: Uint8Array,
    ): Promise<void> => {
      if (appliedPackIds.has(packId)) return;
      const decoded = await decodePack(wireBytes, {
        expectedPackId: packId,
        packKey: keys.packKey,
        zstdDecompressFn: zstdDecompress,
      });
      await materializer!.applyIncomingBlobs(decoded.blobs);
      appliedPackIds.add(packId);
      if (firstPackAppliedAtMs === null) {
        firstPackAppliedAtMs = Date.now();
      }
      sig.send({ type: "report_pack_target_receipt", packId });
    };

    const runR2ConcurrentDownloadUntilGrant = async (): Promise<void> => {
      const concurrency = options.downloadConcurrency ?? 8;
      let activeDownloads = 0;

      await new Promise<void>((resolve, reject) => {
        const pump = () => {
          if (sessionFatalError) {
            reject(sessionFatalError);
            return;
          }
          while (activeDownloads < concurrency && r2Queue.length > 0) {
            const item = r2Queue.shift()!;
            if (appliedPackIds.has(item.packId)) {
              continue;
            }
            activeDownloads++;
            void fetchBytesWithRetry(item.getUrl)
              .then((bytes) => applyPackWireBytes(item.packId, bytes))
              .then(() => {
                activeDownloads--;
                pump();
              })
              .catch((err) => {
                activeDownloads--;
                reject(err instanceof Error ? err : new Error(String(err)));
              });
          }

          if (
            grantCommitReceived &&
            r2Queue.length === 0 &&
            activeDownloads === 0
          ) {
            resolve();
          }
        };

        notifyR2Queue = pump;
        pump();
      });
    };

    if (plan.missingBlobCount === 0) {
      // Zero packs needed; wait directly for Coordinator's grant_atomic_commit
      await waitUntil(() => grantCommitReceived || Boolean(sessionFatalError));
      if (sessionFatalError) throw sessionFatalError;
    } else if (selectedTier === "LOCAL_IPC") {
      const { channel } = await directListeners.waitForAuthenticatedChannel(8000);
      await receivePacksFromSocket(channel, applyPackWireBytes);
      channel.destroy();
      await waitUntil(() => grantCommitReceived || Boolean(sessionFatalError));
      if (sessionFatalError) throw sessionFatalError;
    } else if (selectedTier === "P2P_DIRECT") {
      try {
        const punched = pendingUdpPunchPromise
          ? await pendingUdpPunchPromise
          : null;
        if (punched) {
          udpChan = punched;
          await Promise.race([
            receivePacksFromUdp(punched, applyPackWireBytes),
            waitForFallbackTrigger(() => fallbackToR2Triggered, (fn) => {
              notifyFallback = fn;
            }),
          ]);
        } else {
          const { channel } =
            await directListeners.waitForAuthenticatedChannel(5000);
          await Promise.race([
            receivePacksFromSocket(channel, applyPackWireBytes),
            waitForFallbackTrigger(() => fallbackToR2Triggered, (fn) => {
              notifyFallback = fn;
            }),
          ]);
          channel.destroy();
        }
      } catch {
        // P2P interrupted; wait briefly for Coordinator fallback_to_r2_activated or trigger it
        if (!fallbackToR2Triggered) {
          sig.send({
            type: "fallback_to_r2",
            reason: "Target P2P reader interrupted",
            targetReceivedPackIds: Array.from(appliedPackIds),
          });
          fallbackToR2Triggered = true;
        }
      }

      if (fallbackToR2Triggered) {
        selectedTier = "R2_PIPELINE";
        await runR2ConcurrentDownloadUntilGrant();
      } else {
        await waitUntil(() => grantCommitReceived || Boolean(sessionFatalError));
        if (sessionFatalError) throw sessionFatalError;
      }
    } else if (selectedTier === "EDGE_RELAY") {
      try {
        const alloc = peerConfirmed.selectedEdgeRelay;
        if (!alloc) {
          throw new Error("Missing selectedEdgeRelay allocation on target");
        }
        edgeChan = await connectEdgeRelayBinaryChannel({
          wsRelayUrl: alloc.wsRelayUrl,
          role: "target",
          transportKey: keys.transportKey,
          sessionId,
          certSha256: alloc.certSha256,
          noSni: alloc.noSni,
        });
        await Promise.race([
          receivePacksFromEdgeRelay(edgeChan, applyPackWireBytes),
          waitForFallbackTrigger(() => fallbackToR2Triggered, (fn) => {
            notifyFallback = fn;
          }),
        ]);
        edgeChan.destroy();
      } catch (err) {
        if (
          options.forceTier === "EDGE_RELAY" &&
          err instanceof Error &&
          err.message.includes("EDGE_RELAY_CERT_PIN_MISMATCH")
        ) {
          throw err;
        }
        if (!fallbackToR2Triggered) {
          sig.send({
            type: "fallback_to_r2",
            reason: "Target Edge Relay reader interrupted",
            targetReceivedPackIds: Array.from(appliedPackIds),
          });
          fallbackToR2Triggered = true;
        }
      }

      if (fallbackToR2Triggered) {
        selectedTier = "R2_PIPELINE";
        await runR2ConcurrentDownloadUntilGrant();
      } else {
        await waitUntil(() => grantCommitReceived || Boolean(sessionFatalError));
        if (sessionFatalError) throw sessionFatalError;
      }
    } else if (selectedTier === "STREAM_RELAY") {
      while (!grantCommitReceived) {
        if (sessionFatalError) throw sessionFatalError;
        while (relayReadyPacks.length > 0) {
          const next = relayReadyPacks.shift()!;
          await applyPackWireBytes(next.packId, next.bytes);
        }
        if (grantCommitReceived) break;
        await new Promise<void>((r) => {
          notifyRelayReady = r;
        });
      }
    } else {
      await runR2ConcurrentDownloadUntilGrant();
    }

    unsubTransfer();

    const { committedFiles } = await materializer.commit();
    const committedDonePromise = sig.waitFor("session_committed", 15_000);
    sig.send({
      type: "report_target_committed",
      rootTreeDigest: plan.rootTreeDigest,
      committedFiles,
    });
    await committedDonePromise;

    return {
      sessionId,
      selectedTier,
      selectedEdgeRelayRegion: plan.selectedEdgeRelayRegion,
      fallbackToR2Triggered,
      rootTreeDigest: plan.rootTreeDigest,
      committedFiles,
      packsApplied: appliedPackIds.size,
      firstPackAppliedAtMs,
      durationMs: Date.now() - startedAt,
    };
  } catch (err) {
    await materializer?.abort();
    throw err;
  } finally {
    edgeChan?.destroy();
    udpChan?.destroy();
    await udpPrep?.close();
    await directListeners?.closeAll();
    sig.close();
  }
}

function buildMissingBlobBatches(
  missingHashes: string[],
  blobSlices: ReadonlyMap<string, BlobDiskSlice>,
  targetPackBytes: number,
): string[][] {
  const batches: string[][] = [];
  let current: string[] = [];
  let currentBytes = 0;

  for (const hash of missingHashes) {
    const len = blobSlices.get(hash)?.length ?? 0;
    if (current.length > 0 && currentBytes + len > targetPackBytes) {
      batches.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(hash);
    currentBytes += len;
  }
  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

async function readBlobBatch(
  hashes: string[],
  blobSlices: ReadonlyMap<string, BlobDiskSlice>,
): Promise<PackBlobInput[]> {
  const results: PackBlobInput[] = [];
  for (const hash of hashes) {
    const slice = blobSlices.get(hash);
    if (!slice) {
      throw new Error(`Missing local disk slice for blob ${hash}`);
    }
    const fh = await open(slice.absPath, "r");
    try {
      const buf = Buffer.allocUnsafe(slice.length);
      let readTotal = 0;
      while (readTotal < slice.length) {
        const { bytesRead } = await fh.read(
          buf,
          readTotal,
          slice.length - readTotal,
          slice.offset + readTotal,
        );
        if (bytesRead === 0) break;
        readTotal += bytesRead;
      }
      results.push({
        hash,
        data: new Uint8Array(buf.buffer, buf.byteOffset, readTotal),
      });
    } finally {
      await fh.close();
    }
  }
  return results;
}

async function uploadPackBatchesToR2(params: {
  batches: string[][];
  blobSlices: ReadonlyMap<string, BlobDiskSlice>;
  packKey: Uint8Array;
  convergent?: boolean;
  sig: SignalingClient;
  concurrency: number;
  paceBytes?: (byteCount: number) => Promise<void>;
}): Promise<{
  packIds: string[];
  wireBytesUploaded: number;
  casSkippedPacks: number;
}> {
  if (params.batches.length === 0) {
    return { packIds: [], wireBytesUploaded: 0, casSkippedPacks: 0 };
  }

  const slotWaiters = new Map<
    string,
    (slots: AllocatedUploadSlot[]) => void
  >();
  const unsub = params.sig.subscribe((msg) => {
    if (msg.type === "upload_urls_allocated") {
      const w = slotWaiters.get(msg.requestId);
      if (w) {
        slotWaiters.delete(msg.requestId);
        w(msg.slots);
      }
    }
  });

  const packIds = new Array<string>(params.batches.length);
  let wireBytesUploaded = 0;
  let casSkippedPacks = 0;
  let nextIdx = 0;

  try {
    const workerCount = Math.min(params.concurrency, params.batches.length);
    await Promise.all(
      Array.from({ length: workerCount }, async () => {
        while (true) {
          const idx = nextIdx++;
          if (idx >= params.batches.length) return;

          const blobs = await readBlobBatch(
            params.batches[idx],
            params.blobSlices,
          );
          const pack = await encodePack(blobs, {
            compression: "zstd",
            encryption: "chacha20-poly1305",
            packKey: params.packKey,
            convergent: params.convergent,
            zstdCompressFn: zstdCompress,
          });
          packIds[idx] = pack.packId;

          const reqId = `${idx}-${pack.packId.slice(0, 8)}`;
          const slotsPromise = new Promise<AllocatedUploadSlot[]>((resolve) => {
            slotWaiters.set(reqId, resolve);
          });
          params.sig.send({
            type: "allocate_upload_urls",
            requestId: reqId,
            packs: [
              {
                packId: pack.packId,
                sizeBytes: pack.wireBytes.length,
                blobCount: pack.blobCount,
              },
            ],
          });

          const [slot] = await slotsPromise;
          if (slot.alreadyExistsInCas) {
            casSkippedPacks++;
            continue;
          }

          await params.paceBytes?.(pack.wireBytes.length);
          await putBytesWithRetry(slot.putUrl, pack.wireBytes);
          wireBytesUploaded += pack.wireBytes.length;

          // Immediately emit source receipt so target starts downloading while other workers upload
          params.sig.send({
            type: "report_pack_source_receipt",
            packId: pack.packId,
            sizeBytes: pack.wireBytes.length,
            blobCount: pack.blobCount,
          });
        }
      }),
    );
  } finally {
    unsub();
  }

  return { packIds, wireBytesUploaded, casSkippedPacks };
}

async function tryConnectCandidates(
  candidates: EndpointCandidate[],
  transportKey: Uint8Array,
  sessionId: string,
): Promise<FramedSocketChannel | null> {
  return raceCandidatesHappyEyeballs(candidates, transportKey, sessionId, {
    staggerMs: 100,
    perAttemptTimeoutMs: 900,
  });
}

async function putBytesWithRetry(
  url: string,
  bytes: Uint8Array,
  maxAttempts = 3,
): Promise<void> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, {
        method: "PUT",
        headers: {
          "content-length": String(bytes.byteLength),
        },
        body: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength),
      });
      if (!res.ok) {
        throw new Error(`PUT pack failed with HTTP ${res.status}`);
      }
      await res.arrayBuffer();
      return;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, 150 * attempt));
      }
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

async function fetchBytesWithRetry(
  url: string,
  maxAttempts = 3,
): Promise<Uint8Array> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, { method: "GET" });
      if (!res.ok) {
        throw new Error(`GET pack failed with HTTP ${res.status}`);
      }
      const ab = await res.arrayBuffer();
      return new Uint8Array(ab);
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, 150 * attempt));
      }
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

async function httpPostJson<T>(
  url: string,
  body: unknown,
  bearerToken?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (bearerToken) {
    headers.authorization = `Bearer ${bearerToken}`;
  }
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}: ${text}`);
  }
  return JSON.parse(text) as T;
}

function waitUntil(predicate: () => boolean, pollMs = 15): Promise<void> {
  if (predicate()) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setInterval(() => {
      if (predicate()) {
        clearInterval(timer);
        resolve();
      }
    }, pollMs);
  });
}

function waitForFallbackTrigger(
  check: () => boolean,
  register: (fn: () => void) => void,
): Promise<void> {
  if (check()) return Promise.resolve();
  return new Promise<void>((resolve) => {
    register(() => resolve());
  });
}

export async function runDoctor(serverUrl: string): Promise<{
  serverHealth: Record<string, unknown>;
  stunReflexiveEndpoint: { ip: string; port: number } | null;
  natMapping: NatMappingBehavior;
  natPortStride: number;
  directInterfaces: DiscoveredDirectAddress[];
  edgeRelayRttMs: Record<string, number>;
  zstdSelfTestOk: boolean;
}> {
  const baseHttp = serverUrl.replace(/\/+$/, "");
  const healthRes = await fetch(`${baseHttp}/healthz`);
  if (!healthRes.ok) {
    throw new Error(`Server health check failed with HTTP ${healthRes.status}`);
  }
  const serverHealth = (await healthRes.json()) as Record<string, unknown>;
  const stunServers = Array.isArray(serverHealth.stunServers)
    ? (serverHealth.stunServers as string[])
    : ["stun:stun.cloudflare.com:3478"];
  const edgeRelays = Array.isArray(serverHealth.edgeRelays)
    ? (serverHealth.edgeRelays as EdgeRelayNodeInfo[])
    : [];
  const allStunServers = [
    ...stunServers,
    ...edgeRelays
      .map((r) => r.stunUrl)
      .filter((u): u is string => Boolean(u)),
  ];

  const [prep, edgeRelayRttMs] = await Promise.all([
    prepareUdpPunchEndpoint(allStunServers),
    probeEdgeRelayRtts(edgeRelays, 1500),
  ]);
  const udpCand = prep.candidates.find((c) => c.kind === "udp_punch");
  await prep.close();

  const sample = new TextEncoder().encode("beamsync-doctor-zstd-check".repeat(32));
  const compressed = await zstdCompress(sample);
  const decompressed = await zstdDecompress(compressed);
  const zstdSelfTestOk =
    decompressed.length === sample.length && compressed.length < sample.length;

  return {
    serverHealth,
    stunReflexiveEndpoint: udpCand
      ? { ip: udpCand.address, port: udpCand.port! }
      : null,
    natMapping: prep.natMapping,
    natPortStride: prep.portStride,
    directInterfaces: discoverDirectIpAddresses(),
    edgeRelayRttMs,
    zstdSelfTestOk,
  };
}
