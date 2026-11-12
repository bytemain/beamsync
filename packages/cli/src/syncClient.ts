import { open } from "node:fs/promises";
import WebSocket from "ws";
import {
  BEAMSYNC_PROTOCOL_VERSION,
  bytesToHex,
  collectRequiredBlobHashes,
  computeRootTreeDigest,
  constantTimeEqual,
  controlStreamSegmentBytesFor,
  decodePack,
  deriveRendezvousSlot,
  deriveSessionKeyMaterial,
  encodePack,
  formatPairingPhrase,
  generateSecretWords,
  MAX_SIGNALING_MESSAGE_BYTES,
  HaveBlobsStreamAssembler,
  haveBlobsStreamRecords,
  hexToBytes,
  ManifestStreamAssembler,
  manifestStreamRecords,
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
  selectTransportAgent,
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
import { readControlStream, writeControlStream } from "./controlStream.js";
import { buildSessionHostFingerprint } from "./hostIdentity.js";
import { httpRequestBytes } from "./httpClient.js";
import { AtomicWorkspaceMaterializer } from "./materializer.js";
import {
  scanWorkspace,
  type BlobDiskSlice,
  type IgnoreOptions,
} from "./stateIndex.js";
import {
  establishUdpHolePunch,
  finishUdpStream,
  prepareUdpPunchEndpoint,
  probeUdpPathPayloadSize,
  receivePacksFromUdp,
  sendPackOverUdp,
  type UdpHolePunchChannel,
} from "./udpHolePunch.js";
import type { PortMappingGateway } from "./portMapping.js";
import { resolveProxyForUrl } from "./proxy.js";
import { zstdCompress, zstdDecompress } from "./zstdCodec.js";

export interface TransferCommonOptions {
  serverUrl: string;
  /** Bearer token for servers that require one to create or join a pairing (`BEAMSYNC_API_TOKEN`). */
  apiToken?: string;
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
  /**
   * Disable "relay first, upgrade later": by default, when an Edge Relay is available the
   * transfer starts on it after a short grace period while direct paths keep probing in the
   * background, then hot-upgrades to P2P at a pack boundary.
   */
  disableOptimisticRelay?: boolean;
  /** How long to wait for a direct path before starting on the Edge Relay (default 250 ms). */
  optimisticRelayGraceMs?: number;
  /** Total time budget for transparently resuming a dropped signaling socket (default 30 s; 0 disables). */
  signalingReconnectBudgetMs?: number;
  /**
   * Largest signaling message this client will send (default: the Coordinator's 32 MiB limit).
   * A larger message is refused locally instead of being rejected by the Coordinator.
   */
  maxSignalingMessageBytes?: number;
  /**
   * Uncompressed bytes per sealed control stream segment (manifest, known-blob list). Default
   * 1 MiB, lowered automatically so a segment always fits in one signaling message.
   */
  controlStreamSegmentBytes?: number;
  /** Segments a control stream writer may have in flight before waiting for the reader (default 8). */
  controlStreamWindowSegments?: number;
  /** Disable probe-based UDP payload sizing and keep the conservative 1150-byte chunks. */
  disableUdpMtuProbe?: boolean;
  /** Do not ask the local gateway for a UDP port mapping (NAT-PMP). */
  disablePortMapping?: boolean;
  /** Explicit NAT-PMP gateway; by default the host's default IPv4 gateway is used. */
  portMappingGateway?: PortMappingGateway;
  allowLoopbackUdpForTest?: boolean;
  allowLoopbackTcpForTest?: boolean;
  forceTier?: TransportTier;
  targetPackBytes?: number;
  /** Most blobs packed together regardless of size (default 4096). */
  maxBlobsPerPack?: number;
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

export interface SendDirectoryOptions extends TransferCommonOptions, IgnoreOptions {
  sourceDir: string;
  scopeNamespace?: string;
  customSlotCode?: string;
  customSecretWords?: string;
  simulateP2pDropAfterPacks?: number;
  simulateEdgeRelayDropAfterPacks?: number;
  /** Test hook: delays background direct-path discovery so the Edge Relay starts first. */
  simulateDirectReadyDelayMs?: number;
  onPairingCode?: (pairingCode: string, sessionId: string) => void;
}

export interface ReceiveDirectoryOptions extends TransferCommonOptions {
  targetDir: string;
  pairingCode: string;
  /**
   * Delete target paths that match the source's ignore rules. By default they are kept, so a
   * re-sync does not wipe the target's own dependency folders or local env files.
   */
  deleteIgnored?: boolean;
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
  /** True when the session started on an Edge Relay and moved to a direct path mid-stream. */
  upgradedToDirect: boolean;
  packsViaEdgeRelay: number;
  packsViaDirect: number;
  /** Number of times the signaling socket was transparently resumed. */
  signalingReconnects: number;
  /** UDP chunk payload size in use (after path probing), when a UDP path was established. */
  udpChunkPayloadBytes?: number;
  /** Entries (files, symlinks, empty directories) in the manifest sent to the target. */
  manifestEntries: number;
  /** Sealed signaling segments the manifest was split into. */
  manifestSegments: number;
  /** Sealed (compressed + encrypted) size of the manifest. */
  manifestSealedBytes: number;
  /** Entries skipped by an ignore rule (an ignored directory counts once). */
  ignoredPaths: number;
  /** Workspace-relative ignore files that contributed rules. */
  ignoreFilesLoaded: string[];
}

export interface ReceiveTransferSummary {
  sessionId: string;
  selectedTier: TransportTier;
  selectedEdgeRelayRegion?: string;
  fallbackToR2Triggered: boolean;
  rootTreeDigest: string;
  committedFiles: number;
  upgradedToDirect: boolean;
  signalingReconnects: number;
  packsApplied: number;
  firstPackAppliedAtMs: number | null;
  durationMs: number;
  /** Entries in the manifest received from the source. */
  manifestEntries: number;
  /** Sealed signaling segments the manifest arrived in. */
  manifestSegments: number;
  /** Target paths kept because the source's ignore rules cover them. */
  preservedIgnoredPaths: number;
  /** Ignored paths that could not be carried over; the previous tree is kept when non-empty. */
  preserveFailures: Array<{ relPath: string; error: string }>;
  retainedBackupDir?: string;
}

const DEFAULT_TARGET_PACK_BYTES = 8 * 1024 * 1024; // 8 MiB
const DEFAULT_MAX_BLOBS_PER_PACK = 4096;
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

/** Fails right after pairing rather than letting two incompatible builds wait on each other. */
function assertPeerProtocolVersion(peerVersion: number | undefined): void {
  if (peerVersion === BEAMSYNC_PROTOCOL_VERSION) return;
  throw new Error(
    `PROTOCOL_VERSION_MISMATCH: this build speaks session protocol ${BEAMSYNC_PROTOCOL_VERSION}, ` +
      (peerVersion === undefined
        ? "the other peer or the Coordinator is an older build that does not announce a version"
        : `the other peer speaks ${peerVersion}`) +
      ". Run the same BeamSync version on both machines and on the server.",
  );
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
    options.apiToken,
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
        options.apiToken,
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

const SIGNALING_KEEPALIVE_MS = 20_000;
const SIGNALING_ACK_EVERY_MESSAGES = 32;
/** Acknowledge after this many received bytes so the Coordinator can trim its replay log. */
const SIGNALING_ACK_EVERY_BYTES = 2 * 1024 * 1024;
const SIGNALING_OUTBOX_ACK_SOLICIT_BYTES = 4 * 1024 * 1024;
const DEFAULT_SIGNALING_RECONNECT_BUDGET_MS = 30_000;
/** Matches the Coordinator's pairing TTL: how long a peer waits for the other side to show up. */
const PEER_JOIN_WAIT_MS = 10 * 60 * 1000;

/**
 * Reliable, resumable signaling channel to the Coordinator.
 *
 * Every control message carries a sequence number in both directions. When the
 * WebSocket drops (roaming between networks, proxy idle reset, Coordinator LB
 * recycle) the client reconnects with exponential backoff, re-attaches with
 * `hello.resumeFromSeq`, replays its un-acknowledged outbox, and the Coordinator
 * replays everything the client missed. Callers never observe the gap.
 */
export class SignalingMessageTooLargeError extends Error {
  readonly code = "SIGNALING_MESSAGE_TOO_LARGE";
  constructor(
    readonly messageType: string,
    readonly messageBytes: number,
    readonly limitBytes: number,
  ) {
    super(
      `SIGNALING_MESSAGE_TOO_LARGE: "${messageType}" is ${formatMiB(messageBytes)}, ` +
        `above the ${formatMiB(limitBytes)} signaling limit`,
    );
  }
}

function formatMiB(bytes: number): string {
  const mib = bytes / (1024 * 1024);
  return mib >= 10 ? `${mib.toFixed(0)} MiB` : mib >= 0.1 ? `${mib.toFixed(1)} MiB` : `${bytes} B`;
}

class SignalingClient {
  private ws: WebSocket | null = null;
  private readonly listeners = new Set<(msg: ServerToClientWsMessage) => void>();
  private readonly buffered: ServerToClientWsMessage[] = [];
  private closedError: Error | null = null;
  private closedByUser = false;
  private reconnecting = false;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;

  private helloMsg: Extract<ClientToServerWsMessage, { type: "hello" }> | null = null;
  private nextClientSeq = 0;
  private outbox: Array<{ cseq: number; payload: string }> = [];
  private outboxBytes = 0;
  private outboxBytesAtLastSolicit = 0;
  private lastServerSeq = 0;
  private receivedSinceAck = 0;
  private receivedBytesSinceAck = 0;

  /** Number of successful signaling re-attachments during this session. */
  reconnectCount = 0;
  onReconnect: ((reconnectCount: number) => void) | null = null;

  private constructor(
    private readonly wsUrl: string,
    private readonly reconnectBudgetMs: number,
    /** Largest message `send` accepts. */
    readonly maxMessageBytes: number,
  ) {}

  static async connect(
    wsUrl: string,
    opts: { reconnectBudgetMs?: number; maxMessageBytes?: number } = {},
  ): Promise<SignalingClient> {
    const client = new SignalingClient(
      wsUrl,
      opts.reconnectBudgetMs ?? DEFAULT_SIGNALING_RECONNECT_BUDGET_MS,
      opts.maxMessageBytes ?? MAX_SIGNALING_MESSAGE_BYTES,
    );
    const ws = await client.openSocket(15_000);
    client.attach(ws);

    // Periodic 20s keepalive prevents NAT gateways / reverse proxies (60-100s idle timeout)
    // from dropping the signaling socket, and carries cumulative acks in both directions.
    client.keepaliveTimer = setInterval(() => client.sendAckPing(), SIGNALING_KEEPALIVE_MS);
    client.keepaliveTimer.unref();
    return client;
  }

  private openSocket(timeoutMs: number): Promise<WebSocket> {
    return new Promise<WebSocket>((resolve, reject) => {
      const ws = new WebSocket(this.wsUrl, {
        agent: selectTransportAgent(this.wsUrl),
        maxPayload: 256 * 1024 * 1024,
      });
      const timer = setTimeout(() => {
        ws.terminate();
        reject(new Error("Timed out connecting to signaling WebSocket"));
      }, timeoutMs);
      ws.once("open", () => {
        clearTimeout(timer);
        ws.removeAllListeners("error");
        resolve(ws);
      });
      ws.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  private attach(ws: WebSocket): void {
    this.ws = ws;
    ws.on("message", (raw) => {
      if (this.ws !== ws) return;
      const str = typeof raw === "string" ? raw : raw.toString("utf8");
      let parsed: ServerToClientWsMessage & { sseq?: number };
      try {
        parsed = JSON.parse(str) as ServerToClientWsMessage & { sseq?: number };
      } catch {
        return;
      }
      this.handleIncoming(parsed, str.length);
    });
    ws.on("close", () => this.handleSocketLost(ws));
    ws.on("error", () => this.handleSocketLost(ws));
  }

  private handleIncoming(
    parsed: ServerToClientWsMessage & { sseq?: number },
    wireChars: number,
  ): void {
    if (parsed.type === "pong") {
      if (typeof parsed.ackSeq === "number") this.trimOutbox(parsed.ackSeq);
      return;
    }
    if (parsed.type === "resumed") {
      this.trimOutbox(parsed.lastClientSeq);
      for (const entry of this.outbox) {
        this.rawSend(entry.payload);
      }
      return;
    }
    if (typeof parsed.sseq === "number") {
      if (parsed.sseq <= this.lastServerSeq) {
        return; // duplicate delivered by a replay
      }
      this.lastServerSeq = parsed.sseq;
      this.receivedSinceAck++;
      this.receivedBytesSinceAck += wireChars;
      if (
        this.receivedSinceAck >= SIGNALING_ACK_EVERY_MESSAGES ||
        this.receivedBytesSinceAck >= SIGNALING_ACK_EVERY_BYTES
      ) {
        this.sendAckPing();
      }
    }
    this.dispatch(parsed);
  }

  private dispatch(msg: ServerToClientWsMessage): void {
    if (this.listeners.size === 0) {
      this.buffered.push(msg);
    } else {
      for (const fn of [...this.listeners]) {
        fn(msg);
      }
    }
  }

  private trimOutbox(ackSeq: number): void {
    let drop = 0;
    while (drop < this.outbox.length && this.outbox[drop].cseq <= ackSeq) {
      this.outboxBytes -= this.outbox[drop].payload.length;
      drop++;
    }
    if (drop > 0) this.outbox.splice(0, drop);
    this.outboxBytesAtLastSolicit = Math.min(this.outboxBytesAtLastSolicit, this.outboxBytes);
  }

  private rawSend(payload: string): void {
    const ws = this.ws;
    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(payload);
      } catch {
        // The close handler triggers reconnect + replay
      }
    }
  }

  private sendAckPing(): void {
    this.receivedSinceAck = 0;
    this.receivedBytesSinceAck = 0;
    this.rawSend(
      JSON.stringify({ type: "ping", ts: Date.now(), ackSeq: this.lastServerSeq }),
    );
  }

  private handleSocketLost(ws: WebSocket): void {
    if (this.ws !== ws) return;
    this.ws = null;
    try {
      ws.terminate();
    } catch {
      // already closed
    }
    if (this.closedByUser || this.closedError) return;
    if (!this.helloMsg || this.reconnectBudgetMs <= 0) {
      this.failPermanently(new Error("Signaling WebSocket closed"));
      return;
    }
    if (!this.reconnecting) {
      void this.reconnectLoop();
    }
  }

  private async reconnectLoop(): Promise<void> {
    this.reconnecting = true;
    const deadline = Date.now() + this.reconnectBudgetMs;
    let backoffMs = 100;
    let lastErr: Error = new Error("Signaling WebSocket closed");

    try {
      while (!this.closedByUser && Date.now() < deadline) {
        try {
          const ws = await this.openSocket(Math.max(500, Math.min(5000, deadline - Date.now())));
          if (this.closedByUser) {
            ws.terminate();
            return;
          }
          this.attach(ws);
          this.reconnectCount++;
          // `resumed` answers with the Coordinator's processed watermark; the handler then
          // replays the outbox, and the Coordinator replays everything after resumeFromSeq.
          this.rawSend(
            JSON.stringify({ ...this.helloMsg, resumeFromSeq: this.lastServerSeq }),
          );
          this.onReconnect?.(this.reconnectCount);
          return;
        } catch (err) {
          lastErr = err instanceof Error ? err : new Error(String(err));
          await new Promise((r) => setTimeout(r, backoffMs));
          backoffMs = Math.min(2000, backoffMs * 2);
        }
      }
      if (!this.closedByUser) {
        this.failPermanently(
          new Error(
            `Signaling connection lost and could not be resumed within ${this.reconnectBudgetMs} ms: ${lastErr.message}`,
          ),
        );
      }
    } finally {
      this.reconnecting = false;
    }
  }

  private failPermanently(err: Error): void {
    if (this.closedError) return;
    this.closedError = err;
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    this.dispatch({
      type: "session_error",
      code: "SIGNALING_LOST",
      message: err.message,
    });
  }

  send(msg: ClientToServerWsMessage): void {
    if (msg.type === "hello") {
      this.helloMsg = msg;
      this.rawSend(JSON.stringify(msg));
      return;
    }
    if (msg.type === "ping") {
      this.rawSend(JSON.stringify(msg));
      return;
    }
    const payload = JSON.stringify({ ...msg, cseq: this.nextClientSeq + 1 });
    // The Coordinator closes the socket on an oversized frame. Queuing one would make every
    // resume replay it and be closed again, so refuse it here, before it enters the outbox.
    const payloadBytes = Buffer.byteLength(payload, "utf8");
    if (payloadBytes > this.maxMessageBytes) {
      throw new SignalingMessageTooLargeError(msg.type, payloadBytes, this.maxMessageBytes);
    }
    const cseq = ++this.nextClientSeq;
    this.outbox.push({ cseq, payload });
    this.outboxBytes += payload.length;
    this.rawSend(payload);

    // Solicit a cumulative ack so the replay outbox stays bounded during bulk relaying
    if (
      this.outboxBytes - this.outboxBytesAtLastSolicit >= SIGNALING_OUTBOX_ACK_SOLICIT_BYTES ||
      this.outbox.length % 64 === 0
    ) {
      this.outboxBytesAtLastSolicit = this.outboxBytes;
      this.sendAckPing();
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
      // timeoutMs <= 0 waits for as long as the session lives: liveness then comes from
      // SIGNALING_LOST (own link) and PEER_LOST (other side) rather than a wall-clock guess.
      const timer =
        timeoutMs > 0
          ? setTimeout(() => {
              unsub();
              reject(new Error(`Timed out waiting for signaling message "${expectedType}"`));
            }, timeoutMs)
          : undefined;

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

  /** Test hook: abruptly kills the current socket as if the network path vanished. */
  simulateNetworkDrop(): void {
    this.ws?.terminate();
  }

  close(): void {
    this.closedByUser = true;
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    try {
      this.ws?.close();
    } catch {
      // already closed
    }
  }
}

type DirectPathResult =
  | { kind: "local_ipc" | "tcp"; sock: FramedSocketChannel }
  | { kind: "udp"; chan: UdpHolePunchChannel }
  | null;

function destroyDirectPath(path: DirectPathResult): void {
  if (!path) return;
  if (path.kind === "udp") path.chan.destroy();
  else path.sock.destroy();
}

/** Resolves with the promise's value if it settles within `ms`, otherwise `{ settled: false }`. */
async function settleWithin<T>(
  promise: Promise<T>,
  ms: number,
): Promise<{ settled: true; value: T } | { settled: false }> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.then((value) => ({ settled: true as const, value })),
      new Promise<{ settled: false }>((resolve) => {
        timer = setTimeout(() => resolve({ settled: false }), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
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
  const sig = await SignalingClient.connect(wsUrl, {
    reconnectBudgetMs: options.signalingReconnectBudgetMs,
    maxMessageBytes: options.maxSignalingMessageBytes,
  });
  sig.onReconnect = (n) =>
    options.onProgress?.({ phase: "signaling_resumed", detail: `reconnects=${n}` });
  let udpPrep: Awaited<ReturnType<typeof prepareUdpPunchEndpoint>> | null = null;
  let directSock: FramedSocketChannel | null = null;
  let udpChan: UdpHolePunchChannel | null = null;
  let edgeChan: EdgeRelayBinaryChannel | null = null;
  const directAbort = new AbortController();
  let directAttemptPromise: Promise<DirectPathResult> | null = null;
  const paceBytes = createBandwidthPacer(options.maxBandwidthMbps);
  const allStunServers = [
    ...stunServers,
    ...(edgeRelays ?? [])
      .map((r) => r.stunUrl)
      .filter((u): u is string => Boolean(u)),
  ];

  // A session that ends early must not leave a scan walking the tree in the background
  const scanAbort = new AbortController();
  let scanSettled: Promise<unknown> = Promise.resolve();

  try {
    // Start scanning source workspace and probing Edge Relay RTTs immediately in parallel
    const sourceScanPromise = scanWorkspace(options.sourceDir, {
      signal: scanAbort.signal,
      cacheDir: options.cacheDir,
      extraIgnoreRules: options.extraIgnoreRules,
      ignoreFileNames: options.ignoreFileNames,
      respectGitignore: options.respectGitignore,
      ignoreFromFiles: options.ignoreFromFiles,
      smallFileThresholdBytes: options.smallFileThresholdBytes,
      cdcOptions: options.cdcOptions,
    });
    scanSettled = sourceScanPromise.catch(() => {});
    const relayRttPromise = options.disableEdgeRelay
      ? Promise.resolve<Record<string, number>>({})
      : probeEdgeRelayRtts(edgeRelays, 1000);

    const pake =
      params.mode.kind === "pake"
        ? new PakeHandshake("source", sessionId, params.mode.secretPhrase)
        : null;

    const peerJoinedPromise = sig.waitFor("peer_joined", PEER_JOIN_WAIT_MS);
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
        { disabled: options.disablePortMapping, gateway: options.portMappingGateway },
      );
      if (udpPrep.portMapping) {
        options.onProgress?.({
          phase: "port_mapped",
          detail: `udp ${udpPrep.portMapping.externalIp}:${udpPrep.portMapping.externalPort} via ${udpPrep.portMapping.gateway.address}`,
        });
      }
    }

    const relayRttMs = await relayRttPromise;
    const peerConfirmedPromise = sig.waitFor("peer_confirmed", 20_000);
    const controlSegmentBytes = controlStreamSegmentBytesFor(
      sig.maxMessageBytes,
      options.controlStreamSegmentBytes,
    );
    // Unbounded: the target may be hashing an existing multi-GB directory before it answers
    const haveBlobsAssembler = new HaveBlobsStreamAssembler();
    const targetBlobsReader = readControlStream({
      sig,
      stream: "have_blobs",
      controlKey: keys.controlKey,
      sessionId,
      onRecord: (record) => haveBlobsAssembler.acceptRecord(record),
    });
    targetBlobsReader.done.catch(() => {});

    sig.send({
      type: "pake_confirm",
      confirmMacHex: myConfirmMacHex,
      hostFingerprint,
      candidates: udpPrep ? udpPrep.candidates : [],
      relayRttMs,
      natMapping: udpPrep?.natMapping,
      protocolVersion: BEAMSYNC_PROTOCOL_VERSION,
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
    assertPeerProtocolVersion(peerConfirmed.peerProtocolVersion);

    // Direct-path discovery starts the moment both peers are authenticated and runs in the
    // background, concurrently with the workspace scan and (later) with Edge Relay streaming:
    // same-host IPC -> Happy Eyeballs TCP -> UDP hole punch.
    const relayMayCarryStart =
      !options.disableEdgeRelay &&
      !options.disableOptimisticRelay &&
      Boolean(peerConfirmed.selectedEdgeRelay);
    if (!options.forceTier) {
      const localUdpPrep = udpPrep;
      directAttemptPromise = (async (): Promise<DirectPathResult> => {
        try {
          if (options.simulateDirectReadyDelayMs) {
            await new Promise((r) => setTimeout(r, options.simulateDirectReadyDelayMs));
          }
          if (directAbort.signal.aborted) return null;

          if (peerConfirmed.sameHostMatch && !options.disableLocalIpc) {
            const sock = await tryConnectCandidates(
              peerConfirmed.peerCandidates.filter(
                (c) => c.kind === "unix_socket" || c.kind === "loopback_tcp",
              ),
              keys.transportKey,
              sessionId,
            );
            if (sock) return { kind: "local_ipc", sock };
          }
          if (options.disableP2p || directAbort.signal.aborted) return null;

          if (!options.disableP2pTcp) {
            const sock = await tryConnectCandidates(
              peerConfirmed.peerCandidates.filter((c) => c.kind === "lan_tcp"),
              keys.transportKey,
              sessionId,
            );
            if (sock) return { kind: "tcp", sock };
          }

          // Skip a futile punch when BOTH peers are behind unpredicted Symmetric NAT.
          const bothUnpredictedSymmetricNat =
            localUdpPrep?.natMapping === "symmetric" &&
            !localUdpPrep.hasSequentialPrediction &&
            peerConfirmed.peerNatMapping === "symmetric";
          if (
            localUdpPrep &&
            !bothUnpredictedSymmetricNat &&
            !directAbort.signal.aborted &&
            peerConfirmed.peerCandidates.some((c) => c.kind === "udp_punch")
          ) {
            const chan = await establishUdpHolePunch({
              socket: localUdpPrep.socket,
              transportKey: keys.transportKey,
              sessionId,
              peerUdpCandidates: peerConfirmed.peerCandidates,
              // With a relay carrying the first packs the punch can keep trying far longer
              // without delaying the transfer, which rescues slow or lossy NAT traversal.
              timeoutMs: relayMayCarryStart ? 12_000 : 1500,
              signal: directAbort.signal,
            });
            if (!options.disableUdpMtuProbe) {
              await probeUdpPathPayloadSize(chan).catch(() => {});
            }
            return { kind: "udp", chan };
          }
        } catch {
          // No direct path; relay / R2 tiers take over
        }
        return null;
      })();
    }

    // The manifest does not depend on what the target already has, so it is sealed and sent
    // as soon as the scan is done, while the target may still be hashing its existing tree.
    const manifestSentPromise = sourceScanPromise.then(async (scan) => {
      options.onProgress?.({
        phase: "manifest_sending",
        detail: `entries=${scan.manifest.entries.length}`,
      });
      const stats = await writeControlStream({
        sig,
        stream: "manifest",
        controlKey: keys.controlKey,
        sessionId,
        segmentBytes: controlSegmentBytes,
        windowSegments: options.controlStreamWindowSegments,
        records: manifestStreamRecords(
          scan.manifest,
          scan.rootTreeDigest,
          scan.ignoreSpec.layers.length > 0 ? scan.ignoreSpec : undefined,
        ),
      });
      options.onProgress?.({
        phase: "manifest_sent",
        detail: `entries=${scan.manifest.entries.length} segments=${stats.segments} sealed=${stats.sealedBytes} B`,
      });
      return stats;
    });
    manifestSentPromise.catch(() => {});

    const [sourceScan] = await Promise.all([sourceScanPromise, targetBlobsReader.done]);

    const targetKnownSet = haveBlobsAssembler.finish();
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
    let pendingDirectUpgrade: Promise<DirectPathResult> | null = null;
    let upgradedToDirect = false;
    let packsViaEdgeRelay = 0;
    let packsViaDirect = 0;
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
          if (!options.disableUdpMtuProbe) {
            await probeUdpPathPayloadSize(udpChan).catch(() => {});
          }
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
      // Automatic negotiation. Direct attempts have been racing in the background since
      // `peer_confirmed`, so on LAN / same-host they are normally settled by now.
      const relayEligible = Boolean(
        !options.disableEdgeRelay &&
          peerConfirmed.selectedEdgeRelay &&
          (options.preferEdgeRelay || missingBytesEstimate <= edgeRelayMaxBytes),
      );
      const optimisticRelay = relayEligible && !options.disableOptimisticRelay;
      const direct = await settleWithin(
        directAttemptPromise ?? Promise.resolve(null),
        optimisticRelay ? (options.optimisticRelayGraceMs ?? 250) : 2600,
      );

      if (direct.settled && direct.value) {
        // 1. Same-host LOCAL_IPC / 2. P2P_DIRECT (TCP or punched UDP)
        if (direct.value.kind === "udp") {
          udpChan = direct.value.chan;
          selectedTier = "P2P_DIRECT";
        } else {
          directSock = direct.value.sock;
          selectedTier = direct.value.kind === "local_ipc" ? "LOCAL_IPC" : "P2P_DIRECT";
        }
      } else if (relayEligible) {
        // 3. EDGE_RELAY now; keep probing and hot-upgrade to P2P at a pack boundary
        selectedTier = "EDGE_RELAY";
        selectedEdgeRelayRegion = peerConfirmed.selectedEdgeRelay!.region;
        if (!direct.settled && optimisticRelay) {
          pendingDirectUpgrade = directAttemptPromise;
        } else {
          directAbort.abort();
        }
      } else {
        // 4. Micro-delta STREAM_RELAY vs 5. Bulk CAS R2_PIPELINE
        directAbort.abort();
        selectedTier =
          missingBytesEstimate <= relayThreshold ? "STREAM_RELAY" : "R2_PIPELINE";
      }
    }

    options.onProgress?.({
      phase: "streaming",
      tier: selectedTier,
      detail: `missing=${missingHashes.length} blobs (${missingBytesEstimate} B)${selectedEdgeRelayRegion ? ` relay=${selectedEdgeRelayRegion}` : ""}`,
    });

    // Unbounded: streaming plus target materialization of a multi-GB workspace takes as long
    // as it takes. The no-op catch keeps an early session error from surfacing as an unhandled
    // rejection while packs are still being sent; it is rethrown when awaited below.
    const committedPromise = sig.waitFor("session_committed", 0);
    committedPromise.catch(() => {});

    // The plan follows the last manifest segment on the same ordered channel, so the target
    // always holds the complete manifest by the time it sees the plan.
    const manifestStats = await manifestSentPromise;
    sig.send({
      type: "source_transfer_plan",
      manifestEntryCount: sourceScan.manifest.entries.length,
      rootTreeDigest: sourceScan.rootTreeDigest,
      missingBlobCount: missingHashes.length,
      missingBytesEstimate,
      selectedTier,
      selectedEdgeRelayRegion,
      directUpgradePending: pendingDirectUpgrade ? true : undefined,
      directChannel:
        selectedTier === "P2P_DIRECT" ? (udpChan ? "udp" : "tcp") : undefined,
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
      Math.max(1, Math.floor(options.maxBlobsPerPack ?? DEFAULT_MAX_BLOBS_PER_PACK)),
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
          packsViaDirect++;
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

      // Hot upgrade: once the background direct attempt succeeds, offer it to the target.
      // Only after the target confirms it holds the same channel does the relay stream
      // hand off at the next pack boundary.
      let confirmedUpgrade: DirectPathResult = null;
      let relayPhaseOver = false;
      let signalRelayPhaseOver: () => void = () => {};
      const relayPhaseOverPromise = new Promise<void>((r) => {
        signalRelayPhaseOver = r;
      });
      const upgradeTask: Promise<void> = pendingDirectUpgrade
        ? pendingDirectUpgrade
            .then(async (res) => {
              if (!res) return;
              if (relayPhaseOver) {
                destroyDirectPath(res);
                return;
              }
              const answerPromise = sig
                .waitFor("direct_upgrade_answer", 5000)
                .catch(() => null);
              sig.send({
                type: "direct_upgrade_offer",
                channel: res.kind === "udp" ? "udp" : "tcp",
              });
              const answer = await Promise.race([
                answerPromise,
                relayPhaseOverPromise.then(() => null),
              ]);
              if (answer?.accepted) {
                confirmedUpgrade = res;
              } else {
                destroyDirectPath(res);
              }
            })
            .catch(() => {})
        : Promise.resolve();

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
          shouldHandOff: () => confirmedUpgrade !== null,
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
        packsViaEdgeRelay = ackedPackIds.length;
        if (!streamRes.interrupted && !streamRes.handedOff) {
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

      relayPhaseOver = true;
      signalRelayPhaseOver();
      if (!confirmedUpgrade) {
        // Nothing left for a late direct path to carry; stop probing instead of waiting for it
        directAbort.abort();
      }
      await settleWithin(upgradeTask, 150);
      const upgradePath = confirmedUpgrade as DirectPathResult;

      if (upgradePath) {
        // The target is already reading this channel. Move every not-yet-acknowledged batch
        // onto it; if the relay happened to finish everything, just end the stream cleanly.
        if (upgradePath.kind === "udp") udpChan = upgradePath.chan;
        else directSock = upgradePath.sock;

        if (unackedBatches.length > 0) {
          upgradedToDirect = true;
          selectedTier = "P2P_DIRECT";
          options.onProgress?.({
            phase: "upgraded_to_direct",
            tier: "P2P_DIRECT",
            detail: `channel=${upgradePath.kind} remainingPacks=${unackedBatches.length}`,
          });
        }
        let failedAt = -1;
        for (let i = 0; i < unackedBatches.length; i++) {
          try {
            const blobs = await readBlobBatch(unackedBatches[i], sourceScan.blobSlices);
            const pack = await encodePack(blobs, {
              compression: "zstd",
              encryption: "chacha20-poly1305",
              packKey: keys.packKey,
              zstdCompressFn: zstdCompress,
            });
            await paceBytes?.(pack.wireBytes.length);
            if (upgradePath.kind === "udp") {
              await sendPackOverUdp(upgradePath.chan, i, pack.packId, pack.wireBytes);
            } else {
              await sendPackOverSocket(upgradePath.sock, pack.packId, pack.wireBytes);
            }
            requiredPackIds.push(pack.packId);
            ackedPackIds.push(pack.packId);
            packsViaDirect++;
            wireBytesSent += pack.wireBytes.length;
          } catch {
            failedAt = i;
            break;
          }
        }
        if (failedAt === -1) {
          try {
            if (upgradePath.kind === "udp") await finishUdpStream(upgradePath.chan);
            else await finishSocketStream(upgradePath.sock);
          } catch {
            // Every pack is already acknowledged; a failed FIN is harmless
          }
          unackedBatches = [];
        } else {
          unackedBatches = unackedBatches.slice(failedAt);
        }
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
          reason: upgradePath
            ? "Direct path dropped after hot upgrade; switching remaining packs to R2_PIPELINE"
            : "Edge Relay stream interrupted; switching remaining packs to R2_PIPELINE",
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
      upgradedToDirect,
      packsViaEdgeRelay,
      packsViaDirect,
      signalingReconnects: sig.reconnectCount,
      manifestEntries: sourceScan.manifest.entries.length,
      manifestSegments: manifestStats.segments,
      manifestSealedBytes: manifestStats.sealedBytes,
      udpChunkPayloadBytes: udpChan?.chunkPayloadBytes,
      ignoredPaths: sourceScan.ignoredPathCount,
      ignoreFilesLoaded: sourceScan.ignoreFilesLoaded,
    };
  } finally {
    scanAbort.abort();
    directAbort.abort();
    // Release a direct path that finished connecting but was never adopted
    void directAttemptPromise?.then(destroyDirectPath, () => {});
    edgeChan?.destroy();
    directSock?.destroy();
    udpChan?.destroy();
    await udpPrep?.close();
    sig.close();
    await scanSettled;
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
  const sig = await SignalingClient.connect(wsUrl, {
    reconnectBudgetMs: options.signalingReconnectBudgetMs,
    maxMessageBytes: options.maxSignalingMessageBytes,
  });
  sig.onReconnect = (n) =>
    options.onProgress?.({ phase: "signaling_resumed", detail: `reconnects=${n}` });
  const punchAbort = new AbortController();
  let upgradedToDirect = false;
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

  // A session that ends early must not leave a scan hashing the old tree in the background
  const scanAbort = new AbortController();
  let scanSettled: Promise<unknown> = Promise.resolve();

  try {
    // Scan existing target directory and probe Edge Relay RTTs in parallel
    const existingTargetScanPromise = scanWorkspace(options.targetDir, {
      signal: scanAbort.signal,
      cacheDir: options.cacheDir,
      smallFileThresholdBytes: options.smallFileThresholdBytes,
      cdcOptions: options.cdcOptions,
    }).catch(() => null);
    scanSettled = existingTargetScanPromise;
    const relayRttPromise = options.disableEdgeRelay
      ? Promise.resolve<Record<string, number>>({})
      : probeEdgeRelayRtts(edgeRelays, 1000);

    const pake =
      params.mode.kind === "pake"
        ? new PakeHandshake("target", sessionId, params.mode.secretPhrase)
        : null;

    const peerJoinedPromise = sig.waitFor("peer_joined", PEER_JOIN_WAIT_MS);
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
      includeLoopbackTcpForTest: options.allowLoopbackTcpForTest,
      rejectedAttemptCounter: options.rejectedDirectAttemptCounter,
    });

    if (enableUdp) {
      udpPrep = await prepareUdpPunchEndpoint(
        allStunServers,
        Boolean(options.allowLoopbackUdpForTest),
        { disabled: options.disablePortMapping, gateway: options.portMappingGateway },
      );
      if (udpPrep.portMapping) {
        options.onProgress?.({
          phase: "port_mapped",
          detail: `udp ${udpPrep.portMapping.externalIp}:${udpPrep.portMapping.externalPort} via ${udpPrep.portMapping.gateway.address}`,
        });
      }
    }

    const relayRttMs = await relayRttPromise;
    const peerConfirmedPromise = sig.waitFor("peer_confirmed", 20_000);
    // Listening from the start: the source may send its manifest while this side is still
    // hashing the existing target tree.
    const manifestAssembler = new ManifestStreamAssembler();
    const manifestReader = readControlStream({
      sig,
      stream: "manifest",
      controlKey: keys.controlKey,
      sessionId,
      onRecord: (record) => manifestAssembler.acceptRecord(record),
    });
    manifestReader.done.catch(() => {});
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
      protocolVersion: BEAMSYNC_PROTOCOL_VERSION,
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
    assertPeerProtocolVersion(peerConfirmed.peerProtocolVersion);

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
        // Long-lived background punch: the source may still be scanning a large workspace,
        // or may already be streaming over an Edge Relay while NAT traversal keeps trying.
        timeoutMs: 20_000,
        signal: punchAbort.signal,
      }).catch(() => null);
    }

    const existingScan = await existingTargetScanPromise;
    const existingBlobs =
      existingScan?.blobSlices ?? new Map<string, BlobDiskSlice>();

    // Subscribe to transfer plan, R2 pack notifications, relay frames, and commit grant BEFORE writing the have_blobs stream
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

    // Unbounded: the source may still be scanning tens of thousands of files
    const planPromise = sig.waitFor("source_transfer_plan", 0);
    planPromise.catch(() => {});
    const haveBlobsStats = await writeControlStream({
      sig,
      stream: "have_blobs",
      controlKey: keys.controlKey,
      sessionId,
      segmentBytes: controlStreamSegmentBytesFor(
        sig.maxMessageBytes,
        options.controlStreamSegmentBytes,
      ),
      windowSegments: options.controlStreamWindowSegments,
      records: haveBlobsStreamRecords(existingBlobs.keys(), existingBlobs.size),
    });
    options.onProgress?.({
      phase: "have_blobs_sent",
      detail: `blobs=${existingBlobs.size} segments=${haveBlobsStats.segments} sealed=${haveBlobsStats.sealedBytes} B`,
    });

    const [plan, manifestStats] = await Promise.all([
      planPromise.then((p) => {
        // The plan is sent after the last manifest segment on the same ordered channel
        manifestReader.expectComplete();
        return p;
      }),
      manifestReader.done,
    ]);
    const { header: manifestHeader, manifest } = manifestAssembler.finish();
    if (
      manifestHeader.rootTreeDigest !== plan.rootTreeDigest ||
      manifestHeader.entryCount !== plan.manifestEntryCount
    ) {
      throw new Error(
        "MANIFEST_INTEGRITY: the transfer plan does not match the manifest the source sealed",
      );
    }
    if (computeRootTreeDigest(manifest) !== manifestHeader.rootTreeDigest) {
      throw new Error(
        "MANIFEST_INTEGRITY: the received manifest does not hash to the digest the source sealed",
      );
    }
    options.onProgress?.({
      phase: "manifest_received",
      detail: `entries=${manifest.entries.length} segments=${manifestStats.segments} sealed=${manifestStats.sealedBytes} B`,
    });

    let selectedTier = plan.selectedTier;
    materializer = new AtomicWorkspaceMaterializer({
      targetDir: options.targetDir,
      sessionId,
      manifest,
      rootTreeDigest: manifestHeader.rootTreeDigest,
      existingBlobs,
      ignoreSpec: manifestHeader.ignoreSpec,
      deleteIgnored: options.deleteIgnored,
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
        // The source states which direct channel it writes to, so a target that holds both
        // an accepted TCP socket and a punched UDP channel never reads the wrong one.
        let punched: UdpHolePunchChannel | null = null;
        if (plan.directChannel !== "tcp" && pendingUdpPunchPromise) {
          const res = await settleWithin(
            pendingUdpPunchPromise,
            plan.directChannel === "udp" ? 6000 : 3500,
          );
          punched = res.settled ? res.value : null;
          if (plan.directChannel === "udp" && !punched) {
            throw new Error("Source selected UDP but the target punch did not complete");
          }
        }
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
      // Packs may arrive over the Edge Relay and, after a hot upgrade, over a direct channel.
      // Both readers run concurrently; `applyPackWireBytes` is idempotent per pack id and the
      // Coordinator's bilateral receipts decide when the transfer is complete.
      let relayFailure: Error | null = null;
      let directReaderActive = false;
      let directFailedAtMs: number | null = null;
      let directUpgradeChannel: FramedSocketChannel | null = null;

      const unsubUpgrade = sig.subscribe((msg) => {
        if (msg.type !== "direct_upgrade_offer" || directReaderActive) return;
        const offered = msg.channel;
        void (async () => {
          try {
            let reader: Promise<void>;
            if (offered === "udp") {
              const res = pendingUdpPunchPromise
                ? await settleWithin(pendingUdpPunchPromise, 4000)
                : null;
              const punched = res && res.settled ? res.value : null;
              if (!punched) throw new Error("UDP punch not established on target");
              udpChan = punched;
              reader = receivePacksFromUdp(punched, applyPackWireBytes);
            } else {
              const { channel } = await directListeners!.waitForAuthenticatedChannel(4000);
              directUpgradeChannel = channel;
              reader = receivePacksFromSocket(channel, applyPackWireBytes);
            }
            // Reader is attached before the answer leaves, so no direct pack can be missed
            directReaderActive = true;
            upgradedToDirect = true;
            reader.catch(() => {
              directFailedAtMs = Date.now();
            });
            sig.send({ type: "direct_upgrade_answer", channel: offered, accepted: true });
            options.onProgress?.({
              phase: "upgraded_to_direct",
              tier: "P2P_DIRECT",
              detail: `channel=${offered}`,
            });
          } catch {
            sig.send({ type: "direct_upgrade_answer", channel: offered, accepted: false });
          }
        })();
      });

      const relayTask = (async () => {
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
        await receivePacksFromEdgeRelay(edgeChan, applyPackWireBytes);
        edgeChan.destroy();
      })().catch((err) => {
        relayFailure = err instanceof Error ? err : new Error(String(err));
      });

      // A source-side failure is announced via `fallback_to_r2_activated` immediately. The
      // target-initiated fallback below is only a backstop, so a direct reader that ends
      // abruptly gets a short grace period for the commit grant to arrive first.
      const DIRECT_FAILURE_GRACE_MS = 2000;
      await waitUntil(
        () =>
          grantCommitReceived ||
          Boolean(sessionFatalError) ||
          fallbackToR2Triggered ||
          (relayFailure !== null && !directReaderActive) ||
          (directFailedAtMs !== null &&
            Date.now() - directFailedAtMs >= DIRECT_FAILURE_GRACE_MS),
      );
      unsubUpgrade();
      void relayTask;
      if (sessionFatalError) throw sessionFatalError;

      const relayErr = relayFailure as Error | null;
      if (
        relayErr &&
        options.forceTier === "EDGE_RELAY" &&
        relayErr.message.includes("EDGE_RELAY_CERT_PIN_MISMATCH")
      ) {
        throw relayErr;
      }

      if (!grantCommitReceived && !fallbackToR2Triggered) {
        sig.send({
          type: "fallback_to_r2",
          reason: directReaderActive
            ? "Target direct reader interrupted after hot upgrade"
            : "Target Edge Relay reader interrupted",
          targetReceivedPackIds: Array.from(appliedPackIds),
        });
        fallbackToR2Triggered = true;
      }
      if (fallbackToR2Triggered) {
        selectedTier = "R2_PIPELINE";
        await runR2ConcurrentDownloadUntilGrant();
      } else if (upgradedToDirect) {
        selectedTier = "P2P_DIRECT";
      }
      (directUpgradeChannel as FramedSocketChannel | null)?.destroy();
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

    const { committedFiles, preservedIgnoredPaths, preserveFailures, retainedBackupDir } =
      await materializer.commit();
    if (preserveFailures.length > 0) {
      options.onProgress?.({
        phase: "preserve_ignored_failed",
        tier: selectedTier,
        detail: `${preserveFailures.length} ignored path(s) could not be carried over; previous tree kept at ${retainedBackupDir}`,
      });
    }
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
      upgradedToDirect,
      signalingReconnects: sig.reconnectCount,
      manifestEntries: manifest.entries.length,
      manifestSegments: manifestStats.segments,
      packsApplied: appliedPackIds.size,
      firstPackAppliedAtMs,
      durationMs: Date.now() - startedAt,
      preservedIgnoredPaths,
      preserveFailures,
      retainedBackupDir,
    };
  } catch (err) {
    await materializer?.abort();
    throw err;
  } finally {
    scanAbort.abort();
    punchAbort.abort();
    edgeChan?.destroy();
    udpChan?.destroy();
    await udpPrep?.close();
    await directListeners?.closeAll();
    sig.close();
    await scanSettled;
  }
}

function buildMissingBlobBatches(
  missingHashes: string[],
  blobSlices: ReadonlyMap<string, BlobDiskSlice>,
  targetPackBytes: number,
  maxBlobsPerPack: number = DEFAULT_MAX_BLOBS_PER_PACK,
): string[][] {
  const batches: string[][] = [];
  let current: string[] = [];
  let currentBytes = 0;

  for (const hash of missingHashes) {
    const len = blobSlices.get(hash)?.length ?? 0;
    // The blob cap keeps a tree of tiny files from becoming one pack whose index dwarfs its
    // data and whose loss would mean resending everything.
    if (
      current.length > 0 &&
      (currentBytes + len > targetPackBytes || current.length >= maxBlobsPerPack)
    ) {
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
  maxAttempts = 4,
): Promise<void> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await httpRequestBytes("PUT", url, { body: bytes });
      if (res.status < 200 || res.status >= 300) {
        throw new Error(`PUT pack failed with HTTP ${res.status}`);
      }
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
  maxAttempts = 4,
): Promise<Uint8Array> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await httpRequestBytes("GET", url);
      if (res.status < 200 || res.status >= 300) {
        throw new Error(`GET pack failed with HTTP ${res.status}`);
      }
      return new Uint8Array(res.body.buffer, res.body.byteOffset, res.body.byteLength);
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
  const res = await httpRequestBytes("POST", url, {
    headers,
    body: Buffer.from(JSON.stringify(body), "utf8"),
  });
  const text = res.body.toString("utf8");
  if (res.status === 401) {
    throw new Error(
      `HTTP 401 from ${url}: ${text} — this server requires an API token ` +
        (bearerToken
          ? "and rejected the one provided"
          : "(pass --api-token or set BEAMSYNC_API_TOKEN)"),
    );
  }
  if (res.status < 200 || res.status >= 300) {
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
  gatewayPortMapping: { protocol: string; gateway: string; externalEndpoint: string } | null;
  proxy: string | null;
  directInterfaces: DiscoveredDirectAddress[];
  edgeRelayRttMs: Record<string, number>;
  zstdSelfTestOk: boolean;
}> {
  const baseHttp = serverUrl.replace(/\/+$/, "");
  const healthRes = await httpRequestBytes("GET", `${baseHttp}/healthz`);
  if (healthRes.status < 200 || healthRes.status >= 300) {
    throw new Error(`Server health check failed with HTTP ${healthRes.status}`);
  }
  const serverHealth = JSON.parse(healthRes.body.toString("utf8")) as Record<
    string,
    unknown
  >;
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
  const gatewayPortMapping = prep.portMapping
    ? {
        protocol: "nat-pmp",
        gateway: prep.portMapping.gateway.address,
        externalEndpoint: `${prep.portMapping.externalIp}:${prep.portMapping.externalPort}`,
      }
    : null;
  const udpCand = prep.candidates.find(
    (c) =>
      c.kind === "udp_punch" &&
      !(prep.portMapping && c.port === prep.portMapping.externalPort && c.address === prep.portMapping.externalIp),
  );
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
    gatewayPortMapping,
    proxy: resolveProxyForUrl(baseHttp)?.display ?? null,
    directInterfaces: discoverDirectIpAddresses(),
    edgeRelayRttMs,
    zstdSelfTestOk,
  };
}
