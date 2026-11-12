import {
  buildSignedEdgeRelayWsUrl,
  bytesToHex,
  evaluateSessionEquilibrium,
  mintEdgeRelayTicket,
  randomBytes,
  type AllocatedUploadSlot,
  type ClientToServerWsMessage,
  type CreateManagedLeaseResponse,
  type CreatePairingResponse,
  type EdgeRelayNodeInfo,
  type EndpointCandidate,
  type JoinPairingResponse,
  type NatMappingBehavior,
  type PackReceiptRow,
  type ServerToClientWsMessage,
  type SessionMode,
  type SessionState,
  type SignedEdgeRelayAllocation,
  type TransportTier,
} from "@beamsync/protocol";
import type { PackStorageDriver } from "./storageDriver.js";

export interface PeerSocketHandle {
  send(jsonMessage: string): void;
  close(code?: number, reason?: string): void;
}

export interface CasPackRecord {
  scopeNamespace: string;
  packId: string;
  storageKey: string;
  sizeBytes: number;
  blobCount: number;
  state: "uploading" | "ready";
  lastReferencedAt: number;
  expiresAt: number;
}

export interface CoordinatorPersistenceHook {
  loadCasPacks(): Promise<CasPackRecord[]> | CasPackRecord[];
  upsertCasPack(record: CasPackRecord): Promise<void> | void;
  deleteCasPack(scopeNamespace: string, packId: string): Promise<void> | void;
}

interface PeerRuntimeState {
  token: string;
  socket: PeerSocketHandle | null;
  helloReceived: boolean;
  pakePublicHex?: string;
  confirmMacHex?: string;
  hostFingerprint?: string;
  candidates: EndpointCandidate[];
  relayRttMs?: Record<string, number>;
  natMapping?: NatMappingBehavior;
}

export interface SessionRuntimeRecord {
  sessionId: string;
  generation: number;
  mode: SessionMode;
  slotCode: string | null;
  joinAttempts: number;
  scopeNamespace: string;
  selectedTier: TransportTier | null;
  state: SessionState;
  manifestFinalized: boolean;
  rootTreeDigest: string | null;
  requiredPackIds: string[];
  logicalBytes: number;
  dedupSavedBytes: number;
  expiresAt: number;
  createdAt: number;
  completedAt: number | null;
  source: PeerRuntimeState;
  target: PeerRuntimeState;
  receipts: Map<string, PackReceiptRow>;
  ephemeralStorageKeys: Set<string>;
}

export interface RegisteredEdgeRelay extends EdgeRelayNodeInfo {
  staticEntry: boolean;
  lastHeartbeatAt: number;
  expiresAt: number;
}

export interface CoordinatorEngineOptions {
  storageDriver: PackStorageDriver;
  stunServers?: string[];
  relayAuthSecret?: string;
  initialEdgeRelays?: EdgeRelayNodeInfo[];
  edgeRelayHeartbeatTtlMs?: number;
  casTtlMs?: number;
  pairingTtlMs?: number;
  sessionTtlMs?: number;
  persistence?: CoordinatorPersistenceHook;
}

const DEFAULT_CAS_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days sliding TTL
const DEFAULT_PAIRING_TTL_MS = 10 * 60 * 1000; // 10 minutes
const DEFAULT_SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
const DEFAULT_EDGE_RELAY_TTL_MS = 60 * 1000; // 60s dynamic heartbeat TTL

export class CoordinatorEngine {
  readonly storageDriver: PackStorageDriver;
  readonly stunServers: string[];
  private readonly relayAuthSecret: string;
  private readonly edgeRelayHeartbeatTtlMs: number;
  private readonly casTtlMs: number;
  private readonly pairingTtlMs: number;
  private readonly sessionTtlMs: number;
  private readonly persistence?: CoordinatorPersistenceHook;

  private slotCounter = 100;
  private readonly sessions = new Map<string, SessionRuntimeRecord>();
  private readonly pairingSlots = new Map<string, string>(); // slotCode -> sessionId
  private readonly casPacks = new Map<string, CasPackRecord>(); // `${scope}:${packId}`
  private readonly scopeCasKeys = new Map<string, string>(); // scopeNamespace -> 32B hex
  private readonly edgeRelays = new Map<string, RegisteredEdgeRelay>(); // relayId -> regional Edge Relay node

  constructor(options: CoordinatorEngineOptions) {
    this.storageDriver = options.storageDriver;
    this.stunServers = options.stunServers ?? ["stun:stun.cloudflare.com:3478"];
    this.relayAuthSecret =
      options.relayAuthSecret ?? bytesToHex(randomBytes(32));
    this.edgeRelayHeartbeatTtlMs =
      options.edgeRelayHeartbeatTtlMs ?? DEFAULT_EDGE_RELAY_TTL_MS;
    this.casTtlMs = options.casTtlMs ?? DEFAULT_CAS_TTL_MS;
    this.pairingTtlMs = options.pairingTtlMs ?? DEFAULT_PAIRING_TTL_MS;
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    this.persistence = options.persistence;

    for (const r of options.initialEdgeRelays ?? []) {
      this.edgeRelays.set(r.relayId, {
        ...r,
        staticEntry: true,
        lastHeartbeatAt: Date.now(),
        expiresAt: Number.MAX_SAFE_INTEGER,
      });
    }
  }

  async init(): Promise<void> {
    if (!this.persistence) return;
    const loaded = await this.persistence.loadCasPacks();
    const now = Date.now();
    for (const rec of loaded) {
      if (rec.expiresAt > now && rec.state === "ready") {
        this.casPacks.set(`${rec.scopeNamespace}:${rec.packId}`, rec);
      }
    }
  }

  upsertEdgeRelay(node: EdgeRelayNodeInfo, staticEntry = false): void {
    const now = Date.now();
    this.edgeRelays.set(node.relayId, {
      ...node,
      staticEntry,
      lastHeartbeatAt: now,
      expiresAt: staticEntry
        ? Number.MAX_SAFE_INTEGER
        : now + this.edgeRelayHeartbeatTtlMs,
    });
  }

  listActiveEdgeRelays(): EdgeRelayNodeInfo[] {
    const now = Date.now();
    const out: EdgeRelayNodeInfo[] = [];
    for (const [id, r] of this.edgeRelays) {
      if (!r.staticEntry && r.expiresAt < now) {
        this.edgeRelays.delete(id);
        continue;
      }
      out.push({
        relayId: r.relayId,
        region: r.region,
        httpUrl: r.httpUrl,
        wsUrl: r.wsUrl,
        stunUrl: r.stunUrl,
        certSha256: r.certSha256,
        noSni: r.noSni,
      });
    }
    return out;
  }

  private getEffectiveStunServers(): string[] {
    const seen = new Set<string>();
    const list: string[] = [];
    for (const r of this.listActiveEdgeRelays()) {
      if (r.stunUrl && !seen.has(r.stunUrl)) {
        seen.add(r.stunUrl);
        list.push(r.stunUrl);
      }
    }
    for (const s of this.stunServers) {
      if (!seen.has(s)) {
        seen.add(s);
        list.push(s);
      }
    }
    return list;
  }

  private selectOptimalEdgeRelayForSession(
    sessionId: string,
    sourceRtt?: Record<string, number>,
    targetRtt?: Record<string, number>,
  ): {
    sourceAlloc: SignedEdgeRelayAllocation;
    targetAlloc: SignedEdgeRelayAllocation;
  } | null {
    const relays = this.listActiveEdgeRelays();
    if (relays.length === 0) return null;

    // Minimum joint RTT selection across RelayMap: argmin_r (RTT_source(r) + RTT_target(r))
    let chosen = relays[0];
    let bestScore = Number.POSITIVE_INFINITY;
    for (const r of relays) {
      const s = sourceRtt?.[r.relayId];
      const t = targetRtt?.[r.relayId];
      // Penalize unreachable/unprobed relays slightly so reachable regional relays always win
      const sCost = typeof s === "number" && Number.isFinite(s) ? s : 2500;
      const tCost = typeof t === "number" && Number.isFinite(t) ? t : 2500;
      const score = sCost + tCost;
      if (score < bestScore) {
        bestScore = score;
        chosen = r;
      }
    }

    const expiresAtMs = Date.now() + this.sessionTtlMs;
    const sourceTicket = mintEdgeRelayTicket({
      authSecret: this.relayAuthSecret,
      relayId: chosen.relayId,
      sessionId,
      role: "source",
      expiresAtMs,
    });
    const targetTicket = mintEdgeRelayTicket({
      authSecret: this.relayAuthSecret,
      relayId: chosen.relayId,
      sessionId,
      role: "target",
      expiresAtMs,
    });

    return {
      sourceAlloc: {
        relayId: chosen.relayId,
        region: chosen.region,
        httpUrl: chosen.httpUrl,
        wsRelayUrl: buildSignedEdgeRelayWsUrl({
          wsBaseUrl: chosen.wsUrl,
          relayId: chosen.relayId,
          sessionId,
          role: "source",
          expiresAtMs,
          ticket: sourceTicket,
        }),
        stunUrl: chosen.stunUrl,
        certSha256: chosen.certSha256,
        noSni: chosen.noSni,
        ticket: sourceTicket,
        expiresAtMs,
      },
      targetAlloc: {
        relayId: chosen.relayId,
        region: chosen.region,
        httpUrl: chosen.httpUrl,
        wsRelayUrl: buildSignedEdgeRelayWsUrl({
          wsBaseUrl: chosen.wsUrl,
          relayId: chosen.relayId,
          sessionId,
          role: "target",
          expiresAtMs,
          ticket: targetTicket,
        }),
        stunUrl: chosen.stunUrl,
        certSha256: chosen.certSha256,
        noSni: chosen.noSni,
        ticket: targetTicket,
        expiresAtMs,
      },
    };
  }

  getStats(): {
    activeSessions: number;
    activePairingSlots: number;
    casPackCount: number;
    edgeRelayCount: number;
    edgeRelays: EdgeRelayNodeInfo[];
    storageMode: string;
    stunServers: string[];
  } {
    const activeRelays = this.listActiveEdgeRelays();
    return {
      activeSessions: this.sessions.size,
      activePairingSlots: this.pairingSlots.size,
      casPackCount: this.casPacks.size,
      edgeRelayCount: activeRelays.length,
      edgeRelays: activeRelays,
      storageMode: this.storageDriver.mode,
      stunServers: this.getEffectiveStunServers(),
    };
  }

  getSessionSnapshot(sessionId: string): SessionRuntimeRecord | undefined {
    return this.sessions.get(sessionId);
  }

  createPairingSession(params: {
    wsBaseUrl: string;
    scopeNamespace?: string;
    customSlotCode?: string;
  }): CreatePairingResponse {
    this.pruneExpired();
    const sessionId = globalThis.crypto.randomUUID();
    const slotCode =
      params.customSlotCode?.trim().toLowerCase() ||
      this.allocateNextSlotCode();

    if (this.pairingSlots.has(slotCode)) {
      throw new Error(`SLOT_IN_USE: Pairing slot "${slotCode}" is currently active`);
    }

    const sourceToken = bytesToHex(randomBytes(24));
    const targetToken = bytesToHex(randomBytes(24));
    const now = Date.now();
    const expiresAt = now + this.pairingTtlMs;
    const scopeNamespace =
      params.scopeNamespace?.trim() || `ephemeral:${sessionId}`;

    const record: SessionRuntimeRecord = {
      sessionId,
      generation: 1,
      mode: "pairing_phrase",
      slotCode,
      joinAttempts: 0,
      scopeNamespace,
      selectedTier: null,
      state: "awaiting_peer",
      manifestFinalized: false,
      rootTreeDigest: null,
      requiredPackIds: [],
      logicalBytes: 0,
      dedupSavedBytes: 0,
      expiresAt,
      createdAt: now,
      completedAt: null,
      source: {
        token: sourceToken,
        socket: null,
        helloReceived: false,
        candidates: [],
      },
      target: {
        token: targetToken,
        socket: null,
        helloReceived: false,
        candidates: [],
      },
      receipts: new Map(),
      ephemeralStorageKeys: new Set(),
    };

    this.sessions.set(sessionId, record);
    this.pairingSlots.set(slotCode, sessionId);

    return {
      sessionId,
      slotCode,
      peerToken: sourceToken,
      wsUrl: `${params.wsBaseUrl.replace(/\/+$/, "")}/v1/ws/${sessionId}`,
      stunServers: this.getEffectiveStunServers(),
      edgeRelays: this.listActiveEdgeRelays(),
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  joinPairingSession(params: {
    slotCode: string;
    wsBaseUrl: string;
  }): JoinPairingResponse {
    this.pruneExpired();
    const normalized = params.slotCode.trim().toLowerCase();
    const sessionId = this.pairingSlots.get(normalized);
    if (!sessionId) {
      throw new Error("PAIRING_NOT_FOUND: Unknown or expired pairing code");
    }
    const session = this.sessions.get(sessionId);
    if (!session || session.expiresAt < Date.now()) {
      this.pairingSlots.delete(normalized);
      throw new Error("PAIRING_EXPIRED: Pairing session has expired");
    }
    session.joinAttempts += 1;
    if (session.joinAttempts > 3) {
      this.pairingSlots.delete(normalized);
      session.state = "failed";
      throw new Error("PAIRING_LOCKED: Too many join attempts");
    }

    // Consume pairing slot once joined and extend active transfer window
    this.pairingSlots.delete(normalized);
    session.slotCode = null;
    session.expiresAt = Date.now() + this.sessionTtlMs;
    session.state = "negotiating_path";

    return {
      sessionId: session.sessionId,
      peerToken: session.target.token,
      wsUrl: `${params.wsBaseUrl.replace(/\/+$/, "")}/v1/ws/${session.sessionId}`,
      stunServers: this.getEffectiveStunServers(),
      edgeRelays: this.listActiveEdgeRelays(),
      expiresAt: new Date(session.expiresAt).toISOString(),
    };
  }

  createManagedLease(params: {
    scopeNamespace: string;
    wsBaseUrl: string;
    expiresInSeconds?: number;
  }): CreateManagedLeaseResponse {
    this.pruneExpired();
    const sessionId = globalThis.crypto.randomUUID();
    const sourceToken = bytesToHex(randomBytes(24));
    const targetToken = bytesToHex(randomBytes(24));
    const leaseSecretHex = bytesToHex(randomBytes(32));
    const scopeNamespace = params.scopeNamespace.trim() || `managed:${sessionId}`;
    let scopeCasKeyHex = this.scopeCasKeys.get(scopeNamespace);
    if (!scopeCasKeyHex) {
      scopeCasKeyHex = bytesToHex(randomBytes(32));
      this.scopeCasKeys.set(scopeNamespace, scopeCasKeyHex);
    }
    const now = Date.now();
    const ttlMs = (params.expiresInSeconds ?? 3600) * 1000;
    const expiresAt = now + ttlMs;

    const record: SessionRuntimeRecord = {
      sessionId,
      generation: 1,
      mode: "managed_lease",
      slotCode: null,
      joinAttempts: 0,
      scopeNamespace,
      selectedTier: null,
      state: "negotiating_path",
      manifestFinalized: false,
      rootTreeDigest: null,
      requiredPackIds: [],
      logicalBytes: 0,
      dedupSavedBytes: 0,
      expiresAt,
      createdAt: now,
      completedAt: null,
      source: {
        token: sourceToken,
        socket: null,
        helloReceived: false,
        candidates: [],
      },
      target: {
        token: targetToken,
        socket: null,
        helloReceived: false,
        candidates: [],
      },
      receipts: new Map(),
      ephemeralStorageKeys: new Set(),
    };

    this.sessions.set(sessionId, record);

    return {
      sessionId,
      sourceToken,
      targetToken,
      leaseSecretHex,
      scopeCasKeyHex,
      wsUrl: `${params.wsBaseUrl.replace(/\/+$/, "")}/v1/ws/${sessionId}`,
      stunServers: this.getEffectiveStunServers(),
      edgeRelays: this.listActiveEdgeRelays(),
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  detachSocket(sessionId: string, socket: PeerSocketHandle): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    if (session.source.socket === socket) {
      session.source.socket = null;
    }
    if (session.target.socket === socket) {
      session.target.socket = null;
    }
  }

  async handleWsMessage(
    sessionId: string,
    socket: PeerSocketHandle,
    rawMessage: string,
  ): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      this.sendTo(socket, {
        type: "session_error",
        code: "SESSION_NOT_FOUND",
        message: `Session ${sessionId} does not exist`,
      });
      socket.close(1008, "SESSION_NOT_FOUND");
      return;
    }

    let msg: ClientToServerWsMessage;
    try {
      msg = JSON.parse(rawMessage) as ClientToServerWsMessage;
    } catch {
      this.sendTo(socket, {
        type: "session_error",
        code: "BAD_JSON",
        message: "Invalid JSON control message",
      });
      return;
    }

    if (msg.type === "ping") {
      this.sendTo(socket, { type: "pong", ts: msg.ts });
      return;
    }

    if (msg.type === "hello") {
      const peerState = msg.role === "source" ? session.source : session.target;
      if (peerState.token !== msg.peerToken) {
        this.sendTo(socket, {
          type: "session_error",
          code: "UNAUTHORIZED_PEER",
          message: "Invalid peer token for session",
        });
        socket.close(1008, "UNAUTHORIZED_PEER");
        return;
      }

      peerState.socket = socket;
      peerState.helloReceived = true;
      if (msg.pakePublicHex) {
        peerState.pakePublicHex = msg.pakePublicHex;
      }

      // When both sides have completed hello, notify both simultaneously
      if (session.source.helloReceived && session.target.helloReceived) {
        this.sendToPeer(session.source, {
          type: "peer_joined",
          sessionId: session.sessionId,
          peerRole: "target",
          peerPakePublicHex: session.target.pakePublicHex,
        });
        this.sendToPeer(session.target, {
          type: "peer_joined",
          sessionId: session.sessionId,
          peerRole: "source",
          peerPakePublicHex: session.source.pakePublicHex,
        });

        // On reconnect during R2 streaming, immediately replay unapplied source-ready packs to target
        if (msg.role === "target") {
          await this.replayPendingAvailablePacksToTarget(session);
        }
      }
      return;
    }

    const callerRole = this.identifyRole(session, socket);
    if (!callerRole) {
      this.sendTo(socket, {
        type: "session_error",
        code: "HELLO_REQUIRED",
        message: "Send hello before session messages",
      });
      return;
    }

    switch (msg.type) {
      case "pake_confirm": {
        const me = callerRole === "source" ? session.source : session.target;
        me.confirmMacHex = msg.confirmMacHex;
        me.hostFingerprint = msg.hostFingerprint;
        me.candidates = msg.candidates;
        me.relayRttMs = msg.relayRttMs;
        me.natMapping = msg.natMapping;

        if (session.source.confirmMacHex && session.target.confirmMacHex) {
          const sameHostMatch =
            Boolean(session.source.hostFingerprint) &&
            session.source.hostFingerprint === session.target.hostFingerprint;
          session.state = "indexing_diff";

          const relayChoice = this.selectOptimalEdgeRelayForSession(
            session.sessionId,
            session.source.relayRttMs,
            session.target.relayRttMs,
          );

          this.sendToPeer(session.source, {
            type: "peer_confirmed",
            peerConfirmMacHex: session.target.confirmMacHex,
            sameHostMatch,
            peerCandidates: session.target.candidates,
            peerNatMapping: session.target.natMapping,
            selectedEdgeRelay: relayChoice?.sourceAlloc,
          });
          this.sendToPeer(session.target, {
            type: "peer_confirmed",
            peerConfirmMacHex: session.source.confirmMacHex,
            sameHostMatch,
            peerCandidates: session.source.candidates,
            peerNatMapping: session.source.natMapping,
            selectedEdgeRelay: relayChoice?.targetAlloc,
          });
        }
        break;
      }

      case "target_have_blobs": {
        if (callerRole !== "target") return;
        this.sendToPeer(session.source, {
          type: "target_have_blobs",
          knownBlobHashes: msg.knownBlobHashes,
        });
        break;
      }

      case "source_transfer_plan": {
        if (callerRole !== "source") return;
        session.selectedTier = msg.selectedTier;
        session.state = "streaming";
        this.sendToPeer(session.target, {
          type: "source_transfer_plan",
          manifest: msg.manifest,
          rootTreeDigest: msg.rootTreeDigest,
          missingBlobCount: msg.missingBlobCount,
          missingBytesEstimate: msg.missingBytesEstimate,
          selectedTier: msg.selectedTier,
          selectedEdgeRelayRegion: msg.selectedEdgeRelayRegion,
        });
        break;
      }

      case "transport_ready": {
        session.selectedTier = msg.tier;
        const other = callerRole === "source" ? session.target : session.source;
        this.sendToPeer(other, {
          type: "transport_ready",
          tier: msg.tier,
          chosenCandidate: msg.chosenCandidate,
        });
        break;
      }

      case "relay_pack_frame": {
        if (callerRole !== "source") return;
        this.sendToPeer(session.target, {
          type: "relay_pack_frame",
          packId: msg.packId,
          seq: msg.seq,
          totalChunks: msg.totalChunks,
          payloadBase64: msg.payloadBase64,
        });
        break;
      }

      case "allocate_upload_urls": {
        if (callerRole !== "source") return;
        const slots: AllocatedUploadSlot[] = [];
        const now = Date.now();
        const isPersistentCas = !session.scopeNamespace.startsWith("ephemeral:");
        const datePrefix = new Date(now).toISOString().slice(0, 10);

        for (const reqPack of msg.packs) {
          const casMapKey = `${session.scopeNamespace}:${reqPack.packId}`;
          const existingCas = isPersistentCas
            ? this.casPacks.get(casMapKey)
            : undefined;

          if (
            existingCas &&
            existingCas.state === "ready" &&
            existingCas.expiresAt > now
          ) {
            // CAS hit: refresh sliding TTL and mark source receipt immediately without upload
            existingCas.lastReferencedAt = now;
            existingCas.expiresAt = now + this.casTtlMs;
            await this.persistence?.upsertCasPack(existingCas);

            const prev = session.receipts.get(reqPack.packId);
            const row: PackReceiptRow = {
              packId: reqPack.packId,
              storageKey: existingCas.storageKey,
              sizeBytes: reqPack.sizeBytes,
              blobCount: reqPack.blobCount,
              sourceReceiptAt: prev?.sourceReceiptAt ?? now,
              targetReceiptAt: prev?.targetReceiptAt ?? null,
            };
            session.receipts.set(reqPack.packId, row);

            slots.push({
              packId: reqPack.packId,
              storageKey: existingCas.storageKey,
              putUrl: "",
              alreadyExistsInCas: true,
            });

            // Immediately push PackAvailable to target so it downloads while source continues scanning
            if (row.targetReceiptAt === null) {
              const getUrl = await this.storageDriver.mintGetUrl(
                existingCas.storageKey,
              );
              this.sendToPeer(session.target, {
                type: "pack_available",
                packId: reqPack.packId,
                sizeBytes: reqPack.sizeBytes,
                blobCount: reqPack.blobCount,
                getUrl,
              });
            }
            continue;
          }

          const storageKey = isPersistentCas
            ? `cas/v1/${encodeScopePath(session.scopeNamespace)}/packs/${reqPack.packId}`
            : `ephemeral/v1/${datePrefix}/${session.sessionId}/packs/${reqPack.packId}`;

          if (!isPersistentCas) {
            session.ephemeralStorageKeys.add(storageKey);
          }

          const putUrl = await this.storageDriver.mintPutUrl(storageKey);
          const prev = session.receipts.get(reqPack.packId);
          session.receipts.set(reqPack.packId, {
            packId: reqPack.packId,
            storageKey,
            sizeBytes: reqPack.sizeBytes,
            blobCount: reqPack.blobCount,
            sourceReceiptAt: prev?.sourceReceiptAt ?? null,
            targetReceiptAt: prev?.targetReceiptAt ?? null,
          });

          slots.push({
            packId: reqPack.packId,
            storageKey,
            putUrl,
            alreadyExistsInCas: false,
          });
        }

        this.sendToPeer(session.source, {
          type: "upload_urls_allocated",
          requestId: msg.requestId,
          slots,
        });
        this.checkAndGrantEquilibrium(session);
        break;
      }

      case "report_pack_source_receipt": {
        if (callerRole !== "source") return;
        const now = Date.now();
        const existing = session.receipts.get(msg.packId);
        const isPersistentCas = !session.scopeNamespace.startsWith("ephemeral:");
        const datePrefix = new Date(now).toISOString().slice(0, 10);
        const storageKey =
          existing?.storageKey ??
          (isPersistentCas
            ? `cas/v1/${encodeScopePath(session.scopeNamespace)}/packs/${msg.packId}`
            : `ephemeral/v1/${datePrefix}/${session.sessionId}/packs/${msg.packId}`);

        const updated: PackReceiptRow = {
          packId: msg.packId,
          storageKey,
          sizeBytes: msg.sizeBytes,
          blobCount: msg.blobCount,
          sourceReceiptAt: existing?.sourceReceiptAt ?? now,
          targetReceiptAt: existing?.targetReceiptAt ?? null,
        };
        session.receipts.set(msg.packId, updated);

        if (isPersistentCas && storageKey) {
          const casRecord: CasPackRecord = {
            scopeNamespace: session.scopeNamespace,
            packId: msg.packId,
            storageKey,
            sizeBytes: msg.sizeBytes,
            blobCount: msg.blobCount,
            state: "ready",
            lastReferencedAt: now,
            expiresAt: now + this.casTtlMs,
          };
          this.casPacks.set(
            `${session.scopeNamespace}:${msg.packId}`,
            casRecord,
          );
          await this.persistence?.upsertCasPack(casRecord);
        }

        // If on R2_PIPELINE and target hasn't applied this pack yet, immediately push presigned GET URL
        if (
          session.selectedTier === "R2_PIPELINE" &&
          updated.targetReceiptAt === null &&
          storageKey
        ) {
          const getUrl = await this.storageDriver.mintGetUrl(storageKey);
          this.sendToPeer(session.target, {
            type: "pack_available",
            packId: msg.packId,
            sizeBytes: msg.sizeBytes,
            blobCount: msg.blobCount,
            getUrl,
          });
        }

        this.checkAndGrantEquilibrium(session);
        break;
      }

      case "report_pack_target_receipt": {
        if (callerRole !== "target") return;
        const now = Date.now();
        const existing = session.receipts.get(msg.packId);
        session.receipts.set(msg.packId, {
          packId: msg.packId,
          storageKey: existing?.storageKey ?? null,
          sizeBytes: existing?.sizeBytes ?? 0,
          blobCount: existing?.blobCount ?? 0,
          // Direct/IPC/Relay paths implicitly prove source sent the pack when target verifies its digest
          sourceReceiptAt:
            existing?.sourceReceiptAt ??
            (session.selectedTier !== "R2_PIPELINE" ? now : null),
          targetReceiptAt: existing?.targetReceiptAt ?? now,
        });

        let appliedCount = 0;
        for (const r of session.receipts.values()) {
          if (r.targetReceiptAt !== null) appliedCount++;
        }

        this.sendToPeer(session.source, {
          type: "pack_target_acknowledged",
          packId: msg.packId,
          targetAppliedCount: appliedCount,
          requiredPackCount: session.requiredPackIds.length,
        });

        this.checkAndGrantEquilibrium(session);
        break;
      }

      case "fallback_to_r2": {
        const now = Date.now();
        session.selectedTier = "R2_PIPELINE";
        for (const completedPackId of msg.targetReceivedPackIds) {
          const prev = session.receipts.get(completedPackId);
          session.receipts.set(completedPackId, {
            packId: completedPackId,
            storageKey: prev?.storageKey ?? null,
            sizeBytes: prev?.sizeBytes ?? 0,
            blobCount: prev?.blobCount ?? 0,
            sourceReceiptAt: prev?.sourceReceiptAt ?? now,
            targetReceiptAt: prev?.targetReceiptAt ?? now,
          });
        }

        const alreadyCompletedPackIds = Array.from(session.receipts.values())
          .filter((r) => r.targetReceiptAt !== null)
          .map((r) => r.packId);

        const event: ServerToClientWsMessage = {
          type: "fallback_to_r2_activated",
          reason: msg.reason,
          alreadyCompletedPackIds,
        };
        this.sendToPeer(session.source, event);
        this.sendToPeer(session.target, event);
        this.checkAndGrantEquilibrium(session);
        break;
      }

      case "finalize_source_manifest": {
        if (callerRole !== "source") return;
        session.manifestFinalized = true;
        session.rootTreeDigest = msg.rootTreeDigest;
        session.requiredPackIds = msg.requiredPackIds;
        session.logicalBytes = msg.logicalBytes;
        session.dedupSavedBytes = msg.dedupSavedBytes;

        // For non-R2 direct streaming tiers, mark sourceReceiptAt on required packs if target already acked
        if (session.selectedTier !== "R2_PIPELINE") {
          const now = Date.now();
          for (const pid of msg.requiredPackIds) {
            const existing = session.receipts.get(pid);
            session.receipts.set(pid, {
              packId: pid,
              storageKey: existing?.storageKey ?? null,
              sizeBytes: existing?.sizeBytes ?? 0,
              blobCount: existing?.blobCount ?? 0,
              sourceReceiptAt: existing?.sourceReceiptAt ?? now,
              targetReceiptAt: existing?.targetReceiptAt ?? null,
            });
          }
        }

        this.checkAndGrantEquilibrium(session);
        break;
      }

      case "report_target_committed": {
        if (callerRole !== "target") return;
        if (
          session.rootTreeDigest &&
          msg.rootTreeDigest !== session.rootTreeDigest
        ) {
          this.sendToPeer(session.target, {
            type: "session_error",
            code: "COMMIT_DIGEST_MISMATCH",
            message: "Target committed tree digest does not match source manifest",
          });
          return;
        }
        session.state = "committed";
        session.completedAt = Date.now();

        const doneMsg: ServerToClientWsMessage = {
          type: "session_committed",
          sessionId: session.sessionId,
          rootTreeDigest: msg.rootTreeDigest,
          committedFiles: msg.committedFiles,
        };
        this.sendToPeer(session.source, doneMsg);
        this.sendToPeer(session.target, doneMsg);

        // Clean up ephemeral R2 packs asynchronously once committed
        if (session.ephemeralStorageKeys.size > 0 && this.storageDriver.deleteObjects) {
          const keys = Array.from(session.ephemeralStorageKeys);
          session.ephemeralStorageKeys.clear();
          void this.storageDriver.deleteObjects(keys);
        }
        break;
      }
    }
  }

  async runGarbageCollection(now = Date.now()): Promise<{
    prunedSessions: number;
    prunedCasPacks: number;
  }> {
    let prunedSessions = 0;
    const objectsToDelete: string[] = [];

    for (const [id, session] of this.sessions) {
      if (session.expiresAt < now) {
        if (session.slotCode) {
          this.pairingSlots.delete(session.slotCode);
        }
        for (const key of session.ephemeralStorageKeys) {
          objectsToDelete.push(key);
        }
        this.sessions.delete(id);
        prunedSessions++;
      }
    }

    let prunedCasPacks = 0;
    for (const [mapKey, cas] of this.casPacks) {
      if (cas.expiresAt < now) {
        objectsToDelete.push(cas.storageKey);
        this.casPacks.delete(mapKey);
        await this.persistence?.deleteCasPack(cas.scopeNamespace, cas.packId);
        prunedCasPacks++;
      }
    }

    if (objectsToDelete.length > 0 && this.storageDriver.deleteObjects) {
      await this.storageDriver.deleteObjects(objectsToDelete);
    }

    return { prunedSessions, prunedCasPacks };
  }

  private checkAndGrantEquilibrium(session: SessionRuntimeRecord): void {
    if (
      session.state === "equilibrium_reached" ||
      session.state === "committed"
    ) {
      return;
    }

    const evalResult = evaluateSessionEquilibrium({
      manifestFinalized: session.manifestFinalized,
      rootTreeDigest: session.rootTreeDigest,
      requiredPackIds: session.requiredPackIds,
      receipts: session.receipts,
    });

    if (evalResult.equilibriumReached && session.rootTreeDigest) {
      session.state = "equilibrium_reached";
      this.sendToPeer(session.target, {
        type: "grant_atomic_commit",
        sessionId: session.sessionId,
        rootTreeDigest: session.rootTreeDigest,
        requiredPackCount: evalResult.requiredPackCount,
      });
    }
  }

  private async replayPendingAvailablePacksToTarget(
    session: SessionRuntimeRecord,
  ): Promise<void> {
    if (session.selectedTier !== "R2_PIPELINE") return;
    for (const row of session.receipts.values()) {
      if (
        row.sourceReceiptAt !== null &&
        row.targetReceiptAt === null &&
        row.storageKey
      ) {
        const getUrl = await this.storageDriver.mintGetUrl(row.storageKey);
        this.sendToPeer(session.target, {
          type: "pack_available",
          packId: row.packId,
          sizeBytes: row.sizeBytes,
          blobCount: row.blobCount,
          getUrl,
        });
      }
    }
  }

  private identifyRole(
    session: SessionRuntimeRecord,
    socket: PeerSocketHandle,
  ): "source" | "target" | null {
    if (session.source.socket === socket) return "source";
    if (session.target.socket === socket) return "target";
    return null;
  }

  private sendToPeer(
    peer: PeerRuntimeState,
    msg: ServerToClientWsMessage,
  ): void {
    if (peer.socket) {
      this.sendTo(peer.socket, msg);
    }
  }

  private sendTo(socket: PeerSocketHandle, msg: ServerToClientWsMessage): void {
    try {
      socket.send(JSON.stringify(msg));
    } catch {
      // Ignore closed socket races; reconnect will replay state
    }
  }

  private allocateNextSlotCode(): string {
    for (let i = 0; i < 10_000; i++) {
      this.slotCounter = ((this.slotCounter - 99) % 9000) + 100;
      const candidate = String(this.slotCounter);
      if (!this.pairingSlots.has(candidate)) {
        return candidate;
      }
    }
    return bytesToHex(randomBytes(3));
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [slot, sessionId] of this.pairingSlots) {
      const s = this.sessions.get(sessionId);
      if (!s || s.expiresAt < now) {
        this.pairingSlots.delete(slot);
      }
    }
  }
}

function encodeScopePath(scopeNamespace: string): string {
  return scopeNamespace.replace(/[^a-zA-Z0-9._-]/g, "_");
}
