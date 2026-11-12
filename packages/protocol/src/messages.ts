import type {
  EdgeRelayNodeInfo,
  SignedEdgeRelayAllocation,
} from "./edgeRelayTicket.js";
import type { ControlStreamName } from "./controlStream.js";

/**
 * Largest signaling message the Coordinator accepts. Data that can grow with the workspace (the
 * manifest, the target's known blob list) is split across messages as a sealed control stream.
 */
export const MAX_SIGNALING_MESSAGE_BYTES = 32 * 1024 * 1024;

/**
 * Version of the peer-to-peer session protocol. Peers exchange it through the Coordinator and
 * refuse to continue on a mismatch, instead of waiting for messages the other side never sends.
 *
 * - 2: manifest and known-blob list travel as sealed control streams
 */
export const BEAMSYNC_PROTOCOL_VERSION = 2;

export type TransportTier =
  | "LOCAL_IPC"
  | "P2P_DIRECT"
  | "EDGE_RELAY"
  | "STREAM_RELAY"
  | "R2_PIPELINE";

export type SessionMode = "pairing_phrase" | "managed_lease";

export type SessionState =
  | "awaiting_peer"
  | "negotiating_path"
  | "indexing_diff"
  | "streaming"
  | "equilibrium_reached"
  | "committed"
  | "failed"
  | "canceled";

export interface EndpointCandidate {
  kind: "unix_socket" | "loopback_tcp" | "lan_tcp" | "udp_punch";
  address: string; // socket path or IP
  port?: number;
}

export interface CreatePairingResponse {
  sessionId: string;
  slotCode: string;
  peerToken: string;
  wsUrl: string;
  stunServers: string[];
  edgeRelays?: EdgeRelayNodeInfo[];
  expiresAt: string;
}

export interface JoinPairingResponse {
  sessionId: string;
  peerToken: string;
  wsUrl: string;
  stunServers: string[];
  edgeRelays?: EdgeRelayNodeInfo[];
  expiresAt: string;
}

export interface CreateManagedLeaseRequest {
  scopeNamespace: string;
  expiresInSeconds?: number;
}

export interface CreateManagedLeaseResponse {
  sessionId: string;
  sourceToken: string;
  targetToken: string;
  leaseSecretHex: string;
  scopeCasKeyHex: string;
  wsUrl: string;
  stunServers: string[];
  edgeRelays?: EdgeRelayNodeInfo[];
  expiresAt: string;
}

export interface PackDescriptor {
  packId: string;
  sizeBytes: number;
  blobCount: number;
  blobHashes: string[];
}

export interface AllocatedUploadSlot {
  packId: string;
  storageKey: string;
  putUrl: string;
  alreadyExistsInCas: boolean;
}

export type NatMappingBehavior =
  | "unknown"
  | "endpoint_independent"
  | "symmetric";

/** Direct channel flavour offered when hot-upgrading from Edge Relay to P2P. */
export type DirectUpgradeChannelKind = "tcp" | "udp";

/**
 * Reliable-signaling envelope fields added to every JSON control message
 * except `hello`, `ping`, `pong`, and `resumed`.
 *  - `cseq`: client -> Coordinator sequence number (deduplicated on replay)
 *  - `sseq`: Coordinator -> client sequence number (replayed after `resumeFromSeq`)
 */
export interface SignalingEnvelopeFields {
  cseq?: number;
  sseq?: number;
}

export type ClientToServerWsMessage =
  | {
      type: "hello";
      role: "source" | "target";
      peerToken: string;
      pakePublicHex?: string;
      /**
       * Present only when re-attaching after a dropped signaling socket: the last
       * server sequence number (`sseq`) this peer processed. The Coordinator replays
       * everything after it and answers with `resumed`.
       */
      resumeFromSeq?: number;
    }
  | {
      type: "pake_confirm";
      confirmMacHex: string;
      hostFingerprint: string;
      candidates: EndpointCandidate[];
      relayRttMs?: Record<string, number>;
      natMapping?: NatMappingBehavior;
      protocolVersion?: number;
    }
  | {
      /**
       * One sealed segment of a control stream (see `controlStream.ts`). The Coordinator forwards
       * it to the other peer and cannot read it.
       */
      type: "control_stream_chunk";
      stream: ControlStreamName;
      index: number;
      final: boolean;
      payloadBase64: string;
    }
  | {
      /** Flow control: the reader has processed every segment up to and including `index`. */
      type: "control_stream_ack";
      stream: ControlStreamName;
      index: number;
    }
  | {
      /**
       * Sent after the sealed `manifest` control stream has been written in full. The manifest
       * itself (paths, ignore rules) never appears in a message the Coordinator can read.
       */
      type: "source_transfer_plan";
      manifestEntryCount: number;
      rootTreeDigest: string;
      missingBlobCount: number;
      missingBytesEstimate: number;
      selectedTier: TransportTier;
      selectedEdgeRelayRegion?: string;
      /** Source is still probing a direct path and may offer a mid-stream upgrade. */
      directUpgradePending?: boolean;
      /** Which direct channel the source will write to when `selectedTier` is `P2P_DIRECT`. */
      directChannel?: DirectUpgradeChannelKind;
    }
  | {
      type: "transport_ready";
      tier: TransportTier;
      chosenCandidate?: EndpointCandidate;
    }
  | {
      type: "relay_pack_frame";
      packId: string;
      seq: number;
      totalChunks: number;
      payloadBase64: string;
    }
  | {
      type: "allocate_upload_urls";
      requestId: string;
      packs: Array<{ packId: string; sizeBytes: number; blobCount: number }>;
    }
  | {
      type: "report_pack_source_receipt";
      packId: string;
      sizeBytes: number;
      blobCount: number;
    }
  | {
      type: "report_pack_target_receipt";
      packId: string;
    }
  | {
      type: "finalize_source_manifest";
      rootTreeDigest: string;
      requiredPackIds: string[];
      logicalBytes: number;
      dedupSavedBytes: number;
    }
  | {
      type: "fallback_to_r2";
      reason: string;
      targetReceivedPackIds: string[];
    }
  | {
      type: "report_target_committed";
      rootTreeDigest: string;
      committedFiles: number;
    }
  | {
      type: "direct_upgrade_offer";
      channel: DirectUpgradeChannelKind;
    }
  | {
      type: "direct_upgrade_answer";
      channel: DirectUpgradeChannelKind;
      accepted: boolean;
    }
  | {
      type: "ping";
      ts: number;
      /** Highest server sequence number (`sseq`) processed by this peer. */
      ackSeq?: number;
    };

export type ServerToClientWsMessage =
  | {
      type: "peer_joined";
      sessionId: string;
      peerRole: "source" | "target";
      peerPakePublicHex?: string;
    }
  | {
      type: "peer_confirmed";
      peerConfirmMacHex: string;
      sameHostMatch: boolean;
      peerCandidates: EndpointCandidate[];
      peerNatMapping?: NatMappingBehavior;
      /** Absent when the peer, or the Coordinator relaying it, predates version negotiation. */
      peerProtocolVersion?: number;
      selectedEdgeRelay?: SignedEdgeRelayAllocation;
    }
  | {
      /**
       * One sealed segment of a control stream (see `controlStream.ts`). The Coordinator forwards
       * it to the other peer and cannot read it.
       */
      type: "control_stream_chunk";
      stream: ControlStreamName;
      index: number;
      final: boolean;
      payloadBase64: string;
    }
  | {
      /** Flow control: the reader has processed every segment up to and including `index`. */
      type: "control_stream_ack";
      stream: ControlStreamName;
      index: number;
    }
  | {
      /**
       * Sent after the sealed `manifest` control stream has been written in full. The manifest
       * itself (paths, ignore rules) never appears in a message the Coordinator can read.
       */
      type: "source_transfer_plan";
      manifestEntryCount: number;
      rootTreeDigest: string;
      missingBlobCount: number;
      missingBytesEstimate: number;
      selectedTier: TransportTier;
      selectedEdgeRelayRegion?: string;
      /** Source is still probing a direct path and may offer a mid-stream upgrade. */
      directUpgradePending?: boolean;
      /** Which direct channel the source will write to when `selectedTier` is `P2P_DIRECT`. */
      directChannel?: DirectUpgradeChannelKind;
    }
  | {
      type: "transport_ready";
      tier: TransportTier;
      chosenCandidate?: EndpointCandidate;
    }
  | {
      type: "relay_pack_frame";
      packId: string;
      seq: number;
      totalChunks: number;
      payloadBase64: string;
    }
  | {
      type: "upload_urls_allocated";
      requestId: string;
      slots: AllocatedUploadSlot[];
    }
  | {
      type: "pack_available";
      packId: string;
      sizeBytes: number;
      blobCount: number;
      getUrl: string;
    }
  | {
      type: "pack_target_acknowledged";
      packId: string;
      targetAppliedCount: number;
      requiredPackCount: number;
    }
  | {
      type: "fallback_to_r2_activated";
      reason: string;
      alreadyCompletedPackIds: string[];
    }
  | {
      type: "grant_atomic_commit";
      sessionId: string;
      rootTreeDigest: string;
      requiredPackCount: number;
    }
  | {
      type: "session_committed";
      sessionId: string;
      rootTreeDigest: string;
      committedFiles: number;
    }
  | {
      type: "session_error";
      code: string;
      message: string;
    }
  | {
      type: "direct_upgrade_offer";
      channel: DirectUpgradeChannelKind;
    }
  | {
      type: "direct_upgrade_answer";
      channel: DirectUpgradeChannelKind;
      accepted: boolean;
    }
  | {
      type: "resumed";
      /** Highest client sequence number (`cseq`) the Coordinator has processed. */
      lastClientSeq: number;
    }
  | {
      type: "pong";
      ts: number;
      /** Highest client sequence number (`cseq`) the Coordinator has processed. */
      ackSeq?: number;
    };

export interface PackReceiptRow {
  packId: string;
  storageKey: string | null;
  sizeBytes: number;
  blobCount: number;
  sourceReceiptAt: number | null;
  targetReceiptAt: number | null;
}

export interface SessionEquilibriumSnapshot {
  manifestFinalized: boolean;
  rootTreeDigest: string | null;
  requiredPackIds: string[];
  receipts: ReadonlyMap<string, PackReceiptRow>;
}

export interface EquilibriumEvaluation {
  equilibriumReached: boolean;
  requiredPackCount: number;
  sourceReadyCount: number;
  targetAppliedCount: number;
  missingSourcePackIds: string[];
  missingTargetPackIds: string[];
}

export function evaluateSessionEquilibrium(
  snapshot: SessionEquilibriumSnapshot,
): EquilibriumEvaluation {
  const missingSourcePackIds: string[] = [];
  const missingTargetPackIds: string[] = [];
  let sourceReadyCount = 0;
  let targetAppliedCount = 0;

  for (const packId of snapshot.requiredPackIds) {
    const row = snapshot.receipts.get(packId);
    if (row && row.sourceReceiptAt !== null) {
      sourceReadyCount++;
    } else {
      missingSourcePackIds.push(packId);
    }
    if (row && row.targetReceiptAt !== null) {
      targetAppliedCount++;
    } else {
      missingTargetPackIds.push(packId);
    }
  }

  const requiredPackCount = snapshot.requiredPackIds.length;
  const equilibriumReached =
    snapshot.manifestFinalized &&
    snapshot.rootTreeDigest !== null &&
    missingSourcePackIds.length === 0 &&
    missingTargetPackIds.length === 0;

  return {
    equilibriumReached,
    requiredPackCount,
    sourceReadyCount,
    targetAppliedCount,
    missingSourcePackIds,
    missingTargetPackIds,
  };
}
