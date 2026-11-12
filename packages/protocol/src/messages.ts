import type {
  EdgeRelayNodeInfo,
  SignedEdgeRelayAllocation,
} from "./edgeRelayTicket.js";
import type { TreeManifest } from "./manifest.js";

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

export type ClientToServerWsMessage =
  | {
      type: "hello";
      role: "source" | "target";
      peerToken: string;
      pakePublicHex?: string;
    }
  | {
      type: "pake_confirm";
      confirmMacHex: string;
      hostFingerprint: string;
      candidates: EndpointCandidate[];
      relayRttMs?: Record<string, number>;
      natMapping?: NatMappingBehavior;
    }
  | {
      type: "target_have_blobs";
      knownBlobHashes: string[];
    }
  | {
      type: "source_transfer_plan";
      manifest: TreeManifest;
      rootTreeDigest: string;
      missingBlobCount: number;
      missingBytesEstimate: number;
      selectedTier: TransportTier;
      selectedEdgeRelayRegion?: string;
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
      type: "ping";
      ts: number;
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
      selectedEdgeRelay?: SignedEdgeRelayAllocation;
    }
  | {
      type: "target_have_blobs";
      knownBlobHashes: string[];
    }
  | {
      type: "source_transfer_plan";
      manifest: TreeManifest;
      rootTreeDigest: string;
      missingBlobCount: number;
      missingBytesEstimate: number;
      selectedTier: TransportTier;
      selectedEdgeRelayRegion?: string;
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
      type: "pong";
      ts: number;
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
