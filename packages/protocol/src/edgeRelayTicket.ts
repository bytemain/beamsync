import { constantTimeEqual, hmacSha256Hex, utf8Bytes } from "./crypto.js";

export interface EdgeRelayNodeInfo {
  relayId: string;
  region: string;
  httpUrl: string;
  wsUrl: string;
  stunUrl?: string;
  /**
   * Optional SHA-256 fingerprint (64 lowercase hex chars) of the relay's raw DER X.509 certificate.
   * Enables IP-only + self-signed TLS deployments (e.g. Shanghai / domestic cloud VMs with zero domain name and zero ICP filing).
   */
  certSha256?: string;
  /**
   * When true, TLS ClientHello omits SNI (`servername: ""`) so cloud provider SNI inspection
   * walls do not block domainless IP+TLS relay connections.
   */
  noSni?: boolean;
}

export interface SignedEdgeRelayAllocation {
  relayId: string;
  region: string;
  httpUrl: string;
  wsRelayUrl: string;
  stunUrl?: string;
  certSha256?: string;
  noSni?: boolean;
  ticket: string;
  expiresAtMs: number;
}

export interface EdgeRelayHeartbeatPayload {
  relayId: string;
  region: string;
  httpUrl: string;
  wsUrl: string;
  stunUrl?: string;
  certSha256?: string;
  noSni?: boolean;
  timestampMs: number;
  signature: string;
}

export function mintEdgeRelayTicket(params: {
  authSecret: string;
  relayId: string;
  sessionId: string;
  role: "source" | "target";
  expiresAtMs: number;
}): string {
  const canonical = `beamsync/edge-relay/v1:${params.relayId}:${params.sessionId}:${params.role}:${params.expiresAtMs}`;
  return hmacSha256Hex(utf8Bytes(params.authSecret), utf8Bytes(canonical));
}

export function verifyEdgeRelayTicket(params: {
  authSecret: string;
  relayId: string;
  sessionId: string;
  role: "source" | "target";
  expiresAtMs: number;
  ticket: string;
  nowMs?: number;
}): boolean {
  const now = params.nowMs ?? Date.now();
  if (!Number.isFinite(params.expiresAtMs) || params.expiresAtMs < now) {
    return false;
  }
  const expected = mintEdgeRelayTicket({
    authSecret: params.authSecret,
    relayId: params.relayId,
    sessionId: params.sessionId,
    role: params.role,
    expiresAtMs: params.expiresAtMs,
  });
  return constantTimeEqual(utf8Bytes(expected), utf8Bytes(params.ticket));
}

export function buildSignedEdgeRelayWsUrl(params: {
  wsBaseUrl: string;
  relayId: string;
  sessionId: string;
  role: "source" | "target";
  expiresAtMs: number;
  ticket: string;
}): string {
  const base = params.wsBaseUrl.replace(/\/+$/, "");
  const q = new URLSearchParams({
    relayId: params.relayId,
    role: params.role,
    exp: String(params.expiresAtMs),
    ticket: params.ticket,
  });
  return `${base}/v1/relay/${encodeURIComponent(params.sessionId)}?${q.toString()}`;
}

export function signEdgeRelayHeartbeat(
  authSecret: string,
  payload: Omit<EdgeRelayHeartbeatPayload, "signature">,
): string {
  const canonical = `beamsync/relay-hb/v1:${payload.relayId}:${payload.region}:${payload.httpUrl}:${payload.wsUrl}:${payload.stunUrl ?? ""}:${payload.certSha256 ?? ""}:${payload.noSni ? "1" : "0"}:${payload.timestampMs}`;
  return hmacSha256Hex(utf8Bytes(authSecret), utf8Bytes(canonical));
}

export function verifyEdgeRelayHeartbeat(
  authSecret: string,
  payload: EdgeRelayHeartbeatPayload,
  nowMs = Date.now(),
): boolean {
  if (Math.abs(nowMs - payload.timestampMs) > 60_000) {
    return false;
  }
  const expected = signEdgeRelayHeartbeat(authSecret, payload);
  return constantTimeEqual(utf8Bytes(expected), utf8Bytes(payload.signature));
}
