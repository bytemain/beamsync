# BeamSync Technical Specification

## 1. Scope & Components

BeamSync is a standalone, unidirectional streaming directory migration and incremental synchronization stack built for developer workspaces (tens of thousands of small source files alongside multi-GB build/database artifacts).

The system consists of three components:
1. **`beamsync-server` (Central Coordinator)**: Always-on pairing rendezvous, regional `RelayMap` registry, embedded UDP STUN responder, and offline AWS SigV4 presigner bound directly to Cloudflare R2 without proxying bulk payloads through the control plane.
2. **`beamsync-edge-relay` (Stateless Regional Edge Relay)**: Horizontally deployable binary cut-through and UDP STUN daemon (`sha`, `hkg`, `sgp`, `tyo`, `fra`, `sjc`, etc.) holding zero R2 credentials, zero database state, and zero session keys. Natively supports **domainless raw `IP + self-signed ECDSA P-256 TLS + SHA-256 certificate pinning + SNI suppression`** for regions without domain ICP filing.
3. **`beamsync` CLI / SDK**: Persistent local stat-cache + BLAKE3/FastCDC indexer, zero-knowledge Curve25519 PAKE handshake, 5-tier adaptive transport negotiation, streaming `BMSP` pack encryption, and atomic target workspace materialization.

## 2. Five-Tier Adaptive Transport Hierarchy

| Priority | Tier | Trigger Condition | Data Plane Framing | R2 Operations |
| :--- | :--- | :--- | :--- | :--- |
| Tier 0 | `LOCAL_IPC` | Matching `HMAC(K_host, machineId:bootId)` across peers | Unix Domain Socket (`0666`) / Loopback TCP + mutual `K_transport` auth, uncompressed pack stream | 0 |
| Tier 1 | `P2P_DIRECT` | Overlay/Dual-Stack LAN TCP Happy Eyeballs winner, or STUN UDP hole punch | Framed TCP (`IPv4` + `IPv6`) or `BMU1` AEAD UDP with adaptive SRTT/AIMD + 64-bit SACK + `zstd` | 0 (mid-flight R2 fallback on drop) |
| Tier 2 | `EDGE_RELAY` | P2P blocked by Symmetric NAT / UDP firewall with active regional Edge Relay (`<= 512 MiB` default or `--prefer-edge-relay`) | `argmin(RTT_source + RTT_target)` regional WSS cut-through (supports SNI-free pinned IP+TLS) + mutual `K_transport` auth + sliding-window binary stream | 0 (mid-flight R2 fallback on drop) |
| Tier 3 | `STREAM_RELAY` | No Edge Relay available and missing delta `<= 8 MiB` | End-to-end encrypted WebSocket control-plane slices | 0 |
| Tier 4 | `R2_PIPELINE` | Large cross-region bulk workspace transfers | Concurrent presigned `PUT`/`GET` pipeline directly against Cloudflare R2 with overlapping upload & download | Missing non-CAS packs only |

## 3. Networking Primitives

1. **Smart NIC Discovery & Dual-Stack IPv6**: Filters unroutable container bridges (`docker*`, `br-*`, `veth*`, `cni*`, `virbr*`, `flannel*`, `cali*`) and link-local addresses (`169.254.0.0/16`, `fe80::/10`), ranking **Overlay Mesh VPNs** (`tailscale*`, `wg*`, `zt*`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`) ahead of **Global Unicast IPv6** (`2000::/3`), ahead of **LAN IPv4 / ULA IPv6**.
2. **RFC 8305 Happy Eyeballs Candidate Racing**: Staggers direct socket attempts by `100ms` in parallel, adopts the first mutually authenticated channel, and aborts all remaining in-flight attempts via `AbortController`.
3. **Multi-STUN NAT Mapping Classification & Stride Prediction**: Queries two distinct STUN endpoints on the same bound UDP socket (supporting both IPv4 `0x01` and IPv6 `0x02` `XOR-MAPPED-ADDRESS`), classifies `endpoint_independent` (Cone NAT) vs `symmetric`, predicts sequential ports (`port2 + k * stride`) for small strides (`1..8`), and skips futile UDP timeouts when both peers sit behind unpredicted Symmetric NAT.
4. **Domainless IP+TLS Edge Relay Protocol**: Generates ECDSA P-256 X.509v3 certificates in memory via `node:crypto`, advertises `certSha256` over HMAC-signed heartbeats, suppresses TLS `ClientHello` SNI (`servername: ""`), verifies the raw DER SHA-256 pin on `secureConnect` before sending HTTP bytes, enforces coordinator-minted upgrade tickets, and applies `4 MiB` / `1 MiB` room backpressure.
5. **Control-Plane Keepalives & Token-Bucket Pacing**: Sends periodic `20s` WebSocket keepalives across Coordinator and Edge Relay sockets and enforces optional `--max-mbps` token-bucket bandwidth throttling across all five tiers.

## 4. Cryptographic & Bilateral Equilibrium Invariants

- **Zero-Knowledge Pairing (Curve25519 EKE PAKE)**: Masks ephemeral X25519 public keys with shared-phrase role masks to derive `K_root`, `K_transport`, `K_pack`, and `K_host`.
- **Blinded Custom Phrase Rendezvous**: Derives `slot = "k" + BLAKE3("beamsync/rendezvous/v1:" + phrase)[0..15]` client-side so plaintext phrases never leave the endpoints.
- **Convergent Namespace CAS**: Uses deterministic SIV AEAD under persistent `scopeNamespace` keys for encrypted cross-machine Cloudflare R2 deduplication.
- **Bilateral Pack Equilibrium & Atomic Commit**: Issues `grant_atomic_commit` strictly after `finalize_source_manifest` AND `sourceReceiptAt != null && targetReceiptAt != null` holds for every required `packId`, committing via local hardlink reuse and atomic directory staging.
