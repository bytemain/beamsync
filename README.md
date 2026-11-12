# BeamSync

BeamSync is a self-hosted, end-to-end encrypted streaming directory migration and incremental synchronization system purpose-built for developer workspaces (50,000+ small source files alongside multi-GB build caches and local databases).

Run `beamsync-server` (bound to Cloudflare R2) plus optional regional `beamsync-edge-relay` nodes, enter a shared pairing phrase on both machines, and BeamSync automatically negotiates the fastest available path—from same-host Unix IPC and direct Overlay/IPv6/STUN P2P to regional TLS-pinned Edge Relays and pipelined Cloudflare R2 object streaming.

---

## Key Capabilities

- **5-Tier Adaptive Transport Hierarchy**:
  1. `LOCAL_IPC`: Same-machine cross-user transfers (detected via keyed `HMAC(K_host, machineId:bootId)`) stream uncompressed packs over a Unix Domain Socket (`0666`) or loopback TCP with mutual cryptographic authentication (`0` R2 operations).
  2. `P2P_DIRECT`: Smart NIC discovery prioritizes Overlay VPNs (`tailscale*`, `wg*`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`) and Global Unicast IPv6 (`2000::/3`) ahead of LAN IPv4 while filtering dead container bridges (`docker0`, `br-*`, `veth*`, `cni*`). Candidates race in parallel via **RFC 8305 Happy Eyeballs** (`100ms` stagger), followed by multi-STUN UDP hole punching with adaptive SRTT/AIMD congestion control and 64-bit SACK bitmasks (`0` R2 operations).
  3. `EDGE_RELAY`: When Symmetric NAT or corporate UDP firewalls block direct P2P, peers cut through the lowest-RTT stateless regional `beamsync-edge-relay` (`argmin(RTT_source + RTT_target)`) over binary WebSockets (`WSS`) with sliding-window pipelining and `0` R2 writes.
  4. `STREAM_RELAY`: Micro-deltas (`<= 8 MiB`) when no regional Edge Relay is deployed stream directly as end-to-end encrypted control-plane frames.
  5. `R2_PIPELINE`: Multi-GB cross-region migrations stream concurrently through offline SigV4-presigned Cloudflare R2 URLs—overlapping target `GET` downloads immediately as each source `PUT` completes rather than waiting for full archive upload.
- **Domainless IP + Pinned Self-Signed TLS Edge Relays (Zero Domain, Zero ICP Filing)**:
  - Deploy `beamsync-edge-relay` on any regional cloud VM (e.g. Shanghai, Beijing, Hong Kong, Singapore, Tokyo) with **only a public IP + TCP port (`443` or `8443`)**.
  - Pure `node:crypto` generates an ECDSA P-256 X.509v3 certificate on startup and advertises its `certSha256` fingerprint to `beamsync-server` via HMAC-signed heartbeats.
  - Clients connect directly to `wss://<ip>:<port>` with **TLS SNI suppressed (`servername: ""`)** and verify `SHA256(certDer) === certSha256` on `secureConnect` before transmitting a single HTTP byte.
- **Small-File & Large-File Engine (`BMSP` Packs + FastCDC)**:
  - Persistent local `(ino, size, mtimeNs, ctimeNs)` stat cache avoids re-hashing unchanged files across tens of thousands of source files.
  - Small files (`<= 256 KiB`) are whole-file BLAKE3-hashed and coalesced into `~8 MiB` `zstd`-compressed, `ChaCha20-Poly1305`-encrypted `BMSP` packs; large files (`> 256 KiB`) are split with Gear-based FastCDC (`64 KiB–1 MiB`) so single-line edits only transmit changed chunks.
- **Mid-Flight Fallback, Bandwidth Pacing & Atomic Target Commit**:
  - If a `P2P_DIRECT` or `EDGE_RELAY` connection drops mid-transfer, already-acknowledged packs are retained and only unacknowledged packs seamlessly switch to `R2_PIPELINE`.
  - Optional `--max-mbps <mbps>` token-bucket pacing prevents background workspace migrations from saturating interactive SSH/IDE sessions.
  - Target workspaces stage into `.beamsync-staging-<sessionId>`, hardlink unchanged local files in `O(1)` disk space, verify `rootTreeDigest`, and commit only after bilateral pack receipts (`sourceReceiptAt` & `targetReceiptAt`) reach equilibrium.

---

## Monorepo Architecture

```text
beamsync/
├── packages/
│   ├── protocol/      # @beamsync/protocol    — Curve25519 PAKE, BLAKE3, FastCDC, BMSP packs, R2 SigV4, relay tickets
│   ├── coordinator/   # @beamsync/coordinator — Session state machine, RelayMap min-RTT router, CAS index, bilateral receipts
│   ├── server/        # @beamsync/server      — Standalone coordinator daemon (`beamsync-server`) + UDP STUN (:3478) + WAL
│   ├── edge-relay/    # @beamsync/edge-relay  — Stateless regional Edge Relay (`beamsync-edge-relay`), IP+TLS cert gen & STUN
│   └── cli/           # @beamsync/cli         — `beamsync` CLI (`send`, `receive`, `doctor`) & programmatic TypeScript SDK
├── Dockerfile / docker-compose.yml                       # Central Coordinator (`beamsync-server`) deployment
├── Dockerfile.edge-relay / docker-compose.edge-relay.yml # Regional Stateless Edge Relay (`beamsync-edge-relay`) deployment
├── deploy/install-vps.sh / deploy/install-edge-relay.sh  # One-step systemd installers
├── scripts/setup-r2-lifecycle.mjs                        # Configures R2 bucket lifecycle expiration rules
└── docs/SPEC.md                                          # Protocol & architecture specification
```

---

## Quick Start (Local Development)

```bash
npm install
npm run build
npm test
```

1. Start a local coordinator + STUN server:
   ```bash
   PORT=8787 STUN_PORT=3478 RELAY_AUTH_SECRET=dev-secret node packages/server/dist/bin.js
   ```
2. (Optional) Start a local domainless IP+TLS Edge Relay node:
   ```bash
   REGION=sha PUBLIC_IP=127.0.0.1 PORT=8443 STUN_PORT=3479 TLS_MODE=self-signed \
     COORDINATOR_URL=http://127.0.0.1:8787 RELAY_AUTH_SECRET=dev-secret \
     node packages/edge-relay/dist/bin.js
   ```
3. Send a directory from Machine A (or User A):
   ```bash
   node packages/cli/dist/bin.js send /path/to/workspace \
     --server http://127.0.0.1:8787 \
     --code my-devbox-migration
   ```
4. Receive on Machine B (or User B) using the same phrase:
   ```bash
   node packages/cli/dist/bin.js receive /path/to/target \
     --server http://127.0.0.1:8787 \
     --code my-devbox-migration
   ```

---

## CLI Reference

```bash
# Send with an auto-generated pairing code (e.g. 101-amber-comet-delta)
beamsync send ./workspace --server https://sync.yourdomain.com

# Send with a custom shared phrase, namespace CAS deduplication, and 100 Mbps bandwidth cap
beamsync send ./workspace \
  --server https://sync.yourdomain.com \
  --code migrate-devbox-42 \
  --scope team-backend \
  --max-mbps 100

# Prefer regional Edge Relay cut-through even for multi-GB workspaces (> 512 MiB)
beamsync send ./workspace \
  --server https://sync.yourdomain.com \
  --code migrate-devbox-42 \
  --prefer-edge-relay

# Receive on the destination machine
beamsync receive ./workspace-copy \
  --server https://sync.yourdomain.com \
  --code migrate-devbox-42

# Inspect coordinator health, STUN reflexive address, NAT mapping type (Cone vs Symmetric),
# prioritized local/overlay/IPv6 interfaces, and RTTs to every regional Edge Relay
beamsync doctor --server https://sync.yourdomain.com
```

---

## Production Deployment

### 1. Central Coordinator (`beamsync-server` + Cloudflare R2)

`beamsync-server` is a lightweight standalone Node.js daemon (1 vCPU / 512 MB RAM is plenty) because bulk payloads never pass through it—clients stream directly via P2P, regional Edge Relays, or presigned Cloudflare R2 URLs.

1. Copy `.env.example` to `.env` and fill in your Cloudflare R2 S3 API credentials (`R2_ACCOUNT_ID`, `R2_BUCKET_NAME`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`) plus a 32-byte random `RELAY_AUTH_SECRET`:
   ```bash
   cp .env.example .env
   ```
2. Configure automatic R2 lifecycle cleanup (`7d` temporary packs + `1d` incomplete multipart uploads):
   ```bash
   set -a && source .env && set +a
   npm run setup:r2-lifecycle
   ```
3. Launch with Docker Compose (exposes `8787/tcp` for HTTP/WebSocket signaling and `3478/udp` for STUN):
   ```bash
   docker compose up -d --build
   ```
   *(Alternatively run `sudo bash deploy/install-vps.sh` for bare-metal `systemd`, or deploy via `fly.toml` / `railway.json`.)*

### 2. Regional Stateless Edge Relays (`beamsync-edge-relay`)

#### Mode A: Domainless Raw IP + Self-Signed TLS (Zero Domain, Zero ICP Filing)

Ideal for domestic / Shanghai / Beijing cloud VMs where you want instant low-latency relay cut-through on a raw public IP without registering a domain name:

1. Open `443/tcp` (or `8443/tcp`) and `3478/udp` in your VM security group.
2. Start the relay with `PUBLIC_IP` and the shared `RELAY_AUTH_SECRET`:
   ```bash
   REGION=sha \
   PUBLIC_IP=101.132.x.x \
   PORT=443 \
   TLS_MODE=self-signed \
   COORDINATOR_URL=https://sync.yourdomain.com \
   RELAY_AUTH_SECRET=your_shared_32_byte_hex_secret \
   docker compose -f docker-compose.edge-relay.yml up -d --build
   ```
   Or install directly via `systemd`:
   ```bash
   sudo bash deploy/install-edge-relay.sh
   ```
   The node generates and persists `/tls/edge-relay-tls.json`, computes `certSha256`, and registers itself with `beamsync-server` every 15 seconds. Clients connect to `wss://101.132.x.x:443` with SNI disabled (`noSni: true`) and strict SHA-256 certificate pinning.

#### Mode B: Standard Domain + CA TLS (Overseas Regions)

If placing `beamsync-edge-relay` behind Caddy / Nginx / Cloudflare in Singapore (`sgp`), Tokyo (`tyo`), or Frankfurt (`fra`):

```bash
REGION=sgp \
PUBLIC_RELAY_URL=https://sgp-relay.yourdomain.com \
PUBLIC_STUN_HOST=sgp-relay.yourdomain.com \
TLS_MODE=off \
PORT=8788 \
COORDINATOR_URL=https://sync.yourdomain.com \
RELAY_AUTH_SECRET=your_shared_32_byte_hex_secret \
docker compose -f docker-compose.edge-relay.yml up -d --build
```

---

## License

Proprietary / Internal Infrastructure.
