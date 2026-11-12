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
  - A persistent local index keyed by `(size, mtime, inode)` avoids re-hashing unchanged files across tens of thousands of source files.
  - Small files (`<= 1 MiB`) are whole-file BLAKE3-hashed and coalesced into `~8 MiB` `zstd`-compressed, `ChaCha20-Poly1305`-encrypted `BMSP` packs; larger files are split with Gear-based FastCDC (`1 MiB` to `8 MiB` chunks, `4 MiB` average) so a local edit only transmits the chunks it touches.
  - Large files are chunked while they are read in `4 MiB` blocks and written chunk by chunk on the receiver, so file size is not bounded by memory. A `2.4 GB` file was transferred with about `220 MB` peak memory on each side; after a 3-byte edit in the middle, the next sync sent `3.6 MB`.
- **No File-Count Ceiling (Sealed Control Streams)**:
  - The file list and the receiver's list of blobs it already has are streamed in `1 MiB` segments with an `8`-segment window, instead of travelling as one message. A tree of `220,002` files was transferred end to end; before this, the same tree was refused at about `160,000` entries.
  - Every segment is compressed and encrypted between the two peers, so the Coordinator relays file names, sizes, hashes, and ignore rules without being able to read or change them. A segment that is altered, dropped, reordered, or replayed fails the transfer before the receiver's directory is touched.
- **Sender-Side Ignore Rules (`.gitignore` syntax)**:
  - `.beamsyncignore` files are read in every directory of the source. Any other file name can be added with `--ignore-file <name>` (for example `--ignore-file .raftmigrationignore`), and `.gitignore` files are honoured with `--respect-gitignore`.
  - Ignored directories are never entered, read, or hashed. The receiver keeps its own copies of paths the sender ignored instead of deleting them; `--delete-ignored` on the receiver turns the transfer into an exact mirror.
- **Relay First, Upgrade Later**:
  - Direct-path discovery (same-host IPC, Happy Eyeballs TCP, UDP hole punch) starts in the background as soon as both peers are paired. If no direct path is ready after a `250 ms` grace window and an Edge Relay is eligible, the transfer starts on the relay immediately instead of waiting for NAT traversal.
  - When a direct path comes up later, the source offers it (`direct_upgrade_offer` / `direct_upgrade_answer`), finishes the pack in flight, and continues on `P2P_DIRECT` from the next pack boundary. No pack is sent twice and nothing touches R2. Disable with `--no-optimistic-relay`.
- **Resilient Control Plane**:
  - Every signaling message carries a sequence number (`cseq` client-to-server, `sseq` server-to-client). If the signaling WebSocket drops (Wi-Fi switch, NAT rebind, reverse-proxy restart), the CLI reconnects with exponential backoff for up to `30 s`, resumes with `resumeFromSeq`, and both sides replay only what the other missed, with duplicates discarded.
  - If the Coordinator stays unreachable past the budget, the transfer fails with `SIGNALING_LOST` instead of hanging. If the other peer disappears and does not resume within `45 s`, the Coordinator tells the survivor `PEER_LOST`.
  - Long phases (source scan, target hashing of an existing directory, streaming, target commit) have no wall-clock limit; liveness comes from `SIGNALING_LOST` and `PEER_LOST`. The session TTL (`2 h`) slides forward on every signaling message, including the `20 s` keepalive, so multi-hour migrations are not garbage-collected mid-transfer.
- **Outbound Proxy Support**:
  - Coordinator REST calls, the signaling WebSocket, presigned R2 `PUT`/`GET`, and Edge Relay `WSS` connections tunnel through an HTTP `CONNECT` proxy (`http://` or `https://`, optional Basic auth) or a SOCKS5 proxy (no-auth or username/password, remote DNS).
  - Configure with `BEAMSYNC_PROXY`, or the standard `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` and `NO_PROXY` (exact host, domain suffix, `host:port`, IPv4 CIDR, `*`). TLS and Edge Relay certificate pinning stay end-to-end inside the tunnel. UDP hole punching does not go through proxies.
- **UDP Path Tuning**:
  - After a hole punch succeeds, the sender probes the path with padded datagrams and raises the chunk payload from the conservative `1150` bytes up to `1420` bytes when the path carries it (fewer datagrams per pack). Disable with `--no-udp-mtu-probe`.
  - A `5 s` UDP keepalive holds the NAT binding open while the transfer is still running on the relay or the source is still scanning.
  - Behind a symmetric NAT (or when STUN gives no verdict), the CLI asks the local gateway for a UDP port mapping via NAT-PMP and advertises the mapped public endpoint as the first candidate. The mapping is renewed at half its lifetime and deleted when the session ends. Disable with `--no-port-mapping`.
- **Mid-Flight Fallback, Bandwidth Pacing & Atomic Target Commit**:
  - If a `P2P_DIRECT` or `EDGE_RELAY` connection drops mid-transfer, already-acknowledged packs are retained and only unacknowledged packs seamlessly switch to `R2_PIPELINE`.
  - Optional `--max-mbps <mbps>` token-bucket pacing on every network tier (`P2P_DIRECT`, `EDGE_RELAY`, `STREAM_RELAY`, `R2_PIPELINE`) prevents background workspace migrations from saturating interactive SSH/IDE sessions. Same-host `LOCAL_IPC` never leaves the machine and is not paced.
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

# Skip everything .gitignore and a project-specific ignore file exclude, plus one extra pattern
beamsync send ./workspace \
  --server https://sync.yourdomain.com \
  --respect-gitignore \
  --ignore-file .raftmigrationignore \
  --ignore '*.core'

# Preview what a send would skip, with the rule and file responsible for each path
beamsync ignored ./workspace --respect-gitignore --ignore-file .raftmigrationignore

# Run behind a corporate egress proxy (HTTP CONNECT or SOCKS5)
BEAMSYNC_PROXY=http://user:pass@proxy.corp.example:3128 \
  beamsync send ./workspace --server https://sync.yourdomain.com

# Inspect coordinator health, STUN reflexive address, NAT mapping type (Cone vs Symmetric),
# gateway port mapping, active proxy, prioritized local/overlay/IPv6 interfaces,
# and RTTs to every regional Edge Relay
beamsync doctor --server https://sync.yourdomain.com
```

| Flag | Side | Effect |
| :--- | :--- | :--- |
| `--max-mbps <mbps>` | send | Cap upload bandwidth on network tiers |
| `--prefer-edge-relay` | send | Use the Edge Relay regardless of transfer size (default cap `512 MiB`) |
| `--force-tier <tier>` | send | Pin one transport tier |
| `--no-optimistic-relay` | send | Wait for direct-path probing instead of starting on the Edge Relay |
| `--no-udp-mtu-probe` | send | Keep `1150`-byte UDP chunks |
| `--ignore <pattern>` | send, ignored | Skip matching paths; repeatable; highest precedence |
| `--ignore-file <name>` | send, ignored | Also read ignore files with this name in every directory; repeatable or comma-separated |
| `--respect-gitignore` | send, ignored | Also honour `.gitignore` files (off by default) |
| `--ignore-from <path>` | send, ignored | Read root-anchored rules from a file outside the workspace; repeatable; lowest precedence |
| `--delete-ignored` | receive | Delete target paths the sender ignored instead of keeping them |
| `--disable-edge-relay` | both | Never use an Edge Relay |
| `--no-port-mapping` | both | Do not request a NAT-PMP port mapping from the gateway |

| Environment variable | Effect |
| :--- | :--- |
| `BEAMSYNC_SERVER_URL` | Default Coordinator URL |
| `BEAMSYNC_PROXY` | Outbound proxy (`http://`, `https://`, `socks5://`); takes precedence over `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` |
| `BEAMSYNC_NO_PROXY` / `NO_PROXY` | Hosts that bypass the proxy |
| `BEAMSYNC_IGNORE_FILES` | Comma-separated extra ignore file names, same as repeating `--ignore-file` |

### Ignore Rules

The sender decides what is transferred. Rules use `.gitignore` syntax: `#` comments, `!` negation, a leading or inner `/` anchors a pattern to the directory of its ignore file, a trailing `/` matches directories only, and `*`, `?`, `[a-z]`, `**/`, `/**` behave as in git. An ignored directory is skipped as a whole, so nothing inside it can be re-included.

Rule sources, lowest precedence first (the last matching rule wins):

1. `--ignore-from <path>`: a rules file outside the workspace, anchored at the workspace root.
2. Ignore files inside the workspace, in this order of file name: `.gitignore` (only with `--respect-gitignore`), then each `--ignore-file` / `BEAMSYNC_IGNORE_FILES` name in the order given, then `.beamsyncignore`. For the same file name, a file in a deeper directory wins over one higher up. A later file name wins over an earlier one at any depth, so a root `.raftmigrationignore` containing `!.env` overrides every `.gitignore` in the tree.
3. `--ignore <pattern>`: anchored at the workspace root.

`.gitignore` is opt-in on purpose: a devbox migration usually wants the untracked files git ignores (`.env`, local databases, IDE state). Ignore files themselves are transferred like any other file. Symlinked ignore files are not followed. Ignore files in directories above the source directory, `.git/info/exclude`, and git's global excludes file are not read.

BeamSync's own state (`.beamsync/`, `.beamsync-*`, `.sync-staging-*`) and `.DS_Store` are always skipped and cannot be re-included.

On the receiver, a transfer replaces the target directory with the sender's tree. Target paths that match the sender's rules and that the sender did not send are carried over from the previous tree (rsync's behaviour without `--delete-excluded`), so the target's own `node_modules` or `.env` survive a re-sync. Paths the sender does not have and does not ignore are removed. If a path cannot be carried over, the previous tree is left on disk and its location is reported as `retainedBackupDir`. Pass `--delete-ignored` to `receive` for an exact mirror.

A starting point for a code workspace (`.beamsyncignore` at the workspace root):

```gitignore
# Dependency and build output that the target can regenerate
node_modules/
.venv/
venv/
__pycache__/
target/
dist/
build/
.next/
.turbo/
.gradle/

# Caches and logs
.cache/
*.log
*.pyc

# Sockets and runtime state
*.sock
*.pid
```

### Known Limitations

- Signaling resume covers network drops, not a Coordinator restart: session state lives in Coordinator memory.
- An Edge Relay data connection that drops is not re-attached; unacknowledged packs fall back to `R2_PIPELINE`.
- `--max-mbps` paces at pack granularity (wait, then send one pack of up to `~8 MiB`), so traffic is bursty within a pack. Caps below roughly `0.6 Mbps` can exceed the `120 s` inter-pack timeout on direct TCP and Edge Relay paths and trigger the R2 fallback.
- UDP payload sizing probes a fixed list of sizes (`1420`, `1380`, `1340`, `1300`, `1232`) once after the punch. It is not continuous path-MTU discovery, and hosts that fragment oversized datagrams locally can still pass a probe.
- Port mapping speaks NAT-PMP only (no UPnP IGD or PCP), maps UDP only, and has been tested against a protocol-level mock gateway, not against physical routers.
- UDP candidates are IPv4 only. There is no QUIC transport, and the Coordinator, Edge Relay, and STUN listeners do not share a single port.
- There is no protocol limit on the number of files, but both sides keep the whole file list in memory and the local index cache is a single JSON document. Measured on a `220,002`-file tree: peak memory `742 MB` on the sender and `806 MB` on the receiver. Trees beyond a few hundred thousand files have not been transferred end to end; ignore rules remain the way to keep dependency and build output out of the count.
- Hashing, chunking, and pack encryption run in JavaScript on one thread per process. Measured on a 2-core machine: about `30` to `37 MB/s` to scan a new or modified large file, and `344 s` end to end for a first-time `2.4 GB` transfer between two users on the same host. A file whose size or mtime changed is re-read in full, even when only a few bytes differ.
- Sender, receiver, and server must run the same session protocol version (currently `2`). A mismatch stops the transfer right after pairing with `PROTOCOL_VERSION_MISMATCH`. Builds from before this version do not announce one: the newer side reports the mismatch, and the older side's behaviour has not been tested.
- The scan stops on the first path it cannot represent: an absolute symlink, a symlink that points outside the source directory, or a file or directory the user cannot read. Exclude such paths with an ignore rule. Sockets, FIFOs, and device nodes are skipped without a message.
- The scan follows the directory tree across mount points; there is no one-file-system option.
- Permission bits are transferred for files and for empty directories only. A non-empty directory is created with the receiver's default mode.
- The receiver hashes its existing directory before it learns the sender's ignore rules, so paths the sender ignores are hashed there without being used.
- The Coordinator cannot read file names or ignore rules, but it still sees the number of entries, the tree digest, how much data is missing on the receiver, and which transport tier is used. It can also stall a transfer by not forwarding messages.

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
