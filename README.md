# BeamSync

面向海量小文件开发工作区与整盘目录迁移的独立流式同步服务、DERP 式无状态边缘中继与 CLI 基建。

BeamSync 采用中心协调控制面（`beamsync-server`）+ 可水平扩展的无状态边缘中继节点（`beamsync-edge-relay`，对标 Tailscale DERP）+ 客户端 CLI（`beamsync`）架构：需要迁移或单向同步十几 GB 的代码工作区时，两端 CLI 输入同一个配对词组即可自动完成零知识密钥协商、同机 IPC 识别、NAT 打洞直连、就近 DERP 边缘流式直通转发，或在海量数据/节点中断时无缝切换至 Cloudflare R2 预签名并发边传边下流水线。

## 架构设计要点

1. **为什么中心服务直绑 R2 而不是跑在 Cloudflare Worker 里**
   - `beamsync-server` 与 `beamsync-edge-relay` 在单进程内同时承载 HTTP/WebSocket 与内置 RFC 5389 UDP STUN（`3478/udp`），可直接辅助两端完成跨网 UDP 打洞；Cloudflare Workers 运行时不支持绑定原生 UDP Socket，且在 Free/Pro 计划下受请求体与长连接计费限制（[Cloudflare Workers Limits](https://developers.cloudflare.com/workers/platform/limits/)）。
   - 绑定 R2 无需跑在 Worker 内：`beamsync-server` 通过纯内存 AWS SigV4 离线签发 `https://<accountId>.r2.cloudflarestorage.com` 的预签名 `PUT`/`GET` URL（[Cloudflare R2 Presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/)），大体积 Pack 由客户端直连 R2 并发读写，兼具零公网下行流量费与零控制面带宽占用。
2. **对标 Tailscale DERP 的无状态多地域 Edge Relay（支持上海等境内云主机 `IP + 自签名 TLS` 免域名免备案直连）**
   - **纯无状态盲转发**：`beamsync-edge-relay` 不持有任何 R2 密钥、数据库或会话明文密钥，仅凭共享 `RELAY_AUTH_SECRET` 校验短期 HMAC 票据并在内存中拼合 `source`/`target` 二进制加密流（含 `4 MiB` 水位背压控制）。
   - **免域名免备案（`IP + 自签名 TLS + SHA-256 证书指纹锁定 + 零 SNI`）**：在上海、北京、深圳等境内云主机部署时，无需绑定域名、无需申请 CA 证书、无需 ICP 备案。节点启动时通过纯 Node `node:crypto` 自动生成 ECDSA P-256 自签名 X.509 证书并计算 `certSha256`，通过签名心跳上报至中心服务 RelayMap（类似 Tailscale DERPMap 的 `CertName: sha256-raw:...`）。客户端探活与建立 `wss://<IP>:<Port>` 时自动抹除 TLS `ClientHello` 中的 `SNI` 扩展（避免触发云厂商未备案域名阻断墙），并在握手首包严格校验对端证书 `SHA-256` 指纹与端到端 `K_transport` 双向挑战认证。
   - **双端最低联合 RTT 选路 + 中断自动回退 R2**：两端并行测量 RelayMap 中各地域节点（如 `sha`、`hkg`、`sgp`、`tyo`）的 RTT，中心服务自动分配 `RTT_source + RTT_target` 最低的边缘节点；若传输中途边缘节点断连，仅对未确认的剩余 Pack 自动无缝切换至 `R2_PIPELINE`。

## 五级自适应传输路径

- **Tier 0 `LOCAL_IPC`**：同机（含同机不同 Linux/macOS 用户）通过 `0666` Unix Domain Socket + 双向 `K_transport` HMAC 挑战认证零压缩直传，0 次外部网络请求。
- **Tier 1 `P2P_DIRECT`**：局域网/Tailscale TCP 直连与内置 STUN + 双向 UDP 打洞直连（`BMU1` 滑动窗口加密传输）。
- **Tier 2 `EDGE_RELAY`（DERP 模式）**：对称型 NAT 或企业防火墙封锁 UDP 时，通过就近无状态边缘节点（支持 `wss://<IP>:<Port>` 免备案自签名证书指纹锁定）二进制流式直通转发 `BMSP` 加密压缩包，0 次对象存储写入。
- **Tier 3 `STREAM_RELAY`**：未部署独立边缘节点且增量极小（默认 `<= 8 MiB`）时，直接复用控制面信令通道推送。
- **Tier 4 `R2_PIPELINE`**：超大体积或跨洋异步传输时，源端并发上传 `~8 MiB` 加密 Pack 并上报 `sourceReceiptAt`，目标端即刻并发拉取解包并上报 `targetReceiptAt`，双边回执平衡后原子目录交换提交；托管命名空间（`scopeNamespace`）支持 SIV 收敛加密的跨机器 R2 CAS 去重。

## 仓库结构

- `packages/protocol`：X25519 EKE PAKE 密钥交换、FastCDC 分块、`BMSP` 加密压缩 Pack 容器、DERP 票据与心跳签名、离线 R2 SigV4 预签名器。
- `packages/coordinator`：配对槽位管理、DERP RelayMap 注册表与最低 RTT 选路、R2 CAS 去重索引、双边回执平衡态状态机。
- `packages/server`：中心协调服务 `beamsync-server`（REST + WebSocket + 内置 STUN + 本地 WAL 持久化 + R2 预签名绑定）。
- `packages/edge-relay`：无状态边缘中继服务 `beamsync-edge-relay`（内置纯 `node:crypto` 自签名 X.509 证书生成器、免域名无 SNI `WSS` 二进制流交换、内置 UDP `:3478` STUN、自动心跳注册）。
- `packages/cli`：`beamsync` 命令行客户端（本地增量索引、五级路径协商、TLS 证书指纹锁定无 SNI 客户端、原子暂存区提交）。

## 服务端与边缘节点部署

### 1. 部署中心协调服务 `beamsync-server`（绑定 R2）

```bash
cp .env.example .env
# 编辑 .env 填入 PUBLIC_URL、RELAY_AUTH_SECRET 与 R2 凭证
docker compose up -d --build
curl http://127.0.0.1:8787/healthz
```

可选配置 R2 Bucket 生命周期兜底清理规则：

```bash
CF_API_TOKEN=... R2_ACCOUNT_ID=... R2_BUCKET_NAME=beamsync-packs npm run setup:r2-lifecycle
```

### 2. 部署上海 / 多地域免备案 DERP 边缘节点 `beamsync-edge-relay`

在任意带有公网 IP 的云主机（例如上海轻量云/ECS，假设公网 IP 为 `101.132.x.x`，无需域名与 ICP 备案，只需在安全组放行自定义 TCP 端口如 `8443/tcp` 与 `3478/udp`）执行：

```bash
REGION=sha \
PUBLIC_IP=101.132.x.x \
PORT=8443 \
TLS_MODE=self-signed \
COORDINATOR_URL=https://sync.yourdomain.com \
RELAY_AUTH_SECRET=与中心服务一致的密钥 \
docker compose -f docker-compose.edge-relay.yml up -d --build
```

节点启动后会自动生成并持久化自签名 TLS 证书，每 15 秒通过签名心跳将 `wss://101.132.x.x:8443`、`stun:101.132.x.x:3478` 与 `certSha256` 自动注册进中心服务的 RelayMap，无需重启中心服务。你也可以在新加坡（`REGION=sgp`）、东京（`REGION=tyo`）等任意节点用同一命令随时横向扩容。

如果不希望节点主动心跳，也可以在中心服务的 `.env` 中通过 `EDGE_RELAYS` 静态配置节点启动日志打印出的 `staticEdgeRelayConfigHint`：

```ini
EDGE_RELAYS=sha=https://101.132.x.x:8443|stun:101.132.x.x:3478#sha256=<节点日志输出的64位指纹>
```

## 客户端 CLI 使用指南

```bash
npm install && npm run build
export BEAMSYNC_SERVER_URL=https://sync.yourdomain.com

# 两端输入相同自定义词组即可自动完成同机 / P2P / 就近上海 DERP / R2 同步
npx beamsync send ~/workspace --code "tiger bamboo 2026"
npx beamsync receive ~/workspace --code "tiger bamboo 2026"

# 强制优先走 DERP 边缘直通（不设 512 MiB 体积阈值上限）
npx beamsync send ~/workspace --code "tiger bamboo 2026" --prefer-edge-relay

# 类似 tailscale netcheck：检测 STUN 反射地址与所有在线 DERP 边缘节点的 RTT
npx beamsync doctor --server https://sync.yourdomain.com
```

## 本地构建与测试

```bash
npm run typecheck
npm test
```
