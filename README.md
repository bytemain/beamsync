# BeamSync

面向海量小文件开发工作区与整盘目录迁移的独立流式同步服务与 CLI 基建。

BeamSync 采用独立的常驻协调中继服务（`beamsync-server`）加客户端 CLI（`beamsync`）架构：需要迁移或单向同步十几 GB 的代码工作区时，两端 CLI 输入同一个配对词组即可自动完成零知识密钥协商、同机 IPC 识别、NAT 打洞直连，或在无法直连时自动切换至 Cloudflare R2 预签名并发边传边下流水线。

## 为什么采用独立常驻服务直绑 R2 而不是 Cloudflare Worker

1. **原生 UDP 能力**：作为类似 Tailscale / croc 的独立同步服务，`beamsync-server` 在单进程内同时承载 HTTP/WebSocket 信令协调器与内置 RFC 5389 UDP STUN 服务（`3478/udp`），可直接辅助两端完成跨网 UDP 打洞；Cloudflare Workers 运行时不支持监听原生 UDP Socket。
2. **无请求体上限与时长计费束缚**：Cloudflare Workers 在 Free/Pro 计划下存在 100 MB 请求体上限及长连接计费约束，而独立容器/VPS 常驻进程可维持任意时长的控制面 WebSocket 与小增量流式中继（[Cloudflare Workers Limits](https://developers.cloudflare.com/workers/platform/limits/)）。
3. **直绑 Cloudflare R2 依然零服务端带宽开销**：绑定 R2 并不需要把服务端跑在 Worker 里。`beamsync-server` 通过内置纯内存 AWS SigV4 签名器离线签发 `https://<accountId>.r2.cloudflarestorage.com` 的预签名 `PUT`/`GET` URL（[Cloudflare R2 Presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/)），大体积加密 Pack 数据流由两端 CLI 直接并发读写 R2，既享受 R2 零公网下行流量费，又无需经过控制面服务器中转。

## 核心特性

- **四级自适应传输路径（Happy Eyeballs 自动协商与无缝降级）**
  - **Tier 0 `LOCAL_IPC`**：基于配对密钥派生的主机指纹自动识别同机（含同机跨 Linux/macOS 用户），通过 `0666` Unix Domain Socket + 双向 `K_transport` HMAC 挑战应答零压缩高速直传，0 次 R2 请求。
  - **Tier 1 `P2P_DIRECT`**：局域网/Tailscale TCP 直连与内置 STUN + 双向 UDP 打洞直连（`BMU1` 滑动窗口加密传输），直连中断时仅对未确认的剩余 Pack 自动无缝降级至 `R2_PIPELINE`。
  - **Tier 2 `STREAM_RELAY`**：小体积增量（默认 `<= 8 MiB`）且无法直连时，直接通过 WebSocket 控制面加密分片流式推送，省去对象存储往返延迟。
  - **Tier 3 `R2_PIPELINE`**：源端每上传完一个 `~8 MiB` 加密 Pack 立即上报 `sourceReceiptAt`，服务端即刻向目标端推送预签名 `GET` URL 并发拉取解包并回执 `targetReceiptAt`；双边回执达到平衡态后原子目录交换提交。
- **针对数万小代码文件与大文件混合目录优化**
  - 本地持久化增量状态索引（`(size, mtimeMs, ino)` 命中免重算哈希）+ BLAKE3 整文件寻址（`<= 256 KiB`）+ FastCDC 内容定义分块（`> 256 KiB`）。
  - 小文件流式聚合为 `BMSP` 二进制 Pack 容器（`zstd` 压缩 + `XChaCha20-Poly1305` / ChaCha20-Poly1305 端到端加密），把 50,000 次文件系统与网络元数据开销收敛为数百个高吞吐并发流。
  - 托管命名空间（`scopeNamespace`）支持 SIV 收敛加密的持久化 R2 CAS 去重，跨机器重复同步相同内容无需重复上传。

## 仓库结构

- `packages/protocol`：X25519 EKE PAKE 密钥交换、FastCDC 分块、`BMSP` 加密压缩 Pack 容器、目录树清单与忽略规则、离线 R2 SigV4 预签名器、双边回执平衡态判定。
- `packages/coordinator`：配对会话槽位管理、四级路径状态机、R2 CAS 去重索引与边传边下双边回执引擎。
- `packages/server`：独立常驻服务端（HTTP REST + WebSocket 信令与流式中继 + 内置 UDP `:3478` STUN 服务 + 本地 WAL 持久化索引）。
- `packages/cli`：`beamsync` 命令行客户端（本地增量索引、同机 Unix Socket / LAN TCP / STUN UDP 打洞、并发 R2 流水线、硬链接预填充与原子暂存区提交）。

## 服务端一键部署方案

服务端无外部 Postgres / Redis 依赖，仅需绑定一个 Cloudflare R2 Bucket 即可上线运行。

### 方案一：Docker Compose 部署（推荐，任意云服务器 / 自有节点 1 分钟启动）

1. 复制环境变量模板并填入 Cloudflare R2 S3 API 凭证：

```bash
cp .env.example .env
```

`.env` 关键配置：

```ini
PUBLIC_URL=https://sync.yourdomain.com
PUBLIC_STUN_HOST=sync.yourdomain.com
PORT=8787
STUN_PORT=3478

R2_ACCOUNT_ID=你的_cloudflare_account_id
R2_BUCKET_NAME=beamsync-packs
R2_ACCESS_KEY_ID=你的_r2_access_key_id
R2_SECRET_ACCESS_KEY=你的_r2_secret_access_key
```

2. 一键构建并后台启动（同时暴露 `8787/tcp` 与 `3478/udp`）：

```bash
docker compose up -d --build
curl http://127.0.0.1:8787/healthz
```

3. 一键配置 R2 Bucket 生命周期自动清理兜底规则（临时前缀 `ephemeral/v1/` 24 小时过期，`cas/v1/` 30 天上限过期）：

```bash
CF_API_TOKEN=你的_cf_api_token \
R2_ACCOUNT_ID=你的_cloudflare_account_id \
R2_BUCKET_NAME=beamsync-packs \
npm run setup:r2-lifecycle
```

### 方案二：Linux 裸机 systemd 一键安装

在 Debian / Ubuntu / RHEL 主机上直接执行：

```bash
sudo ./deploy/install-vps.sh
sudo vim /etc/beamsync/beamsync.env
sudo systemctl restart beamsync
```

### 方案三：Fly.io / Railway 容器托管平台

仓库根目录已内置 `fly.toml`（含持久化挂载卷与 `8787/tcp` + `3478/udp` 双端口映射）与 `railway.json`：

```bash
fly volumes create beamsync_data --region sin --size 1
fly secrets set PUBLIC_URL=https://beamsync-server.fly.dev PUBLIC_STUN_HOST=beamsync-server.fly.dev R2_ACCOUNT_ID=... R2_BUCKET_NAME=... R2_ACCESS_KEY_ID=... R2_SECRET_ACCESS_KEY=...
fly deploy
```

## 客户端 CLI 使用指南

编译并链接 CLI：

```bash
npm install
npm run build
```

### 1. 自动生成一次性配对词组

源机器执行：

```bash
export BEAMSYNC_SERVER_URL=https://sync.yourdomain.com
npx beamsync send /path/to/devbox-workspace
# 输出示例：101-amber-falcon-river
```

目标机器执行：

```bash
export BEAMSYNC_SERVER_URL=https://sync.yourdomain.com
npx beamsync receive /path/to/devbox-workspace --code 101-amber-falcon-river
```

### 2. 两端共同输入自定义秘钥或词组（先后顺序任意）

两端无需拷贝槽位号，直接约定任意词组即可通过盲化槽位与零知识 PAKE 自动汇合（包括同机不同用户目录直传）：

```bash
# 机器 A（或同机用户 A）
npx beamsync send ~/workspace --code "tiger bamboo 2026"

# 机器 B（或同机用户 B，即使先回车等待也可自动汇合）
npx beamsync receive ~/workspace --code "tiger bamboo 2026"
```

### 3. 环境与连通性自检

```bash
npx beamsync doctor --server https://sync.yourdomain.com
```

## 本地构建与端到端测试

```bash
npm run typecheck
npm test
```
