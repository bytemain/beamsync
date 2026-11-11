# BeamSync 技术规范

## 1. 定位与边界

BeamSync 是一套独立的单向目录流式迁移与增量同步基础设施，面向包含数万个代码小文件与数 GB 编译/数据库产物的开发工作区（Devbox Workspace）。

系统由三部分组成：
1. **`beamsync-server`（中心协调面）**：常驻配对协调、DERP RelayMap 注册表管理、内置 UDP STUN 与离线 AWS SigV4 预签名直绑 Cloudflare R2，控制面自身不中转大体积文件流量。
2. **`beamsync-edge-relay`（DERP 式无状态边缘中继）**：可按地域（上海 `sha`、香港 `hkg`、新加坡 `sgp`、东京 `tyo` 等）水平部署的纯无状态二进制流交换与 STUN 节点，不持有任何 R2 凭证、数据库或明文会话密钥；原生支持 **`IP + 自签名 TLS + SHA-256 证书指纹锁定 + 零 SNI`** 免域名免 ICP 备案模式。
3. **`beamsync` CLI / SDK**：负责本地持久化增量索引、零知识 PAKE 配对、五级传输路径协商、流式打包压缩加密以及目标端原子目录提交。

## 2. 五级传输路径优先级

| 等级 | 标识 | 触发条件 | 数据面封装 | R2 读写次数 |
| :--- | :--- | :--- | :--- | :--- |
| Tier 0 | `LOCAL_IPC` | 两端 `HMAC(K_host, machineId:bootId)` 一致 | Unix Domain Socket (`0666`) / Loopback TCP + 双向 `K_transport` 鉴权，免压缩流式 Pack | 0 |
| Tier 1 | `P2P_DIRECT` | 局域网/虚拟网 TCP 可达，或内置 STUN 辅助双向 UDP 打洞成功 | TCP 帧通道或 `BMU1` AEAD 加密滑动窗口 UDP 通道 + `zstd` 压缩 | 0（中断时仅剩余 Pack 降级 R2） |
| Tier 2 | `EDGE_RELAY` | P2P 被对称 NAT / UDP 防火墙阻断且存在在线 DERP 边缘节点（默认 `<= 512 MiB` 或启用 `--prefer-edge-relay`） | 按 `argmin(RTT_source + RTT_target)` 选定就近边缘节点，建立 `WSS`（支持无域名无 SNI + 证书 SHA-256 指纹锁定）+ 端到端双向 `K_transport` 鉴权 + 滑动窗口加密二进制流 | 0（中断时仅剩余 Pack 降级 R2） |
| Tier 3 | `STREAM_RELAY` | 未部署边缘节点且缺失总字节数 `<= 8 MiB` | WebSocket 控制面端到端加密分片帧 | 0 |
| Tier 4 | `R2_PIPELINE` | 大体积工作区或跨地域异步批量传输 | 客户端并发直传/直拉 Cloudflare R2 预签名 URL，边传边下 | 仅缺失且未命中 CAS 的 Pack |

## 3. DERP 式免域名免备案边缘中继协议（`@beamsync/edge-relay`）

对标 Tailscale 自定义 DERP 的境内 IP 直连架构（`CertName: "sha256-raw:..."`）：
1. **纯内存自签名 X.509 生成与指纹上报**：边缘节点在 `TLS_MODE=self-signed`（或仅指定 `PUBLIC_IP`）下通过 `node:crypto` 自动生成 ECDSA P-256 X.509v3 证书并计算 `certSha256 = SHA256(certDer)`，每 15 秒向中心协调器的 `/v1/edge-relays/heartbeat` 发送带 `HMAC-SHA256(RELAY_AUTH_SECRET, ...)` 签名的心跳包。
2. **零 SNI 防阻断**：当 `noSni: true` 时，客户端在 TLS `ClientHello` 中显式清空 `servername: ""`（不携带任何域名扩展），并使用纯 `IP:Port` 作为 HTTP `Host`，规避境内云厂商针对未备案域名的 SNI / Host 阻断墙。
3. **首包证书指纹锁定 + 票据鉴权 + 端到端双向认证**：
   - 客户端在 TLS `secureConnect` 完成瞬间、任何 HTTP Upgrade 字节发出前校验对端证书 `SHA256(raw) === certSha256`，不匹配立即以 `EDGE_RELAY_CERT_PIN_MISMATCH` 销毁连接。
   - 边缘节点在 HTTP Upgrade 阶段校验协调器签发的会话级角色票据 `verifyEdgeRelayTicket`（绑定 `relayId`、`sessionId`、`role` 与过期时间戳），非法连接直接返回 `HTTP 403`。
   - 源端与目标端进入同一内存房间收到 `0x01` 配对就绪字节后，先执行基于 PAKE 派生密钥 `K_transport` 的双向挑战应答（`FRAME_AUTH_INIT` / `FRAME_AUTH_REPLY`），再流式转发 `ChaCha20-Poly1305` 加密的 `BMSP` Pack；边缘节点全程零知识，且单房间施加 `4 MiB` 高水位 / `1 MiB` 低水位 TCP 背压控制。

## 4. 密码学与双边回执平衡态不变量

- **零知识配对（Curve25519 EKE PAKE）**：源端与目标端基于共享词组对临时 X25519 公钥做角色分离掩码并派生 `K_root`、`K_transport`、`K_pack`、`K_host`。
- **自定义词组盲化汇合**：客户端计算 `slot = "k" + BLAKE3("beamsync/rendezvous/v1:" + phrase)[0..15]` 作为汇合槽位，服务端不接触明文词组。
- **托管命名空间收敛加密 CAS**：在持久化 `scopeNamespace` 下采用 SIV 确定性 AEAD 封装 Pack，实现跨机器 R2 CAS 全密文去重。
- **双边回执平衡态与原子提交**：仅当源端提交 `finalize_source_manifest`，且所有必需 `packId` 同时具备 `sourceReceiptAt != null` 与 `targetReceiptAt != null` 时，协调器才下发 `grant_atomic_commit`，目标端通过本地硬链接复用已有块并原子交换暂存目录。
