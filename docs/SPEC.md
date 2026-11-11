# BeamSync 技术规范

## 1. 定位与边界

BeamSync 是一套独立的单向目录流式迁移与增量同步基础设施，面向包含数万个代码小文件与数 GB 编译/数据库产物的开发工作区（Devbox Workspace）。

系统由两部分组成：
1. **`beamsync-server`**：常驻协调、WebSocket 微增量中继与内置 UDP STUN 服务，通过离线 AWS SigV4 预签名直绑 Cloudflare R2，服务端自身不转发大体积文件流量。
2. **`beamsync` CLI / SDK**：负责本地持久化增量索引、零知识 PAKE 配对、四级传输路径协商、流式打包压缩加密以及目标端原子目录提交。

## 2. 四级传输路径优先级

| 等级 | 标识 | 触发条件 | 数据面封装 | R2 读写次数 |
| :--- | :--- | :--- | :--- | :--- |
| Tier 0 | `LOCAL_IPC` | 两端 `HMAC(K_host, machineId:bootId)` 一致 | Unix Domain Socket (`0666`) / Loopback TCP + 双向 `K_transport` 鉴权，免压缩流式 Pack | 0 |
| Tier 1 | `P2P_DIRECT` | 局域网/虚拟网 TCP 可达，或内置 STUN 辅助双向 UDP 打洞成功 | TCP 帧通道或 `BMU1` AEAD 加密滑动窗口 UDP 通道 + `zstd` 压缩 | 0（中断时仅剩余 Pack 降级 R2） |
| Tier 2 | `STREAM_RELAY` | 无法直连且缺失总字节数 `<= 8 MiB` | WebSocket 控制面端到端加密分片帧 | 0 |
| Tier 3 | `R2_PIPELINE` | 无法直连且缺失总字节数 `> 8 MiB` | 客户端并发直传/直拉 Cloudflare R2 预签名 URL，边传边下 | 仅缺失且未命中 CAS 的 Pack |

## 3. 密码学与安全模型

- **零知识配对（Curve25519 EKE PAKE）**：源端与目标端基于共享词组对临时 X25519 公钥做角色分离掩码并绑定会话转录本派生 `K_root`、`K_transport`、`K_pack`、`K_host`；服务端仅转发掩码公钥，无法离线枚举词组，也无法解密任何 Pack。
- **自定义词组盲化汇合**：当两端共同输入自定义词组时，客户端计算 `slot = "k" + BLAKE3("beamsync/rendezvous/v1:" + phrase)[0..15]` 作为汇合槽位，服务端不接触明文词组。
- **同机跨用户防劫持**：同机不同系统用户无法共享 `0700` 目录权限，因此目标端在 `/tmp` 创建 `0666` 随机套接字，任何连接必须先通过基于 PAKE `K_transport` 的双向挑战应答鉴权，未授权本机进程连接立即断开并计数告警。
- **托管命名空间收敛加密 CAS**：在平台调用 `/v1/leases` 指定持久化 `scopeNamespace` 时，采用 SIV 确定性 AEAD 封装 Pack，保证相同内容块跨会话生成一致 `packId` 并命中 R2 CAS 去重，同时对 R2 存储层保持全密文。

## 4. 双边回执平衡态与原子提交不变量

在 `R2_PIPELINE` 及 P2P 降级流水线中，服务端维护每个 `packId` 的双边回执 `(sourceReceiptAt, targetReceiptAt)`：
1. 源端每完成单个 Pack 的 R2 `PUT`，立即上报 `report_pack_source_receipt`。
2. 协调器立即向目标端下发 `pack_available(packId, presignedGetUrl)`，目标端无需等待源端全部上传完毕即可并发下载、校验 BLAKE3 与 AEAD 标签并解包至 `.beamsync-staging-<sessionId>`。
3. 仅当源端已提交 `finalize_source_manifest(rootTreeDigest, requiredPackIds)`，且所有必需 Pack 同时具备 `sourceReceiptAt != null` 与 `targetReceiptAt != null` 时，协调器才下发 `grant_atomic_commit`。
4. 目标端已有相同内容块直接通过本地硬链接（`fs.link`）O(1) 挂载进暂存目录，收到提交授权后原子交换目录并写入 `.beamsync/commit-v1.json`。
