# FerrumGate 架构设计

FerrumGate 是面向家庭网络、NAS 和小型服务器的 Rust 自托管网关。交付入口为 `fgate`，业务面负责代理流量，未来的管理面负责修改期望状态。优先交付文件配置、可验证的代理和 HTTPS，再逐步增加 Web UI 与可选模块。

执行阶段、命令和验收见 [EXECUTION.md](EXECUTION.md)。贡献规范见 [AGENT.md](AGENT.md)。

## 1. 上游基线与兼容性范围

以 2026-11-25 的 Gately README、Web 服务文档和模块清单为功能参考，上游 `main` 当时为 `442162e4d0b64df119bc5fe6469a088adee844c4`。实际迁移工作开始时，冻结一个上游 tag 或提交以及脱敏导出样本。各模块的配置格式、默认值和行为由该版本的样本与测试确认。FerrumGate 使用独立 TOML schema 和自有界面。上游仓库标注 Apache-2.0，未来若复用上游实现或资源，需要核对其适用许可及署名义务。[Gately](https://github.com/wangwanjie/gately) · [Web 服务](https://gately.cn/en/docs/modules/web) · [模块清单](https://github.com/wangwanjie/gately/blob/main/modules.json)

| 上游能力 | FerrumGate 顺序 | 范围 |
|---|---|---|
| Web 服务 | A–C | HTTP 代理、TLS、WebSocket、HTTP/2、gRPC、静态文件、重定向、健康检查 |
| 证书与自动 HTTPS | B、D | 文件导入与 SNI，随后 ACME HTTP-01、DNS-01、续期和部署 |
| 管理、认证与观测 | E–F | 独立管理端口、审计、版本回滚、API、UI、OIDC/TOTP/Passkeys、站点策略 |
| WAF 与入侵防护 | F | 可选 CRS 引擎、站点策略、日志告警、受限的主机封禁 |
| DDNS、L4、NAT 与隧道 | G–H | DNS 更新、TCP/UDP 转发、SNI/ALPN、STUN、受监管外部服务 |
| 迁移、定制构建与发布 | I | 按上游样本迁移、编译期裁剪、签名和可复核构建 |
| Docker 管理、终端、SPA、文件服务、定时任务、诊断等 | J | 按授权模型与实际需求分别立项 |

## 2. 实施边界与组件

Cargo workspace 使用 Rust 2024 和 resolver 3。Tokio 驱动网络与信号，Hyper 提供 HTTP 编解码，hyper-util 提供共享上游连接池。Serde/TOML 严格加载配置，ArcSwap 发布包含路由、TLS 和上游连接池的只读运行快照。核心自有 Rust 代码禁用 `unsafe`。Axum 可用于未来管理 API。TLS 采用 rustls，优先选可复现构建并通过目标矩阵的密码学提供方。

```text
配置文件 → 读取上限 → 反序列化 → 校验和编译 → 原子发布运行快照
                                                 ↓
客户端 → TCP 接入 → Hyper → Host / path → 代理 → 连接池 → 上游
```

根包 `ferrumgate` 生成 `fgate`，处理命令行、运行时和日志初始化。`crates/fg-gateway` 承担配置和数据面逻辑，对根包只暴露 `check_config` 和 `serve`。包内按 `config`、`proxy`、`server`、`tls` 和 `websocket` 划分。根 workspace 共享锁文件、构建目录和公共依赖版本。后续拆分依据实际编译、权限或复用需求，新增可选能力由消费它的 crate 声明 feature，根二进制负责组合。

## 3. 阶段 A 数据面契约

### 配置

一次服务启动使用一个 TOML 文件，`schema_version = 1` 必填。命令行通过 `--config` 选择文件。运行参数位于可省略的 `[server]` 表。在所有配置层拒绝未知字段。读入上限 1 MiB，最多 1024 条路由和 2048 个后端条目。配置错误只输出字段或索引，避免输出配置值。配置例见 [ferrumgate.example.toml](../ferrumgate.example.toml)。

| 字段 | 默认值 | 约束 |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | IP 和端口；服务在显式配置时接受外部绑定 |
| `server.tls` | `false` | `true` 使用 TLS 监听，需要证书 |
| `server.tls_handshake_timeout_ms` | 5000 | 1–300000；从开始处理 TLS 握手起计时 |
| `server.max_connections` | 1024 | 1–65535 |
| `server.header_timeout_ms` | 5000 | 1–300000 |
| `server.connect_timeout_ms` | 2000 | 1–300000；单次上游 TCP 连接预算 |
| `server.response_header_timeout_ms` | 30000 | 1–300000；覆盖解析 DNS、连接、TLS、上传等待和上游响应头 |
| `server.connection_lifetime_ms` | 300000 | 1–86400000；从接受连接起计时 |
| `server.shutdown_timeout_ms` | 10000 | 1–300000 |
| `routes[].host` | 必填 | 精确匹配 ASCII DNS 名或 IP，无端口；DNS 大小写不敏感并容许一个末尾根点 |
| `routes[].path_prefix` | `/` | 以斜杠开头；除根路径外无末尾斜杠，无查询 |
| `routes[].upstream_h2c` | `false` | 为 `http://` 上游启用 HTTP/2 prior knowledge |
| `routes[].websocket` | `false` | 为匹配该条路由的请求允许 HTTP/1.1 WebSocket 升级 |
| `routes[].backends` | 可选 | 配置 1–32 个后端，与 `upstream` 二选一 |
| `routes[].upstream` | 单后端形态必填 | `http://host[:port]` 或 `https://host[:port]`，可选末尾 `/`；无认证信息、路径前缀及查询 |

至少配置一条路由。重复的规范化 Host 与路径组合在校验时报错。HTTP Host 可带端口，路由匹配使用其中的主机名。路径采用最长段边界前缀，`/api` 匹配 `/api` 和 `/api/v1`。匹配读取原始 URI 路径，转发保留路径与查询的编码。下游可接受的 URI 范围与上游归一化方式应一并考虑。若未来同一站点以路径隔离权限，必须在引入策略时收紧该契约。

### HTTP 转发

- HTTP/1.1 监听接受 origin-form 和单一合法 Host。TLS 上的 HTTP/2 路由见 §6。未知网站或路径返回 404。无效 Host、无效请求目标或冲突的消息成帧字段返回 400。HTTP/1.0 返回 505，CONNECT 或当前路由不支持的 Upgrade 返回 501。
- 出口 origin 完全来自已验证配置。上游请求的 `Host` 为配置中的上游 authority。清除客户端的 `Forwarded`、`X-Forwarded-*` 和 `X-Real-IP`，重新写入 TCP 对端地址、原 Host 和访问 scheme。部署在另一代理后时，地址仍为直接对端。
- 双向清理 `Connection` 指定的字段及标准逐跳字段。代理保留端到端语义。仅支持无传输编码或单一 chunked，按照该跳重建 framing。HTTP/1.1 代理丢弃 trailer frames。WebSocket 与 HTTP/2 见 §5–6。参考 [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110#section-7.6.1) 与 [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)。
- 请求与响应按 frame 流式传递，利用连接读写反压，不缓存整包。连接池闲置保留每 origin 最多 8 条，空闲期限 30 秒。代理不额外重放请求。上游故障返回 502，响应头期限到达返回 504，响应开始后的读写错误终止流。
- 接入主循环确认活跃任务数低于上限后调用 accept；达到上限时连接等待内核队列。HTTP/1 头部缓冲上限为 32 KiB，头部等待设期限。连接最大寿命约束长期占用，也会终止到期的慢上传、下载和持续连接。应用层带宽/请求体配额与精细化空闲超时在阶段 C 增加。

### 生命周期

启动时先校验完整配置，完成监听绑定后记录就绪日志。Unix 接收 SIGHUP 后重新读取和校验，单次发布完整运行快照。整个 `[server]` 表视作启动参数，变更需重启。已开始的代理请求使用已选上游。同一持久连接上的下一次请求获取新快照。新快照使用新的连接池和 TLS 配置，已开始的 TLS 会话保留原握手结果。错误候选仍保留在线快照。文件应在同一目录写入新文件后原子替换。SIGINT、Unix SIGTERM 停止接入，连接进入优雅关闭，随后按期限取消剩余任务。

## 4. 阶段 B 手动 TLS

`[server] tls = true` 让单个业务监听器使用 TLS 1.2 或 1.3，HTTP 明文与 HTTPS 使用两种独立启动配置。每个 HTTPS 路由 DNS 名都需要一条 `[[certificates]]`，字段为 `host`、`cert_file`、`key_file`。域名须匹配叶子证书 SAN，证书文件按叶子到中间证书排序，密钥文件提供一把 rustls 支持的 PEM 私钥。rustls 验证叶子证书的解析、SAN 及密钥匹配。签发链完整性和当前有效期由 TLS 客户端校验。未知或缺失的 SNI 会在握手时被拒绝。TLS 下的 Host 需与 SNI 一致，否则返回 421。

外连 HTTPS 验证证书链和目标名称。默认信任 `webpki-roots` 的根证书集。根字段 `upstream_ca_file` 可追加私有 CA，添加后对当前所有 HTTPS 上游生效。指定的 TLS 文件相对配置文件目录解析，每个文件最多 1 MiB。Unix 热加载以一代提交路由、证书和上游信任配置。使用带版本的证书和密钥文件名，再替换 TOML。TLS 配置示例和轮换命令见 [EXECUTION.md](EXECUTION.md)。

## 5. 阶段 C1 WebSocket

命中精确 Host 和路径规则后，`websocket = true` 允许 HTTP/1.1 GET 升级。网关校验 `Connection`、`Upgrade`、版本 13、16 字节握手 nonce 和请求体边界。每一跳重建 Upgrade 头，保留 `Origin` 供上游执行来源策略，并按配置验证 HTTPS 上游。上游返回 101 时，网关再核对升级类型、握手证明和已选子协议。握手请求无效返回 400，上游 101 不符合契约返回 502，上游普通拒绝响应按 HTTP 路径透传。该阶段停用 WebSocket 扩展协商。SHA-1 仅用于 RFC 6455 规定的握手证明。[RFC 6455 §4](https://www.rfc-editor.org/rfc/rfc6455#section-4) · [Hyper Upgrade](https://docs.rs/hyper/latest/hyper/upgrade/index.html)

成功后两端共享一条双向字节转发任务，使用有界缓冲并透传文本、二进制和控制帧。升级保持原连接的并发名额和寿命预算。服务停止或达到寿命期限时关闭两端连接。端点正常发出的 Close 帧照常通过。重载后已升级会话继续使用握手时的上游，新的升级请求读取新快照。

## 6. 阶段 C2 HTTP/2 与原生 gRPC

TLS 监听器公布 `h2` 和 `http/1.1` ALPN，明文入口使用 HTTP/1.1。HTTP/2 按 `:authority` 路由，要求 `:scheme` 为 `https`，同时提供 Host 时必须与 authority 一致，站点身份仍与 TLS SNI 绑定。服务端每连接最多 100 条并发流，设置 32 KiB 头部列表、65,535 字节流窗口、1 MiB 连接窗口及 64 KiB 每流发送缓冲。连接寿命与停机预算仍由监听器管理。

HTTPS 上游自动通过 ALPN 协商。HTTP 明文上游可在路由显式设置 `upstream_h2c = true`，使用 HTTP/2 prior knowledge 连接池。WebSocket 升级使用独立 HTTP/1.1 池，可与 h2c 共用一个支持双协议的上游地址。入口 HTTP/2 的普通请求可转为 HTTP/1.1 上游请求。原生 gRPC 要求入口及上游均为 HTTP/2，后端不提供适配协议时返回 502。

原生 gRPC 的请求和响应按 frame 流式转发，HTTP/2 两端之间保留业务 trailers 与 gRPC 状态。逐跳、成帧、凭据和转发身份相关字段按网关策略过滤。HTTP/2 取消由协议库向对应上游流传播。gRPC-Web、明文 HTTP/2 入口及 HTTP/2 扩展 CONNECT 留待后续。[Gately 后端设置](https://gately.cn/en/docs/modules/web) · [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) · [gRPC HTTP/2 协议](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)

## 7. 阶段 C3 多后端和被动摘除

同一路由按权重轮询可用主后端。权重为 1–100，缺省为 1。全部主后端处于冷却期时，才按权重挑选备用后端。编译配置时校验至少一个主后端，并按 scheme、规范化主机和有效端口拒绝重复 origin。原有 `upstream` 单后端写法仍可使用。

多后端路由按配置快照保存独立的被动状态。后端连续三次出现连接故障后暂停选择 30 秒。期限到达后恢复参与选择，下一次收到响应头清除故障状态。导致摘除的请求仍返回 502，后续请求重新选择；全部后端冷却时返回 503。单后端保持原有错误语义。新配置代重新建立后端状态，已选上游的请求继续绑定原配置。主动探测与按请求安全重试各自作为后续切片。[Gately 后端权重、备用与健康检查](https://gately.cn/en/docs/modules/web#backends-weight-and-backup)

## 8. 协议与策略演进

| 阶段 | 决策 | 接入条件 |
|---|---|---|
| C HTTP 扩展 | WebSocket、HTTP/2、原生 gRPC、加权后端池和被动摘除已接入。静态文件基于根目录限制访问并覆盖符号链接语义。 | 按协议做双端 E2E；使用独立测试后端验证 HEAD、Range、SSE、升级以及大文件 |
| D ACME | 先 staging HTTP-01，再 DNS-01。以账户、域名集为幂等键，持久化任务并去重，校验外部 CA/区域配置，退避遵循服务端反馈。证书和密钥作为同一代更新。 | 本地 CA E2E 覆盖签发、续期、挑战清理、重启、服务端重试与旧证书继续工作 |
| E 管理面 | 单独监听回环地址或本地 socket。随机一次性初始化凭据，校验权限，写 API 需要预期配置版本，浏览器写请求校验来源和 CSRF。 | 匿名、过期、越权访问有负向验证；业务站点无法路由到管理入口 |
| F 可选安全策略 | 先确定可信客户端地址，再评估维护中的 ACL、认证、WAF 规则。WAF 以检测模式试运行，延迟、并发与可观察的失败模式按站点配置。主机规则由最小权限组件执行。 | 凭据与身份头处理、超载、引擎故障、策略优先级和规则回滚均有集成证据 |

控制面提交过程采用校验、准备资源、持久化、发布的顺序。写入以版本比较防止覆盖并发修改。持久化原子性需要同目录替换与相应的目录同步。历史版本、审计和恢复步骤需要覆盖持久化完成但发布前崩溃的场景。监听变更涉及管理入口时，用独立连接验证新路径并设置确认期限。密钥保存引用，审计记录变更操作、结果和版本。每个外部调度器独立设置并发、退避、期限与关闭行为。

## 9. 性能与运维契约

- 热路径每请求只读取一次路由快照。Host 查询走哈希表，同一 Host 的前缀按长度降序匹配。优先测量在真实站点数量下的开销，确认热点后再考虑 radix tree。
- 复用连接池、避免中间整包缓存和逐请求字符串日志。变更前后用相同后端、协议、连接复用与负载分布，比较吞吐、p50/p95/p99、超时、CPU、RSS 和打开文件数。
- 第一批用生命周期事件和重载状态用于诊断。以 `fgate serve --log-level debug` 启用连接和上游错误日志。后续指标按监听器、固定站点标识、响应码族聚合，客户端 IP、原始路径、查询、请求头和密钥不作为标签。
- 发布标准通过实测建立。性能验收先比较同一基线的前后运行漂移，再用 Gately 做语义等价的外部参照。样本分布、硬件、版本和参数写入报告。
- 默认样例运行在回环地址。对外部署可启用手动 TLS 或交由前置终止代理，并配置资源限制。管理面落地后单独验收隔离。平台验收分别记录 Linux、macOS 和其他目标系统的构建及运行结果。

依赖实现参考 [Hyper HTTP/1 服务端](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html) 与 [hyper-util 连接池](https://docs.rs/hyper-util/latest/hyper_util/client/legacy/struct.Builder.html)。版本以提交的 `Cargo.lock` 为准。
