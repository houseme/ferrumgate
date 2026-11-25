# FerrumGate 实战与实施路线

架构与配置契约见 [DESIGN.md](DESIGN.md)，贡献门禁见 [AGENT.md](AGENT.md)。以下先走通核心代理，再逐阶段增加服务能力。

## 1. 本地启动

在仓库根目录执行。需要 Rust stable、Cargo 和 curl。样例用业务端口 8080、后端端口 9000。端口冲突时同时修改后端端口和配置，先运行校验。

终端一启动 Rust 编写的演练后端。

```bash
cargo run --locked -p ferrumgate --example demo_origin
```

终端二验证配置并运行代理。

```bash
cargo build --locked --release -p ferrumgate
./target/release/fgate check --config ferrumgate.example.toml
./target/release/fgate serve --config ferrumgate.example.toml
```

终端三确认成功和默认拒绝。

```bash
curl --noproxy '*' -fsS --resolve app.test:8080:127.0.0.1 http://app.test:8080/
curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' -H 'Host: unknown.test' http://127.0.0.1:8080/
```

预期首条返回 `hello from upstream`，第二条显示 404。停止代理用 Ctrl-C。用 Ctrl-C 停止测试后端。生产环境使用独立服务账户、文件权限、日志收集和经过验证的 TLS。定位上游连接或响应故障时，可通过 `fgate serve --log-level debug --config …` 提高日志级别。

## 2. 重载与恢复

Unix 环境可验证热加载。准备独立运行配置，启动时传入该文件。选取进程 PID 并正常记录。准备新的完整 TOML 后，按下列顺序替换。候选文件和运行配置必须在同一目录。演练使用文件副本。

```bash
./target/release/fgate check --config ./candidate.toml
cp ./live.toml ./last-good.toml
mv ./candidate.toml ./live.toml
kill -HUP "$fgate_pid"
```

用实际 Host 再请求一次并确认日志中已应用。若候选运行效果异常，校验 `last-good.toml`，复制到同目录临时文件，原子替换运行文件，再发 SIGHUP 并复验。格式错误、未知字段或重载时修改运行参数会拒绝候选。进程重启会重新读当前文件，因此在重启前恢复有效文件。变更 `listen` 和资源预算时，验证候选并由进程管理器实施排空与重启。

| 现象 | 先查 | 处理 |
|---|---|---|
| 启动失败 | 退出码和配置校验或 bind 日志 | 核对地址、端口、文件与 schema |
| 400 / 404 | 请求目标、Host、路径前缀 | 用 `curl --resolve` 和已配置域名验证 |
| 502 | 网关到上游的连接、HTTP 响应和协议 | 从同一网络环境直连固定上游 |
| 504 | 上游响应头预算、上传耗时 | 分开测连接与响应头时间，检查后端饱和 |
| 长连接中断 | 连接寿命、退出预算、上游关闭 | 核对配置的硬期限和应用容错 |
| SIGHUP 未生效 | reload 日志、有效文件与运行参数 | 恢复已验证配置后再请求 |

## 3. 启用 TLS 与轮换

将签发好的 PEM 证书链与对应私钥保存到配置文件旁的 `tls` 目录。下面的本地演练可生成短期自签名证书。保持私钥仅运行账户可读。

```bash
tls_demo=$(mktemp -d)
umask 077
mkdir "$tls_demo/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj /CN=app.test -addext 'subjectAltName=DNS:app.test' \
  -keyout "$tls_demo/tls/app.key" -out "$tls_demo/tls/app.pem"
```

将以下内容写入 `$tls_demo/live.toml`，继续使用第 1 节的 HTTP 后端。把上游 URL 换成 `https://...` 即可启用出站 TLS 验证。使用私有 CA 时在 `[server]` 前配置 `upstream_ca_file = "tls/upstream-ca.pem"`。

```toml
schema_version = 1

[server]
listen = "127.0.0.1:8443"
tls = true

[[routes]]
host = "app.test"
upstream = "http://127.0.0.1:9000"

[[certificates]]
host = "app.test"
cert_file = "tls/app.pem"
key_file = "tls/app.key"
```

```bash
./target/release/fgate check --config "$tls_demo/live.toml"
./target/release/fgate serve --config "$tls_demo/live.toml"
```

从另一终端把命令中的 `/path/to/tls-demo` 替换成创建的目录并验证。

```bash
curl --noproxy '*' --fail --cacert /path/to/tls-demo/tls/app.pem \
  --resolve app.test:8443:127.0.0.1 https://app.test:8443/
```

轮换时写入新的证书和私钥文件，以不同文件名作为一组。在候选 TOML 改引用，执行 `fgate check`，随后按第 2 节替换和重载。复验新连接看到的证书、SAN 和到期时间，旧连接保留已协商状态。保留旧版本文件直到回滚窗口结束。TLS PEM 配置需要可读文件和兼容密钥，部署前在实际 TLS 客户端核验证书链。

## 4. 启用 WebSocket

为上游 WebSocket 接口添加更长的路径匹配。保留第 1 节的根路由以代理普通请求。两个路由都可使用 HTTP 或 HTTPS 上游。

```toml
[[routes]]
host = "app.test"
path_prefix = "/ws"
upstream = "http://127.0.0.1:9001"
websocket = true
```

在替换配置前运行 `fgate check`，再按第 2 节重载。用真实 WebSocket 客户端连接 `ws://app.test:8080/ws`，设置 DNS 或主机映射使其指向网关。TLS 监听器使用 `wss://`。浏览器客户端的来源授权由上游处理。连接默认仍受 300 秒寿命限制，预期长期保持连接的部署应按业务调整 `connection_lifetime_ms`，并验证客户端重连。

可运行 `cargo test --locked -p ferrumgate --test gateway websocket::validates_upgrades_and_relays_text_binary_ping_and_close` 使用测试自带的独立上游及客户端，核验子协议、文本、二进制、Ping/Pong 和 Close，避免依赖另外安装 WebSocket 测试工具。

## 5. 交付阶段与退出标准

| 阶段 | 实施步骤 | 退出证据 |
|---|---|---|
| A 核心 HTTP | 严格 TOML 与 CLI → 精确 Host/最长前缀 → 流式代理及池 → 生命周期、热加载与回环测试 | 启动、转发、未知站点、头部清理、越权目标限制、超时、重载、排空 |
| B 手动 TLS | 集成 rustls → 文件证书和多站点 SNI → 证书原子更新 → 验证 HTTPS 上游 | 两个 SNI 站点，证书更新，错误证书拒绝；通过测试 CA 验证出站链与主机名 |
| C Web 协议与负载 | 先补真实 WebSocket 往返，接着 HTTP/2 和 gRPC trailers；再加多上游、健康检查、重定向、静态文件 | 独立后端 E2E、慢客户流量、重连和耗尽测试；平滑停止升级连接 |
| D 自动 HTTPS | 接入 ACME 客户端，实现订单持久化、HTTP-01 challenge 路由，再加 DNS-01 与续期调度 | 本地 Pebble 或等效环境签发与续期；staging 环境分开记录；失败时旧证书可继续服务 |
| E 管理、审计与可观测 | 先做配置版本和原子提交，再加独立管理 API、角色、初始化、指标和原创 UI | 并发更新有冲突响应，权限检查生效，回滚恢复可用。UI 在同版本 API 上验收 |
| F 站点安全 | 明确信任的代理与身份头模型，添加访问策略、OIDC/TOTP/Passkeys，验证 CRS 引擎和有限权日志封禁 | 代理信任、认证授权、WAF 负向测试、资源不足降级与审计、实验主机规则回收 |
| G DDNS 与 L4 | IPv4/IPv6 IP 来源 → 只在变化时更新 DNS → TCP 转发 → UDP 状态与 SNI/ALPN | DNS 幂等和退避，连接数限制、半关闭、协议解析输入预算和地址策略测试 |
| H NAT 与隧道 | STUN 地址发现 → 局域网与公网边界验证 → 隧道生命周期 → 支持经签名的外部程序版本管理 | 已记录实际 NAT 拓扑，按协议验证连通。外部进程崩溃、升级失败和恢复可观察 |
| I 迁移与发布 | 固定 Gately 样本，构建 dry-run 迁移 → 功能白名单与构建隔离 → 产物发布 | fixtures 可重放，失败不覆盖源，产物能验证签名和 SBOM，多平台可启动 |
| J 外围能力 | 按 Docker、文件、终端、系统命令、计划任务等分别制定授权和宿主机边界 | 单项权限和恢复测试通过，再启用相应模块 |

### C 代理协议与站点能力

1. C1 WebSocket 已接入路由开关和双向流式转发。当前测试覆盖握手校验、子协议、普通拒绝响应、两跳 TLS、连接名额、寿命和停机。
2. 逐步启用 HTTP/2 和 h2c，分别限制连接数、流数、头表和流控窗口。以统一的 URI、authority、身份头和每跳字段规则处理两种协议。客户端取消时取消相应上游流。端到端验收 gRPC unary、双向流、取消和 trailers。
3. 后端定义使用稳定标识。主动探测有自己的并发和超时。被动失败只统计约定故障，健康快照原子发布。测试权重比例、探测抖动、失败阈值、摘除后的恢复以及单个后端失败时的在途请求。自动重试限制在能证明尚未写出请求的情形。
4. 重定向目标由站点配置生成。静态文件使用明确根目录，验证符号链接、目录索引、HEAD、Range、路径编码和跨平台行为。SSE、WebDAV、大文件等依赖长时连接的场景需要独立的上传与响应超时策略。

### D 证书签发与续期

1. 先用本地 ACME 测试 CA 接通账户、订单、授权、验证、签发和安装。持久化账户引用、域名集、订单状态、重试时间和最后成功版本，部署时以一代写入证书、密钥和配置。
2. HTTP-01 challenge 的查询按精确 Host 和 token 匹配，有过期时间和显式清理。测试订单重复、挑战中止与进程重启。第二个切片实现 DNS-01，清理仅针对该订单建立的记录，传播检查与 provider 限流分开。
3. 续期优先读 CA 提供的续期窗口，保留兼容的回退调度和退避。EAB 凭据通过单独引用提供。未获得新证书时持续使用原证书，记录失败阶段和证书剩余寿命。
4. 在本地通过真实握手确认新旧证书切换，再独立运行公开 staging。记录域名、挑战类型、签发链、真实客户端验证和撤销/恢复演练。生产密钥和真实域名不进入测试 fixtures。

### E 管理、审计与观测

1. 实现版本化配置的本地存储与恢复工具。对配置验证、资源准备、持久化、发布增加失败注入，重启后应恢复到已提交快照。涉及监听器的变更要预绑定，管理入口提供超时确认与回滚。
2. 开放独立管理 listener，再提供候选配置校验、当前版本读取、配置提交和历史回滚接口。写提交用 If-Match 或同等预期版本。验证并发冲突、响应丢失后重试以及权限不足。
3. 把认证初始化、最小权限、CSRF、来源校验和审计接入写入口。审计记录操作者、版本、结果与时间。UI 的写操作经相同 API，移除原始密钥和未经脱敏的差异显示。
4. 指标先覆盖配置代数与重载失败、并发连接、响应码、上游错误/超时以及读取响应头时延。站点维度来自有限的配置标识。用负载验证指标基数和采集开销，再接入运维面板。

### F 访问控制与防护

1. 先明确可信代理范围、地址链顺序、身份头和策略优先级。在部署拓扑中验证直连、单层代理与多级代理。
2. 逐个接入站点 ACL、前置认证与 OIDC/TOTP/Passkeys。并发登录、会话撤销、角色变更、身份头清理与审计需要端到端负向验证。
3. WAF 选择能通过匹配版本 CRS 回归的引擎，在检测模式建立延迟和误报基线，再验证阻断和超载行为。封禁使用有界、可过期的状态，内核表只能由受限组件修改其拥有的规则。切换与卸载后验证已有宿主机规则与合法流量。

### G DDNS 与 L4

1. 先选择一个 DNS API，完成 A/AAAA 获取、地址校验、记录归属确认、条件性更新和状态持久化。用模拟服务系统验证无变化、5xx、429 和部分失败。真实供应商跑签名、授权与更新读回。
2. TCP 转发设置监听和目标白名单、接入预算、连接期限与双向半关闭。UDP 跟踪有限会话和空闲过期。SNI/ALPN 解析使用维护中的库或已有解析能力，入口限制缓冲和等待，配置显式的未知协议结果。
3. 分别记录 IPv4、IPv6、TCP、UDP 与平台覆盖。具备等价配置、恢复检查和网络拓扑记录后，再在小流量站点试运行。

### H NAT 与托管隧道

1. STUN 先完成公网映射发现、变化事件与保活。用可控制 NAT 类型的节点矩阵评估可达性，记录链路不成立与中继降级的行为。启用端口映射时记录映射所有权、刷新和退出清理。
2. 外部隧道实例具有独立配置路径、进程标识、权限、健康和重启预算。下载仅使用批准的来源和签名产物。安装先暂存和验证，升级失败则恢复原版本，发布前演练二进制或配置损坏。

### I 迁移、定制构建与发布

1. 固定 Gately tag 和脱敏导出，生成结构化字段级迁移报告。状态包含已转换、需确认、需手工迁移。缺失安全策略或证书依赖时阻止发布候选。迁移工具只读源文件，对生成的 TOML 执行目标版本的 `fgate check`。
2. 在同一后端先做并行验证，再切 DNS 或前置均衡。比较状态、关键头、证书及权限，观察错误率和尾延迟。切换前保留原端点、配置及证书，回滚后用相同请求复验。
3. 建立实际可用的 feature 清单和兼容目标，服务端接受固定源码版本、目标、feature 和产物类型。构建任务使用隔离环境，固定工具链与 lockfile，上传、签名权限分开。
4. 产物包含平台、配置版本、校验和、签名、SBOM 与来源信息。首发从可以真实启动和冒烟的目标开始，再增加 musl、容器以及 NAS 安装包。

### J 外围服务

Docker、终端、文件服务、定时任务和诊断工具先各自明确哪些操作需要访问宿主机、凭据或网络。每项独立设置授权、资源预算、日志与关闭路径。以单模块完成安装、撤销权限、崩溃、并发和卸载演练作为启用条件。对同一机器上的已有系统服务优先采用可独立关闭的适配方式。

## 6. 校验与性能验收

```bash
cargo fmt --all --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo build --locked --release -p ferrumgate
git diff --check
```

Cargo 自动运行 Rust 集成测试。测试会在本机回环地址启动网关子进程和独立后端，并用 Rust 生成 TLS 测试证书。SIGHUP/SIGTERM 用例在 Unix 执行。

快速迭代可先运行 `cargo test --locked -p fg-gateway`，交付前跑整个 workspace。

有可选 feature 后，分别增加 `cargo check --workspace --locked --no-default-features` 与 `cargo check --workspace --locked --all-features`。构建平台分别从 Linux amd64/arm64、macOS 和 Windows 的原生或可执行测试开始。新平台先验证真实 bind、信号与文件替换语义，再记录为受支持。

性能对照在独立测试节点执行。选定相同规格的硬件、同一后端、连接复用和等价配置。至少覆盖 1 KiB、32 KiB、1 MiB 下载，POST、大流和慢客户端，逐级提高并发并记录错误率。对固定小响应可用下列命令作为单次采样。安装并固定 `oha` 的版本后再执行。

```bash
oha -z 30s -c 64 -H 'Host: app.test' http://127.0.0.1:8080/
```

预热后按 A1、B1、B2、A2 对照运行。本项目将 5% 的吞吐漂移、10% 的 p99 漂移作为首轮实验的暂停归因阈值，第一组稳定样本建立基线后再修订。记录 CPU/RSS、FD、二进制大小、错误率和原始输出。用流式大响应、慢连接和重载分别做资源上限验证。正式性能结论需要附全部环境与样本记录。

## 7. 当前交付记录

- 2026-11-25 在 macOS arm64、Rust stable 1.100.0 上通过格式检查、Clippy、4 项 Rust 单元测试、release 构建和 8 项 Rust 端到端用例。后者覆盖实际转发、路径与查询、逐跳头、连接复用、16 个并发客户端共 400 次成功请求、1 MiB 上传和分段下载、504、错误重载保留旧配置、排空、TLS SNI、上游证书校验与轮换。第 3 节的 curl TLS 验证也通过。
- 依赖已用注册表索引核对，当前 15 个直接 crate 均采用最新稳定版，传递依赖按兼容约束求解。重点版本为 Tokio 1.54.1、Hyper 1.13.0、rustls 0.23.46、Clap 4.6.10 和 TOML 1.2.3。rustls 0.24 当前发布的是开发预览，HTTP/TLS 适配器使用 0.23 系列。精确版本见 [Cargo.lock](../Cargo.lock)。
- Workspace 由 `ferrumgate` 和 `fg-gateway` 组成。C1 在 macOS arm64 上通过 workspace Clippy、5 项 Rust 单测、release 构建和 12 项 Rust 端到端测试。新增场景覆盖两跳握手校验、WebSocket over TLS、子协议、路由关闭后保留既有会话，以及连接名额、寿命和停机。
- 下一阶段为 C2 HTTP/2 和 gRPC trailers。其余 C–J 功能、正式吞吐与尾延迟对照、Linux/Windows 运行及供应商环境仍待验收。
