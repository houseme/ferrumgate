> 历史方案。当前架构、贡献规范与执行命令见 [DESIGN.md](DESIGN.md)、[AGENT.md](AGENT.md) 和 [EXECUTION.md](EXECUTION.md)。

## DESIGN.md — FerrumGate 架构设计

### 1. 项目标识

**FerrumGate**（拉丁语 *ferrum*，铁；Rust 即铁锈）是 Gately 的 Rust 重写项目。它保留 Gately“单二进制、编译期模块选择、Web
定制构建”的产品形态，同时以内存安全、异步 Rust 核心替换 Go 运行时。

| 项目       | 值                          |
|------------|-----------------------------|
| 项目名     | FerrumGate                  |
| 二进制     | `fgate`                     |
| Crate 前缀 | `fg-`                       |
| 许可证     | Apache-2.0                  |
| MSRV       | 1.85+（edition 2024）       |
| 默认目标   | `x86_64-unknown-linux-musl` |

### 2. 目标与非目标

**目标**

1. 复现 Gately 模块矩阵：核心网关（端口转发、Web 服务、SSL 证书）始终存在；其余 22 个可选模块通过 Cargo Features 在编译期独立纳入或排除。
2. 提供与 `build.gately.cn` 等价的定制构建服务，将用户选择映射为白名单内的
   `cargo build --no-default-features --features ...` 调用。
3. 交付内嵌 Web UI 的单静态二进制，支持 Linux、macOS、Windows、FreeBSD 与 musl 目标。
4. 在可行范围内保持 Gately 配置迁移兼容（优先 Web 服务、ACME、DDNS、WAF、入侵防护）。

**第一阶段非目标**

- 不追求 frp、Tailscale、Cloudflare Tunnel、Docker 管理、文件服务等边缘模块的 100% 行为等价。
- 不实现纯 Rust WAF 规则引擎；采用 `coraza-rs`（对 Coraza/Go 的 FFI）保证 OWASP CRS v4 兼容性。
- 不强制全栈 Rust Web UI；前端仍为 TypeScript/React SPA，通过 `include_dir` 嵌入。

### 3. 核心架构原则

| 原则               | 执行方式                                                                                                          |
|--------------------|-------------------------------------------------------------------------------------------------------------------|
| **编译期模块化**   | 每个可选能力位于 Cargo feature 之后；默认构建不链接重型依赖。                                                     |
| **核心—模块解耦**  | `fg-core` 定义 `Module` trait、`ModuleContext` 与 `Registry`；核心不直接导入可选 crate。                          |
| **单一事实来源**   | `features.toml` 声明每个 feature、默认值、风险等级与依赖。`xtask` 生成注册代码、`modules.json` 与构建站点白名单。 |
| **安全默认**       | 管理 API 默认绑定回环地址；首次启动生成一次性管理员令牌；WAF 与入侵防护默认关闭。                                 |
| **可观测性内建**   | 所有模块通过 `fg-observability` 输出结构化 `tracing` 事件、注册 Prometheus 指标并写入审计记录。                   |
| **Feature 仅可加** | 启用 feature 永不删除功能或破坏编译；features 是可组合的并集。                                                    |

### 4. 工作区布局

```
ferrumgate/
├── Cargo.toml                  # workspace resolver = "3"
├── features.toml               # 单一事实来源
├── crates/
│   ├── fg-core/                # Module trait、Registry、Context、错误
│   ├── fg-config/              # Schema、校验、热加载
│   ├── fg-runtime/             # 生命周期、信号、监督
│   ├── fg-proxy/               # HTTP 反向代理（axum + hyper + tower）
│   ├── fg-l4/                  # TCP/UDP、SNI/ALPN 路由
│   ├── fg-acme/                # instant-acme 集成
│   ├── fg-certs/               # 证书存储 + rustls resolver
│   ├── fg-ddns/                # Provider trait + 11 个提供商
│   ├── fg-nat/                 # STUN 穿透、TCP/UDP 打洞
│   ├── fg-waf/                 # coraza-rs 适配器
│   ├── fg-ban/                 # fail2ban-rs 风格入侵防护
│   ├── fg-auth/                # 本地、OIDC、TOTP、Passkeys
│   ├── fg-api/                 # REST API（axum）
│   ├── fg-webui/               # 嵌入静态资源
│   ├── fg-observability/       # tracing、指标、审计
│   ├── fg-storage/             # SQLite / redb 抽象
│   └── fg-buildctl/            # 定制构建后端
├── apps/fgate/                 # 主二进制
├── web/                        # React/TS 前端
├── xtask/                      # 代码生成 + 校验
├── tests/                      # 集成与兼容性测试
└── deploy/                     # Docker、systemd、安装器
```

### 5. 模块注册设计

**`features.toml` 片段**

```toml
[[feature]]
name = "proxy"
display = "Web 服务 / 反向代理"
default = true
risk = "low"
depends = ["core"]
gately_equiv = "Web services"

[[feature]]
name = "acme"
display = "ACME / SSL 证书"
default = true
risk = "low"
depends = ["core", "certs"]
gately_equiv = "SSL Certificates"

[[feature]]
name = "waf"
display = "WAF（OWASP CRS v4）"
default = false
risk = "high"
depends = ["proxy"]
gately_equiv = "WAF"

[[feature]]
name = "ban"
display = "入侵防护"
default = false
risk = "medium"
depends = ["core"]
gately_equiv = "Intrusion Prevention"

[[feature]]
name = "ddns"
display = "动态 DNS"
default = false
risk = "medium"
depends = ["core"]
gately_equiv = "DDNS"
```

**生成的注册代码**（`fg-core/src/registry.generated.rs`）

```rust
pub fn register_enabled(reg: &mut Registry) {
    reg.add(Box::new(fg_proxy::ProxyModule::default()));          // #[cfg(feature = "proxy")]
    #[cfg(feature = "acme")]
    reg.add(Box::new(fg_acme::AcmeModule::default()));
    #[cfg(feature = "waf")]
    reg.add(Box::new(fg_waf::WafModule::default()));
    #[cfg(feature = "ban")]
    reg.add(Box::new(fg_ban::BanModule::default()));
    #[cfg(feature = "ddns")]
    reg.add(Box::new(fg_ddns::DdnsModule::default()));
}
```

`xtask` 从 `features.toml` 生成三份产物：

1. `registry.generated.rs` — 编译期模块注册。
2. `modules.json` — 供构建站点与 API 使用。
3. `web/src/generated/features.json` — 前端 feature 选择器数据。

CI 检查（`xtask check-features`）若发现三者与 `features.toml` 不一致则失败。

### 6. Module Trait 契约

```rust
#[async_trait::async_trait]
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn feature_name(&self) -> &'static str;
    fn dependencies(&self) -> &'static [&'static str] { &[] }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn validate(&self, cfg: &Config) -> Result<()>;
    async fn init(&self, ctx: &ModuleContext) -> Result<()>;
    async fn run(&self, ctx: &ModuleContext, cancel: CancellationToken) -> Result<()>;
    async fn shutdown(&self, ctx: &ModuleContext) -> Result<()>;
}
```

`ModuleContext` 携带 `Arc<Config>`、`Arc<dyn Storage>`、`Arc<Metrics>`、`Arc<AuditLog>`、`FeatureSet` 以及每模块独立的
`CancellationToken`。

### 7. 技术选型

| 领域           | Crate / 方案                                             | 理由                                                       |
|----------------|----------------------------------------------------------|------------------------------------------------------------|
| 异步运行时     | `tokio`                                                  | 事实标准，生态成熟                                         |
| HTTP 服务/代理 | `axum` + `hyper` + `tower`                               | 可组合中间件，HTTP/1.1、HTTP/2、WebSocket、gRPC            |
| TLS            | `rustls` + `tokio-rustls`                                | 内存安全，无 OpenSSL 依赖                                  |
| ACME           | `instant-acme`                                           | 在 Instant Domain Search 生产验证；纯 Rust RFC 8555 客户端 |
| SNI / L4 路由  | `tokio` + 自研 `ClientHello` 解析；可选参考 `refractium` | 对应 Gately 的 SNI 路由与端口转发语义                      |
| WAF            | `coraza-rs`（对 Coraza 的 FFI）                          | 保证 OWASP CRS v4 兼容，避免重写 SecLang                   |
| 入侵防护       | `fail2ban-rs` 设计 / crate                               | 纯 Rust，nftables/iptables/ipset 后端，单二进制            |
| DDNS           | 自研 `Provider` trait + 分提供商 crate                   | Gately 支持 11 家；trait 模式可扩展                        |
| STUN 穿透      | `stun` crates + 自研打洞                                 | TCP/UDP、保活、UPnP/NAT-PMP                                |
| 认证           | `openidconnect`、`totp-rs`、`webauthn-rs`                | OIDC、TOTP、Passkeys                                       |
| 存储           | `sqlite`（`rusqlite`）或 `redb`                          | 证书、封禁、审计、构建任务                                 |
| 可观测性       | `tracing`、`metrics`、`opentelemetry-otlp`               | 结构化日志、Prometheus、OTLP                               |
| 前端           | React + TypeScript + `include_dir`                       | Gately 同样前后端分离；避免全栈 Rust 约束                  |

### 8. 数据流与请求管线

以功能最密集的 **Web 服务 / 反向代理** 路径为例：

```
客户端
  → 监听器（443/TCP 或 QUIC）
    → TLS 终止（rustls，基于 SNI 选择证书）
      → [WAF 检查]        #[cfg(feature = "waf")]
      → [入侵检查]        #[cfg(feature = "ban")]
      → [认证中间件]      #[cfg(feature = "auth")]
      → 路由（域名 + 路径匹配）
        → 后端池（负载均衡、健康检查）
          → 后端（HTTP/HTTPS、WebSocket、gRPC）
```

每一层都是 `tower::Service`，仅在对应 feature 启用时插入。这与 Gately 的注入函数模式一致：核心路由器从不直接引用 `fg-waf` 或
`fg-ban` 类型。

### 9. 构建站点架构（`fg-buildctl`）

```rust
pub async fn create_build(req: BuildRequest) -> Result<BuildJob> {
    validate_whitelist(&req.features)?;          // 仅允许 features.toml 中的项
    validate_target(&req.target)?;               // 固定三元组白名单
    validate_dependency_closure(&req.features)?; // 例如 waf 依赖 proxy
    let job = enqueue(BuildJob { ... });
    ci_trigger(job).await?;                      // GitHub Actions / Woodpecker
    Ok(job)
}
```

生成命令（绝不 shell 插值）：

```bash
cargo build --release --locked \
  --no-default-features \
  --features "core,proxy,acme,waf,ban"
```

产物：二进制、`sha256sum`、CycloneDX SBOM、cosign 签名、Docker 镜像（多架构）、`.deb` / `.rpm`（可选）。

### 10. 安全模型

| 层面         | 控制                                                                                      |
|--------------|-------------------------------------------------------------------------------------------|
| 管理 API     | 默认回环绑定；Bearer token 或会话；状态变更校验 CSRF/Origin                               |
| Feature 选择 | 从 `features.toml` 白名单选取；服务端校验依赖闭包                                         |
| WAF 失败模式 | 管理面 `fail-close`，业务面 `fail-open`（可配置，记录日志）                               |
| 封禁引擎     | nftables `inet` 表、按 jail 的 set；IPv6 端口扫描封禁使用 `/64` 严格模式                  |
| 供应链       | `cargo deny`、`cargo audit`、SBOM、可复现构建（固定 Rust 工具链、`Cargo.lock`、容器摘要） |
| 密钥         | 审计日志永不记录请求体或密钥；配置差异对密钥脱敏                                          |

### 11. 部署拓扑

| 目标          | 产物                          | 说明                                             |
|---------------|-------------------------------|--------------------------------------------------|
| Linux（通用） | 静态 `fgate` 二进制           | 提供 musl 构建                                   |
| Docker        | 多架构镜像 `ferrumgate/fgate` | 端口转发/STUN 建议 `--network host`              |
| OpenWrt       | `.ipk`                        | 交叉编译 `mips`/`arm` 目标                       |
| fnOS / NAS    | 原生包                        | 对应 Gately 的 fnOS 集成                         |
| systemd       | unit 文件                     | 封禁引擎需 `CapabilityBoundingSet=CAP_NET_ADMIN` |

### 12. 从 Gately 迁移

`fgate migrate gately --config ./gately.json --out ./ferrumgate.toml`

第一阶段映射表：

| Gately 模块 | FerrumGate feature |
|-------------|--------------------|
| 端口转发    | `l4`               |
| Web 服务    | `proxy`            |
| SSL 证书    | `acme`、`certs`    |
| DDNS        | `ddns`             |
| WAF         | `waf`              |
| 入侵防护    | `ban`              |
| STUN 穿透   | `nat`              |

不支持的模块输出结构化报告，附替代建议。
