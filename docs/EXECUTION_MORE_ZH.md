> 历史方案。当前架构、贡献规范与执行命令见 [DESIGN.md](DESIGN.md)、[AGENT.md](AGENT.md) 和 [EXECUTION.md](EXECUTION.md)。

**EXECUTION.md — FerrumGate 架构执行计划（中文版本）**

**版本 1.1 — 详细、可执行、生产级**

---

## 1. 执行摘要

**可行性：高。** Rust 生态以生产级 crate 覆盖了 Gately 的每一项能力。两个工程热点：

1. **WAF**：`coraza-rs` 是 OWASP Coraza 的安全 Rust 绑定，基于官方 C 绑定；Coraza 是基于 Go 的 WAF，兼容 ModSecurity
   SecLang，可确保 OWASP CRS v4 等价性，无需重写 SecLang。构建需要 Go ≥1.21 与 C 编译器；首次构建将 Go WAF 引擎编译为静态库，后续构建很快。
2. **DDNS 提供商广度**：Gately 支持 11 家。FerrumGate 提供 `Provider` trait，M1 实现 5 家，M2 完成剩余 6 家。

Cargo Features 干净地映射 Gately 的 `no_<module>` 构建标签。构建站点逻辑是 `cargo build` 之上的薄校验层。Gately
自身文档确认：除端口转发、Web 服务与 SSL 证书三个核心模块外，其余模块均可在编译时去掉；build.gately.cn 根据用户勾选生成二进制、OpenWrt
包、飞牛安装包或多架构 Docker 镜像，页面实时估算体积。

---

## 2. 里程碑计划（详细任务分解）

### M0 — 骨架与对齐（2 周）

**目标：** 建立可编译、CI 验证通过的工作区，确保 feature 清单一致，`xtask` 代码生成管线可运行。

| #    | 任务                                                                                                  | 交付物                     | 验收                               |
|------|-------------------------------------------------------------------------------------------------------|----------------------------|------------------------------------|
| M0.1 | 创建工作区，`resolver = "3"`，edition 2024，MSRV 1.85                                                 | `Cargo.toml`               | `cargo metadata` 成功              |
| M0.2 | 编写 `features.toml`，包含全部 25 个 feature（3 核心 + 22 可选）                                      | `features.toml`            | `xtask check-features` 退出码 0    |
| M0.3 | 实现 `xtask codegen`：生成 `registry.generated.rs`、`modules.json`、`web/src/generated/features.json` | 三份生成产物               | 生成文件与已提交副本一致           |
| M0.4 | 实现 `fg-core`：`Module` trait、`Registry`、`ModuleContext`、`RiskLevel`、错误类型                    | `crates/fg-core`           | 依赖校验与条件注册单元测试通过     |
| M0.5 | 实现 `fg-config` schema：`serde` 反序列化、校验、feature 感知解析                                     | `crates/fg-config`         | 引用未编译模块的配置产生可操作错误 |
| M0.6 | CI 流水线：fmt、clippy、`cargo hack` feature 矩阵、`check-features`                                   | `.github/workflows/ci.yml` | 桩二进制上所有门禁通过             |
| M0.7 | 验证 `cargo build --no-default-features`、默认、`--all-features`                                      | CI 矩阵条目                | 三者均可编译                       |

**退出标准：** 默认、最小（`core`）、全 feature 构建通过；`xtask check-features` 绿；任何清单漂移导致 CI 失败。

---

### M1 — 核心网关 MVP（4 周）

**目标：** 生产可用的反向代理，具备自动 TLS、证书管理、管理 API 与内嵌 Web UI。

#### M1.1 反向代理（`fg-proxy`）

使用 `axum` + `hyper` + `tower`，参考 `axum-reverse-proxy` 实现正确的逐跳头剥离、`X-Forwarded-*` 处理、WebSocket 升级与
gRPC trailer 保留。

| 任务                     | 细节                                                                                      | 测试                       |
|--------------------------|-------------------------------------------------------------------------------------------|----------------------------|
| HTTP/1.1 与 HTTP/2 监听  | `hyper` 自动检测；按站点配置                                                              | 集成：curl 访问后端        |
| SNI TLS 终止             | `rustls` `ResolvesServerCert` trait；主机名→证书基数树                                    | 两个虚拟主机使用不同证书   |
| WebSocket 透传           | `tower-http` 升级处理                                                                     | 通过代理进行 echo 测试     |
| gRPC trailer 保留        | **不**剥离 `grpc-status` / `grpc-message`                                                 | `tonic` 健康检查穿透代理   |
| 负载均衡                 | 轮询 + 健康检查（每个后端 `/healthz`）                                                    | 下线一个后端，验证流量转移 |
| 中间件链（feature 门控） | `[WAF]` → `[ban]` → `[auth]` → 路由，每层为 `tower::Layer`，仅在 `#[cfg(feature)]` 下插入 | 禁用 feature，验证层不存在 |

#### M1.2 证书存储（`fg-certs`）与 ACME（`fg-acme`）

`instant-acme` 是异步、纯 Rust 的 RFC 8555 客户端，在 Instant Domain Search 生产使用，依赖 Tokio 与 rustls。

| 任务          | 细节                                                                                 |
|---------------|--------------------------------------------------------------------------------------|
| 证书存储      | SQLite 表 `certificates(domain, cert_pem, key_pem, expires_at, issuer)`              |
| 手动导入      | `fgate certs import --domain example.com --cert ./fullchain.pem --key ./privkey.pem` |
| ACME 账户     | 首次使用生成 ECDSA 密钥；序列化凭据加密存储                                          |
| ACME 订单流程 | `Account::new_order` → HTTP-01 或 DNS-01 挑战 → 最终化 → 下载证书                    |
| 续期调度      | 后台任务检查 `expires_at - 30 days`；失败指数退避：1h → 6h → 24h                     |
| 失败兜底      | 告警日志；保留上一证书；暴露 `fgate_acme_renewal_failures_total`                     |

#### M1.3 管理 API（`fg-api`）与 Web UI（`fg-webui`）

| 端点                 | 方法      | 认证                       |
|----------------------|-----------|----------------------------|
| `/api/v1/health`     | GET       | 无（回环或 token）         |
| `/api/v1/modules`    | GET       | Bearer token               |
| `/api/v1/config`     | GET / PUT | Bearer token + CSRF/Origin |
| `/api/v1/certs`      | GET       | Bearer token               |
| `/api/v1/acme/renew` | POST      | Bearer token               |
| `/api/v1/metrics`    | GET       | 仅回环                     |

首次启动生成一次性管理员令牌写入 `data/admin.token`，权限 `0600`；首次登录改密后令牌失效。

#### M1.4 可观测性基线

| 信号       | 实现                                                                                                   |
|------------|--------------------------------------------------------------------------------------------------------|
| 结构化日志 | `tracing` JSON 格式化；请求 ID 经 `tower-http::trace` 传播                                             |
| 指标       | `metrics` + `metrics-exporter-prometheus`；启动时注册                                                  |
| 审计日志   | SQLite 表 `audit(ts, actor, action, resource, outcome, metadata_json)`；登录、配置变更、证书操作均写入 |
| 健康探针   | `/healthz`（存活）与 `/readyz`（就绪：配置已加载、存储已打开、监听已绑定）                             |

**M1 退出标准：** 两个虚拟主机真实 HTTP/HTTPS 代理；证书导入与 ACME staging 签发成功；API 强制认证；审计记录存在；Prometheus
指标可抓取。

---

### M2 — 安全与认证（4 周）

#### M2.1 WAF（`fg-waf`）

`coraza-rs` 通过官方 C 绑定提供 OWASP Coraza 的安全 Rust 绑定；Coraza 是基于 Go 的 WAF，兼容 ModSecurity SecLang。构建依赖：Go
≥1.21、C 编译器、libclang。

| 任务             | 细节                                                                                                                                           |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| 构建集成         | `build.rs` 调用 `go build -buildmode=c-archive`；链接 `libcoraza.a`                                                                            |
| WAF 实例生命周期 | 每站点一个 `WafConfig`，启动时加载；`DetectionOnly` 或 `On` 可配置                                                                             |
| 事务处理         | Phase 0（连接/URI）→ Phase 1（请求头）→ Phase 2（请求体，若 `SecRequestBodyAccess On`）→ Phase 3（响应头）→ Phase 4（响应体）→ Phase 5（日志） |
| 失败模式         | 管理面：`fail-close`（WAF 错误时阻断）。业务面：默认 `fail-open`，可配置并记录                                                                 |
| 自定义规则       | `SecRule` 指令可从文件加载；CRS v4 从内嵌或挂载规则集加载                                                                                      |
| 指标             | `fgate_waf_interventions_total{site, action}`                                                                                                  |

**测试：** 包含已知 CRS 触发载荷的请求（如 `?id=1' OR '1'='1`）在 `SecRuleEngine On` 下必须返回 403；同一请求在
`DetectionOnly` 下通过。

#### M2.2 入侵防护（`fg-ban`）

`fail2ban-rs` 是纯 Rust 替代品，单二进制约 5 MB，nftables/iptables/ipset 后端，在 `table inet fail2ban-rs` 中按 jail 创建
set。

| 任务          | 细节                                                                             |
|---------------|----------------------------------------------------------------------------------|
| 日志规则引擎  | 对 `fgate` 访问日志进行正则/两阶段匹配；按 jail 配置阈值与时长                   |
| nftables 后端 | `executor_nftables` 创建 `table inet ferrumgate-ban`、按 jail 的 set；关闭时拆除 |
| 封禁升级      | 首次 10 分钟 → 重复 1 小时 → 持续 24 小时（按 jail 可配）                        |
| 白名单        | CIDR 集合始终排除；回环与私有网段默认白名单                                      |
| IPv6 处理     | 端口扫描封禁使用 `/64` 严格模式；单 IP 封禁使用 `/128`                           |
| API           | `POST /api/v1/ban`（手动）、`DELETE /api/v1/ban/{ip}`                            |

**测试：** 60 秒内触发 5 次失败认证；验证 IP 出现在 `nft list set inet ferrumgate-ban sshd`；封禁时长后验证移除。

#### M2.3 认证（`fg-auth`）

| 子 feature                 | Crate             | 测试                             |
|----------------------------|-------------------|----------------------------------|
| 本地认证                   | `argon2` 密码哈希 | 登录、登出、会话过期             |
| OIDC（`auth-oidc`）        | `openidconnect`   | Mock IdP；token 校验；claim 映射 |
| TOTP（`auth-totp`）        | `totp-rs`         | 注册、验证、拒绝错误码           |
| Passkeys（`auth-passkey`） | `webauthn-rs`     | 软件认证器注册与断言             |

**M2 退出标准：** OWASP CRS 核心规则在阻断模式下通过；封禁在 `nft list ruleset` 可见；MFA 登录可用；所有安全测试通过。

---

### M3 — 可选模块（5 周）

#### M3.1 DDNS（`fg-ddns`）

Gately 支持 11 家 DNS 服务商、URL/网卡/命令取 IP、IPv4/IPv6、Webhook。

| 任务                    | 细节                                                                        |
|-------------------------|-----------------------------------------------------------------------------|
| `Provider` trait        | `async fn update(&self, domain: &str, ip: IpAddr) -> Result<UpdateOutcome>` |
| IP 检测策略             | URL（`reqwest`）、网卡接口（`get_if_addrs`）、命令（仅结构化 JSON 输出）    |
| M3 实现的提供商         | Cloudflare、阿里云 DNS、DNSPod、DuckDNS、No-IP                              |
| 剩余 6 家（M3 延伸/M4） | 华为云 DNS、Namecheap、GoDaddy、deSEC、FreeDNS、自定义 Webhook              |
| 调度器                  | 按提供商间隔；失败退避；`fgate_ddns_updates_total{provider, outcome}`       |

**测试：** Mock 提供商 API；验证更新载荷、5xx 重试、IP 变化检测。

#### M3.2 L4 / SNI 路由（`fg-l4`）

Gately 的“协议分流”模块按 SNI 与 ALPN 多路复用 TLS，按 Host 分流 HTTP，并识别 SSH、RDP、MQTT、PostgreSQL、Redis 等。

| 任务         | 细节                                                                                                               |
|--------------|--------------------------------------------------------------------------------------------------------------------|
| TCP 监听     | `tokio::net::TcpListener`；窥探 `ClientHello` 而不消费                                                             |
| SNI 提取     | 解析 TLS ClientHello 扩展 0（server_name）                                                                         |
| ALPN 提取    | 解析扩展 16                                                                                                        |
| 魔法字节路由 | 可配置前缀表：SSH（`SSH-`）、RDP、PostgreSQL（`\x00\x00\x00\x08\x04\xd2\x16\x2f`）、Redis（`*`）、MQTT（`\x10`）等 |
| 端口转发     | TCP/UDP、IPv4/IPv6、端口段、多目标故障转移、连接数限制                                                             |

#### M3.3 NAT / STUN 穿透（`fg-nat`）

| 任务           | 细节                                                    |
|----------------|---------------------------------------------------------|
| STUN 发现      | 查询公共 STUN 服务器；检测 NAT 类型（全锥、受限、对称） |
| TCP 打洞       | 同时打开，带重试与保活                                  |
| UDP 打洞       | 保活间隔可配（默认 25 秒）                              |
| UPnP / NAT-PMP | 可选端口映射，通过 `igd` crate                          |
| 变化触发       | 公网 IP 变化时 Webhook + 脚本                           |

**M3 退出标准：** DDNS 对 mock 提供商更新成功；SNI 路由正确分发两个 TLS 后端；两个 NAT 后对等体 STUN 穿透演示。

---

### M4 — 构建站点与迁移（4 周）

#### M4.1 `fg-buildctl` — 构建站点后端

Gately 的构建站点将选择转换为 `no_<module>` 与 `lang_*` 构建标签；`tools/custombuild` 将选择转换为这些参数。FerrumGate
将其映射为 Cargo features。

**`POST /api/v1/builds` 请求：**

```json
{
  "version": "0.1.0",
  "target": "x86_64-unknown-linux-musl",
  "features": [
    "core",
    "proxy",
    "acme",
    "waf",
    "ban"
  ],
  "artifacts": [
    "binary",
    "docker"
  ],
  "preset": "security"
}
```

**服务端校验流水线：**

| 步骤 | 检查                                                 | 失败响应                 |
|------|------------------------------------------------------|--------------------------|
| 1    | 每个 feature 存在于 `features.toml`                  | `400 unknown_feature`    |
| 2    | 依赖闭包满足（`waf` → `proxy`）                      | `400 missing_dependency` |
| 3    | 目标三元组在白名单内                                 | `400 unsupported_target` |
| 4    | 速率限制（5 次构建 / IP / 小时；20 次 / token / 天） | `429 rate_limited`       |
| 5    | feature 数量 ≤ 25                                    | `400 feature_limit`      |

**生成命令（绝不 shell 插值）：**

```bash
cargo build --release --locked \
  --no-default-features \
  --features "core,proxy,acme,waf,ban" \
  --target x86_64-unknown-linux-musl
```

**每个成功构建的产物流水线：**

1. 二进制 → `strip` → `sha256sum` → `fgate-{version}-{target}`。
2. `cargo cyclonedx --format json --output-file fgate-{version}-{target}.sbom.cdx.json`。
3. `cosign sign-blob --keyless --output-signature fgate.sig fgate`，SBOM 同样处理。
4. Docker：使用 musl 时多阶段 `Dockerfile`，运行时 `FROM scratch`。
5. 上传对象存储；在 `GET /api/v1/builds/{id}` 返回签名 URL。

#### M4.2 多架构 CI 矩阵

GitHub Actions 交叉编译矩阵：

```yaml
strategy:
  matrix:
    include:
      - target: x86_64-unknown-linux-musl
        os: ubuntu-latest
      - target: aarch64-unknown-linux-musl
        os: ubuntu-latest
        cross: true
      - target: x86_64-apple-darwin
        os: macos-latest
      - target: aarch64-apple-darwin
        os: macos-latest
      - target: x86_64-pc-windows-msvc
        os: windows-latest
```

`aarch64-unknown-linux-musl` 使用 `cross`（基于 Docker 的零配置交叉编译）或 `cargo-zigbuild`。

#### M4.3 迁移工具

`fgate migrate gately --config ./gately.json --out ./ferrumgate.toml --report ./migration-report.json`

| Gately 配置段    | FerrumGate 段     | 字段映射说明                                                 |
|------------------|-------------------|--------------------------------------------------------------|
| `web_services[]` | `[[proxy.sites]]` | `domain`、`upstream`、`tls`、`auth`、`waf`                   |
| `acme`           | `[acme]`          | `email`、`provider`、`domains[]`、`challenge_type`           |
| `ddns`           | `[ddns]`          | `provider`、`credentials`、`interval`、`ip_detection`        |
| `waf`            | `[waf]`           | `mode`（`DetectionOnly`/`On`）、`body_limit`、`rule_toggles` |
| `guard`          | `[ban]`           | `jails[]`、`whitelist[]`、`ban_duration`、`find_time`        |
| `stun`           | `[nat]`           | `stun_server`、`keepalive_interval`、`upnp`                  |

不支持的字段 → `migration-report.json` 条目，含 `severity: warning`、`field_path`、`suggestion`。

**M4 退出标准：** 用户所选 feature 生成已签名二进制与 SBOM；Docker 镜像在 `scratch` 上运行；Web 服务、ACME、DDNS fixture
核心字段迁移率 ≥90%。

---

### M5 — 加固与 GA（3 周）

| 任务      | 细节                                                        | 验收               |
|-----------|-------------------------------------------------------------|--------------------|
| 模糊测试  | `cargo-fuzz` 对 HTTP 头解析、TLS ClientHello 解析、配置解析 | 72 小时无崩溃      |
| 负载测试  | `oha` / `k6` 压测代理；与 Gately 同配置对比 p99             | p99 ≤ Gately + 10% |
| 安全评审  | 威胁模型、认证绕过、WAF 绕过、构建站点注入                  | 无阻断性发现       |
| 依赖审计  | `cargo deny check` + `cargo audit --deny warnings`          | 零未豁免 advisory  |
| SBOM 验证 | `cosign verify-blob` 验证 SBOM 与二进制                     | 签名有效           |
| 回滚演练  | N → N-1 部署，使用旧二进制 + 配置降级迁移                   | RTO < 5 分钟       |
| 文档      | OpenAPI、迁移指南、运维手册                                 | 所有端点有文档     |

**M5 退出标准：** 无阻断性安全问题；性能目标达成；回滚演练通过。

---

## 3. CI/CD 流水线（完整 GitHub Actions 规范）

### 3.1 PR 门禁

每个 PR 运行五个阻断性 job：

| Job              | 命令                                                                      | 超时    |
|------------------|---------------------------------------------------------------------------|---------|
| `fmt`            | `cargo fmt --all --check`                                                 | 2 分钟  |
| `clippy`         | `cargo clippy --workspace --all-targets --all-features -- -D warnings`    | 15 分钟 |
| `test`           | `cargo nextest run --workspace`                                           | 20 分钟 |
| `feature-matrix` | `cargo hack check --feature-powerset --depth 2 --no-dev-deps --workspace` | 25 分钟 |
| `manifest-check` | `cargo run -p xtask -- check-features`                                    | 2 分钟  |

`cargo-hack` 使用 `--depth 2` 测试每个 feature 单独以及每对组合，在不触发全幂集（2^25）爆炸的前提下捕获大多数真实 feature
交互问题。FerrumGate 的 25 个 feature 在 depth 2 下约产生 325 次检查调用，在 CI 超时范围内。

### 3.2 供应链 Job（每个 PR + 每日夜间）

```yaml
- name: cargo-deny
  run: cargo deny check
- name: cargo-audit
  run: cargo audit --deny warnings
```

`deny.toml` 策略：

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
yanked = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-3.0"]

[bans]
multiple-versions = "warn"
deny = [
    { name = "openssl-sys", reason = "rustls is the TLS backend" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

`cargo audit` 默认工作区感知（读取 `Cargo.lock`）；`cargo deny` 图感知。两者基于同一 lockfile 运行。

### 3.3 发布 Job（Tag push `v*`）

| 步骤     | 命令 / Action                                                               |
|----------|-----------------------------------------------------------------------------|
| 构建矩阵 | 6 个目标（见 §M4.2）                                                        |
| SBOM     | `cargo cyclonedx --format json --output-file target/{target}.sbom.cdx.json` |
| 签名     | `cosign sign-blob --keyless target/{target}/fgate` + SBOM 同样              |
| Docker   | Buildx 多架构 `linux/amd64`、`linux/arm64`、`linux/arm/v7`                  |
| 校验和   | 每个产物 `sha256sum`                                                        |
| 发布     | GitHub Release 附带二进制、`.sbom.cdx.json`、`.sig`、`.sha256`              |

---

## 4. 测试策略（可执行矩阵）

| 测试层       | 工具                                      | 范围                                                    | 运行时机  |
|--------------|-------------------------------------------|---------------------------------------------------------|-----------|
| 单元         | `cargo test` / `nextest`                  | `fg-config`、`fg-certs`、`fg-acme`、`fg-ban`、`fg-ddns` | 每个 PR   |
| 集成         | `testcontainers` + `fgate` 二进制         | 代理、TLS SNI、WebSocket、gRPC、ACME（Pebble）          | 每个 PR   |
| Feature 矩阵 | `cargo hack --feature-powerset --depth 2` | 所有成对组合                                            | 每个 PR   |
| 安全         | 自定义 harness + `cargo-fuzz`             | WAF 绕过、认证绕过、路径穿越                            | 夜间 + M5 |
| 并发         | `loom`                                    | 封禁列表状态转换                                        | M2 起     |
| 属性         | `proptest`                                | 配置解析、头部处理                                      | 每个 PR   |
| 性能         | `oha` / `k6`                              | 代理 p99、吞吐                                          | M5 + 发布 |
| 迁移         | Fixture JSON → 预期 TOML                  | Gately 配置                                             | M4 起     |

**ACME 测试：** CI 中运行 Pebble；针对 challenge test server 签发；通过操纵存储的 `expires_at` 验证续期调度在
`expires_at - 30 days` 触发。

**WAF 测试：** CRS v4 回归套件：50 个精选请求（SQLi、XSS、LFI、RCE、协议违规）在 `On` 模式下必须返回预期 `403`，在`DetectionOnly`
下 `200`。

---

## 5. 构建矩阵（显式 feature 集）

```yaml
strategy:
  matrix:
    features:
      - "core"
      - ""                          # 默认 feature
      - "core,proxy,acme,certs"
      - "core,proxy,waf,ban"
      - "core,proxy,acme,ddns,l4,nat"
      - "core,proxy,acme,waf,ban,ddns,l4,nat,auth-oidc,auth-totp"
      - "--all-features"
      - "--no-default-features"
```

每个条目运行 `cargo check --locked --no-default-features --features "$FEATURES"`。至少 `core`、默认、`core,proxy,waf,ban`
运行完整集成测试。

---

## 6. 风险登记册与具体缓解措施

| 风险                                          | 概率 | 影响 | 具体缓解                                                      | 回滚触发                                |
|-----------------------------------------------|-----:|-----:|---------------------------------------------------------------|-----------------------------------------|
| `coraza-rs` 在 musl 上 FFI 构建失败           |   中 |   高 | CI Docker 镜像中预构建 `libcoraza.a`；缓存 Go 模块依赖        | 关闭 `waf` feature；发布不含 WAF 的版本 |
| Feature 依赖环发现过晚                        |   中 |   高 | M0 阶段 `xtask check-features` 运行拓扑排序                   | 移除问题 feature；重构 `depends`        |
| ACME 速率限制（Let’s Encrypt：50 证书/域/周） |   低 |   中 | 测试用 staging 端点；按域签发计数器，40/周告警                | 回退手动导入                            |
| DDNS 提供商 API 破坏性变更                    |   高 |   中 | 每个提供商独立 feature；按提供商集成测试基于录制 fixture      | 补丁版本禁用单个提供商 feature          |
| 构建站点滥用（通过 CI 挖矿）                  |   中 |   高 | 队列隔离、5 次/IP/小时、禁止任意 `RUSTFLAGS`、签名产物        | 暂停构建队列；要求 token 才能构建       |
| 容器中 nftables 后端不可用                    |   中 |   中 | 启动时检测；回退 `iptables` 或记录降级模式                    | 运行时禁用 `ban` feature（配置）        |
| Go 基线性能回退                               |   低 |   中 | 基准 harness 在同主机运行 `fgate` 与 Gately                   | 接受有记录的差值或优化热路径            |
| `cargo-hack` CI 超时（25 feature，depth 2）   |   中 |   中 | 缓存依赖；feature 矩阵仅在夜间 + 合并队列运行，非每次 PR push | PR 降级为 `--each-feature`，夜间全幂集  |

---

## 7. 验收标准（完成定义）— 扩展版

一个 feature **完成** 当且仅当 **全部** 满足：

- [ ] 在 `features.toml` 中声明 `name`、`display`、`default`、`risk`、`depends`、`gately_equiv`。
- [ ] `#[cfg(feature = "...")]` 在 `--no-default-features` **和** `--all-features` 下均可编译。
- [ ] 引入该 feature 的 crate 通过 `cargo hack check --each-feature`。
- [ ] 单元测试覆盖公开函数；集成测试在临时端口以启用该 feature 的 `fgate` 启动。
- [ ] 至少发出一个带 `fgate_` 前缀的 Prometheus 指标。
- [ ] 初始化时 `info` 级结构化日志事件，失败时 `error` 级，含 `module` 字段。
- [ ] 若涉及 WAF、封禁、认证或管理 API：安全评审完成，负向测试存在。
- [ ] `DESIGN.md` 技术表与 `EXECUTION.md` 里程碑映射已更新。
- [ ] `cargo run -p xtask -- check-features` 通过。
- [ ] Feature 至少出现在一个 CI 构建矩阵条目中。

---

## 8. 交付物（发布检查清单）

| 产物           | 格式                                                                          | 验证                                                       |
|----------------|-------------------------------------------------------------------------------|------------------------------------------------------------|
| `fgate` 二进制 | 静态 musl（x86_64、aarch64）、macOS（x86_64、aarch64）、Windows MSVC、FreeBSD | `file` 显示静态链接；在 `scratch` 中运行                   |
| Docker 镜像    | 多架构 `amd64`、`arm64`、`arm/v7`                                             | `docker run --rm ferrumgate/fgate:version fgate --version` |
| SBOM           | 每个产物 CycloneDX JSON                                                       | `cosign verify-blob` 通过                                  |
| 签名           | cosign keyless                                                                | `cosign verify-blob --certificate-identity ...` 通过       |
| 校验和         | 每个产物 SHA-256                                                              | 与发布校验和文件一致                                       |
| OpenAPI 规范   | `docs/openapi.json`                                                           | `openapi-diff` 无破坏性变更                                |
| 迁移报告       | 每个 Gately 配置的 JSON                                                       | 核心字段覆盖率 ≥90%                                        |
| 安全报告       | Markdown                                                                      | 无阻断性发现                                               |
| 性能基线       | Markdown + 原始 `oha` 输出                                                    | p99 已记录                                                 |
| 回滚 Runbook   | Markdown                                                                      | M5 演练完成                                                |

---
