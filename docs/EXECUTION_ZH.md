> 历史方案。当前架构、贡献规范与执行命令见 [DESIGN.md](DESIGN.md)、[AGENT.md](AGENT.md) 和 [EXECUTION.md](EXECUTION.md)。

## EXECUTION.md — 架构执行计划

### 1. 执行摘要

**可行性：高。** Rust 生态以生产级 crate 覆盖了 Gately 的每一项能力。两个工程热点：

1. **WAF**：使用 `coraza-rs` FFI 保证 OWASP CRS v4 等价性；纯 Rust 规则引擎明确排除在 v1 之外。
2. **DDNS 提供商广度**：Gately 支持 11 家；FerrumGate 在 M1 交付 `Provider` trait 并实现 5 家，M2 完成剩余 6 家。

Cargo Features 干净地映射 Gately 的 `no_<module>` 构建标签。构建站点逻辑是 `cargo build` 之上的薄校验层。

### 2. 里程碑计划

| 里程碑                  | 周期 | 范围                                                                                         | 退出标准                                                                        |
|-------------------------|-----:|----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| **M0 — 骨架**           | 2 周 | 工作区、`features.toml`、`xtask`、CI、`fg-core` trait、`fg-config` schema                    | `core`、默认、全 feature、`--no-default-features` 构建通过；`check-features` 绿 |
| **M1 — 核心网关**       | 4 周 | `fg-proxy`、`fg-certs`、`fg-acme`、`fg-api`、`fg-webui`、本地认证、审计、指标                | 真实 HTTP/HTTPS 代理；证书导入；ACME staging 签发；API 认证生效                 |
| **M2 — 安全与认证**     | 4 周 | `fg-waf`（coraza-rs）、`fg-ban`（nftables）、OIDC/TOTP/Passkeys、fail2ban 风格 jail          | OWASP CRS 核心规则通过；`nft list ruleset` 可见封禁；MFA 登录可用               |
| **M3 — 可选模块**       | 5 周 | `fg-ddns`（11 家）、`fg-l4`（SNI/ALPN）、`fg-nat`（STUN）、Docker/frp/Cloudflare Tunnel 适配 | DDNS 更新成功；SNI 路由正确；STUN 穿透演示                                      |
| **M4 — 构建站点与迁移** | 4 周 | `fg-buildctl`、多架构产物、SBOM、签名、`migrate gately`                                      | 用户所选 feature 生成已签名二进制；Gately 核心字段迁移率 ≥90%                   |
| **M5 — 加固与 GA**      | 3 周 | 模糊测试、压测、安全评审、文档、回滚演练                                                     | 无阻断性安全问题；p99 代理延迟 ≤ Go 基线 +10%；回滚演练通过                     |

### 3. 工作分解结构

| 工作流           | 主要 crate                   | 负责角色   | 关键交付                                |
|------------------|------------------------------|------------|-----------------------------------------|
| 运行时与生命周期 | `fg-core`、`fg-runtime`      | 架构师     | Module trait、注册表、优雅关闭          |
| 配置             | `fg-config`                  | 后端       | Schema、校验、热加载、迁移              |
| 代理与路由       | `fg-proxy`、`fg-l4`          | 网络工程师 | HTTP/WS/gRPC 代理、SNI/ALPN 路由        |
| TLS 与 ACME      | `fg-acme`、`fg-certs`        | 安全/网络  | 签发、续期、rustls resolver             |
| WAF              | `fg-waf`                     | 安全工程师 | coraza-rs 适配、CRS v4 加载、按站点开关 |
| 入侵防护         | `fg-ban`                     | 安全工程师 | Jail 引擎、nftables/iptables/ipset 后端 |
| 认证             | `fg-auth`                    | 后端/安全  | 本地、OIDC、TOTP、Passkeys              |
| API 与 UI        | `fg-api`、`fg-webui`、`web/` | 全栈       | 管理控制台、feature 选择器              |
| DDNS 与 NAT      | `fg-ddns`、`fg-nat`          | 后端       | Provider trait、11 家提供商、STUN 穿透  |
| 构建站点         | `fg-buildctl`                | DevOps     | 任务队列、白名单、CI 触发、产物签名     |
| 测试与 CI        | `tests/`、`xtask`            | QA/DevOps  | Feature 矩阵、SBOM、可复现构建          |

### 4. CI 构建矩阵

每个 PR 运行：

```yaml
strategy:
  matrix:
    features:
      - "core"
      - ""                          # 默认 feature
      - "core,proxy,acme,certs"
      - "core,proxy,waf,ban"
      - "core,proxy,acme,ddns,l4,nat"
      - "--all-features"
      - "--no-default-features"
```

每个矩阵条目执行 `cargo check --locked --no-default-features --features "$FEATURES"`，至少 core 与默认条目执行完整
`cargo test`。

### 5. 构建站点 API 契约

**`POST /api/v1/builds`**

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
  ]
}
```

服务端校验：

1. 请求的每个 feature 存在于 `features.toml`。
2. 依赖闭包满足（如 `waf` → `proxy`）。
3. 目标三元组在白名单内。
4. 按 IP/token 限流。

响应：

```json
{
  "job_id": "bld_01J...",
  "status": "queued",
  "estimated_seconds": 420
}
```

**`GET /api/v1/builds/{id}`** 返回 `status`、`logs_url`、`artifact_urls`、`sha256`、`sbom_url`、`signature_url`。

### 6. 迁移策略

第一阶段映射（必须通过）：

| Gately 配置段  | FerrumGate 段   | 说明                       |
|----------------|-----------------|----------------------------|
| `web_services` | `[proxy.sites]` | 域名、后端、TLS、认证字段  |
| `acme`         | `[acme]`        | 邮箱、提供商、域名         |
| `ddns`         | `[ddns]`        | 提供商、凭据、间隔         |
| `waf`          | `[waf]`         | 模式、规则开关、请求体限制 |
| `intrusion`    | `[ban]`         | Jail、白名单、时长         |

迁移工具行为：

- 读取 Gately JSON 配置。
- 输出 FerrumGate TOML。
- 生成 `migration-report.json`，列出不支持字段与建议的手动操作。
- **不**修改源 Gately 配置。

### 7. 风险登记册

| 风险                 | 概率 | 影响 | 缓解                                                                            | 回滚                         |
|----------------------|-----:|-----:|---------------------------------------------------------------------------------|------------------------------|
| coraza-rs FFI 不稳定 |   中 |   高 | WAF 运行在隔离的 `spawn_blocking` 并带超时；管理面 fail-close，业务面 fail-open | 关闭 `waf` feature           |
| Feature 组合爆炸     |   高 |   高 | 生成注册表 + CI 矩阵 + `xtask check-features`                                   | 锁定默认 feature 集          |
| DDNS 提供商 API 漂移 |   高 |   中 | `Provider` trait 隔离；按提供商集成测试                                         | 禁用单个提供商 feature       |
| ACME 续期失败        |   中 |   高 | 指数退避、到期告警、手动导入兜底                                                | 从存储恢复上一证书           |
| 构建站点滥用         |   中 |   高 | Feature 白名单、限流、队列隔离、产物签名                                        | 暂停构建队列                 |
| Go 基线性能回退      |   低 |   中 | 相同配置下基准对比 `fgate` vs Gately；p99 目标 ≤ +10%                           | 优化热路径或接受有记录的差值 |

### 8. 验收标准（完成定义）

一个 feature **完成**当且仅当：

- [ ] 在 `features.toml` 中声明，依赖与风险等级正确。
- [ ] `#[cfg(feature = "...")]` 在 `--no-default-features` 与 `--all-features` 下均可编译。
- [ ] 单元测试覆盖公开函数；集成测试以启用该 feature 的 `fgate` 启动。
- [ ] 输出结构化日志与至少一个 Prometheus 指标。
- [ ] 若涉及 WAF、封禁、认证或管理 API，安全评审已完成。
- [ ] `DESIGN.md` 技术表与 `EXECUTION.md` 里程碑映射已更新。
- [ ] `cargo run -p xtask -- check-features` 通过。

### 9. 交付物

| 交付物         | 格式                                        | 负责人     |
|----------------|---------------------------------------------|------------|
| `fgate` 二进制 | 静态 Linux（musl）、macOS、Windows、FreeBSD | 发布工程   |
| Docker 镜像    | 多架构（`amd64`、`arm64`、`arm/v7`）        | 发布工程   |
| SBOM           | CycloneDX JSON                              | CI         |
| 签名           | cosign / minisign                           | CI         |
| 迁移工具       | `fgate migrate gately`                      | 后端       |
| OpenAPI 规范   | `docs/openapi.json`                         | API 负责人 |
| 安全评审       | Markdown 报告                               | 安全       |
| 性能基线       | Markdown + Grafana 快照                     | QA         |
