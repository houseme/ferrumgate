> 历史方案。当前架构、贡献规范与执行命令见 [DESIGN.md](docs/DESIGN.md)、[AGENT.md](docs/AGENT.md) 和 [EXECUTION.md](docs/EXECUTION.md)。

# ARCHITECTURE_EXECUTION.md — FerrumGate 架构设计与执行文档

# 项目命名

## 名称：**FerrumGate**

- **英文名**：FerrumGate
- **中文名**：铁门网关
- **Cargo workspace 前缀**：`ferrumgate`
- **二进制名**：`fgate`
- **模块 crate 前缀**：`fg-`
- **命名理由**：
    - `Ferrum` 为拉丁语“铁”，呼应 Rust 的“铁锈/铁”语义；
    - `Gate` 延续 [Gately](https://github.com/wangwanjie/gately) 的网关定位；
    - 名称短、可注册、适合作为单二进制网关、构建站点与品牌名；
    - 可衍生：`FerrumGate Build`、`fgate-build`、`FerrumGate Cloud`。

## 1. 文档目的

本文档定义 FerrumGate 用 Rust 重写 [Gately](https://github.com/wangwanjie/gately)
的架构方案、实施阶段、工作分解、验收标准、测试矩阵、构建站点方案与风险控制。本文档面向架构师、Rust
工程师、DevOps、安全评审与 AI 编码代理。

## 2. 可行性结论

**结论：可实现，工程复杂度中等偏高。**

- 网络核心、TLS、ACME、认证、可观测性在 Rust 生态成熟。
- Cargo Features 可原生实现 [Gately](https://github.com/wangwanjie/gately) 的“编译期可选安装”。
- 最大技术决策点是 WAF：建议优先 `coraza-rs` FFI 保证 OWASP CRS 兼容，纯 Rust 实现作为长期探索。
- DDNS 提供商数量多但模式统一，可通过 Provider trait 分批实现。
- 构建站点逻辑可复用 Gately 思路：用户选择 → feature 白名单 → `cargo build --no-default-features --features ...` → 产物签名。

## 3. 总体架构

```text
┌─────────────────────────────────────────────────────────────┐
│                        fgate 单二进制                        │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ fg-runtime  │  │ fg-config   │  │ fg-observability    │  │
│  │ 生命周期    │  │ 配置/热加载 │  │ 日志/指标/追踪/审计 │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                    │             │
│  ┌──────▼────────────────▼────────────────────▼──────────┐  │
│  │              fg-core: Module Registry / Context        │  │
│  └──────┬──────────────┬──────────────┬──────────────────┘  │
│         │              │              │                     │
│  ┌──────▼─────┐ ┌──────▼─────┐ ┌──────▼─────┐               │
│  │ fg-proxy   │ │ fg-l4      │ │ fg-acme    │               │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘               │
│  ┌──────▼─────┐ ┌──────▼─────┐ ┌──────▼─────┐               │
│  │ fg-ddns    │ │ fg-waf     │ │ fg-ban     │               │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘               │
│  ┌──────▼─────┐ ┌──────▼─────┐ ┌──────▼─────┐               │
│  │ fg-auth    │ │ fg-api     │ │ fg-webui   │               │
│  └────────────┘ └────────────┘ └────────────┘               │
└─────────────────────────────────────────────────────────────┘

外部：
  build.gately.cn 同类站点 → fg-buildctl → CI/CD → 定制产物
```

## 4. 进程模型

- 单进程 Tokio 多任务；管理面与业务面可分离监听。
- 模块生命周期：`load config → validate → init → run → shutdown`。
- 每个模块拥有独立 `CancellationToken`，支持优雅关闭。
- 关键后台任务：ACME 续期、DDNS 更新、封禁过期清理、证书清理、构建任务轮询。
- 管理 API 与业务代理使用独立限流与超时策略。

## 5. 核心抽象

### 5.1 ModuleContext

```rust
pub struct ModuleContext {
    pub config: Arc<Config>,
    pub storage: Arc<dyn Storage>,
    pub metrics: Arc<Metrics>,
    pub tracer: Arc<Tracer>,
    pub cancel: CancellationToken,
    pub feature_set: FeatureSet,
}
```

### 5.2 Registry

```rust
pub struct Registry {
    modules: Vec<Box<dyn Module>>,
}

impl Registry {
    pub fn validate_dependencies(&self) -> Result<()> { /* ... */ }
    pub async fn init_all(&self, ctx: &ModuleContext) -> Result<()> { /* ... */ }
    pub async fn shutdown_all(&self, ctx: &ModuleContext) -> Result<()> { /* ... */ }
}
```

### 5.3 Feature 元数据

`features.toml` 示例：

```toml
[[feature]]
name = "proxy"
display = "反向代理"
default = true
risk = "low"
depends = ["core"]
description = "HTTP/HTTPS 反向代理、WebSocket、gRPC"

[[feature]]
name = "waf"
display = "WAF / OWASP CRS"
default = false
risk = "high"
depends = ["proxy"]
description = "基于 Coraza 的 WAF 防护"

[[feature]]
name = "ddns"
display = "动态 DNS"
default = false
risk = "medium"
depends = ["core"]
description = "多提供商 DDNS 更新"
```

`xtask` 生成：

- `registry.generated.rs`
- `modules.json`
- `web/src/generated/features.json`
- 构建站点 feature 白名单

## 6. 功能模块实施映射

| 能力       | Rust 方案                 | 实施优先级 | 验收标准                                      |
|------------|---------------------------|-----------:|-----------------------------------------------|
| 反向代理   | axum/hyper/tower          |         P0 | HTTP/1.1、HTTP/2、WebSocket、gRPC、逐跳头正确 |
| 自动 HTTPS | instant-acme + rustls     |         P0 | 申请、续期、失败重试、状态可观测              |
| 证书管理   | 存储 + rustls resolver    |         P0 | 导入、热加载、到期告警                        |
| 管理 API   | axum                      |         P0 | 认证、审计、限流                              |
| Web UI     | React/Vue + include_dir   |         P0 | 模块选择、配置、证书、日志                    |
| 认证       | 本地 + OIDC/TOTP/Passkeys |      P0/P1 | 登录、MFA、会话安全                           |
| DDNS       | Provider trait            |         P1 | 首批 5 家，后续扩展                           |
| L4/SNI     | tokio + SNI 解析          |         P1 | TCP/UDP 分流、ALPN                            |
| NAT 穿透   | 隧道库思路                |         P2 | 反向连接、断线重连                            |
| WAF        | coraza-rs FFI             |         P1 | OWASP CRS 核心规则通过                        |
| Fail2ban   | nftables/iptables/ipset   |         P1 | 自动封禁、白名单、过期                        |
| 构建站点   | axum + CI API             |         P1 | feature 白名单、任务隔离、产物签名            |
| 可观测性   | tracing/metrics/otlp      |         P0 | 日志、指标、追踪、审计                        |

## 7. 分阶段执行计划

### M0：对齐与骨架（1-2 周）

- 对齐 Gately 与 `build.gately.cn` 功能清单。
- 建立 workspace、`features.toml`、`xtask`、CI 骨架。
- 实现 `fg-core` Module trait、Registry、Config 基础。
- 输出 `modules.json` 与前端 feature 清单。
- 验收：默认构建、最小构建、全 feature 构建均可编译。

### M1：核心网关 MVP（3-4 周）

- 反向代理、TLS、证书存储、管理 API、基础 Web UI。
- 本地认证 + 审计日志 + Prometheus 指标。
- 配置热加载与校验。
- 验收：可代理真实 HTTP/HTTPS 服务；证书可导入；API 有认证与审计。

### M2：自动化与安全（3-4 周）

- ACME 自动证书申请与续期。
- Fail2ban 式封禁；nftables/iptables/ipset 后端。
- 认证扩展：OIDC、TOTP、Passkeys 子 feature。
- 验收：ACME 测试环境通过；封禁规则可观测；MFA 登录通过安全测试。

### M3：可选模块扩展（4-6 周）

- DDNS Provider trait 与首批提供商。
- L4/SNI 路由。
- NAT 穿透原型。
- WAF `coraza-rs` 适配与规则加载。
- 验收：DDNS 更新成功；SNI 分流正确；WAF 核心 CRS 规则通过。

### M4：构建站点与发布（3-4 周）

- `fg-buildctl`：创建构建任务、feature 白名单、队列、状态查询。
- CI/CD：多 feature 矩阵、产物签名、SBOM、Docker/安装包。
- 迁移工具：Gately 配置迁移。
- 验收：用户选择 feature 后生成定制二进制；产物可验证签名；迁移报告完整。

### M5：加固与 GA（2-3 周）

- 安全评审、模糊测试、性能压测、故障注入。
- 文档、升级策略、回滚策略。
- 验收：安全评审通过；性能达标；回滚演练成功。

## 8. 工作分解与责任

| 工作流     | 主要 crate            | 负责角色   | 关键交付                         |
|------------|-----------------------|------------|----------------------------------|
| 核心运行时 | fg-core, fg-runtime   | 架构/后端  | Module trait、Registry、生命周期 |
| 配置       | fg-config             | 后端       | Schema、热加载、迁移             |
| 代理       | fg-proxy              | 网络工程师 | HTTP/WS/gRPC 代理                |
| TLS/ACME   | fg-acme, fg-certs     | 安全/网络  | 证书申请、续期、存储             |
| DDNS       | fg-ddns               | 后端       | Provider trait + 提供商          |
| 安全       | fg-waf, fg-ban        | 安全工程师 | WAF 适配、封禁                   |
| 认证       | fg-auth               | 安全/后端  | OIDC/TOTP/Passkeys               |
| API/UI     | fg-api, fg-webui, web | 全栈       | 管理面                           |
| 构建站点   | fg-buildctl           | DevOps     | 构建任务与产物                   |
| 测试/CI    | tests, xtask          | QA/DevOps  | 矩阵、SBOM、签名                 |

## 9. 构建站点设计

### 9.1 用户流程

1. 用户访问构建站点，前端读取 `features.json`。
2. 选择模块，前端提交 `POST /api/v1/builds`：
   ```json
   {
     "version": "0.1.0",
     "target": "x86_64-unknown-linux-musl",
     "features": ["core", "proxy", "acme", "ddns"],
     "artifact": ["binary", "docker"]
   }
   ```
3. 后端校验 feature 白名单与依赖闭包。
4. 生成构建任务，调用 CI API，使用固定模板：
   ```bash
   cargo build --release --locked \
     --no-default-features \
     --features "core,proxy,acme,ddns"
   ```
5. 产物：二进制、校验和、SBOM、签名、构建元数据。
6. 用户下载；任务状态可查询。

### 9.2 安全控制

- Feature 白名单，禁止任意 Cargo 参数。
- 目标三元组白名单。
- 队列隔离与速率限制。
- 构建日志脱敏。
- 产物签名与校验和。
- 构建环境可复现：固定 Rust 版本、`Cargo.lock`、容器镜像摘要。

## 10. 测试矩阵

| 构建   | Features                | 目的               |
|--------|-------------------------|--------------------|
| 最小   | `core`                  | 验证核心可独立运行 |
| 默认   | 默认 feature            | 生产默认路径       |
| 代理   | `core,proxy,acme,certs` | 核心网关           |
| 安全   | `core,proxy,waf,ban`    | WAF/封禁           |
| 自动化 | `core,proxy,acme,ddns`  | ACME+DDNS          |
| 全功能 | 所有稳定 feature        | 集成与体积基线     |
| 无默认 | `--no-default-features` | 构建系统健壮性     |

测试类型：

- 单元测试、集成测试、端到端测试；
- 配置迁移测试；
- 证书状态机测试；
- WAF 规则兼容测试；
- 封禁后端测试（nftables/iptables/ipset）；
- 构建站点 API 安全测试；
- 性能压测与故障注入。

## 11. 可观测性与运维

- 日志：`tracing` JSON/文本可切换，请求 ID 贯穿。
- 指标：请求量、延迟、错误率、证书到期、DDNS 更新、封禁计数、构建任务。
- 追踪：可选 OTLP。
- 审计：登录、配置变更、证书操作、封禁、构建任务。
- 健康检查：`/healthz`、`/readyz`。
- 升级：单二进制替换 + 配置版本迁移；支持回滚上一版本。

## 12. 安全与合规

- `cargo deny` 许可证与漏洞检查。
- `cargo audit` 与依赖更新策略。
- SBOM：CycloneDX。
- 产物签名：cosign/minisign。
- 管理面默认认证与 CSRF/Origin 校验。
- WAF 规则加载需签名与版本校验。
- 外部命令调用禁止 shell 拼接。
- 最小权限运行；systemd 加固；容器只读根文件系统可选。

## 13. 迁移与兼容

- `fgate migrate gately --config ./gately.toml --out ./ferrumgate.toml`
- 映射表：
    - Gately 反向代理 → `proxy`
    - Gately 自动 HTTPS → `acme,certs`
    - Gately DDNS → `ddns`
    - Gately WAF → `waf`
    - Gately Fail2ban → `ban`
    - Gately 认证 → `auth` 及子 feature
- 输出不兼容项报告与建议。
- 第一阶段保证核心路径迁移；冷门模块标记为后续。

## 14. 风险与回滚

| 风险                 | 概率 | 影响 | 缓解                   | 回滚               |
|----------------------|-----:|-----:|------------------------|--------------------|
| WAF FFI 稳定性       |   中 |   高 | 隔离进程/超时/失败策略 | 关闭 `waf` feature |
| Feature 组合编译失败 |   中 |   高 | CI 矩阵 + 生成注册表   | 固定默认 feature   |
| 构建站点滥用         |   中 |   高 | 白名单/限流/隔离       | 暂停构建任务       |
| DDNS 提供商差异      |   高 |   中 | Provider trait + 分批  | 禁用单 provider    |
| 证书续期失败         |   中 |   高 | 重试/告警/手动导入     | 回退证书           |
| 性能不达标           |   低 |   中 | 压测/池化/零拷贝       | 调整默认配置       |

## 15. 交付物清单

- `ferrumgate` 源码 workspace；
- `features.toml` 与生成产物；
- `fgate` 单二进制；
- Web UI 静态资源；
- Docker 镜像、deb/rpm、校验和、SBOM、签名；
- Gately 迁移工具；
- 构建站点后端与 API 文档；
- 安全评审报告、性能报告、测试报告；
- 运维手册与升级/回滚手册。

## 16. 最终验收标准

1. 默认构建可生产运行反向代理 + 自动 HTTPS + 管理面。
2. 最小构建仅 `core` 可启动并暴露健康检查。
3. 用户可在构建站点选择 feature 并生成定制二进制。
4. DDNS、WAF、封禁、L4、NAT 至少各有一个可演示路径。
5. Gately 核心配置迁移成功率达到约定阈值（建议 ≥90% 核心字段）。
6. 安全评审无阻断项；供应链检查通过。
7. 性能基线：默认构建空闲内存、P99 代理延迟、证书续期成功率达标。
8. 所有 feature 组合在 CI 矩阵中可编译；关键组合有集成测试。