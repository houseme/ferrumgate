> 历史方案。当前架构、贡献规范与执行命令见 [DESIGN.md](DESIGN.md)、[AGENT.md](AGENT.md) 和 [EXECUTION.md](EXECUTION.md)。

## AGENT.md — 工程代理与贡献规则

### 1. 适用范围

本文档约束人类工程师与 AI 编码代理如何修改 FerrumGate。它是代码生成、评审、测试与文档同步的契约。

### 2. 动手前必读

1. 阅读 `features.toml`，确认目标 feature 存在且 `depends` 与 `risk` 正确。
2. 阅读目标 crate 的 `README.md` 与 `lib.rs` 模块文档。
3. 若新增 feature，必须同步更新 **四份** 产物：
    - `Cargo.toml`（工作区 feature 表）
    - `features.toml`
    - 生成的 `registry.generated.rs`
    - `web/src/generated/features.json`
4. 写代码前先运行 `cargo run -p xtask -- check-features` 确认基线一致。

### 3. 新增 Feature 检查清单

新增 feature `foo` 时：

- [ ] 在 `features.toml` 中声明 `name`、`display`、`default = false`、`risk`、`depends`、`gately_equiv`（如适用）。
- [ ] 在工作区 `Cargo.toml` 中添加 `foo = ["dep:fg-foo"]`。
- [ ] 创建 `crates/fg-foo` 并实现 `Module`。
- [ ] 运行 `cargo run -p xtask -- codegen` 重新生成注册表与 JSON 清单。
- [ ] 将 feature 加入至少一个 CI 构建矩阵条目。
- [ ] 添加集成测试：以 `--features foo` 启动 `fgate` 并验证模块行为。
- [ ] 更新 `DESIGN.md` 技术表与 `EXECUTION.md` 里程碑映射。
- [ ] 若涉及安全（WAF、封禁、认证），添加 `SECURITY.md` 说明与负向测试。

### 4. 核心—模块边界规则

| 规则                                                                                 | 理由                            |
|--------------------------------------------------------------------------------------|---------------------------------|
| `fg-core` **不得** `use fg_waf::...`、`use fg_ban::...` 等                           | 保证编译期可排除性              |
| 跨模块协作使用注入函数或 `ModuleContext` trait                                       | 与 Gately 注入模式一致          |
| 可选 crate 不得出现在 `fg-core` 的 `[dependencies]`；使用 feature 门控的 `dep:` 语法 | 防止意外默认链接                |
| 每个 `#[cfg(feature = "...")]` 必须在 `features.toml` 有对应条目                     | `xtask check-features` 强制校验 |

### 5. 代码风格与安全

- 除 `fg-waf`（FFI 边界）外，每个 crate 使用 `#![forbid(unsafe_code)]`。
- 所有公开 API 带 `///` 文档与用法示例。
- 库中使用 `thiserror`，二进制边界使用 `anyhow`。
- 库代码禁止 `unwrap()` / `expect()`；使用 `?` 并提供上下文错误。
- 可能阻塞的异步操作（DNS、文件 I/O）包裹在 `tokio::task::spawn_blocking` 中。
- Shell 命令通过 `std::process::Command` 以参数数组调用；**禁止** `sh -c`。

### 6. 测试要求

| 测试类型     | 要求                                                                                        |
|--------------|---------------------------------------------------------------------------------------------|
| 单元测试     | `fg-config`、`fg-certs`、`fg-acme`、`fg-ban` 的每个公开函数                                 |
| 集成测试     | 每个 feature 至少一个；在临时端口启动 `fgate`                                               |
| Feature 矩阵 | CI 构建：`core`、默认、`proxy+acme`、`waf+ban`、`ddns`、全 feature、`--no-default-features` |
| 兼容性       | Web 服务、ACME、DDNS 的 Gately 配置迁移样例                                                 |
| 安全         | 认证绕过、路径穿越、WAF 对类 EICAR 载荷的假阴性负向测试                                     |
| 并发         | 封禁列表状态使用 `loom`；配置解析使用 `proptest`                                            |

### 7. 提交前门禁

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo run -p xtask -- check-features
cargo deny check
```

CI 运行相同命令外加 feature 构建矩阵。任何门禁失败 PR 不可合并。

### 8. 文档同步

- `features.toml` 是**单一事实来源**。文档与其冲突时，以 `features.toml` 为准并修正文档。
- `DESIGN.md` 变更若影响里程碑或交付物，必须同步更新 `EXECUTION.md`。
- API 变更需重新生成 OpenAPI schema（`cargo run -p fg-api -- openapi > docs/openapi.json`）。
- 安全相关变更需添加 `SECURITY.md` 条目与 changelog 说明。

### 9. AI 代理专属规则

- 生成 `Cargo.toml` 依赖前，先检查现有 feature 是否已覆盖该能力。
- 被要求“添加模块 X”时，先查 `features.toml` 中的 `gately_equiv`；复用已有 feature 名，不另造同义词。
- 生成的代码必须同时在 `--no-default-features` 与 `--all-features` 下可编译。
- 若请求违反核心—模块边界（如“就在 fg-proxy 里 import fg-waf”），拒绝并提议基于注入的设计。
- WAF 相关工作始终以 `coraza-rs` 为引擎；除非明确要求研究性 spike，否则不提议纯 Rust 规则引擎。

### 10. Commit Message 约定

```
<scope>: <祈使句摘要>

feat(waf): add SecLang custom rule loading
fix(ban): correct IPv6 /64 expansion for scan bans
docs(design): update build-site flow diagram
chore(features): regenerate registry after adding ddns
```

Scope 对应去掉 `fg-` 前缀的 crate 名。
