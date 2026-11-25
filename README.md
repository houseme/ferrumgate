# FerrumGate

FerrumGate 是 Rust 编写的自托管网关，按模块参考 Gately 的公开行为。当前提供 HTTP/1.1 反向代理、Host 和路径路由、手动 TLS、HTTPS 上游验证、Unix 配置热加载、WebSocket（`ws` / `wss`）、HTTP/2、原生 gRPC 代理和加权后端池。参考 [Gately 源码仓库](https://github.com/wangwanjie/gately)和 [Gately Web 服务文档](https://gately.cn/en/docs/modules/web)。

## 启动

```bash
cargo build --release --locked -p ferrumgate
./target/release/fgate check --config ferrumgate.example.toml
./target/release/fgate serve --config ferrumgate.example.toml
```

样例监听 `127.0.0.1:8080`，将 `app.test` 转发至 `127.0.0.1:9000`。完整演练包含测试后端、curl 和证书轮换命令。[执行手册](docs/EXECUTION.md)

## WebSocket

在需要升级的 `[[routes]]` 内设置 `websocket = true`。TLS 入口使用 `wss://`。子协议、连接寿命和重连行为见 [WebSocket 配置](docs/EXECUTION.md#4-启用-websocket)。

## HTTP/2 和 gRPC

TLS 监听器通过 ALPN 提供 HTTP/2 和 HTTP/1.1。明文 HTTP/2 后端的路由使用 `upstream_h2c = true`，HTTPS 后端通过 ALPN 协商。原生 gRPC 使用两端 HTTP/2，可转发双向数据及 `grpc-status` 等 trailers。[配置与实战验证](docs/EXECUTION.md#5-启用-http2-和-grpc)

## 多后端

同一路由可以配置多条 `[[routes.backends]]`，以 `weight` 分配主后端流量，以 `backup = true` 声明备用后端。连接连续三次失败后暂停选择该后端 30 秒。[配置示例和故障演练](docs/EXECUTION.md#6-配置多后端和备用切换)

## 工作区

根包 `ferrumgate` 生成 `fgate`，`crates/fg-gateway` 负责数据面。每个功能模块单独提交，同时更新本页的能力说明和相应验证记录。[架构设计](docs/DESIGN.md) · [贡献规范](AGENT.md)

在根目录运行 `cargo test --workspace --locked`，可执行 Rust 单元测试和真实回环端到端测试。

为代理路由添加 `[routes.health]` 可开启 HTTP 或 TCP 主动检查，探测按连续失败和成功次数摘除或恢复后端。[健康检查配置](docs/EXECUTION.md#主动健康检查)
