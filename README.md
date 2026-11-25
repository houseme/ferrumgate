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

本地站点响应支持 HTTP 重定向和带状态码、内容类型的固定文本。[配置示例](docs/EXECUTION.md#本地响应路由)

静态站点支持目录索引、Clean URLs、自定义 404、HEAD 和单区间 Range，目录访问受配置根限制。[静态站点配置](docs/EXECUTION.md#静态站点)

域名路由支持精确域名、单星通配规则和 `*` 兜底。TLS 优先选精确 SNI 证书，同时支持明确配置的 `*.suffix` 证书。[域名配置](docs/EXECUTION.md#通配域名与证书)

TCP 端口转发通过 `[[tcp_forward]]` 配置，可独立运行或与 Web 监听并存，支持多个目标、连接失败时的顺序切换及双向半关闭。[端口转发配置](docs/EXECUTION.md#tcp-端口转发) · [Gately 功能对齐状态](ARCHITECTURE_EXECUTION.md#当前对齐状态)

UDP 可用 `[[udp_forward]]` 按客户端维护独立会话，并配置会话上限和空闲回收。[UDP 配置](docs/EXECUTION.md#udp-端口转发)

自动 HTTPS 支持 ACME HTTP-01、自主续期和在线换证。配置 `[acme]` 后，默认连接 Let's Encrypt staging；生产 CA 可显式指定。[ACME 配置与验证](docs/EXECUTION.md#acme-http-01-与自动续期)

ACME DNS-01 支持 Cloudflare 托管区自动发现、CNAME 委托、通配证书、TXT 传播检查和重启后的记录清理。[DNS-01 配置](docs/EXECUTION.md#acme-dns-01-cloudflare)

可通过 `acme.profile` 选择 CA 支持的证书档位，例如 `shortlived`。调整档位后重启会触发重新签发。[证书档位](docs/EXECUTION.md#acme-http-01-与自动续期)

可为 IPv4 或 IPv6 地址手动配置证书，也可通过 ACME HTTP-01 shortlived 档位自动签发。无 SNI 客户端按连接本地地址选择证书，并支持 NAT 场景下的有效期兜底。[配置 IP 证书](docs/EXECUTION.md#手动配置-ip-证书)

TCP 端口转发支持向后端发送 PROXY v1/v2，以传递网关看到的连接地址。[TCP 转发配置](docs/EXECUTION.md#tcp-端口转发)
