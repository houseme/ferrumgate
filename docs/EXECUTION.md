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

### 手动配置 IP 证书

路由和证书的 `host` 可填写 IPv4 或 IPv6 地址。证书的 SAN 必须包含所配置的 IP。配置中 IPv6 可以写成 `2001:db8::1`，浏览器 URL 中使用方括号。

```toml
[[routes]]
host = "192.0.2.10"
upstream = "http://127.0.0.1:9000"

[[certificates]]
host = "192.0.2.10"
cert_file = "tls/ip-fullchain.pem"
key_file = "tls/ip-key.pem"
```

没有 SNI 时优先选连接本地地址对应的有效证书。若监听在 NAT 后且本地地址与证书地址不同，选择有效期结束最晚的 IP 证书。同一连接上的 HTTP authority 必须属于已选证书配置的 IP。 [Gately IP 证书](https://gately.cn/en/docs/modules/ssl#short-lived-and-ip-address-certificates)

### ACME HTTP-01 与自动续期

先创建私有状态目录，再启用专用的 HTTP-01 明文端口。域名的 DNS 应解析到网关，CA 需要能通过公网 TCP 80 到达该端口。通过端口映射部署时，`challenge_listen` 使用对应的本地端口。 HTTP-01 支持精确 DNS 名和带 shortlived 档位的 IP 地址。通配 DNS 名使用 DNS-01。 [Gately 证书文档](https://gately.cn/en/docs/modules/ssl#http-01-validation)

```bash
mkdir -m 700 ./acme-state
```

```toml
schema_version = 1

[acme]
domains = ["app.example.com"]
email = "ops@example.com"
accept_terms = true
state_dir = "acme-state"
challenge_listen = "0.0.0.0:80"

[server]
listen = "0.0.0.0:443"
tls = true

[[routes]]
host = "app.example.com"
upstream = "http://127.0.0.1:9000"
```

默认使用 Let’s Encrypt staging。生产用途可在确认外部网络与部署条件后设置 `directory = "https://acme-v02.api.letsencrypt.org/directory"`，为不同 CA 使用独立状态目录。自有测试 CA 通过 `ca_file` 指定 CA 服务端根证书。这一信任配置只用于 ACME 客户端。

通过 `fgate check` 后启动。看到 `ACME certificate installed` 后，用实际客户端检查域名、链和到期时间。配置代内的在线证书在文件持久化成功后切换。连接已建立时继续使用原会话。重启读取 `identity.pem` 和持久化账户。修改 ACME 设置需重启。

标准档位默认提前 720 小时，shortlived 默认提前 24 小时。实际提前量取配置值与证书寿命三分之一中的较短者。失败后指数退避，初次间隔 30 秒，最长 1 小时。保留已有证书直到新身份验证并持久化。状态目录有进程锁，避免两个实例同时管理。

CA 要求外部账户绑定时，在 `[acme]` 后添加：

```toml
[acme.eab]
key_id = "your-ca-issued-key-id"
hmac_key_file = "secrets/eab.key"
```

文件包含 CA 提供的 base64url 编码 HMAC 密钥。Unix 上仅运行账户可读，例如 0600。EAB 只在创建账户时使用，账户状态文件保存注册后的凭据。首次注册成功后，可在后续启动配置移除 EAB 表，并沿用原状态目录。

可在 `[acme]` 下设置 `profile = "shortlived"`，前提是 CA 支持该证书档位。更改或移除档位并重启后，已持有证书将被重新签发。具体有效期由 CA 决定。 [Gately 证书档位](https://gately.cn/en/docs/modules/ssl#short-lived-and-ip-address-certificates)

本机测试使用 Pebble 和 pebble-challtestsrv。确保两者在 PATH 上，或通过 `FGATE_PEBBLE`、`FGATE_PEBBLE_DNS` 指定二进制路径。

```bash
cargo test --locked -p ferrumgate --test gateway pebble_ -- --ignored --test-threads=1
```

### ACME 签发 IP 证书

在 `[acme]` 的 `domains` 中加入 IP 地址，设置 `profile = "shortlived"` 并使用 HTTP-01。DNS 名和 IP 可以放在同一订单。 `[[routes]]` 的 `host` 填写相应 IP。IPv6 证书标识和配置可写裸 IPv6，HTTP Host 和访问 URL 使用方括号。

```toml
[acme]
domains = ["192.0.2.10", "app.example.com"]
profile = "shortlived"
email = "ops@example.com"
accept_terms = true
state_dir = "acme-state"
challenge_listen = "0.0.0.0:80"
```

示例地址用于演示。使用公开 CA 时，配置其可验证的公网 IP 和对应的 TCP 80 路径。自有 CA 可验证其能够访问的内网地址，需要支持 IP 标识与 shortlived 档位。签发后无 SNI 按本地地址或有效期选择，HTTP authority 与已选证书的配置地址一致。 [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738) · [Gately IP 证书](https://gately.cn/en/docs/modules/ssl#short-lived-and-ip-address-certificates)

### ACME 本地证书部署

Unix 环境可创建独立部署目录，并向 `[acme]` 配置加入一个或多个目标。目录需要由运行账户管理，部署目录不能包含 ACME 状态目录，也不能由组或其他用户写入。

```toml
[[acme.deploy]]
directory = "/var/lib/ferrumgate-deployed/app"
fullchain_name = "fullchain.pem"
key_name = "privkey.pem"
```

文件位于 `directory/current/`。每次发布先写完整的证书代，校验并同步后再原子更新 `current` 链接。需要读取证书和私钥两份文件时，先解析一次 `current`，再从同一代目录读取。私钥权限为 0600。网关保留上一代，同时修复缺失或改动的文件。

部署工作在签发、续期、进程重启时触发，并按小时检查文件是否需要修复。通过 `ACME certificate deployed` 确认发布完成。目录中的 `current` 与 `.fgate-acme` 保留给网关，已有无关路径保持原样。部署失败会记录日志并重试，业务 TLS 继续由内部证书存储提供。 [Gately 本地部署](https://gately.cn/en/docs/modules/ssl#auto-deploy)

### ACME DNS-01 Cloudflare

使用 Cloudflare 该托管区的 DNS 编辑 API Token，保存到运行账户可读的私有文件，例如 Unix 0600。为 `acme.domains` 配置精确域名或 `*.example.com`，提供以下表。 `zone_id` 是 Cloudflare 托管区的 ID，`resolver` 指定能读取该公开托管区的 DNS 解析器。

```toml
[acme.dns01]
zone = "example.com"
zone_id = "0123456789abcdef0123456789abcdef"
token_file = "secrets/cloudflare.token"
resolver = "1.1.1.1:53"
propagation_timeout_secs = 120
```

删除 HTTP-01 专用的 `challenge_listen` 设置。签发验证通过 TXT 记录进行。可同时省略 `zone` 与 `zone_id`，网关会按挑战最终落点查询 SOA，再用 Cloudflare API 找到唯一匹配的活动区域。自动模式需要该区域的 Zone Read 和 DNS 编辑权限。能够确认权威区域时才写入 TXT。生产请求默认发送至 Cloudflare HTTPS API。本地测试可通过 `api_base` 和 `api_ca_file` 使用自有 HTTPS 测试端点。

默认跟随 `_acme-challenge` 的 CNAME 委托。跨区委托使用自动发现，或显式配置 TXT 最终落点所在的 Cloudflare 区域。设置 `follow_cname = false` 后改为在原始名称写入。DNS 查询失败或 CNAME 链有循环时，签发在写入 TXT 前停止。传播检查从原始挑战名称查询，清理以记录首次写入时的名称和 ID 为准。 [Gately DNS-01 验证](https://gately.cn/en/docs/modules/ssl#dns-01-validation)

等待日志 `ACME certificate installed` 后核对预期域名的 HTTPS 证书。在发生 `ACME DNS cleanup will retry` 时，保留原托管区、令牌和 `dns-cleanup.json`，让网关重试清理。每条记录的区域与 ID 随清理状态保存。从旧显式配置切换到自动发现前，需要先清完旧格式的待删除记录。授权和记录审计仍可在提供商端确认。

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

## 5. 启用 HTTP/2 和 gRPC

先按第 3 节配置入口 TLS，再为明文 HTTP/2 后端设置路由。将 `9001` 换成上游 gRPC 服务的端口。HTTPS 后端直接使用 `https://`，使用私有 CA 时按第 3 节配置 `upstream_ca_file`。

```toml
[[routes]]
host = "app.test"
path_prefix = "/echo.Service"
upstream = "http://127.0.0.1:9001"
upstream_h2c = true
```

路径匹配采用段边界。请将 `/echo.Service` 替换成实际全限定服务名。上游需接受直接 HTTP/2 连接。对同时支持 HTTP/1.1 WebSocket 和 h2c 的后端，可以再设置 `websocket = true`。入口需要验证 TLS 域名及证书。gRPC 客户端使用 `app.test:8443` 和对应根证书，并用已知方法验证响应数据与最终 gRPC 状态。502 时先核对上游是否实际支持 h2c 或协商到 `h2`。[Gately Web 服务文档](https://gately.cn/en/docs/modules/web)

独立协议回归使用 Rust 在本机生成证书，启动 TLS 和 h2c 测试后端。

```bash
cargo test --locked -p ferrumgate --test gateway http2::
```

## 6. 配置多后端和备用切换

为同一条路由定义主后端和备用后端。以下例子将两个主后端的健康流量约按 3:1 分配。三个 origin 均可用时，备用后端保持待命。使用 gRPC 的池应为每个后端准备可用的 HTTP/2。

```toml
[[routes]]
host = "app.test"

[[routes.backends]]
upstream = "http://127.0.0.1:9001"
weight = 3

[[routes.backends]]
upstream = "http://127.0.0.1:9002"

[[routes.backends]]
upstream = "http://127.0.0.1:9003"
backup = true
```

先通过 `fgate check`，再按第 2 节重载。用后端标识验证分流比例。停止两个主后端，观察连续连接失败导致的 502，以及随后转到备用。启动主后端，等待冷却期结束再发请求，验证权重分流恢复。故障注入使用本机回环环境。

```bash
cargo test --locked -p ferrumgate --test gateway backends::selects_weighted_backends_and_switches_after_connect_failures
```

### 主动健康检查

在该路由下添加以下表，默认关闭。HTTP 检查默认访问 `/`，TCP 模式省略 `path`。

```toml
[routes.health]
mode = "http"
path = "/ready"
interval_secs = 10
timeout_secs = 3
fails = 3
passes = 2
```

`interval_secs` 允许 1–3600，`timeout_secs` 允许 1–60，`fails` 和 `passes` 允许 1–20。观察日志中 `upstream unavailable` 和 `upstream recovered`。使用真实探测路径返回 503 后再恢复 200，验证备用切换和恢复次数。

### 本地响应路由

为选定的 Host 和路径直接生成重定向或固定文本。响应路由与后端、健康检查及 WebSocket 配置互斥。

```toml
[[routes]]
host = "app.test"
path_prefix = "/move"
[routes.response]
type = "redirect"
target = "https://{host}:8443"
status = 308
keep_path = true

[[routes]]
host = "app.test"
path_prefix = "/maintenance"
[routes.response]
type = "text"
status = 503
body = "服务维护中"
content_type = "text/plain; charset=utf-8"
```

重定向支持 301、302、307 和 308，默认 302。目标须为绝对 HTTP(S) URL。目标 authority 中的 `{host}` 使用已匹配的主机名。保留原路径时，原始路径追加到目标路径。目标查询参数优先，未设置时保留请求查询。固定文本默认 200，接受 200–599，HEAD 只返回头部。 [Gately 站点类型](https://gately.cn/en/docs/modules/web#site-types)

### 静态站点

```toml
[[routes]]
host = "app.test"
path_prefix = "/assets"
[routes.response]
type = "static"
root = "/srv/ferrumgate-site"
clean_urls = true
not_found = "404.html"
```

`root` 使用独立的绝对目录，与配置目录分开，目录中不能包含配置引用的 TLS 文件。该路由会移除匹配的路径前缀。目录以 `index.html` 为入口，Clean URLs 同时尝试 `name.html`，目录内容不列出。缺少文件时返回 404，可用 `not_found` 指定根目录内的文件。GET 流式读取文件，支持一个字节范围。HEAD 返回元数据。

```bash
cargo test --locked -p ferrumgate --test gateway site::
```

### 通配域名与证书

`routes[].host` 可使用 `*.example.test`、`api-*.example.test`、`shop.*.example.test`、`tools.*` 或 `*`。优先精确域名，再按通配表达式长度和配置顺序选择域名规则。选定域名后再按最长路径前缀路由。

```toml
[[routes]]
host = "*.example.test"
upstream = "http://127.0.0.1:9000"

[[certificates]]
host = "*.example.test"
cert_file = "tls/wildcard.pem"
key_file = "tls/wildcard.key"
```

示例要求 TLS 监听已开启。通配路由可以匹配多层子域；通配证书覆盖一个子域标签，更深的域名仍需匹配的证书。证书 SAN 必须包含配置的通配名称。精确证书优先。 [Gately 域名匹配](https://gately.cn/en/docs/modules/web#structure-listeners-sites-and-the-default-site)

### TCP 端口转发

配置独立 TCP 规则。目标使用带端口的 IPv4 或 IPv6 地址，按列表顺序拨号。

```toml
schema_version = 1

[server]
http_enabled = false

[[tcp_forward]]
listen = "127.0.0.1:9443"
targets = ["127.0.0.1:9444", "127.0.0.1:9445"]
max_connections = 128
connect_timeout_ms = 2000
first_data_timeout_ms = 60000
connection_lifetime_ms = 300000
```

使用 `fgate check` 校验后启动。移除 `http_enabled = false` 并配置 Web 路由，即可并行提供两个监听器。已连接的数据流在终止时可在当前排空预算内完成。修改监听、目标或规则预算需重启。

`first_data_timeout_ms` 允许 1 到 3600000 毫秒。后端连接成功并写完可选 PROXY 头后开始计时，两端都未发送应用数据的连接到期释放接入名额。任一端开始传输后继续受总连接寿命约束，空半关闭也可传递给另一端。 [Gately 首次数据超时](https://gately.cn/en/docs/modules/portforward#connection-limits-and-empty-connections)

```bash
cargo test --locked -p ferrumgate --test gateway tcp::
```

TCP 目标支持匹配的 PROXY protocol 时，可在规则内设置 `proxy_protocol = "v1"` 或 `"v2"`。网关在转发应用数据前写入真实 TCP 对端和网关接收地址。启用后，后端需配置为从受信任的网关地址接收该版本。 [Gately 端口转发](https://gately.cn/en/docs/modules/portforward#proxy-protocol) · [PROXY protocol 规范](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt)

### TCP 与 UDP 的来源规则

在转发规则下添加来源表，值可为单个 IP 或 CIDR。以下示例只允许指定网段，并永久拒绝其中一个地址。UDP 使用相同字段，表名替换为 `[udp_forward.source]`。

```toml
[tcp_forward.source]
allow = ["192.0.2.0/24", "2001:db8:12::/48"]
deny = ["192.0.2.9"]
```

`deny` 优先于 `allow`。省略 `allow` 表示接受未拒绝的来源，设置空数组表示拒绝所有来源。IPv4 映射地址按 IPv4 匹配。可通过 Unix SIGHUP 热重载来源规则。新 TCP 连接在拨号前应用规则，已建立的 TCP 连接继续工作。UDP 每次转发前检查请求和回复，规则修改后也会限制已有会话的报文。 [Gately 来源 IP 访问控制](https://gately.cn/en/docs/modules/portforward#source-ip-access-control)

TCP 可在规则的顶层启用每源并发配额。示例限制每个来源最多 16 条连接，并将指定的运维网段排除在每源配额之外。

```toml
max_connections_per_source = 16
source_limit_exempt = ["192.0.2.64/26"]
```

IPv4 按单地址计数，IPv6 按 /64 分组。先执行来源允许／拒绝规则，再检查并发配额。来源豁免仍受该规则的总连接上限约束。省略配额即保持原有接入行为，启用后修改配额需重启。 [Gately 连接限制](https://gately.cn/en/docs/modules/portforward#connection-limits-and-empty-connections)

### UDP 端口转发

```toml
schema_version = 1

[server]
http_enabled = false

[[udp_forward]]
listen = "127.0.0.1:5354"
targets = ["127.0.0.1:5353", "[::1]:5353"]
max_sessions = 128
idle_timeout_ms = 30000
```

用 `targets` 设置 1 到 8 个目标。旧配置可继续使用单个 `target`。每条规则填写其中一个字段。每个监听端口按客户端 IP 与端口建立独立会话。新会话轮询选择起始目标，绑定或连接失败时依次试下一个目标。建立后会话固定使用该目标，只有来自该目标的响应可返回客户端。UDP 目标无响应时会话按空闲期限回收，已发送的数据报不会重发。满载时丢弃超出预算的报文。收到响应时才借用回包缓冲，等待响应的会话不会常驻一份回包缓冲。修改目标或预算需重启。 [Gately UDP 参考实现](https://github.com/wangwanjie/gately/blob/442162e4d0b64df119bc5fe6469a088adee844c4/internal/modules/portforward/forwarder.go#L316-L355)

```bash
cargo test --locked -p ferrumgate --test gateway udp::
```

### TCP 与 UDP 多端口映射

在同一 IP 后用逗号列出端口，用连字符表示闭区间。每个目标可写一个端口供所有监听端口共享，也可按书写顺序逐个映射。IPv6 地址使用方括号。下例把 9443、9444 和 9550 分别映射到主后端的 443、444 和 8080。主后端拨号失败时改拨备用地址的 8443。UDP 将 5354、5355 分别映射到第一个目标的 5353、5354。第二个目标为两个监听端口都配置了 5353。

```toml
schema_version = 1

[server]
http_enabled = false

[[tcp_forward]]
listen = "127.0.0.1:9443-9444,9550"
targets = ["127.0.0.1:443-444,8080", "[::1]:8443"]

[[udp_forward]]
listen = "127.0.0.1:5354-5355"
targets = ["192.0.2.10:5353-5354", "192.0.2.11:5353"]
max_sessions = 128
```

需要同号映射时，在目标 IP 后重复监听端口表达式。每种协议最多展开 64 个监听器。配置校验拒绝重叠监听、无效范围和端口数量不匹配的目标。每个监听端口独立应用连接或会话上限，全部 UDP 监听端口的 `max_sessions` 之和不能超过 4096。调整映射需重启，来源规则可按原方式热重载。 [Gately 端口映射实现](https://github.com/wangwanjie/gately/blob/main/internal/l4proxy/ports.go)

### 转发流量指标

在现有 `[server]` 表中设置 `metrics_listen = "127.0.0.1:9090"` 后重启。省略该字段时关闭采集。也可使用 IPv6 回环地址 `[::1]:9090`。该监听独立于业务 HTTP 和转发监听，使用本机访问边界。可在同一主机运行 Prometheus，按以下配置采集。

```yaml
scrape_configs:
  - job_name: ferrumgate
    metrics_path: /api/metrics
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

`GET /api/metrics` 返回 Prometheus 0.0.4 文本。每个实际绑定的端口以 `protocol` 和 `listen` 为标签。标签取自监听器，采集结果不含请求内容或客户端标识。

| 指标 | 含义 |
|---|---|
| `ferrumgate_portforward_active_connections` | 当前运行的 TCP 连接任务或已连接上游的 UDP 会话 |
| `ferrumgate_portforward_connections_total` | 已启动的 TCP 连接任务或已连接上游的 UDP 会话总数 |
| `ferrumgate_portforward_bytes_total` | 双向成功写入套接字的应用字节。 `in` 是客户端到后端，`out` 是后端到客户端。出站 PROXY 头单独发送 |
| `ferrumgate_portforward_source_denied_total` | 入站来源规则拒绝的 TCP 连接或 UDP 数据报数 |

来源规则热重载保留累计值，进程重启重新计数。同一次采集独立读取各项值，持续传输时可看到实时进展。 [Gately 转发指标](https://github.com/wangwanjie/gately/blob/442162e4d0b64df119bc5fe6469a088adee844c4/internal/modules/portforward/metrics.go) · [Gately 监控文档](https://gately.cn/en/docs/reference/monitoring)

```bash
curl -fsS http://127.0.0.1:9090/api/metrics
cargo test --locked -p ferrumgate --test gateway metrics::
```

## 7. 交付阶段与退出标准

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
2. C2 HTTP/2 和 h2c 已接入入口 ALPN、独立上游池、流控和 authority 校验。gRPC 验证双向流、客户端取消及 trailers。
3. C3 已接入加权后端池、备用切换和被动冷却。主动 HTTP/TCP 探测已验证失败阈值、备用和恢复。自动重试限制在能证明尚未写出请求的情形。
4. 重定向目标由站点配置生成。静态文件使用明确根目录，验证符号链接、目录索引、HEAD、Range、路径编码和跨平台行为。SSE、WebDAV、大文件等依赖长时连接的场景需要独立的上传与响应超时策略。

### D 证书签发与续期

1. HTTP-01 已接入账户、订单、授权、签发、重启恢复和续期。证书和密钥以一个身份文件原子写入。未完成订单恢复与调度状态持久化作为后续切片。
2. HTTP-01 challenge 按精确 Host 和 token 匹配，并随订单结束、错误和取消清理。Cloudflare DNS-01 已实现传播检查和可恢复清理。其他提供商继续独立交付。
3. 当前按证书有效期调度续期和退避，已支持 EAB 注册，后续接入 ARI。未获得新证书时持续使用原证书，记录失败阶段和证书剩余寿命。
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

## 8. 校验与性能验收

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

## 9. 当前交付记录

### WP-00 配置目录存储

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-core -p fg-config -p fg-testkit
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

2026-11-26 在 macOS arm64、Rust stable 1.100.0 上，上述检查通过。工作区默认套件通过 72 项，其中 9 项新增用例覆盖原始字节和 JSON 往返、相同内容保持 mtime、权限、非法名称、受保护目录、错误脱敏以及替换失败后的临时文件清理。9 项需本机 Pebble 的 ACME 测试单独运行并全部通过。Linux、Windows 和真实断电恢复留待对应环境验证。

### WP-01 模块框架与注册表

```bash
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway --all-features acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway --no-default-features modules
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --all-features --test gateway modules
git diff --check
```

2026-11-26 在 macOS arm64、Rust stable 1.100.0 上，默认套件通过 79 项，另有 9 项本机 Pebble ACME 用例全部通过。两种 Cargo feature 构建各通过 3 项模块回环用例，均包含当前三个核心模块。目录表在各次生成中的字节一致。Linux 和 Windows 留待对应环境验证。

现有回环用例覆盖 SIGHUP 的 Web/TLS 和 TCP/UDP 更新，以及 SIGTERM 的正常排空。WP-01 新用例执行 `fgate serve`，通过占用 TCP 端口验证预绑定失败与关闭转发的行为，发送 SIGHUP 验证开关变更要求重启，并用持续打开的回环连接验证 SIGINT 排空超时会回收连接。

### WP-02 配置历史、差异与回滚

```bash
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
git diff --check
```

2026-11-26 在 macOS arm64、Rust stable 1.100.0 上通过 93 项默认测试。新增 14 项覆盖版本保留、恢复后撤销、并发版本链、快照失败保留当前文件、敏感项排除、版本 ID 与链接校验、差异上限及回滚请求的原子领取。全量回归包含既有网关回环测试。Linux、Windows 和断电恢复尚待实测。CLI、管理 API 与重启接入由后续工作包验证。

### WP-16 事件总线

```bash
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

2026-11-26 在 macOS arm64、Rust stable 1.100.0 上通过 101 项默认测试与 9 项本机 Pebble ACME 测试。7 项事件总线测试覆盖 32 项目录、饱和行为、慢订阅者隔离、并发发布、panic 恢复和退订清理。附加的网关回环测试验证实际健康检查的故障与恢复事件。入口容量设为 1 时，10,000 次发布只构造了一次负载。Linux、Windows 与通知渠道接入留待对应验证。

### WP-09 运行日志基础链路

```bash
./target/release/fgate serve --config ferrumgate.example.toml --log-dir "$PWD/ferrumgate-logs"
```

在文件中查看系统的 `gately.log` 与对应模块日志。正常退出会刷新待写条目，重启后可在同一文件里核对序号是否接续。

```bash
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

在 macOS arm64、Rust stable 1.100.0 上，110 项默认测试和 9 项本机 Pebble ACME 测试通过。新增用例覆盖内存保留与字段筛选、写盘合批和轮转、不完整行恢复、目录单实例持有、stderr 饱和隔离及日志文件权限。真实网关用例验证回环请求、SIGINT 刷新、重启续号和拒绝发布日志目录，主动健康检查日志顺序也单独复验通过。后续覆盖跨文件查询、导出与访问归档。Linux 和 Windows 留待实测。

### WP-09 跨文件筛选与导出

`fg-logging` 提供 `Logs::query` 和 `Logs::export`。正条数查询从内存、待写批次、当前文件和轮转文件中按序号补足。零条数参数只查内存。导出支持 JSON Lines 和 CSV，文件扫描与输出都在快照锁外完成。

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-logging
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

在 macOS arm64、Rust stable 1.100.0 上通过 115 项默认测试及 9 项本机 Pebble ACME 测试。新增 5 项测试覆盖关键词与 IP 条件组合、跨文件和损坏长行、待写记录在内存淘汰后可读、快照跨轮转及追加保持一致、CSV 公式防护与多行转义。访问日志压缩归档、清空、目录热切换和管理端授权继续按计划接入。

### WP-09 Web 日志归档与清空

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-logging
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo tree --locked --offline -p fg-logging --depth 1
git diff --check
```

在 macOS arm64、Rust stable 1.100.0 上通过 120 项默认测试及 9 项本机 Pebble ACME 测试。五项新增测试覆盖跨日和按大小轮转、gzip 恢复与导出、按保留期限和总量淘汰、清空后拒绝旧批次及压缩结果。归档使用锁定的 `flate2 1.1.11`，Unix 分区容量通过 `rustix` 读取。当前由 Rust 库启用归档，Web 访问日志生产者与管理接口分别随 WP-28 和 WP-11 接入。目录热切换与 gzip 时间范围裁剪仍在 WP-09。

### 数据面交付记录

- 2026-11-25 在 macOS arm64、Rust stable 1.100.0 上通过格式检查、Clippy、4 项 Rust 单元测试、release 构建和 8 项 Rust 端到端用例。后者覆盖实际转发、路径与查询、逐跳头、连接复用、16 个并发客户端共 400 次成功请求、1 MiB 上传和分段下载、504、错误重载保留旧配置、排空、TLS SNI、上游证书校验与轮换。第 3 节的 curl TLS 验证也通过。
- 依赖已用注册表索引核对，当前 15 个直接 crate 均采用最新稳定版，传递依赖按兼容约束求解。重点版本为 Tokio 1.54.1、Hyper 1.13.0、rustls 0.23.46、Clap 4.6.10 和 TOML 1.2.3。rustls 0.24 当前发布的是开发预览，HTTP/TLS 适配器使用 0.23 系列。精确版本见 [Cargo.lock](../Cargo.lock)。
- Workspace 由 `ferrumgate` 和 `fg-gateway` 组成。C1 在 macOS arm64 上通过 workspace Clippy、5 项 Rust 单测、release 构建和 12 项 Rust 端到端测试。新增场景覆盖两跳握手校验、WebSocket over TLS、子协议、路由关闭后保留既有会话，以及连接名额、寿命和停机。
- C2 在 macOS arm64 通过 3 项独立 HTTP/2 端到端用例，覆盖两条并行 gRPC 流、双向数据、取消传播、请求与响应 trailers、TLS 上游、WebSocket 回落及 HTTP/1.1 普通后端。
- C3 在 macOS arm64 通过 workspace Clippy、6 项 Rust 单测、release 构建与 17 项 Rust 端到端测试。新增场景验证 2:1 权重、三次连接失败后的备用切换、冷却期边界及配置拒绝。
- 已接入主动 HTTP/TCP 健康检查。Web 服务已接入重定向、固定文本和静态文件。其余 C–J 功能、正式吞吐与尾延迟对照及 Linux/Windows 运行仍待验收。

- 本轮独立验证覆盖 HTTP/TCP 探测、固定文本、重定向、目录受限静态文件、通配域名/SNI 和 TCP 字节和 UDP 报文转发。

- 本轮 ACME 验证使用本机 Pebble 实际完成两次 HTTP-01 授权、签发及 HTTPS 握手。重启复用了账户与未过续期窗口的证书，临近到期的测试证书自动替换。公开 staging CA 与 DNS-01 分开验收。
- EAB 已通过要求绑定的本机 Pebble。首次注册并签发后，测试移除了 EAB 文件和配置，重启仍复用账户并成功续期。
- Cloudflare DNS-01 通过本机 Pebble 与 HTTPS API 模拟的端到端测试，覆盖通配证书签发、实际 TXT 查询、历史未确认记录清理、删除失败后的重启恢复，以及保留外部 TXT。公开 CA 和真实 Cloudflare 托管区分开验收。
- 证书档位通过本机 Pebble 验证。标准证书在档位变化时被重新签发为约六天的证书，保持档位重启后复用该证书。
- 本机 Pebble 验证 DNS-01 可经 CNAME 跨区签发。签发后改变 CNAME 再重启，网关依照持久化日志清理原 TXT，而新目标和其他记录保持原样。
- 已通过本机 Pebble 验证 CNAME 跨区后根据 SOA 阴性响应中的权威记录发现委托子区。HTTPS API 模拟确认只查询和使用该子区，重启清理不重新发现区域，旧显式日志仍可恢复。
- 本机 Pebble 通过 IPv4 与 IPv6 的真实 HTTP-01、短寿命 IP 证书签发、数值地址 HTTPS 握手及重启复用，同时覆盖 DNS 名与 IPv4 混合订单。公开 CA 的公网地址签发分开验收。
- 本机 Pebble 验证本地部署拒绝覆盖外部 current 文件、仍可使用已签发证书、重启部署、修复缺失链文件、私钥 0600 及续期发布新一代。
