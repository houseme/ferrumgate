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

在 macOS arm64、Rust stable 1.100.0 上通过 120 项默认测试及 9 项本机 Pebble ACME 测试。五项新增测试覆盖跨日和按大小轮转、gzip 恢复与导出、按保留期限和总量淘汰、清空后拒绝旧批次及压缩结果。归档使用锁定的 `flate2 1.1.11`，Unix 分区容量通过 `rustix` 读取。当前由 Rust 库启用归档，Web 访问日志生产者与管理接口分别随 WP-28 和 WP-11 接入。

### WP-09 目录切换与归档时间裁剪

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-logging
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo tree --locked --offline -p fg-logging --depth 1
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 123 项默认测试及 9 项本机 Pebble ACME 测试。三项新增测试覆盖目标被占用时继续向旧目录写入、回到旧目录及恢复落盘、并发切换前后的序号连续，以及只读取头部即可排除时间不相交的 gzip。归档元数据覆盖顺序异常与亚秒边界，损坏或缺少元数据时回到逐条读取。WP-09 的 Rust 库阶段已完成，设置、管理接口和访问日志的接入随各自工作包验证。

### WP-11 管理 API 基础链路

```bash
./target/release/fgate api-docs ./admin-docs
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo tree --locked --offline -p fg-admin --depth 1
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 131 项默认测试和 9 项本机 Pebble ACME 测试。新增 8 项测试覆盖 808 个上游操作的权限推导、公开分类、回环 HTTP 鉴权和同源约束、请求体大小与读取时限、模块状态、集合提交及失败回滚、OpenAPI 与 `fgate api-docs`。回环鉴权使用测试身份，实际管理监听、会话认证和令牌接入随各自工作包实施。

### WP-11 集合复制与批量操作

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 133 项默认测试和 9 项本机 Pebble ACME 测试。两个新增回环用例通过真实 HTTP 验证候选启停校验、重复键去重、单次版本提交、失败不触发回调、排序、分组、删除前检查、复制位置、密钥掩码合并和写权限门禁。权限测试仍覆盖固定上游快照的 808 个操作。线上身份和监听仍随对应工作包接入。

### WP-11 管理响应脱敏与压缩

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo tree --locked --offline -p fg-admin --depth 1
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 136 项默认测试和 9 项本机 Pebble ACME 测试。新增回环用例验证压缩后的只读响应解压后仍已脱敏、写权限保留原值、超大和坏 JSON 返回受控错误、流式策略及已编码响应透传。容量测试验证饱和时拒绝未经脱敏的正文并允许可选压缩回退。线上身份和管理监听仍随对应工作包接入。

### WP-11 集合展示字段与响应本地化

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin compat::
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 138 项默认测试及 9 项本机 Pebble ACME 测试。新增两项回环用例覆盖空集合新增、展示结果整对象替换与复制、未知和重复可写键拒绝、语言标签及权重协商、错误翻译和翻译后的序列化安全。用例确认配置字段仍保持原文，译文中的 URL 凭据在 gzip 之前被掩码。真实词典由 WP-10 接入。

### WP-11 大文件上传与管理资源

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin transport::
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo tree --locked --offline -p fg-admin --depth 1
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 141 项默认测试及 9 项本机 Pebble ACME 测试。两个新增回环用例验证 5 MiB 分块上传、长度及累计超限、授权边界和 HTTP/1 未读完时关闭连接，以及静态首页前缀、gzip 原样发送和身份变体、HEAD、Range、缓存规则及 API 路径隔离。虚拟时间用例验证空闲超时、低速拒绝和合规上传超过 60 秒时能完整读取。生产管理监听和实际资源包仍随对应工作包接入。

### WP-11 通用日志与 OpenAPI 模型

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin logs::
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-logging --test reconfigure
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 143 项默认测试和 9 项本机 Pebble ACME 测试。新增回环用例覆盖历史查询、只读筛选和导出脱敏、JSON Lines 和 CSV、模块清空权限、模块状态与 OpenAPI 一致性，以及模型与实际 Serde 请求和响应结构一致。日志重配置用例验证管理句柄随目录切换，以及旧句柄在日志所有者退出后只能清理自身内存。接口通过路由器显式挂载，生产管理监听和正式身份解析待接入。

### WP-11 集合接口模型

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin collection
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 143 项默认测试和 9 项本机 Pebble ACME 测试。集合回环用例验证展示字段回传、嵌套配置的严格校验、删除计数字段、接口文档导出，以及只读身份读取的 OpenAPI 与静态定义一致。只读身份仍无法通过密钥接口读取实际值。

### WP-11 公开路由

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 147 项默认测试和 9 项本机 Pebble ACME 测试。新增用例覆盖公开路由与同路径受保护方法的鉴权隔离、模块凭据、同源校验、JSON 请求上限、禁用和未编译模块的状态，以及 OpenAPI 和 Markdown 的收录规则。808 个上游权限条目继续逐项通过。实际登录处理器和模块凭据由相应工作包接入。

### WP-12 账号存储与签名会话

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 153 项工作区测试和 9 项本机 Pebble ACME 测试。六项认证测试覆盖随机初始化、单写者、Unix 文件权限和历史排除、签名篡改与过期、吊销跨重启、吊销容量触发纪元切换、写入失败时保持已发布状态，以及已配置 TOTP 或禁用密码登录时的拒绝行为。HTTP 登录和 Cookie 在后续步骤接入。

### WP-12 密码规则与改密

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 156 项工作区测试和 9 项本机 Pebble ACME 测试。新增用例覆盖弱口令变形、原因码、Unicode 字符与 bcrypt 字节上限、长口令和并发改密。验证失败保持磁盘和会话状态，两个并发改密请求只有一次能提交，成功后旧密码及旧会话在重启后仍失效。HTTP 接口和登录限流由后续步骤接入。

### WP-12 登录限流与递增锁定

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth lockout
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 161 项工作区测试和 9 项本机 Pebble ACME 测试。五项新增用例验证来源锁定的递增与上限、并发预占和取消释放、IPv4 映射与 IPv6 子网归并、陌生来源预算与单次事件、来源表容量与过期清理，以及已知来源重启后仍可登录。HTTP 登录与 Cookie 由下一步骤接入。

### WP-12 HTTP 登录与会话

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login::
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 163 项工作区测试和 9 项本机 Pebble ACME 测试。两项新增回环用例覆盖首次登录和强制改密、写入失败时保留旧会话、Cookie 路径和安全属性、同源校验、重复 Cookie 拒绝、可信连接地址、HTTP 429、单会话与全部会话吊销，以及 API 令牌的会话查询权限。生产管理监听和 TOTP 仍按计划接入。

### WP-12 TOTP 两步验证

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth totp
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login::login_totp
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 167 项工作区测试和 9 项本机 Pebble ACME 测试。新增用例覆盖 RFC 6238 SHA-1 向量、验证码前导零与时钟偏差、写入失败时拒发会话、并发与跨重启防重放、缺少验证码时保留失败计数，以及绑定会话限制和启停后的旧会话失效。[RFC 6238 附录 B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B)

### WP-12 管理员 Passkey

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth passkey
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login::login_passkey
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 171 项工作区测试和 9 项本机 Pebble ACME 测试。四项新增用例验证 Origin 限制、挑战容量与过期、软件认证器注册、挑战重放、签名计数回退、重启恢复、独立登录限流，以及 HTTP 层的密码登录开关、最后一把 Passkey 保护和删除后会话失效。物理认证器和生产管理监听待实测，上游已有 Passkey 记录的迁移待实现。[WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)

### WP-12 只读账号

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth --test readonly
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login::login_readonly
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 174 项工作区测试和 9 项本机 Pebble ACME 测试。三项新增用例验证只读账号 CRUD、密码哈希持久化、会话角色与响应脱敏、敏感接口和写入拒绝、重置及删除后的会话失效、限流计数保留，以及吊销容量阈值下的会话隔离。

### WP-12 强制改密状态

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login::login_legacy_weak_password
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 176 项工作区测试和 9 项本机 Pebble ACME 测试。用例验证旧默认密码和弱密码识别、重启后改密状态、有效强密码登录无需写账号文件、TOTP 完成后提交以及提交失败时拒发会话。HTTP 回环验证改密豁免、普通令牌操作和安全配置拒绝、改密后旧会话失效。界面语言豁免使用测试路由验证，持久化由 WP-07 接入。

### WP-12 剩余链路与启动验收

第 10 步接入第三方登录，第 11 步接入账号恢复，第 12 步接入七项安全评分，第 13 步接入可选的管理监听。首次启动、登录、改密、登出及在线重置已通过真实进程和回环 HTTP 验证。macOS arm64、Rust stable 1.100.0 上通过 180 项工作区测试和 9 项 Pebble ACME 测试。Clippy、格式检查和差异检查通过。

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth --test reset
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login_oidc
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway management_bootstrap
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

启用回环管理监听的示例：

```bash
fgate serve --config ferrumgate.example.toml \
  --admin-listen 127.0.0.1:8080 --admin-dir "$PWD/management"
```

如管理服务由受信代理对外提供，配置 `--admin-origin`，必要时同时配置 `--admin-prefix`。第三方登录配置在 `ferrumgate.json` 的 `thirdLogin` 字段，也可通过管理员设置接口保存。允许列表按提供方与稳定身份指定，例如 `github:<数字 ID>`、`qq:<OpenID>` 或 `oidc:<sub>`。将外部管理地址与前缀拼接 `/api/login/oauth/callback`，作为提供方登记的回调地址。全局字段缺失时，兼容使用 `--admin-origin` 和旧文件 `third-login.json`。

```json
{
  "thirdLogin": {
    "enable": true,
    "callbackBase": "https://admin.example.test",
    "providers": [
      {
        "key": "oidc",
        "name": "Organization login",
        "type": "oidc",
        "issuer": "https://identity.example.test",
        "clientId": "<client id>",
        "clientSecret": "<client secret>"
      }
    ],
    "allowed": ["oidc:<subject>"],
    "skipTotp": false
  }
}
```

`fgate reset-password --admin-dir <目录>` 交互式读取新密码，可用 `--disable-totp` 同时清除二次验证。`fgate reset-totp --admin-dir <目录>` 仅清除二次验证。两条命令需要输入 `yes`。运行中请求由管理服务轮询应用，离线时命令直接更新账号。

验收边界包括物理认证器、旧 Passkey 格式迁移、真实身份提供方，以及依赖 WP-07 的界面语言与全局设置、WP-08 的持久化审计和 WP-14 的可信代理、安全入口及飞牛统一网关。当前管理监听使用回环地址。[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) · [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

### WP-13 令牌存储与认证核心

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth --test tokens
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 185 项工作区测试和 9 项本机 Pebble ACME 测试。令牌核心用例验证了明文一次性返回、私有文件权限与历史排除、摘要认证、停用与过期、轮换及删除、写入失败时保持有效凭据、旧记录加载、未编译权限保留，以及使用记录的节流与重启恢复。运行期刷盘调度和 HTTP 鉴权由后续步骤接入。

### WP-13 遗留令牌迁移与权限继承

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-auth --test tokens
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway admin::
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 189 项工作区测试和 9 项本机 Pebble ACME 测试。真实进程启动用例验证旧 `apiToken` 自动迁移、其他设置保留和迁移失败时初始密码仍可取用。令牌用例验证重复迁移、写入失败时保留旧字段、避免把明文写入历史快照，以及通配与目标域已有权限的继承规则。

### WP-13 令牌管理接口

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin tokens::
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 190 项工作区测试和 9 项本机 Pebble ACME 测试。回环 HTTP 用例覆盖八个管理接口、会话权限、明文只在签发和轮换时返回、轮换后旧值失效、排序校验与批量分组回退。真实进程用例验证管理员登录后可通过 `/api/tokens` 读取遗留令牌元数据。运行期 Bearer 鉴权和使用记录刷盘由第 5 步接入。

### WP-13 创建与使用 API 令牌

使用管理员会话向 `POST /api/tokens` 提交 `{"name":"collector","scopes":["logs:read"]}`。从响应保存一次性 `secret`，将其传给客户端的 `FGATE_API_TOKEN` 环境变量。以下示例假设管理监听地址为 `127.0.0.1:8080`。

```bash
curl --fail-with-body \
  --header "Authorization: Bearer ${FGATE_API_TOKEN:?}" \
  http://127.0.0.1:8080/api/logs/sources
```

同一令牌访问 `/api/session` 返回 `api-token:collector`，访问 `/api/tokens` 返回 403。若需轮换，通过管理员会话调用 `POST /api/tokens/{id}/regenerate`，保存响应中的新 `secret`。轮换提交后旧值立即失效。

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --bin fgate auth_maintenance_flushes_due_token_usage
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway admin::management_bootstrap_login_change_logout_and_online_reset
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 191 项工作区测试和 9 项本机 Pebble ACME 测试。真实进程用例覆盖签发后使用、权限不足返回 403、无效凭据返回 401、遗留令牌及会话 Bearer 兼容、以 TCP 对端记录来源，以及正常退出后恢复最近使用记录。维护用例验证达到刷盘间隔后，即使没有新请求也会写盘。本机 curl 演练确认日志来源接口返回 200、令牌管理接口返回 403、收到 SIGTERM 后保存最近使用记录。可信代理地址解析、持久化审计和备份分别随 WP-14、WP-08 和 WP-70 验收。

### WP-07 全局设置模型与规范化

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-core --test settings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 197 项工作区测试和 9 项本机 Pebble ACME 测试。六项模型用例覆盖空配置、上游 `442162e` 的 JSON 字段与 `null` 列表、旧字段省略、未知及重复字段拒绝、规范化幂等性与自定义状态码保留。字段校验和生效方式判定在步骤 3～4 接入，随后装配管理接口和进程启动路径。

### WP-07 字段校验与生效方式

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-core --test settings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 203 项工作区测试和 9 项本机 Pebble ACME 测试。12 项设置测试覆盖监听地址、访问限制、数值边界、时区、DNS 与代理、日志路径、第三方登录配置和模块依赖。用例验证单次返回多个字段错误且不回显秘密，并核对设置生效方式与差异列表一致。依赖沿用锁定版本 `ipnet 2.12.2`、`url 2.5.9` 和 `jiff-tzdb 1.0.0`。真实管理 API、目录可写性与运行时更新在步骤 5～6 接入。[时区数据库](https://github.com/BurntSushi/jiff/tree/master/crates/jiff-tzdb)

### WP-07 设置管理 API 与持久化

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin settings::
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 204 项工作区测试和 9 项本机 Pebble ACME 测试。回环 HTTP 测试覆盖三个设置接口的管理员会话权限、响应脱敏和 `no-store`、完整表单往返、错误字段聚合、严格 JSON、日志目录探测和重启提示。校验失败与文件替换失败保留原快照，保存成功后订阅者收到新快照，重复保存相同设置不会重复通知。当前验证路径为独立管理路由，后续接入 `fgate serve`、会话时长写入和运行期消费者。

### WP-07 真实启动与运行时设置

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin settings::
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway admin::
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 205 项工作区测试和 9 项本机 Pebble ACME 测试。真实进程用例覆盖命令行覆盖保存地址、运行中切换日志级别、登录限流即时更新、保存后原模块继续服务、重启应用保存地址及模块开关、会话时长持久化和无效设置拒绝启动。回环 API 用例分别阻断设置文件和账号文件的写入，验证账号更新失败时可重试，已保存的全局设置与读回快照一致。

### WP-07 运行日志目录与保留参数

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-logging --test reconfigure
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway admin::management_switches_log_directories_and_keeps_memory_when_persistence_is_disabled
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 207 项工作区测试和 9 项本机 Pebble ACME 测试。真实进程用例覆盖默认落盘、拒绝静态根下的目标、占用期间保留原目标、释放后自动切换、停用后继续查询内存环与恢复后序号递增。日志库用例覆盖同目录更新内存行数和轮转上限，以及按天数和容量淘汰归档。Web 请求访问日志生产者由 WP-28 接入。

### WP-07 全局第三方登录

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway admin::management_switches_third_login_from_legacy_and_disables_pending_flows
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin login_oidc
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 208 项工作区测试和 9 项本机 Pebble ACME 测试。真实管理进程测试覆盖旧文件兼容、运行中切换到本机 OIDC、回调源校验、路径前缀与 PKCE、停用时拒绝已开始的回调，以及重启后保持停用。签名 OIDC 用例覆盖合法身份与浏览器绑定，设置用例覆盖密钥和代理凭据脱敏及还原。真实 GitHub、Google、QQ 和生产 OIDC 环境待验收。

### WP-08 审计日志

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --lib audit
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin audit::
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 221 项工作区测试和 9 项本机 Pebble ACME 测试。判定规则用例覆盖变更方法、只读 POST 跳过清单、敏感读取片段与备份列表豁免。审计库用例覆盖最新优先查询、类别与文本过滤、轮转保留三份且幸存记录为最新连续段、队列满丢弃计数、钩子按写入顺序逐条回调，以及冻结目录下轮转失败计数且条目继续追加。回环 HTTP 用例覆盖登录成功与失败的原因键、变更与敏感访问记录、请求体与凭据不入档、令牌操作者命名 `api-token:<名称>`、只读账号与令牌查询 `/api/audit` 被拒、非法查询参数返回 400，以及审计写失败不影响请求成功。管理进程把每条变更与访问记录经钩子发布为 `audit.change` / `audit.access` 事件。可信代理的 `via` 字段随 WP-14 验收。

### WP-03 重启与离线回滚请求

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway management_restart_reexeces_with_same_pid_and_listener
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway management_takes_offline_rollback_requests_while_running
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 223 项工作区测试和 9 项本机 Pebble ACME 测试。`POST /api/system/restart` 仅限管理员会话，响应写出 500 毫秒后触发重启；`bootstrap::serve` 以 `Outcome::Restart` 返回，主程序用标准库的安全 `exec` 封装以相同参数与环境重新执行自身，失败或不支持的平台以退出码 3 退出。端到端用例验证重启后 PID 不变、固定管理监听恢复、凭据可用且 SIGINT 仍能干净退出；用例等待第二次 `management ready` 日志行而不是抢先连接，避免把请求发给尚未被替换的旧镜像。管理进程启动时对配置存储启用历史（保留 30，跳过账号、令牌与登录来源），2 秒维护轮询在应用账号重置与令牌刷盘之外取走并应用 `rollback-request.state`，运行中写入请求文件的用例验证文件被取走且配置回退到上一版本。`fgate run` 子命令、`Boot`/`Clock` 与声明式目录应用随 WP-39 前的配置解析决策接入；Windows 路径（退出码 3 加外部拉起）待实机标注。

### WP-06 声明式配置

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-config --test apply
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway management_applies_declarative_directory_before_config_load
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 234 项工作区测试和 9 项本机 Pebble ACME 测试。`apply_config_dir` 用例覆盖首次写入与二次跳过、缺尾换行比较前补齐、被替换内容进入历史可回读、`account`/`tokens` 报错且此前无任何写入、非法 JSON 与非法配置名报错含文件名、子目录/隐藏文件/其他扩展名忽略、按名称排序处理、来源目录登记为受保护路径及目录缺失报错。端到端用例验证 `--apply` 在读取任何配置之前覆盖已保存设置、被替换内容可在历史回读，且第二次启动相同内容不再重写或产生新历史。环境变量 `FERRUMGATE_APPLY_DIR` 走 clap 的 env 装配，与 `--apply` 同一参数位。启动日志记录应用与跳过的数量及名称。git 仓库下发演练：把 `<名称>.json` 提交到仓库并以 `--apply` 指向检出目录，每次启动幂等应用；与本用例的二段启动验证等价。

### WP-10 国际化基础链路

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-i18n
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p xtask
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 253 项工作区测试和 9 项本机 Pebble ACME 测试。`fg-i18n` 用例覆盖规范化（大小写、分隔符、简繁与地区归并、未知标签）、`Accept-Language` 的 q 值与顺序、`*` 与未编译档位回退、服务端环境变量链、`tr` 源语言与空值键回退、`tr_args` 以键为模板渲染与占位符规则、`tr_deep`/`tr_fields` 的字段选择（用户字段不翻译）。`build.rs` 在编译期校验并压缩嵌入 9 个语言目录，运行时按语言惰性建表。`xtask` 的提取器识别第二参数为含中文字面量的 `tr!` 调用（含转义与嵌套括号）并跳过 `tests/` 目录；一致性检查作为 `cargo test -p xtask` 的一部分运行，覆盖键集合、占位符与译文等于键三类违规，删译文失败的用例以临时目录固定。管理进程把 `Localizer` 接入响应链，默认语言取规范化的设置 `language`、缺失时回退环境变量链，按请求 `Accept-Language` 协商。已核实上游快照不含服务端译文文件（由 `i18nsync` 生成、键值待翻译，仅界面目录随仓库分发），因此 9 个语言目录以空键集就绪，译文随各模块 `tr!` 键经 `cargo run -p xtask -- i18n-extract` 同步后补齐；新增文案流程已写入 `docs/AGENT.md`。界面目录（WP-80）与语言档位（WP-90）另行接入。

### WP-15 回滚命令

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test rollback
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 257 项工作区测试和 9 项本机 Pebble ACME 测试。`fgate rollback --admin-dir <目录>` 支持交互选择、`--last`、`--pending`、`--config`+`--version`、`--list` 与 `--yes`；执行前要求输入 `yes`，非交互且无 `--yes` 时取消并提示。命令先确认目录内存在全局设置或账号文件，外来目录直接拒绝且不写任何内容。回滚请求经 `write_request` 写入后，每 200 毫秒检查一次是否被运行实例取走（至多 6 秒，大于服务端 2 秒轮询），取走则提示「已交给运行中的实例处理」；超时则取回请求并离线 `apply_offline`，提示改写内容已入历史。Unix 上请求文件的属主对齐账号文件。端到端用例覆盖离线改写（文件内容回到上一版本且被替换内容入历史）、外来目录拒绝、缺确认取消（配置不变、无请求文件残留）与委托运行实例（真实 `fgate serve` 进程取走请求并完成回滚后 SIGINT 干净退出）。`ctl` 与 `mcp` 子命令随后续步骤接入。

### WP-15 ctl 与 MCP

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --bin fgate mcp
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test ctl
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test mcp
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 275 项工作区测试和 9 项本机 Pebble ACME 测试。`fgate ctl` 提供 `ls`/`get`/`post`/`put`/`delete`/`patch`/`login`：连接信息按内置默认（`http://127.0.0.1:16680`）→ 用户配置目录 `ferrumgate/ctl.json`（0700 目录内 0600 文件）→ `FERRUMGATE_URL`/`FERRUMGATE_TOKEN` → 命令行选项的顺序覆盖，`insecure` 一旦被任何一层启用即保持；路径必须以 `/api/` 开头，请求体接受 JSON 字面量、`@文件` 与 `-`（标准输入）且必须是合法 JSON；成功输出格式化 JSON（`--raw` 输出原文）并以 0 退出，接口非 2xx 输出 `错误: HTTP <状态>: <说明>` 以 1 退出，参数问题以 2 退出。`ls` 读取实例 OpenAPI 只列出 `x-token-allowed` 的操作并可按关键字过滤；`login` 先以 `/api/session` 验证令牌，无效令牌不落盘。HTTPS 经 webpki 根证书验证，`--insecure` 使用接受任意证书的校验器。单元用例覆盖覆盖顺序、文件 0600、路径校验与三种请求体来源；端到端用例（真实 `fgate serve` 实例与 `gtl_` 前缀 48 位十六进制令牌）覆盖退出码与格式化输出、`ls` 隐藏会话专属接口、`login` 拒绝无效令牌并持久化有效连接，以及配置文件在无命令行参数时供连接。

`fgate mcp` 通过标准输入输出提供 JSON-RPC 2.0 服务（每行一条消息）：`initialize` 返回协议版本 `2024-11-05` 与 `serverInfo`，`tools/list` 在首次请求时读取实例 OpenAPI 生成并缓存工具，`tools/call` 执行调用；通知与未知方法按 JSON-RPC 处理（前者不回复、后者返回 -32601）。工具名为方法加 `/api` 以下路径（转小写、非字母数字替换为 `_`、去掉花括号，最长 64 字符，重名追加序号）；路径参数成为必填字符串，GET 工具带可选 `query` 对象，带请求体的操作有 `body` 参数；描述包含摘要、方法路径与所需权限，标注 `readOnlyHint` 与 `destructiveHint`；结果超过 200000 个字符截断并说明。默认只读：仅暴露 GET/HEAD 工具且不含路径带 `secrets` 的接口，`--write` 后才提供写操作，令牌自身权限始终生效。单元用例覆盖只读默认与 secrets 隐藏、命名规则、长度上限、重名去重、截断、路径参数必填与 schema 结构；端到端用例经管道驱动子进程验证协议握手、默认列表仅 GET、隐藏工具不可调用、未知方法报错、工具调用含路径参数与 query 的实际转发，以及 `--write` 下写工具出现但只读令牌仍被实例以 403 拒绝。修复了日志归档目录尚未创建时查询返回 500 的问题：归档列表把目录缺失视为没有归档。MCP 客户端配置示例：以 `fgate mcp --url http://127.0.0.1:16680 --token <专用只读令牌>` 作为子进程接入 AI 客户端，验证流程后再按需换写令牌并加 `--write`。

### WP-17 系统接口与演示模式

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-core
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --lib
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test system
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway demo_mode
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 301 项工作区测试和 9 项本机 Pebble ACME 测试。基础层：`CheckResult` 只含 id/status/params 且空参数省略键（有 schema 派生），Prometheus 0.0.4 输出按族聚合 HELP/TYPE 各一次、标签按键排序并转义、整数压实并支持 NaN/±Inf 拼写，sysstat 在 Linux 解析 `/proc`（含命令名带空格的 stat），其他平台以无损缺省返回。状态路由返回模块三态矩阵与运行时字段，info 报告构建内容（集成测试用真实监听验证 webservice=enabled、ssl 由依赖恢复、portforward=disabled、ddns=absent）。公网地址：并发刷新共享一次查询（两族共 2 次调用）、10 秒窗口零新增出站、族失败进 `errors`、GET 不出站。probe：目标解析拒绝凭据与非 http(s)、错误映射七类稳定类别。自检：组网网卡上的 CGNAT 地址不计入、直连公网按网卡命名、时钟阈值 90s/600s 分级、`Date` 头偏差估算；端点仅限会话。存储统计按分类累加且符号链接永不跟随（顶层与分类两处都用 symlink_metadata），外部日志目录单独列出。指标端点输出 `ferrumgate_` 前缀的全局 gauge 并要求 `metrics:read`。onboarding：场景校验/去重、清单项编号模式与 32 项上限、dismiss 清除 `scenePending` 且 `done` 保留、全新安装判定不触碰已有部署（单元测试固定）。演示模式：`--demo`/`FERRUMGATE_DEMO=1` 开启，守卫在鉴权之外，端到端用例验证真实进程下管理员会话的写请求与敏感读取被 403「演示模式下不可用」拒绝而普通读取与登录放行。诊断包、GeoIP 查询与模块摘要/指标随对应工作包接入。

### WP-04 保存后确认与自动回滚

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-config --lib confirm
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test rollback unconfirmed_save
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 311 项工作区测试和 9 项本机 Pebble ACME 测试。状态文件字段名与上游一致且零值省略（waitRestart/rollback/hold 不出现），begin 合并进行中的登记保留第一次保存前内容并重设截止；recover 覆盖三种回滚结论——rollback 标记、截止已过、启动满 3 次——均恢复归档内容并删除状态，未到期时以 45 秒宽限为下限继续等待并计一次启动；部分恢复失败时启动拒绝继续且状态保留供重试；wait_restart 在下一次启动开始计时；discard 清除状态后确认返回 none；手动回滚要求存在待确认状态并记录错误。管理接口挂载三个仅限会话的端点，WebSocket 确认在新建连接上任何消息生效、整个交换限时 10 秒。端到端用例构造已过期的待确认状态并启动真实 fgate serve：配置在监听就绪前恢复为保存前内容、状态文件消失、实例以 SIGINT 干净退出。保存登记的中间件与 X-Gately-Confirm 请求头链随 WP-05 的批量修改一起接入运行实例；手动演练步骤：改坏端口转发目标 → 界面倒计时 → 新连接确认或 POST /api/system/confirm/rollback → 观察重启后配置恢复。

### WP-05 批量修改与访问路径识别

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-core --lib apply_hold
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-core --lib access_path
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test system
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 325 项工作区测试和 9 项本机 Pebble ACME 测试。ApplyHold 用例覆盖暂缓队列语义：begin 返回上一批遗留项并可并入本批；defer_action 同模块同键只保留最后一个动作且保持原位；release 按登记顺序执行且不持有队列锁、动作可重入；drop_all 丢弃并结束暂缓；apply 之后暂缓保持到确认或放弃。访问路径用例覆盖 HMAC-SHA256 签名路径头与常量时间比较、8 跳上限、无登记时回退本机端点跳、missing 标记已删规则。九种风险各一正一反：编辑忽略名称/分组/备注等纯显示字段且仅对带键规则生效；删除/停用命中路径上的规则；模块关闭在路径穿越该模块时报告；站点迁移对比已存监听；管理监听变更、仅内网与强制 HTTPS 依赖访客来源；改用的监听地址做本机绑定测试并附系统原因。六个仅限会话的端点经 SystemRoutes 挂载：changeset begin/check/apply/discard 与 access-path 视图、access-path/check。模块的 defer_action 接入与 L4/Web 服务的跳登记随 portforward、protoroute、webservice 工作包落地；演示模式下批量修改同样受守卫限制。

### WP-14 管理访问控制与统一网关

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-net
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --lib access
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --lib gateway
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test admin_access
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-admin --test gateway
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 386 项工作区测试和 9 项本机 Pebble ACME 测试。`fg-net` 的解析矩阵九例：不可信对端的转发头一律忽略、`X-Forwarded-For` 自右向左跳过可信代理取第一个不可信地址、双头不一致时公网优先（伪造内网地址不能绕过仅内网访问）、`verified`/`via` 语义、CGNAT 与 IPv6 ULA 的内网判定，以及 `trust_src` 登记表。accept 决策矩阵覆盖各拒绝方式与仅内网组合；256 连接上限与 64 KiB 丢弃上限用真实 socket 对实测——第 257 条挂起连接被直接断开、发送超过 64 KiB 后结束挂起、客户端放弃视为正常结束。安全入口标记 13 项：入口路径的合法与非法值、同密钥往返有效、伪造（篡改载荷与签名）、过期与换密钥后一律拒绝、Cookie 的安全属性与清除。五种响应方式集成测试：`notfound` 正文仿默认页且不含产品信息、`blank` 空体、`custom` 的可选状态码与沙箱 CSP（`default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; sandbox`）、默认方式的 403 不带 `Vary` 头、保存时清洗并报告移除内容。网关纯函数 8 项：前缀规范化、来源键与来源确认（仅管理员会话或管理员登录成功可确认，`same-site` 拒绝、无来源放行登录退出）、`gateway_origins.json` 的持久化与 16 项上限、网关客户端地址取 `X-Real-IP` 或最右 `X-Forwarded-For`、Cookie `Path` 与资源路径改写、`gately-base` 注入的 HTML 转义、按飞牛用户的限流键 `fnOS:<用户名>`；`listen_unix` 清理陈旧 Socket 并拒绝同名普通文件、权限 `0660`。

深度集成接线（386 项含新增）：管理监听改走自定义 accept 循环——accept 时经 `accept_action` 落实 `close`（直接断开）与 `drop`（共享 HoldSlots 池挂起，drain 即中止、in-flight 连接 3 秒窗口后取消），Serve 连接经 hyper-util auto builder 支持 WebSocket 升级与 h2 CONNECT 协议，每连接注入 `ConnectInfo`；`--gateway-socket`/`--gateway-prefix` 启用 0660 Unix Socket 的完整 serve 链——restore 以整体包裹方式生效（axum 0.8 的 layer 在路由匹配之后，前缀剥离必须包裹路由器，测试已钉住）、origin guard 确认并持久化来源、rewrite_response 改写 Location/Cookie/首页，网关路径跳过仅内网/安全入口/强制 HTTPS；`POST /api/login/fnos` 经 Socket 标记 + gatewaySSO + `X-Trim-*` 四条件签发管理员会话（已有会话保持、失败统一 403 不泄漏状态），`SessionCookies` 公开供二进制构建；访问入口路径时种植签名标记 Cookie，端到端验证「访问入口 → Cookie → 门禁开启 → 认证应答」全流程；真实进程冒烟覆盖双就绪日志、跨源 403、TCP 直连 `X-Trim-*` 一律拒绝。HTTPS 证书装配经 WP-31/WP-32 联调。诊断包（`GET /api/system/diagnostics`，仅会话）输出脱敏 JSON 预览：redactor 覆盖配置目录/主目录/主机名字面量、密钥键值对、认证头、bearer/basic 凭据、秘密命令行参数、MAC、长令牌与用户路径；地址折叠为方案/端口/IP 类别（CGNAT 单列），非公共域名替换为 `<domain>` 并保留公共服务白名单；配置 JSON 保留结构、枚举与时间键，动态键匿名化、数组截断至 100、其余字符串一律 `<redacted>`，账号与令牌文件永不读取（负向测试断言密钥、域名与真实地址不入档）。

### WP-36 L4 共用基础

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-net
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-gateway --lib l4::shared
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway tcp
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway udp
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p ferrumgate --test gateway acme::pebble -- --ignored
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 409 项工作区测试和 9 项本机 Pebble ACME 测试。`fg_net::ports` 的解析四例：混合写法保序展开（单端口、逗号列表、范围、全角分隔符）、非法输入区分空项/端口 0/越界/逆序范围（u32 先行解析使 0 与 65536 错误各异）、目标映射单目标复用与等长按位、collapse 去重排序合并连续区间。`quota` 五例：默认一半（第 6 条连接对同源 Full、另一来源仍成功）、豁免网段永不 Full、回环/内网/CGNAT/ULA 全豁免（复用 WP-14 的 is_internal 口径）、IPv6 按 /64 分组且 ::ffff: 映射与 V4 同组、许可 drop 释放与 10 秒告警节流。`openports` 两例：属主覆盖与空表撤销、快照读侧无锁（ArcSwap 旧代快照不随发布变化）。`source_rule` 五例：封禁 → 拒绝名单 → 白名单/黑名单 → 敲门的顺序（封禁胜过名单命中、敲门关闭时名单命中也拒绝）、实时注册表查询（同过滤器下清除封禁即放行，不重建）、mapped-V4 前缀缩减与聚合、逐清单错误命名、1024 项上限。`l4::shared` 七例（真实 socket 对）：半关闭保留（一端 EOF 后另一方向继续）、双方沉默时首次数据超时、任一方发言后不再受限、取消闭包排空返回 Killed、顺序拨号在第二监听器（静默但可连）成功、全部拒绝返回最后一个错误、PROXY v1 文本行与 v2 二进制布局（v4 28 字节/v6 52 字节）逐字段回读。

步骤 7 纯重构：tcp_forward 的私有故障转移循环、PROXY 头写入、CountWrites 与首数据 peek 全部替换为共用组件（stats 计数映射 bytes_out/bytes_in、FirstData::None 保持双侧等待语义、日志文案逐条复现）；forward_ports 的展开循环改为委托 `fg_net::ports::parse_ports`（SocketAddr 形 API 与 64 上限不变，既有单测不改地通过）；source_policy 删除 29 行重复的 `compile_networks` 改为重导出 `fg_net::source_rule::compile_networks`。三个消费文件净减 125 行，`tests/gateway/tcp` 12 项、`udp` 10 项、`fg-gateway` lib 18 项一个不改地通过。splice 式零拷贝记录为后续优化；订阅列表由 Web 服务写入 `fg_net` 注册表的句柄随 WP-26 接入。

### WP-34 端口转发对齐（模型与运行时基础）

```bash
RUSTUP_TOOLCHAIN=stable cargo test --locked --offline -p fg-gateway --lib portforward
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --locked --offline --all-targets -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo fmt --all --check
git diff --check
```

macOS arm64、Rust stable 1.100.0 上通过 439 项工作区测试和 9 项本机 Pebble ACME 测试。模型七例：零值设置规范化为上游默认（256/60/1024/5/60）、首数据超时 3600 钳制、缺失协议/监听/目标一次收集、目标端口数「1 复用或按位对应」、每来源默认零的契约、PROXY 拒绝 UDP 规则、重复 key 收集。编译五例：每来源默认推导链（规则 → 设置 → 一半下限 1）、跨规则错误一次收集、禁用规则跳过、按位目标映射（裸 IP 附加映射端口、固定 address:port 忽略）、空监听地址通配与空目标端口恒等映射。运行时两例：UDP 预算获取/释放、规则快照原子替换。routes 二十四例（完整 HTTP）：创建（客户端键保留、重复重生成）、无效创建 400 带问题清单且不持久化、复制后源插入、更新整体校验、单项与批量删除（缺失 404、空键 400）、排序（恒等跳过持久化）、启停计数、分组截断与 65 字符拒绝、设置 PUT 应用默认并钳制、未知字段 400、无效 JSON 400；提交顺序为 fg-admin 集合契约的镜像（持久化先行、内存快照随后、on_change 最后）。lucky 六例：三种安全模式的名单映射、自建规则按动作并入、不可导入项告警、键唯一性、camelCase 解析。

随后续增量：数据面 serve 循环接入 l4 Module（bind/accept/来源判定/拨号/管道）、WP-39 同批的 TOML 迁移映射与既有 tcp/udp/metrics 测试改生成新模型、Lucky 导入的路由接线。

数据面桥接与测试迁移（444 项工作区测试）：config::load 读取 TOML 旁的 portforward.json——parse FileConfig → 校验（问题以字段:原因清单失败）→ compile → 每条 CompiledRule 经其 serde 定义桥接为既有 TcpForward/UdpForward（监听主机+逗号端口表、逐监听目标行、上限与来源列表——既有 TOML 校验原样适用），追加到 TOML 转发之后并共用 MAX_LISTENERS/重复监听/UDP 会话数检查；serve、check 与 SIGHUP 重载同路径生效（重载仍拒绝监听/上限变更、放行来源策略更新）。tests/gateway/common.rs 增设 forwarding_json 助手（JSON 模型拒绝端口 0，:0 监听解析为预留的具体端口），tcp/udp/metrics 三套测试改由 portforward.json 构建转发、断言逐字节不变——唯二强制适配是秒级时间粒度（500ms → firstDataTimeout:1）与无 connection_lifetime 字段时主动 drop 客户端释放计数器；非法配置用例映射为 JSON 模型等价物（firstDataTimeout:4000、重复 key、目标端口命中自身监听、65 监听器超 64 上限）。

### 工作包状态核查与第三方登录评审

主方案和本地细化目录的状态已按运行入口及已有验收同步。运行日志、管理认证、令牌和全局设置有本地证据。进程装配、Web 数据面、证书和端口转发按现有实现标为部分实现或前置。上游配置模型、生产服务验收与跨包联调按各包记录跟踪。

- 已修正第三方登录密钥还原条件。更换客户端身份后提交旧遮蔽值会拒绝保存，原配置和提供方快照保留。
- 已修正 OAuth 配置切换中的登录记账。测试使用本地签名提供方，验证配置失效后的合法旧流程不会写入常用来源。
- WP-11 的 `fgate api-docs` 目前导出默认路由器，仅包含 `/api/openapi.json`。运行实例的目录由真实路由装配生成。CLI 目录对齐待处理。

本轮在 macOS arm64、Rust stable 1.100.0 上复跑并通过 208 项工作区测试、9 项本机 Pebble ACME 测试、工作区 Clippy、格式与 Git 差异检查。CLI 目录核查使用本机构建的 `fgate api-docs` 在临时目录生成并读回 OpenAPI 文件。

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

### WP-23 后端、负载均衡、健康检查与超时（大部分交付）

- 2026-11-27 交付三个增量（101fd2a、a830ed0、290a73d）：`web/upstream/` 模块（地址行 weight/backup、候选主→备→全主回退、被动摘除 3 次/30 秒、探测驱动恢复、加权轮询/随机/ip_hash/least_conn、至多 3 后端仅建连失败重试、主动检查参数对齐 1–3600/1–60/1–20/1–20 与 PROXY 协议强制 TCP 降级）与 `web/proxy/` 特性模块（后端/访客超时、头增删改、正则重写与重定向、CORS、身份头、按用户分流），全部纯逻辑 + 单元/性质测试。
- 管线接线：`Site` 新增 WP-23 全部字段，`ProxyRoute.options`（Box 聚合，TOML 路径 `Box::default()` 保持旧行为逐字节不变）承载按站点编译的身份头/重写/头改写/CORS/站点级响应头超时；`forward()` 先剥身份头（连字符/下划线双拼写防伪造），重写在转发前执行（重定向直答、内部重写保留 query），CORS 预检本地应答，Host 与转发头开关生效。9 组字段校验进入 `web/validate`。
- 与旧实现的默认值差异（迁移时需提示，建议采用新默认值）：现有连接超时 2 秒/响应头 30 秒（设置级）对应新模型的连接 10 秒/握手 10 秒/响应头不限（站点级可覆盖）；转发头当前为始终写（新模型 `forwardedHeaders` 可关）；`Host` 当前恒为目标地址（新模型 `useTargetHost=false` 保留访客 Host）。
- 测试：31 + 29 + 24 个新测试；fg-gateway 全量 188 lib + 3 集成；根 gateway e2e 68 通过（9 忽略）；Clippy 0 警告。
- 尚余（3b 增量）：建连失败重试接入 `forward()`（需小体积精确长度请求体缓冲重放；hyper `Incoming` 被 client 消费后不可重放，`Attempt`/`body_read` 标记逻辑已单测就绪）；四种负载策略替换 legacy 池选择（`Pool::from_site` 编译入口已就绪，尚未被 bridge 消费）；per-site TLS 客户端（`insecureSkipVerify`/`upstreamSniFromHost` 需按站点客户端，`disableKeepAlives` 需空闲池归零客户端组）；`sendProxyProtocol` 发送；访客读写空闲超时进服务循环；身份头写入（等 WP-24 Visitor）与按用户分流分派进 `dispatch`。

### WP-31 证书条目模型与多种来源（步骤 1-9 交付）

- 2026-11-28 交付三个增量（a3be4ac、2b25eeb、c04bf5d）。a3be4ac（步骤 1-3）：`ssl.json` 模型（`settings`、`certs[]`、`accounts{}`，条目含 key、remark、group、enable、source、acme、certFile/keyFile、fnosDomain、certPem/keyPem/issuerPem、mapping/deploys 占位、updatedAt、issuedProfile）与规范化校验（0 值取默认 30 天/24 小时、`shortLivedRenewHours` 钳 80、备注字符集 `^[A-Za-z0-9*_.@-]+$`、文件来源必填双路径、上传来源解析加密钥配对、ACME `keyType` 四值、空键与重复键回填 12 位小写十六进制），以及证书信息解析（DNS/IP SAN、签发者 CN 带 DN 回退、有效期、SHA-256 指纹）和 SNI 索引（精确表、一层通配按父域为键、IP 默认取到期最晚、名称归一化含大小写/尾点/IPv4 映射与方括号 IPv6）。
- 2b25eeb（步骤 4、6、7、9）：四种来源——acme/upload 读条目内 PEM（链中只有叶子时拼入 `issuerPem`）、file 按 FNV-1a 内容指纹做变化检测重读（内容不变沿用旧 `Arc`）、fnos 跟随 `/usr/trim/etc/network_cert_all.conf`（4 MiB 截断、域名小写去尾点、目录取 privkey+fullchain 或 privkey+cert、域名被删除后保留最后加载的证书并记为错误）；`CertProvider` 整体换索引并递增 `watch` 版本，热路径单次只读快照零分配；`SslState` 加载语义（ssl.json 缺失按默认、解析失败整个模块初始化失败、单条目失败不阻塞其他）；续期调度 30 秒首查、30 分钟一轮、失败 6 小时退避（三个时长可注入），`needs_renewal` 六类理由，`enable=false` 不签发不停服务，WP-32 签发钩子已标记；`CertSummary` 分类与 `ferrumgate_cert_days_remaining`、`ferrumgate_cert_expiry_timestamp_seconds` 两个指标。
- c04bf5d（步骤 5 接线）：TLS 解析器先查 ssl.json 证书池再回退 TOML/ACME（不装配证书池时行为逐字节不变，无 SNI 仍禁用会话恢复）；`config::load` 从 TOML 旁读取 ssl.json 并把证书池交给 TLS 装配；进程级续期调度器每轮取当前代证书状态、随 drain 关闭——重启/停机 e2e 曾抓到调度器悬挂导致排空等待，改为挂到 drain 后修复。
- 接口摩擦：rustls 0.23 的 `CertifiedKey::from_der` 内建密钥匹配，配不上的私钥在装配一步即报「证书与私钥无法装配」，`keys_match` 退为二次确认；索引测试夹具不能用伪造链——`from_der` 需解析叶子证书提取公钥，假链被证书校验拒绝，最终内嵌真实自签证书与配对私钥（`fixture_key.pem`）；fnos 登记表格式没有上游 `fnos.go` 快照可核对，按宽松假设解析并在源码逐条注明，待上游快照核对。
- 测试规模：certs 模块 46 个测试；fg-gateway 全量 245 lib + 3 集成；根 gateway e2e 68 通过（9 忽略）；Clippy 0 警告。
- 尚余：步骤 8 集合与设置接口（`/api/ssl/*`，权限域 `ssl`）与步骤 11 收尾；WP-32 在 `needs_renewal` 命中点接入真实签发流程；WP-33 证书映射与部署目标；自检缺失清单接线（`cert.ok`/`expiring`/`expired` 分类已有，按实际访问域名逐个判断站点覆盖待接运行时）。

### WP-90 定制构建（步骤 1-4 交付）

- 2026-11-28 交付 f582f1e + 1f64639。`features.toml` 成为模块清单唯一来源：27 个模块（核心 3 + 可选 24）、6 分组、requires（backup→storage、webservice→ssl+waf）、三语 title/desc、3 个语言档位（all 10 语言、cjk-en、zh）、3 个预设（minimal/router/nas）、19 个发布目标。`cargo xtask modules gen` 从它确定性生成三产物——根 Cargo.toml 的 `[features]` 段与可选模块依赖、`crates/fg-core/src/features.rs` 编译期常量、上游同格式 `modules.json`——连跑两次字节一致；`modules resolve` 补齐 requires 多级依赖、输出 Cargo 参数与 sha256 组合键（金标准向量已固定）；`modules check` 校验清单 ↔ 生成产物 ↔ 根 features ↔ 已实现 crate 四者一致。
- 已定偏差（写回 WP-90 §8 注记）：gen 只为 workspace 中实际存在的 crate 生成 `mod-<id>` feature（当前实现 guard、cron 两个），check 把清单中有、crate 不存在的模块报 planned 而非错误；resolve 在选择集含未实现模块时直接报错。fg-core 的 build.rs 最小声明新顶层小节使清单继续可解析；每个 mod-*/lang-* feature 转发 `fg-core/...`，`features::built()` 因此观察最终构建配置（str 匹配非 const 稳定，门控为普通函数；生成数组带 `#[rustfmt::skip]` 保持再生成幂等）。
- 测试规模：xtask 26 项（manifest 6、resolve 8、gen 6、check 3 等）；fg-core 全量回归通过；Clippy 0 警告、fmt 干净。
- 尚余（P6）：语言档位裁剪嵌入文案与 fg-ui 清单、运行时 absentModules 行为、六种构建矩阵验收、size-baseline、fg-gateway 拆分。

### WP-37 自动放行防火墙（库实现交付）

- 2026-11-28 交付 0a55ca1。`fg_net::fwopen` 单文件承载上游 internal/fwopen 的职责拆分：实例标识（配置目录 SHA-256 短哈希，文件内自实现避免引入 sha2）与启动清理、`Group` 按 key 登记期望放行（后台线程按登记顺序串行写、与在途写互斥的 `clear_all`）、`for_listen` 端口计算（双栈/v4/v6、绑定地址限定 daddr、回环不放行、HTTP/3 同号 UDP、区间合并、规则带 `ferrumgate-open:` 注释）、30 秒对账严格照上游 diff 算法（他实例规则只标记不动、legacy 旧注释迁移、空闲链不增删）。Linux 后端探测 nft/iptables/ip6tables（含 iptables-nft 识别与内核无 nf_tables 时的 legacy 专用链回退、群晖 PRIMITIVE_INPUT、iptables-save 解析），命令以参数数组 + 10 秒超时执行；非 Linux 编译为显式 unsupported 空实现。
- 测试规模：35 个单元 + 5 个集成（全部 `{主题}_{行为}_{预期}`）；另以 `--target x86_64-unknown-linux-gnu` 交叉 clippy/check 验证 Linux-only 路径并修复 9 个仅 Linux 可见的编译错误。fg-net 仅新增 `serde_json` workspace 引用（解析 `nft -j` 输出）。
- 尚余：步骤 8 监听接线（web/pf/protoroute 各持 Group，监听成功后 `want`、停止时 `clear_all`，`Deps.fw_open` 注入）、步骤 9 Linux 网络命名空间真机验证、DESIGN/EXECUTION 的模块章节、与 WP-51 的命令执行封装共用。

### WP-50 统一封禁表（核心与 fg-guard 交付）

- 2026-11-28 交付 512477a。`fg_net::banlist`：`BanKey`（裸 IPv6 聚合 /64、v4-mapped 还原、显式 CIDR 保留）、递增封禁（30 天窗口内翻倍至策略上限；默认 3600 秒、默认上限 7 天、可配最大 365 天）、32768 上限淘汰（先到期后最早临时自动；永久与手动不淘汰）、白名单与内网忽略（默认含回环/链路本地/100.64/10/ULA）、登录免封（仅免 trap/scan，24 小时、1024 上限）、手动封禁拒绝回环目标、ArcSwap 无锁 `is_banned` 热路径、`guard/bans.json` 持久化（0600、tmp+rename、2 秒合并延迟保存；fg-net 不引 serde_json，手写编解码器）、RFC 3339 手写模块。设计稿的 EventBus/anyhow 依赖改为 `BanHooks` 回调与 `io::Result`（fg-net 依赖边界不可扩，语义不变）。
- `fg-guard`：guard.json 设置（enable/firewall 占位〔WP-51〕/时长参数/ignorePrivate/ignoreList）、`GuardService` 门面（`guard.banned` 事件、`table()` 共享句柄）、`/api/guard` bans/settings/status 集合契约路由、容量自检（>90% 警告）、`fg_core::module::Module` 入口（ID=guard，drain 后 flush）。
- 测试规模：fg-net 16 单测 + 6 集成、fg-guard 8 单测 + 7 集成，共 102 项相关用例全绿；Clippy -D warnings、fmt 干净。
- 尚余：根进程接线（REGISTRY/管理路由/自检/登录免封/本机 /64 收集/`Deps` 注入）、WP-51 nftables 集合同步（settings.firewall 占位）、WP-52/53 的 trap/scan/jail 生产者、WP-26 调用点切换；`is_banned` 的 CIDR 兜底线性扫描与上游一致，必要时 WP-51 后加前缀索引。

### WP-62 计划任务（完整模块交付）

- 2026-11-28 交付 cfe06a0。`fg-cron`：cron.json 模型（上游无 settings）、调度引擎（5 段、6 段含秒、`@every`/`@daily` 等描述符、dom/dow 双受限 OR、位掩码推进、周日 0/7 别名、中文 describe）、运行时（每启用任务一个独立 CancellationToken 循环、重叠触发记「已跳过」、错过的触发不补偿〔上游语义〕、generation watch 重载循环、drain 后 30 秒期限等在途）、命令执行（`sh -c`、env 注入 `FERRUMGATE_TASKNAME`、600 秒保护超时〔上游无字段，FerrumGate 自有常量〕、输出截 4000 字符）、HTTP 任务（reqwest，2xx 且 successContent 命中、insecureSkipVerify、超时默认 30 秒上限 600 秒）、每任务 20 条内存历史、`/api/cron` 12 个操作按集合契约（run 同步等待、失败回 500 输出摘要）。
- 测试规模：40 项（lib 27 + exec 8 + runtime 5）；外部命令替身用 rustc 现场编译的 Rust 小可执行文件夹具（约定禁 shell 脚本）；Clippy -D warnings、fmt 干净。
- 尚余：REGISTRY/bootstrap 接线、fg-logging 补 `Cron` 来源变体（当前 tracing 目标落到 System）、HTTP 出站换接 `Deps.http`（WP-14 的 OutboundHttp）、全局时区注入（WP-07）、Windows `.bat` 分支按文档实现未本机验证。

### WP-41 DNS 提供商适配（步骤 1-6 交付）

- 2026-11-28 交付 d542b19。fg-dns 核心机制：`DnsProvider` trait + 能力一致性注册宏（声明 ACME 能力必须提供 `TxtRecords` 实现，编译期保证）、`UpsertAction` 与上游语义一致、八类 `ProviderError`（含 i18n 键与密钥脱敏）、`OutboundHttp`（hyper-util + webpki 根、20 秒默认超时、4 MiB 响应上限、不跟随重定向、日志只记 method/host/path/status）、七类错误经本地假服务器逐一验证、删除流程纯函数（A/AAAA 地址折叠含 v4-mapped、TXT 去引号、CNAME 尾点）、TXT_TTL=600、Go 兼容转义的 simple 骨架、35 个内置多级后缀的拆分表（未收录后缀回退最后两段，可在配置显式指定主域名）、自定义回调渲染器。
- 第一批 9 个适配项全部带契约测试（方法/路径/认证头/请求体逐字段对照上游测试样例，55 项契约断言）：cloudflare、dnspod/dnspodcom、duckdns、dynv6、porkbun、callback、gandi、bunny。
- 已核实偏差（写回 WP-41 文档注记）：文档「37 项」与契约表实际 36 行不符，`ALL_NAMES` 按契约表 36 个名称收录；cloudflare/dnspod/dnspodcom/porkbun/dynv6 的能力标记按上游源码为准（均支持 TXT 增删），与 §3.3「Cloudflare/DNSPod 的 ACME DNS-01 即可用」一致。
- 测试规模：116 项（单元 61 + 契约 55）；Clippy -D warnings（含 no-default-features）、fmt 干净；每提供商一个 `dns-*` feature，default 为空、测试自依赖启用全部。
- 尚余：步骤 7 签名工具（SigV4/TC3-HMAC-SHA256/阿里云 RPC/华为云 AK/SK/OVH 三步）、第二三批 28 项、与 WP-40/WP-32 的联调（`Deps.http` 换接 fg-net 出站策略）、`credentials_extra_masked_for_readonly` 随 WP-11 脱敏约定。

### WP-91 持续集成（第一梯队交付）

- 2026-11-28 交付 1e7377b。`.github/workflows/ci.yml` 四个 job（fmt / clippy / test / modules-check）全部经 `cargo xtask ci <job>` 单一代码路径（本地与 CI 同命令）；最小权限（contents: read、persist-credentials: false）、按 job 超时、分支级并发取消、按 Cargo.lock 键控的依赖缓存、actionlint 以固定 SHA 安装。dependabot 周更 cargo 与 actions（docker 待 WP-92 有 Dockerfile 后启用）。xtask 新增 ci 规划器：job 目录与外部环境要求、八变体构建矩阵（六种构建 + 两个语言档位，预设经 modules resolve 展开）输出 workflow-ready JSON、Pebble/网络测试等后续 job 的环境探测。40 项 xtask 测试（含工作流内容断言）；本地已跑 actionlint 与 YAML 校验，runner 实际行为待首跑验证。其余 job（supply-chain、msrv、cross、ui/e2e/pebble）随 WP-92/32/80 接线。

### WP-42 STUN 穿透（第一梯队交付）

- 2026-11-28 交付 3d8ddde（另 d990517 修复 7c38e40 引入的重复 BootOnly match 臂，恢复工作区 -D warnings 门）。fg-stun：RFC 5389 binding 编解码（XOR-MAPPED 优先、MAPPED 回退、双地址族、RFC 5769 线格式向量、TCP 自定界帧、2048 上限）、客户端（窗口内一次重传、按序服务器回退、同 socket NAT 一致性判定）、映射保持运行时（每规则独立 CancellationToken、ArcSwap 只读快照输出面、`ferrumgate_stun_*` 指标、`stun.changed` 事件、autoFirewall 经 fwopen Group 放行、drain 30 秒期限含 clear_all）、18 个操作口径的管理接口。45 项测试全部走本地假 STUN 服务器（UDP+TCP）。UPnP/NAT-PMP、内置转发、webhook/脚本通知、selfcheck 与 Lucky 导入随后续梯队。

### WP-41 DNS 提供商适配（步骤 7-8 交付）

- 2026-11-28 交付 b77de59。`src/sign/` 五套请求签名：AWS SigV4（官方 get-vanilla 套件向量）、腾讯云 TC3（官方文档哈希链 + 交叉验证签名）、阿里云 RPC HMAC-SHA1（官方示例向量）、华为云 SDK-HMAC-SHA256、OVH 三步签名，另有 BCE（百度云）签名随提供商实现；全部纯函数、时间戳由调用方注入。第二批 12 家提供商带契约测试（假服务器端按同算法重算比对签名）：tencentcloud、huaweicloud、alidns、route53（SigV4+XML）、edgeone、aliesa、baiducloud、trafficroute、dnsla、gcore、desec、vercel；能力标记与上游注册表一致（route53 仅 TXT 无删除），注册宏编译期断言。fg-dns 全量 190 项测试（74 新增）、双 clippy 口径零警告。第三批 16 项（含 ovh 提供商本体）随后续梯队。

### WP-40 动态域名（完整模块交付）

- 2026-11-28 交付 bf7a5ad（根注册与 lock 随对方会话的 WP-39 提交先行入库）。fg-ddns：ddns.json 模型、IP 来源（URL 按请求地址族钉住拨号、网卡地址、命令来源带超时与截断、停用地址替换表）、`{ipv4Addr}/{ipv6Addr}/{STUN_规则_IP|PORT|ADDR}` 变量展开、webhook 通知（URL 位置变量编码、successContent）、远端记录映射（Cloudflare proxied TTL 1、备注长度上限、删除语义复用 fg-dns pick_targets）、调度器（300 秒检查 / 3600 秒强推 / 失败退避封顶任务周期、RateLimited 取 Retry-After、stun.changed 即时同步）、批量添加解析（按行号报错、去重）、21 个管理操作、match/mismatch/unresolved 自检。66 项测试走本地假服务器与假提供商。根进程接线、指标与 OutboundHttp 迁移（ip_source/webhook 获得自定义 DNS 与更新代理）随后续接线批次；`Deps::delete_remote` 建议由 fg-dns 暴露顶层便捷函数后简化。

### WP-51 防火墙同步（核心交付）

- 2026-11-28 交付 cc19fa0。fg-guard/src/firewall 把 BanTable 镜像进系统防火墙：nftables `table inet gately`（ban4/ban6 带内核超时集合，IPv6 自动封禁按 /64 网络地址入集并以掩码 saddr 匹配；deny4/deny6 interval 集合吸收重叠手动网段；prerouting 链按文档顺序放行 lo/回复流量后注释计数 drop）+ 内核无 nf_tables 时的 iptables legacy + ipset 回退（mangle GATELY_PRE 链、hash:ip/net 集合、restore -exist 批量写）。引擎增量对账：banned 钩子毫秒级唤醒、10 秒轮询、到期前 10 分钟重推、结构检查缺失即全量重写并折叠计数器基线、连续 3 次写失败降级为应用层封禁并 300 秒退避重试、停机有界等待内先清空集合。状态经 `/api/guard/status#firewallSync` 与 `GET /api/guard/firewall/rules` 暴露，自检增 guard.firewall 项。40 项新增测试（fg-guard+fg-net 全量 142 无回归）；clippy -D warnings、fmt 干净。**未在真实防火墙验证**（按 §7 要求标注）：建议在带 NET_ADMIN 的网络命名空间按 §8 顺序验证并先确认带外恢复手段。WP-53 的 redir/trap 集与 WP-54 的 knock 表随后续包扩展同一张表。

### WP-68 通知中心（完整模块交付）

- 2026-11-28 交付 7934208（并发会话已暂存的 WP-39 增量 src/lib.rs、migrate_toml、tests/gateway/common.rs 因共享 index 一并入库，已验证自洽可构建）。fg-notify：14 种渠道（webhook/telegram/bark/ntfy/gotify/pushover/discord/slack/serverchan/pushplus/wecom/dingtalk/feishu/email，业务返回码逐一检查，钉钉/飞书 HMAC-SHA256 签名以 RFC 4231 向量校验）、规则分发（事件通配与级别过滤、静默窗口去重、模板渲染含 URL 位置变量编码）、重试时间线 10s/30s/60s 后每 60s（默认 3 次上限 10）、耗尽入 `notify/pending.json` 补推队列（每渠道 100 条、0600 原子写、默认 24h 保留）倍增退避补发、全局+渠道级代理（follow/direct/updateProxy/custom；http CONNECT 与 socks5；SMTP 走同隧道，错误中密码一律脱敏）、28 个管理操作 + 测试发送 + 历史与待补推视图。74 项测试走本地假服务器（自签 TLS/假代理/假 SMTP）；clippy -D warnings、fmt 干净。渠道请求格式按各服务公开 API 实现（仓库内无上游快照对照，文件头已注明来源）；SMTP 仅 AUTH PLAIN。文档 §4「rules 各有 secrets」与总数 32 冲突，按 32 实现（rules 不带 secrets）并已在 routes.rs 注明。根进程接线与 `Deps.update_proxy`/`server_language` 注入随后续接线批次。

### WP-43 托管程序基础设施（核心交付）

- 2026-11-28 交付 a8e58de（根注册 fg-notify/fg-proc 成员、mod-notify feature、tar/zip 依赖、lock 与 gen 产物同笔落地）。fg-proc：`Proc::open` 维护 `<config>/bin`（0700、fsperm 保护）；安装器按规格解析发布 → 512 MiB 上限带进度下载（HttpGetter 注入，fg-net OutboundHttp 就绪后接自定义 DNS 与更新代理）→ SHA-256 校验（摘要文件或告警）→ 安全解包（穿越/绝对路径/符号链接/条目数/总量上限负向用例齐全）→ 运行确认 → 原子替换失败还原、保留 3 个旧版本；AutoChecker 每 12 小时发 `program.update`。监督器 SIGTERM→5 秒→SIGKILL（rustix，保持 forbid(unsafe_code)）、1s→60s 退避（稳定 30 秒重置）、输出清洗分级（frp/cloudflared 级别、URL 打码）、进程登记表不含参数与环境。45 项测试（rustc 现场编译夹具 + 本地假 HTTP 服务器真实 tar.gz 字节流）；clippy -D warnings、fmt 干净。Tailscale 等静态包清单 URL 与资产命名待各托管模块（WP-44/45/46/66）接入时对照上游发布页复核；fg-logging 进程日志来源变体与 CPU/RSS（WP-69）随后续接入。

### WP-41 DNS 提供商适配（步骤 9 交付，全量 36 项）

- 2026-11-28 交付 ba572e1。第三批 15 家（批次表实际 15 项，9+12+15=36 与契约表一致）：ovh（三步签名 + 时钟注入消除跨秒抖动、写入后强制 refresh）、ns1、cloudns、namecom、namesilo（XML reply.code、key 泄露防护）、spaceship（整域 PUT 按类型决定 force）、rainyun（线路代码）、nowcn/eranet/tnethk 三家共用 HMAC-SHA1 客户端（假服务器端重算签名比对）、hipmdnsmgr、godaddy、dynadot/namecheap/dyndns2（仅更新）。ovh 与 godaddy 的能力标记按上游注册表核对为 TXT+DEL（契约表原标注较保守，已在文件头注明）；能力断言扩至全部 36 家。fg-dns 全量 236 项测试（连跑 4 次稳定）、双 clippy 口径零警告。**WP-41 实现层收尾**：尚余步骤 10（与 WP-40/WP-32 的根进程接线联调，届时核对 dyndns2 的 UA 覆盖）与 DESIGN/EXECUTION 的提供商清单章节。

### WP-39 迁移现有 TOML 配置（步骤 1-9 交付，2026-11-28）

- `fgate migrate --config <toml> --dir <dir> [--force] [--report]` 端到端可用：读取（仅 schema_version = 1）→ 纯函数转换 → 写入（目标目录须全新/空，--force 先备份，ssl.json 0600）→ 模型级自检 → 失败回滚；源文件永不改动。
- 转换覆盖：server 段 → 监听器（保护值固化 5s/30s，显式超时保留、未配置按新默认并在报告说明）；[[routes]] → 站点（backends 权重/备援行、health 一一对应、response 三型、文本 statusCode）；[[certificates]]/​[acme] → ssl.json（file 来源 + acme 的 camelCase 参数、小时→天向上取整、DNS-01 → challenge/credentials）；TCP/UDP 转发 → portforward 规则（dial 取最大、UDP 会话求和）；ferrumgate.json 携带 disabledModules/shutdownTimeoutMs/upstreamCaFile。
- 运行时双形态：serve/check 接受 TOML 文件或配置目录（dir_config 装配器：首个启用监听器、webservice.settings.enable 开关、ssl.json 证书池直供 TLS 解析、legacy 保护值固化、connection_lifetime 保留 300s）。
- 测试切换：integration 套件经迁移目录运行（断言零改动）——11 个 migrate 单测 + 根 e2e 68 全绿。5 个场景显式留在 legacy 路径（replace+reload、websocket=false 拒绝、SIGINT 截止期、模块停用开关、证书轮换重读——均为 legacy 运行时专属语义，待 locations/身份头/WP-32 落地后迁移）。
- 迁移套件抓出的真缺陷：connection_lifetime=0 使连接瞬时过期、webservice.settings.enable 被无视、TCP 健康检查误带 path、Site Default 与 serde 语义分叉（enable/forwardedHeaders）、文本 statusCode 缺失、桥接 WS 恒禁、tls::load 守卫误拒目录形态、ferrumgate.json 空对象丢全局。
- 剩余：locations（前缀路由）落地后迁移剩余 5 个场景并移除 TOML 路径（serve --config 保留提示语一个版本）；README/样例更新随移除一起交付。

### WP-42 STUN 穿透（后续梯队交付，模块收尾）

- 2026-11-28 交付 707b26e。UPnP IGD：SSDP 发现（upnpGateway 单播 + 组播、设备描述 XML 按服务优先级解析、controlURL 强制指向网关本机否则拒绝〔§8 安全要求〕）、SOAP Add/Get/Delete 映射（错误 725 自动回退永久租期、删除前经 GetSpecificPortMappingEntry 校验归属、强制 no_proxy）、多层 NAT 判定（网关 WAN IP ≠ STUN 公网 IP 时只映射通道端口）；NAT-PMP 按 RFC 6886（250ms 起倍增重传、7200 秒建议租期半租期刷新）；运行时自动维护映射（端点变化跟随、停止规则删除映射、5 秒优雅清理）；通知按文档语义（webhook 每次成功或仅变化、脚本 30 秒上限 + 环境变量、事件仅变化/首次）；selfcheck 三项（module/rules/network，CGNAT 检测排除 tun/wg/utun 等虚拟网卡）。fg-stun 全量 70 项测试（+25）、fg-net 87 项无回归。UPnP/NAT-PMP 位置按文档 §3.1 放 fg-stun/src/upnp/（fg-net 零改动）。**跳过项**：内置转发（步骤 9）待 L4 数据面落地后在 channel socket 上接管（record_connection 计数钩子已预留）；SSDP 组播收包与真实 NAT 穿透按 §8 留待真实 LAN 验证。**WP-42 实现层收尾**：尚余 DESIGN/EXECUTION 模块章节与转发接线。

### WP-46 Cloudflare Tunnel（完整模块交付）

- 2026-11-28 交付 5e8f7f5。fg-cloudflared：token/quick 双模式隧道经 fg-proc 监督运行（`TUNNEL_TOKEN` 只进环境变量、quick 模式从进程输出解析 trycloudflare 地址、退出即重启、drain 有界停止）；ingress 编辑器经注入的 FetchFn 读写远端隧道配置（最长后缀 zone 限定本账号、proxied CNAME 同步、8 MiB 响应帽、版本并发核对 409、local 源需 force、只替换 ingress 键保留其他远端字段）；安装管理（check/rollback/backups）、settings 携带二进制与版本、reset 停全部隧道保留程序。23 个操作按集合契约；token 四种 base64 变体解析与脱敏。66 项测试（rustc 编译的 cloudflared 夹具 + 假 Cloudflare API 服务器）；clippy -D warnings、fmt 干净。**已定偏差**：crate 零网络直连（骨架中的 fg-net 依赖移除），Cloudflare 出站经注入通道在装配层包装——若改为 CfClient 直持 OutboundHttp 需同步更新 WP-46 §3.1；ingress 版本用 JSON 数字（对齐 Cloudflare API 线格式）；`/api/cloudflared/settings` 的 session-only 由 fg-admin 接线层执行；真实 trycloudflare 隧道未验证（§7 允许标注）。根进程接线与 fg-logging 日志来源替换随后续接线批次。

### WP-54 单包授权与放行（核心交付）

- 2026-11-28 交付 40e2508（aes、md-5 加入 workspace 依赖）。fg-knock：fwknop 兼容 SPA 解码流水线（prefilter → 全密钥集 HMAC → AES-256-CBC 解密〔手写 CBC、EVP_BytesToKey MD5 派生、Salted__ 框架〕→ 字段解析），密码学路径用 OpenSSL 4.1 实测生成的固定向量端到端锚定（并绕过 OpenSSL 4 不再输出 Salted__ 标记的行为）；纵深防御：每 /24、/64 令牌桶 + 全局 HMAC 单位预算、（凭据指纹，随机数，时间戳）重放缓存且拒绝早于进程启动的报文、被封禁来源直接丢弃而命中来源经 trust_login 盾护。授权登记表 ArcSwap 无锁 admitted、single_addr 撤销、规则编辑撤销范围表、容量上限；knock.opened/knock.failed 事件（失败仅 TCP 通道、5 秒节流）；开窗/关窗经注入钩子（每规则 CancellationToken+定时器、重复敲门重排）；16 个操作（规则集合、secrets 明文、授权撤销、防火墙视图、status）与四项自检。85 项测试（UDP/TCP 套接字直发 + 真实 HTTP）；clippy -D warnings、fmt 干净。**遗留**：真实 fwknop 客户端互操作夹具待 brew 安装后补；防火墙拦截本体（gately_knock 集合）属 WP-51 扩展；网页登录授权（GrantSource::Web）随 WP-26 与 fg-core knockgate 提升（fg-knock/src/grants.rs 已按可搬迁语义实现）。

### WP-45 Tailscale、NetBird 与 EasyTier（完整交付）

- 2026-11-28 交付 5f07085。三个结构对照的托管模块（各 lib/model/validate/args/status/runtime/routes）：实例按指纹（分组/备注/enable 不参与）只重启受影响者、冲突实例「排后者不启动并显示原因」、drain 15 秒有界停止、reset 停全部→注销→恢复默认配置（保留已装程序）；**密钥一律走环境变量**（TS_AUTHKEY/NB_SETUP_KEY/ET_NETWORK_SECRET，快照断言）；状态解析字段白名单（nodekey/网络密钥不读不转发，有「输出不含密钥」断言）。NetBird 附加外部内核实例检查、<0.75 的 SOCKS5 告警与登录链接刷新；Tailscale 内核模式遇 nf_tables 主机注入 TS_DEBUG_FIREWALL_MODE=nftables；EasyTier rpc portal 钉在回环 + 白名单、拒绝 extra args 里的网络密钥。操作数对齐上游（28/28/27 含通用日志）；安装接 fg-proc Installer，装毕经 on_installed 自动重启运行中实例。79 项测试（rustc 现场编译的多调用替身二进制，auth 标记/状态 canned JSON 内含密钥样串验证不泄露）；clippy -D warnings、fmt 干净。**移交项**：settings 的 session-only 由 fg-admin authorize 层落实；真实二进制联调（记录版本与结果）待实机；字段名对照上游 config.go 无快照可读，按文档形态 + 官方程序接口设计。

### WP-91 持续集成（步骤 5 交付：supply-chain job）

- 2026-11-28 交付 3780eae。deny.toml 按实测许可证清单逐项列出（每条注明覆盖的 crate 族）：Apache-2.0/MIT/ISC/BSD 三档/BSL-1.0/0BSD/Unlicense/Zlib/Unicode-3.0，另加 webpki-roots 的 CDLA-Permissive-2.0、webauthn 族的 MPL-2.0、UEFI 目标 r-efi 的 LGPL-2.1-or-later、cap-std Windows 栈的 Apache-2.0 WITH LLVM-exception；来源限定 crates.io；重复依赖保持信息性（与 `cargo tree --duplicates` 并行）；yanked 直接拒绝。xtask supply-chain job 依次跑 cargo-deny（--locked 为全局旗标）与 cargo-audit，工具缺失时说明跳过（CI 固定安装 cargo-deny 0.22.2 与 cargo-audit 0.23.0 并缓存 advisory 数据库）。licenses/bans/sources 三项已用真实工具本地验证通过；advisories 因本机 GitHub 不可达留待 CI 首跑验证。41 项 xtask 测试（新增工作流内容断言）。剩余 job：msrv（仓库未声明最低工具链）、matrix/each-feature 的 CI 接线、cross/x86/ui/e2e/pebble/openwrt（分别随 WP-92/65/80/32）。

### WP-24 站点认证：基本认证、网页认证与共享用户（大部分交付，2026-11-28）

- 三批交付（2721137、d8004ab、454119f）：`web/auth/` 十个模块——站点用户（明文→bcrypt、掩码按位置/用户名沿用、72 字节上限）、共享用户（不可变 id、SSO 域点分边界最长匹配与嵌套拒绝、常量时序校验含未命中占位、凭据指纹 HMAC 密码+TOTP）、签名会话（`gately_site_<sha256[:6]>` 绑定监听器/站点、`base64url+HMAC`、7 天、Site/Sso 作用域、一次性令牌防重放）、校验预留（每来源 8 并发/64 排队先于 bcrypt、15 分钟 10 次锁死、IPv6 /64 归一）、基本认证（三级判定）、TOTP 步（RFC 6238 向量）、自助改密（8–128 字符、60s 冷却、改密即失效会话）、登录页（全上限校验 + 默认样式渲染快照 + HTML/CSS 转义）。
- 管线接线：`/__gately_auth` 保留路径在任何站点路径下由认证器应答（登录页/登录提交/两步验证/退出）；web 会话先行、Basic 兜底；未认证浏览器 302 登录页、非浏览器 401；同源表单校验与 safeNext 防开放重定向；跨站 Cookie 按站点 key 绑定天然隔离。
- 模型：settings 增 authSecret/authUsers/ssoDomains/autoBanSeconds，站点增 basicAuth/webAuth/users/sharedUsers/loginStyle；桥接校验「基本认证至少一个用户」「网页认证需用户或共享用户」。
- 测试：auth 模块 54 单元 + 6 管线集成（basic 允许/拒绝、登录全流程含跨域拒绝、safe_next_only、跨站 Cookie 隔离、TOTP 步含令牌重放拒绝、保留路径旁路路径规则），fg-gateway 全量 309 lib + 68 e2e，clippy 0。
- 尚余：dir_config 装配生产 Authenticator（with_authenticator 已就绪）；bcrypt 校验移入阻塞线程池；站点用户凭据指纹；SSO 父域 Cookie（Authenticator 需 ssoDomains 输入，随 WP-25）；auth.banned 事件接 WP-26 封禁表；登录页其余 9 种样式资产（WP-86）。

### WP-55 WAF 实例与站点集成（引擎层第一梯队交付）

- 2026-11-28 交付 9909249。fg-waf-engine（纯引擎，无 tokio、全借用零拷贝）：请求模型（headers 切片引用 + 主体摘要，默认送检 12.5 MiB 可钳制）、规则集 JSON（camelCase、四种互斥匹配形态：单条件〔negate/大小写不敏感〕与 all/any/not 嵌套）、8 字段 × 6 运算符（regex/contains/equals/prefix/suffix/ipIn〔仅 clientIp，IP/CIDR 列表〕）、allow/deny/count 动作（首 deny 生效、allow 短路、count 继续计数）。compile() 校验全部启用规则并收集所有错误（停用规则整体跳过便于 UI 保存）、预编译正则与 IP 集、上限集中（512 规则/深度 8/4096 字符/1 MiB 编译体积/1024 条目）；不可变 Compiled 经 ArcSwap 发布，每请求一次快照、命中前零分配；热重载失败保留旧快照。事件复用既有 `waf.blocked` Kind（fg-core 零改动），经集成层钩子发布；`ferrumgate_waf_*` 指标含总量/每规则命中/编译错误。63 项测试（UTF-8 截断不 panic、Unicode 折叠、IPv6 前缀等）；clippy -D warnings、fmt 干净。**后续梯队**：SecLang/CRS 解析、五阶段事务与异常评分、请求体解析器、libinjection、正则预过滤（E1-E11）；站点管道接线与管理接口（fg-waf 模块 crate）随集成层交付。

### WP-52 日志规则与 jails（完整交付）

- 2026-11-28 交付 7d99852。fg-guard 的 jail 引擎：七类来源（文件 tail 带轮转/copytruncate/删除重建处理、journalctl -f、命令带退避重启、docker 留 DockerFollow trait 待 WP-60、事件总线订阅、web 路径、TLS 握手失败）× 17 个预设模板（全部可编译并过校验）；`<HOST>` 命名捕获（IPv4/方括号 IPv6/裸 IPv6/::ffff: 映射形）；滑窗计数按 /32 与 /64 聚合、50000 上限按活跃序淘汰；达阈值即 `ban_auto`（来源 `jail:<key>`）→ 经既有钩子直入 WP-51 防火墙镜像；白名单/ignorePrivate/已封禁不计。web 探测（正则或分段通配、默认 404/403/444、trusted_user 不计）与 TLS 八类失败经 ProbeSink 供 WP-21/28 在请求结束/握手失败时调用。12 个管理操作 + jails 汇总进 /api/guard/status。122 项测试（67 新增、零回归）；clippy -D warnings、fmt 干净。**已核实偏差**：预设数量文档三处矛盾（16/18/17），按 §3.3 表 17 个实现并断言 ≥17；8 个非 Gately 预设的 filter 按 fail2ban 惯例 RE2 写成，待上游快照核对。**接线点**：`ProbeHub::new(engine)` 交 WP-21/28；docker 源保存即 400 直到 WP-60 调 `engine.set_docker`。

### WP-44 frp（完整模块交付）

- 2026-11-28 交付 772cfc0。fg-frp：frpc/frps 实例经 fg-proc 监督运行，配置渲染为 frp 0.52+ TOML（字段逐项对照 frp 源码 pkg/config/v1；QUIC 调优默认与上限集中）；reconcile 只重启渲染配置变化的实例、drain 15 秒有界停止、0600 配置落盘、密钥输出脱敏。frps 登录检查端点实现 frp server-plugin 协议（拒绝名单 → 常量时间 token → 黑白名单含订阅 IP 集），已登录 frpc 来源登记为 10 分钟可信并学习远端端口为开放端口（4096 上限）；代理地址按类型映射（http/https 回退 frps vhost）。INI 与 TOML 导入上报被忽略字段、新实例默认停用。45 个操作按集合契约；自检报告冲突与重复。51 项测试（rustc 编译的 frpc/frps 夹具 + 假上游安装）；clippy -D warnings、fmt 干净。fg-proc 的 FRPC/FRPS 规格与上游命名核对无差异。真实 frp 联调与根进程接线（fwopen Group、OpenPorts、可信来源消费）随后续。

### WP-55 WAF 引擎层第一梯队交付

（见前文 9909249 条目。）

### WP-66 File Browser（完整模块交付）

- 2026-11-28 主会话接手交付 e99968a（原 agent 三次模型流拥堵）。fg-filebrowser 托管 FileBrowser **Quantum**（gtsteffaniak/filebrowser；fg-proc 的 FILEBROWSER 规格一并修正为该分支，资产模式对照 v2.1.0-stable 发布核实——裸二进制 `{os}-{arch}-filebrowser`，Windows 裸 `filebrowser.exe` 单模式无法表达、显式不匹配并注明待 WP-92 扩展；校验取 GitHub 资产摘要）。Quantum 配置 schema 直接对照其 v2.1.0-stable 的 settings 结构体核实后渲染：http.listen/port/baseURL/externalUrl/disableWebDAV/trustProxyHeaders、auth.tokenExpirationHours + methods.{proxy.header,noauth}、server.sources[].config.readOnly。管理员密码只走环境变量（配置文件写 `${FILEBROWSER_ADMIN_PASSWORD}` 引用，Quantum 的 admin-password 启动重置语义每次启动同步 Gately 设置）；配置文件 0600 落实例数据目录；共享目录必须绝对路径且与配置目录三种重叠（相等/在内/包含）全部拒绝；proxy 认证非回环监听出警告；缺失来源或程序不启动并在卡片显示原因。21 个操作（实例集合 + secrets 明文 + 安装 check/rollback/backups + reset 保程序；安装完成自动重启启用实例）。19 项测试（rustc 编译夹具绑定所配端口）；clippy -D warnings、fmt 干净。真实 Quantum 联调按文档标注未验证。

### WP-71 网络诊断（完整模块交付）

- 2026-11-28 交付 808ee46（根注册 mod-nettools、socket2 依赖、lock 与 gen 产物同笔闭环）。fg-nettools 六类诊断任务经共享 JobRegistry（并发上限 429、5 分钟超时可取消、历史 500 行）：ICMP ping 无特权 dgram 套接字（socket2 + AsyncFd、自研 RFC 792/4443 报文、macOS 回包剥 IP 头、不可用时给明确原因〔net.ipv4.ping_group_range/NET_RAW〕并建议端口探测——按 D13 不试原始套接字）、traceroute 走平台命令（参数数组、流式输出）、TCP 端口探测（1024 端口、256 并发、服务名映射）、DNS 查询（hickory-resolver 七类型 + 自研 RFC 8484 DoH：hickory-proto wire 消息 + base64url + hyper GET，绕开 workspace resolver 无 https 构建的限制）、下载测速（4 路分段 Range 并行）、局域网扫描（if-addrs 推断网段、> /24 钳到 /24）。7 个操作按集合契约；问题返回 400 problems、写操作记审计。55 项测试（rustc 编译 traceroute 夹具、假 UDP/DoH 服务器、macOS 本机实跑 ping 通过）；clippy -D warnings、fmt 干净。WP-07 自定义 DNS 经 Deps.dns_servers 注入；ARP/MAC 厂商为文档确认的后续项。
