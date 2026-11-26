# FerrumGate 全量对齐 Gately 的 Rust 执行方案

## 1. 文档定位与使用方式

### 1.1 目的

本方案把 Gately 的**全部功能**拆成可逐步执行的 Rust 工作包，供后续按包实施。每个工作包给出上游依据、行为契约、Rust 设计、验收标准、依赖与规模。读完后应当能回答三个问题：还差什么、下一步做哪个包、这个包做到什么程度算完成。

### 1.2 与现有文档的关系

- [DESIGN.md](DESIGN.md)：当前已交付功能的契约。本方案中已完成的工作包，其契约最终并入 `DESIGN.md`。
- [EXECUTION.md](EXECUTION.md)：已交付功能的验证步骤与演练。
- [ARCHITECTURE_EXECUTION.md](../ARCHITECTURE_EXECUTION.md)：早期的架构规划与对齐状态表。本方案以逐模块研读上游源码与文档的结果取代其中「原始架构规划」的里程碑划分；两者冲突时以本方案为准，对齐状态表在每完成一个阶段后更新。
- [AGENT.md](../AGENT.md)：工程约束（Rust 测试、无 Python 脚本、feature 加法、依赖更新方式、交付前检查）。本方案全部工作包遵守这些约束。
- [docs/plan/](plan/README.md)：**79 个工作包的细化文档**，每个工作包一份（范围、准备、设计、接口与配置、实施步骤、测试、完成标准、注意事项，附从上游源码自动提取的测试索引与常量），以及全部工作包共用的 [00-conventions.md](plan/00-conventions.md)。本方案给出行为契约与取舍，细化文档给出实现层面的内容；实现某个工作包时以细化文档为操作手册，两者冲突时先改文档再改代码。

### 1.3 使用方式

1. 在「17. 进度跟踪表」中找到下一个「未开始」且依赖已满足的工作包，改为「进行中」。
2. 打开它的细化文档（`docs/plan/WP-xx-….md`），先读 [00-conventions.md](plan/00-conventions.md)，再按细化文档的「实施步骤」逐条执行。行为细节以细化文档对照上游源码核实的结论为准；仍标注「待核实」的条目，以及各文档「注意事项」里的可行性验证，必须在动手实现前完成并写回结论。
3. 按细化文档的「关键类型」与「流程」实现，按「测试」补齐用例（上游的测试函数已列在每份文档的附录里），以「完成标准」收尾。与上游不一致的地方写进该工作包的说明与接口文档。
4. 更新 `README.md`、`DESIGN.md`、`EXECUTION.md` 与进度表，提交。

每个工作包都可以独立成一个或几个提交，提交粒度沿用现有仓库的习惯（`feat(<模块>): …`）。

### 1.4 术语

- **上游**：Gately，本文中的路径均指其仓库根目录下的路径，文档页均指 `https://gately.cn/docs/…` 下的简体中文页面。
- **模块**：与上游的 27 个功能模块一一对应，模块 ID 沿用上游标识（`webservice`、`portforward`、`ssl`、`protoroute` 等）。
- **核心模块**：`portforward`、`ssl`、`webservice`，始终编译；其余 24 个为可选模块。
- **工作包（WP）**：本方案的执行单元，编号固定，不随排期调整而改变。
- **行为契约**：实现必须满足的可观察行为，数值与默认值来自上游文档或源码。

## 2. 上游基线与研读材料

### 2.1 基线

| 项 | 值 |
|---|---|
| 仓库 | <https://github.com/wangwanjie/gately>（Apache-2.0，Go 1.26.11） |
| 提交 | `main` @ `442162e4d0b64df119bc5fe6469a088adee844c4`（2026-11-24），对应标签 `v0.6.8.8` |
| 网站与文档 | <https://gately.cn>，10 种语言；**简体中文为原始版本**，英文版为机器翻译 |
| 模块 | 27 个：3 个核心、24 个可选；分组为网络、组网与穿透、Web、文件服务、工具、系统 |
| 源码规模 | 仓库 4600 个文件；`internal/` 下非测试 Go 约 15.9 万行（5.5 MB，其中内置的 SMB 协议栈 `gosamba` 约 2 万行）、测试约 13.5 万行；`internal/modules/` 下非测试约 8 万行、测试约 6.4 万行，其中 `webservice` 非测试 2.4 万行、117 个测试文件、560 个测试函数 |
| 前端 | Vue 3 + TypeScript + Vite + Element Plus，67 个视图、138 个组件、881 个语言文件 |
| 管理 API | 651 条路径、808 个操作、34 个权限域；74 个操作仅限登录会话 |
| 构建裁剪 | `modules.json`：按模块去掉（构建标签 `no_<id>`）、按语言档位裁剪、19 个构建目标、3 个预设 |

DESIGN.md 第 1 节记录的上游基线与本次一致。

### 2.2 取得上游快照

```bash
git clone https://github.com/wangwanjie/gately upstream-gately
git -C upstream-gately checkout 442162e4d0b64df119bc5fe6469a088adee844c4
```

到 GitHub 的链路较慢时，可只取需要的文件：先用 `https://api.github.com/repos/wangwanjie/gately/git/trees/<提交>?recursive=1` 取得文件树，再并发请求 `https://api.github.com/repos/wangwanjie/gately/contents/<路径>?ref=<提交>`（请求头 `Accept: application/vnd.github.raw`），每个文件用 `git hash-object` 与文件树中的 blob SHA 比对。上游代码只用于阅读，不在本仓库中编译或执行。

文档可在本地阅读：`website/<语言>/docs/` 下是 VitePress 的 Markdown 源文件（`website/docs/` 为简体中文）。

### 2.3 研读范围与局限

本次研读**通读**了 README 的功能清单、`modules.json`、模块框架（`internal/module`、`internal/modules/registry`）、全局设置、管理请求处理链、配置存储与历史、通用集合接口、各模块的配置结构体，以及 `docs/modules/` 下全部模块页的主要章节和 `docs/guide/` 下的配置、安全、审计、CLI 与 MCP 页面。

**没有逐行核对**的部分：各模块实现里的全部测试断言、`internal/gosamba`（上游内置的 SMB 协议栈）、演示模式的大部分实现、`docs/tutorials/` 的大部分内容。因此：

- 第 3 节的功能清单来自 README 与文档目录，是**完整**的；各工作包的行为契约是**可据以开工**的，但不是上游行为的穷举。
- 细化阶段（`docs/plan/`，2026-11-26）在此之上逐个阅读了：前端源码（`web/src` 的全部视图、组件与辅助模块，以及 `web/tests` 的 42 个测试文件）、`internal/app` 的统一网关、保存确认、批量修改、访问路径、首次运行引导、更新检查与在线升级、备份恢复、`internal/webpage`（服务端渲染的访客页面）、`internal/service`、`internal/minisign` 与 `internal/releasesig`、`tools/custombuild`、持续集成与发布流程、各平台的打包脚本；并把细化文档里出现的全部接口路径与上游的接口清单逐个比对（736 个「方法 + 路径」组合一致）。各模块的内部实现与测试断言仍在对应工作包实现时逐个对照，细化文档的「注意事项」里列出了需要先动手验证的事项。

## 3. 上游功能全量清单与追溯表

每一项上游能力都对应到工作包。「平台」指 P0 的公共能力。

### 3.1 模块能力（来自 README「Full feature list」与各模块文档）

| 领域 | 上游能力 | 工作包 |
|---|---|---|
| 动态域名 | 37 个适配项（35 家服务商加自定义回调与 DynDNS2）；IP 来自 URL、网卡或命令；IPv4 / IPv6；Webhook；分组、排序与搜索；备注写到提供商；删除时同时删除提供商记录；记录值变量与 STUN 联动；批量添加记录 | WP-40、WP-41 |
| STUN 穿透 | TCP / UDP 打洞与保活；UPnP / NAT-PMP；内置转发；地址变化触发 Webhook 与脚本；来源规则；自动放行防火墙 | WP-42 |
| 端口转发 | TCP / UDP、IPv4 / IPv6 互转、端口段；多目标故障转移；连接数与单来源上限；空连接超时；流量统计；PROXY 协议 v1 / v2；来源黑白名单、订阅列表与优先拒绝名单；要求敲门 | WP-34、WP-36、WP-37 |
| 协议分流 | 一个端口按协议分流：TLS 的 SNI 与 ALPN、HTTP 的 Host、Minecraft，以及 SSH、RDP、SOCKS、OpenVPN、RTSP、SIP、XMPP、MQTT、AMQP、PostgreSQL、Redis、SMB、Git、IRC、ADB、BitTorrent 与等待超时路由；默认目标；每条路由的 PROXY 协议；热更新；经 TCP 接收敲门包 | WP-35 |
| SSL 证书 | ACME DNS-01（通配、SOA 区域发现、CNAME 委托）与 HTTP-01；EAB；上传、读文件、映射到目录并执行脚本；短期证书与 IP 证书；部署到 SSH 主机、Docker 容器；飞牛系统证书 | WP-31、WP-32、WP-33 |
| Web 服务：站点 | 反向代理、重定向、静态文件、固定文本、关闭连接、导航面板；重定向变量 | WP-22、WP-29 |
| Web 服务：监听 | HTTPS、HTTP/3、HTTP 与 HTTPS 同端口、额外 HTTP 端口、WebSocket、h2c 后端、PROXY 协议进出、自动放行防火墙；不中断连接的保存 | WP-20、WP-21、WP-37 |
| Web 服务：后端 | 按路径后端、按认证用户分流、权重 / 备用 / 负载策略、主动与被动健康检查、连接失败重试、各类超时、HTTPS 后端的 SNI、路径重写与前缀剥离 | WP-23 |
| Web 服务：登录 | Basic、网页认证、GitHub / Google / QQ / OIDC、共享用户与 TOTP、Passkey、自助改密、子域单点登录、内置 OIDC 提供方、Forward Auth、公网到内网的登录态转发、身份请求头、管理员免认证、信任已登录用户 | WP-24、WP-25、WP-56 |
| Web 服务：访问控制 | IP 黑白名单、订阅 IP 列表、优先拒绝名单、GeoIP、路径规则、临时分享链接、认证失败自动封禁、敲门准入与登录后放行、拒绝时断开连接 | WP-26、WP-54 |
| Web 服务：性能 | 压缩、按 IP 限流、内存响应缓存与按路径规则、缓存清除、错误页、拦截后端错误 | WP-27 |
| Web 服务：可见性 | 每分钟统计、Prometheus 指标、实时连接、网络拓扑与回放、访客审计、访问日志归档 | WP-28、WP-09 |
| Web 服务：导入 | 导入 nginx 配置（含 `nginx -T`）、Nginx Proxy Manager、Sun-Panel；站点批量操作与移动 | WP-30 |
| WAF | Coraza + OWASP CRS v4；规则文件开关；自定义 SecLang；拦截与仅检测；请求体上限与跳过；WebDAV 兼容；雷池检测引擎；多实例 | WP-55 |
| 入侵防护 | 日志 jail（文件、journald、命令、Docker 日志、Gately 事件）；诱饵端口；端口扫描检测；Web 路径探测；TLS 握手失败；统一封禁表与递增时长；nftables / iptables + ipset 同步 | WP-50～WP-53 |
| 端口敲门 | fwknop 兼容的单包授权；身份与每身份密钥；单地址放行；防火墙拦截；端口转发 / 协议分流 / STUN / Web 站点的准入与放行；被拒绝的敲门交给入侵防护 | WP-54 |
| 组网与隧道 | Tailscale、NetBird、EasyTier、frp（frpc / frps，多实例）、Cloudflare Tunnel；官方程序的在线安装、更新、回滚与恢复默认 | WP-43～WP-46 |
| Docker | 容器、Compose、镜像更新与一键升级（失败回滚）、网络与卷；可中断的后台任务；Gately 自身容器的升级 | WP-60 |
| Web 终端 | SSH、Telnet、本机 Shell；持久会话；SFTP 文件管理；认证预设；主机密钥首次信任 | WP-61 |
| 网络诊断 | Ping、traceroute、端口探测、DNS、测速、局域网扫描 | WP-71 |
| 通知中心 | 14 种渠道；级别、通配、静默与去重；全局与渠道代理；内置模板；重试、补推队列（跨重启） | WP-68 |
| 配置备份 | 加密备份（scrypt + AES-GCM）、保留策略、定时备份到本地或存储挂载、恢复时保留账号 | WP-70 |
| 网络唤醒 | 魔术包；在线检测；远程关机 / 重启 / 睡眠（客户端、SSH、HTTP）；巴法云语音控制 | WP-72 |
| 文件服务 | WebDAV、FTP / FTPS、SMB；多用户、按用户目录、只读；共享用户；File Browser；存储挂载与在线文件管理 | WP-63～WP-67 |
| 计划任务 | cron 表达式；命令或 HTTP 请求；运行历史 | WP-62 |
| 性能监控 | 主机、进程、站点与托管进程的趋势（60 秒 / 1 小时 / 24 小时）；首字节延迟分位数；阈值 + 持续时长的告警与恢复 | WP-69 |

### 3.2 平台能力

| 领域 | 上游能力 | 工作包 |
|---|---|---|
| 配置 | 配置目录、每模块明文 JSON、原子写；历史与一键回滚；声明式目录（`-apply`） | WP-00、WP-02、WP-06 |
| 模块 | 模块框架、编译期裁剪、运行时开关、未编译与已关闭模块的接口语义 | WP-01、WP-90 |
| 安全变更 | 保存后确认与自动回滚；批量修改；当前访问路径识别 | WP-04、WP-05 |
| 管理登录 | bcrypt + 签名会话；密码策略与强制改密；TOTP；Passkey；只读账号；第三方登录；递增锁定；陌生地址失败预算；安全评分 | WP-12 |
| 管理 API | 多令牌与按模块授权；OpenAPI 文档与导出；通用集合接口 | WP-11、WP-13 |
| 管理入口 | 安全入口、仅内网、强制 HTTPS、未授权响应方式、可信代理的真实地址 | WP-14 |
| 审计 | 操作审计（登录、变更、敏感访问），轮转与保留 | WP-08 |
| 日志 | 每模块日志缓冲、落盘与轮转、访问日志归档、筛选与导出 | WP-09 |
| 国际化 | 10 种语言、语言档位、协商 | WP-10 |
| CLI 与 MCP | `ctl`、`mcp`、`rollback`、`reset-password`、`reset-totp` | WP-15、WP-02 |
| 总览与自检 | 系统状态、公网 IP、自检、存储占用、诊断包、全局 Prometheus 端点 | WP-17 |
| 列表管理 | 分组、排序、批量、复制（各页面一致） | WP-81 |
| 界面 | 全局搜索、首次运行引导、快速建站、演示模式、主题、手机端 | WP-80、WP-82～WP-85 |
| 更新与发布 | 更新检查与安全公告提示；在线升级；签名、来源证明、SBOM；多平台包与镜像；系统服务 | WP-92～WP-95 |
| 迁移 | 从 Gately 导入；从 Lucky 导入；从 nginx 导入 | WP-38、WP-30 |
| 定制构建 | 模块、语言与目标的选择；体积估算；构建站点 | WP-90、WP-96 |

## 4. FerrumGate 现状与差距矩阵

现状以 `main` 分支的提交 `f0823b4` 为准。工作区为根包 `ferrumgate`（二进制 `fgate`，子命令 `check` 与 `serve`）与 `crates/fg-gateway`（约 5900 行源码、3700 行集成测试）。配置为单个 TOML 文件（`schema_version = 1`），SIGHUP 整体重载。

| 上游模块 | FerrumGate 已有 | 主要差距 | 工作包 |
|---|---|---|---|
| `webservice` | HTTP/1.1、HTTP/2、h2c、原生 gRPC、WebSocket；Host + 路径前缀路由；加权后端池、备用、被动摘除（连续 3 次失败暂停 30 秒）与主动检查；重定向、固定文本、静态文件；单监听器 + 手动 TLS；精确与单层通配 SNI；配置快照热重载 | 多监听器与站点模型；域名规则；HTTP/3；同端口 HTTP 与额外 HTTP 端口；PROXY 协议接收；关闭连接与导航面板；负载策略、重试、TLS 握手与访客超时；全部登录认证、访问控制、压缩、限流、缓存、错误页、统计、拓扑、访客审计、指标、导入；OIDC 提供方 | WP-20～WP-30、WP-56 |
| `ssl` | PEM 证书；SNI、通配与 IP 证书；ACME HTTP-01 与 Cloudflare DNS-01；EAB；profile；续期与在线换证；本地目录部署 | 证书条目列表管理；上传 / 文件来源；多部署目标（SSH、Docker）；其余 30 多家 DNS 提供商；未完成订单恢复 | WP-31～WP-33、WP-41 |
| `portforward` | TCP / UDP；端口列表与范围；顺序故障转移；半关闭；首次数据超时；单来源配额；出站 PROXY v1 / v2；来源规则热重载；回环 Prometheus 指标 | 配置模型与默认值对齐；订阅列表与优先拒绝名单；自动放行防火墙；要求敲门；分组排序 | WP-34、WP-36、WP-37 |
| `protoroute` | — | 全部 | WP-35 |
| `ddns`、`stun`、`frp`、`tailscale`、`netbird`、`easytier`、`cloudflared` | — | 全部 | WP-40～WP-46 |
| `guard`、`knock`、`waf` | — | 全部 | WP-50～WP-55 |
| `docker`、`webterminal`、`cron`、`webdav`、`ftp`、`smb`、`filebrowser`、`storage`、`notify`、`perf`、`nettools`、`wol`、`backup` | — | 全部 | WP-60～WP-72 |
| 平台 | TOML 配置与 CLI 校验；原子重载；结构化运行日志到标准错误 | 配置目录与历史、模块框架、管理 API、认证与令牌、审计、确认与回滚、日志系统、国际化、CLI / MCP、Web 界面 | WP-00～WP-17、WP-80～WP-86 |
| 发布 | Cargo workspace 产出单进程 `fgate` | 编译期裁剪、CI、多平台、签名、升级、系统服务、打包 | WP-90～WP-96 |

## 5. 目标架构

### 5.1 运行形态

单进程 `fgate`，Tokio 运行时。进程内有两组监听：**业务面**（各模块的监听器：Web 服务、端口转发、协议分流、文件服务等）与**管理面**（管理 API 与界面，默认 `:16680`，可选 HTTPS 与 Unix Socket）。管理面与业务面使用独立的限流与超时策略。

```text
fgate（根包：参数、装配、ctl / mcp / rollback / reset / migrate / service）
│
├─ fg-core       模块 trait 与注册表、Wiring、事件总线、受保护路径、系统指标、敲门放行查询
├─ fg-config     配置目录存储、历史、diff、声明式应用
├─ fg-logging    日志缓冲、落盘、查询、导出（tracing Layer）
├─ fg-i18n       消息目录与语言协商
├─ fg-admin      管理 API（axum）、中间件链、通用集合路由器、OpenAPI、审计、确认与批量修改
├─ fg-auth       账号、会话、TOTP、Passkey、API 令牌
├─ fg-ui         管理界面（Rust WASM，产物嵌入）
├─ fg-net        出站 HTTP 与策略、自定义 DNS、来源规则、IP 列表、GeoIP、封禁表、防火墙放行
│
├─ 核心模块      fg-web（webservice）、fg-certs（ssl）、fg-l4（portforward、protoroute）
└─ 可选模块      每个（或每组）一个 crate，由同名 Cargo feature 控制
```

`fg-gateway` 是过渡期的宿主：P0 先在其中把现有实现接到模块框架上（`fg_gateway::web`、`::certs`、`::l4`）；`fg-net` 不放在它里面——从 P0（WP-14）起就是独立 crate，因为管理面与各可选模块都要用它，又不能依赖承载数据面的 `fg-gateway`。`web`、`certs`、`l4` 在 WP-90 拆成上图中的独立 crate。各工作包中的 `fg-web::…`、`fg-certs::…`、`fg-l4::…` 在拆分前对应 `fg-gateway` 内的同名模块（见 [00-conventions](plan/00-conventions.md) §1）。

### 5.2 配置与期望状态

配置目录（权限 0700）：

```text
<配置目录>/
  ferrumgate.json      全局设置（上游为 gately.json）
  account.json         管理员账号、会话吊销记录（不记历史）
  tokens.json          API 令牌（不记历史）
  <模块ID>.json        每个模块一个文件，字段名与上游一致
  gateway_origins.json 已确认的统一网关页面来源（WP-14）
  update-check.json    上次更新检查的结果（运行状态，WP-94）
  onboarding.json      首次运行引导的进度（WP-17）
  history/<名称>/      被覆盖前的版本，每个配置保留 30 个
  pending-confirm.state  待确认的配置变更
  rollback-request.state 离线回滚请求（WP-02）
  audit.log            操作审计（JSON Lines）
  logs/                运行日志与访问日志归档
  backups/             本地配置备份
  bin/ 与 bin/.versions/   托管程序与旧版本
  guard/bans.json      共享封禁表（由入侵防护模块持久化）
  以及各模块自己的数据目录（geoip/、iplists/、visitors/、notify/、compose/、frp/、filebrowser/、tailscale/ 等）
```

完整的目录布局表见 [00-conventions](plan/00-conventions.md) §3.2。

配置变更的路径：管理 API 写入 → 校验与规范化 → 持久化（原子写，旧内容进历史）→ 生效（热更新或登记为需重启）→ 审计 →（需要时）进入保存后确认。声明式目录（`-apply`）在每次启动时覆盖。热路径只读取只读快照，每个请求只读一次。

### 5.3 模块与裁剪

模块框架见 WP-01。编译期裁剪用 Cargo feature（与模块 ID 同名，默认全开），运行时开关用全局设置中的关闭列表。模块间协作只经过 `Wiring` 中的具体函数与只读句柄，提供方未编译时得到明确的「未包含在此构建中」错误。

### 5.4 安全边界

- 管理面默认要求认证；写操作记入审计；只读身份的输出统一脱敏。
- 配置目录是受保护目录，任何文件服务、静态站点或存储挂载都不能对外提供它或包含它的目录（包含时隐藏）。
- 外部命令一律以参数数组或标准输入脚本执行，不经 shell 拼接；用户填写的命令字符串只在用户明确配置的位置经 `sh -c` 执行。
- 文件访问经「打开的目录句柄 + 相对路径」的受限打开（现有 `cap-std` 的用法）。
- 出站请求受自定义 DNS、更新代理与可选的「出站请求限制」约束。
- 新增的监听、任务、连接、队列与缓冲都必须有上限、默认值与到达上限后的行为。

### 5.5 平台范围

开发与 CI 以 macOS（arm64）与 Linux 为主。防火墙（nftables / iptables）、系统服务、原始套接字等能力只在 Linux 上完整可用，其他平台编译为返回「不支持」的实现并在界面说明原因；Windows 提供二进制、系统服务与不依赖特权的功能。路由器架构（mips、mipsle、riscv64）的加密后端是一个**已知风险**：工作区现在用的 `ring` 0.17.14 只面向 aarch64、arm、x86、x86_64 编译，这三个架构都不在其中（见 §16.2 与 WP-92 步骤 1 的可行性验证）。

## 6. 工作包总览与执行路线

| 阶段 | 目标 | 工作包 | 数量 | 结束标志 |
|---|---|---|---|---|
| P0 平台基座 | 配置目录、模块框架、管理 API、认证、审计、日志、事件、CLI | WP-00～WP-17 | 18 | 现有数据面以模块形式运行在框架上；`fgate ctl` 可管理；`fgate rollback` 可回滚 |
| P1 核心数据面 | Web 服务、证书、端口转发、协议分流对齐 | WP-20～WP-39 | 20 | 现有集成测试在新配置模型下通过；站点支持登录与访问控制；协议分流可用 |
| P2 网络自动化 | DDNS、STUN、隧道与托管程序 | WP-40～WP-46 | 7 | DDNS 与 STUN 可用；frp 与三个组网程序可托管 |
| P3 安全 | 入侵防护、端口敲门、WAF、OIDC 提供方 | WP-50～WP-56 | 7 | 封禁表与防火墙同步可用；敲门可用；WAF 集成层可用 |
| P4 运维工具 | Docker、终端、计划任务、文件服务、通知、性能、备份、诊断、唤醒 | WP-60～WP-72 | 13 | 各模块可独立启用并通过验收 |
| P5 管理界面 | Rust WASM 管理界面 | WP-80～WP-86 | 7 | 全部页面可用 |
| P6 发布 | 定制构建、CI、多平台、签名、升级、系统服务 | WP-90～WP-96 | 7 | 六种构建可发布；签名与校验文档齐全 |

依赖关系的主干：

```text
P0 平台基座 ──► P1 核心数据面 ──► P3 安全（不依赖界面的部分）
   │                  │
   │                  ├──► P2 网络自动化
   │                  └──► P4 运维工具
   ├──► P6 发布（WP-90、WP-91 可在 P0 后立即开始）
   └──► P5 管理界面（随各模块逐页交付）
```

P2 与 P4 之间相互独立，可以按需要调整先后。P3 的 WAF 引擎层是长期并行任务，不阻塞其他阶段。详细顺序见 17.1。

## 7. 阶段 P0：平台基座

P0 交付「其余 26 个工作包都要依赖」的骨架：配置目录、模块框架、历史与回滚、管理 API 框架、认证与令牌、审计、日志、事件、CLI/MCP。P0 完成后，现有数据面（Web 服务、TCP/UDP 转发、证书）以模块形式挂在框架下运行，后续每个模块都按同一模式接入。

> 阅读方式：每个工作包给出「上游依据」（实现该包时应读的文档与源码，路径均相对上游仓库根目录）、行为契约、Rust 设计、验收标准。上游数值未在本次研读中核实的标注「待核实」，实现时以源码为准。

### WP-00 配置目录与存储

- **目标**：以「配置目录 + 每模块一个明文 JSON」替代当前的单一 TOML 文件（决策 D1）。
- **上游依据**：`internal/config/store.go`；文档 `docs/guide/configuration`「配置目录」；`internal/fsperm/`（受保护目录）。
- **行为契约**：
  - 每个模块对应 `<模块ID>.json`；模块名须匹配 `^[a-z0-9][a-z0-9_-]*$`，防止路径穿越。
  - 写入采用「临时文件 + rename」保证原子性；文件权限 0600、目录 0700；配置保持明文，便于审计、备份与纳入 git。
  - `Load` 在文件不存在时返回「未找到」并保留调用方的默认值；`Save` 序列化整个结构；`WriteRaw` 写入原始字节（供声明式应用使用）；`Remove` 删除。
  - 配置目录在打开时登记为**受保护目录**：静态站点、WebDAV/FTP/SMB、存储挂载、文件管理器拒绝把它（或包含它的目录）对外提供。目录内含会话签名密钥、令牌与私钥。
- **Rust 设计**：新 crate `fg-config`。`ConfigStore` 持有目录路径与互斥锁，提供 `load::<T: DeserializeOwned>()`、`save::<T: Serialize>()`、`write_raw`、`remove`、`load_raw`。原子写在同目录创建临时文件、写入、`sync_all`、rename，再在 Unix 上对目录 `sync_all`。受保护目录登记放在 `fg-core::fsperm`（进程内只追加集合）。解析错误仅报告配置名和行列。
- **与现状的衔接**：`schema_version = 1` 的 TOML 配置由 `fgate migrate`（WP-39）一次性转换为配置目录；转换完成前保留现有加载路径作为兼容入口，转换后移除。
- **验收**：单元测试覆盖原子写（写入中途失败不留半文件）、权限位、非法模块名、缺失文件返回默认值、受保护目录拒绝；E2E 用临时目录完成保存—读取—校验模式位。

### WP-01 模块框架与注册表

- **上游依据**：`internal/module/module.go`、`internal/modules/registry/{registry,core,catalog}.go` 与 `mod_<ID>.go`；`modules.json`；`internal/app/modules.go`。
- **行为契约**：
  - 模块接口：`ID()`、`Title()`、`Init(env)`（加载配置，不启动任何网络服务）、`Start(ctx)`（按配置启动服务）、`Stop()`（停止全部服务并释放端口）、`Routes(r)`（注册 `/api/<ID>/` 下的管理接口）。
  - 可选能力接口：`PublicRouter`（免登录接口 `/api/<ID>/public/*`，模块自行校验凭据）、`Migrator`（全部模块初始化前迁移配置）、`LogSourcer`（配置中的日志来源标签）、`AccessLogger`（访问日志按天归档）、`Summarizer`（总览页指标）、`Metricer`（Prometheus 采样）、`SelfChecker`（网络与配置自检）、`HTTPClientAware`（注入遵循「更新代理」设置的出站客户端）。
  - 模块间协作经**函数注入**完成，避免直接依赖。提供能力的模块未编译时对应槽位为空，调用方得到明确的「功能模块未包含在此构建中」错误。现有注入项：证书模块与 Web 服务实例、WAF 提供者、存储挂载、Web 终端的 SSH 推送/执行/目标列表、Docker 的重启容器/容器列表/跟随日志。
  - 运行时依赖：依赖方开启期间，被依赖模块不能关闭；被依赖模块未编译时该依赖自动忽略（如 Web 服务依赖 `ssl` 与 `waf`，备份依赖 `storage`）。
  - 运行时开关 `disabledModules` 采用**关闭列表**：关闭的模块仍加载配置，但不启动服务、不注册任何接口，整个 `/api/<ID>/` 前缀返回 403「已关闭」；改动重启生效。未编译进构建的模块：配置文件原样保留，令牌权限仍有效，接口返回 404「未包含在此构建」。
  - 注册表、各 `mod_<ID>.go` 与 `modules.json` 三者由测试校验一致。
- **Rust 设计**：`fg-core` 提供模块标识、运行方法与注册表。装配层显式传入配置和具体能力句柄，先准备全部启用模块，再启动任务。运行时拥有监听器和子任务，通过共享信号并行排空。配置迁移、管理路由与其他可选能力随首个调用方接入，接口状态由 WP-11 映射为 403 或 404。
  - `crates/fg-core/build.rs` 由 `features.toml` 生成 27 个模块的目录表。WP-90 在此清单上接入 Cargo feature 裁剪，三个核心模块始终编译。
  - `fg-gateway` 的 Web、证书和 TCP/UDP 模块共用一次 TOML 编译及 SIGHUP 原子快照。TOML 顶层 `disabled_modules` 提供兼容阶段的运行时开关。
- **验收**：测试覆盖依赖校验、缺席模块、关闭开关、预绑定失败、重载和有期限的并行排空；继续执行现有数据面端到端用例。

### WP-02 配置历史、差异与回滚

- **上游依据**：`internal/config/history.go`、`internal/config/diff.go`；`internal/app/{history,rollback}.go`；`cmd/gately/rollback.go`；文档 `docs/guide/audit`「配置历史与回滚」、`docs/guide/configuration`「命令行回滚」。
- **行为契约**：
  - 每次覆盖配置文件之前，把旧内容保存为历史版本，位于 `history/<名称>/`，每个配置保留最近 30 个；`account.json` 与 `tokens.json` 不记录历史。
  - 版本标识格式 `YYYYMMDDTHHMMSS.fffffffffZ`（UTC，纳秒）。差异为行级 LCS，上下文 3 行，计算单元上限 4,000,000。
  - 回滚恢复指定版本后进程重启生效；回滚前的当前内容同样保存为新的历史版本，因此回滚本身可以再次撤销。
  - 命令行 `rollback -list / -last / -pending / -config <名称> -version <版本> / -y`：运行中由进程处理并重启，未运行时直接改写文件、下次启动生效。
- **Rust 设计**：`fg-config::history`。文件名为版本标识；保留数量与是否跳过可配置。差异算法自研（行级 LCS + 上下文折叠），避免为此引入 C 库。`fgate rollback` 子命令需要与运行中实例通信（复用 WP-15 的本机控制通道）。
- **验收**：保留 30 个的淘汰、版本格式校验、路径穿越防护、差异输出、回滚产生新版本、运行中与未运行两条路径。

### WP-03 进程装配、启动参数与重启

- **上游依据**：`internal/app/app.go`（`New`、`Run`、`run`、`stopModules`）、`internal/app/system.go`（`handleRestart`）、`cmd/gately/main.go`；文档 `docs/guide/configuration`「命令行参数」。
- **行为契约**：
  - 参数：`-c` 配置目录（环境变量 `GATELY_CONFIG_DIR`）、`-listen` 覆盖管理界面监听地址、`-apply` 声明式配置目录（`GATELY_APPLY_DIR`）、`-gateway-socket` 额外的 Unix Socket 管理入口、`-gateway-prefix` 经网关访问时的路径前缀、`-api-docs` 导出接口文档后退出、`-version`。
  - 环境变量：初始密码（至少 8 位，账号已存在时不起作用；短于 10 位或强度不足时首次登录被要求修改）、服务端语言、日志级别。
  - `Run` 启动全部模块与管理服务，阻塞直到上下文取消；收到重启请求时停止全部服务后重新执行自身（Unix 上 `syscall.Exec` 同一二进制）。
- **Rust 设计**：根包 `ferrumgate`（`fgate`）负责参数解析与装配。子命令规划：`fgate run`（默认）、`check`、`ctl`、`mcp`、`rollback`、`reset-password`、`reset-totp`、`migrate`、`api-docs`、`service <install|uninstall|start|stop|restart|status>`、`version`。重启：Unix 用 `exec` 替换进程映像（`std::os::unix::process::CommandExt::exec`，属标准库安全封装之外的一处受控调用）；Windows 采用「拉起新进程后退出」并等待交接，需在实现时单独验证。启动顺序：恢复待确认变更（WP-04）→ 应用声明式目录（WP-06）→ `Init` 全部模块 → `Start` → 管理服务。
- **验收**：参数与环境变量矩阵、启动顺序、停止时全部监听被释放、重启后端口可立即重新绑定、崩溃后的状态恢复。

### WP-04 保存后确认与自动回滚

- **上游依据**：`internal/app/confirm.go`；文档 `docs/guide/configuration`「保存后确认与自动回滚」。
- **行为契约**：
  - 管理界面保存端口转发、协议分流、Web 服务与全局设置时带请求头 `X-Gately-Confirm`；服务端在保存前读取相关配置文件，保存后内容有变化即登记为一次待确认变更（同一配置只记录第一次保存前的内容）。仅管理员登录会话触发，API 令牌与脚本不受影响。
  - 待确认状态保存在配置目录的 `pending-confirm.state`（原子写），进程重启后继续计时。时限默认 90 秒，可配 30–600 秒，负数关闭。
  - 确认必须经由**新建的 WebSocket 连接**（`GET /api/system/confirm/connect`），因为它经过修改后的转发与监听；早于修改生效完成的请求不能确认，连接超时 10 秒。
  - 超时未确认：标记回滚并重启，下次启动时、加载任何配置之前恢复改动前的内容。连续启动 3 次仍未确认同样回滚；启动后至少保留 45 秒宽限。
  - 需要重启才生效的设置（管理界面监听地址、功能模块开关）在经管理界面重启时登记，重启后开始计时。
  - 从备份或历史版本恢复配置时放弃待确认变更（恢复后的配置是用户明确选择的）。
  - 接口：`GET /api/system/confirm`、`GET /api/system/confirm/connect`、`POST /api/system/confirm/rollback`（均仅限登录会话）。
- **Rust 设计**：`fg-admin::confirm`。状态机 `Idle / Pending{files, deadline, boots} / RollingBack`；到期由 Tokio 定时任务触发；状态文件带 `schema` 版本。WebSocket 用 `axum::extract::ws`。
- **验收**：保存后未确认→超时回滚；确认成功→保留；连续 3 次启动未确认→回滚；令牌保存不登记；旧连接不能确认；状态文件在重启后恢复。

### WP-05 批量修改与访问路径识别

- **上游依据**：`internal/applyhold/applyhold.go`、`internal/app/changeset.go`、`internal/app/accesspath.go`、`internal/app/apply.go`；文档 `docs/guide/configuration`「批量修改：几处一起改」「保存前提醒：当前访问路径」。
- **行为契约**：
  - 批量修改期间，端口转发、协议分流与 Web 服务照常保存配置，但运行中的监听、规则**不切换**；结束时按保存的先后顺序一次性生效，随后与单次保存一样经新连接确认，确认不了时整批回滚到开始前的配置。
  - 生效前检查暂存的监听地址能否在本机使用，不可用时先列出原因再由用户决定。全局设置不受批量修改影响。放弃修改：恢复开始前的配置并重启。
  - 同一模块同一键的生效动作连续登记只保留一次。
  - 访问路径：端口转发与协议分流连到本机目标时登记这一跳；Web 服务反代到管理界面时附带签名的路径信息（外部无法伪造）。保存前检查这次修改是否影响该路径（修改路径上的规则/监听/站点的转发设置、停用或删除、关闭路径经过的模块、修改管理监听地址、从外网开启仅内网、经 HTTP 开启强制 HTTPS）。
  - 接口：`POST /api/system/changeset/{begin,check,apply,discard}`、`GET /api/system/access-path`、`POST /api/system/access-path/check`。
- **Rust 设计**：`applyhold` 对应一个进程级的 `ApplyHold`（互斥保护的动作队列，元素为 `Box<dyn FnOnce() + Send>`）。访问路径用跳转列表表示（协议分流规则 → Web 服务监听/站点 → 管理界面），由各模块在转发到本机目标时上报。签名头用 HMAC（密钥来自会话签名密钥）。
- **验收**：批量期间保存不生效、`apply` 按序生效、`discard` 恢复、整批回滚、访问路径识别与保存前检查的正反用例。

### WP-06 声明式配置

- **上游依据**：`internal/app/apply.go`；文档 `docs/guide/configuration`「声明式配置」。
- **行为契约**：指定 `-apply <目录>` 后，每次启动把该目录下的 `<名称>.json` 覆盖到配置目录，内容相同的文件不重写；写入前校验合法 JSON，任一文件无效则拒绝启动；`account.json` 与 `tokens.json` 不允许覆盖；被覆盖的旧内容保存到配置历史。
- **Rust 设计**：`fg-config::apply`。只处理目录第一层的 `*.json`，忽略其他文件；比较字节相等后再决定是否写入。
- **验收**：相同内容不重写（比较 mtime 与历史数量）、非法 JSON 拒绝启动、账号与令牌文件被跳过、历史保留。

### WP-07 全局设置

- **上游依据**：`internal/app/settings.go`（`Settings` 结构、默认值与校验）；文档 `docs/guide/configuration`、`docs/guide/security`。
- **行为契约**（字段名为上游 JSON 名；全局设置在上游保存为配置目录下的 `gately.json`，FerrumGate 使用 `ferrumgate.json`）：

| 字段 | 含义 | 默认与校验 |
|---|---|---|
| `listen` / `httpsListen` | 管理界面 HTTP / HTTPS 监听地址 | 格式为 `:端口` 或 `IP:端口`；两者不能相同 |
| `forceHTTPS` | HTTP 访问重定向到 HTTPS | 需要先设置 `httpsListen`；证书由证书模块按域名提供 |
| `safePath` | 安全入口路径 | 至少 3 个字符；不能以 `/api`、`/assets` 开头；不能含空格、`?`、`#` |
| `lanOnly` | 仅允许内网地址访问管理界面 | 含 Tailscale 等 CGNAT 地址 |
| `denyMode` / `denyStatus` / `denyPage` | 未授权访问的响应方式 | 为空时：安全入口返回 404 提示页，封禁与仅内网返回 403；`custom` 时使用自定义状态码与 HTML |
| `gatewaySSO` | 飞牛 fnOS 管理员经统一网关自动登录 | 默认关闭，仅 fnOS 包显示 |
| `disableProxyHeaders` / `trustedProxies` | 是否信任本机反向代理传来的 `X-Real-IP` / `X-Forwarded-For`；额外信任的代理地址 | 默认信任本机地址 |
| `maxLoginFailures` / `lockMinutes` | 登录限流 | 失败上限 1~100；锁定 1 分钟~7 天 |
| `loginGlobalLimit` | 陌生来源 10 分钟内累计失败预算 | 0 表示 20，负数关闭，不能超过 10000 |
| `confirmTimeout` | 保存后确认时限（秒） | 0 表示 90，负数关闭，范围 30~600 |
| `language` / `uiLanguage` / `timeZone` | 服务端语言、界面语言、IANA 时区 | 为空时按环境；时区须有效 |
| `dnsServers` | 自定义 DNS，影响全部出站域名解析 | 支持 IP、`IP:端口`、`doh@主机`、`https://` DoH 地址 |
| `updateProxy` | 检查更新与在线升级访问 GitHub 的代理 | `http`、`https`、`socks5` |
| `restrictOutbound` | 出站请求限制 | 默认关闭；开启后管理员配置的出站请求在拨号层拒绝回环、私网、链路本地与 ULA |
| `disableUpdateCheck` | 关闭自动检查更新与安全公告 | 默认开启检查 |
| `logLevel` / `logLines` / `disableLogPersist` / `logFileMB` / `accessLogDays` / `accessLogMB` / `logDir` | 运行日志参数 | 日志条数默认 2000（上限 20000）；单文件默认 2 MB（上限 100 MB）；访问日志默认 7 天（上限 3650）、32 MB（最小 4 MB） |
| `gcPercent` / `maxProcs` | Go 运行时调优 | **不迁移**（Rust 无对应物），读取时忽略 |
| `thirdLogin` | 管理界面的第三方登录 | 见 WP-12 |
| `disabledModules` | 关闭的功能模块 ID 列表 | 见 WP-01；重启生效 |

- **Rust 设计**：`fg-core::settings` 定义 serde 配置模型，未知字段报错，旧 Go 运行时字段只读兼容。`fg-admin` 提供设置接口。日志、代理和 DNS 等设置立即生效，管理访问限制保存后确认，监听地址和模块开关重启生效。
- **验收**：每个校验规则一条负向测试；三类生效方式各有 E2E；设置读取接口不回显密钥明文。

### WP-08 审计日志

- **上游依据**：`internal/audit/audit.go`；文档 `docs/guide/audit`「操作审计」。
- **行为契约**：
  - 记录三类操作：登录（密码、Passkey、第三方登录的成功与失败、退出）、变更（管理后台与 API 令牌发起的全部写操作）、敏感访问（下载配置备份、诊断包、证书私钥，打开 Web 终端或容器终端等）。
  - 每条含时间、操作者（用户名或 `api-token:<令牌名>`）、来源 IP、方法、路径与状态码；不记录请求体与任何密钥。放在反向代理之后时记录真实来源并单独标注经过的代理地址。
  - 写入配置目录的 `audit.log`（JSON Lines），单文件超过 5 MiB 后轮转，保留 3 份历史。
  - 变更与敏感访问作为 `audit.change`、`audit.access` 事件发出。只读账号与 API 令牌无法查看审计日志；查询接口 `GET /api/audit` 仅限登录会话，可按类别筛选或按路径、用户、IP 搜索。
- **Rust 设计**：`fg-admin::audit`，中间件形态：响应完成后写一条记录；写文件走独立的有界通道与后台任务，队列满时丢弃并计数。
- **验收**：三类操作各一条；请求体与密钥不入日志；轮转与保留；只读身份不能查询。

### WP-09 运行日志系统

- **上游依据**：`internal/logbuf/`（`logbuf.go`、`persist.go`、`archive.go`、`query.go`、`filter.go`、`export.go`、`echo.go`、`serverlog.go`）；`internal/app/logs.go`；文档 `docs/guide/configuration`「运行日志」「查看与筛选」「导出」。
- **行为契约**：
  - 日志条目：`seq`（单调递增，前端增量拉取）、`time`、`level`、`source`、`message`、`fields`（IP、域名、站点、状态码等结构化字段）。每模块一个固定容量环形缓冲，写满后覆盖最旧的日志。
  - 落盘到配置目录的 `logs/`：每个来源一个 JSON Lines 文件 `logs/<模块ID>.log`，系统日志为 `logs/gately.log`；有新日志时最多延迟 1 秒批量写入；单个文件超过上限（默认 2 MB）后轮转为 `.1`，只保留这一份历史；每个模块记录出现过的日志来源（`logs/<模块ID>.sources`）；启动时按「日志保留条数」从文件恢复。
  - 运行日志同时回显到标准错误，批量写出；积压超过 1 MB 时丢弃新行并补一行说明。
  - 查询：级别、来源、关键词（空格分隔表示同时包含，双引号包住短语，`-` 排除）、「不包含」、IP（地址、网段或地址的一部分，`!` 或 `-` 排除）、时间范围；Web 服务另支持站点、监听器、状态码、`hideBanned`、`hideAdmin`。内存不足时继续查找文件与压缩归档中的历史。
  - 导出：CSV（UTF-8 带 BOM；以 `=`、`+`、`-`、`@` 开头的单元格前加单引号，防止公式注入）与 JSON Lines，按筛选条件导出全部日志。只读账号与只读令牌导出时同样脱敏。
  - 接口：`GET /api/logs`、`GET /api/logs/sources`、`GET /api/logs/export`，以及每个模块的 `GET|DELETE /api/<ID>/logs`、`/logs/sources`、`/logs/export`。清空模块日志同时删除对应文件、历史文件、压缩归档与来源记录。
- **Rust 设计**：新 crate `fg-logging`。`tracing` 的 `Layer` 把事件写入对应模块的环形缓冲（`VecDeque<LogEntry>` + 原子序号）；持久化任务按模块聚合、定时刷盘；查询解析器自研（关键词语法简单）。访问日志归档接口（`AccessLogs` 能力）由 Web 服务模块实现。
- **验收**：环形覆盖、恢复、轮转、回显背压丢弃、查询语法全集、导出格式与公式注入防护、脱敏。

### WP-10 国际化

- **上游依据**：`internal/i18n/`（`i18n.go`、`format.go`、`http.go`、`jsonrewrite.go`、`locales_*.go`）；`CONTRIBUTING.md` 的 i18n 工作流；文档 `docs/guide/configuration`。
- **行为契约**：服务端文案（日志、通知、校验错误、服务端渲染的页面）按语言输出；支持简体中文、繁体中文、英语、日语、韩语、西班牙语、法语、德语、俄语、葡萄牙语（巴西）共 10 种；语言档位 `lang_zh`（仅简体中文）、`lang_cjken`（简中、繁中、英语）、全部。请求语言按界面语言、`Accept-Language`、Cookie、环境变量协商；日志记录保存消息模板与参数，从文件读回的日志没有模板。自检结果只返回 ID 与参数，后端不拼接面向人的文案。
- **Rust 设计**：新 crate `fg-i18n`。消息目录为编译期嵌入的静态表（键 → 各语言文案），用 `build.rs` 从 `locales/*.json` 生成；格式化支持命名占位与复数类别。候选实现：`fluent`（待核实）或自研最小实现；无论哪种，都要有一条测试保证各语言键集合一致（对应上游 `check-i18n`）。语言档位用 Cargo feature `lang-en`、`lang-zh-tw` 等加法开关，默认全开。
- **验收**：键集合一致性测试、协商顺序、复数与占位、缺失译文回退到简体中文。

### WP-11 管理 API 框架

- **上游依据**：`internal/app/app.go`（`Handler`）、`internal/app/{apicatalog,apischema,openapi,openapi_md,routes,bodylimit,redact,deny}.go`、`internal/httpx/`、`internal/apitoken/scope.go`、`internal/i18n/http.go`；`docs/api/en/openapi.json`、`docs/api/en/API.md`；文档 `docs/reference/api`。
- **行为契约**：
  - 请求处理链（由外到内）：请求体读取限速 → 安全响应头 → 压缩 → 翻译 → 访问控制（封禁、仅内网、安全入口）→ 同源校验 → 接口安全头 → 路由 → 鉴权（会话或令牌）→ 演示模式写保护 → 角色（只读账号）→ 默认密码强制修改 → 只读脱敏 → 审计 → 演示数据覆盖 → 保存确认。
  - 请求体限速：普通接口的请求体需在 60 秒内读完；备份恢复、升级包与文件上传等大文件接口不限总时长，但要求持续发送并保持最低平均速率（每秒 4 KiB）。
  - 规模：651 条路径、808 个操作；每个操作声明所需权限 `x-required-scope` 与是否允许令牌 `x-token-allowed`。权限域 34 个（27 个模块 ID 加 `status`、`logs`、`metrics`、`import`、`fileusers`，以及写入共享用户的组合域），权限形如 `<域>:read` / `<域>:write`。74 个操作仅限登录会话（账号、两步验证、令牌管理、备份恢复、系统设置、历史回滚、确认与批量修改、自升级等），4 个为公开接口。
  - 未经编译的模块前缀返回 404，已关闭模块前缀返回 403；只读账号与只读令牌读取配置时，密码、分享链接令牌、请求头与响应头的值、各类密钥以及地址中的密码和查询参数一律显示为 `********`，也看不到命令与脚本、托管程序的附加启动参数与环境变量、Webhook 请求体。
  - 接口文档：`GET /api/openapi.json` 由路由注册时的文档信息生成，管理界面内有 API 文档页，可用 `-api-docs <目录>` 导出。
  - **通用集合接口**（上游 `internal/crud/crud.go` 的 `Collection[T]`）：列表类资源（规则、任务、实例、证书等）统一注册 `GET <path>`（列表）、`POST <path>`（新增）、`POST <path>/{key}/copy`（复制）、`PUT <path>/{key}`（修改）、`DELETE <path>/{key}`、`PUT <path>/{key}/enable`、`PUT <path>-order`、`PUT <path>-enable`（批量启停）、`POST <path>-delete`（批量删除），可选 `PUT <path>-group` 与 `GET <path>/{key}/secrets`（查看被脱敏字段的明文，按写权限鉴权）。集合带一组钩子：`Validate`（校验并规范化，持锁）、`Check`（依赖其他配置的校验）、`CheckEnable`（「同时启用的条目之间不能冲突」）、`Merge`（修改时保留被脱敏的密钥）、`View`（附加运行状态与脱敏的输出结构）、`Changed` / `Removed`（驱动运行实例重启）、`BeforeRemove`（条目仍被引用时拒绝删除）、`Secrets` / `SecretsGuard`、`Max`（条目数上限，只在新增时检查）、`Copy`（复制时把仍是占位符的密钥恢复为模板的值）。分组名最长 64 个字符。808 个操作里的大多数由它生成。
- **Rust 设计**：新 crate `fg-admin`（axum + tower）。中间件按上面的顺序用 `tower::ServiceBuilder` 组合，每层一个独立的 `Layer`/中间件函数，并各自带测试。路由注册时同时登记文档元数据：用 `utoipa` + `utoipa-axum`（待核实）生成 OpenAPI，或自研一个从 `#[derive(ApiDoc)]` 收集元数据的轻量方案；关键是让**路由、权限与文档出自同一处声明**。**必须先做泛型集合路由器** `fg_admin::collection::Collection<T>`：一个类型加一组钩子（闭包或小型 trait）就能注册上面的全部集合接口，并自动生成对应的 OpenAPI 条目；各模块只写校验、生效与输出转换。统一响应：`httpx.OK` 的成功信封与错误信封按上游字段实现（实现时以 `internal/httpx/httpx.go` 为准）。
- **验收**：中间件顺序测试（每层对请求的影响可观察）；权限域与操作的映射由测试对比 `docs/api/en/openapi.json`（路径、方法、权限三者一致）；404/403 前缀行为；限速；OpenAPI 可导出且能被上游前端或工具消费。

### WP-12 管理员认证与会话

- **上游依据**：`internal/auth/`、`internal/webauthn/`、`internal/thirdauth/`、`internal/loginips/`、`internal/app/{users,tokens,passkey,thirdlogin,loginip,defaultpw,onboarding,secstatus}.go`；文档 `docs/guide/security`「认证与访问控制」。
- **行为契约**：
  - bcrypt 密码哈希 + HMAC 签名会话令牌；登录 Cookie 带 `HttpOnly` 与 `SameSite=Strict`，经 HTTPS 访问时带 `Secure`。
  - 会话吊销：退出登录在服务端吊销当前令牌；「退出所有设备」使全部管理界面会话失效（API 令牌不受影响）；修改密码、启停两步验证与重置密码同样使全部会话失效。吊销记录保存在账号文件中，重启后仍有效，随令牌过期清理，数量有上限。
  - 密码规则：管理员密码至少 10 个字符、至多 72 字节（bcrypt 的上限），拒绝常见弱口令（含首尾加数字或符号、`p@ssw0rd` 式替换等变形）、包含 gately 或用户名、连续字符、重复字符或片段，以及只含一种字符的密码（16 位以上的口令短语放宽字符种类要求）。
  - 强制改密：仍在使用默认密码 `gately.cn` 或强度不足的密码时，登录后弹出无法关闭的改密对话框；在此之前，会话除修改密码、切换界面语言与退出所有设备外的写操作一律被服务端拒绝；API 令牌不能修改账号、两步验证、通行密钥、附加账号、API 令牌、系统设置与 Web 终端安全设置。**初始密码的做法见决策 D14**（推荐：首次启动生成随机初始密码，不再使用固定的默认密码）。
  - 重置：`gately reset-password` / `gately reset-totp` 直接读写配置目录并要求输入确认，重置后所有会话失效并记入审计日志。
  - Passkey（WebAuthn）：只保存公钥，强制用户验证，签名计数防克隆；需要通过域名与 HTTPS（或 localhost）访问。注册了 Passkey 后可关闭密码登录。
  - 两步验证：TOTP，通过 RFC 6238 测试向量验证。
  - 只读账号：可查看状态与配置，不能修改、下载备份、读取密钥或打开终端；重置密码或删除后会话立即失效；「审计日志」「配置历史」「API 令牌」「设置」只对管理员开放。
  - 登录失败限流与递增锁定：同一来源连续失败达到上限后被锁定，反复被锁定时每次锁定时长翻倍，最长 24 小时。陌生来源失败预算：10 分钟内从未成功登录过的地址累计失败达到预算后，陌生地址的密码登录暂时返回 429，并发出「认证：疑似分布式爆破」事件；Passkey 登录使用独立的按来源限流。
  - 安全评分：七项合计 0～100（密码 35、二次验证 20、安全入口 15、登录失败锁定 10、HTTPS 10、陌生地址失败预算 5、用户名不是常见名称 5）；管理端没有暴露到公网时，安全入口、HTTPS 与用户名三项视为满分。
  - 第三方登录（GitHub / Google / QQ / OIDC）使用用户自己的 OAuth 应用，不经过中转。
- **Rust 设计**：新 crate `fg-auth`。bcrypt 用 `bcrypt` crate；TOTP 用 `hmac` + `sha1` 自研（便于用 RFC 向量测试）或 `totp-rs`（待核实）；WebAuthn 用 `webauthn-rs`（待核实）；会话令牌为「随机 ID + HMAC-SHA256 签名」的无状态令牌加服务端吊销表。账号文件 `account.json` 的字段对齐上游（实现时以 `internal/auth/auth.go` 的持久化结构为准）。
- **验收**：bcrypt 往返与错误密码；会话吊销在重启后仍有效；弱口令字典与变体；强制改密状态下的写操作拒绝；TOTP 的 RFC 6238 向量；Passkey 注册与断言（软件认证器）；锁定时长翻倍；陌生来源预算；只读账号的越权访问；安全评分各项。

### WP-13 API 令牌

- **上游依据**：`internal/apitoken/{apitoken,scope}.go`、`internal/app/tokens.go`；文档 `docs/guide/security`、README「API usage」。
- **行为契约**：令牌以 `gtl_` 为前缀，明文只在创建时显示一次；保存 SHA-256 哈希与首末几位提示；每个令牌只拥有创建时勾选的模块读写权限，可设置过期时间，记录最近使用的来源 IP（磁盘写入有节流，至多滞后一分钟）；最多 100 个令牌，名称最长 64 字符；可排序与分组；旧版全局令牌在启动时迁移为「遗留令牌」（全部权限）；权限域随本次构建包含的模块变化，模块迁移时令牌继承权限。管理接口均仅限登录会话。
- **Rust 设计**：放在 `fg-auth::token`。哈希比较用常量时间比较。`last_used` 的节流写入用 Tokio 定时刷盘任务。
- **验收**：创建—使用—过期—禁用—删除；权限域校验；遗留令牌迁移；节流写盘；越权返回 403。

### WP-14 管理访问控制与管理界面入口

- **上游依据**：`internal/app/{deny,accesspath}.go`、`internal/httpx/{clientip,adminlisten}.go`、`internal/trustsrc/`、`internal/app/gateway.go`；文档 `docs/guide/security`、`docs/guide/hardening`。
- **行为契约**：安全入口（设置后需先访问该路径才能打开登录页，其他路径返回 404）；仅内网访问；管理界面 HTTPS（证书由证书模块按域名提供）与强制 HTTPS；未授权访问的响应方式（普通 404、空白页、断开连接、不响应直到超时、自定义页面）；只信任本机地址（及额外配置的可信代理）传来的 `X-Real-IP` / `X-Forwarded-For`，两个头不一致时以代理追加的 `X-Forwarded-For` 为准，一个是内网地址另一个是公网地址时取公网地址；模块的免登录接口凭有效设备凭据可以越过安全入口，但封禁与仅内网的限制仍然生效；内容安全策略（页面只加载自身脚本，不能被嵌入，接口响应不加载任何资源）；经飞牛统一网关访问时的来源校验（`Sec-Fetch-Site` 或专用请求头 `X-Gately-Page`）。
- **Rust 设计**：`fg-admin::access` 与新 crate `fg-net`（客户端地址解析等纯函数，管理面与各模块共用）。真实客户端地址解析独立成纯函数并单独测试。管理 HTTPS 监听通过 `Wiring.certs` 取得 SNI 证书解析器，证书模块未就绪时按上游行为处理（实现时核对 `adminlisten.go`）。飞牛统一网关（Unix Socket + 路径前缀 + 页面来源确认 + 飞牛登录态登录）作为本包的最后一个切片，fnOS 专用行为在不面向 fnOS 的构建中默认关闭；它是一整套安全机制（页面来源的三种确认依据、已确认来源的持久化、Cookie 路径与重定向地址的改写、按飞牛用户限流），已在上游 `gateway.go` 中逐行核实，见 [细化文档](plan/WP-14-admin-access.md) §3.3。
- **验收**：安全入口正反用例；仅内网（含 CGNAT 地址）判定；五种未授权响应；伪造 `X-Forwarded-For` 不能绕过仅内网；CSP 等响应头。

### WP-15 CLI、回滚命令与 MCP

- **上游依据**：`internal/ctl/`、`cmd/gately/{main,reset,rollback}.go`；文档 `docs/guide/cli-mcp`、`docs/tutorials/api-automation`。
- **行为契约**：
  - `ctl` 通过 HTTP 与 API 令牌访问运行中的实例，接口清单来自实例的 `/api/openapi.json`。连接信息依次取自：默认地址 `http://127.0.0.1:16680` → 配置文件 `ctl.json`（用户配置目录下的 `gately/ctl.json`）→ 环境变量 `GATELY_URL`、`GATELY_TOKEN` → 命令行选项 `-url`、`-token`。
  - 子命令：`ls [关键字]`（只列出令牌可访问的接口）、`get`、`post`、`put`、`delete`、`patch`、`login <地址> <令牌>`；请求体为 JSON 字面量、`@文件` 或 `-`（标准输入）；路径必须以 `/api/` 开头；退出码 0 / 1（接口非 2xx）/ 2（参数问题）。
  - `mcp` 通过标准输入输出提供 MCP（JSON-RPC，每行一条消息）：首次请求工具列表时读取实例的 OpenAPI 文档，每个令牌可访问的接口生成一个工具；工具名由方法与路径组成（最长 64 字符）；路径参数为必填，GET 带可选 query 参数，有请求体的带 `body` 参数；标注 `readOnlyHint` 与 `destructiveHint`；返回内容超过 200000 个字符时截断；默认只读（只暴露 GET 与 HEAD，不提供取回明文的接口），`--write` 开启写入。
- **Rust 设计**：`fgate ctl` 与 `fgate mcp` 放在根包的 `src/ctl.rs`、`src/mcp.rs`。MCP 用官方 Rust SDK `rmcp` 的 stdio 传输（待核实）；工具由 OpenAPI JSON 动态生成，因此 `fg-admin` 需要提供稳定的 OpenAPI 输出。默认端口沿用上游的 16680 还是另选，见决策 D9。
- **验收**：连接信息的覆盖顺序；`ls` 不含仅限会话的接口；退出码；MCP 工具命名与只读默认；大结果截断。

### WP-16 事件总线

- **上游依据**：`internal/events/events.go`。
- **行为契约**：进程内事件总线，各模块在状态变化时发布事件，通知中心等订阅者异步消费；发布永不阻塞调用方，事件投递给每个订阅者时各自在独立任务中执行；缺省的时间与级别会被补全。事件类型目录（新增类型时同步更新）：`ddns.changed`、`ddns.failed`、`ssl.expiring`、`ssl.renew_failed`、`ssl.deploy_failed`、`waf.blocked`、`upstream.down`、`upstream.up`、`docker.exited`、`process.exited`、`backup.done`、`backup.failed`、`auth.failed`、`auth.banned`、`fileauth.failed`、`auth.flood`、`guard.banned`、`knock.opened`、`knock.failed`、`notify.test`、`stun.changed`、`login.success`、`login.newip`、`audit.change`、`audit.access`、`perf.alert`、`perf.recovered`、`system.update`、`system.security`、`program.update`、`docker.update`、`config.rolledback`。
- **Rust 设计**：`fg-core::events` 以带 `#[non_exhaustive]` 的 `Kind` 枚举生成 32 项目录。发布读取订阅者快照并尝试占用有界入口队列。分发任务把同一事件投递至独立队列，各订阅者串行处理并隔离处理器 panic。现有 Web 主动健康检查发布上游故障与恢复事件。
- **验收**：发布不阻塞；订阅者 panic 隔离；退订后不再收到；事件目录与文档一致。

### WP-17 总览、自检与系统接口

- **上游依据**：`internal/app/{system,probe,selfcheck,publicip,storage_usage,diag,metrics,geoip_lookup,onboarding}.go`、`internal/sysstat/`；接口清单中 `/api/system/*`、`/api/status`、`/api/metrics`、`/api/geoip/lookup`。
- **行为契约**：总览展示 CPU、内存、磁盘、流量、网络接口与公网 IPv4/IPv6、每个模块的状态摘要（`Summarizer`）；一键网络自检（公网 IP、CGNAT、时钟、端口 80/443、DDNS 解析、证书到期、缺少证书的 HTTPS 站点、frp 代理冲突），结果为 ID 加参数；公网 IP 按需查询（10 秒内重复查询返回上次结果，结果保存在内存）；后端地址测试（一次 TCP 连接或不跟随重定向的 HEAD 请求）；存储占用按用途分类统计；全局 Prometheus 端点 `GET /api/metrics`（权限 `metrics:read`）；首次运行引导状态；诊断包导出（已脱敏）。
- **Rust 设计**：`fg-admin::system` 与 `fg-core::sysstat`（主机与进程指标采集，按平台条件编译；候选 `sysinfo` crate，待核实）。自检框架在 `fg-core`，各模块实现 `SelfCheck`。
- **验收**：自检各项的模拟环境用例；公网 IP 的并发与节流；指标文本格式符合 Prometheus 0.0.4；诊断包不含密码、令牌、域名与真实 IP。

## 8. 阶段 P1：核心数据面（Web 服务、证书、端口转发、协议分流）

P1 把三个核心模块补齐到上游水平。Web 服务是上游最大的模块（非测试 Go 约 2.4 万行、117 个测试文件、560 个测试函数、64 个管理接口），拆成 11 个工作包；证书与端口转发各 2～3 个工作包。

### 8.1 Web 服务（webservice）

**配置文件** `webservice.json`，顶层为 `settings`、`listeners[]`、`ipLists[]`、`errorPages[]`、`visitors`、`replay`、`panels[]`、`loginPage`。**管理接口** 81 个操作，权限域 `webservice:read` / `webservice:write`，资源组：`listeners`（含 order / enable / delete / copy）、`sites`（batch）、`settings`（含 `secrets/oauth|totp|marker`）、`users`、`iplists`、`errorpages`、`panels`、`loginpage`、`bans`、`cache`、`connections`、`topology`、`visitors`、`stats`、`metrics`、`geoip`、`import/nginx`、`logs`。

**现有实现可复用的部分**（`crates/fg-gateway/src/`）：`proxy.rs` 的逐跳头处理与流式转发、`websocket.rs`、HTTP/2 与 gRPC 转发、`backend.rs` 的加权池与被动摘除、`health.rs` 的主动检查、`site.rs` 的重定向与固定文本、`static_files.rs` 的受限根目录与 Range、`domains.rs` 的通配匹配、`tls.rs` 的 SNI 选择。它们需要迁到新的配置模型与模块框架下，并按下面的契约修正差异。

### WP-20 Web 服务配置模型 v2

- **目标**：用上游的「监听器 + 站点 + 默认站点」模型替换现有的 `[[routes]]` 扁平列表。
- **上游依据**：`internal/modules/webservice/config.go`（`Site`、`Listener`、`Settings`、`fileConfig` 及全部子结构）、`site.go`（校验与规范化）、`internal/hostname/pattern.go`（域名规则）；文档 `docs/modules/web`「结构：监听、站点与默认站点」「移动站点」「批量操作」。
- **行为契约**：
  - 监听器 `Listener`：`key`、`name`、`enable`、`network`（`tcp` 双栈 / `tcp4` / `tcp6`）、`listenIp`、`port`、`tls`、`minTls`（`1.0` / `1.1` / `1.2` / `1.3`）、`http3`、`plainHttp`（空 / `redirect` / `serve`）、`httpPort`、`httpPortMode`、`acceptProxyProtocol`、`accessScheme` / `accessPort`（只用于界面生成链接）、`autoFirewall`、`sites[]`、`default`（站点）、`remark`。
  - 站点 `Site` 的字段组：标识（`key`、`name`、`enable`、`group`、`remark`）、域名与类型（`domains[]`、`type`）、反向代理（`targets[]`、`insecureSkipVerify`、`useTargetHost`、`disableKeepAlives`、`sendProxyProtocol`、`forwardedHeaders`、`upstreamSniFromHost`、`upstreamH2c`、`passAuthCookies`、`locations[]`、`userRoutes[]`、`identityHeaders[]`）、重定向（`redirectTo`、`redirectCode`、`keepPath`）、静态文件（`root`、`listDir`、`cleanUrls`、`notFoundPage`）、导航面板（`panel`）、固定文本（`text`、`contentType`、`statusCode`）、认证与访问控制（见 WP-24～26）、流量（`lbPolicy`、`health`、`timeouts`、`clientTimeouts`、`compress`、`rateLimit`、`cache`、`rewrites[]`、`requestHeaders[]`、`responseHeaders[]`、`cors`、`accessLog`、`waf`）、`errorPage`、`loginStyle`。
  - 域名规则：精确域名；`*.example.com` 匹配**任意级**子域名；`api-*.example.com` 段内通配，可在任意一段；`audiobook.*.example.com` 中间整段匹配一段；`audiobook.*` 末尾整段匹配一段或多段；`*` 匹配所有。每条只能有一个 `*`；全是数字标签的末尾通配（如 `192.168.*`）被拒绝，因为它实际是 IP 前缀。
  - 默认站点在没有站点匹配时使用，未启用时返回 404；默认站点可以是「断开连接」类型。
  - 分组名最长 64 个字符，只影响管理界面的展示；排序与分组变更不重启服务、不切断连接。
  - 保存站点或默认站点时**原地替换**站点表：监听器继续运行，进行中的连接（含 WebSocket）保持，各站点保留统计。监听器地址、端口、证书、HTTP/3 等字段变更才重建监听。
- **与现状的差异**：现有通配规则只匹配单个子域标签；现有路由以 `(host, path_prefix)` 为键，新模型把路径规则收进站点的 `locations` / `rules`；现有 `server.*` 的超时与连接上限拆到「后端超时」「访客超时」与监听器级别。
- **Rust 设计**：`fg-web::model`，用 serde 结构体一比一映射上游 JSON 名（`#[serde(rename_all = "camelCase", default, deny_unknown_fields)]`），编译为只读快照 `Arc<SiteTable>`（按监听器分：`HashMap<ExactHost, &[SiteId]>`、通配规则列表、默认站点），经 `arc_swap::ArcSwap` 发布。域名匹配器支持四种通配形态并保留「更长规则优先」的既有语义，具体优先级以 `internal/hostname/pattern.go` 为准。
- **验收**：域名规则五种形态的匹配与拒绝用例；重复域名、非法类型、引用不存在资源的校验；原地替换站点表时已有连接不断开；`fgate check` 对新配置目录的校验输出。

### WP-21 监听器与传输协议

- **上游依据**：`listener.go`、`sniff.go`、`module.go`、`listeners_etag.go`、`sitecert.go`、`internal/reuseport/`；文档 `docs/modules/web`「传输与协议」「访客真实 IP」「自动放行防火墙」。
- **行为契约**：
  - 多监听器并存，网络可为双栈、仅 IPv4、仅 IPv6。
  - TLS 最低版本可设为 1.0 / 1.1 / 1.2 / 1.3（rustls 只实现 1.2 与 1.3；配置为 1.0 / 1.1 时的等价行为见决策 D11）。证书由证书模块按 SNI 提供。
  - 同端口 HTTP：开启 HTTPS 的监听按连接的第一个字节区分协议；`redirect` 把 `http://地址:端口` 跳转到 `https://地址:端口`（GET/HEAD 用 301，其他方法用 308）；`serve` 直接按 HTTP 提供站点。ACME HTTP-01 验证请求照常应答。
  - 额外 HTTP 端口 `httpPort`：与主端口共用全部站点与设置。开启 HTTPS 时 `httpPortMode` 默认 `redirect`（跳转到主端口的 HTTPS 地址，保留域名、路径与查询串，端口换成「访问地址」中的端口），或 `serve`。没有对应站点的域名不跳转。该端口被占用时主端口照常运行，监听状态显示原因。
  - HTTP/3：在 HTTPS 监听上开启，在同一端口号的 UDP 上提供，并通过 `Alt-Svc` 通告。
  - PROXY 协议接收：仅信任模块设置 `trustedProxies` 中的 IP 或网段，留空不信任任何来源。经可信来源进入且带 `X-Forwarded-Proto: https` 的连接按 HTTPS 处理（会话 Cookie 带 Secure、不再跳转、如实向后端传递）。
  - 访客真实 IP：`realIPFrom`（可信代理的 IP 或网段，不能填 `0.0.0.0/0`、`::/0`）与 `realIPHeaders`（按顺序查找，如 `CF-Connecting-IP`、`X-Forwarded-For`、`X-Real-IP`）。只在原始对端位于可信代理中时读取；`X-Forwarded-For` 等多项头自右向左跳过可信代理，取第一个不可信的地址。访客源端口只来自 `realPortHeader`。该地址用于访问日志、黑白名单、仅内网访问、国家过滤、认证失败封禁、统计、路径探测与转发给后端的头。
  - 自动放行防火墙：见 WP-37。
- **Rust 设计**：`fg-web::listener`。每个监听器一个 Tokio 任务持有 `TcpListener`，接入后先读取首字节再分流到 TLS 或明文（`tokio::io::AsyncReadExt::peek`）。HTTP/3 用 `quinn` + `h3`（待核实版本），与 HTTPS 监听共用 rustls 的 `ServerConfig` 与证书解析器；HTTP/3 请求与 TCP 请求进入同一个 `Service`。PROXY 协议解析自研（v1/v2，限长、超时）。真实地址解析为纯函数 `resolve_client_addr(peer, headers, &settings)`。
- **验收**：首字节分流的 TLS/明文/非法输入用例；同端口 `redirect` 与 `serve`；额外 HTTP 端口被占用；HTTP/3 握手与请求（需要 QUIC 测试客户端）；PROXY 协议可信与不可信来源；伪造 `X-Forwarded-For` 不生效。

### WP-22 站点类型

- **上游依据**：`site.go`、`static.go`、`redirectvars.go`、`location.go`；文档 `docs/modules/web`「站点类型」「重定向变量」「按路径分流后端」。
- **行为契约**：
  - 类型：`proxy`、`redirect`、`static`、`text`、`panel`（见 WP-29）、`close`（不返回任何响应直接断开，相当于 nginx 的 `return 444`，访问日志记 444）。
  - 重定向：`redirectTo` 为目标地址前缀，可用 `{host}` 代表访客请求的域名；`keepPath` 时附加原路径与查询串。
  - 静态文件：`root`、`listDir`、`cleanUrls`（找不到文件时再尝试 `路径.html` 与 `路径/index.html`）、`notFoundPage`（相对 `root`，如 `404.html`）。
  - 按路径后端 `locations[]`：`prefix` 按路径段边界匹配（`/api` 与 `/api/` 都匹配 `/api` 与 `/api/x`，不匹配 `/apix`）；`targets` 留空时沿用站点后端，只追加请求头；`stripPrefix` 开启后转发前去掉前缀（路径先按 `//`、`.`、`..` 规范化再去前缀，不能借点段越过前缀；后端地址自带的路径接在前面；查询串原样保留）；`requestHeaders` 在站点请求头之后应用，同名覆盖。最长前缀优先。
  - 站点的 Host 选项、证书校验、转发头、PROXY 协议、负载均衡策略与健康检查对每个路径后端同样生效。
- **Rust 设计**：`fg-web::site` 把请求处理抽象为「站点动作」枚举，`locations` 编译为按长度降序的前缀表。静态文件沿用现有受限目录句柄方案，增加目录索引与 Clean URLs。
- **验收**：六种类型各自的 E2E；`{host}` 变量；目录索引、Clean URLs、自定义 404；`stripPrefix` 与点段规范化；路径后端继承站点选项。

### WP-23 后端、负载均衡、健康检查与超时

- **上游依据**：`upstream.go`、`proxyconf.go`、`proxyretry.go`、`clienttimeout.go`、`userroute.go`、`identityheader.go`、`realip.go`；文档 `docs/modules/web`「后端、权重与备用」「负载均衡策略」「健康检查」「后端超时」「访客超时」「按认证用户分流」「传递身份信息」「请求头与响应头」「路径重写与重定向」。
- **行为契约**：
  - 后端每行一个地址，可附 `weight=N`（1～100，默认 1）与 `backup`。备用后端仅在全部非备用后端都不可用时启用；全部不可用时回退到所有非备用后端继续尝试。
  - 负载策略 `lbPolicy`：空（按权重轮询，默认）、`random`、`ip_hash`、`least_conn`（按「连接数 / 权重」选择最小者）。
  - 重试：连不上某个后端（连接被拒绝、不可达或连接超时）时，同一请求立即换下一个后端重试，先试其他主后端再试备用后端，**最多尝试 3 个后端**；此时请求尚未发出，POST 重发也安全。连接建立后的失败不重试，照常计入被动检查。
  - 主动检查（默认关闭）：`mode` 为 `http`（状态码小于 400 为健康）或 `tcp`；`path` 默认 `/`；`interval` 10 秒（1～3600）；`timeout` 3 秒（1～60）；`fails` 3 次（1～20）；`passes` 2 次（1～20）。启用向后端发送 PROXY 协议时，HTTP 检查自动改用 TCP。启用后恢复完全由检查结果决定。
  - 被动检查始终生效：多个后端中，连续 3 次连接失败的后端暂停 30 秒后再试探；只有一个后端且未启用主动检查时不摘除。后端状态变化发布 `upstream.down` / `upstream.up`。
  - 后端超时：`connect` 默认 10 秒（1～300）；`tlsHandshake` 默认 10 秒（1～300）；`responseHeader` 默认不限（1～86400），只限制响应头到达之前的等待，之后的响应体传输与 WebSocket、SSE 不受影响，上传大文件时从请求体发完才开始计时。超时返回 504，连接被拒绝等其他错误返回 502。
  - 访客超时：`readIdle`、`writeIdle` 默认 60 秒（1～3600），只在一次读取或写出卡住时计时。读取超时返回 408 并关闭连接，不计入后端被动检查；写出超时直接断开。对 HTTP/1、HTTP/2、HTTP/3 都生效。
  - 按认证用户分流 `userRoutes[]`：`users[]`（站点用户或共享用户的用户名；第三方登录写 `提供方key:标识`；转发认证为 `Remote-User`）与 `targets[]`。未列出的用户与公开路径上的未登录访客使用站点后端；填写了后端的分路径规则优先。重定向、静态、导航面板、固定文本站点同样可以按用户分流。
  - 身份请求头 `identityHeaders[]`：`header` + `field`（`user` / `email` / `name` / `groups`），最多 16 条；访客自带的同名请求头总是被删除（含用下划线代替连字符的写法）；不能是 `Host`、`Cookie`、`Authorization`、`X-Forwarded-For` 等影响转发或认证的头。
  - 请求头/响应头每项 `Key: Value`，值为空表示删除；`rewrites[]` 为正则重写（`pattern`、`to`、`redirect`、`code` 301/302/307/308），按顺序匹配，命中第一条即停止，重定向规则先于认证执行；`cors` 开启跨域。
- **与现状的差异**：现有默认连接超时 2 秒、响应头超时 30 秒、无 TLS 握手与访客空闲超时、无重试、无负载策略选择、通配只到单层。
- **Rust 设计**：`fg-web::upstream`。后端选择器按策略实现为一个小枚举，状态（连续失败计数、暂停截止时间、连接数）放在 `BackendState` 的原子字段里；每代配置快照持有自己的状态。主动检查沿用现有每代最多 32 个并发探测的任务模型。重试只在「连接阶段失败且请求体尚未开始读取」时进行，保持 DESIGN.md 中「代理不额外重放请求」的原则，仅对上游允许的连接失败情形重试。
- **验收**：四种负载策略的分布与故障切换；最多 3 次重试与备用回退；主动/被动检查的摘除与恢复；三类超时的边界（含大文件上传与 SSE）；按用户分流与身份头的伪造防护；正则重写与重定向。

### WP-24 站点认证：基本认证、网页认证与共享用户

- **上游依据**：`auth.go`、`users.go`、`siteusers.go`、`shared.go`、`password.go`、`loginpage.go`、`loginpage_api.go`、`internal/webpage/{styles,styles_builtin,loginskins_builtin}.go`；文档 `docs/modules/web`「认证」「共享用户：TOTP 与单点登录」「自助修改密码」「登录页外观」。
- **行为契约**：
  - 基本认证：`users` 每项 `用户名:密码`，密码可为 bcrypt 哈希；保存时明文转为哈希，接口只显示 `********`，提交掩码或留空表示沿用原密码。启用基本认证至少需要一个用户。
  - 网页认证：浏览器显示登录页；启用时至少需要一个用户或第三方登录身份。
  - 共享用户 `authUsers[]`：`id`（不可变的随机标识，改名后保持不变，OIDC 用作 `sub`）、`name`、`password`（bcrypt）、`totpSecret`（Base32，空为不启用）、`email`、`displayName`、`groups`、`passkeys`、`remark`。站点开启 `sharedUsers` 后接受共享用户；基本认证只接受未启用 TOTP 的共享用户。
  - 单点登录域 `ssoDomains[]`：在该域或其子域名下的任一站点登录后，其他站点无需再登录；使用父域 Cookie `gately_sso`，有效期 7 天，不转发给后端。多个域互不嵌套、相互独立。
  - TOTP：只要有共享用户启用了 TOTP，登录页就显示验证码输入框，每个验证码只能使用一次；修改用户密码或 TOTP 密钥后该用户已有会话立即失效。
  - 自助修改密码 `selfServicePassword`：路径 `/__gately_auth/password`；新密码 8～128 个字符且与当前密码不同；同一账号 1 分钟内不能再次修改；与登录失败共用限流与自动封禁；其他网站代为提交的表单被拒绝。
  - 登录页外观：默认样式加 9 种内置样式（锁屏、分屏、极简、终端、信笺、粗野、极光、像素、蓝图）；品牌项（主色、背景图 ≤1 MB、Logo ≤256 KB、标题与说明、隐藏页脚标识）；自定义 CSS ≤32 KB，`<` 被转义。站点可用 `loginStyle` 单独指定。
- **Rust 设计**：`fg-web::auth`。会话 Cookie 用 `AuthSecret`（首次启动自动生成）做 HMAC 签名，Cookie 名按「监听器 key / 站点 key」隔离。登录页由服务端渲染（对应上游的 `internal/webpage`），用 `askama` 模板或内嵌的静态 HTML 加占位替换（样式与皮肤是纯前端资产，在 WP-80 一并处理）。bcrypt 校验放在 `spawn_blocking`，并按来源限制并发。
- **验收**：基本认证与掩码保持语义；网页认证的登录、登出、会话失效；共享用户与 TOTP（含重放）；单点登录域内通用与跨域隔离；自助改密的节流与防 CSRF；两种内置样式的渲染。

### WP-25 站点认证：第三方登录、Passkey、转发认证与信任传递

- **上游依据**：`oauth.go`、`passkey.go`、`passkey_page.go`、`forwardauth.go`、`adminpass.go`、`admincookie.go`、`adminhop.go`、`trustauth.go`、`authmarker.go`、`internal/thirdauth/`；文档 `docs/modules/web`「认证」「转发认证」「Passkey 登录」「访问控制」中「后台登录免认证」「信任已登录用户」。
- **行为契约**：
  - 第三方登录：GitHub、Google、QQ、OIDC，使用用户自己的 OAuth 应用。提供方在模块设置 `oauthProviders[]` 中配置，回调地址 `OAuthCallbackBase` 下的 `/__gately_auth/oauth/callback`。允许的身份 `oauthUsers[]` 每行 `提供方标识:账号`，`github:*` 表示该提供方任意账号。登录完成后带着一次性票据回到发起登录的站点，只能从指向本实例的地址发起（域名须匹配站点域名，端口须是监听端口、HTTP 端口或访问地址中的端口）。
  - Passkey 登录 `passkeyLogin`：共享用户在 `/__gately_auth/passkey` 先验证身份再管理凭据，每用户最多 10 个；RP ID 为单点登录域或站点域名；只在精确域名上提供，通配域名站点与默认站点不提供；需要 HTTPS 或 localhost。
  - 转发认证 `forwardAuth`：`url`、`loginUrl`（可用 `{url}`、`{method}`）、`loginFromLocation`、`copyHeaders`（默认 `Remote-User`、`Remote-Groups`、`Remote-Email`、`Remote-Name`）。每个请求先以不带请求体的 GET 发到认证接口，带访客的请求头与 `X-Original-*`、`X-Forwarded-*`、`X-Real-Ip`，超时 10 秒；2xx 放行并带上身份头；401 跳转登录地址（302）；其他结果原样返回；无法连接返回 502。访客自带的身份头一律删除。与基本认证、网页认证互斥。
  - 后台登录免认证 `adminPass`：已登录管理后台的管理员访问本站点不再需要认证；需要单点登录域，凭据 `gately_admin` 绑定那一次后台会话，只读账号不获得；身份记为 `gately:用户名`。
  - 信任已登录用户 `trustAuthUsers`：通过本站点 Gately 认证的访客不经过 WAF，也不计入入侵防护的路径探测；第三方登录只信任逐个列出的身份，通配允许的身份不信任。
  - 双层 Gately：两端填写相同的认证标记密钥 `authMarkerKey`（至少 16 个字符）；内层在响应头 `X-Gately-Auth` 返回签名标记，绑定该请求所用凭据的哈希，5 分钟有效；外层开启 `passAuthCookies` 与 `trustBackendAuth`，校验后放行并在返回访客前去掉标记头。
- **Rust 设计**：`fg-web::oauth`（授权码 + PKCE，状态与一次性随机数用签名 Cookie）、`fg-web::passkey`（复用 WP-12 的 WebAuthn 实现）、`fg-web::forward_auth`（独立的 HTTP 客户端连接池）。认证标记用 HMAC-SHA256。
- **验收**：每种提供方的模拟授权服务器流程；回调地址校验；Passkey 注册、登录、删除与克隆检测；转发认证的 2xx/401/403/不可达；免认证凭据随后台会话失效；认证标记的签发、校验、过期与头剥离。

### WP-26 访问控制

- **上游依据**：`access.go`、`iplists.go`、`knockgrant.go`、`internal/iplist/`、`internal/geoip/`、`internal/knockgate/`；文档 `docs/modules/web`「访问控制」「IP 黑白名单」「拒绝方式」「敲门准入与登录后放行」「订阅 IP 列表」「路径规则」「临时分享链接」「认证失败限流与自动封禁」「封禁列表」「GeoIP 国家过滤」「IP 归属地」。
- **行为契约**：
  - IP 访问控制 `ipMode`：空（关闭）、`whitelist`、`blacklist`；`ipList[]` 每行一个 IP 或网段；`ipSets[]` 引用订阅列表。优先拒绝名单 `ipDenyList` / `ipDenySets` 先于白名单、黑名单判断，路径规则无法覆盖。
  - 拒绝方式 `denyClose`：被拒绝时不返回任何内容直接断开，访问日志记 444；限流（429）与 WAF 拦截不受影响。
  - 路径规则 `rules[]`：`prefix`、`auth`（空沿用站点 / `off` / `on`）、`ipMode`、`ipList`、`ipSets`。最长前缀优先，按路径段边界匹配，请求路径先规范化（消除 `.`、`..` 与重复斜杠）。`authOptional` 开启后认证只作用于标记为「必须认证」的路径。
  - 订阅 IP 列表 `ipLists[]`：`url`、`refreshHours`（默认 24）、`proxy`（空遵循环境变量，`direct` 直连，`update` 全局更新代理）；内容每行一个 IP、CIDR 或 `起始-结束` 范围，`#`、`;`、`//` 之后为注释；定时下载并缓存到配置目录；内容无法识别时保留上次的列表并在一小时后重试；下载成功前按空列表处理；删除仍被引用的列表被拒绝。
  - 临时分享链接 `shareLinks[]`：`token`（保存后生成，至少 16 位）、`expiresAt`、`maxUses`（重启后计数清零）、`pathPrefix`。访客访问 `任意路径?_gs=令牌` 兑换会话，会话最长 24 小时且不超过链接的过期时间；令牌无效时按普通访问处理。
  - 认证失败限流与自动封禁：同一来源 IP 在 15 分钟内认证失败累计 10 次后暂时拒绝继续尝试；`autoBanSeconds`（0～43200）非零时封禁来源，发布 `auth.banned` 事件；IPv6 按 /64 聚合。封禁列表可与入侵防护共用，支持手动封禁（1～720 小时，接口默认 24 小时；永久为 `seconds = -1`）。
  - 敲门准入：`knock` 引用敲门规则，未持有授权的来源按拒绝方式处理；`knockLan` 让私有地址与链路本地地址直接放行。登录后放行 `knockGrant`：`rule`、`minutes`（默认 360，5～10080）、`v6Prefix`（默认 64，48～128）、`probeV4` / `probeV6` 双栈探测域名；回环、内网、链路本地与 `100.64.0.0/10` 不被放行；每个用户对每条规则最多 16 个放行；授权保存在内存中。
  - GeoIP：`countryMode`（空 / `allow` / `deny`）与 `countries[]`（两位 ISO 代码）。数据库经上传（`.mmdb`、`.mmdb.gz`、`.tar.gz`，上传限制 257 MB）或下载地址导入；未加载时过滤不生效；内网地址始终放行；「拒绝」模式下查不到国家的地址放行。IP 归属地查询只用本机数据库。
- **Rust 设计**：`fg-web::access`（决策顺序：封禁 → 优先拒绝 → 敲门准入 → 国家 → IP 模式/路径规则 → 认证），`fg-net::iplist`（下载、解析、缓存、定时刷新；`ipnet` 存储），`fg-net::geoip`（`maxminddb` crate，待核实），`fg-web::banlist`（与入侵防护模块共用一张表，见 WP-50；未编译入侵防护时由 Web 服务自己维护）。
- **验收**：优先拒绝先于白名单；路径规范化后再匹配；订阅列表的成功、失败保留、空列表语义；分享链接的兑换、次数、过期、路径限制、删除后失效；失败计数与封禁（含 IPv6 /64）；敲门准入与放行（需 WP-51 的接口，可先用测试桩）；国家过滤的三种模式。

### WP-27 性能：压缩、限流、缓存与错误页

- **上游依据**：`internal/httpcompress/`、`rate.go`、`cache.go`、`cache_api.go`、`errorpages.go`、`errorpages_api.go`；文档 `docs/modules/web`「压缩」「按 IP 限流」「内存响应缓存」「错误页」「拦截后端错误」「自定义页面」。
- **行为契约**：
  - 压缩：对反向代理、静态文件、固定文本站点可启用；按 `Accept-Encoding` 优先 br，其次 gzip；仅文本类内容（`text/*`、JSON、JavaScript、XML、XHTML、RSS/Atom、WebAssembly、SVG），`text/event-stream` 排除；`Content-Length` 小于 256 字节保持原样；已有 `Content-Encoding` 的保持原样；WebSocket 升级直接放行；压缩后强校验 ETag 改为弱校验。
  - 限流：按客户端 IP 的令牌桶，`rate`（每秒请求数）、`burst`（设了 rate 而 burst 为 0 时取 rate 取整加 1）、`maxConns`（单 IP 并发上限，0 不限）；rate 与 maxConns 至少设置一项。
  - 缓存：仅反向代理站点，内存 LRU。`ttl` 0～30 天（上游未声明时 200 响应的缓存时长，0 表示只缓存上游明确允许的），`maxMb` 默认 64（1～4096）。仅缓存 GET、无 Range、无 `no-cache`、不带凭据的请求；原始路径含 `;`、`\`、`%2F`、`%5C` 的不缓存；仅状态码 200；响应含 `Set-Cookie`、`Vary: *` 或 `Cache-Control: no-store / private / no-cache` 时跳过；`Vary` 只能包含 `Accept-Encoding`（开启跨域时还可含 `Origin`）；遵循 `s-maxage`，其次 `max-age`；单条目上限 4 MB 且不超过总容量的四分之一；命中返回 `X-Cache: HIT` 与 `Age`，未命中 `MISS`；缓存键含 Host、完整请求 URI 与 `Accept-Encoding`（配置了按用户分流或身份头时还包含它们）。按路径规则最多 200 条（`path`、`noCache`、`ttl`、`override`），更具体的规则优先。接口 `GET /api/webservice/cache`、`POST /api/webservice/cache/purge`。
  - 错误页：10 种内置风格（极简、终端、霓虹、星空、报刊、粗野、极光、像素、蓝图、状态链路）或自定义页面；作用于 Gately 为站点生成的 404 与 5xx；非浏览器客户端仍得到纯文本。拦截后端错误：只替换浏览器打开页面的请求（`Accept` 含 `text/html`），状态码支持范围与 `5xx` 简写，只能填 400～599；保留状态码与 `Set-Cookie`、`Retry-After`，去掉描述原响应体的头。
  - 自定义页面库 `errorPages[]`：上传或粘贴（UTF-8，≤256 KB）或服务器文件（每次使用时检查变化）；占位符 `{code}`、`{status}`、`{title}`、`{detail}`、`{host}`、`{path}`、`{time}` 输出时 HTML 转义；保存时去掉脚本、事件属性、`javascript:` 链接、内嵌框架、表单、`<base>`、`<meta http-equiv>` 与危险样式；输出时附加 `Content-Security-Policy: sandbox; default-src 'none'; …`。
- **Rust 设计**：压缩用 `async-compression`（gzip + brotlic）或 `tower-http` 的压缩层（需确认它能按上游规则排除 `text/event-stream`，否则自研一层）；限流用 `governor`（待核实）加并发计数信号量；缓存用 `moka` 或自研 LRU（条目为序列化的响应头与响应体字节）；错误页 sanitizer 需要一个 HTML 解析器（`html5ever` + 标记化后白名单输出，待核实）。
- **验收**：压缩的内容类型、最小长度、ETag 弱化；令牌桶与并发上限；缓存的全部排除条件、容量淘汰、键隔离、按路径规则与清除接口；错误页对浏览器与curl 的差异；拦截后端错误；自定义页面的清洗与 CSP。

### WP-28 可观测性：统计、连接、拓扑、访客审计与指标

- **上游依据**：`internal/modules/webservice/{minutering,latency,connections,topology,replay,replay_api,visitors,metrics,traffic}.go`、`internal/visitors/`；文档 `docs/modules/web`「访问统计与监控」、`docs/reference/monitoring`、`docs/en/MONITORING.md`。
- **行为契约**：
  - 站点统计：分钟级，保留最近 24 小时（请求数、4xx/5xx、状态码分布、累计流量、来源 IP Top 10、国家 Top 10、后端健康与连接数、按原因的拦截次数）；首字节延迟为请求到达到响应头发出的时间，每分钟 P50/P95，协议升级与被断开的请求不计入；统计在内存中，修改站点保留计数，修改监听器自身的设置后重新计数；排行榜最多 5000 个来源。
  - 实时连接：以**请求**为单位归属站点（HTTP/2、HTTP/3 一条连接可承载多个请求），最多显示 500 条，每站点保留最近 200 条历史（只记录持续 1 秒以上或被手动断开的连接）；「断开」对 HTTP/1.x 关闭整条连接、对 HTTP/2 与 HTTP/3 只重置该请求；「断开并封禁」把来源地址（IPv6 为 /64）加入封禁列表。接口 `GET /api/webservice/connections`、`POST /api/webservice/connections/close`。
  - 网络拓扑：节点为互联网 → Gately → 监听 → 站点 → 后端，每 2 秒刷新；每个站点、后端与监听级动作最多记录 1024 个近期地址，接口一次最多返回 500 个。回放：开启后每 5 秒录一帧，压缩后只保存在内存，默认上限 8 MiB（1～256）。接口 `GET /api/webservice/topology`、`/topology/replay`、`/topology/replay/frame`、`PUT /topology/replay/settings`。
  - 访客审计：按访客地址汇总全部站点（含默认站点与未匹配的请求）；只保存聚合计数，不保存逐条请求，不记录查询串、请求体、Cookie 与凭据；每位访客最多保留 12 个站点、10 个路径、6 个身份、4 个 User-Agent；数据在 `visitors/visitors.jsonl.gz`（0600），有变化后约 10 分钟写盘；保留天数 1～180（默认 30），最多访客 100～100000（默认 10000）。接口 `GET /api/webservice/visitors`、`/visitors/detail`、`/visitors/settings`、`POST /visitors/delete`、`PUT /visitors/settings`。
  - 指标 `GET /api/webservice/metrics`：`gately_site_requests_total`、`gately_site_errors_total`、`gately_site_active_requests`、`gately_site_response_bytes_total`、`gately_site_responses_total{class}`、`gately_site_blocked_total{reason}`、`gately_upstream_up{upstream}`、`gately_upstream_requests_total`、`gately_upstream_response_bytes_total`、`gately_listener_requests_total{action}`；标签 `listener`、`site`，分流后端另带 `route`。FerrumGate 的指标前缀统一为 `ferrumgate_`（决策 D12）。
  - 访问日志：站点 `accessLog` 开关；归档与保留见 WP-09。
- **Rust 设计**：`fg-web::stats`。每站点一个 1440 点的分钟环（原子计数数组）与延迟直方图（每档内取平均耗时估算分位数，与上游一致）；连接登记表为分片 `Mutex<Slab<ConnInfo>>`，上限有界；访客审计用 `parking_lot::Mutex<HashMap<IpAddr, Visitor>>` + 后台压缩写盘（`flate2` gzip）。所有计数只使用固定基数标签。
- **验收**：分钟环与保留；延迟口径；连接归属与断开；封禁联动；拓扑数据与回放帧；访客审计的保留、淘汰与脱敏；指标名称与标签集合的快照测试；负载下内存不随访客数无界增长。

### WP-29 导航面板

- **上游依据**：`panel.go`、`panel_api.go`、`panel_favicon.go`、`panel_sunpanel.go`、`internal/webpage/{panel,panelui,panelskin,panelthemes,panelicons,custom}.go`；文档 `docs/modules/web`「导航面板」、`docs/tutorials/navigation-panel`。
- **行为契约**：作为站点类型 `panel` 提供的链接页，引用面板库 `panels[]` 中的一个；LAN 访客得到 LAN 地址；内置图标；访客语言菜单；仅登录可见的链接；卡片或图标两种样式与布局参数；搜索框、自定义页脚、背景图；多地址链接的地址选择器；favicon 生成；接口 10 条路径（`panels` 的 CRUD、order、group、enable、delete、copy、`icons`、`favicon`、`preview`）与 Sun-Panel 导入 `POST /api/webservice/panels/sunpanel`。
- **Rust 设计**：`fg-web::panel`。面板数据模型按上游 JSON 一比一映射；渲染在服务端完成（对应上游 `panelui.go`），图标集与主题作为静态资产嵌入。先做数据模型、CRUD 与基本渲染，再做主题与布局的全部参数。
- **验收**：面板 CRUD 与引用校验；LAN 地址替换；仅登录可见的链接；favicon；Sun-Panel 1.x/2.x 导入样例。

### WP-30 配置导入与站点批量操作

- **上游依据**：`nginx_import.go`（1666 行）、`nginxconf.go`、`nginx_npm.go`、`lucky.go`、`batch.go`、`internal/luckyimport/`；文档 `docs/modules/web`「导入 nginx 配置」「导入 Nginx Proxy Manager」、`docs/guide/migration`、`docs/en/MIGRATION.md`、`docs/tutorials/migrate-from-nginx`。
- **行为契约**：
  - nginx 导入：支持直接粘贴 `nginx -T` 的输出；转换反向代理与 upstream、静态目录、重定向、按路径后端、访问控制；`auth_request` 转换为转发认证；`location /api/ { proxy_pass http://后端/; }` 这类带 URI 的写法转换为开启 `stripPrefix` 的分路径规则。**导入的规则默认停用**，便于逐步切换（见 `docs/guide/introduction` 的设计原则）。
  - Nginx Proxy Manager：导入其配置，`set` 变量代入 `proxy_pass`。
  - Lucky：`POST /api/import/lucky`，解析 lkcf / lkcf v2 与归档，映射 IP 过滤规则与网络存储。
  - 站点批量操作 `POST /api/webservice/sites/batch`：批量添加、删除或替换域名，批量修改选项（如错误页样式），全部校验通过才保存；移动站点到其他监听器为单次请求，源与目标监听器各重载一次。
- **Rust 设计**：`fg-web::import`。nginx 配置解析器自研（指令 tokenizer + 块结构），不执行任何外部命令。导入流程为「解析 → 预览 → 用户确认 → 以停用状态写入」。Lucky 归档解包限定条目数与解压后大小。
- **验收**：nginx 各类指令的转换样例（含 `nginx -T` 多文件与 `set` 变量）；不支持的指令在报告中列出；导入结果默认停用；批量操作的全有或全无；移动站点时其他连接保持。

### 8.2 SSL 证书（ssl，核心模块）

**配置文件** `ssl.json`：`settings`、`certs[]`、`accounts{}`。证书私钥保存在该文件中。**管理接口** 23 个操作，权限域 `ssl:read` / `ssl:write`。

FerrumGate 已有 PEM 手动加载、精确与通配 SNI、IP 证书、ACME HTTP-01（DNS 名与 IP）、Cloudflare DNS-01（CNAME 委托、SOA 区域发现）、EAB、证书 profile、账户复用、续期、在线换证与本地目录部署（`crates/fg-gateway/src/{tls,acme,dns01,cert_deploy}.rs`）。差距集中在：多证书条目的列表管理、多种来源、多个部署目标、更多 DNS 提供商、与 Web 服务共用 80 端口。

### WP-31 证书条目模型与多种来源

- **上游依据**：`internal/modules/ssl/config.go`（`Cert`、`Settings`、`Account`）、`module.go`（加载、证书表与 SNI 提供者）、`network.go`、`fnos.go`、`internal/modules/registry/registry.go`（`wiring.certs`）；文档 `docs/modules/ssl`「能力」「飞牛系统证书」。
- **行为契约**：
  - `certs[]` 每项：`key`、`remark`、`group`、`enable`、`source`（`acme` / `upload` / `file` / `fnos`）、`acme`（见 WP-32）、`certFile` / `keyFile`（文件来源，定期重新读取）、`fnosDomain`、`certPem` / `keyPem` / `issuerPem`、`mapping`、`deploys[]`、`updatedAt`、`issuedProfile`。
  - 多张证书覆盖同一域名时，使用到期时间最晚的一张；列表的排序与分组只影响展示。
  - `settings`：`enable`（自动续签开关，关闭后不再自动签发，已有证书仍可使用）、`renewBeforeDays`（默认 30）、`shortLivedRenewHours`（短期证书默认 24，上限 80）、`defaultEmail`。
  - 通过 IP 访问 HTTPS 且无 SNI 时按连接的本机地址选择 IP 证书，本机地址不是证书中的公网 IP 时使用到期时间最晚的 IP 证书（FerrumGate 已实现）。
- **Rust 设计**：现有 `acme.rs` 的 `Managed` 状态迁到 `fg-certs` crate，持久化为 `ssl.json`。证书解析与 SNI 选择沿用 `tls.rs`，入口改为「按域名查询当前有效证书」的提供者接口 `CertProvider`，经 `Wiring.certs` 交给 Web 服务与管理界面 HTTPS。文件来源用定时重新读取 + 内容指纹比较。
- **验收**：多证书重叠时的选择；四种来源的加载与轮换；续签开关关闭后不再签发；`fgate check` 不输出私钥。

### WP-32 ACME 签发与续期对齐

- **上游依据**：`internal/modules/ssl/acme.go`、`internal/acmehttp/`、`internal/dnsprovider/txt.go`、`internal/resolver/`；文档 `docs/modules/ssl`「DNS-01 验证」「签发网络」「HTTP-01 验证」「短期证书与 IP 地址证书」。
- **行为契约**：
  - `ACMEConfig`：`domains[]`、`email`、`ca`（预置名称或 `custom`）、`directoryUrl`、`eabKid` / `eabHmac`、`keyType`、`profile`、`challenge`（`dns` 默认，支持通配符；`http`）、`httpPort`（默认 80）、`provider` 与 `credentials`、`zone`（留空自动推断）、`resolvers[]`、`propagationTimeout`（默认 300 秒）、`skipPropagationCheck`、`disableAuthoritativeCheck`、`disableCname`、`network`（空 / `tcp4` / `tcp6`，作用于 ACME 接口、DNS 服务商接口与 TXT 生效检查）。
  - 账户按（目录 URL、邮箱）复用，`accounts{}` 保存邮箱、目录地址、账户私钥与注册信息。
  - DNS-01：区域留空时用 SOA 查询找出权威区域（含多级后缀）；`_acme-challenge` 的 CNAME 默认跟随，来自泛解析记录的 CNAME 自动识别并不跟随。
  - HTTP-01：Web 服务已在 80 端口监听时由它直接应答，不影响现有站点；80 端口空闲时在签发期间临时监听，完成后立即关闭；可指定临时监听端口。
  - 短期证书：`profile` 为 `shortlived` 时约 6 天有效，按 `shortLivedRenewHours` 续签，失败后每小时重试一次；配置在默认与短期之间切换后立即按新配置重新签发（FerrumGate 已实现 profile 变更重签）。
  - IP 地址证书：IP 与域名可写在同一张证书里，要求公共 CA 下使用短期 profile 与 HTTP-01。
- **与现状的差异**：现有实现只支持 Cloudflare DNS-01、单一 ACME 配置、独立挑战监听器；续期与订单状态机的其余语义已基本一致。未完成订单恢复仍待补齐（见 `docs/DESIGN.md` 的遗留项）。
- **Rust 设计**：沿用现有实现（`acme.rs` 基于 `instant-acme` crate），补充多订单并发与未完成订单恢复；DNS 提供商接口见 WP-41；HTTP-01 应答改为向 `Wiring.web` 注册挑战路径的回调，Web 服务未在 80 端口监听时回退到临时监听器。
- **验收**：本地测试 CA（现有 `tests/gateway/acme.rs` 的做法）覆盖 HTTP-01 与 DNS-01、EAB、通配、IP、短期 profile、续期失败重试、账户复用、80 端口被 Web 服务占用时的应答。

### WP-33 证书映射与自动部署

- **上游依据**：`internal/modules/ssl/deploy.go`（部署目标与执行）与 `module.go` 中的证书映射；文档 `docs/modules/ssl`「证书映射」「自动部署」。
- **行为契约**：
  - 映射 `mapping`：`enable`、`dir`、`script`。启用后把 `.crt`、`.key`、`.pem` 与 `_issuerCertificate.crt` 写入目录，内容变化后执行脚本。
  - 自动部署 `deploys[]`：`enable`、`type`（`local` / `ssh` / `docker`）、`remark`、`connection`（Web 终端中的 SSH 连接 key）、`dir`（绝对路径）、`certName` / `keyName`（都填写后只写这两个文件）、`command`（可用 `$certName`、`$certDir`、`$certFile`、`$keyFile`）、`containers[]`、`deployedHash`、`deployedAt`。
  - 本机目录：目录中的证书文件被删除或改动后，下一次检查会重新复制；在本机执行命令。SSH：复用 Web 终端连接的地址、认证与代理，文件先写临时文件并设好权限再改名替换，私钥 0600，然后执行远程命令。Docker：依次重启所选容器。
  - SSH 连接需要先在 Web 终端中连接一次并记录主机密钥，否则不推送。部署失败每小时重试一次并发出 `ssl.deploy_failed`；「立即部署」忽略重试间隔并显示每个目标的结果。目标设置没有变化的部署不重复执行。
- **Rust 设计**：沿用现有 `cert_deploy.rs` 的原子部署思路，扩展为部署目标列表与执行器枚举。命令执行用 `tokio::process::Command` 直接执行（经 `sh -c` 时仅用于展开用户填写的命令字符串，不拼接任何其他内容），环境变量传入 `$certFile` 等值。SSH 推送与容器重启通过 `Wiring` 取得，对应模块未编译时返回明确的错误。
- **验收**：映射目录的文件名与脚本执行；三种部署类型的成功、失败、重试与「立即部署」；哈希不变不重复部署；SSH 主机未信任时拒绝。

### 8.3 端口转发（portforward，核心模块）与协议分流（protoroute）

**配置文件**：`portforward.json` 与 `protoroute.json`，顶层均为 `settings` 与 `rules[]`。**管理接口** 各 16 个操作，权限域 `portforward` 与 `protoroute`。

FerrumGate 已有：TCP/UDP 转发、端口列表与范围、TCP 顺序目标切换、半关闭、首次数据超时、每源并发配额、出站 PROXY v1/v2、UDP 多目标轮询与会话建立时故障切换、来源 IP/CIDR 规则热重载、转发指标（`crates/fg-gateway/src/{tcp_forward,udp_forward,forward_ports,source_policy,source_quota,forward_metrics}.rs`）。

### WP-34 端口转发对齐

- **上游依据**：`internal/modules/portforward/{config,forwarder,module}.go`、`internal/l4proxy/`、`internal/netpipe/`、`internal/iplist/`；文档 `docs/modules/portforward`。
- **行为契约**：
  - 规则 `Rule`：`key`、`name`、`enable`、`group`、`protocols[]`（`tcp` / `udp`）、`listenAddress`、`listenPorts`（`443`、`443,8443` 或端口段）、`autoFirewall`、`targetAddresses[]`、`targetPorts`、`maxConnections`（每个 TCP 端口，0 取全局默认 256）、`maxConnsPerSource`（单个来源：IPv4 地址、IPv6 /64；0 取全局默认，即最大连接数的一半；回环与内网来源不受限）、`udpSessionTimeout`、`proxyProtocol`（`v1` / `v2`，只作用于 TCP）、来源访问控制（见 WP-36）、`remark`。
  - 设置 `Settings`：`enable`、`defaultMaxConnections`、`defaultMaxConnsPerSource`、`perSourceExempt[]`（不受单来源上限约束的来源）、`defaultUDPSessionTimeout`、`maxUDPSessions`、`dialTimeout`、`firstDataTimeout`（默认 60 秒，最长 3600 秒）。
  - 多目标为**顺序故障转移**（多个地址依次尝试），不是负载均衡。IPv4 与 IPv6 之间可互相转发。
  - 超过单来源上限时新连接直接断开，运行日志每 10 秒最多记录一条。规则卡片显示启动以来的拒绝次数（TCP 按连接、UDP 按数据包）。
  - 分组与排序只影响列表显示，修改后不重启转发，已建立的连接不受影响。
  - 指标（文档 `docs/reference/monitoring`）：`gately_portforward_*` 系列；FerrumGate 前缀见决策 D12。
- **与现状的差异**：现有每规则 8 个目标、64 个监听器、UDP 进程总预算 4096 会话等上限是 FerrumGate 自己的取值，需与上游默认值逐项对照后在接口文档中写明；来源规则需要增加订阅列表与优先拒绝名单；缺少自动放行防火墙与「需要敲门」。
- **Rust 设计**：现有实现迁到新 crate `fg-l4::portforward`，配置从 `[[tcp_forward]]` / `[[udp_forward]]` 改为 `rules[]`。来源配额默认值改为「最大连接数的一半」的推导规则。规则与监听的生效动作接到 WP-05 的 `ApplyHold`。
- **验收**：现有 `tests/gateway/{tcp,udp,metrics}.rs` 的场景在新配置模型下全部保留并通过；单来源上限的默认推导与豁免；拒绝计数；分组排序不中断转发。

### WP-35 协议分流

- **上游依据**：`internal/modules/protoroute/`（`config.go`、`sniff.go`、`router.go`、`module.go` 等 11 个非测试文件，约 2700 行）；文档 `docs/modules/protoroute`、`docs/tutorials/one-port-443`。
- **行为契约**：
  - 只处理 TCP。规则 `Rule`：监听（`protocols`、`listenAddress`、`listenPorts`）、`routes[]`、默认目标（`targetAddresses[]`、`targetPorts`、`proxyProtocol`；地址留空表示直接断开）、`sniffTimeout`（0 为默认 5 秒，最短 0.1，最长 60）、`maxConnections`、`maxConnsPerSource`、来源访问控制、`autoFirewall`。
  - 路由 `Route`：`name`、`disabled`、`protocol`、`domains[]`（仅 TLS 的 SNI 与 HTTP 的 Host）、`alpn[]`（仅 TLS）、`targetAddresses[]`（依次尝试，带故障转移）、`targetPort`（0 表示与监听端口相同）、`proxyProtocol`、`knock`。
  - 协议识别器与依据：TLS（ClientHello，可拆成多个记录，最大 64 KB）、HTTP（方法名与版本号，含 CONNECT、WebDAV 与 h2c；最多读取 32 KB 请求头查找 Host）、SSH（`SSH-`）、RDP（TPKT 头与 X.224 连接请求）、SOCKS4/4a/5、OpenVPN（客户端硬重置包）、XMPP、MQTT（3.1/3.1.1/5.0）、PostgreSQL（启动消息、SSLRequest、GSSENCRequest）、Minecraft（握手包中的服务器地址）、RTSP、SIP、Redis（RESP 数组）、AMQP、SMB（NetBIOS 会话中的协商请求）、Git（`git://` 首个 pkt-line）、IRC、ADB（CNXN）、BitTorrent（未加密握手）、`timeout`（等待超时）、`spa`（经 TCP 接收敲门包）。请求行最长 8 KB。
  - 匹配优先级：精确域名 → 最长的通配（匹配任意级子域名）→ `*` → 未填写域名的路由（匹配该协议全部连接，含没有 SNI 或 Host 的）；不区分大小写，国际化域名转 punycode；带端口、路径或 `@` 的写法被拒绝。TLS 路由的 ALPN 更具体者优先，不匹配时继续按更宽泛的域名查找。同一协议下同一域名（及 ALPN）只能属于一条路由，其他协议每种只能有一条；「等待超时」每个端口只能有一条。
  - 交给默认目标的连接：没有匹配的路由、数据不属于任何可识别协议、ClientHello 无法解析、没有「等待超时」路由时客户端一直不发数据。没有默认目标时断开并计入「已断开」。
  - 每个连接只识别一次。停用的路由不参与匹配与冲突检查。修改路由、默认目标与识别超时后立即生效，监听不中断；协议、域名与 ALPN 不变的路由保留命中次数。
- **Rust 设计**：新 crate 模块 `fg-l4::protoroute`。协议识别为纯函数 `classify(&[u8]) -> Option<Protocol>` 加 TLS/HTTP 的增量解析状态机（数据未到齐时继续等待，直到 `sniffTimeout`），可脱离网络做表驱动测试。SNI/ALPN 解析自研（只读 ClientHello 明文部分）。连接转发复用端口转发的双向复制。路由表编译为按协议分组的匹配器。
- **验收**：每种协议一组真实握手字节的识别用例（优先取自上游 `sniff_test.go`）；拆分的 ClientHello；匹配优先级与冲突校验；超时路由与默认目标；PROXY 协议按路由发送；来源规则与敲门在识别之前判断；热更新不中断。

### WP-36 L4 共用基础：来源规则、连接登记与管道

- **上游依据**：`internal/iplist/`（`iplist.go`、`rule.go`、`access.go`）、`internal/l4proxy/`（`ports.go`、`server.go`、`target.go`）、`internal/netpipe/`（`netpipe.go`、`firstdata.go`、`readable_*.go`、`splice_linux.go`）。
- **行为契约**：来源访问控制（`iplist.Access`）由手填的 IP / 网段与引用的订阅列表组成；白名单 / 黑名单模式，另有优先拒绝名单；封禁表中的地址无论何种模式都被拒绝，入侵防护的封禁优先于名单；判断在连接目标之前进行，TCP 不满足的连接直接关闭，UDP 按数据包判断，名单变化后已有会话也立即按新名单处理；修改名单不中断监听。端口写法支持单个、逗号列表与范围。
- **Rust 设计**：`fg-net::source_policy`（现有 `source_policy.rs` 泛化）、`fg-net::ports`（现有 `forward_ports.rs`）、`fg-l4::pipe`（现有 TCP 双向复制、半关闭与首次数据超时）。订阅列表的数据来自 Web 服务模块的 `iplists`，经 `Wiring` 提供只读句柄；Web 服务未编译时（它总是编译的，核心模块）不存在该情况。
- **验收**：名单各模式的判定顺序；名单热更新对已有 UDP 会话生效；范围展开与重复端口；现有 TCP/UDP 测试在新结构下通过。

### WP-37 自动放行防火墙

- **上游依据**：`internal/fwopen/`（`fwopen.go`、`backend.go`、`chain.go`、`group.go`、`listen.go`）；文档 `docs/modules/web`「自动放行防火墙」。
- **行为契约**：
  - 只放行监听成功的端口，连续端口合并为一条规则；按监听的网络放行 IPv4 / IPv6；绑定具体地址时只放行发往该地址的连接；只监听回环地址时不放行；开启 HTTP/3 时同时放行同号 UDP 端口。监听停用、删除、启动失败或关闭开关时撤销，进程退出时一并移除。
  - nftables（OpenWrt fw4、firewalld 等）在 input 过滤链最前面插入规则；iptables / ip6tables 在 `INPUT` 链最前面插入；规则带 `gately-open:` 注释，防火墙重新加载后 30 秒内补回。
  - 内核没有 nf_tables 时改用 legacy iptables：规则写在专用链（`GTLY_OPEN_` 前缀）中，`INPUT` 的第一条规则跳到这条链，被系统防火墙挤到后面时 30 秒内挪回。
  - 只支持 Linux；容器部署需要 host 网络与 `NET_ADMIN`。Web 服务、端口转发、协议分流与 STUN 共用。
- **Rust 设计**：`fg-net::fwopen`（Linux 条件编译）。上游通过执行 `nft` / `iptables` / `ip6tables` 可执行文件下发规则，FerrumGate 采用相同方式：`tokio::process::Command` 加参数数组或标准输入脚本，不经过 shell，不拼接任何外部输入（端口与地址先经解析器校验）。`Group` 把各模块登记的端口需求合并为一个工作线程的增删操作。非 Linux 平台编译为返回「不支持」的空实现。
- **验收**：用假的 `nft` / `iptables` 可执行文件记录收到的参数，验证规则合并、注释标记、撤销与 30 秒补回；监听失败时不放行；回环不放行。真实防火墙行为在 Linux + `NET_ADMIN` 环境单独记录。

### 8.4 配置迁移入口

### WP-38 导入 Gately 配置目录

- **目标**：让现有 Gately 用户把配置目录直接迁移到 FerrumGate。
- **上游依据**：各模块的 `fileConfig` 结构；文档 `docs/guide/migration`。
- **行为契约**：读取另一个 Gately 实例的配置目录，逐个模块校验并转换；无法转换的字段在报告中列出原因与建议；`account.json` 与 `tokens.json` 的处理方式需明确（建议默认不导入，账号重新初始化）；导入后先 `fgate check` 再启动。
- **Rust 设计**：`fgate import gately --dir <目录>`。由于 FerrumGate 的 JSON 模型与上游同名同构（决策 D1），多数模块只需反序列化后再校验；差异集中在 FerrumGate 自有的上限与未实现模块。
- **验收**：用上游各模块的测试样例配置做往返测试；不支持项全部出现在报告中；导入过程不写入来源目录。

### WP-39 迁移现有 TOML 配置

- **目标**：把 `schema_version = 1` 的 `ferrumgate.toml` 转换为配置目录，并移除旧的 TOML 加载路径。
- **行为契约**：`[[routes]]` → `webservice.json` 的一个监听器与若干站点（`host` + `path_prefix` 合并为站点与 `locations`；`response` 转为 `redirect` / `text` / `static` 类型）；`[[certificates]]` → `ssl.json` 的 `upload` 来源条目；`[acme]` → `acme` 来源条目；`[[tcp_forward]]` / `[[udp_forward]]` → `portforward.json` 的 `rules[]`；`server.*` 的超时映射到监听器或后端超时，连接上限与指标监听在报告中提示需手工设置。
- **Rust 设计**：`fgate migrate --config ferrumgate.toml --dir <配置目录>`，只写目标目录，不修改来源文件；现有测试辅助 `tests/gateway/common.rs` 同步改为生成配置目录。
- **验收**：样例配置 `ferrumgate.example.toml` 的转换结果通过 `fgate check`；现有全部集成测试在转换后的配置上通过；迁移报告列出无法自动映射的字段。

## 9. 阶段 P2：网络自动化（DDNS、STUN、隧道与托管程序）

本阶段的模块都不在 FerrumGate 现有范围内，全部为新建。共同点：每个模块都有「规则/实例列表 + 全局设置 + 运行日志 + 自检 + 指标」的固定形态，并共享事件总线、来源规则、防火墙放行与日志能力。

### WP-40 动态域名任务

- **上游依据**：`internal/modules/ddns/{config,runner,remote,layout,module,selfcheck,metrics}.go`、`internal/ipsource/`、`internal/webhook/`；文档 `docs/modules/ddns`、`docs/tutorials/ddns-basics`、`docs/tutorials/wildcard-cert-ddns`。
- **行为契约**：
  - 配置 `ddns.json`：`settings`（`enable`、`deleteRemote`）与 `tasks[]`。任务 `Task`：`key`、`name`、`enable`、`group`、`ipv4` / `ipv6`（各一个 `ipsource.Source`）、`provider`、`credentials`（`id`、`secret`、`extra{}`）、`records[]`、`interval`（检查周期，秒）、`forceInterval`（强制同步周期，0 表示只在 IP 变化时同步）、`httpTimeout`、`webhook`、`remark`。管理接口 25 个操作。
  - IP 来源 `Source`：`enable`、`type`（`url` / 网卡 / `command`）、`urls[]`（按顺序尝试直到成功）、`interface`、`regex`（多个候选地址的筛选）、`command`（经 `sh -c` 执行，从输出中提取 IP）。支持 IPv4 与 IPv6。
  - 解析记录 `Record`：`zone`（主域名）、`sub`（主机记录，根域名填 `@`）、`type`、`value`、`ttl`（0 使用服务商默认值）、`line`（解析线路，仅部分国内服务商）、`remark`、`group`。
  - 记录值变量：`{ipv4Addr}`、`{ipv6Addr}`（A / AAAA 留空时的默认值）；`{STUN_规则名_PORT}`、`{STUN_规则名_IP}`、`{STUN_规则名_ADDR}`。STUN 规则地址变化后引用它的任务立即同步；规则未启用或尚未穿透成功时该记录本轮跳过并显示原因。
  - 自定义回调可用变量：`{ip}`、`{domain}`、`{subDomain}`、`{zone}`、`{recordType}`、`{ttl}`（为 0 时取 600）、`{timestamp}`；地址中的变量值做 URL 编码。
  - Cloudflare 代理状态可作为附加字段填写，留空不改动已有记录；开启代理的记录 TTL 固定为 1。
  - 备注：同步时写到支持备注的服务商（阿里云、Cloudflare、腾讯云、DNSPod、华为云），超过 100 个字符的部分不写入，阿里云最多 50 个字符；只修改备注也会触发一次同步。
  - 删除：「同时从 DNS 服务商删除解析」只删除由 Gately 同步的那一条（同名、同类型、同线路且值与最近一次同步结果相同）；尚未同步过、服务商处的值不一致、按记录集管理的服务商记录集里还有其他值时不删除并提示；DuckDNS、Namecheap、DynDNS2 与自定义回调不提供删除接口。先删服务商、全部成功才删本地配置。
  - 主机记录保存为小写并以小写发给服务商；A / AAAA 记录值按地址比较，服务商返回展开写法或大写 IPv6 不算变化。从配置文件加载时校验失败的任务不启动（避免缺字段的任务以零值运行）。公网 IP 查询地址不依赖任何项目方服务。
- **Rust 设计**：新 crate `fg-ddns`。调度为每任务一个 Tokio 任务（`interval` 加随机抖动），失败退避；状态机 `Unknown / Unchanged / Updated / Failed`；提供商调用经 WP-41 的 `DnsProvider` trait。网卡地址用 `if-addrs` 或 `network-interface`（待核实）；命令来源用 `tokio::process::Command` 加超时与输出长度上限。STUN 变量通过 `Wiring` 注册的查询回调取值，并订阅 `stun.changed` 事件。
- **验收**：三种 IP 来源的解析与回退；地址比较的归一化；变量替换与 STUN 联动；备注同步；删除的四种「不删除」情形；加载校验失败不启动；自检（解析结果与当前地址一致）。

### WP-41 DNS 提供商适配

- **上游依据**：`internal/dnsprovider/`（`provider.go`、`simple.go`、`more.go`、`split.go`、`delete.go`、`txt.go` 与 25 个提供商文件；33 个测试文件）；文档 `docs/modules/ddns`「支持的服务商」。
- **行为契约**：
  - 接口极小：`Provider.Upsert(ctx, Record) (recordID, error)`；`Record` 含 `Zone`、`Sub`、`Type`、`Value`、`TTL`、`Line`、`Remark`。删除与 TXT 增删是可选能力。
  - 提供商元数据 `Meta`：`name`、`title`、`idLabel`、`secretLabel`、`extra[]`（附加字段及其输入类型）、`supportsLine`、`docUrl`、`supportsAcme`、`supportsRemark`、`supportsDelete`。
  - 全部 37 个提供商及能力（TXT = 可用于 ACME DNS 验证，DEL = 支持删除远端记录，LINE = 支持解析线路，REMARK = 支持写备注）：

| 提供商 `name` | 能力 | 提供商 `name` | 能力 |
|---|---|---|---|
| `alidns` 阿里云 DNS | LINE、REMARK | `namecheap` | — |
| `aliesa` 阿里云 ESA | TXT、DEL | `namecom` Name.com | TXT、DEL |
| `baiducloud` 百度智能云 | TXT、DEL | `namesilo` | TXT、DEL |
| `bunny` Bunny DNS | TXT | `nowcn` 时代互联 | TXT、DEL |
| `callback` 自定义回调 | — | `ns1` | TXT |
| `cloudflare` | REMARK | `ovh` OVHcloud | TXT |
| `cloudns` ClouDNS | TXT、DEL | `porkbun` | — |
| `desec` deSEC | TXT、DEL | `rainyun` 雨云 | TXT、DEL、LINE |
| `dnsla` DNS.LA | TXT、DEL | `route53` Amazon Route 53 | TXT |
| `dnspod` DNSPod 国内站 | LINE、REMARK | `spaceship` | TXT、DEL |
| `dnspodcom` DNSPod 国际站 | REMARK | `tencentcloud` 腾讯云 DNSPod | LINE、REMARK |
| `duckdns` DuckDNS | — | `tnethk` Tnet.hk | TXT、DEL |
| `dynadot` Dynadot | — | `trafficroute` 火山引擎 | LINE、TXT、DEL |
| `dyndns2` DynDNS2（No-IP、Dynu 等） | — | `vercel` | TXT、DEL |
| `dynv6` | — | `edgeone` 腾讯云 EdgeOne | LINE、TXT、DEL |
| `eranet` 新网互联 | TXT、DEL | `gandi` | TXT |
| `gcore` Gcore | TXT、DEL | `godaddy` GoDaddy | — |
| `hipmdnsmgr` HiPM DNSMgr | TXT、DEL | `huaweicloud` 华为云 DNS | REMARK |

  - 凭据 `Credentials{id, secret, extra}`：不同提供商把 access key、token 等放进 `id` / `secret`，其余（接入点、区域 ID、代理状态、回调地址、请求头与请求体等）放进 `extra`。只读身份读取时看不到 `extra` 中除接入点、请求方法以外的字段。
- **Rust 设计**：新 crate `fg-dns`。`trait DnsProvider { async fn upsert(&self, rec: &Record) -> Result<RecordId>; }` 加可选 trait `TxtRecords`、`Deleter`；每个提供商一个文件、一个 Cargo feature（`dns-<name>`），默认全开，定制构建可以只带需要的提供商。HTTP 客户端统一走 `fg-net::http`（遵循自定义 DNS 与更新代理）。请求契约以上游各文件的测试为准（用本地假服务器重放）。按实现难度分三批：
  1. **第一批**（Bearer 令牌或简单密钥 + REST）：`cloudflare`、`dnspod`、`tencentcloud`、`huaweicloud`、`alidns`、`duckdns`、`dynv6`、`callback`、`porkbun`。
  2. **第二批**（需要签名或两步查询）：`route53`（SigV4）、`aliesa`、`baiducloud`、`edgeone`、`trafficroute`、`dnsla`、`ovh`（三步签名）、`gandi`、`ns1`、`bunny`、`desec`、`gcore`、`cloudns`、`vercel`、`namecom`、`namesilo`、`spaceship`、`rainyun`、`nowcn`、`eranet`、`tnethk`、`hipmdnsmgr`、`godaddy`、`dnspodcom`。
  3. **第三批**（仅 DDNS，无 TXT 与删除）：`dynadot`、`namecheap`、`dyndns2`。
- **验收**：每个提供商至少一个「请求契约」测试（方法、路径、认证头、请求体、响应解析）与一个错误分类测试；`Meta` 的能力标记与 trait 实现的一致性由编译期保证；未启用的提供商在接口清单中不出现。

### WP-42 STUN 穿透

- **上游依据**：`internal/modules/stun/{config,engine_tcp,engine_udp,runner,module,metrics}.go`、`internal/stun/`（`stun.go` 客户端、`server.go` 测试用服务器）、`internal/stunaddr/`、`internal/upnp/`（`upnp.go`、`natpmp.go`）；文档 `docs/modules/stun`、`docs/tutorials/stun-traversal`、`docs/tutorials/remote-access-without-public-ip`。
- **行为契约**：
  - 配置 `stun.json`：`settings`（`enable`、`stunServers[]`、`keepAliveServers[]`、`webhook`、`addrCheckInterval`）与 `rules[]`。管理接口 18 个操作。
  - 规则 `Rule`：`protocol`（`tcp` / `udp`）、`bind`（`mode`、`ip`、`interface`、`regex`）、`localPort`（0 为随机）、`useGlobalServers`、`stunServers[]`、`keepAliveServers[]`（仅 TCP，端口缺省 80）、`disableForward`、`targetAddresses[]`、`targetPort`、UPnP（`upnp`、`upnpGateway`、`upnpLocalHost`、`upnpControlUrl`、`upnpInternalPort`）、NAT-PMP（`natpmp`、`natpmpGateway`）、`autoFirewall`、`heartbeatInterval` / `stunTimeout` / `retryInterval`（毫秒）、`autoRetry`、`disableCheck`（连接自身公网地址验证可达）、`useGlobalWebhook`、`webhook`、`webhookOnlyOnChange`、`scriptEnable`、`script`、`maxConnections`、`udpSessionTimeout`、来源访问控制、`remark`。
  - 能力：TCP / UDP 打洞与保活；UPnP / NAT-PMP 在路由器上创建端口映射；内置转发把公网端口转发到内网目标；公网地址或端口变化时触发 Webhook 与脚本（脚本以 `sh -c` 执行，变量经环境变量传入：`ruleName`、`time`、`ip`、`port`、`ipAddr`）。
  - 限制：CGNAT 下能否穿透取决于运营商那层 NAT 的类型，全锥型可以，端口受限或对称型不行；多层 NAT 下只保留通道端口的映射；部分路由器的锥形 NAT 只对 UDP 生效，TCP 规则需要开启 UPnP；主机开启防火墙时建议固定本地端口并放行。
  - 名单只作用于内置转发，STUN 查询与通道有效性检测不受影响；修改名单不会重新打洞，公网端口保持不变。规则卡片显示通道的公网地址、端口与检测结果。
- **Rust 设计**：新 crate `fg-stun`。STUN 客户端自研（RFC 5389 的 Binding Request/Response，解析 `XOR-MAPPED-ADDRESS`、`MAPPED-ADDRESS`、`OTHER-ADDRESS`；测试用上游 `server.go` 的行为为蓝本写一个 Rust 的假 STUN 服务器）；TCP 与 UDP 两个引擎共享一个「通道」状态机（`Binding → Mapped → Checking → Ready / Lost`）。UPnP 用 `igd` crate（待核实），NAT-PMP 自研（报文简单）。内置转发复用 WP-36 的管道。
- **验收**：假 STUN 服务器下的映射地址获取、超时与重试；保活；映射端口变化的检测与事件、Webhook、脚本；UPnP / NAT-PMP 的报文（假网关）；内置转发与来源规则；自检（CGNAT 判定）。

### WP-43 托管程序基础设施

- **上游依据**：`internal/binstall/`（`binstall.go`、`fetch.go`、`latest.go`、`routes.go`）、`internal/proc/proc.go`；文档 `docs/modules/tunnels`「在线安装、更新与回滚」「恢复默认配置」「程序放置」；README「Tailscale, NetBird, EasyTier, frp, cloudflared」。
- **行为契约**：
  - Gately 不打包这些程序。可执行文件按顺序查找：模块设置中填写的路径 → 配置目录下的 `bin/` → `PATH`。填写了路径时在线安装的版本不生效。
  - 在线安装：从上游下载最新正式版（或指定版本，可用于降级），按上游记录的 SHA-256 校验，确认能在本机运行后安装到配置目录的 `bin/`，完成后重启使用该程序的进程。已经是最新版时不重复下载。
  - 检查更新：只查询上游最新正式版；开启自动检查时每 12 小时检查一次已安装的程序，发现新版本发布 `program.update`。
  - 每个程序可单独设置下载代理（`http`、`https`、`socks5`），留空使用全局更新代理。
  - 被替换下来的版本保存在 `bin/.versions/`，最多保留 3 个，可一键回滚。卸载：删除 `bin/` 下的程序与全部旧版本，模块配置保留；之后使用该程序的进程重启，`PATH` 中有同名程序时改用它。
  - 恢复默认配置与卸载分开：停止该模块的全部进程，把设置恢复为默认值，删除 Gately 为它生成的文件，安装的程序保留；旧配置在配置历史中。接口 `DELETE /api/<模块>/install`、`POST /api/<模块>/reset`。
  - 来源：frp（GitHub `fatedier/frp`：`frpc`、`frps`）、cloudflared（GitHub）、Tailscale（`pkgs.tailscale.com` 静态包，仅 Linux：`tailscale`、`tailscaled`）、NetBird（GitHub，Linux / macOS / Windows）、EasyTier（GitHub，多架构）、FileBrowser Quantum（GitHub `gtsteffaniak/filebrowser`）。
  - 令牌与密钥以 0600 权限保存；cloudflared 的令牌通过环境变量传递，不出现在进程列表中。
- **Rust 设计**：新 crate `fg-proc`，两部分。`install`：解析各上游的发布元数据（GitHub Releases API 与 Tailscale 的静态包清单）、下载（经代理）、校验 SHA-256、解包（`tar` / `zip` / `zstd`，防路径穿越、限制条目数与解压后大小）、运行一次 `-version` 确认可执行、原子替换、保留与回滚版本。`supervise`：`ManagedProcess` 持有子进程、日志管道（接到 WP-09 的模块日志）、退出原因与重启退避；停止用信号加超时。每个程序一个「发布来源」描述（`ReleaseSource` trait 的真实多实现需求）。
- **验收**：假发布服务器下的下载、校验失败、解包安全、版本保留与回滚、已是最新版不下载；查找顺序；进程崩溃后的重启退避与日志汇聚；令牌不出现在命令行。

### WP-44 frp

- **上游依据**：`internal/modules/frp/{config,module,ports,access,importer,import_handler,install,selfcheck}.go`；文档 `docs/modules/tunnels`「frp」、`docs/tutorials/frp-tunnel`。
- **行为契约**：多个 frpc 与 frps 实例并存，各自独立启停；代理归属某个 frpc 实例，类型 `tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`，增删改后只重启所属实例；实例的「访问地址」用于生成可点击的链接，修改后不重启；frps 的端口白名单、子域名、控制台、KCP 与 QUIC 端口（`kcpBindPort`、`quicBindPort`，0 为不启用，两者不能相同）、QUIC 调节（保活间隔、空闲断开时间、最大并发流，默认 10 秒 / 30 秒 / 100000）；frps 自动放行防火墙；frps 的来源 IP 访问控制（在 frps 校验令牌之前判断，Gately 在本机回环地址开一个检查端点并在生成的 frps 配置中接入）；导入旧版 INI 与 0.52+ 的 TOML（预览被忽略的字段，追加或替换，新建实例默认停用）。管理接口 49 个操作。
- **Rust 设计**：`fg-frp`。配置生成器把结构体写成 frp 的 TOML（`toml` crate 的序列化 + 逐字段映射表），文件写入配置目录的 `frp/` 下并设 0600；INI 解析器自研（分节 + 键值 + 字符串），TOML 用 `toml` crate。进程由 WP-43 托管。检查端点是一个只监听回环的小型 HTTP 服务。
- **验收**：配置生成的快照测试；INI 与 TOML 导入样例；QUIC 参数校验；访问地址计算；只重启被修改的实例；来源规则在令牌校验之前生效。

### WP-45 Tailscale、NetBird 与 EasyTier

- **上游依据**：`internal/modules/{tailscale,netbird,easytier}/`（各自的 `config.go`、`module.go`、`install.go`，NetBird 另有 `external.go`）；文档 `docs/modules/tunnels`「Tailscale」「NetBird」「EasyTier」、`docs/tutorials/mesh-vpn`。
- **行为契约**：
  - 三个模块都支持多个实例，每个实例一个独立进程（状态目录、控制套接字、WireGuard 端口互不相同）；新实例的状态目录默认在配置目录下的 `<模块>/<实例 key>`，也可填写已有目录以沿用节点身份。修改、启停一个实例只重启它自己的进程。
  - 同时启用的内核模式实例（托管且未开启用户态网络）最多一个；保存、启用、批量启用与复制时检查冲突。
  - Tailscale：托管 tailscaled（用户态网络，容器友好）或接入系统已有的守护进程；认证密钥或登录链接，支持 Headscale；子网路由与出口节点；节点列表与 SOCKS5 代理（无认证，监听地址不限本机时提示）；固定 WireGuard UDP 端口；额外参数与环境变量。macOS 与 Windows 没有可直接运行的程序包，需用官方安装程序并填写路径。
  - NetBird：官方云或自建管理服务；设置密钥或登录链接（Linux 为设备码登录）；托管守护进程或接入系统服务；用户态网络下允许其他节点访问本机服务，本机经 SOCKS5 代理（默认 `127.0.0.1:1080`）访问组网；路由、出口节点与访问策略在管理端配置，本模块选择是否接受路由、是否作为路由节点、是否接受 DNS、拒绝入站；节点列表显示直连或中继与延迟；启动前检查系统里已有的内核模式实例。
  - EasyTier：网络密钥经环境变量 `ET_NETWORK_SECRET` 传入，不出现在命令行，日志打码，只读身份只看到脱敏值；节点地址与监听地址（`协议://地址:端口`）；虚拟 IP 自动或固定；TUN 网卡（需要 root 与 `/dev/net/tun`）或用户态网络；端口转发、子网代理（`192.168.1.0/24->10.1.0.0/24`）、出口节点、延迟优先、KCP / QUIC 代理；管理端口在 `127.0.0.1` 上随机分配，状态经 `easytier-cli` 读取；冲突检查（监听端口、转发端口、网卡名、实例名称）。
  - 管理接口：Tailscale 28 个、NetBird 28 个、EasyTier 27 个操作。
- **Rust 设计**：三个 crate `fg-tailscale`、`fg-netbird`、`fg-easytier`（或一个带三个 feature 的 `fg-mesh`，按编译裁剪需要决定）。公共部分（实例生命周期、状态目录、冲突检查、节点列表轮询）放在 `fg-proc::instance`。状态查询通过执行官方 CLI（如 `tailscale --socket=<路径> status --json`）取得，解析其 JSON 输出。
- **验收**：每模块的配置校验与冲突检查；命令行与环境的生成快照（密钥不在命令行中）；用假的 CLI 可执行文件测试状态解析；恢复默认配置删除的范围。

### WP-46 Cloudflare Tunnel

- **上游依据**：`internal/modules/cloudflared/{module,ingress,install}.go`；文档 `docs/modules/tunnels`「Cloudflare 隧道」「路由规则」。
- **行为契约**：令牌隧道与 trycloudflare 临时隧道；多隧道、自动重启；展示公网地址。填写可选的 API 令牌后可编辑令牌隧道的路由规则：令牌需要「Cloudflare Tunnel：编辑」权限，自动创建 DNS 记录还需要「DNS：编辑」权限；账号与隧道 ID 从隧道令牌中解析；每条规则含主机名、可选的路径正则与服务（`http://localhost:8080`、`ssh://localhost:22`、`http_status:404`），按顺序匹配，未命中用兜底服务；保存后立即生效，规则在此期间被他人修改时提示并要求重新加载；「同步 DNS」为每个主机名创建开启代理、指向 `<隧道ID>.cfargotunnel.com` 的 CNAME 记录。管理接口 27 个操作。
- **Rust 设计**：`fg-cloudflared`。隧道令牌的解析（Base64 的 JSON 配置）与 Cloudflare API 调用自研；ingress 规则校验（HTTP 类服务不能带路径）。
- **验收**：令牌解析；ingress 规则的校验与排序；假 Cloudflare API 下的读取、保存与冲突提示；DNS 同步的「保持原样」情形；进程托管与重启。

## 10. 阶段 P3：安全（入侵防护、端口敲门、WAF、OIDC 单点登录）

本阶段全部为新建模块，彼此之间以及与 Web 服务、端口转发、协议分流、STUN 之间有较多联动。入侵防护与端口敲门的防火墙部分是整个项目中除 WAF 外风险最高的内容：它们直接改写系统防火墙，必须在独立的 Linux 环境里验证。

### 10.1 入侵防护（guard）

**配置文件** `guard.json`：`settings` 与 `jails[]`。封禁表单独持久化。**管理接口** 23 个操作，权限域 `guard`。上游非测试代码约 6200 行，其中防火墙相关约 2500 行。

### WP-50 统一封禁表

- **上游依据**：`internal/banlist/{banlist,evict}.go`、`internal/modules/guard/{guard,routes,trust}.go`；文档 `docs/modules/guard`「能力」「Web 路径探测」「封禁范围」「与 Web 服务的关系」。
- **行为契约**：
  - `settings`：`firewall`（同步到 nftables）、`banSeconds`（默认封禁时长）、`increment`（同一地址 30 天内再次被封禁时时长翻倍，直到 `maxBanSeconds`）、`maxBanSeconds`、`ignorePrivate`（内网、回环与链路本地地址不被自动封禁）、`ignoreList[]`（白名单 IP 或网段）、`trap`（诱饵端口）、`scan`（扫描检测）。
  - 白名单默认忽略内网、回环、`100.64.0.0/10` 与本机网卡所在的 IPv6 /64 网段；白名单中的单个 IPv6 地址保护它所在的整个 /64。封禁按 /64 进行。
  - 统一封禁表：手动封禁（支持 CIDR 与永久封禁）、Web 服务认证失败的自动封禁、各规则产生的封禁都在这里管理；手动封禁不能包含回环地址；封禁持久化，重启后恢复。
  - 总量上限 32768 条：满了以后新的自动封禁先淘汰已到期的，再淘汰最早的临时自动封禁；永久封禁与手动封禁不会被淘汰。
  - 登录免封：管理后台登录成功的地址 24 小时内免于诱饵端口与端口扫描两类封禁（IPv6 按 /64）；其他自动封禁与手动封禁照常生效。
  - 封禁对全部监听、站点与 Gately 的其他服务生效；Web 服务模块单独运行时由它自己维护这张表（见 WP-26）。
  - 被封禁来源的敲门报文直接丢弃。
- **Rust 设计**：新 crate `fg-guard`，封禁表放在 `fg-net::banlist`（用 `ipnet` 的前缀类型存储，小集合线性匹配，条目多时用自研前缀树；`ip_network_table` crate 自 2021 年未更新，不采用），带文件持久化（延迟保存，合并短时间内的多次变化）。淘汰策略与递增计时写成纯函数便于测试。
- **验收**：三种来源的封禁写入同一张表；上限与淘汰顺序；递增时长；白名单与内网忽略；IPv6 /64 聚合；重启恢复；登录免封的时间窗。

### WP-51 防火墙同步

- **上游依据**：`internal/modules/guard/{firewall,firewall_ipt,origdst_linux}.go`、`internal/modules/knock/{firewall,firewall_ipt,firewall_nft}.go`；文档 `docs/modules/guard`「生效范围」「防火墙规则」、`docs/modules/knock`「防火墙拦截」。
- **行为契约**：
  - 生效范围：Linux（root 或 `CAP_NET_ADMIN`，已安装 nftables）与 Docker（host 网络 + `NET_ADMIN`）在内核层丢弃被封禁地址的全部流量，包括 SSH、其他程序与转发给容器或内网设备的流量；内核没有 nf_tables 的 Linux 改用 iptables（legacy）的 mangle 表与 ipset；其他情况只对 Gately 自身的服务生效。
  - 入侵防护在 nftables 中创建独立的 `inet gately` 表，不改动系统已有规则：`prerouting` 链（优先级 -190）丢弃被封禁地址发来的数据包，本机主动发起的连接的回包照常放行；`redir` 链（nat，优先级 -90）只看发往本机的 TCP 新连接，把诱饵端口的连接以及 10 分钟内连接未开放端口超过阈值的可疑来源重定向到 Gately 在随机端口上的监听，**完成握手才计入封禁**（不凭 SYN 封禁，源地址可以伪造）；集合与 meter 每个最多 65536 条。关闭同步或停止时整张表被删除；表被其他程序清除后 10 秒内自动重写。
  - 端口敲门在 nftables 中创建独立的 `inet gately_knock` 表：`prerouting` 链（优先级 -160）把发往受保护端口的包交给 `gate` 链，依次放行目标不是本机的流量、回环接口、已建立的连接、TCP 中非发起连接的包、免敲门网段与放行集合中的地址 + 协议 + 端口，其余丢弃。
  - 内核不支持重定向时（nftables 需要 Linux 5.2 及以上的 inet 族 nat）不写重定向规则并提示：诱饵端口改由 Gately 直接监听（最多 64 个），端口扫描检测不可用。
- **Rust 设计**：`fg-net::nftables` 与 `fg-net::iptables`（Linux 条件编译）。两种实现路径：直接执行 `nft` / `iptables` / `ipset` 可执行文件（与上游自动放行防火墙的做法一致，参数数组或标准输入脚本，不经 shell），或经 netlink（候选 `rustables` / `mnl`，待核实）。建议先用可执行文件方式完成首个版本并用假的 `nft` 记录规则做测试，再评估是否需要 netlink。规则的声明写成结构体，渲染为 nft 脚本的函数单独测试，输出与上游「查看规则」看到的脚本逐条对照。
- **验收**：渲染出的 nft 脚本与 iptables 命令的快照；表被清除后的重写；停止时删除；权限不足时的降级路径；在 Linux 网络命名空间（`ip netns`）中的真实规则验证单独记录。

### WP-52 日志规则与事件来源

- **上游依据**：`internal/modules/guard/{jail,presets,tail,tail_linux,webprobe,handshake,login,ports}.go`；文档 `docs/modules/guard`「日志规则」「Web 路径探测」「TLS 握手失败」。
- **行为契约**：
  - 规则来源：日志文件（从文件末尾开始读取新增内容，轮转后自动切换）、systemd 日志（`journalctl -f <unit>`）、命令输出（如 `logread -f`，命令退出后自动重启）、Docker 容器日志（经 Docker 模块）、Gately 事件（管理后台登录失败、WAF 拦截、端口敲门被拒绝、文件服务登录失败；事件自带来源 IP）、Web 路径探测、TLS 握手失败。
  - 过滤规则为正则表达式，每行一条，用 `<HOST>` 表示来源地址；「排除规则」中匹配的行不计数；统计窗口、失败次数与封禁时长可按规则设置（默认、自定义或永久）。内置模板：SSH、Dropbear、Nginx、Vaultwarden、Home Assistant、Proxmox VE 等；「文件服务登录失败」默认 10 分钟内 10 次即封禁，同一来源每 5 秒最多计一次。
  - Web 路径探测直接统计 Web 服务处理的请求：监听（可留空表示全部）、路径规则（`*` 通配或 `~` 开头的正则，不区分大小写，按规范化后的路径匹配）、排除路径；默认只统计 404 与 444，「任意状态码」需搭配路径规则或「只统计未知域名」；内置三个模板（Web 诱饵路径、未知域名扫描、Web 404 探测）。来源地址与访问日志一致（经 PROXY 协议与可信代理还原）。站点开启「信任已登录用户」或「信任后端认证标记」后，相应请求不计入。
  - TLS 握手失败：按失败类型（握手中途断开、连接被重置、握手超时、非 TLS 或协议错误、无法协商参数、未知域名、客户端中止、其他）计数，每次握手失败都计数；来源属于可信代理（CDN 回源节点）时不计数；内置两个模板（TLS 异常握手、TLS 握手中断）。
- **Rust 设计**：`fg-guard::jail`：每个 jail 一个任务，按来源类型读取行 → 正则匹配提取 `<HOST>` → 窗口计数 → 达到阈值调用封禁表。正则用 `regex` crate（RE2 语法，与上游一致）。文件跟踪需要处理轮转（比较 inode 或按名重开）；systemd 日志与命令来源用 `tokio::process::Command` 读取标准输出。Web 路径探测与 TLS 握手失败由 Web 服务通过 `Wiring` 的回调上报（无日志开销的上报接口）。
- **验收**：四种日志来源（含轮转）；`<HOST>` 提取；窗口计数与封禁；排除规则；三个 Web 模板与两个 TLS 模板；可信代理来源不计入。

### WP-53 诱饵端口、端口扫描检测与 IPv6 严格模式

- **上游依据**：`internal/modules/guard/{trap,ports,trust}.go`、`internal/openports/`；文档 `docs/modules/guard`「端口扫描检测的取舍」「IPv6 严格模式」。
- **行为契约**：
  - 诱饵端口 `trap`：`ports`（逗号或换行分隔，支持范围，默认 23、135、1433、3389、5900、6379 等）、`banSeconds`。在本机没有使用的端口上设诱饵，连接完成 TCP 握手即封禁；正在被监听的端口自动排除。
  - 端口扫描检测 `scan`：`threshold`（每分钟允许的未开放端口连接次数，默认 12，不建议低于 10）、`excludePorts`、`banSeconds`、`ipv6Strict`。正在监听的 TCP 端口视为开放：Gately 自身模块的端口在监听成功后立即登记、300 毫秒内生效，其他程序的监听端口每 10 秒自动刷新一次。自动登记的开放端口包括 Web 服务监听、端口转发、协议分流、SMB、WebDAV、FTP 控制与被动端口范围、STUN 的 TCP 端口、frps 的相关端口与 frpc 登录后申请的远程端口。已登录 frps 的 frpc 在登录后 10 分钟内不参与诱饵端口与扫描检测。
  - IPv6 严格模式：IPv6 来源只能连接开放端口，第一次连接其他端口即被封禁，不再按阈值计数；端口停止监听后 10 分钟内仍视为开放；需要防火墙同步并先启用端口扫描检测。
- **Rust 设计**：`fg-guard::trap` 与 `fg-net::openports`（各模块登记开放端口的进程内注册表；读取系统监听端口用 `/proc/net/tcp*` 与 `/proc/tcp6` 的解析，待核实）。用户态诱饵监听与内核重定向两条路径共用同一个「握手完成即封禁」的处理。
- **验收**：开放端口登记的时效（300 毫秒与 10 秒）；阈值的窗口计数；严格模式的首次即封禁与 10 分钟宽限；诱饵端口排除；frpc 豁免。

### 10.2 端口敲门（knock）

**配置文件** `knock.json`：`settings` 与 `rules[]`。**管理接口** 20 个操作，权限域 `knock`。

### WP-54 单包授权与放行

- **上游依据**：`internal/modules/knock/{knock,routes}.go`、`internal/spa/spa.go`、`internal/knockgate/`；文档 `docs/modules/knock`、`docs/tutorials/port-knocking`。
- **行为契约**：
  - 与 fwknop 客户端兼容：密钥格式与 `fwknop -k` 生成的 `KEY_BASE64`、`HMAC_KEY_BASE64` 相同（32 / 64 字节，留空自动生成）；报文用 AES-256-CBC 加密，先校验 HMAC（SHA-256 默认 / 384 / 512）再解密；每个报文只能使用一次（防重放）；时间戳超出有效期（`maxAge` 默认 120 秒）即拒绝。只支持 Rijndael CBC + HMAC，不支持 GnuPG、旧版 IV 模式、不带 HMAC 的报文、命令消息与 NAT 访问请求。
  - `settings`：`port`（UDP 敲门端口，默认 62201；0 表示只接收经协议分流发来的报文）、`autoFirewall`、`allowLan`（内网、回环与本机网卡所在的公网 IPv6 网段免敲门）、`allowList[]`、`maxAge`。
  - 规则 `Rule`：`ports[]`（最多 16 个，如 `tcp/22`；留空时只经网页登录放行）、`firewall`、`encKey` / `hmacKey`、`hmacType`、`timeout`（放行时长，默认 30 秒）、`maxTimeout`（客户端用 `-f` 请求的上限，默认 300 秒；0 忽略）、`user`（限定用户名）、`requireAddr`（拒绝不带地址的报文）、`identities[]`（`id`、`name`、`enable`、`encKey`、`hmacKey`、`remark`；每条规则最多 64 个，全部启用规则接受的密钥合计最多 1024 个，各 HMAC 密钥不能重复）、`sharedKeyOff`、`singleAddr`（每个身份同时只放行一个地址）、`remark`。
  - 修改规则时：改动端口、防火墙拦截、放行时长、限定用户名或地址要求会撤销敲门报文取得的全部授权；只改身份时只撤销密钥已失效的授权；网页登录取得的授权都保留。停用或删除规则撤销其全部授权。
  - Gately 入口按敲门放行：端口转发、协议分流（整条规则或单条路由）与 STUN 内置转发可选择「需要敲门」，由 Gately 自己判断，不需要防火墙权限；UDP 在新建会话时判断，授权到期后已有会话照常转发。被引用的规则不能删除。
  - 协议分流的「端口敲门」路由（协议 `spa`）把报文交给端口敲门模块，不转发、不回复；带敲门路由的协议分流端口与 UDP 敲门端口不能出现在开启防火墙拦截的规则中。
  - 网页登录授权：见 WP-26 的 `knockGrant`；开启了防火墙拦截的规则上，授权下实际访问过入口站点的地址（每个授权最多 8 个）写入放行集合。
  - 认证前的限速：按来源网段（IPv4 每个 /24、IPv6 每个 /64 每秒最多 10 个报文），再受全局预算约束（按 HMAC 校验量计，每秒 20000 个单位）；HMAC 认证失败的报文不逐条记录，每分钟汇总一条。
  - 与入侵防护联动：经协议分流 TCP 端口发来的被拒绝敲门发布 `knock.failed` 事件；经 UDP 发来的只计数、写日志，不发布事件（UDP 来源地址可以伪造）。
  - 授权与防重放记录都保存在内存中，重启后需要重新敲门；时间戳早于本次启动的报文在重启后一律拒绝。
- **Rust 设计**：新 crate `fg-knock`，加共享的 `fg-core::knockgate`（放行登记表的查询接口，供 Web 服务、端口转发、协议分流、STUN 使用）。SPA 报文解析自研：Base64 解码 → 按密钥集合逐个校验 HMAC（常量时间比较，密钥多时先比较摘要再验证）→ Rijndael CBC 解密（`aes` + `cbc` crate）→ 解析字段 → 时间窗与重放检查 → 登记授权。fwknop 的字段编码细节以 `internal/spa/spa.go` 与 fwknop 协议文档为准，测试用真实的 fwknop 客户端生成的报文。防火墙部分见 WP-51。
- **验收**：真实 fwknop 报文的接受与放行；错误密钥、过期、重放、端口不在列表、用户名不符、未写明地址的拒绝；身份的识别、吊销与单地址放行；限速与预算；TCP 敲门路由；授权的重启丢失。

### 10.3 WAF 防火墙（waf）

**配置文件** `waf.json`。**管理接口** 17 个操作，权限域 `waf`。上游非测试代码约 1700 行，但核心引擎来自 Go 依赖 `coraza/v3` 与 `coraza-coreruleset/v4`。

### WP-55 WAF 实例与站点集成

- **上游依据**：`internal/modules/waf/{waf,safeline,t1k,reqinfo}.go`、`webservice.WAFProvider` 接口；文档 `docs/modules/waf`、`docs/tutorials/guard-waf`。
- **行为契约**：
  - 多个实例，站点按需引用（`Site.waf`）；实例不存在或停用时放行。
  - 实例配置：内置 OWASP CRS v4 规则集、可按规则文件启用；自定义 SecLang 规则；规则组可调整顺序；拦截模式与仅检测模式；请求体检查上限（0 表示默认 12.5 MB，最大 1024 MB），超过上限时「拒绝请求」（413）或「只检查前面部分」；跳过请求体的路径；WebDAV 兼容模式（放行 `PUT`、`DELETE`、`PROPFIND` 等方法与相关请求头）；正则预过滤开关（默认开启，检测 CPU 开销约降低 16%）；接入雷池（SafeLine）检测引擎。
  - 命中日志记录客户端 IP、域名、路径与规则 ID；拦截计入访问日志（`deny=waf`）、站点统计与 `waf.blocked` 事件。
  - 绕过：带本实例有效管理员登录态的请求不经过 WAF；站点开启「信任已登录用户」或「信任后端认证标记」后相应请求不经过 WAF。
  - 雷池检测引擎：经 Unix 套接字（`unix:/data/safeline/resources/detector/snserver.sock`）或 TCP；先发心跳再送检一个示例请求做「测试连接」；送检请求体默认最多 1024 KB；检测超时默认 1 秒；不可用时默认放行并写错误日志，或选择「拒绝请求」（503）；只检测请求，不送检响应。
- **Rust 设计**：拆成两层。**集成层** `fg-waf`（实例配置、日志、指标、`WafProvider` trait、雷池客户端、请求缓冲策略）是确定可实现的部分，先做。**规则引擎层**见决策 D4：上游用 Coraza（Go）解释 SecLang，Rust 没有等价的成熟实现，需要一个与 CRS v4 兼容的 SecLang 引擎 `fg-waf-engine`，它是本方案中工作量与不确定性最大的单项。引擎分步交付：
  1. SecLang 解析器（全部指令、运算符、变换、变量、动作、链式规则、注释与 `Include`），以 CRS v4 全部规则文件零失败解析为验收。
  2. 求值引擎（五个阶段、变量集合、变换链、异常评分模式、`setvar` 与事务变量、持久化集合 `IP` / `USER` / `GLOBAL`、计数器 `&@rx`、`capture`、`chain`、`skip` / `skipAfter`、`ctl:*`）。
  3. 请求体解析（`application/x-www-form-urlencoded`、`multipart/form-data`、XML、JSON）与 libinjection 等价实现（SQL 注入与 XSS 检测；候选 Rust 移植，待核实）。
  4. 一致性测试：以 CRS 自带的回归用例为语料，统计通过率；正则先使用 `fancy-regex`（支持前后查找与回溯引用），出现兼容性缺口时再评估可选的 PCRE2 后端。
- **验收**（引擎层按步）：解析零失败；每类指令与运算符的单元测试；回归用例通过率达到约定阈值后才允许在默认构建中启用拦截模式；请求体上限的两种行为；雷池客户端用假检测服务器验证心跳、送检、超时与不可用。

### 10.4 OIDC 身份提供方

### WP-56 内置 OIDC 单点登录提供方

- **上游依据**：`internal/modules/webservice/oidc.go`（1067 行）与 `oidc_test.go`，`OIDCSettings` / `OIDCClient` 结构；文档 `docs/modules/oidc`、`docs/tutorials/oidc-sso`。
- **行为契约**：
  - 把共享用户提供给支持 OpenID Connect 的应用（Gitea、OpenList、Grafana 等）；只接受共享用户。
  - `OIDCSettings`：`enable`、`issuer`（只含协议、域名与可选端口，如 `https://auth.example.com`）、`clients[]`、`signingKey`（PEM 格式的 RSA 私钥，首次启用时自动生成 2048 位，接口不返回）。签发者域名不需要建站点，Gately 在所有监听上识别它的 OIDC 路径；签发者地址为 HTTPS 时，明文 HTTP 访问 OIDC 路径的 GET 请求跳转到 HTTPS，其他请求被拒绝。
  - `OIDCClient`：`id`（字母、数字与 `-._~`）、`name`、`secret`（至少 16 个字符，保存 bcrypt 哈希）、`public`（公共客户端不使用密钥，必须使用 PKCE，不签发刷新令牌）、`redirectUris[]`（逐字比较）、`allow[]`（用户名或 `group:分组名`，留空表示全部共享用户）、`remark`。
  - 端点：`/.well-known/openid-configuration`、`/__gately_oidc/{authorize,token,userinfo,jwks,logout}`。
  - 协议：只支持授权码模式（`response_type=code`，`response_mode=query`）；令牌接口接受 `client_secret_basic` 与 `client_secret_post`，公共客户端使用 `none`；PKCE 只支持 S256；支持 `prompt=none`。scope：`openid`（必需）、`profile`、`email`、`groups`、`offline_access`。ID Token 与 Access Token 为 RS256 签名的 JWT，ID Token 含 `iss`、`aud`、`azp`、`exp`、`iat`、`auth_time`、`nonce`、`at_hash`。
  - 退出接受 `id_token_hint`、`client_id` 与 `post_logout_redirect_uri`（须是该客户端登记的回调地址或与之同源）。
  - 有效期：授权码 2 分钟且只能使用一次；ID Token 与 Access Token 1 小时；刷新令牌 30 天。修改共享用户的密码或 TOTP、改名、删除用户、移出允许列表、删除客户端后，未兑换的授权码、刷新令牌与已签发的 Access Token 立即失效。
  - 签发者域名位于单点登录域之内时，与站点登录态互通。
- **Rust 设计**：`fg-web::oidc`。JWT 签发用 `rsa` + `sha2` 或 `jsonwebtoken`（待核实）；授权码与刷新令牌的吊销需要在内存中保存已签发令牌的索引（按用户与客户端）；端点挂在所有监听上，按 Host 识别签发者域名。
- **验收**：发现文档；授权码 + PKCE 的完整流程（机密与公共客户端）；令牌校验与 `at_hash`；刷新与轮换语义；吊销的各类触发；`prompt=none`；退出；回调地址不匹配的错误页；与 Gitea / Grafana 配置示例的兼容性用模拟客户端验证。

## 11. 阶段 P4：运维工具

本阶段共 13 个工作包，全部为新建模块，彼此独立，可在 P0 之后任何时间按需插入。推荐顺序：通知中心与事件消费（WP-68）→ 配置备份（WP-70）→ 计划任务（WP-62）→ Web 终端（WP-61）→ 文件服务（WP-63～67）→ Docker（WP-60）→ 性能监控（WP-69）→ 网络诊断与网络唤醒（WP-71、WP-72）。文件服务共享用户（WP-63）被 WebDAV、FTP、SMB 共用，先做。

### WP-60 Docker 管理

- **上游依据**：`internal/modules/docker/`（19 个非测试文件，约 8300 行；先读 `module.go`、`tasks.go`、`system.go`、`self.go`、`selfupgrade.go`）；文档 `docs/modules/docker`、`docs/reference/docker-api`、`docs/en/DOCKER_API.md`。管理接口 69 个操作，权限域 `docker`。
- **行为契约**：
  - 设置：`host`（默认 `unix:///var/run/docker.sock`）、`mirrors`（镜像加速地址，直接拉取失败时依次尝试并重新打标签）、`registries`（私有仓库登录信息，密码脱敏）、`autoCheckHours`（大于 0 时按该间隔自动检查容器镜像更新，发现新镜像发布 `docker.update`，同一个新镜像只通知一次）。
  - 容器：列表（全部 / 运行中 / 已停止 / 异常）、启动、停止、重启、暂停、恢复、强制终止、重命名、删除（可同时删除匿名卷）、提交为镜像；新建与编辑覆盖命令、环境变量、端口映射、挂载、网络、重启策略、特权模式、能力、设备映射、用户、工作目录等。详情页含概览、日志、终端、文件（在线编辑 ≤1 MiB，上传、下载、重命名、删除）、监控。
  - 自身保护：识别自己所在的容器与 Compose 项目，会让自身无法访问的操作（停止、强制终止、暂停、删除自身容器，对所在项目执行 down 等）被拒绝。升级 Gately 自身时用当前镜像创建临时辅助容器（`<容器名>-upgrade-<时间>`），由它停止旧容器、按原配置创建并启动新容器，失败时恢复旧容器。
  - 敏感信息：只读账号与只有 `docker:read` 的令牌看不到环境变量的值、Command、Entrypoint、启动参数与进程命令参数。
  - Compose：项目由容器标签聚合；启动、停止、重启、暂停、恢复、down、汇总日志；新建项目写入配置目录 `compose/<name>/compose.yaml` 并执行 up；在线编辑 compose 文件。up、拉取、构建依赖 `docker compose` 命令行。
  - 镜像：列表、拉取、推送、打标签、删除、构建（内联 Dockerfile 或 Git 地址）、导入与导出 tar；更新检查与一键升级（拉取新镜像后重建容器，沿用原配置，失败自动回滚），支持批量。
  - 网络与卷：列表、创建、删除、容器的接入与断开、卷的导出与导入（借助临时 `alpine` 辅助容器）。
  - 系统：主机与 Docker 信息、磁盘占用、清理、设置。
  - 后台任务：拉取、推送、构建、批量检查、批量升级、Compose up 作为后台任务，任务面板显示实时输出与状态；可中断（拉取、推送、构建随即停止；Compose 先发中断信号，30 秒未退出才强制结束；批量升级在当前容器处理完后停止）。
  - 事件：订阅 Docker 事件流，容器异常退出或 OOM 时发布 `docker.exited`；Docker 暂不可用时每 30 秒重试订阅。
- **Rust 设计**：新 crate `fg-docker`。Docker Engine API 客户端用 `bollard`（异步、rustls，待核实）；容器终端、日志跟随与 stats 流分别对应三种流式接口，终端经 WebSocket 暴露（复用 WP-61 的终端通道）。后台任务模型 `Task{id, kind, state, output_ring, cancel}`，输出环有界。Compose 操作执行 `docker compose` 可执行文件（参数数组）。
- **验收**：用假的 Docker API 服务器（按 `docs/en/DOCKER_API.md` 的请求与响应）验证主要调用；自身保护的拒绝用例；一键升级的失败回滚（假服务器模拟）；任务中断的三种语义；只读脱敏。

### WP-61 Web 终端

- **上游依据**：`internal/modules/webterminal/`（18 个非测试文件，约 5100 行）；文档 `docs/modules/terminal`、`docs/reference/webterminal-api`、`docs/en/webterminal-api.md`。管理接口 64 个操作，权限域 `webterminal`。
- **行为契约**：
  - 连接类型：SSH（密码或私钥认证，可指定本机 `keyFile`、私钥口令、`workDir`、`keepAlive`、连接超时 1～120 秒默认 15、代理）、Telnet（默认端口 23，检测到 `login:`、`username:`、`password:` 提示时各自动填充一次）、本机 Shell（可指定 Shell 路径、工作目录与附加环境变量）。编辑连接时密码、私钥、口令与代理密码脱敏显示，保持不变时沿用原值。「SSH 认证预设」可被多个连接复用，仍被引用的预设无法删除。
  - 代理：SSH 与 Telnet 可单独配置 `socks5` 或 `http` 出口代理。
  - 主机密钥首次信任：首次建立时记录指纹并信任，之后每次连接核对；同时记录密钥类型，写法同 `ssh-keygen -l`；核对在认证之前进行，全部不符时不发送密码或签名；「重置主机指纹」重新信任。
  - 会话持久保存在服务端，浏览器刷新或断开后可重新附着（先回放输出缓冲再实时转发）；同一会话允许多个客户端同时附着；设置项：`allowLocalShell`（默认关闭）、`maxSessions`（默认 20，上限 1000，超出返回 429）、`idleTimeout`（分钟，0 不限）、`bufferSize`（回放缓冲，默认 256 KB，上限 16384）、`heartbeatInterval`（默认 30 秒，上限 600）、`sessionKeepAlive`（浏览器断开后保留的分钟数，默认 0 即断开即结束，上限 10080）。
  - SFTP 文件管理：浏览、新建、多文件上传（桌面端支持整个文件夹）、流式下载（支持 Range）、在线编辑（超过 1 MB 或二进制不可预览）、重命名、复制、粘贴、批量删除（根目录受保护）、压缩与解压（zip、tar.gz；解压前可预览，最多 10000 条；含 `..` 的条目整体拒绝，符号链接与硬链接条目跳过）、修改权限、快速访问。压缩解压由 Gately 自身完成，远端无需安装命令。
  - 对其他模块提供的能力：经 SSH 连接上传文件并执行命令（供证书部署）、执行单条命令（供远程关机）、列出 SSH 连接。
- **Rust 设计**：新 crate `fg-webterminal`。SSH 客户端用 `russh` + `russh-keys`（待核实），SFTP 客户端用 `russh-sftp`（待核实），本机 Shell 的 PTY 用 `portable-pty`（待核实），Telnet 自研最小协商。会话模型 `Session{backend, pty_or_channel, replay: VecDeque<u8>, attachers: watch::Sender}`；WebSocket 消息协议按 `docs/en/webterminal-api.md` 一比一实现。
- **验收**：用 `russh` 的服务端示例或本地 sshd 做 SSH 往返；主机密钥变更时拒绝且不发送凭据；会话重新附着与回放；多客户端附着；并发上限；SFTP 各操作与解压的路径穿越防护；本机 Shell 默认关闭。

### WP-62 计划任务

- **上游依据**：`internal/modules/cron/cron.go`；文档 `docs/modules/tools`「计划任务」。管理接口 16 个操作，权限域 `cron`。
- **行为契约**：`spec` 支持标准 5 段表达式、可选的秒字段（6 段）与 `@every 10m`、`@daily` 等描述符；`type` 为 `command` 时经 `sh -c`（Windows 为临时 `.bat`）执行，环境变量注入 `taskName` 及带 `GATELY_` 前缀的同名大写变量；`type` 为 `http` 时按 `url`、`method`、`headers`、`body`、`successContent`（响应体需包含其中任意一项，为空时只检查 2xx）、`timeout`、`insecureSkipVerify` 发起请求；同一任务上一次尚未结束时本次触发被跳过；每个任务保留最近 20 次执行记录，输出最多保留 4000 字符摘要；可手动立即运行；创建时校验表达式。
- **Rust 设计**：`fg-cron`。表达式解析用 `cron` crate（待核实是否支持 6 段与描述符，不支持则自研）；每任务一个 Tokio 任务，输出截断到上限。HTTP 类型复用 `fg-net::http`。
- **验收**：表达式解析各形态；跳过重叠触发；执行记录与输出截断；HTTP 任务的 `successContent` 与超时；时区。

### WP-63 文件服务共享用户与 WebDAV

- **上游依据**：`internal/fileusers/`、`internal/modules/webdav/webdav.go`、`internal/fsperm/`；文档 `docs/modules/tools`「共享用户」「WebDAV」。
- **行为契约**：
  - 共享用户保存在配置目录的 `fileusers.json`，字段与各服务的本地用户相同（`name`、`password`、`root` 与 `readOnly`，或 `mounts[]`：`name`、`path`、`readOnly`）；用户名不区分大小写不可重复，也不能包含冒号。每个服务单独决定是否接受共享用户（`sharedUsers`）；与本地用户同名时只按本地用户校验。修改共享用户立即生效：WebDAV 在下一个请求按新设置校验；FTP 与 SMB 只改密码时不重启服务，只断开该用户已登录的连接，增删用户或修改目录时重启服务。接口 `GET|PUT /api/fileusers`，权限域 `fileusers`。
  - 共享用户可自助修改密码（经 Web 服务的 `/__gately_auth/password`）。
  - WebDAV：`listenIp`、`port`（默认 18800）、`tls`（证书由证书模块按 SNI 提供）、`users`、`sharedUsers`；启用时至少需要一个用户。每个用户可映射一个目录（`root` + `readOnly`）或挂载多个目录（登录后根目录按名称列出，根目录不能写入，文件不能跨目录移动）。
  - 目录不能是配置目录或其中的目录（否则能读到登录密钥）；包含配置目录的目录可以使用，配置目录被隐藏。
  - 登录限流：每个来源地址 15 分钟内累计 10 次失败后，窗口内的登录一律被拒绝（WebDAV 返回 429），成功登录不清零失败次数。空闲的 keep-alive 连接 2 分钟后关闭；上传时请求体连续 2 分钟没有数据则断开。
  - 符号链接：共享目录经受限根访问，指向共享目录之外的符号链接不能被跟随。
- **Rust 设计**：`fg-files`（共享用户与 `fsperm` 受保护路径）与 `fg-webdav`。WebDAV 服务端用 `dav-server` crate（待核实是否能在现有 hyper/tokio 栈上运行且支持自定义认证与根目录限制），不满足时基于 `http` + `hyper` 自研（WebDAV 的方法集有限：`OPTIONS`、`PROPFIND`、`PROPPATCH`、`MKCOL`、`COPY`、`MOVE`、`LOCK`、`UNLOCK`、`PUT`、`DELETE`、`GET`/`HEAD`）。文件访问统一经「打开的目录句柄 + 相对路径」的受限打开（`cap-std` 或 `rustix::openat` 族，待核实）。
- **验收**：共享用户对各服务的生效与同名优先；配置目录不可作为共享目录；符号链接越界被拒绝；登录限流；WebDAV 各方法与多目录挂载；KEEPALIVE 超时。

### WP-64 FTP 与 FTPS

- **上游依据**：`internal/modules/ftp/`；文档 `docs/modules/tools`「FTP」。管理接口 9 个操作，权限域 `ftp`。
- **行为契约**：`listenIp`、`port`（默认 2121）、`passiveStart` / `passiveEnd`（均为 0 时由系统随机分配；填写时需 `1 ≤ 起始 ≤ 结束 ≤ 65535`）、`publicHost`（被动模式对外通告的 IP）、`tlsMode`（0 明文与 FTPS 均可，1 必须显式 FTPS，2 隐式 FTPS；证书由证书模块按 SNI 提供）、`idleTimeout`（默认 900 秒）、`connectionTimeout`（默认 30 秒）、`disableActiveMode`、`users`、`sharedUsers`。符号链接限制同 WebDAV；`SITE CHOWN` 一律拒绝。
- **Rust 设计**：`fg-ftp`，FTP 服务端用 `libunftp` + `unftp-sbe-fs`（纯 Rust、生产使用，待核实），认证与存储后端接到 `fg-files`。
- **验收**：用 FTP 客户端库（`supervisely-ftp` 或自研最小客户端）覆盖登录、列表、上传、下载、被动端口范围、三种 TLS 模式、登录限流、符号链接。

### WP-65 SMB

- **上游依据**：`internal/modules/smb/`（约 1050 行）与 `internal/gosamba/`（约 1.7 MB、203 个文件：`config`、`discovery`、`inotify`、`ntlm`、`parent`、`smb2`、`smb3`、`transport`、`userdb`、`vfs`）；文档 `docs/modules/tools`「SMB」。管理接口 9 个操作，权限域 `smb`。
- **行为契约**：`listenIp`、`port`（默认 445）、`requireEncryption`（要求 SMB 3 加密）、`mdns`（Bonjour 广播）、`users`、`sharedUsers`。协议支持 SMB 2.0.2～3.1.1、NTLMv2 认证与签名，可要求 SMB 3 加密，不支持 SMB1。共享按用户划分：单个目录时共享名为用户名；多个目录时每个目录一个共享。用户名与共享名的字符限制；NTLM 认证需要明文密码。登录前限制：30 秒内没有下一个请求或从连接起 60 秒仍未完成登录即断开；登录前单个请求不得超过 128 KiB；未登录的连接合计最多 256 条，单个来源最多 32 条（IPv6 按 /64）。
- **Rust 设计**：见决策 D5。这是本方案中除 WAF 引擎外最大的不确定项：Rust 生态里没有与上游 `gosamba` 等价的、生产可用的纯 Rust SMB 2/3 **服务端**（候选 `smb` / `smb-core` / `smb-packets` 系列，成熟度待核实）。三条路径：
  1. **纯 Rust 自研**：按 SMB 2.0.2～3.1.1 的报文实现协商、会话建立（NTLMv2、签名）、树连接、文件打开/读写/关闭、查询目录与信息、加锁，以及 SMB 3 加密与 mDNS 发现。工作量估计 XL，且必须用 smbclient 做一致性测试。
  2. **托管 Samba**：用 WP-43 的托管程序机制管理系统的 `smbd`（或容器内的 Samba），模块负责生成 `smb.conf`、用户与共享。行为上不等价于上游内置实现，但功能可达。
  3. **延后**：`smb` 作为可选 feature 保留接口与配置模型，实现排到最后。
  建议先做配置模型、共享用户映射与管理接口，再对候选 crate 做一次可行性验证（一次 negotiate → session setup → tree connect → read/write 的闭环），根据结果在路径 1 与路径 2 之间决定。
- **验收**（路径 1）：用 `smbclient` 与 Windows 客户端验证协商、NTLMv2 登录、读写、只读共享、加密要求、登录前限制；mDNS 发现。路径 2 的验收为生成的 `smb.conf` 快照与真实 `smbd` 的访问验证。

### WP-66 File Browser

- **上游依据**：`internal/modules/filebrowser/{module,instance,install}.go`；文档 `docs/modules/tools`「File Browser」。管理接口 25 个操作，权限域 `filebrowser`。
- **行为契约**：托管 FileBrowser Quantum（程序不内置，经 WP-43 在线安装到 `bin/filebrowser`）。每个实例一个独立进程：`listenIp`、`port`（默认 8080）、`baseUrl`、`accessUrls[]`、`sources[]`（`path`、`name`、`readOnly`；不能与配置目录重叠）、`authMethod`（`password` / `proxy` / `noauth`）、`proxyHeader`、`adminUser`、`adminPassword`（至少 8 位）、`trustProxyHeaders`、`disableWebDav`、`locale`、`tokenHours`。管理员密码在每次启动时同步，经环境变量传入；配置、数据库与缓存在 `filebrowser/<实例 key>/`（0600）；共享目录不存在时实例不启动。
- **Rust 设计**：`fg-filebrowser`，实例生命周期基于 `fg-proc::instance`；配置文件生成为 FileBrowser 的 JSON 配置。
- **验收**：实例配置生成；目录不存在时不启动；密码不写入文件；更新与回滚后实例重启。

### WP-67 存储挂载

- **上游依据**：`internal/modules/storage/`（7 个非测试文件）、`internal/mountfs/`（`afero.go`、`mountfs.go`、`rootfs.go`、`webdav.go`）；文档 `docs/modules/tools`「存储挂载」。管理接口 21 个操作，权限域 `storage`。
- **行为契约**：挂载类型 `local`、`webdav`、`smb`；字段 `name`、`remark`、`enable`、`path`（已存在的绝对路径；不能是配置目录或其中的目录；包含配置目录时自动隐藏）、`url` / `username` / `password`（密码脱敏）、`skipVerify`、`domain`、`readOnly`。在线文件管理支持浏览目录、下载、流式上传（不把整个文件载入内存）、新建目录、重命名和删除。挂载点可作为备份任务的目标位置。
- **Rust 设计**：`fg-storage`。统一一个最小的「文件系统」抽象（列目录、打开读、创建写、建目录、重命名、删除），有本地、WebDAV、SMB 三个真实实现，这是本方案中少数确有跨实现需求的 trait。WebDAV 客户端自研（`PROPFIND` 解析）；SMB 客户端取决于 WP-65 的结论。
- **验收**：三种挂载的操作矩阵；只读挂载拒绝写；配置目录隐藏；大文件的流式上传内存占用恒定。

### WP-68 通知中心

- **上游依据**：`internal/modules/notify/notify.go`（1692 行）与 11 个测试文件、`internal/webhook/`、`internal/events/events.go`；文档 `docs/modules/notify`、`docs/tutorials/notify-alerts`。管理接口 32 个操作，权限域 `notify`。
- **行为契约**：
  - 渠道：Webhook、Telegram、Bark、ntfy、Gotify、Pushover、Discord、Slack、Server酱、PushPlus、企业微信、钉钉、飞书、邮件。钉钉与飞书填写签名密钥后请求自动附带 `timestamp` 与 `sign`；企业微信、钉钉、飞书、Bark 检查响应中的业务返回码，HTTP 200 但业务失败同样记为投递失败。
  - 规则：事件类别、级别、通配匹配、静音与去重；内置模板（严重故障、证书到期、地址变化、登录、配置变更、版本更新）；Webhook 模板变量；通知语言与服务器名称。
  - 失败重试与补推：默认重试 3 次，分别在失败后 10 秒、30 秒、60 秒重试（超过 3 次的部分每次间隔 60 秒），最多 10 次，0 为不重试。补推保留时长默认 24 小时（最长 168 小时）：重试用尽仍失败的消息保存到配置目录的 `notify/pending.json`，重启后继续；之后按渠道定期补发，失败等待时间从 1 分钟起翻倍，最长 15 分钟。每个渠道最多积压 100 条。测试通知只发送一次。
  - 代理：全局代理（不使用 / 使用全局更新代理 / 自定义）与渠道代理（跟随 / 直连 / 全局更新代理 / 自定义），支持 `http://`、`https://`、`socks5://`、`socks5h://`，可带用户名与密码；邮件经 http(s) 代理时使用 CONNECT 隧道，之后 STARTTLS / SSL 与认证在隧道内完成。
- **Rust 设计**：新 crate `fg-notify`。每个渠道一个结构体实现 `trait Channel { async fn send(&self, msg) -> Result<()>; }`（14 个真实实现）。投递器为「按渠道的有界队列 + 后台任务」，补推队列持久化为 JSON。邮件用 `lettre`（待核实）。订阅 WP-16 的事件总线。
- **验收**：每个渠道的请求格式用假服务器验证（含签名与业务返回码）；重试时间线；补推队列的持久化与恢复；每渠道积压上限；代理 CONNECT 隧道；规则匹配的通配与去重。

### WP-69 性能监控

- **上游依据**：`internal/modules/perf/`（6 个非测试文件）、`internal/sysstat/`；文档 `docs/modules/perf`。管理接口 19 个操作，权限域 `perf`。
- **行为契约**：后台每 5 秒采样；60 秒档每个采样一个点，1 小时档每分钟一个点（取平均），24 小时档每 5 分钟一个点；CPU 图表保留每时段的峰值。主机指标（CPU、内存、磁盘、1 分钟负载）、Gately 进程（CPU、常驻内存、文件描述符）、托管进程（PID、运行时长、重启次数、CPU、内存）、站点（进行中请求、每秒请求、5xx 比例、首字节延迟 P95、后端健康）。首字节延迟落入 50 个细分档（1 毫秒到 60 秒），分位数取所在档的平均耗时。告警规则：指标、阈值（比较符与数值）、持续时长（1～1440 分钟，中途回落一次即重新计时）、生效站点、最小请求数（默认 20）、级别；状态机为「计时中 → 告警中 → 解除」，发布 `perf.alert` 与 `perf.recovered`；修改规则的关键字段或停用规则会清除计时并补发恢复通知。数据只保存在内存中。
- **Rust 设计**：`fg-perf`。采集基于 `fg-core::sysstat`（候选 `sysinfo` crate，待核实；macOS 的 CPU 使用率需单独实现）；三档降采样环形缓冲；延迟直方图沿用 WP-28。
- **验收**：采样与降采样；告警状态机的计时、回落、解除、站点删除；低流量时最小请求数的判定；指标在各平台的可得性降级。

### WP-70 配置备份

- **上游依据**：`internal/modules/backup/backup.go`、`internal/app/system.go`（下载与恢复）、`internal/config/history.go`；文档 `docs/modules/backup`、`docs/tutorials/history-backup`。管理接口 21 个操作，权限域 `backup`；下载与恢复接口仅限登录会话。
- **行为契约**：
  - 备份包是 zip，包含配置目录根部的全部 `*.json`（含账号、各模块配置、证书、令牌哈希）；不含 `logs/` 与 `audit.log`。文件名上游为 `gately-backup-YYYYMMDD-HHMMSS.zip`，**本项目用 `ferrumgate-backup-` 前缀**（加密备份为 `.zip.enc`）；加密格式的魔数 `GATELYBK1` 保持不变，这样才能与上游的备份互相恢复。
  - 恢复：上传上限 64 MB；覆盖前把现有配置复制到配置目录下的 `backup-时间` 文件夹；恢复后自动重启；默认用备份中的账号配置覆盖当前账号，备份中没有 `account.json` 时拒绝恢复；勾选「保留当前管理员账号」时不覆盖账号、密码、两步验证、只读账号、API 令牌与管理界面的第三方登录；恢复了账号配置时换用新的会话密钥，恢复前签发的登录会话全部失效；仍在使用默认密码时拒绝恢复；只接受位于 zip 根目录、非隐藏、内容为合法 JSON 的 `*.json`。
  - 定时备份：执行计划（5 段 cron，默认 `0 3 * * *`）、保留数量（每个目的地 1～365，默认 7）、加密口令（留空不加密，已设置时留空表示保持不变）、本地目录（默认开启，写入配置目录的 `backups`）；远程目的地为「存储挂载」中的挂载点加子目录；写入成功后按保留数量清理较旧的备份，只处理本项目前缀 `ferrumgate-backup-` 开头的 `.zip` / `.zip.enc`（目录里若有上游生成的 `gately-backup-*`，不动它们）；同一时刻只运行一次备份。
  - 加密格式：scrypt（N=32768，r=8，p=1）派生 32 字节密钥，盐 16 字节随机数；AES-256-GCM，nonce 12 字节随机数；文件为魔数 `GATELYBK1`、盐、nonce、密文依次拼接，魔数同时作为 GCM 的附加认证数据。口令保存在 `backup.json`，API 令牌不能读取、修改或清空口令。
- **Rust 设计**：`fg-backup`。zip 用 `zip` crate，scrypt 用 `scrypt`，AEAD 用 `aes-gcm`；加密格式与上游一致，以便互相恢复备份。
- **验收**：打包内容清单；恢复的各条规则（无账号文件、保留账号、默认密码、非法条目忽略）；加密往返并能读取上游生成的 `.zip.enc` 样例；定时与保留数量；远程目的地经 `fg-storage`。

### WP-71 网络诊断

- **上游依据**：`internal/modules/nettools/`；文档 `docs/modules/nettools`。管理接口 11 个操作，权限域 `nettools`。
- **行为契约**：每次点击「开始」创建后台任务并立即返回任务 ID；同时运行的任务最多 4 个；单个任务最长 5 分钟；保留最近 50 个任务，每个任务最多保留 500 行输出；可取消。Ping：ICMP 回显，默认 4 次（最多 20），每次超时 2 秒、间隔约 0.7 秒，优先使用无特权的 UDP 型 ICMP 套接字，失败再尝试原始套接字。路由追踪：调用系统命令（Windows 用 `tracert`，其他优先 `traceroute`、其次 `tracepath`），最多 20 跳。端口探测：一次最多 1024 个端口，并发 100，单端口连接超时 1.5 秒，对常见端口显示服务名。DNS 查询：类型 A、AAAA、CNAME、MX、TXT、NS、PTR，可指定服务器或 DoH 地址，超时 8 秒。测速：下载测速，4 路并发。局域网扫描。
- **Rust 设计**：`fg-nettools`。任务模型与 Docker 的后台任务共用一个小的 `JobRegistry`（有界、可取消、输出环）。Ping 用 `socket2` 创建无特权 ICMP 套接字（Linux 依赖 `net.ipv4.ping_group_range`，失败时返回明确错误而不是尝试需要特权的原始套接字——与上游的差异在文档中写明）；DNS 用 `hickory-client`（已在依赖树中）；路由追踪执行系统命令（参数数组）。
- **验收**：任务上限与超时；Ping 的回显解析（可用假应答）；端口探测的范围与并发；DNS 各类型（用假 DNS 服务器）；命令不存在时的错误。

### WP-72 网络唤醒

- **上游依据**：`internal/modules/wol/`（6 个非测试文件，约 2200 行）；文档 `docs/modules/tools`「网络唤醒」「远程关机」「巴法云语音控制」。管理接口 30 个操作，权限域 `wol`。
- **行为契约**：
  - 设备：`name`、`macs[]`、`broadcastIps[]`（留空时向 `255.255.255.255` 及各启用网卡的广播地址发送）、`port`（默认 9）、`repeat`（每个 MAC 重复次数，默认 3，上限 20）、`checkAddr`（`主机:端口` 在线探测）、`shutdownMode`（空 / `agent` / `ssh` / `http`）、`shutdownConn`、`shutdownCommand`、`agentToken`、`shutdownHttp`、`bemfaTopic`、`remark`。魔术包为 6 字节 `0xFF` 后接 16 次 MAC。
  - 远程关机 `POST /api/wol/devices/{key}/shutdown`（可带 `{"action": "reboot" | "sleep"}`）：同一设备同时只执行一次，最长 30 秒。客户端方式：设备上运行客户端脚本，主动连接 Gately 长轮询取指令（每 25 秒一次，断开后从 5 秒起最长 60 秒重试），只认关机、重启、睡眠三种操作；指令只在发出后 10 秒内有效；同一凭据只能用于一台设备；接口挂在 `/api/wol/public/agent/` 下，不需要登录，只认设备凭据。SSH 方式：每次新建一条连接，该连接须已记录主机密钥。HTTP 方式：2xx 视为成功。
  - 经 SSH 设置或执行命令需要 `wol:write` 之外的 `webterminal:write`。
  - 巴法云语音控制：以 MQTT 3.1.1 经 TLS 连接 `bemfa.com:9503` 并校验证书，私钥作为客户端 ID；断开后从 5 秒起最长 5 分钟重连。
- **Rust 设计**：`fg-wol`。魔术包用 Tokio 的 UDP socket（可绑定网卡）。客户端脚本（Windows PowerShell、Linux shell、macOS、OpenWrt）作为静态资产嵌入并提供 SHA-256 校验；长轮询接口挂在公开路由下。MQTT 用 `rumqttc`（待核实）。
- **验收**：魔术包内容与广播地址；在线探测；三种关机方式的成功、超时与互斥；客户端凭据的单设备约束与指令有效期；脚本的校验值；MQTT 重连退避（假 broker）。

## 12. 阶段 P5：管理界面

Gately 的定位是「在浏览器里配置一切」，管理界面是产品的一部分。上游前端是 Vue 3 + TypeScript + Vite + Element Plus 的单页应用（`web/`：67 个视图文件、138 个组件、21 个 composable、881 个语言文件，约 7.5 MB），经 `go:embed` 打进二进制。FerrumGate 目前没有管理界面。

### 12.1 技术路线（决策 D6）

| 路线 | 做法 | 与「全部用 Rust」的契合 | 主要代价 |
|---|---|---|---|
| A. Rust WASM 单页应用（**推荐**） | 用 Leptos（待核实）编写 CSR 应用，编译为 WASM 嵌入 `fgate` | 高：应用代码全部是 Rust | 终端模拟器、图表、拓扑布局、拖拽、代码编辑器没有现成的 Rust 组件，需要自研或用 `web-sys` 封装成熟的 JS 库 |
| B. Rust 服务端渲染 | Askama/Axum 模板输出页面，少量 WASM 岛屿处理交互 | 高 | 上游界面的交互密度（拖拽排序、实时拓扑、终端、图表）不适合以服务端渲染为主 |
| C. 复用上游 Vue 前端 | 以上游前端（Apache-2.0，需署名）对接 Rust 管理 API，由 Rust 托管静态资源 | 低：前端仍是 TypeScript | 无法称为 Rust 实现，但能最快得到完整界面，也是检验 API 兼容性最直接的手段 |

**推荐 A**，并采用下面的约束：管理 API 与界面无关（WP-11 先行）；重交互的叶子组件（终端模拟器、代码编辑器）允许经 `web-sys` 封装成熟的 JS 库，其余界面代码全部用 Rust；在 P0～P1 期间，可以把上游前端构建产物当作**测试工具**挂到 Rust 管理 API 上，用它逐页核对接口契约（不作为交付物）。

### 12.2 页面清单（来自上游 `web/src/views`）

| 分组 | 页面 | 上游视图规模（字节） |
|---|---|---|
| 外壳 | 登录 `Login`、布局 `Layout`、总览 `Overview`、集线页 `Hub` | 25 K、18 K、36 K、2 K |
| Web 服务 | `Web`（监听与站点）、`WebPanels`（导航面板）、`WebTopologyPage`、`WebUsers`（认证用户）、`WebVisitors`（访客审计） | 131 K、75 K、2 K、19 K、43 K |
| 网络 | 端口转发 `PortForward`、协议分流 `ProtoRoute`、DDNS、STUN、SSL | 25 K、35 K、47 K、28 K、46 K |
| 组网 | `Frp`、`Tailscale`、`NetBird`、`EasyTier`、`Cloudflared` | 57 K、25 K、29 K、24 K、15 K |
| 安全 | `WAF`、`Guard`、`Knock` | 21 K、48 K、44 K |
| 文件 | `WebDAV`、`FTP`、`SMB`、`FileServiceUsers`、`FileBrowser`、`Storage` | 5 K、6 K、10 K、5 K、21 K、18 K |
| 运维 | `Docker` 及 23 个子视图、`Terminal`、`Cron`、`Notify`、`Perf` | 约 160 K（合计）、35 K、12 K、36 K、31 K |
| 工具 | `NetTools`、`WOL` | 13 K、27 K |
| 系统 | `Settings`、`ApiTokens`、`ApiDocs`、`Audit`、`History`、`Logs`、`About` | 72 K、26 K、25 K、5 K、6 K、3 K、27 K |

依赖库：`vue-router`、`vue-i18n`（10 种语言）、`element-plus`、`lucide-vue-next`（图标）、`@xterm/xterm`（终端，含 fit、search、web-links 插件）、`d3-hierarchy`（拓扑的树形/旭日等布局）、`qrcode`。

### WP-80 管理界面基座

- **上游依据**：`web/package.json`、`web/vite.config.ts`、`web/src/{router,navRoutes,api,nav,configConfirm,basePath,security}.ts`、`web/src/App.vue`、`web/src/views/{Login,Layout}.vue`；文档 `docs/guide/configuration`（保存确认与批量修改的交互）、`docs/guide/security`。
- **行为契约**：单页应用嵌入二进制；支持经网关访问时的路径前缀（`-gateway-prefix`，如 `/app/gately`）；登录页含密码、两步验证、Passkey 与第三方登录入口；全局搜索（Ctrl/⌘+K）；首次运行场景选择与「开始使用」清单；只读公开演示模式（`-demo`）；主题（15 个色系，各有亮色与暗色，可跟随系统）；10 种语言；手机端适配；保存后确认的倒计时与回滚提示、批量修改横幅；地址打码显示。
- **Rust 设计**：新 crate `fg-ui`（Leptos CSR，`trunk` 或 `cargo-leptos` 构建，产物嵌入 `fg-admin` 的静态资源服务）。路由与上游的 `router.ts` 对应；API 客户端封装 `fetch` 与 WebSocket，统一处理错误信封、只读脱敏标记与 `basePath`。i18n 复用 WP-10 的语言键与文案来源，界面文案单独一套目录。全局状态用 Leptos 的信号。
- **验收**：登录全流程；路径前缀下的资源加载；只读账号的界面裁剪；主题与语言切换；手机宽度下的布局。

### WP-81 列表通用能力

- **上游依据**：`web/src/{groupSort,paging,copyDraft,copyName,emptyTemplates}.ts` 与 `web/src/components` 中的列表、分组排序、IP 输入、Cron 编辑等组件；文档 `docs/guide/lists`。
- **行为契约**：条目较多的列表统一支持分组（最长 64 个字符）、手动排序（箭头与拖拽，整组移动，多选一起移动）、批量启停删（一次最多 500 个条目，全部校验通过才保存）、复制条目（名称加「副本」）、卡片与紧凑视图、搜索。顺序和分组只影响显示，修改后不重启服务、不切断连接。
- **Rust 设计**：在 `fg-ui` 中实现一个泛型的 `ListPage<T>` 组件与配套的分组排序组件；拖拽用 `web-sys` 的指针事件自研。所有配置页复用。
- **验收**：分组、排序、批量、复制的交互在各页一致；窄屏下用箭头与工具栏替代拖拽。

### WP-82 核心配置页

- **范围**：端口转发、协议分流、Web 服务（监听、站点编辑的各个页签、认证用户、订阅 IP 列表、错误页库、登录页外观）、导航面板编辑、SSL 证书、DDNS、STUN、WAF、入侵防护、端口敲门。
- **上游依据**：对应视图文件及其表单校验；各模块文档中对界面的描述。
- **Rust 设计**：每页一个模块目录（`pages/<module>/`），表单校验规则与管理 API 的校验一致（共用 `fg-core` 中导出的常量，如上限与默认值）。复杂表单（站点编辑）拆成页签组件。
- **验收**：每个页面完成「新增—编辑—启停—删除—复制」闭环，并通过界面对应模块的 E2E 用例。

### WP-83 可视化页

- **范围**：网络拓扑（七种布局：树形、竖向、径向、桑基、旭日、矩形树图、气泡；链路高亮；活动 IP；打码；筛选；回放时间轴）、站点统计、访客审计、性能监控、实时连接、日志查看器（筛选、全屏、导出）。
- **上游依据**：`web/src/{topology,topologyReplay,visitors,logView,ipGeo}.ts`、`web/src/views/{WebTopologyPage,WebVisitors,Perf,Logs}.vue`；`d3-hierarchy` 的使用点。
- **Rust 设计**：图形用 SVG 直接生成（Leptos 的 `view!`），图表自研轻量实现；布局算法（树形、径向、旭日、矩形树图、桑基）自研，树形与旭日对应 `d3-hierarchy` 的 tree 与 partition；终端以外的重交互在这里主要是缩放与平移（指针事件）。
- **验收**：拓扑数据到节点/连线的渲染与 2 秒刷新；回放；统计图表与接口数据一致；日志查看器的筛选语法与导出。

### WP-84 运维页

- **范围**：Docker（六个标签页与容器详情）、Web 终端（xterm 等价：多标签、分屏、搜索、复制粘贴、手机端长按）、文件服务、存储挂载的文件管理器、通知中心、配置备份、网络诊断、网络唤醒、隧道与组网。
- **上游依据**：`web/src/views/{Docker,Terminal,Notify,NetTools,WOL,Storage,…}.vue` 与 `web/src/views/docker/*`。
- **Rust 设计**：终端模拟器经 `web-sys` 封装 `@xterm/xterm`（这是允许封装 JS 库的叶子组件）；Docker 的 Compose 编辑器与 YAML 编辑用带行号的文本域加高亮，不引入代码编辑器库；文件管理器的上传用 `File` API 流式提交。
- **验收**：终端的连接、重连、分屏；Docker 各标签页；文件上传下载；通知测试发送；备份下载与恢复。

### WP-85 系统页

- **范围**：总览（CPU、内存、磁盘、流量、网卡与公网地址、模块状态、托管进程）、设置（访问限制、账号与安全、网络与运行、存储占用、功能模块、GeoIP 数据库、备份与迁移）、API 令牌、API 文档、审计日志、配置历史（差异对比与回滚）、系统日志、关于（版本、更新、升级、构建中未包含的模块）。
- **Rust 设计**：行级差异视图复用 `fg-config` 的 diff 输出；API 文档页渲染 `GET /api/openapi.json`。
- **验收**：安全评分展示；配置历史的对比与回滚；在线升级进度与取消。

### WP-86 服务端渲染的对外页面

- **范围**：站点登录页（10 种样式与品牌项）、错误页（10 种风格与自定义页）、导航面板（主题与布局）。这些页面由 Web 服务在服务端渲染，面向访客，不属于管理界面。
- **上游依据**：`internal/webpage/{styles,styles_builtin,loginskins_builtin,panelthemes,panelskin,panelui}.go`、`web/src/{errorPages,loginPage,themes,palette}.ts`、`web/src/style.css`。
- **Rust 设计**：新 crate `fg-page`（被 `fg-web` 与 `fg-admin` 共用）。样式表作为静态资产嵌入，HTML 用 Askama 模板（编译期检查）；自定义 CSS 追加在所选样式之后。占位符输出时做 HTML 转义。导航面板页面上的访客侧交互（换肤、搜索过滤、语言与内外网切换）按决策 **D15** 实现（推荐 Rust WASM）。
- **验收**：每种样式在桌面与手机尺寸的渲染快照；占位符转义；自定义 CSS 中 `<` 被转义；自定义错误页里的脚本、内嵌框架与危险协议被清除。

## 13. 阶段 P6：发布、升级与定制构建

### WP-90 定制构建与模块清单

- **上游依据**：`modules.json`（`$comment`、`schema`、`baseSizeKB`、`groups`、`modules`、`languages`、`targets`、`presets`）、`tools/custombuild/{main,build}.go`、`internal/modules/registry/registry_test.go`；文档 `docs/modules/`（模块总览）「Custom builds」。
- **行为契约**：
  - 除端口转发、Web 服务、SSL 证书三个核心模块外，每个模块都可以在编译时去掉；界面语言可裁剪为仅简体中文或简中、繁中、英语；包体积与内存随之缩小。
  - 模块清单字段：`id`、`group`（`network` / `tunnel` / `web` / `storage` / `tools` / `system`）、`core`、`requires`、`tag`（构建标签，如 `no_smb`）、`sizeKB`（去掉该模块后 linux/arm64 体积的减少量估算）、`title` 与 `desc`（三语）。`baseSizeKB` 为 linux/arm64 完整版体积。
  - 预设：`minimal`（仅核心）、`router`（协议分流、DDNS、STUN、frp、入侵防护、端口敲门、网络唤醒、计划任务、通知、网络诊断）、`nas`（在路由器预设上增加 Tailscale、cloudflared、Web 终端、Docker、WebDAV、SMB、File Browser、存储挂载、性能监控、配置备份）。
  - 未编译进构建的模块：配置文件原样保留，接口返回 404，令牌权限仍有效；定制构建不能在线升级（下载的是完整版），改用「上传升级包」；关于页列出未包含的模块。
- **Rust 设计**：`features.toml` 作为唯一来源；`xtask`（Rust，符合仓库「禁止 Python 脚本」的约定）生成模块注册表、`modules.json` 与前端的模块清单，并校验三者一致。Cargo feature 与模块 ID 同名；语言档位用加法 feature `lang-*`；三个核心 crate 不提供关闭开关。体积基准由 `xtask size-baseline` 在固定的 linux/arm64 目标上测量后写回 `modules.json`，不手工估算。
- **验收**：`--no-default-features`、默认、`--all-features`、`minimal`、`router`、`nas` 六种构建可编译并启动；未编译模块的 404 与配置保留；生成的三份产物一致性测试。

### WP-91 持续集成

- **上游依据**：`.github/workflows/ci.yml`、`CONTRIBUTING.md`；`AGENT.md`「交付」一节。
- **行为契约**：每次推送与 PR 运行前端构建与测试、格式检查、静态检查、带竞态检测的测试，以及若干需要额外环境的测试步骤。
- **Rust 设计**：GitHub Actions 的 job 划分：`fmt`、`clippy --workspace --locked --all-targets --all-features -- -D warnings`、`test --workspace --locked`、feature 矩阵（WP-90 的六种构建做 `check`，其中默认与 `minimal` 跑完整集成测试）、`harness`（每种可选 feature 单独启用时的编译检查，候选 `cargo-hack`，待核实）、供应链审计（`cargo-deny` 与 `cargo-audit`，待核实）、WASM UI 构建与测试。
- **验收**：流水线在全部 job 上通过；feature 矩阵的失败能定位到具体组合。

### WP-92 多平台构建与打包

- **上游依据**：`Dockerfile`、`deploy/`（`docker-compose.yml`、`systemd/gately.service`、`openwrt/`、`fnos/`、`grafana/`）、`.github/workflows/release.yml`；文档 `docs/guide/install`。
- **行为契约**：
  - 目标：Docker 多架构（`linux/amd64`、`linux/arm64`、`linux/arm/v7`）、Linux amd64 / arm64 / arm / mipsle / mips / riscv64、Windows amd64、macOS amd64 / arm64、FreeBSD amd64 的压缩包、fnOS 的 `.fpk`（x86 / arm）、OpenWrt 的 `.ipk`（24.10 及更早）与 `.apk`（25.12 及更后），以及架构无关的 LuCI 应用。
  - Docker 镜像：多阶段构建（前端 → 后端 → `alpine` 运行时），运行时包含 CA 证书、时区数据、`curl`、`bash`、Docker CLI 与 Compose 插件、`nftables`、`iptables`、`iptables-legacy`、`ipset`；`GATELY_CONFIG_DIR=/etc/gately`；对外暴露管理端口。发布时推送到 GHCR 与 Docker Hub，带版本标签与 `latest`。
  - 版本号最多四段；每个 `v*` 标签触发发布流水线；安全修复只针对最新版本。
- **Rust 设计**：Linux 目标用 musl 静态链接（`x86_64-unknown-linux-musl` 等，候选 `cargo-zigbuild` 或 `cross`，待核实），路由器架构（mips、mipsle、riscv64）对应 Rust 的 tier 2 目标 `mips-unknown-linux-musl`、`mipsel-unknown-linux-musl`、`riscv64gc-unknown-linux-musl`（待核实）；`ring`（现有加密提供方）对这些目标的支持需要在 WP-90 之前验证，不支持时改用 `aws-lc-rs` 或评估 `rustls` 的其他后端。OpenWrt 与 fnOS 的打包脚本沿用上游的目录结构与元数据格式，改由 `xtask` 调用。
- **验收**：全部目标产物可构建；`file` 显示静态链接；musl 产物在 `scratch` 容器中可运行；OpenWrt 与 fnOS 包在对应系统的安装验证单独记录。

### WP-93 签名、来源证明与校验

- **上游依据**：`internal/minisign/`、`internal/releasesig/`、`tools/sign/`、`.github/workflows/release.yml`（`publish` 任务）；文档 `docs/guide/verify`、`docs/en/VERIFY.md`。
- **行为契约**：`checksums.txt` 用 minisign 格式的 Ed25519 私钥签名，生成 `checksums.txt.minisig`（在线升级先用编进程序的公钥验证它）；用 cosign 无密钥签名校验和文件与镜像；生成构建来源证明与 SBOM；校验方法公开在文档中。
- **Rust 设计**：`fg-release`（或 `xtask sign`）实现 minisign 的签名与校验（候选 `minisign-verify` crate，待核实）；公钥在构建时通过环境变量注入。CI 中用 cosign、`attest-build-provenance`、`cargo cyclonedx`（待核实）生成来源证明与 SBOM。
- **验收**：签名文件的格式可被 minisign 工具校验；篡改后的校验和文件验证失败；SBOM 包含全部直接依赖。

### WP-94 更新检查与在线升级

- **上游依据**：`internal/app/{updatecheck,upgrade}.go`、`internal/releasesig/`；文档 `docs/guide/security`「隐私承诺」「自主升级」、README「Update checks」。
- **行为契约**：默认每 12 小时匿名读取 GitHub 上的发布列表与安全公告，只用于提示新版本与安全更新，可以关闭；运行的版本受已公布的安全问题影响时给出醒目提示并通知。程序不会在后台下载或替换自身：在线升级只在管理员点击后执行，先验证发布签名再核对 SHA-256，并保留旧版本；另有「上传升级包」路径；定制构建不能在线升级。
- **Rust 设计**：`fg-admin::update`。下载经更新代理；替换二进制的方式与 WP-03 的重启共用（Unix 上写入临时文件后 rename，再 `exec`）。Windows 的自替换需要走「拉起新进程后退出」的路径。
- **验收**：假发布源下的检查、签名验证失败拒绝安装、SHA-256 不符拒绝、升级后版本变化、旧版本保留与回退、取消进行中的升级。

### WP-95 系统服务与安装

- **上游依据**：`internal/service/`（`service.go`、`unit.go`、`service_{linux,darwin,windows,other}.go`、`safety_*.go`）、`deploy/systemd/gately.service`、`deploy/openwrt/gately.init`；文档 `docs/guide/install`。
- **行为契约**：`fgate service install|uninstall|start|stop|restart|status`；Linux 注册 systemd 单元并在崩溃后拉起；macOS 注册 launchd 守护进程（`-user` 为登录项）；Windows 注册系统服务；配置目录默认为 `/etc/gately`、`/usr/local/etc/gately` 或 `%ProgramData%\FerrumGate`；服务指向二进制的最终路径；卸载时保留配置目录。OpenWrt 由 procd 启动并在系统升级时保留配置。
- **Rust 设计**：按平台条件编译。Windows 服务用 `windows-service` crate（待核实）。单元文件模板放在 `deploy/` 并在构建时嵌入。注册服务属于高权限操作，命令要求显式确认并记录到审计日志。
- **验收**：三类系统上的安装、启动、崩溃拉起、停止、卸载；单元文件内容快照；重复安装的行为。

### WP-96 构建站点后端（可选）

- **上游依据**：`tools/custombuild/`、`modules.json` 的 `targets` 与 `presets`；README 对 `build.gately.cn` 的描述。
- **行为契约**：用户选择模块、语言与目标，在线生成二进制、OpenWrt 或 fnOS 包、多架构 Docker 镜像，页面上估算体积。
- **Rust 设计**：`fg-buildctl`（axum）：校验 feature 与目标白名单 → 生成 `cargo build` 命令 → 任务队列 → 触发 CI → 产物签名与下载链接。安全控制：只接受白名单内的 feature、目标与预设，不接受任意 Cargo 参数；按来源限速；队列隔离。属于独立部署的服务，不进入 `fgate`。
- **验收**：白名单外的输入被拒绝；任务状态可查询；产物可校验签名。

## 14. 测试策略与验收标准

本节遵循根目录 `AGENT.md` 的约定：测试全部用 Rust，经 Cargo 的统一入口执行；不引入 Python 或其他脚本的测试；用临时目录、临时端口与自有测试数据；对外部服务的模拟结果与真实环境的结果分别标注。

### 14.1 测试层次

| 层次 | 做法 | 适用范围 |
|---|---|---|
| 单元测试 | 模块内的 `#[cfg(test)]`，覆盖解析、校验、状态机与纯函数 | 所有工作包 |
| 集成测试（`tests/`） | 启动真实回环后端与 `fgate` 的服务端，用真实连接验证行为 | 数据面、管理 API、认证 |
| 契约测试 | 用本地假服务器重放上游的请求与响应样例 | DNS 提供商、通知渠道、Docker API、OAuth 提供方、Cloudflare API、发布源 |
| 快照测试 | 对生成的配置、脚本、规则与页面输出做快照比较 | frp 配置、nftables 脚本、OpenAPI、错误页与登录页 |
| 性质测试 | `proptest` 验证解析器的不变量（不 panic、往返一致） | 协议识别、SPA 报文、路径规范化、域名规则、日志查询语法 |
| 构建矩阵 | 六种 feature 组合的编译与启动 | WP-90、WP-91 |
| 真实环境验证 | Linux + `NET_ADMIN`、真实 fwknop 客户端、真实 Docker、真实 smbclient | 防火墙、敲门、Docker、SMB；结果在文档中单独记录平台与条件 |

### 14.2 测试辅助

- `tests/common` 扩展为通用的测试装配：生成临时配置目录、在随机回环端口启动 `fgate`、提供假 HTTP/UDP/TCP 服务器的构造函数、等待就绪的轮询、进程回收。现有 `tests/gateway/common.rs` 是雏形。
- 外部程序的替身用 Rust 写的小型可执行文件（放在 `tests/fixtures/`）或直接用 `cfg(test)` 构造的假服务器；需要「假的 `nft` / `iptables` / CLI 程序」时，用一个只把收到的参数追加到文件的 Rust 二进制作为测试夹具（`[[bin]]` + `required-features = ["test-fixtures"]`），不依赖 shell 脚本。
- 所有测试在 macOS 与 Linux 上都可运行；只能在 Linux 上运行的用例用 `#[cfg(target_os = "linux")]` 标注，并在文档中列出。

### 14.3 每个工作包的完成定义

一个工作包同时满足以下条件才算完成：

1. 行为契约中的每一条都有对应的测试，或写明为何无法自动验证并给出手动验证步骤。
2. 与上游的差异（数值、默认值、不支持项）已写进该工作包的文档段落与接口说明。
3. 新增的监听、任务、连接与缓冲都有上限、默认值与到达上限后的行为，并有测试。
4. 新增的 Cargo feature 已进入构建矩阵；`--no-default-features` 仍可编译启动。
5. `cargo fmt --all --check`、`cargo clippy --workspace --locked --all-targets -- -D warnings`、`cargo test --workspace --locked`、`git diff --check` 通过。
6. `README.md` 的能力说明、`docs/DESIGN.md` 的契约与 `docs/EXECUTION.md` 的验证步骤已同步。
7. 对外依赖的真实请求契约有出处（上游代码位置或官方文档链接）。

### 14.4 整体验收

- **功能**：第 3 节功能全量清单中的每一项都对应到已完成的工作包，或有明确记录的未实现原因。
- **兼容**：用上游各模块的配置样例做导入测试（WP-38）全部通过；管理 API 的路径、方法与权限与上游 OpenAPI 文档逐项一致（仅差 FerrumGate 自有的少量接口）。
- **性能**：以现有数据面为基线，同一后端、协议、连接复用与负载分布下比较吞吐、p50/p95/p99、超时、CPU、RSS 与打开文件数；重构到模块框架后的 Web 代理与端口转发不得比当前基线退化超过约定幅度（建议 5%，以实测漂移为准）。HTTP/3 与压缩单独测量。
- **安全**：管理面默认认证；凭据、私钥与用户流量不进入日志与样例；新增的命令执行与文件访问边界有负向测试；`cargo deny` 与 `cargo audit` 无未豁免项。
- **交付物**：六种构建可编译启动；多平台产物、签名、SBOM 与校验文档齐全；`fgate check` 对样例配置目录通过。

## 15. 依赖选型

版本号为 2026-11-25 在 crates.io 核实的最新稳定版（2026-11-26 补充核实的条目见表末说明）；仅作参考，实现时按 `AGENT.md` 用当前注册表可解析的最新版本并保留 `Cargo.lock`。

### 15.1 现有依赖（保持）

`tokio` 1.54、`hyper` 1.13、`hyper-util` 0.1、`hyper-rustls` 0.27、`rustls` 0.23（`ring` 提供方）、`tokio-rustls` 0.26、`hickory-resolver` 0.26、`instant-acme` 0.8、`arc-swap` 1.9、`cap-std` 4.0、`ipnet` 2.12、`serde` / `serde_json`、`toml` 1.2、`tracing`、`clap` 4.6、`anyhow`。工具链：rustc / cargo 1.100.0（本次研读所用环境为 aarch64-apple-darwin）。

### 15.2 新增候选（按用途）

| 用途 | crate（最新稳定版） | 说明 |
|---|---|---|
| 管理服务 | `axum` 0.8.9、`tower` 0.5.3、`tower-http` 0.7.1 | 管理面与中间件链 |
| OpenAPI | `utoipa` 6.0.0、`utoipa-axum` 0.3.0、`schemars` 1.2.3 | 路由、权限与文档出自同一处声明 |
| HTTP/3 | `quinn` 0.11.12、`h3` 0.0.8、`h3-quinn` 0.0.10 | `h3` 系列仍是 0.0.x 且最近一次发布在 2025-05，见决策 D3 |
| WebSocket | `tokio-tungstenite` 0.30.0 | 已在开发依赖中 |
| HTTP 客户端 | `reqwest` 0.13.5 或继续用 `hyper-util` 的连接池 | 需要代理（http / socks5）与自定义 DNS 时评估 `reqwest` |
| 缓存与限流 | `moka` 0.12.16、`governor` 0.10.4 | 响应缓存与令牌桶 |
| 压缩与归档 | `async-compression` 0.4.54、`flate2` 1.1、`brotli`、`tar` 0.4.46、`zip` 9.8、`zstd` 0.14 | `async-brotli` 没有稳定版，brotli 需另行评估 |
| 认证与密码学 | `bcrypt` 0.19.3、`scrypt` 0.12、`aes-gcm` 0.11、`aes` 0.9、`cbc` 0.2、`hmac` 0.13、`sha1` 0.11、`sha2` 0.11、`subtle` 2.6、`totp-rs` 6.0、`webauthn-rs` 0.6.2、`cbor` 0.4.2、`jsonwebtoken` 12.0、`rsa` 0.10、`openidconnect` 4.1、`oauth2` 5.0、`secrecy` 0.10、`zeroize` 1.9、`ed25519-dalek` 3.0.0、`blake2` 0.11.0 | TOTP 也可用 `hmac` + `sha1` 自研以便跑 RFC 向量；后两个用于发布签名的 minisign 格式（WP-93） |
| DNS 与网络 | `ipnet` 2.12、`maxminddb` 0.33、`hickory-client` 0.25、`socket2` 0.6、`if-addrs` 0.15、`network-interface` 2.0、`surge-ping` 0.9 | `ip_network_table`（2021 年后未更新）与 `webrtc-stun`（2021）不建议使用 |
| NAT 穿透 | `igd` 0.12.1（2023 年后未更新）、`stun_codec` 0.4.0 | UPnP 与 STUN 建议自研，报文简单且可控 |
| 防火墙 | `rustables` 0.9.0、`mnl` 0.3.1、`iptables` 0.6.0 | 仅当决定走 netlink 或库封装时使用；首个版本直接执行系统命令 |
| 终端与 SSH | `russh` 0.65.4、`russh-sftp` 4.0、`russh-keys` 0.49.2、`ssh-key` 0.6.7、`portable-pty` 0.9 | `russh-keys` 的版本落后于 `russh`，需要确认兼容性 |
| 文件服务 | `dav-server` 0.12.0、`libunftp` 0.25.1、`unftp-sbe-fs` 0.4.1、`smb` 0.12.1、`cap-std` 4.0、`rustix` 1.1 | `smb` 的服务端成熟度见决策 D5 |
| Docker | `bollard` 0.21.1 | 异步 Docker Engine API 客户端 |
| 运维 | `sysinfo` 0.40.4、`lettre` 0.11.24、`rumqttc` 0.25.1、`cron` 0.17.0、`windows-service` 0.8.1 | |
| MCP | `rmcp` 3.11.0 | 官方 Rust SDK |
| 规则引擎 | `regex` 1.13.2、`fancy-regex` 0.20.2、`pcre2` 0.2.11、`html5ever` 0.40、`ammonia` 4.2.5 | `pcre2` 带 C 代码，只在 `fancy-regex` 出现兼容性缺口时启用 |
| 管理界面 | `leptos` 0.8.23、`leptos_router` 0.8.17、`thaw` 0.4.8、`trunk` 0.22.2、`wasm-bindgen` 0.2.130、`wasm-bindgen-test` 0.3.80、`web-sys` 0.3.107、`askama` 0.16.1 | `thaw` 相对 `leptos` 更新较慢，选用前先评估 |
| 发布 | `minisign-verify` 0.3.0、`cargo-deny` 0.22.1、`cargo-audit` 0.23.0、`cargo-auditable` 0.7.8、`cargo-cyclonedx` 0.5.10、`cargo-hack` 0.6.46、`cargo-zigbuild` 0.24.1 | |
| 测试 | `proptest` 1.12、`tempfile` 3.27、`rcgen` 0.14.10、`csv` 1.4、`loom` 0.7.3 或 `shuttle` 0.9.10 | 后两个是并发状态机的模型检测工具，选用前先各做一个小样 |

2026-11-26 补充核实（crates.io 当日最新稳定版）：`sysinfo`、`web-sys`、`wasm-bindgen-test`、`ed25519-dalek`、`blake2`、`loom`、`shuttle`。另有两个结论影响选型：`rustls-rustcrypto`（纯 Rust 的 TLS 加密提供方）在 crates.io 上只有 `0.1.0-pre.0` 预发布版，不能作为发布依赖；名为 `cross` 的 crates.io 包是 2023 年的 0.2.5、与交叉编译工具无关，该工具要从它的 GitHub 发布页安装并固定版本与校验和。

### 15.3 选型约束

- 能用纯 Rust 实现的不引入 C 依赖；确需 C 依赖（`pcre2`、`ring` 已存在）时在 `Cargo.toml` 注明原因。
- 新增直接依赖须在 `Cargo.toml` 写明用途，传递依赖由 Cargo 求解；更新后用 `cargo tree --locked --depth 1` 核对。
- 候选 crate 在引入前先做一次最小验证（能否在目标平台上编译、许可是否兼容、维护是否活跃），结论写进对应工作包。
- 不引入 `coraza` 的 C 绑定或其他需要 Go 工具链的方案（见 D4）。

## 16. 风险、决策点与回滚

### 16.1 决策点

实现前需要确认的决策。每项给出推荐值；改动推荐值只影响对应工作包，不影响整体路线。

| 编号 | 决策 | 推荐 | 备选与影响 |
|---|---|---|---|
| D1 | 配置模型 | 改为「配置目录 + 每模块一个明文 JSON」，JSON 字段名与上游一致 | 保留 TOML：需要为每个接口写映射层，且无法直接导入 Gately 配置目录 |
| D2 | 管理面技术栈 | axum + tower，运行在现有的 Tokio / hyper 之上 | 自研路由：中间件链与 OpenAPI 生成的工作量更大 |
| D3 | HTTP/3 | `quinn` + `h3`，放在 WP-21 的最后一个切片 | `cloudflare/quiche`（C++）；或先只通告 `Alt-Svc` 不提供 h3（功能不完整）。`h3` crate 仍是 0.0.x，需要先做可行性验证 |
| D4 | WAF 规则引擎 | 分两层：集成层先做；规则引擎用纯 Rust 自研，按 WP-55 的四步交付，以 CRS 回归用例通过率为门槛 | 外置 Coraza 进程（需要 Go 运行时，且不能称为 Rust 实现）；或只支持雷池检测引擎（功能不完整） |
| D5 | SMB 服务端 | 先做配置模型与管理接口，再对 `smb` crate 做可行性验证；不通过则改为托管 Samba | 完全自研 SMB 2/3（工作量最大）；或延后到其他模块之后 |
| D6 | 管理界面 | Rust WASM（Leptos），个别重交互叶子组件允许封装 JS 库 | 复用上游 Vue 前端（最快，但不是 Rust 实现）；服务端渲染 |
| D7 | 防火墙下发方式 | 执行 `nft` / `iptables` / `ipset` 可执行文件（参数数组或标准输入脚本） | netlink（`rustables` / `mnl`）：不依赖可执行文件，但实现与调试成本更高 |
| D8 | SSH 客户端 | `russh` 系列 | 仅支持系统 `ssh` 可执行文件（功能与体验受限） |
| D9 | 管理界面默认端口 | 沿用 16680，与上游一致，便于迁移与文档对照 | 另选端口：需要同步修改文档、CLI 默认地址与 Dockerfile |
| D10 | 保留路径与 Cookie 名 | 保留 `__gately_*` 路径与 `gately_*` Cookie 名 | 改名：已登记的 OAuth 回调地址失效，双层 Gately 与迁移场景需要重新配置 |
| D11 | TLS 最低版本 1.0 / 1.1 | rustls 不实现 1.0 与 1.1；配置为这两个值时按 1.2 处理并在界面提示 | 引入支持旧版本的 TLS 库：不建议 |
| D12 | 指标前缀 | 统一为 `ferrumgate_`，指标名与标签其余部分与上游一致 | 沿用 `gately_`：可直接套用上游 Grafana 面板，但与本项目的命名不一致 |
| D13 | ICMP Ping | 只用无特权 ICMP 套接字，不可用时返回明确错误 | 也尝试原始套接字：需要 root 或 `CAP_NET_RAW` |
| D14 | 初始管理员密码（WP-12） | 首次启动生成随机初始密码，打印在标准输出并写入日志一次，首次登录强制修改 | 沿用上游的固定默认密码 `admin` / `gately.cn`：迁移与文档对照最省事，但公网暴露的实例在改密前人人可登录 |
| D15 | 导航面板页面上的访客侧交互（WP-86） | 用 Rust WASM（只用 `wasm-bindgen` 的极小模块，页面渲染后异步加载；没有脚本时链接仍可点） | 保留一段内联的原生 JS：体积最小，但是项目里唯一的非 Rust 代码；纯 CSS 渐进增强：搜索过滤与换肤做不到 |
| D16 | 名称前缀 | 环境变量、配置文件、服务名、镜像名用本项目的前缀（`FERRUMGATE_CONFIG_DIR`、`ferrumgate.json`、服务名 `ferrumgate`） | 全部沿用上游名称：从 Gately 迁移最无感，但本项目与上游在同一台机器上会互相覆盖 |
| D17 | 防火墙里的名称（WP-51、WP-54） | 沿用上游：nftables 的表 `gately`、`gately_knock` 与链名，iptables 的 `GATELY_*` 链，ipset 的 `gately_ban4` / `gately_ban6` | 改成 `ferrumgate_*`：与本项目的命名一致，但防火墙快照、排障文档与迁移时的旧规则清理都要跟着改 |

### 16.2 风险与回滚

| 风险 | 可能性 | 影响 | 缓解 | 回滚 |
|---|---|---|---|---|
| WAF 引擎无法达到 CRS 兼容目标 | 高 | 高 | 分层设计：集成层、雷池客户端与站点集成独立交付；引擎按步验收，不达标不设为默认 | 关闭 `waf` feature 或仅保留雷池路径 |
| SMB 服务端没有可用的 Rust 实现 | 高 | 中 | 可行性验证前置；备选为托管 Samba | `smb` 保留接口与配置模型，实现延后 |
| HTTP/3 crate 不够成熟 | 中 | 中 | 可行性验证；先交付 `Alt-Svc` 之后的完整 h3 路径并单独测量 | 关闭 HTTP/3 配置项，监听不受影响 |
| 防火墙规则误伤管理员 | 中 | 高 | 登录免封、白名单默认含内网与回环、规则渲染快照测试、网络命名空间验证；自身保护参照 Docker 的做法 | 关闭防火墙同步；恢复用「仅对 Gately 自身服务生效」的降级路径 |
| 配置模型迁移破坏现有部署 | 中 | 高 | WP-39 的迁移命令 + 现有全部集成测试在转换后的配置上通过；保留一个版本的 TOML 兼容入口 | 回退到迁移前的二进制与配置（迁移只写目标目录） |
| 模块框架重构使数据面性能退化 | 中 | 中 | 重构前后用同一负载对比；热路径保持「每请求只读一次快照」 | 按提交逐个模块回退；`fg-gateway` 在迁移期间保持可用 |
| 管理界面工作量超出预期 | 高 | 中 | 先 API 后界面；界面按页交付，每页可独立上线；上游前端可作为对照 | 界面进度不影响 API 与 CLI 的可用性 |
| 路由器架构（mips、mipsle、riscv64）上加密后端不可用 | 高 | 中 | **已确认存在**：`ring` 0.17.14 的构建脚本只面向 aarch64、arm、x86、x86_64，这三个架构都不在其中（19 个发布目标里的 6 个）。WP-92 的步骤 1 提前到 WP-90 之前做：在全部目标上构建并完成一次 TLS 握手；备选依次为 `aws-lc-rs` 1.19.0（同样不含 mips）、自写的最小 `CryptoProvider`（纯 Rust，最可能的路线；现成的 `rustls-rustcrypto` 只有预发布版） | 这三个架构暂不发布，列入已知限制（与上游的偏差，需用户确认） |
| 上游持续快速演进导致对齐目标漂移 | 高 | 中 | 基线冻结在 `442162e4d0b6`；之后的上游变更作为增量对齐，不混入本方案 | — |
| 真实环境验证不足（Linux、NET_ADMIN、Windows） | 中 | 中 | 每个相关工作包列出需真实环境验证的条目；开发机为 macOS 时使用 Linux 虚拟机或容器 | 相关工作包保持「未验证」状态，不宣称完成 |
| 供应链与许可证 | 低 | 高 | `cargo deny`（许可与来源）+ `cargo audit`；复用上游前端或资产时核对 Apache-2.0 的署名义务 | 替换或移除有问题的依赖 |

### 16.3 已知不迁移或有意不同的部分

- Go 运行时调优项（`gcPercent`、`maxProcs`）：无对应物，读取时忽略。
- TLS 1.0 / 1.1：不实现（D11）。
- 上游的 fnOS 专用集成（统一网关登录、系统证书来源、`.fpk` 打包）：保留为可选切片，不阻塞其他工作包。
- 上游界面中的 15 套主题、登录页与错误页的全部样式：作为资产迁移，逻辑不变；样式的像素级一致性不在验收范围内。
- ICMP 原始套接字路径（D13）。
- Windows 与 macOS 上的在线升级：上游也只在 Linux 二进制部署中开放，本项目保持一致（WP-94）。
- 在线构建站点的后端：上游的 `build.gately.cn` 后端不在仓库里，本项目按文档描述的行为自行设计（WP-96，可选）。
- 与上游一致地保留的两处限制：定制构建不能在线升级（下载的是完整版），只能上传升级包；构建站点生成的产物同样如此。

## 17. 进度跟踪表

执行时每完成一个工作包，把状态从「未开始」改为「进行中」或「已完成」，并在备注里写上提交号或验证记录的位置。状态以可执行的测试与文档更新为依据。

| 工作包 | 名称 | 规模 | 依赖 | 状态 |
|---|---|---|---|---|
| WP-00 | 配置目录与存储 | S | — | 已完成，见 [验收记录](EXECUTION.md#wp-00-配置目录存储) |
| WP-01 | 模块框架与注册表 | M | WP-00 | 已完成，见 [验收记录](EXECUTION.md#wp-01-模块框架与注册表) |
| WP-02 | 配置历史、差异与回滚 | S | WP-00 | 已完成，见 [验收记录](EXECUTION.md#wp-02-配置历史差异与回滚) |
| WP-03 | 进程装配、启动参数与重启 | M | WP-00、WP-01 | 未开始 |
| WP-04 | 保存后确认与自动回滚 | M | WP-02、WP-03、WP-11 | 未开始 |
| WP-05 | 批量修改与访问路径识别 | M | WP-04 | 未开始 |
| WP-06 | 声明式配置 | S | WP-00、WP-02 | 未开始 |
| WP-07 | 全局设置 | S | WP-00、WP-11 | 进行中（设置模型、校验与管理 API 持久化） |
| WP-08 | 审计日志 | S | WP-11 | 未开始 |
| WP-09 | 运行日志系统 | M | WP-00 | 已完成库阶段，见 [验收记录](EXECUTION.md#wp-09-目录切换与归档时间裁剪) |
| WP-10 | 国际化 | M | — | 未开始 |
| WP-11 | 管理 API 框架 | L | WP-01 | 进行中 |
| WP-12 | 管理员认证与会话 | L | WP-11 | 本地实现及回环验收（真实提供方与实机验收待完成） |
| WP-13 | API 令牌 | S | WP-11、WP-12 | 本地实现与回环验收完成，见 [验收记录](EXECUTION.md#wp-13-创建与使用-api-令牌) |
| WP-14 | 管理访问控制与界面入口 | M | WP-12、WP-31 | 未开始 |
| WP-15 | CLI、回滚命令与 MCP | M | WP-02、WP-11、WP-13 | 未开始 |
| WP-16 | 事件总线 | S | — | 已完成，见 [验收记录](EXECUTION.md#wp-16-事件总线) |
| WP-17 | 总览、自检与系统接口 | M | WP-01、WP-16 | 未开始 |
| WP-20 | Web 服务配置模型 v2 | L | WP-01、WP-39 | 未开始 |
| WP-21 | 监听器与传输协议 | L | WP-20、WP-31 | 未开始 |
| WP-22 | 站点类型 | M | WP-20 | 未开始 |
| WP-23 | 后端、负载均衡、健康检查与超时 | L | WP-20 | 未开始 |
| WP-24 | 站点认证：基本认证、网页认证与共享用户 | L | WP-12、WP-22 | 未开始 |
| WP-25 | 站点认证：第三方登录、Passkey、转发认证与信任传递 | L | WP-24 | 未开始 |
| WP-26 | 访问控制 | L | WP-24、WP-50 | 未开始 |
| WP-27 | 性能：压缩、限流、缓存与错误页 | L | WP-22 | 未开始 |
| WP-28 | 可观测性：统计、连接、拓扑、访客审计与指标 | L | WP-09、WP-22 | 未开始 |
| WP-29 | 导航面板 | M | WP-22 | 未开始 |
| WP-30 | 配置导入与站点批量操作 | L | WP-20、WP-22、WP-05 | 未开始 |
| WP-31 | 证书条目模型与多种来源 | M | WP-01 | 未开始 |
| WP-32 | ACME 签发与续期对齐 | M | WP-31、WP-21、WP-41 | 未开始 |
| WP-33 | 证书映射与自动部署 | M | WP-31、WP-60、WP-61 | 未开始 |
| WP-34 | 端口转发对齐 | M | WP-01、WP-36 | 未开始 |
| WP-35 | 协议分流 | L | WP-36、WP-54 | 未开始 |
| WP-36 | L4 共用基础 | S | WP-01 | 未开始 |
| WP-37 | 自动放行防火墙 | M | WP-36 | 未开始 |
| WP-38 | 导入 Gately 配置目录 | M | 各模块配置模型 | 未开始 |
| WP-39 | 迁移现有 TOML 配置 | M | WP-20、WP-31、WP-34 | 未开始 |
| WP-40 | 动态域名任务 | M | WP-16、WP-41 | 未开始 |
| WP-41 | DNS 提供商适配 | L（分三批） | — | 未开始 |
| WP-42 | STUN 穿透 | L | WP-36、WP-16 | 未开始 |
| WP-43 | 托管程序基础设施 | M | WP-09 | 未开始 |
| WP-44 | frp | L | WP-43、WP-36 | 未开始 |
| WP-45 | Tailscale、NetBird 与 EasyTier | L | WP-43 | 未开始 |
| WP-46 | Cloudflare Tunnel | M | WP-43 | 未开始 |
| WP-50 | 统一封禁表 | M | WP-16 | 未开始 |
| WP-51 | 防火墙同步 | L | WP-50、WP-37 | 未开始 |
| WP-52 | 日志规则与事件来源 | L | WP-50、WP-16、WP-28 | 未开始 |
| WP-53 | 诱饵端口、端口扫描检测与 IPv6 严格模式 | M | WP-51 | 未开始 |
| WP-54 | 单包授权与放行 | L | WP-50、WP-51 | 未开始 |
| WP-55 | WAF 实例与站点集成 | XL（引擎层） | WP-23 | 未开始 |
| WP-56 | 内置 OIDC 单点登录提供方 | M | WP-24 | 未开始 |
| WP-60 | Docker 管理 | XL | WP-61 | 未开始 |
| WP-61 | Web 终端 | L | WP-09 | 未开始 |
| WP-62 | 计划任务 | S | WP-01 | 未开始 |
| WP-63 | 文件服务共享用户与 WebDAV | M | WP-24 | 未开始 |
| WP-64 | FTP 与 FTPS | M | WP-63、WP-31 | 未开始 |
| WP-65 | SMB | XL（自研）或 M（托管 Samba） | WP-63 | 未开始 |
| WP-66 | File Browser | S | WP-43 | 未开始 |
| WP-67 | 存储挂载 | M | WP-65 | 未开始 |
| WP-68 | 通知中心 | M | WP-16 | 未开始 |
| WP-69 | 性能监控 | M | WP-17、WP-28 | 未开始 |
| WP-70 | 配置备份 | M | WP-67 | 未开始 |
| WP-71 | 网络诊断 | M | WP-01 | 未开始 |
| WP-72 | 网络唤醒 | M | WP-61 | 未开始 |
| WP-80 | 管理界面基座 | L | WP-11、WP-12 | 未开始 |
| WP-81 | 列表通用能力 | M | WP-80 | 未开始 |
| WP-82 | 核心配置页 | XL | WP-81 及对应模块 | 未开始 |
| WP-83 | 可视化页 | XL | WP-28、WP-69、WP-80 | 未开始 |
| WP-84 | 运维页 | XL | WP-60～WP-72、WP-81 | 未开始 |
| WP-85 | 系统页 | L | WP-80、WP-13、WP-70 | 未开始 |
| WP-86 | 服务端渲染的对外页面 | M | WP-24、WP-27、WP-29 | 未开始 |
| WP-90 | 定制构建与模块清单 | M | WP-01 | 未开始 |
| WP-91 | 持续集成 | M | — | 未开始 |
| WP-92 | 多平台构建与打包 | L | WP-90 | 未开始 |
| WP-93 | 签名、来源证明与校验 | M | WP-92 | 未开始 |
| WP-94 | 更新检查与在线升级 | M | WP-03、WP-93 | 未开始 |
| WP-95 | 系统服务与安装 | M | WP-03 | 未开始 |
| WP-96 | 构建站点后端（可选） | M | WP-90、WP-91 | 未开始 |

规模含义：S ≤ 1 周，M 约 1～2 周，L 约 3～5 周，XL ≥ 6 周（单人、含测试与文档的粗估，仅用于排期比较）。

### 17.1 推荐执行顺序

1. **P0 骨架**：WP-00 → WP-01 → WP-02 → WP-16 → WP-09 → WP-11 → WP-12 → WP-13 → WP-07 → WP-08 → WP-03 → WP-06 → WP-10 → WP-15 → WP-17 → WP-04 → WP-05 → WP-14。每完成一步，现有数据面都保持可运行。
2. **P1 数据面**：WP-36 → WP-34 → WP-39 → WP-20 → WP-22 → WP-23 → WP-31 → WP-32 → WP-21 → WP-24 → WP-25 → WP-26（先用封禁表的测试桩）→ WP-27 → WP-28 → WP-35 → WP-37 → WP-29 → WP-30 → WP-33 → WP-38。
3. **P3 安全中不依赖界面的部分**：WP-50 → WP-54 → WP-55 的集成层 → WP-52 → WP-51 → WP-53 → WP-56。WAF 引擎层（WP-55 第 1～4 步）作为长期并行任务。
4. **P2 网络自动化**：WP-41 第一批 → WP-40 → WP-42 → WP-43 → WP-44 → WP-46 → WP-45 → WP-41 第二、三批。
5. **P4 运维工具**：WP-68 → WP-70 → WP-62 → WP-61 → WP-63 → WP-64 → WP-66 → WP-67 → WP-60 → WP-69 → WP-71 → WP-72 → WP-65。
6. **P5 界面**：WP-80 → WP-81 → WP-82（随各模块页面逐页交付）→ WP-85 → WP-83 → WP-84 → WP-86。
7. **P6 发布**：WP-90、WP-91 可以在 P0 之后任何时间开始。其中 **WP-90 的前四步（模块清单 `features.toml`、生成的 Cargo features、`resolve`、一致性检查）必须在第一个可选模块 WP-40 动工之前完成**——可选模块的 crate 从一开始就要声明为可选依赖；其余步骤（六种构建矩阵、语言档位、`fg-gateway` 的拆分、体积基准）留在 P6。加密提供方对路由器架构的可行性验证（WP-92 步骤 1）也要尽早做，它决定 19 个发布目标里能不能保住 6 个。之后 WP-92 → WP-93 → WP-94 → WP-95 → WP-96。


## 附录 A 上游各模块的规模与接口数量

行数来自上游快照的统计（非测试 / 测试），接口数为该模块前缀下的操作数，已包含每个模块都有的 4 个通用日志接口（查看、来源、导出、清空）。这些数字用于估计工作量与确定实现顺序，不是验收目标。

| 模块 ID | 非测试行数 | 测试行数 | 测试文件 | 管理接口操作数 | 配置文件 | 分组 |
|---|---:|---:|---:|---:|---|---|
| `portforward` | 1140 | 1814 | 12 | 16 | `portforward.json` | 网络（核心） |
| `protoroute` | 2680 | 2954 | 13 | 16 | `protoroute.json` | 网络 |
| `ddns` | 1925 | 1605 | 6 | 25 | `ddns.json` | 网络 |
| `stun` | 2218 | 1226 | 6 | 18 | `stun.json` | 组网与穿透 |
| `tailscale` | 1419 | 633 | 4 | 28 | `tailscale.json` | 组网与穿透 |
| `netbird` | 1984 | 1532 | 3 | 28 | `netbird.json` | 组网与穿透 |
| `easytier` | 1491 | 1049 | 4 | 27 | `easytier.json` | 组网与穿透 |
| `frp` | 3300 | 2633 | 15 | 49 | `frp.json` | 组网与穿透 |
| `cloudflared` | 1157 | 636 | 5 | 27 | `cloudflared.json` | 组网与穿透 |
| `ssl` | 3050 | 2216 | 9 | 23 | `ssl.json` | Web（核心） |
| `waf` | 1678 | 1206 | 6 | 17 | `waf.json` | Web |
| `webservice` | 24434 | 25822 | 117 | 81 | `webservice.json` | Web（核心） |
| `guard` | 6221 | 4084 | 13 | 23 | `guard.json` | 网络 |
| `knock` | 3413 | 3105 | 9 | 20 | `knock.json` | 网络 |
| `wol` | 2185 | 1639 | 5 | 30 | `wol.json` | 工具 |
| `webterminal` | 5081 | 2783 | 9 | 64 | `webterminal.json` | 工具 |
| `cron` | 307 | 95 | 1 | 16 | `cron.json` | 工具 |
| `docker` | 8276 | 3926 | 10 | 69 | `docker.json` | 工具 |
| `nettools` | 1242 | 262 | 1 | 11 | `nettools.json` | 工具 |
| `webdav` | 540 | 951 | 6 | 9 | `webdav.json` | 文件服务 |
| `ftp` | 671 | 1090 | 7 | 9 | `ftp.json` | 文件服务 |
| `smb` | 1050 | 1191 | 5 | 9 | `smb.json` | 文件服务 |
| `filebrowser` | 966 | 778 | 4 | 25 | `filebrowser.json` | 文件服务 |
| `storage` | 1325 | 548 | 4 | 21 | `storage.json` | 文件服务 |
| `backup` | 485 | 168 | 1 | 21 | `backup.json` | 文件服务 |
| `notify` | 1692 | 1549 | 11 | 32 | `notify.json` | 系统 |
| `perf` | 1532 | 1226 | 6 | 19 | `perf.json` | 系统 |

平台部分（`internal/` 中除 `modules` 与 `gosamba` 之外的包）非测试约 5.7 万行，其中与管理后台直接相关的主要包：

| 包 | 职责 | 对应工作包 |
|---|---|---|
| `internal/app` | 管理后台装配、API 路由、设置、账号、令牌、确认与回滚、系统接口 | WP-03～WP-08、WP-12～WP-15、WP-17 |
| `internal/crud` | 通用集合接口 | WP-11 |
| `internal/config` | 配置存储、历史、差异 | WP-00、WP-02 |
| `internal/module`、`internal/modules/registry` | 模块接口与注册表 | WP-01 |
| `internal/auth`、`internal/webauthn`、`internal/thirdauth`、`internal/apitoken` | 认证 | WP-12、WP-13、WP-25 |
| `internal/logbuf`、`internal/i18n`、`internal/events` | 日志、国际化、事件 | WP-09、WP-10、WP-16 |
| `internal/httpx`、`internal/trustsrc` | 请求工具、客户端地址、同源校验 | WP-11、WP-14 |
| `internal/iplist`、`internal/geoip`、`internal/fwopen`、`internal/openports`、`internal/banlist` | 来源规则、GeoIP、防火墙放行、开放端口、封禁表 | WP-26、WP-36、WP-37、WP-50、WP-53 |
| `internal/dnsprovider`、`internal/resolver` | DNS 提供商与自定义解析 | WP-41 |
| `internal/l4proxy`、`internal/netpipe`、`internal/stun`、`internal/upnp` | L4 与穿透的共用基础 | WP-36、WP-42 |
| `internal/proc`、`internal/binstall` | 托管进程与在线安装 | WP-43 |
| `internal/sysstat`、`internal/visitors` | 系统指标、访客审计 | WP-17、WP-28、WP-69 |
| `internal/minisign`、`internal/releasesig`、`internal/service` | 签名校验、系统服务 | WP-93、WP-94、WP-95 |
| `internal/webpage` | 服务端渲染的登录页与导航面板 | WP-24、WP-29、WP-86 |

## 附录 B 上游文档页索引

实现某个工作包时先读对应的中文文档页（`https://gately.cn/docs/` 为根）。

| 页面 | 内容 | 工作包 |
|---|---|---|
| `guide/introduction`、`guide/quick-start`、`guide/install` | 项目定位、快速开始、安装与系统服务、重置密码 | WP-03、WP-95 |
| `guide/configuration` | 命令行参数、配置目录、声明式配置、运行日志、保存确认、批量修改、命令行回滚 | WP-03、WP-04、WP-05、WP-06、WP-09 |
| `guide/lists` | 列表的分组、排序、批量与复制 | WP-81 |
| `guide/cli-mcp` | `ctl` 与 `mcp` | WP-15 |
| `guide/security`、`guide/hardening`、`guide/verify` | 安全模型、加固清单、校验发布产物 | WP-12、WP-14、WP-93 |
| `guide/audit` | 操作审计与配置历史 | WP-02、WP-08 |
| `guide/migration` | 从其他工具迁移 | WP-30、WP-38 |
| `guide/benchmarks`、`guide/faq` | 性能对比、常见问题 | 性能验收的参照 |
| `modules/`（总览）、`modules/web`、`modules/ssl`、`modules/portforward`、`modules/protoroute` | 核心模块 | WP-20～WP-39 |
| `modules/ddns`、`modules/stun`、`modules/tunnels` | 网络自动化 | WP-40～WP-46 |
| `modules/oidc`、`modules/waf`、`modules/guard`、`modules/knock` | 安全 | WP-50～WP-56 |
| `modules/docker`、`modules/terminal`、`modules/tools`、`modules/notify`、`modules/perf`、`modules/backup`、`modules/nettools` | 运维工具 | WP-60～WP-72 |
| `reference/api`、`reference/api-reference`、`reference/monitoring`、`reference/docker-api`、`reference/webterminal-api`、`reference/diagnostics` | 接口与运维参考 | WP-11、WP-17、WP-28、WP-60、WP-61 |
| `tutorials/*` | 25 篇教程（替换 haproxy 与 nginx、一个端口 443、端口敲门、STUN 穿透、站点访问控制等） | 端到端验收场景的来源 |
