> Historical proposal. Current contracts and commands are in [DESIGN.md](DESIGN.md) and [EXECUTION.md](EXECUTION.md).

**EXECUTION.md — FerrumGate Architecture Execution Plan (English Version)**

**Version 1.1 — Detailed, Executable, Production-Grade**

---

## 1. Executive Summary

**Feasibility: High.** Rust’s ecosystem covers every Gately capability with production-grade crates. The two engineering
hotspots are:

1. **WAF**: `coraza-rs` (safe Rust bindings to OWASP Coraza, based on the official C bindings) guarantees OWASP CRS v4
   parity without reimplementing SecLang. The build requires Go ≥1.21 and a C compiler; the first build compiles the Go
   WAF engine into a static library, subsequent builds are fast.
2. **DDNS provider breadth**: Gately supports 11 providers. FerrumGate ships a `Provider` trait and implements 5 in M1,
   remaining 6 in M2.

Cargo Features map cleanly to Gately's `no_<module>` build tags. The build site logic is a thin validation layer over
`cargo build`. Gately’s own documentation confirms that apart from Port Forwarding, Web Services, and SSL Certificates
(the three core modules), all other modules can be removed at compile time; build.gately.cn generates binaries, OpenWrt
packages, fnOS installers, and multi-arch Docker images from user selections, with volume estimation on the page.

---

## 2. Milestone Plan (Detailed Task Breakdown)

### M0 — Skeleton & Alignment (2 weeks)

**Objective:** Establish a compilable, CI-verified workspace with consistent feature manifests and a working `xtask`
codegen pipeline.

| #    | Task                                                                                                           | Deliverable                | Acceptance                                                        |
|------|----------------------------------------------------------------------------------------------------------------|----------------------------|-------------------------------------------------------------------|
| M0.1 | Create workspace with `resolver = "3"`, edition 2024, MSRV 1.85                                                | `Cargo.toml`               | `cargo metadata` succeeds                                         |
| M0.2 | Author `features.toml` with all 25 features (3 core + 22 optional)                                             | `features.toml`            | `xtask check-features` exits 0                                    |
| M0.3 | Implement `xtask codegen`: generate `registry.generated.rs`, `modules.json`, `web/src/generated/features.json` | Three generated artefacts  | Generated files match committed copies                            |
| M0.4 | Implement `fg-core`: `Module` trait, `Registry`, `ModuleContext`, `RiskLevel`, error types                     | `crates/fg-core`           | Unit tests for dependency validation and conditional registration |
| M0.5 | Implement `fg-config` schema with `serde`, validation, and feature-aware parsing                               | `crates/fg-config`         | Config referencing uncompiled module produces actionable error    |
| M0.6 | CI pipeline: fmt, clippy, `cargo hack` feature matrix, `check-features`                                        | `.github/workflows/ci.yml` | All gates pass on a stub binary                                   |
| M0.7 | Verify `cargo build --no-default-features`, default, `--all-features`                                          | CI matrix entries          | All three compile                                                 |

**Exit criteria:** Default, minimal (`core`), and all-features builds pass; `xtask check-features` is green; CI fails on
any manifest drift.

---

### M1 — Core Gateway MVP (4 weeks)

**Objective:** A production-usable reverse proxy with automatic TLS, certificate management, admin API, and embedded Web
UI.

#### M1.1 Reverse Proxy (`fg-proxy`)

Use `axum` + `hyper` + `tower`, with `axum-reverse-proxy` as a reference for correct hop-by-hop header stripping,
`X-Forwarded-*` handling, WebSocket upgrades, and gRPC trailers.

| Task                              | Detail                                                                                             | Test                                    |
|-----------------------------------|----------------------------------------------------------------------------------------------------|-----------------------------------------|
| HTTP/1.1 and HTTP/2 listener      | `hyper` auto-detect; configurable per-site                                                         | Integration: curl against backend       |
| TLS termination with SNI resolver | `rustls` `ResolvesServerCert` trait; hostname→cert radix tree                                      | Two virtual hosts with distinct certs   |
| WebSocket passthrough             | `tower-http` upgrade handling                                                                      | Echo test through proxy                 |
| gRPC trailer preservation         | Do **not** strip `grpc-status` / `grpc-message`                                                    | `tonic` health check through proxy      |
| Load balancing                    | Round-robin + health check (`/healthz` per backend)                                                | Fail one backend, verify traffic shifts |
| Middleware chain (feature-gated)  | `[WAF]` → `[ban]` → `[auth]` → router, each a `tower::Layer` inserted only under `#[cfg(feature)]` | Disable feature, verify layer absent    |

#### M1.2 Certificate Store (`fg-certs`) and ACME (`fg-acme`)

`instant-acme` is an async, pure-Rust RFC 8555 client, used in production at Instant Domain Search; it relies on Tokio
and rustls.

| Task                | Detail                                                                                       |
|---------------------|----------------------------------------------------------------------------------------------|
| Certificate storage | SQLite table `certificates(domain, cert_pem, key_pem, expires_at, issuer)`                   |
| Manual import       | `fgate certs import --domain example.com --cert ./fullchain.pem --key ./privkey.pem`         |
| ACME account        | ECDSA key generated on first use; serialized credentials stored encrypted                    |
| ACME order flow     | `Account::new_order` → HTTP-01 or DNS-01 challenge → finalize → download cert                |
| Renewal scheduler   | Background task checks `expires_at - 30 days`; exponential backoff on failure: 1h → 6h → 24h |
| Failure fallback    | Log alert; retain previous cert; expose `fgate_acme_renewal_failures_total`                  |

#### M1.3 Admin API (`fg-api`) and Web UI (`fg-webui`)

| Endpoint             | Method    | Auth                       |
|----------------------|-----------|----------------------------|
| `/api/v1/health`     | GET       | None (loopback or token)   |
| `/api/v1/modules`    | GET       | Bearer token               |
| `/api/v1/config`     | GET / PUT | Bearer token + CSRF/Origin |
| `/api/v1/certs`      | GET       | Bearer token               |
| `/api/v1/acme/renew` | POST      | Bearer token               |
| `/api/v1/metrics`    | GET       | Loopback only              |

First boot generates a one-time admin token written to `data/admin.token` with mode `0600`; token is invalidated after
first login and password change.

#### M1.4 Observability Baseline

| Signal          | Implementation                                                                                                              |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------|
| Structured logs | `tracing` with JSON formatter; request ID propagated via `tower-http::trace`                                                |
| Metrics         | `metrics` crate + `metrics-exporter-prometheus`; registered at startup                                                      |
| Audit log       | SQLite table `audit(ts, actor, action, resource, outcome, metadata_json)`; written for login, config change, cert operation |
| Health probes   | `/healthz` (liveness) and `/readyz` (readiness: config loaded, storage open, listeners bound)                               |

**M1 Exit Criteria:** Real HTTP/HTTPS proxying through two virtual hosts; certificate import and ACME staging issuance
succeed; API requires authentication; audit records present; Prometheus metrics scrapeable.

---

### M2 — Security & Authentication (4 weeks)

#### M2.1 WAF (`fg-waf`)

`coraza-rs` provides safe Rust bindings to OWASP Coraza via the official C bindings; Coraza is a Go-based WAF compatible
with ModSecurity’s SecLang. Build dependencies: Go ≥1.21, C compiler, libclang.

| Task                   | Detail                                                                                                                                                                                 |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Build integration      | `build.rs` invokes `go build -buildmode=c-archive`; link `libcoraza.a`                                                                                                                 |
| WAF instance lifecycle | One `WafConfig` per site, loaded at startup; `DetectionOnly` or `On` configurable                                                                                                      |
| Transaction processing | Phase 0 (connection/URI) → Phase 1 (request headers) → Phase 2 (request body, if `SecRequestBodyAccess On`) → Phase 3 (response headers) → Phase 4 (response body) → Phase 5 (logging) |
| Failure mode           | Admin plane: `fail-close` (block on WAF error). Business plane: `fail-open` default, configurable and logged                                                                           |
| Custom rules           | `SecRule` directives loadable from file; CRS v4 loaded from embedded or mounted ruleset                                                                                                |
| Metrics                | `fgate_waf_interventions_total{site, action}`                                                                                                                                          |

**Test:** A request containing a known CRS trigger (e.g., `?id=1' OR '1'='1`) must produce a 403 when
`SecRuleEngine On`; the same request passes in `DetectionOnly`.

#### M2.2 Intrusion Prevention (`fg-ban`)

`fail2ban-rs` is a pure-Rust replacement with a single ~5 MB binary, nftables/iptables/ipset backends, and per-jail sets
in `table inet fail2ban-rs`.

| Task             | Detail                                                                                       |
|------------------|----------------------------------------------------------------------------------------------|
| Log rule engine  | Regex/two-phase matching against `fgate` access logs; per-jail thresholds and durations      |
| nftables backend | `executor_nftables` creates `table inet ferrumgate-ban`, per-jail sets; teardown on shutdown |
| Ban escalation   | First ban 10 min → repeat 1 h → persistent 24 h (configurable per jail)                      |
| Whitelist        | CIDR set always excluded; loopback and private ranges whitelisted by default                 |
| IPv6 handling    | Port-scan bans use `/64` strict mode; single-IP bans use `/128`                              |
| API              | `POST /api/v1/ban` (manual), `DELETE /api/v1/ban/{ip}`                                       |

**Test:** Trigger 5 failed auth attempts within 60 s; verify IP appears in `nft list set inet ferrumgate-ban sshd`;
after ban duration, verify removal.

#### M2.3 Authentication (`fg-auth`)

| Sub-feature               | Crate                     | Test                                                   |
|---------------------------|---------------------------|--------------------------------------------------------|
| Local auth                | `argon2` password hashing | Login, logout, session expiry                          |
| OIDC (`auth-oidc`)        | `openidconnect`           | Mock IdP; token validation; claim mapping              |
| TOTP (`auth-totp`)        | `totp-rs`                 | Enroll, verify, reject wrong code                      |
| Passkeys (`auth-passkey`) | `webauthn-rs`             | Registration and assertion with software authenticator |

**M2 Exit Criteria:** OWASP CRS core rules pass in blocking mode; bans visible in `nft list ruleset`; MFA login works;
all security tests pass.

---

### M3 — Optional Modules (5 weeks)

#### M3.1 DDNS (`fg-ddns`)

Gately supports 11 DNS providers, URL/NIC/command IP detection, IPv4/IPv6, and Webhook.

| Task                          | Detail                                                                                   |
|-------------------------------|------------------------------------------------------------------------------------------|
| `Provider` trait              | `async fn update(&self, domain: &str, ip: IpAddr) -> Result<UpdateOutcome>`              |
| IP detection strategies       | URL (`reqwest`), NIC interface (`get_if_addrs`), command (structured JSON output only)   |
| Providers implemented (M3)    | Cloudflare, Alibaba Cloud DNS, DNSPod, DuckDNS, No-IP                                    |
| Remaining 6 (M3 stretch / M4) | Huawei Cloud DNS, Namecheap, GoDaddy, deSEC, FreeDNS, custom Webhook                     |
| Scheduler                     | Per-provider interval; backoff on failure; `fgate_ddns_updates_total{provider, outcome}` |

**Test:** Mock provider API; verify update payload, retry on 5xx, and IP-change detection.

#### M3.2 L4 / SNI Routing (`fg-l4`)

Gately's "Protocol Routing" module multiplexes TLS by SNI and ALPN, HTTP by Host, and recognizes SSH, RDP, MQTT,
PostgreSQL, Redis, and more.

| Task               | Detail                                                                                                                             |
|--------------------|------------------------------------------------------------------------------------------------------------------------------------|
| TCP listener       | `tokio::net::TcpListener`; peek `ClientHello` without consuming                                                                    |
| SNI extraction     | Parse TLS ClientHello extension 0 (server_name)                                                                                    |
| ALPN extraction    | Parse extension 16                                                                                                                 |
| Magic-byte routing | Configurable prefix table for SSH (`SSH-`), RDP, PostgreSQL (`\x00\x00\x00\x08\x04\xd2\x16\x2f`), Redis (`*`), MQTT (`\x10`), etc. |
| Port forwarding    | TCP/UDP, IPv4/IPv6, port ranges, multi-target failover, connection limits                                                          |

#### M3.3 NAT / STUN Traversal (`fg-nat`)

| Task              | Detail                                                                       |
|-------------------|------------------------------------------------------------------------------|
| STUN discovery    | Query public STUN server; detect NAT type (full-cone, restricted, symmetric) |
| TCP hole punching | Simultaneous open with retry and keep-alive                                  |
| UDP hole punching | Keep-alive interval configurable (default 25 s)                              |
| UPnP / NAT-PMP    | Optional port mapping via `igd` crate                                        |
| Change trigger    | Webhook + script on public IP change                                         |

**M3 Exit Criteria:** DDNS update succeeds against mock provider; SNI routing dispatches two TLS backends correctly;
STUN traversal demo between two NATed peers.

---

### M4 — Build Site & Migration (4 weeks)

#### M4.1 `fg-buildctl` — Build Site Backend

Gately's build site turns a selection into `no_<module>` and `lang_*` build tags; `tools/custombuild` converts the
selection into these parameters. FerrumGate maps this to Cargo features.

**`POST /api/v1/builds` request:**

```json
{
  "version": "0.1.0",
  "target": "x86_64-unknown-linux-musl",
  "features": ["core", "proxy", "acme", "waf", "ban"],
  "artifacts": ["binary", "docker"],
  "preset": "security"
}
```

**Server validation pipeline:**

| Step | Check                                                                                                                                                                                     | Failure response         |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------|
| 1    | Every feature exists in `features.toml`                                                                                                                                                   | `400 unknown_feature`    |
| 2    | Dependency closure satisfied (`waf` → `proxy`)                                                                                                                                            | `400 missing_dependency` |
| 3    | Target triple in whitelist (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `x86_64-unknown-freebsd`) | `400 unsupported_target` |
| 4    | Rate limit (5 builds / IP / hour; 20 / token / day)                                                                                                                                       | `429 rate_limited`       |
| 5    | Feature count ≤ 25                                                                                                                                                                        | `400 feature_limit`      |

**Generated command (never shell-interpolated):**

```bash
cargo build --release --locked \
  --no-default-features \
  --features "core,proxy,acme,waf,ban" \
  --target x86_64-unknown-linux-musl
```

**Artifact pipeline per successful build:**

1. Binary → `strip` → `sha256sum` → `fgate-{version}-{target}`.
2. `cargo cyclonedx --format json --output-file fgate-{version}-{target}.sbom.cdx.json`.
3. `cosign sign-blob --keyless --output-signature fgate.sig fgate` and same for SBOM.
4. Docker: multi-stage `Dockerfile` with `FROM scratch` runtime stage when using musl.
5. Upload to object storage; return signed URLs in `GET /api/v1/builds/{id}`.

#### M4.2 Multi-Architecture CI Matrix

GitHub Actions matrix for cross-compilation:

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

For `aarch64-unknown-linux-musl`, use `cross` (Docker-based zero-setup cross-compilation) or `cargo-zigbuild`.

#### M4.3 Migration Tool

`fgate migrate gately --config ./gately.json --out ./ferrumgate.toml --report ./migration-report.json`

| Gately config section | FerrumGate section | Field mapping notes                                         |
|-----------------------|--------------------|-------------------------------------------------------------|
| `web_services[]`      | `[[proxy.sites]]`  | `domain`, `upstream`, `tls`, `auth`, `waf`                  |
| `acme`                | `[acme]`           | `email`, `provider`, `domains[]`, `challenge_type`          |
| `ddns`                | `[ddns]`           | `provider`, `credentials`, `interval`, `ip_detection`       |
| `waf`                 | `[waf]`            | `mode` (`DetectionOnly`/`On`), `body_limit`, `rule_toggles` |
| `guard`               | `[ban]`            | `jails[]`, `whitelist[]`, `ban_duration`, `find_time`       |
| `stun`                | `[nat]`            | `stun_server`, `keepalive_interval`, `upnp`                 |

Unsupported fields → `migration-report.json` entry with `severity: warning`, `field_path`, `suggestion`.

**M4 Exit Criteria:** User-selected features produce a signed binary and SBOM; Docker image runs on `scratch`; migration
achieves ≥90% core-field coverage on Web Services, ACME, DDNS fixtures.

---

### M5 — Hardening & General Availability (3 weeks)

| Task              | Detail                                                                             | Acceptance               |
|-------------------|------------------------------------------------------------------------------------|--------------------------|
| Fuzzing           | `cargo-fuzz` on HTTP header parsing, TLS ClientHello parser, config parser         | 72 h no crashes          |
| Load testing      | `oha` / `k6` against proxy; compare p99 latency with Gately under identical config | p99 ≤ Gately + 10%       |
| Security review   | Threat model, auth bypass, WAF bypass, build-site injection                        | No blocking findings     |
| Dependency audit  | `cargo deny check` + `cargo audit --deny warnings`                                 | Zero unwaived advisories |
| SBOM verification | `cosign verify-blob` on SBOM and binary                                            | Signature valid          |
| Rollback drill    | Deploy N → N-1 using previous binary + config migration down                       | RTO < 5 min              |
| Documentation     | OpenAPI, migration guide, operations manual                                        | All endpoints documented |

**M5 Exit Criteria:** No blocking security findings; performance target met; rollback drill passes.

---

## 3. CI/CD Pipeline (Complete GitHub Actions Specification)

### 3.1 Pull Request Gate

Every PR runs five blocking jobs:

| Job              | Command                                                                   | Timeout |
|------------------|---------------------------------------------------------------------------|---------|
| `fmt`            | `cargo fmt --all --check`                                                 | 2 min   |
| `clippy`         | `cargo clippy --workspace --all-targets --all-features -- -D warnings`    | 15 min  |
| `test`           | `cargo nextest run --workspace`                                           | 20 min  |
| `feature-matrix` | `cargo hack check --feature-powerset --depth 2 --no-dev-deps --workspace` | 25 min  |
| `manifest-check` | `cargo run -p xtask -- check-features`                                    | 2 min   |

`cargo-hack` with `--depth 2` tests each feature individually and each pair, catching most real-world feature
interaction issues without the exponential blowup of full powerset (2^25). For FerrumGate's 25 features, depth 2 yields
roughly 25 + 300 = 325 check invocations, bounded by CI timeout.

### 3.2 Supply-Chain Job (Every PR + Nightly)

```yaml
- name: cargo-deny
  run: cargo deny check
- name: cargo-audit
  run: cargo audit --deny warnings
```

`deny.toml` policy:

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

`cargo audit` is workspace-aware by default (reads `Cargo.lock`); `cargo deny` is graph-aware. Both run on the same
lockfile.

### 3.3 Release Job (Tag push `v*`)

| Step         | Command / Action                                                            |
|--------------|-----------------------------------------------------------------------------|
| Build matrix | 6 targets (see §M4.2)                                                       |
| SBOM         | `cargo cyclonedx --format json --output-file target/{target}.sbom.cdx.json` |
| Sign         | `cosign sign-blob --keyless target/{target}/fgate` + same for SBOM          |
| Docker       | Buildx multi-arch `linux/amd64`, `linux/arm64`, `linux/arm/v7`              |
| Checksums    | `sha256sum` per artifact                                                    |
| Publish      | GitHub Release with binary, `.sbom.cdx.json`, `.sig`, `.sha256`             |

---

## 4. Testing Strategy (Executable Matrix)

| Test layer     | Tool                                      | Scope                                                   | Runs on      |
|----------------|-------------------------------------------|---------------------------------------------------------|--------------|
| Unit           | `cargo test` / `nextest`                  | `fg-config`, `fg-certs`, `fg-acme`, `fg-ban`, `fg-ddns` | Every PR     |
| Integration    | `testcontainers` + `fgate` binary         | Proxy, TLS SNI, WebSocket, gRPC, ACME (Pebble)          | Every PR     |
| Feature matrix | `cargo hack --feature-powerset --depth 2` | All pair combinations                                   | Every PR     |
| Security       | Custom harness + `cargo-fuzz`             | WAF bypass, auth bypass, path traversal                 | Nightly + M5 |
| Concurrency    | `loom`                                    | Ban-list state transitions                              | M2 onward    |
| Property       | `proptest`                                | Config parsing, header handling                         | Every PR     |
| Performance    | `oha` / `k6`                              | Proxy p99, throughput                                   | M5 + release |
| Migration      | Fixture JSON → expected TOML              | Gately configs                                          | M4 onward    |

**ACME testing:** Run Pebble (`letsencrypt/pebble`) in CI; issue against `pebble` challenge test server; verify renewal
scheduler triggers at `expires_at - 30 days` by manipulating stored `expires_at`.

**WAF testing:** CRS v4 regression suite: a curated set of 50 requests (SQLi, XSS, LFI, RCE, protocol violations) must
produce expected `403` in `On` mode and `200` in `DetectionOnly`.

---

## 5. Build Matrix (Explicit Feature Sets)

```yaml
strategy:
  matrix:
    features:
      - "core"
      - ""                          # default features
      - "core,proxy,acme,certs"
      - "core,proxy,waf,ban"
      - "core,proxy,acme,ddns,l4,nat"
      - "core,proxy,acme,waf,ban,ddns,l4,nat,auth-oidc,auth-totp"
      - "--all-features"
      - "--no-default-features"
```

Each entry runs `cargo check --locked --no-default-features --features "$FEATURES"`. At least `core`, default, and
`core,proxy,waf,ban` run full integration tests.

---

## 6. Risk Register with Concrete Mitigations

| Risk                                                  | Probability | Impact | Concrete mitigation                                                                           | Rollback trigger                                        |
|-------------------------------------------------------|------------:|-------:|-----------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `coraza-rs` FFI build failure on musl                 |      Medium |   High | Pre-build `libcoraza.a` in CI Docker image; cache Go module deps                              | Disable `waf` feature; release without WAF              |
| Feature dependency cycle discovered late              |      Medium |   High | `xtask check-features` runs topological sort at M0                                            | Remove offending feature; restructure `depends`         |
| ACME rate limit (Let’s Encrypt: 50 certs/domain/week) |         Low | Medium | Staging endpoint for tests; per-domain issuance counter with alert at 40/week                 | Fall back to manual import                              |
| DDNS provider API breaking change                     |        High | Medium | Each provider behind its own feature; integration test per provider against recorded fixtures | Disable single provider feature in patch release        |
| Build site abuse (crypto mining via CI)               |      Medium |   High | Queue isolation, 5 builds/IP/hour, no arbitrary `RUSTFLAGS`, signed artifacts                 | Pause build queue; require token for builds             |
| nftables backend unavailable in container             |      Medium | Medium | Detect at startup; fall back to `iptables` or log degraded mode                               | Disable `ban` feature at runtime (config)               |
| Go baseline performance regression                    |         Low | Medium | Benchmark harness runs both `fgate` and Gately on same host                                   | Accept documented delta or optimize hot path            |
| `cargo-hack` CI timeout (25 features, depth 2)        |      Medium | Medium | Cache dependencies; run feature matrix on nightly + merge queue only, not every PR push       | Reduce to `--each-feature` on PR, full powerset nightly |

---

## 7. Acceptance Criteria (Definition of Done) — Expanded

A feature is **done** when **all** of the following are true:

- [ ] Declared in `features.toml` with `name`, `display`, `default`, `risk`, `depends`, `gately_equiv`.
- [ ] `#[cfg(feature = "...")]` guards compile under `--no-default-features` **and** `--all-features`.
- [ ] `cargo hack check --each-feature` passes for the crate introducing the feature.
- [ ] Unit tests cover public functions; integration test starts `fgate` with the feature enabled on an ephemeral port.
- [ ] At least one Prometheus metric emitted with `fgate_` prefix.
- [ ] Structured log events at `info` on init and `error` on failure, with `module` field.
- [ ] If the feature touches WAF, ban, auth, or admin API: security review completed, negative tests present.
- [ ] `DESIGN.md` technology table and `EXECUTION.md` milestone mapping updated.
- [ ] `cargo run -p xtask -- check-features` passes.
- [ ] Feature listed in at least one CI build-matrix entry.

---

## 8. Deliverables (Release Checklist)

| Artifact             | Format                                                                        | Verification                                               |
|----------------------|-------------------------------------------------------------------------------|------------------------------------------------------------|
| `fgate` binary       | static musl (x86_64, aarch64), macOS (x86_64, aarch64), Windows MSVC, FreeBSD | `file` shows statically linked; runs on `scratch`          |
| Docker image         | multi-arch `amd64`, `arm64`, `arm/v7`                                         | `docker run --rm ferrumgate/fgate:version fgate --version` |
| SBOM                 | CycloneDX JSON per artifact                                                   | `cosign verify-blob` passes                                |
| Signature            | cosign keyless                                                                | `cosign verify-blob --certificate-identity ...` passes     |
| Checksums            | SHA-256 per artifact                                                          | Matches published checksum file                            |
| OpenAPI spec         | `docs/openapi.json`                                                           | `openapi-diff` no breaking changes                         |
| Migration report     | JSON per Gately config                                                        | ≥90% core-field coverage                                   |
| Security report      | Markdown                                                                      | No blocking findings                                       |
| Performance baseline | Markdown + raw `oha` output                                                   | p99 documented                                             |
| Rollback runbook     | Markdown                                                                      | Drill completed in M5                                      |

---