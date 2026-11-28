# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for FerrumGate (WP-92):
#   1. ui-builder   : builds the web UI on the build host platform
#   2. rust-builder : cross-compiles static musl `fgate` binary for TARGETARCH/TARGETVARIANT
#   3. runtime      : minimal alpine:3.23 runtime with optional docker-cli and pinned nftables

# ------------------------------------------------------------------------------
# Stage 1: UI assets
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui-builder
WORKDIR /src
ARG FERRUMGATE_LANG=all
ARG FERRUMGATE_LOCALES=zh-CN,zh-TW,en,de,es,fr,ja,ko,pt-BR,ru
ENV FERRUMGATE_LANG=${FERRUMGATE_LANG}
ENV FERRUMGATE_LOCALES=${FERRUMGATE_LOCALES}
COPY . .
RUN mkdir -p /out/ui \
    && if [ -f web/package.json ]; then \
         cd web && npm ci && npm run build && cp -a dist/. /out/ui/; \
       fi

# ------------------------------------------------------------------------------
# Stage 2: Rust static musl binary cross-compilation
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM rust:1.88-alpine AS rust-builder
WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH
ARG TARGETVARIANT
ARG FERRUMGATE_FEATURES=lang-all
ARG FERRUMGATE_LANG=all
ARG FERRUMGATE_LOCALES=zh-CN,zh-TW,en,de,es,fr,ja,ko,pt-BR,ru
ARG VERSION=v0.1.0
ARG COMMIT=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z

ENV FERRUMGATE_VERSION=${VERSION}
ENV FERRUMGATE_COMMIT=${COMMIT}
ENV FERRUMGATE_BUILD_DATE=${BUILD_DATE}

RUN apk add --no-cache musl-dev pkgconfig zig

COPY . .
COPY --from=ui-builder /out/ui /src/web/dist

RUN set -eu; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64)   RUST_TARGET="x86_64-unknown-linux-musl" ;; \
      arm64)   RUST_TARGET="aarch64-unknown-linux-musl" ;; \
      armv7)   RUST_TARGET="armv7-unknown-linux-musleabihf" ;; \
      *)       echo "unsupported Docker target: ${TARGETOS}/${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${RUST_TARGET}"; \
    cargo build --release --locked --bin fgate --target "${RUST_TARGET}" \
      --no-default-features --features "${FERRUMGATE_FEATURES}"; \
    install -Dm0755 "target/${RUST_TARGET}/release/fgate" /out/fgate

# ------------------------------------------------------------------------------
# Stage 3: Runtime (alpine:3.23)
# ------------------------------------------------------------------------------
FROM alpine:3.23 AS runtime

# Driven by `cargo xtask modules resolve` (WP-90 / WP-92):
#   WITH_DOCKER_CLI=1 only when the `docker` management module is enabled
#   WITH_NFTABLES=1   only when `guard` or `stun` is enabled
ARG WITH_DOCKER_CLI=1
ARG WITH_NFTABLES=1

# Base runtime utilities: CA certificates, timezone data, curl, bash (user scripts).
RUN apk add --no-cache ca-certificates tzdata curl bash

# Optional Docker CLI (installed only when WITH_DOCKER_CLI=1).
RUN if [ "${WITH_DOCKER_CLI}" = "1" ]; then \
      apk add --no-cache docker-cli docker-cli-compose; \
    fi

# Optional firewall tools (installed only when WITH_NFTABLES=1).
#
# IMPORTANT (WP-92 §2 / §8): nftables MUST stay pinned to Alpine 3.21's 1.1.1!
# Starting with nftables 1.1.2, set elements carry metadata that older host
# nftables binaries (< 1.1.1, e.g. Debian 12 / fnOS shipping 1.0.6) cannot parse,
# causing `nft list ruleset` on the host to crash and breaking ban-list sync.
# Do NOT bump nftables without verifying host compatibility across Debian 12/fnOS.
#
# We also remove the un-suffixed `iptables*` symlinks that point to the nf_tables
# backend, leaving explicit `*-legacy` and `*-nft` binaries so runtime probing
# selects the right backend deterministically.
RUN if [ "${WITH_NFTABLES}" = "1" ]; then \
      apk add --no-cache \
        --repository=https://dl-cdn.alpinelinux.org/alpine/v3.21/main \
        'nftables=1.1.1-r0' \
      && apk add --no-cache iptables-legacy ipset \
      && rm -f \
        /usr/sbin/iptables /usr/sbin/iptables-save /usr/sbin/iptables-restore \
        /usr/sbin/ip6tables /usr/sbin/ip6tables-save /usr/sbin/ip6tables-restore \
        /sbin/iptables /sbin/iptables-save /sbin/iptables-restore \
        /sbin/ip6tables /sbin/ip6tables-save /sbin/ip6tables-restore; \
    fi

COPY --from=rust-builder /out/fgate /usr/local/bin/fgate

ENV FERRUMGATE_CONFIG_DIR=/etc/ferrumgate
VOLUME ["/etc/ferrumgate"]
EXPOSE 16680

ENTRYPOINT ["/usr/local/bin/fgate"]
CMD ["serve", "--config", "/etc/ferrumgate"]
