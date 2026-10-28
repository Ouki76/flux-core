# syntax=docker/dockerfile:1
#
# Multi-stage production build for flux-core.
#
# Built for linux/amd64 and linux/arm64 from this single file: both stages use
# images that are themselves multi-arch, so `docker buildx build --platform
# linux/arm64` works under emulation without a per-arch Dockerfile.
#
# `.dockerignore` excludes `target/` and `target-cov/`, which reach tens of
# gigabytes locally; without that exclusion the build context alone would
# defeat the daemon.

FROM rust:1.91-bookworm AS builder

WORKDIR /app

# Manifests and sources are copied together. Splitting them to cache
# dependencies would need a stub build per crate in this workspace, which is
# more fragile than the caching it buys; the BuildKit cache mounts below give
# the same benefit without restructuring the copy.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src src
COPY benches benches
COPY examples examples

# Cache mounts keep the registry and the target directory across builds, so a
# rebuild after a source-only change does not recompile every dependency. The
# binary is lifted out inside the same RUN because cache mounts are not part of
# the resulting layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release -p flux-core && \
    cp target/release/flux-core /flux-core && \
    strip /flux-core

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates iptables iproute2 curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /flux-core /usr/local/bin/flux-core

RUN mkdir -p /etc/flux-core

# The proxy needs NET_ADMIN (TUN device) and NET_BIND_SERVICE when using
# tproxy/tun/redirect inbounds or privileged ports:
#   docker run --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE ...
# For pure TCP/UDP listeners on unprivileged ports no extra capabilities are required.

EXPOSE 1080/tcp 10808/tcp 10808/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["flux-core", "check", "-c", "/etc/flux-core/config.json"]

ENTRYPOINT ["/usr/local/bin/flux-core"]
CMD ["run", "-c", "/etc/flux-core/config.json"]