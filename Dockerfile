# Multi-stage production build for flux-core
FROM rust:1.91-bookworm AS builder

WORKDIR /app

# Cache dependencies: build a stub first so dependency layers are cached
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src src
COPY benches benches
COPY examples examples
RUN cargo build --release -p flux-core && \
    strip target/release/flux-core

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates iptables iproute2 curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/flux-core /usr/local/bin/flux-core

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
