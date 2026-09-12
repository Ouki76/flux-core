# Multi-stage production build for flux-core
FROM rust:1.85-bookworm AS builder

WORKDIR /app
COPY . .

# Build release binary with optimization
RUN cargo build --release -p flux-core && \
    strip target/release/flux-core

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates iptables iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/flux-core /usr/local/bin/flux-core
COPY config.example.json /etc/flux-core/config.json

RUN mkdir -p /etc/flux-core

EXPOSE 1080 10808 10809 9090

ENTRYPOINT ["/usr/local/bin/flux-core"]
CMD ["run", "-c", "/etc/flux-core/config.json"]
