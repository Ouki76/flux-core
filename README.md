# flux-core

A high-performance, asynchronous proxy core written in Rust (Edition 2024).

## Features

### Protocols (Server & Client)
- **VLESS**: REALITY (full XTLS-compatible implementation: X25519 auth via TLS session_id, Ed25519 HMAC-tagged certificate, transparent fallback relay), `xtls-rprx-vision` flow, TLS, WebSocket.
- **Trojan**: SHA-224 password hashing over TLS (Inbound & Outbound).
- **VMess**: AEAD header authentication, AES-128-GCM and ChaCha20-Poly1305 ciphers (Inbound & Outbound).
- **Shadowsocks & Shadowsocks-2022**: AEAD (ChaCha20-Poly1305, AES-256-GCM), 2022 Blake3-ciphers, ReplayFilter defense (Inbound & Outbound).
- **TUIC v5**: Spec-compliant QUIC carrier (TLS EKM auth, per-flow bi-streams, datagram UDP; inbound and outbound, interoperable with sing-box).
- **Hysteria 2**: Spec-compliant QUIC carrier with HTTP/3 auth (minimal built-in H3/QPACK server), Brutal pacer, **Salamander obfuscation** (custom quinn runtime wrapping every UDP datagram), TCP stream & datagram UDP relay (Inbound & Outbound; interoperable with sing-box).
- **SOCKS5**: TCP CONNECT and UDP ASSOCIATE support with user/password authentication (Inbound & Outbound).
- **HTTP / HTTP CONNECT**: Forward proxy, tunneling, Basic authentication (Inbound & Outbound).
- **Mixed Inbound**: Auto-detection of SOCKS5 and HTTP protocols on a single port.
- **Transparent Inbounds**: TUN (powered by the `smoltcp` userspace TCP/IP stack — full retransmission, congestion control, out-of-order reassembly & UDP relay), REDIRECT (`SO_ORIGINAL_DST`), TPROXY (`IP_TRANSPARENT`).
- **WireGuard**: AmneziaWG dialect with junk packet obfuscation — server **inbound** (Noise IK responder, MAC1 anti-DoS screening, TAI64N freshness validation, per-peer allow-list with preshared keys and `allowed_ips`, session roaming & reaping; inner traffic terminated by the shared `smoltcp` userspace stack) and **outbound** tunnel with full TCP+UDP support via an embedded `smoltcp` userspace TCP/IP stack (single-demux socket reader, per-flow reply routing, transparent rekey).

### Transport & Performance
- **Linux Zero-Copy**: Socket-to-socket `splice(2)` data transfer.
- **Buffer Pooling**: Memory chunk reuse via `BufferPool` without per-connection allocations.
- **TLS**: Async TLS 1.3/1.2 powered by `rustls` with ALPN negotiation.

### Routing & DNS
- **Rule Engine**: Matching by domain (exact, suffix, keyword), IP CIDR, ports, network (TCP/UDP), rule sets, and inverted matching (`invert: true`).
- **Rule Sets**: High-capacity GeoIP and GeoSite list matching with O(1) hash lookups and O(L) suffix climbing. Local files, inline lists, and **remote URL rule sets** (`type: "remote"`, background HTTP/HTTPS fetch with redirect support, size caps, optional `update_interval` refresh, hot-swappable without restart; fetch failures never break routing).
- **Multiplexing**: smux v1 (sing-box compatible) for VLESS/VMess/Trojan/Shadowsocks, including muxed UDP, off by default.
- **DNS**: Built-in resolver with Fake-IP (`198.18.0.0/15`) served through a dedicated `dns` inbound (`dns.listen`), wireformat parser (IPv4 `A` & IPv6 `AAAA`), DoH (RFC 8484), DoT and DoQ clients, negative caching and end-to-end deadlines.

### Outbound Groups
- **Selector**: Manual or programmatic outbound node selection.
- **URLTest**: Latency-based automated failover with tolerance thresholding.
- **Fallback**: Priority-ordered active-passive failover with healthcheck probing.
- **LoadBalance**: Round-robin and consistent-hashing traffic distribution.

### Configuration & Modularity
- **Multi-Format**: Seamless support for YAML (`.yaml`, `.yml`), JSON, and JSON with comments (`.jsonc`).
- **Modular Includes**: `$include` / `include` directives supporting individual files and glob patterns (e.g. `outbounds/*.json`).
- **Environment Variables**: Automatic `${ENV_VAR}` and `${ENV_VAR:-default}` expansion across configs.
- **Strict Graph Validation**: Pre-flight verification of outbound dependencies and cycle detection in groups.

### Security Hardening
- **Rate Limiting**: optional per-inbound connection limiting (`rate_limit`): per-client-IP token bucket (`max_conn_per_ip_per_sec` + `burst`) and a global `max_concurrent` cap; rejected connections are dropped before any per-connection allocation.
- Handshake timeouts on every TCP inbound (slow-loris protection), bounded header/body sizes on the management API, anti-replay windows for SS-2022 and WireGuard, TAI64N freshness validation, MAC1 pre-screening for WireGuard initiations.

### Testing & Verification
- **libFuzzer targets** (`fuzz/`): VLESS/Trojan/VMess headers, DNS wire format, SOCKS5 UDP, WG initiation, URI and rule-set parsing. Run: `cargo +nightly fuzz run fuzz_vless_header`.
- **Deterministic parser fuzz regression suite** (`tests/test_fuzz_parsers.rs`) — runs in CI without nightly.
- **Soak / leak detection**: `scripts/soak.sh [duration_secs]` (default 24h) — sustained load with RSS/FD/thread sampling and leak assertion.
- 41 sing-box interop tests plus 17 mux interop tests run against the real `sing-box` binary (graceful skip when absent), including Salamander-obfuscated Hysteria 2 **in both directions**.
- 4 Xray interop tests run against the real `xray` binary: REALITY plain and REALITY + XTLS Vision, both directions.
- `h2spec` 2.6.0 against the H2 listener: 108/108 applicable cases pass.
- TUN, REDIRECT and TPROXY are tested end-to-end inside a user network namespace, so they are no longer skipped.
- **UDP relay e2e** for every UDP-capable protocol (SOCKS5, Trojan, VMess, SS/SS-2022, VLESS, TUIC, Hy2), including reply-address-header correctness.
- **Transparent inbound e2e** (TUN/REDIRECT/TPROXY) — seven tests that re-exec into a user network namespace, so they run unprivileged here and in the CI `privileged-tests` job. A missing environment is a hard failure, never a silent pass.
- **SIGHUP hot-reload e2e**: listener swap and invalid-config rollback against the real binary.

### Management & Control
- **Flux Core Native REST API**: Native control plane API (`/api/v1/*`) over TCP or Unix Domain Sockets (`unix://...`) with Bearer token authentication, real-time traffic metering, dynamic outbound selector switching, delay/latency probing, route simulation dry-run, and connection lifecycle management.
- **Zero-Downtime Reload**: Configuration reload via `SIGHUP` without terminating active streams.

## Architecture

The project is designed around a strictly decoupled, modular 4-tier network stack:
1. **L4 Carrier**: Transport delivery (`tcp` or `udp` in config; QUIC is a `udp` carrier with its own TLS, and Unix domain sockets carry the management API).
2. **L5 Security**: Encryption & anti-censorship camouflage (`tls`, `reality` with decoy fallback, `shadowtls`, `fragment`, Salamander obfs).
3. **L6 Framing**: Stream & multiplexing framing (`websocket`, `httpupgrade`, `http2`, `grpc`).
4. **L7 Protocol**: Application proxy layer (`vless`, `trojan`, `vmess`, `shadowsocks`, `hysteria2`, `tuic`, `wireguard`, `socks5`, `http`).

Any protocol can be layered arbitrarily over any compatible security or framing mechanism (e.g. Shadowsocks or VLESS over REALITY + WebSocket, or Hysteria 2 / TUIC streamed over TCP + REALITY).

> **REALITY**: fully XTLS-compatible — interoperates with sing-box / Xray clients and
> servers (verified by live interop tests in both directions). The server transparently
> relays non-REALITY clients (browsers, active probers) to the configured `fallback`
> target. The client ships a minimal purpose-built TLS 1.3 stack (rustls cannot control
> the ClientHello session_id that REALITY uses for authentication).

### Workspace Crates

- `crates/flux-types`: Core session abstractions, target addresses, errors, and common traits (`Inbound`, `Outbound`, `StreamDialer`, `PacketEndpoint`, `Dispatcher`).
- `crates/flux-common`: Memory pool (`BufferPool`), zero-copy socket pipe (`splice`), and bidirectional copying.
- `crates/flux-transport`: Multi-layer pipeline (`LayeredTransportPipeline`, `ServerTransportPipeline`), TLS (`rustls`), REALITY, ShadowTLS, TLS fragmentation, WebSocket, HTTPUpgrade, HTTP/2, gRPC, and QUIC (`quinn`).
- `crates/flux-protocol`: Decoupled protocol codecs: VLESS (with Vision flow), Trojan, VMess (AEAD), Shadowsocks (AEAD & SS-2022 Blake3), Hysteria 2 (Salamander obfs & Brutal pacer), TUIC v5, WireGuard / AmneziaWG, SOCKS5, HTTP CONNECT.
- `crates/flux-router`: Rule evaluation engine, CIDR matching, GeoIP / GeoSite rule-set registry.
- `crates/flux-dns`: Fake-IP engine, DNS wireformat parser, DoH client with connection pooling, and DoT/DoQ resolvers.
- `crates/flux-inbound`: Inbound listener adapters (`VlessInbound`, `TrojanInbound`, `VmessInbound`, `ShadowsocksInbound`, `TuicInbound`, `Hysteria2Inbound`, `SocksInbound`, `HttpInbound`, `MixedInbound`, `TunInbound`, `RedirectInbound`, `TproxyInbound`).
- `crates/flux-outbound`: Outbound connection adapters and group balancers (Selector, UrlTest, Fallback, LoadBalance).
- `crates/flux-app`: Dispatcher, 4-tier configuration parser, link URI importer, and runtime lifecycle manager.
- `src/main.rs`: Modern CLI entry point with `clap`.

## Building

### Prerequisites
- Rust 1.91+ (Edition 2024; `rust-version` in `Cargo.toml` is 1.91)
- Linux x86_64 / aarch64

### Build Release Binary
```bash
cargo build --release -p flux-core
```

The optimized binary will be located at `target/release/flux-core`.

## Benchmarking

The harnesses ship with the tree; all are self-contained and need no external
tooling (the native ones compare against `sing-box` when it is installed):

```bash
# TCP throughput + CPU cost per GB + peak RSS, median of interleaved rounds
cargo run --release --example bench_native -- --rounds 5 --mb 300

# Multi-stream aggregate throughput
cargo run --release --example bench_native -- --rounds 5 --streams 8

# UDP relay: datagrams/second and round-trip latency (SOCKS5 UDP ASSOCIATE)
cargo run --release --example bench_udp -- --rounds 5 --count 20000

# Framing layers, one direction at a time (raw/ws/upgrade/h2/grpc)
cargo run --release --example bench_layers -- --one-way --rounds 5 --mb 64

# Micro-benchmarks: router, buffer pool, SOCKS5 proxy throughput
cargo bench --bench throughput
```

Measurements are interleaved across rounds and reported as a median: loopback
throughput on a busy machine drifts by >10% between runs, so a single-shot number
is not a basis for comparing implementations.

### Reference numbers

Loopback, 16-core desktop, release build, byte-verified, median of interleaved
rounds. Only numbers re-measured against the current tree are listed; earlier
side-by-side comparisons (sing-box, direct echo, multi-stream aggregates) were
removed rather than left to rot — the harness still prints them when `sing-box`
is installed on the machine.

Single stream:

| Path | Throughput |
|---|---|
| TCP relay (SOCKS5 → direct) | **2622 MB/s** |
| VLESS + REALITY | 729 MB/s |
| VLESS + TLS | 660 MB/s |
| VMess (AES-128-GCM) | 3676 MB/s |
| Shadowsocks-2022 (blake3-aes-128-gcm) | 3792 MB/s |
| Shadowsocks-AEAD (aes-256-gcm) | 3323 MB/s |

Userspace datapaths (the two that run their own TCP/IP stack):

| Path | Throughput | CPU per GB |
|---|---|---|
| **TUN** (smoltcp, default jumbo MTU 9000) | **1259 MiB/s** | not re-measured |
| TUN (same code, MTU 1500) | 464 MiB/s | not re-measured |
| **WireGuard** (Noise + smoltcp) | **210 MB/s** | **9.3 s** |

A TUN device supports no read/write batching (verified with `readv`/`writev`
probes: it returns exactly one packet per call), so these paths are syscall-bound
and bytes-per-syscall is the only lever — which is why the default MTU is 9000.
The other half of the TUN win was the TCP window: a socket buffer *is* the
advertised window and must cover the bandwidth-delay product, not a segment count.
Raising the floor from 64 KiB to 256 KiB cost 4x per-connection memory
(128 → 512 KiB) and bought +33 % at MTU 1500 and +65 % at jumbo; lower
`TCP_SOCKET_BUF_MIN` in `crates/flux-inbound/src/tun.rs` to trade it back.

Framing layers, one-way (an echo benchmark splits one stream, and in tokio the
split is a per-poll mutex, so full-duplex figures measure the harness):

| Layer | Throughput |
|---|---|
| h2 | **648 MB/s** |
| gRPC | **414 MB/s** |

(`cargo run --release --example bench_layers -- --one-way --rounds 5 --mb 64`.)

UDP relay:

| Path | Throughput |
|---|---|
| **flux-core** (SOCKS5 UDP relay, 1200 B payload) | **118k datagrams/s** |

Micro-benchmarks (median): pooled 64 KiB buffer acquire+release **1009 ns** — the
release scrubs, because a recycled buffer that still holds the previous
connection's bytes is one careless `write_all(&guard)` away from cross-tenant
disclosure. Resource cost per established TCP relay: ≈ 4 KB RSS and 6 file
descriptors (2 sockets + 4 `splice` pipe ends); idle process footprint 7.5 MB.

Absolutes depend on the machine and drift by ~10% between runs even on an idle
box, which is why the harness interleaves rounds and reports medians. Measured on
a 16-core desktop with the desktop session running.

### Running Tests
```bash
cargo test --workspace
```

### Running Benchmarks
```bash
cargo bench --bench throughput
```

## Usage

```bash
# Validate a configuration file (supports .yaml, .json, .jsonc)
./target/release/flux-core check -c examples/config.yaml

# Show which outbound a destination would use, without starting anything
./target/release/flux-core trace -c examples/config.yaml -d example.com:443 -n tcp

# Run the core
./target/release/flux-core run -c examples/config.yaml

# Print version information
./target/release/flux-core version
```

### Reloading Configuration
Send a `SIGHUP` signal to reload the configuration file at runtime:
```bash
kill -HUP <PID>
```

## Configuration Examples

Complete configuration examples are provided in the `examples/` directory:
- `examples/config.yaml`: Full YAML configuration with VLESS Reality, Trojan, SS, DoH, and all Outbound Groups.
- `examples/config.jsonc`: JSON with comments and modular `$include` demonstrating file splitting.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Deployment runbook](docs/deployment.md) (Docker, systemd, capabilities, monitoring)
- [Security guide](docs/security.md) (hardening, threat model, fuzzing)
- [Management API](docs/api.md) (REST endpoints, Prometheus)
- [Troubleshooting](docs/troubleshooting.md)
- [Changelog](CHANGELOG.md)

## License

MIT License
