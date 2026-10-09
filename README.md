# flux-core

A high-performance, asynchronous proxy core written in Rust (Edition 2024).

## Features

### Protocols (Server & Client)
- **VLESS**: REALITY (X25519, ChaCha20-Poly1305), `xtls-rprx-vision` flow, TLS, WebSocket.
- **Trojan**: SHA-224 password hashing over TLS (Inbound & Outbound).
- **VMess**: AEAD header authentication, AES-128-GCM and ChaCha20-Poly1305 ciphers (Inbound & Outbound).
- **Shadowsocks & Shadowsocks-2022**: AEAD (ChaCha20-Poly1305, AES-256-GCM), 2022 Blake3-ciphers, ReplayFilter defense (Inbound & Outbound).
- **TUIC v5**: Full QUIC/quinn carrier, BBR congestion control, TCP stream & UDP relay (Inbound & Outbound).
- **Hysteria 2**: Full QUIC/quinn carrier, Brutal pacer, port-hopping, TCP stream & UDP relay (Inbound & Outbound).
- **SOCKS5**: TCP CONNECT and UDP ASSOCIATE support with user/password authentication (Inbound & Outbound).
- **HTTP / HTTP CONNECT**: Forward proxy, tunneling, Basic authentication (Inbound & Outbound).
- **Mixed Inbound**: Auto-detection of SOCKS5 and HTTP protocols on a single port.
- **Transparent Inbounds**: TUN (userspace TCP stack & UDP relay), REDIRECT (`SO_ORIGINAL_DST`), TPROXY (`IP_TRANSPARENT`).
- **WireGuard**: AmneziaWG dialect with junk packet obfuscation (Outbound tunnel).

### Transport & Performance
- **Linux Zero-Copy**: Socket-to-socket `splice(2)` data transfer.
- **Buffer Pooling**: Memory chunk reuse via `BufferPool` without per-connection allocations.
- **TLS**: Async TLS 1.3/1.2 powered by `rustls` with ALPN negotiation.

### Routing & DNS
- **Rule Engine**: Matching by domain (exact, suffix, keyword), IP CIDR, ports, network (TCP/UDP), rule sets, and inverted matching (`invert: true`).
- **Rule Sets**: High-capacity GeoIP and GeoSite list matching with O(1) hash lookups and O(L) suffix climbing.
- **DNS**: Built-in resolver with Fake-IP (`198.18.0.0/15`), wireformat parser (IPv4 `A` & IPv6 `AAAA`), and DNS-over-HTTPS (DoH, RFC 8484) client.

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

### Management & Control
- **Flux Core Native REST API**: Native control plane API (`/api/v1/*`) over TCP or Unix Domain Sockets (`unix://...`) with Bearer token authentication, real-time traffic metering, dynamic outbound selector switching, delay/latency probing, route simulation dry-run, and connection lifecycle management.
- **Zero-Downtime Reload**: Configuration reload via `SIGHUP` without terminating active streams.

## Architecture

The project is organized as a Cargo workspace with modular crates:

- `crates/flux-types`: Core types, session metadata, target addresses, and common traits (`Inbound`, `Outbound`, `Dispatcher`).
- `crates/flux-common`: Memory pool (`BufferPool`), zero-copy socket pipe (`splice`), and bidirectional copying.
- `crates/flux-router`: Rule evaluation engine, CIDR matching, and rule-set registry.
- `crates/flux-dns`: Fake-IP engine, DNS wireformat parser (A and AAAA records), and DoH client.
- `crates/flux-transport`: TLS, TCP, and REALITY transport implementations.
- `crates/flux-protocol`: SOCKS5, HTTP, VLESS, Trojan, and Shadowsocks protocol implementations.
- `crates/flux-inbound`: Inbound listener adapters (Mixed, SOCKS, HTTP, VLESS, Trojan, SS, TUN).
- `crates/flux-outbound`: Outbound connection adapters and group balancers (Selector, UrlTest, Fallback, LoadBalance).
- `crates/flux-app`: Dispatcher, configuration parser, and runtime lifecycle manager.
- `src/main.rs`: Modern CLI entry point with `clap`.

## Building

### Prerequisites
- Rust 1.85+ (Edition 2024)
- Linux x86_64 / aarch64

### Build Release Binary
```bash
cargo build --release -p flux-core
```

The optimized binary will be located at `target/release/flux-core`.

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

## License

MIT License
