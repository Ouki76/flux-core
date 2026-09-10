# flux-core

A high-performance, asynchronous proxy core written in Rust.

## Features

### Protocols
- **VLESS**: REALITY (X25519, ChaCha20-Poly1305) and `xtls-rprx-vision` flow.
- **Trojan**: SHA-224 password hashing over TLS.
- **Shadowsocks**: AEAD (ChaCha20-Poly1305, HKDF key derivation).
- **SOCKS5**: TCP CONNECT and UDP ASSOCIATE support.
- **HTTP / HTTP CONNECT**: Forward proxy and tunneling.
- **Mixed Inbound**: Auto-detection of SOCKS5 and HTTP protocols on a single port.
- **TUN**: Network interface abstraction for transparent proxying.

### Transport & Performance
- **Linux Zero-Copy**: Socket-to-socket `splice(2)` data transfer.
- **Buffer Pooling**: Memory chunk reuse without per-connection allocations.
- **TLS**: Async TLS 1.3/1.2 powered by `rustls`.

### Routing & DNS
- **Rule Engine**: Matching by domain (exact, suffix, keyword), IP CIDR, ports, and rule sets.
- **Rule Sets**: High-capacity GeoIP and GeoSite list matching.
- **DNS**: Built-in resolver with Fake-IP (`198.18.0.0/15`) and DNS-over-HTTPS (DoH, RFC 8484).

### Outbound Groups
- **Selector**: Manual or programmatic outbound node selection.
- **URLTest**: Latency-based automated failover with tolerance thresholding.

### Management & Control
- **REST API**: External controller with endpoints for traffic, proxies, and connection state.
- **Zero-Downtime Reload**: Configuration reload via `SIGHUP` without terminating active streams.

## Architecture

The project is organized as a Cargo workspace with modular crates:

- `crates/flux-types`: Core types, session metadata, and common traits (`Inbound`, `Outbound`, `Dispatcher`).
- `crates/flux-common`: Memory pool, zero-copy socket pipe (`splice`), and bidirectional copying.
- `crates/flux-router`: Rule evaluation engine and rule-set registry.
- `crates/flux-dns`: Fake-IP engine, DNS wireformat parser, and DoH client.
- `crates/flux-transport`: TLS, TCP, and REALITY transport implementations.
- `crates/flux-protocol`: SOCKS5, HTTP, VLESS, Trojan, and Shadowsocks protocol implementations.
- `crates/flux-inbound`: Inbound listener adapters.
- `crates/flux-outbound`: Outbound connection adapters and group balancers.
- `crates/flux-app`: Dispatcher, configuration parser, and runtime lifecycle manager.
- `src/main.rs`: CLI entry point.

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
# Validate a configuration file
./target/release/flux-core check -c config.json

# Run the core
./target/release/flux-core run -c config.json

# Print version information
./target/release/flux-core version
```

### Reloading Configuration
Send a `SIGHUP` signal to reload the configuration file at runtime:
```bash
kill -HUP <PID>
```

## Docker

```bash
docker build -t flux-core:latest .
docker run -d \
  --name flux-core \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_BIND_SERVICE \
  -v $(pwd)/config.json:/etc/flux-core/config.json:ro \
  flux-core:latest
```

## License

MIT License

