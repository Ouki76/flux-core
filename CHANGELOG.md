# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-14

Production-ready release of the flux-core proxy core.

### Added

- **Protocols (inbound & outbound)**: VLESS (REALITY with full XTLS compatibility, `xtls-rprx-vision` flow, TLS, WebSocket), Trojan (SHA-224 over TLS), VMess (AEAD, AES-128-GCM / ChaCha20-Poly1305), Shadowsocks & Shadowsocks-2022 (AEAD, Blake3 2022-ciphers, replay filter), TUIC v5 (spec-compliant QUIC, BBR), Hysteria 2 (spec-compliant QUIC, HTTP/3 auth via built-in H3/QPACK, Brutal pacer, port-hopping, Salamander obfuscation), SOCKS5 (CONNECT + UDP ASSOCIATE, user/password auth), HTTP/HTTP CONNECT, mixed SOCKS5+HTTP auto-detect inbound.
- **Transparent inbounds**: TUN (`smoltcp` userspace TCP/IP stack with retransmission, congestion control, RFC 793 out-of-order reassembly, UDP relay), REDIRECT (`SO_ORIGINAL_DST`), TPROXY (`IP_TRANSPARENT`).
- **WireGuard (AmneziaWG dialect)**: server inbound (Noise IK responder, MAC1 anti-DoS screening, TAI64N freshness, per-peer allow-list with PSKs and `allowed_ips`, session roaming & reaping) and outbound tunnel (embedded `smoltcp` stack, single-demux socket reader, per-flow reply routing, transparent rekey, ICMP echo-reply).
- **Layered transport architecture**: orthogonal Carrier → Security → Framing → Protocol pipeline composition for every inbound/outbound, including REALITY camouflage for Shadowsocks and multi-security cascades.
- **Routing & DNS**: rule engine (domain exact/suffix/keyword, IP CIDR, ports, network, invert), GeoIP/GeoSite rule sets with O(1) hash lookups, **remote URL rule sets** (background fetch, size caps, disk cache, `update_interval` hot-swap, failure-safe), built-in DNS with Fake-IP (`198.18.0.0/15`) and DoH (RFC 8484) client.
- **Outbound groups**: Selector, URLTest (tolerance thresholding), Fallback (healthcheck probing), LoadBalance (round-robin / consistent hashing).
- **Configuration**: YAML/JSON/JSONC with auto-detection, `$include` with glob patterns, `${ENV_VAR}` / `${ENV_VAR:-default}` expansion, proxy-URI outbounds (VLESS/Trojan/SS/SOCKS5/HTTP links), strict dependency-graph validation with cycle detection, `flux-core check` validation subcommand.
- **Performance**: Linux zero-copy `splice(2)`, buffer pooling, SO_REUSEPORT listeners, sharded DNS cache, `LTO=fat` release profile.
- **Security hardening**: per-inbound rate limiting (per-IP token bucket + global concurrent cap, reject before allocation), handshake timeouts on every TCP inbound, bounded API request sizes, anti-replay windows (SS-2022, WireGuard), management API secret enforcement with constant-time comparison, CSRF/cross-origin rejection before dispatch, Prometheus `/api/v1/metrics` endpoint.
- **Management API** (`/api/v1/*`): version, status, metrics (Prometheus), traffic, inbounds, DNS resolve, route test, rules, outbounds (list/select/delay-probe), connections (list/close).
- **Testing infrastructure**: 233 automated tests including 35 sing-box interop tests (TUIC v5 / Hysteria 2 / REALITY), deterministic parser fuzz regression suite, 8 libFuzzer targets, WireGuard e2e (UDP+TCP echo, rogue peer), perf/memory leak tests, 24h soak harness (`scripts/soak.sh`).
- **Operations**: multi-stage Dockerfile (distroless-slim runtime, healthcheck via `flux-core check`), CI pipeline (fmt, clippy `-D warnings`, full test suite with sing-box, release build).

### Security

- OsRng (CSPRNG) entropy across WireGuard, Vision, Hysteria 2, ShadowTLS.
- Hardened Hy2 varint-length DoS caps, Fake-IP /32 underflow fix, strict DNS upstream errors, UDP reply-destination normalization, `select!` arm drop fixes (lost UDP replies / first TCP chunks).

## [0.1.0] - 2026-09-10

Initial development snapshot.
