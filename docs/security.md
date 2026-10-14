# Security Guide

## Threat model

flux-core terminates untrusted network input on every inbound. All protocol parsers are written with explicit bounds checks; a panic inside a per-connection Tokio task is caught at the task boundary and cannot take down the process (`panic = unwind` is deliberate).

## Built-in hardening

| Layer | Mechanism |
|---|---|
| TCP inbounds | Handshake timeout on every listener (slow-loris protection) |
| All inbounds | Optional `rate_limit`: per-IP token bucket (`max_conn_per_ip_per_sec` + `burst`) and global `max_concurrent` cap; rejects happen **before** per-connection allocation; bucket map is memory-bounded (100k IPs + idle sweep) |
| Shadowsocks-2022 | Anti-replay window |
| WireGuard | Anti-replay window, TAI64N freshness validation, MAC1 pre-screening of initiations, per-peer allow-list + preshared keys, `allowed_ips` enforcement, session reaping |
| REALITY | X25519 auth via TLS session_id, Ed25519 HMAC-tagged certificate, transparent decoy fallback relay |
| Management API | Secret token (constant-time comparison), CSRF/cross-origin rejection **before** dispatch, bounded header/body sizes, public-listener-without-secret startup refusal |
| DNS | Strict upstream error handling, bounded wireformat parser, Fake-IP pool isolation (`198.18.0.0/15`) |
| Entropy | `OsRng` CSPRNG across all protocols |
| TLS | rustls 0.23 (TLS 1.3/1.2), ring backend, no OpenSSL |

## Deployment checklist

1. **Management API**: keep on `127.0.0.1` or a unix socket. If it must be remote, set `secret` and use TLS-terminating reverse proxy; the process refuses a public bind without a secret unless `allow_insecure_api: true` is set explicitly.
2. **Public inbounds**: always configure `rate_limit`. Start with `max_conn_per_ip_per_sec: 5`, `burst: 10`, `max_concurrent` sized to your RAM budget.
3. **Secrets**: use `${ENV_VAR}` expansion; never commit keys. REALITY private keys, WG private keys, SS passwords belong in a secret store.
4. **Least privilege**: run as an unprivileged user with only the capabilities you need (see [deployment.md](deployment.md)). Root is not required for plain TCP/UDP listeners.
5. **Remote rule sets**: fetch over HTTPS only; they are size-capped and failure-safe, but treat the source as part of your trust boundary.
6. **DoH upstreams**: prefer `https://IP/dns-query` endpoints with pinned IPs to avoid bootstrap loops.
7. **Supply chain**: CI runs `cargo audit` against the RustSec advisory database; review `deny.toml` policy before relaxing any lint.

## Fuzzing

8 libFuzzer targets cover the highest-risk parsers (VLESS/Trojan/VMess headers, DNS wire format, SOCKS5 UDP, WG initiation, proxy URIs, config, rule-set lines):

```bash
cargo +nightly fuzz run fuzz_vless_header -- -max_total_time=300
```

A deterministic regression suite (`tests/test_fuzz_parsers.rs`) runs the same parsers against a fixed corpus on stable Rust in CI.

## Reporting

Please report security issues privately to the maintainers rather than in public issues.
