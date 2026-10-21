# Security Guide

## Threat model

flux-core terminates untrusted network input on every inbound. All protocol parsers are written with explicit bounds checks; a panic inside a per-connection Tokio task is caught at the task boundary and cannot take down the process (`panic = unwind` is deliberate).

## Built-in hardening

| Layer | Mechanism |
|---|---|
| TCP inbounds | Handshake timeout on every listener (slow-loris protection), including TUIC stream mode |
| QUIC outbounds | Certificate verification is **on by default** (`insecure` must be set explicitly) |
| All inbounds | Optional `rate_limit`: per-IP token bucket (`max_conn_per_ip_per_sec` + `burst`) and global `max_concurrent` cap; rejects happen **before** per-connection allocation; bucket map is memory-bounded (100k IPs + idle sweep) |
| Shadowsocks-2022 | Anti-replay window (TCP salts **and** UDP packet IDs, with cached per-session subkeys) |
| WireGuard | Anti-replay window, TAI64N freshness validation, MAC1 pre-screening of initiations, per-peer allow-list + preshared keys, `allowed_ips` enforcement, session reaping, bounded session table with collision-checked indices, runt-datagram rejection |
| VMess | AEAD auth-ID replay filter (120 s window) plus the standard timestamp check |
| TUIC (stream mode) | AUTH token bound to a timestamp (±300 s), so a captured frame cannot be replayed |
| VLESS / Trojan | An empty credential list is rejected rather than treated as "no authentication" |
| Configuration | Undefined `${VAR}` is an error; rule-set cache paths are sanitised; invalid port ranges/globs are rejected |
| REALITY | X25519 auth via TLS session_id, Ed25519 HMAC-tagged certificate, transparent decoy fallback relay |
| Management API | Secret token (constant-time comparison, empty secret treated as unset), CSRF/cross-origin rejection **before** dispatch with exact host matching (`http://localhost.attacker.tld` is rejected), bounded header/body sizes, public-listener-without-secret startup refusal, single-owner bind (no `SO_REUSEPORT`) |
| Outbound probing | Delay-probe destinations are checked against private/link-local ranges and **fail closed** when a name cannot be resolved |
| DNS | Strict upstream error handling, bounded wireformat parser, Fake-IP pool isolation (`198.18.0.0/15`), per-query and overall deadlines so a stalled upstream cannot wedge resolution |
| WireGuard | Runt/truncated datagrams are rejected before parsing; session table is capped and indices are collision-checked |
| Salamander (Hy2 obfs) | Spec-exact cipher (8-byte salt, BLAKE2b-256 keystream) verified against sing-box in both directions |
| Entropy | `OsRng` CSPRNG across all protocols |
| TLS | rustls 0.23 (TLS 1.3/1.2), ring backend, no OpenSSL |

## Deployment checklist

1. **Management API**: keep on `127.0.0.1` or a unix socket. If it must be remote, set `secret` and use TLS-terminating reverse proxy; the process refuses a public bind without a secret unless `allow_insecure_api: true` is set explicitly. An empty or whitespace-only `secret` is treated as *unset*: `${VAR}` with an undefined variable expands to `""`, which would otherwise silently satisfy both the bind guard and the bearer check.
2. **Public inbounds**: always configure `rate_limit`. Start with `max_conn_per_ip_per_sec: 5`, `burst: 10`, `max_concurrent` sized to your RAM budget.
3. **Secrets**: use `${ENV_VAR}` expansion; never commit keys. REALITY private keys, WG private keys, SS passwords belong in a secret store.
4. **Least privilege**: run as an unprivileged user with only the capabilities you need (see [deployment.md](deployment.md)). Root is not required for plain TCP/UDP listeners.
5. **Remote rule sets**: fetch over HTTPS only; they are size-capped and failure-safe, but treat the source as part of your trust boundary. Watch for the "no usable rules parsed" warning — a rule set that loads but matches nothing makes the rules referencing it fail open to `final`.
6. **QUIC nodes**: leave certificate verification enabled. Self-signed servers are a deliberate opt-in (`insecure: true`) rather than the default.
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
