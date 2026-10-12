# Flux-Core Hardening Plan (audit remediation) — STATUS

## Phase 1 — Reliability & quick wins ✅
- [x] 1.1 ruleset: fail loudly on unreadable ruleset file
- [x] 1.2 ruleset: compile() idempotent
- [x] 1.3 DNS: precompiled split-DNS rules (zero-alloc matching)
- [x] 1.4 DNS: empty rule.servers falls back to global upstreams, never silently to system
- [x] 1.5 DNS: real TTL from DoH/DoT/DoQ responses
- [x] 1.6 DNS: inflight query single-flight dedup
- [x] 1.7 DNS: concurrent A+AAAA queries (v4-preferred, v6 fallback)
- [x] 1.8 DNS: cheap Clone via Arc<ResolverInner>
- [x] 1.9 process.rs: dedicated blocking-scan worker thread, never blocks tokio workers; IPv6 /proc support fixed
- [x] 1.10 dispatcher: per-destination UDP route cache + HashMap endpoints + Cow effective meta
- [x] 1.11 panic="abort" removed; network-path unwraps verified guarded or converted to errors
- [x] 1.12 dead mimalloc + DEFAULT_COPY_BUFFER_SIZE removed
- [x] 1.13 Dockerfile hardened (healthcheck, caps docs, EXPOSE fix)
- [x] 1.14 CI: sing-box installed for interop tests; interop tests skip gracefully without binary; machine-specific path removed

## Phase 2 — WireGuard ✅ (kept custom stack for AmneziaWG; hardened)
- [x] 2.1 IP-packet encapsulation in data plane (was: bare payload — broken vs real servers)
- [x] 2.2 session rekey (REKEY_AFTER_TIME=120s), automatic re-handshake, handshake serialization
- [x] 2.3 persistent keepalive (default 25s, configurable keepalive_secs)
- [x] 2.4 responder: mac1 DoS verification (constant-time), TAI64N freshness check
- [x] 2.5 local_address config; sing-box interop test still green

## Phase 3 — TUN → smoltcp ✅
- [x] 3.1 full rewrite: smoltcp stack actor, AnyIP transparent capture, per-flow socket bridging
- [x] 3.2 frame-level unit tests (SYN/ACK handshake, data roundtrip, UDP dispatch) — no root needed
- [x] 3.3 UDP session idle cleanup via UdpSessionClose

## Phase 4 — REALITY v2 ✅
- [x] 4.1 transcript-bound HKDF (client ephemeral + SNI), server auth tag in ServerHello.random
- [x] 4.2 timestamp window + LRU replay cache server-side
- [x] 4.3 honest docs: NOT XTLS-REALITY compatible (README + rustdoc)

## Phase 5 — Final verification (in progress)
- [ ] 5.1 full cargo test --workspace (running)
- [ ] 5.2 cargo build --release (fat LTO)
- [ ] 5.3 final report
