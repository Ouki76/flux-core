# Flux-Core Hardening Plan (audit remediation)

Baseline: cargo test --workspace (running)

## Phase 1 — Reliability & quick wins
- [ ] 1.1 ruleset: fail loudly on unreadable ruleset file (no silent empty ruleset)
- [ ] 1.2 ruleset: make compile() idempotent, remove path.clone() hack
- [ ] 1.3 DNS: precompile split-DNS rules (no format!/lowercase per query)
- [ ] 1.4 DNS: fix empty rule.servers → must not leak to system resolver
- [ ] 1.5 DNS: real TTL from DoH responses (remove hardcoded 300)
- [ ] 1.6 DNS: inflight query dedup (single-flight per domain)
- [ ] 1.7 DNS: AAAA support (concurrent A+AAAA, cache both, v4-preferred)
- [ ] 1.8 DNS: cheap Clone for DnsResolver (Arc-wrap servers/rules)
- [ ] 1.9 process.rs: non-blocking /proc scan (dedicated worker thread + request queue)
- [ ] 1.10 dispatcher: UDP route cache per destination (no route() per packet, no meta.clone per packet)
- [ ] 1.11 Cargo: remove panic="abort"; scrub unwrap() in network-data parsing paths (wireguard, vmess, ss2022, reality, vision, shadowsocks, trojan, vless, tuic, hysteria2, transport/*)
- [ ] 1.12 remove dead mimalloc dep + DEFAULT_COPY_BUFFER_SIZE dead constant + fix stress_bench banner
- [ ] 1.13 Dockerfile: non-root where possible, fix CMD/EXPOSE, healthcheck
- [ ] 1.14 CI: install sing-box in workflow or graceful skip when binary absent

## Phase 2 — WireGuard → boringtun
- [ ] 2.1 replace hand-rolled Noise/WireGuard with boringtun (keep wire-compat; sing-box interop test must pass)

## Phase 3 — TUN → smoltcp
- [ ] 3.1 replace hand-rolled TCP/IP stack with smoltcp (TCP retransmission/congestion/reordering handled properly)
- [ ] 3.2 keep UDP association behavior + ICMP echo reply; verify tun tests

## Phase 4 — REALITY honesty & hardening
- [ ] 4.1 bind handshake transcript into HKDF (anti-MITM hardening), bump wire version
- [ ] 4.2 document clearly: custom camouflage protocol, NOT XTLS-REALITY compatible

## Phase 5 — Docs & final verification
- [ ] 5.1 README updates (REALITY disclaimer, mimalloc claims, features)
- [ ] 5.2 cargo fmt + clippy -D warnings clean
- [ ] 5.3 full cargo test --workspace green
- [ ] 5.4 final report
