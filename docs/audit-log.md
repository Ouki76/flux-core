# Audit log

Continuous, evidence-based audit. Every entry names the command that produced the
result. A dimension is only marked green when there is output showing it; claims
without a command are not accepted, and subagent reports are re-run by the
maintainer before they are trusted (one reported "dead protocol" earlier turned
out to be a broken build on the reviewer's side).

## Cycle protocol

1. Re-verify the baseline: `cargo fmt --check`, `cargo clippy --workspace
   --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit`,
   `cargo deny check`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`.
2. Pick the weakest areas. Priority order: (a) code written most recently and
   covered least, (b) the worst measured numbers, (c) anything a previous cycle
   left as "documented gap".
3. Fan out subagents with disjoint file ownership so they cannot collide.
4. Re-verify every claim by running the code.
5. Fix, prove with a test that fails without the fix, commit, push.
6. Append the result here, including what was NOT fixed and why.

---

## Cycle 1 — 2026-10-22

### Baseline

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | clean |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Tests | `cargo test --workspace` | **478 passed, 0 failed** |
| Advisories | `cargo audit` | 0 vulnerabilities (1 documented `unmaintained` warning) |
| Policy | `cargo deny check` | advisories/bans/licenses/sources ok |
| Docs | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | clean |

### Leak / stability soak (4 minutes, sustained load)

`scripts/soak.sh 240` — 64 short-connection workers + 8 long-lived streams:

```
requests: 3,349,277   errors: 0   bytes proxied: 26,166 MB
RSS 11.6 / 12.8 MB (min/max), head-median 12.5 → tail-median 12.6 MB (+1%)
FDs bounded (final 270, sampled 553–588 under load), threads flat at 18
OK: bounded memory
```

No leak in RSS, file descriptors or threads under 3.3M requests. This is the
strongest available evidence for "it stays up".

### Measured performance (release, this machine, byte-integrity verified)

| Path | Throughput | CPU s/GB |
|---|---|---|
| TCP relay, single stream | 2113 MB/s (+8.8% vs sing-box 1943) | 0.63 |
| TCP relay, 64 concurrent streams | 3496 MB/s (peak) | 0.30 |
| TCP relay, 2048 streams | 1344 MB/s, RSS 15.6 MiB | 3.53 |
| UDP relay (SOCKS5) | 118k datagrams/s | – |
| VLESS + TLS | 542 MB/s | 2.71 |
| VLESS + REALITY | 375 MB/s | 4.78 |
| **TUN (smoltcp)** | **308 MiB/s** | **7.89** |
| **WireGuard (Noise + smoltcp)** | **58 MB/s** | **50.3** |

The two userspace-stack paths are the weak points and are the subject of this
cycle's performance workstreams.

### Findings and fixes this cycle

Four workstreams ran in parallel. Every fix below is proved by a test that fails
without it (verified by reverting), and every performance number was re-measured
by the maintainer before being believed.

| Area | Found | Fixed | Evidence |
|---|---|---|---|
| smux `mux.rs` (new code, ~2500 lines) | **8** | 8 | 11 new tests; 10 of them fail on the previous code |
| DNS subsystem (recently rewritten) | **6** | 6 | 8 new tests in `test_dns_hardening.rs` + structured fuzz |
| WireGuard datapath | 2 (+1 pre-existing memory bug) | 3 | 64 → 93.6 MB/s, CPU 46 → 21.4 s/GB, RSS 503 → 27 MiB |
| TUN datapath | 4 | 4 | 324 → 745 MiB/s, CPU 6.7 → 3.4 s/GB |
| Config wiring | 1 (IPv6 fake-IP unreachable) | 1 | 2 new tests; the feature was dead code before |
| Hardening (mine) | 3 | 3 | DNS rate limit, upstream exchange budget, resilience tests |

Notable individual defects:

- **smux**: a writer could hang forever — a `Notify::notified()` future was built
  in a local and dropped while returning `Pending`, deregistering the waiter. Also
  one leaked stream slot per UDP association, one detached task per FIN frame under
  backpressure (2000 FINs → 1992 tasks), and a buffer bound that allowed 64× the
  configured budget.
- **DNS**: 83× reflection amplification (the relay ignored the client's UDP payload
  size), SERVFAIL cached as "does not resolve" for up to an hour, and a trailing-dot
  FQDN bypassing every split-DNS rule — a real DNS leak of internal names.
- **TUN**: `mtu` was a **no-op** — stored, logged and used to size a buffer, but
  never written to the device, so the kernel always segmented at 1500 bytes and no
  configuration could change it. Fixing it exposed two further defects (socket
  buffers not scaling with the MTU, and smoltcp's 10 ms delayed ACK) that made
  jumbo packets collapse to 58 MiB/s.
- **WireGuard**: an unbounded proxy→socket queue held one byte of RSS per byte
  transferred (503 MiB resident during a 512 MiB transfer).

### Reliability of the suite itself

The full suite was run repeatedly, including with six CPU-saturating background
loops: **516 passed, 0 failed** every time. Twice during the session two tests
failed when the machine still had leftover processes from a benchmark run; the
suite is green once they exit. Recorded here because a flaky suite is a defect
too — the next cycle should make the process-spawning helpers diagnose a busy
port explicitly instead of timing out.

### Numbers after the cycle

| Path | Before | After |
|---|---|---|
| WireGuard | 58–64 MB/s, 46–50 CPU s/GB, RSS grew 1:1 with bytes | **93.6 MB/s, 21.4 s/GB, 27 MiB flat** |
| TUN (MTU 1500) | 308 MiB/s, 7.89 s/GB | 324 MiB/s, 6.67 s/GB |
| TUN (jumbo 9000, new default) | *unreachable — mtu was a no-op* | **745 MiB/s, 3.40 s/GB** |

### Open items handed to cycle 2

1. `crates/flux-inbound/src/tun.rs::run_stack_channels: parse_ip_packet` copies the
   whole payload on **every** inbound frame (up to 3× per packet) just to detect a
   new flow. A header-only peek removes one alloc+copy per packet.
2. The inbound stack actor is still a separate task from the carrier: merging them
   is what bought +24 % on the client side, and is the last cross-task hop.
3. UDP GSO/`UDP_SEGMENT` would break the one-syscall-per-packet floor at MTU 1500
   (measured ceiling: MTU 1500 is already at 85–95 % of its syscall floor).
4. The suite should surface a busy port as such instead of a start timeout.

