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


---

## Cycle 2 — 2026-10-22

### Baseline

Same commands as cycle 1: fmt, clippy `-D warnings`, `cargo test --workspace`
(516 tests), `cargo audit`, `cargo deny check`, `cargo doc -D warnings` — all
green at `de7f75d`.

### Coverage — measured for the first time

Earlier cycles could not measure coverage (no rustup, no `llvm-tools`). An
isolated toolchain was installed into `~/.local/rustup` **without touching the
system toolchain**, and coverage was collected with `-C instrument-coverage`:

```
cargo test --workspace --lib --tests          # with RUSTFLAGS=-C instrument-coverage
llvm-profdata merge -sparse cov-prof/*.profdata
llvm-cov report --instr-profile=... <test binaries> --ignore-filename-regex='(/rustc/|\.cargo/|/registry/|tests/|examples/)'
```

Result: **53.25 % of lines, 55.20 % of regions, 55.40 % of functions** across the
library crates (30,329 regions, 13,588 hit).

Caveat recorded honestly: the number under-reports generic code that is only
instantiated inside test binaries (e.g. `fragment.rs` reports 0 % although it has
5 passing tests), so it is used as a *relative* signal, not an absolute score.

Worst files by percentage, with the number of tests that actually exist:

| File | Coverage | Tests |
|---|---|---|
| `flux-transport/src/pipeline.rs` | ~0 % | **0** → fixed this cycle |
| `flux-transport/src/fingerprint.rs` | 26 % | 2 |
| `flux-transport/src/httpupgrade.rs` | 32 % | 2 |
| `flux-app/src/ruleset_fetch.rs` | 45 % | – |
| `flux-transport/src/websocket.rs` | 46 % | 2 |
| `flux-transport/src/reality.rs` | 50 % | 10 |

### Fixed this cycle

**The dominant finding: one root cause behind three separate "slow" numbers.**
The `aes-gcm` crate drives AES one block at a time and never pipelines AES-NI.
Microbenchmarked on 16 KiB records (enc+dec pair): `aes-gcm` 1.75 GB/s vs `ring`
11.07 GB/s for the identical in-place call. Three protocols and one transport were
paying it.

| Path | Before | After | CPU s/GB |
|---|---|---|---|
| Shadowsocks-2022 (blake3-aes-128-gcm) | 805 MB/s | **3792 MB/s** | 1.23 → 0.27 |
| Shadowsocks-AEAD (aes-256-gcm) | 748 MB/s | **3323 MB/s** | 1.33 → 0.30 |
| VMess (aes-128-gcm) | 767 MB/s | **3676 MB/s** | 1.23 → 0.27 |
| VLESS + REALITY | 375 MB/s | **729 MB/s** | 4.78 → 2.14 |
| TUN, MTU 1500 | 349 MiB/s | **466 MiB/s** | 6.6 → 6.1 |
| TUN, jumbo 9000 | 767 MiB/s | **1268 MiB/s** | 3.3 → 2.4 |

REALITY is now faster than the rustls TLS path in the same harness (654 MB/s) and
at parity with unencrypted VLESS (673 MB/s). Wire compatibility is proved by the
41 sing-box interop tests and 4 Xray tests, not by inspection.

Two secondary findings worth recording:

- **TUN was window-limited, not syscall-limited.** A socket buffer *is* the
  advertised window and must cover the bandwidth-delay product, not a segment
  count; the old 64 KiB floor throttled the flow. Raising it to 256 KiB unlocked
  the other fixes (the pump merge was worth +19.5 % only once the window stopped
  being the bottleneck). Cost: 4× per-connection memory, documented in the
  CHANGELOG with the constant to revert.
- **A hypothesis that measured wrong and was reverted**: coalescing the record
  read syscalls in REALITY (2.10 → 0.58 syscalls/record) made the transport 5 %
  *slower* because the window straddles records and forces compaction memmoves.
  Reverted rather than kept as a plausible-looking change.

- **`pipeline.rs` had no tests at all** (304 lines, the composition point for every
  security and framing layer). Added 9: a real listener plus the client pipeline,
  then a byte-exact round trip through raw, WebSocket, HTTPUpgrade, HTTP/2 and gRPC
  framing, two layers composed (fragmentation under WebSocket), a path mismatch
  being rejected, and the accessor contract.

### Test-suite reliability (recurring)

The suite failed twice this session with `AddrInUse` in the mux interop tests.
Root cause found: **benchmark runs orphan their spawned `flux-core` children**
when the harness is killed by `timeout`, and those children hold ports in the test
range. Not a product bug, but it wasted two full runs — cycle 3 should make the
port allocator resilient to a foreign listener rather than relying on manual
cleanup.

Final state after cleanup: **525 tests, 0 failed** (was 516; +9 pipeline tests),
fmt/clippy/audit/deny/doc all green.

### Open: a rare mux teardown race

One full-suite run failed with, in `test_mux_vless_flux_to_singbox`:

```
read echo: InvalidData: "mux stream closed before the server status byte"
```

Reproduction attempts: **30 clean runs** (20 isolated, 10 with eight CPU-saturating
background loops and 8 test threads each) — not reproducible. The message is
raised when the client's handshake is still waiting for the server's status byte
and the underlying session reports EOF (`mux.rs:1209`/`:1217`), i.e. a teardown
race between the peer closing the session and the reply arriving, not a data
corruption. Cycle 3 should either reproduce it deterministically (e.g. by closing
the session from the server at a chosen point) or add the session's event state to
the error so the next occurrence is diagnosable.
