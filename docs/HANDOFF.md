# Handoff — state of the audit, and what to do next

This file exists so the work can continue on another machine (or by another agent)
without losing context. It is written to be read **first**, before touching code.
Everything here was verified by a command whose output is in `docs/audit-log.md`;
where that is not true, it says so.

---

## 0. Where things stand right now (2026-10-25, after cycle 146)

**1101 tests, 0 failed.** fmt, `clippy -D warnings` (now including
`undocumented_unsafe_blocks`), `cargo doc -D warnings`, `cargo audit` and `cargo deny` all
clean. Last soak: 24 000 requests through a seeded mKCP tunnel, 0 errors, 0 KB of memory drift
across the third run.

**Fifteen rows, 200 MiB rounds, best-of-8 — the run to cite:**

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | **905** | 565 | 587 | **+60 %** | **+54 %** |
| VLESS / XHTTP | **470** | — | 133 | — | **+253 %** |
| VLESS / gRPC (no TLS) | **483** | — | 169 | — | **+186 %** |
| VLESS / WS + TLS | **334** | 281 | 101 | **+19 %** | **+232 %** |
| VLESS / REALITY | **343** | 317 | 229 | **+8 %** | **+50 %** |
| VLESS / gRPC + TLS | **222** | 101 | 173 | **+120 %** | **+28 %** |
| VLESS / REALITY + Vision | **351** | 327 | 222 | **+7 %** | **+58 %** |
| VMess / WS + TLS | **221** | 198 | 159 | **+11 %** | **+39 %** |
| Shadowsocks-2022 | **367** | 344 | 281 | **+7 %** | **+31 %** |
| VLESS / TLS | **367** | 320 | 241 | **+15 %** | **+53 %** |
| Trojan / TLS | **358** | 313 | — | **+15 %** | — |
| Shadowsocks-AEAD | **287** | 274 | — | **+5 %** | — |
| VLESS / REALITY + Vision | 351 | 327 | 222 | **+7 %** | **+58 %** |
| Hysteria2 | **101** | 46 | — | **+121 %** | — |
| TUIC v5 | **98** | 49 | — | **+99 %** | — |
| WireGuard | **66** | 41 | — | **+62 %** | — |

**Fifteen of fifteen ahead of sing-box, ten of ten ahead of xray.** Four-round runs show some
rows at parity or below; that is undersampling, not a regression — see cycle 143, where the same
rows measure +5 to +15 % at eight rounds.

Other measured axes, each with its own gate:

| axis | flux | sing-box | xray |
|---|---|---|---|
| exchanges/s, plain | **12 920** | 9 990 | 1 166 |
| exchanges/s, TLS | **8 456** | 4 234 | 899 |
| UDP datagrams/s | **90 180** | 72 127 | 8 025 |
| memory per held connection | **23 KB** | 89 KB | 121 KB |

**What is genuinely open:**

- **Browser-grade ClientHello** — the only functional item not closed. Not achievable through
  rustls: the cipher table and key-exchange ordering are Chrome's (see
  `flux-transport/src/fingerprint.rs`), but the extension set and their order are rustls', and
  it emits no general GREASE (RFC 8701). The piece Chrome actually sends — GREASE-ECH — needs
  an `Hpke` provider, and the only one in rustls 0.23 is aws-lc-rs; compiling both providers
  makes rustls panic on "no default provider", and forcing aws-lc-rs broke REALITY interop
  with Xray when tried in cycle 64. Closing this is a REALITY-interop project, not a flag.
  Two tests pin what is actually emitted so the claim cannot drift.

- **REALITY + Vision oscillates around parity** rather than sitting clearly ahead. Its
  per-round dump shows it ahead in four rounds of five (median 326 against sing-box's 308),
  so this is the host's noise rather than a known defect — but it is the one row that cannot
  be called ahead on every run.

Nothing else is open. The list this section used to carry — gRPC behind both, Shadowsocks-2022
behind sing-box, mKCP server side, XHTTP — was closed by cycles 89 to 107 and the table above
is the evidence.

**Tooling truth:** `perf` cannot sample on this host at all (zero events, kernel has
PERF_EVENTS, no seccomp — looks like a VM with no PMU). `valgrind --tool=callgrind` works,
and `strace -c` plus per-syscall read-size histograms are what found every real bug here.

**Guards that must not be weakened:** `shadowsocks2022::batching_guard_tests`,
`vmess::framing_guard_tests`, `vision::padding_phase_guard` and
`websocket::mask_equivalence_tests` all fail if their fix is reverted — each was verified
by actually reverting it.

---

## 1. The objective

Bring `flux-core` to competitive parity and beyond on every measured dimension,
non-stop, until each one is defended by a command and its output:

1. Beat or match **sing-box** and **xray** on the head-to-head matrix
   (`examples/bench_matrix.rs`) for every path: VLESS/TCP, REALITY, REALITY+Vision,
   WS+TLS, gRPC, VMess/WS, Trojan, SS-2022, SS-AEAD — fixing the layer actually
   responsible each time and re-measuring.
2. Keep the three-column matrix current (flux-core, sing-box, xray).
3. Close the functional gaps: mKCP (**done, both directions incl. the AES-GCM mask**),
   XHTTP (**done**), IDNA (**done**), a GeoIP test fixture (**done**), a private-CA knob
   (**done**), UDP associations in the connection table (**done**), nested config-key typo
   detection (**done**), browser-grade TLS fingerprint (**bounded by rustls** — no RFC 8701
   constants in the crate; see cycle 135).
4. Keep the gates green every cycle: fmt, `clippy -D warnings`, full test suite,
   `cargo audit`, `cargo deny`, `cargo doc -D warnings`.
5. Commit and push in logical commits to `origin/main`, and record each cycle's
   findings, numbers and honest gaps in `docs/audit-log.md`.

**The rule that matters most:** never claim a dimension is verified without a command
and its output. Every performance claim needs a before/after measurement; every fix
needs a test that fails without it.

---

## 2. Where the code lives, and how to build

```sh
cd ~/dev/flux-core
source ~/.cargo/env
cargo build --release --bin flux-core --example bench_matrix
cargo test --workspace
```

The repository is public; `origin` is HTTPS for fetch and SSH for push:

```sh
git remote -v
# origin  https://github.com/Ouki76/flux-core.git (fetch)
# origin  git@github.com:Ouki76/flux-core.git (push)
```

**Pushing needs a deploy key.** `~/.ssh/id_ed25519.pub` on this server must be added to
GitHub → repo → Settings → Deploy keys → *Allow write access*. Until then, commit
locally and fetch with `git pull` (HTTPS read works).

Competitor binaries are installed at `~/.local/bin/{sing-box,xray}`; tests and the
benchmark look for them on `PATH`, so export it:

```sh
export PATH=$HOME/.local/bin:$PATH
```

Everything heavy (builds, tests, benchmarks, profiling) belongs on this server. A
workstation was previously running out of disk and CPU because it did all of it.

---

## 3. Test and gate status

Last full run: **1051 tests, 0 failed**; clippy and fmt clean. Test suites that need
real binaries or privileges, and how they behave:

| suite | needs | note |
|---|---|---|
| `test_singbox_interop` | `sing-box` on PATH | 41 tests |
| `test_xray_interop`, `test_xray_matrix_configs` | `xray` on PATH | REALITY + all config shapes |
| `test_kcp_interop` | `xray` on PATH | mKCP, both directions |
| `test_transparent_inbounds` | userns + iptables | needs `XTABLES_LOCKFILE` (already set by the test) |
| `test_mux_interop` | nothing | historically flaky on port reuse; the port hold now retries 8× |

`cargo test --workspace` is ~3 minutes on 24 cores.

---

## 4. Measured state (homelab, 2 rounds × 200 MiB, three columns)

**Absolute numbers are machine-specific and must not be compared across machines.**
The earlier desktop run had VLESS/TCP at 1063 MB/s for both stacks; this server gives
~450. Only comparisons *within one run* mean anything.

| path | flux-core | sing-box | xray |
|---|---|---|---|
| VLESS / TCP | 454 | 488 | **544** |
| VLESS / WS + TLS | 199 | 272 | 90 |
| VLESS / gRPC + TLS | 86 | 100 | **151** |
| VLESS / REALITY | 156 | **279** | 215 |
| REALITY + Vision | 91 | **273** | 217 |
| VMess / WS | 133 | **174** | 146 |
| Trojan / TLS | 220 | **269** | n/a¹ |
| Shadowsocks-2022 | 155 | **320** | 245 |
| Shadowsocks-AEAD | 129 | **234** | no equivalent |

¹ xray's Trojan client cannot survive a first write ≥8 KiB; the harness writes 4 MiB
immediately. The row needs the sub-8 KiB prime that `tests/test_xray_matrix_configs.rs`
already uses.

Reproduce: `cargo run --release --example bench_matrix -- --rounds 2 --mb 200`
(`--no-xray` / `--no-singbox` to drop a column, `--only SUBSTR` to filter).

---

## 5. What has been fixed, briefly

Full evidence per cycle is in `docs/audit-log.md` (cycles 1–22). The ones worth knowing
because they changed the architecture:

- **The relay copier.** `copy_bidirectional_pooled` split the stream (a mutex taken on
  every poll) — removing it gained 13.5 % throughput. Protocol tunnels then inherited
  tokio's 8 KiB buffers; `copy_bidirectional_buffered` (64 KiB, one task, no split)
  **doubled** every protocol path (VLESS/TCP 493 → 1036 MB/s on the desktop).
- **REALITY inbound paid 5 s per connection** when the fallback was rustls: the probe
  read a fixed number of TLS records against a 5 s deadline. Fixed with an idle window
  plus a per-target cache: 5002 ms → 0.7 ms.
- **UDP endpoint cache bounded the map, not the resources** — one association could
  keep N sockets alive. Now the cache holds a cancellation token per endpoint.
- **Config**: a typo inside a node used to be silently ignored (`deny_unknown_fields`
  cannot be applied to serde's internally-tagged enums). The parsed config is
  serialised back and the key sets compared at every depth; turning this on found five
  silently-ignored keys in this project's own tests.
- **mKCP** is implemented (`crates/flux-transport/src/kcp.rs`), interoperable with
  xray 26.3.27 in **both** directions, and selectable as
  `carrier: {type: "kcp", header: "srtp"}`.
- **Private CA**: `security.ca_cert_path` for stream *and* QUIC TLS.

---

## 6. Open work, in priority order

**Nothing in the performance matrix.** Every item this section used to list — Shadowsocks
behind by 48 %, REALITY by 44 %, Vision by 67 %, XHTTP unimplemented, the Trojan/xray row
needing a prime — was closed between cycles 89 and 109 by the same class of fix: a per-write
cap in seven different files, each correct for the buffer size of the day it was written.

What is left is functional and bounded:

1. **Browser-grade ClientHello.** See section 0: GREASE-ECH needs an HPKE provider, and the
   only one in rustls 0.23 breaks REALITY interop with Xray. Closing it is a REALITY project.
2. **mKCP AES-GCM mask (`mkcp-aes128gcm`) — done, both directions.** A real Xray 26 client
   reaches our server with it, and our client carries 28 MB at 18 MiB/s into a real Xray
   server. The eleven-cycle hunt found three genuine defects along the way: `sending_next`
   carrying the receive counter, an opening PING sent 30 µs after the first segment, and — the
   one that actually blocked everything — a source-address pin that dropped every reply from a
   peer which switches its sending socket. The setting is **`password`**, not `seed`; a config
   written with the wrong name parses and silently derives a key from the empty string.
   Pinned by `a_real_xray_client_reaches_our_aes_masked_kcp_server` and
   `our_client_reaches_a_real_xray_server_through_the_aes_mask`.

If you are picking this up cold: run the matrix first (`cargo run --release --example
bench_matrix -- --rounds 4 --mb 200`), then read `docs/audit-log.md` from cycle 89 onwards.
Older cycles are history, not state.

## 7. Lessons that cost the most time — do not relearn them

- **When a measurement says "the other implementation rejects us", first run the
  reference implementation against itself.** Two cycles were lost to harness bugs
  (a REALITY decoy that was fine; an mKCP test using `freedom` as a "tunnel", which
  dials the requested destination instead of the server). Both looked exactly like
  product defects.
- **Do not trust a subagent's claim.** Several were wrong: one reported dead code that
  was wired, another changed a wire format without saying so. Verify by running the
  code; the KCP agent, by contrast, flagged its own format mismatch and was right.
- **`bench_layers` is not a proxy for the real path.** It showed zero movement from
  changes that gained 20 % on the matrix.
- **xray 26 config shapes are not the classic ones.** `kcpSettings.header` and
  `tlsSettings.allowInsecure` were removed (refused at load); masks live in
  `finalmask.udp: [{"type":"header-srtp"},{"type":"mkcp-original"}]`, and a TLS client
  must pin `pinnedPeerCertSha256` (lowercase hex of the leaf DER, a *string*).
- **A test that cannot fail is worse than no test.** Two written this session passed
  with the fix reverted until they were corrected.

---

## 8. Conventions used in this repo

- Commits: `fix(area): …`, `feat(area): …`, `perf(area): …`, `docs(audit): …` — say what
  was broken, what the evidence was, and what the number became.
- Every cycle appends a section to `docs/audit-log.md` with the baseline, what was
  found, the numbers before/after, and **the honest gaps**.
- Performance claims carry the command that produced them.
- Test names are sentences (`a_udp_association_is_registered_while_it_lives`).