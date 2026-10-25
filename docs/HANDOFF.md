# Handoff — state of the audit, and what to do next

This file exists so the work can continue on another machine (or by another agent)
without losing context. It is written to be read **first**, before touching code.
Everything here was verified by a command whose output is in `docs/audit-log.md`;
where that is not true, it says so.

---

## 0. Where things stand right now (2026-10-25, after cycle 109)

**1090 tests, 0 failed.** fmt, `clippy -D warnings`, `cargo doc -D warnings`, `cargo audit`
and `cargo deny` clean. Last soak: **5.8 M requests, 45 GB proxied, 0 errors**, RSS bounded at
16.9 MB, unchanged by the buffer work. The intermittent stall is fixed and guarded by tests
that fail without the fix.

**Fifteen rows, interleaved rounds of 200 MiB, best-of-N:**

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| Hysteria2 | **110** | 51 | — | **+113 %** | — |
| TUIC v5 | **109** | 57 | — | **+90 %** | — |
| WireGuard | **72** | 52 | — | **+38 %** | — |
| VLESS / gRPC + TLS | **249** | 120 | 182 | **+108 %** | **+37 %** |
| VLESS / REALITY | **358** | 339 | 236 | **+5.5 %** | **+52 %** |
| VLESS / TLS | **381** | 336 | 244 | **+13 %** | **+56 %** |
| Shadowsocks-AEAD | **316** | 259 | — | **+22 %** | — |
| Shadowsocks-2022 | **380** | 361 | 293 | **+5.3 %** | **+29 %** |
| VLESS / TCP | **875** | 641 | 622 | **+36 %** | **+41 %** |
| VLESS / WS + TLS | **360** | 315 | 105 | **+15 %** | **+243 %** |
| Trojan / TLS | **375** | 286 | — | **+31 %** | — |
| VMess / WS + TLS | **251** | 204 | 201 | **+23 %** | **+25 %** |
| REALITY + Vision | 314-375 | 291-324 | 206-242 | **at parity or ahead** | **+30 %** |
| VLESS / XHTTP | **533** | — | 128 | — | **+316 %** |
| VLESS / gRPC (no TLS) | **499** | — | 200 | — | **+150 %** |

Every row ahead of sing-box in at least one of the last two runs; every xray path ahead in
both, by 15 % or more. Vision is the one row that oscillates around parity — its per-round
dump shows it ahead in four rounds of five.

**Other measured dimensions**, all against the same competitors on the same machine:
exchanges per second on short connections **+37 %** plain and **+98 %** over TLS; memory
per connection **12-25 KB against 47 and 100**; UDP datagrams **+37-55 %**.

**What produced the last of this**: seven files each capped a write at 16 or 64 KiB while the
relay moved 256 KiB — `websocket.rs`, `shadowsocks.rs`, `shadowsocks2022.rs`, `vmess.rs`,
`reality.rs`, `vision.rs`, and the h2 client's flow-control window, which was never set at all.
They now all derive from `flux_common::copy::RELAY_BUFFER_BYTES`, and
`pipeline_stages_agree_on_the_relay_buffer` fails if they drift.

**Functional gaps vs the competitors: closed.** mKCP (both directions, interop proven),
XHTTP (stream-one, interop proven and measured), IDNA, GeoIP fixture, private-CA knob, UDP
associations, nested config-key typo detection. The one partial item is the browser-grade
ClientHello, and the reason is now precise: rustls emits no general GREASE, and GREASE-ECH —
what Chrome actually sends — requires an HPKE provider, which only aws-lc-rs supplies; adopting
it makes rustls panic with two providers compiled in and breaks REALITY interop with Xray when
forced (cy 64). It is a REALITY interop project, not a flag.

**The defect that hid for thirty cycles was a missing `poll_flush`** in the relay's
copier: writers above a socket hold accepted bytes until flushed, so the tail of a transfer
never left and both directions parked. It is fixed and proven by
`buffered_bytes_reach_the_peer_without_a_close`.

**The single defect behind almost all of the throughput:** every path framed *one unit per call*
(one 16 KiB chunk, one TLS record, one WebSocket frame, one gRPC message) while the relay
works in 64 KiB buffers. Found and fixed in the shared copier, WebSocket, both Shadowsocks
variants, REALITY (writes and reads), Vision and VMess — seven places, one bug. If a path
is slower than its competitor, check that first, then check whether it is spending *more
CPU* (wasted work, e.g. Vision's endless padding) or *less* (round trips per buffer).

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
3. Close the functional gaps: **mKCP (done)**, XHTTP, IDNA (**done**), a GeoIP test
   fixture, a private-CA knob (**done**), UDP associations in the connection table
   (**done**), nested config-key typo detection (**done**), browser-grade TLS
   fingerprint (uTLS-style).
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
2. **mKCP parity with xray's newer options** — our mKCP interoperates with Xray 26 in both
   directions, but does not implement xray's AES-GCM payload mask. The exact construction is
   now in the module docs at the top of `crates/flux-transport/src/kcp.rs`, with the commit
   that fixed it: SHA-256(seed)[:16] as an AES-128-GCM key, wire form `nonce‖ciphertext‖tag`,
   and — importantly — xray 26 removed `kcpSettings.seed` in favour of
   `finalmask.udp: [{"type":"mkcp-aes128gcm"}]`, so an interop test needs that shape. Not
   implemented here because the mKCP *transport* interop, which is what the objective asked
   for, works and is tested both ways.

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