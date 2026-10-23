# Handoff — state of the audit, and what to do next

This file exists so the work can continue on another machine (or by another agent)
without losing context. It is written to be read **first**, before touching code.
Everything here was verified by a command whose output is in `docs/audit-log.md`;
where that is not true, it says so.

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

1. **Shadowsocks is the largest measured gap** (−48 % SS-2022, −45 % SS-AEAD) and it is
   not the cipher: this host's AES-128-GCM does 5.9 GB/s (`openssl speed`). Our CPU per
   GiB is 1.5× sing-box's, which points at copies, not crypto. **Needs a profiler** —
   `perf` and `samply` are now installed, which they were not when this was last
   attempted. Recipe:
   ```sh
   export PATH=$HOME/.local/bin:$PATH
   cargo build --release --example bench_matrix
   ./target/release/examples/bench_matrix --rounds 6 --mb 200 --only Shadowsocks-2022 --no-xray &
   pid=$(pgrep -f 'flux-core run' | head -1)
   perf record -F 2000 -g -p $pid -- sleep 8
   perf report --stdio --sort symbol | head -40
   # or, with a flamegraph:
   samply record -p $pid
   ```
   Suspects already ruled out: the per-chunk `resize(…, 0)` (fixed, no change), the
   cipher, and buffer size. Next suspects: two AEAD calls per 16 KiB chunk (one on a
   2-byte length), a copy into `write_buf`, and a copy out of `read_buf`.
2. **REALITY −44 %** and **Vision −67 %**. Vision's cost is its 8 KiB framing with
   padding; it switches to direct copy only when the payload looks like TLS, which a
   synthetic benchmark never does — **for Vision the competitor is xray, not sing-box**
   (sing-box ignores the flow field). Compare against the xray column only.
3. **Trojan/xray row**: add the sub-8 KiB prime so the row measures something.
4. **Functional**: XHTTP transport, GeoIP test fixture (needs an `.mmdb`), uTLS-style
   fingerprint. mKCP still lacks xray's `seed`/AES-GCM mask, PING/TERMINATE liveness and
   `tti`/`uplinkCapacity` pacing.

---

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