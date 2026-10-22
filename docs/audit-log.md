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

## Cycle 6 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 646 tests, audit, deny, doc — green at `e3a68a2`.

### Theme: the pre-authentication surface

Everything audited this cycle consumes **untrusted bytes before authentication** —
the most exposed code in a proxy. None of it had unit tests. Result: **29 defects**.

#### Inbound protocol parsers — 6 defects (43 tests)

| Defect | Consequence |
|---|---|
| VLESS answered an **unknown command** with the response header (the "authenticated, go ahead" signal) and only then dropped the connection | A command we cannot serve was acknowledged as if it were valid |
| VLESS's mux branch ignored the command | A UDP request to the mux destination was handed to smux, so datagram framing was parsed as mux frames |
| VLESS accepted Vision addons with a non-TCP command | Flow silently dropped |
| Trojan read the UDP frame terminator `[addr][len][CRLF][payload]` and threw it away | Any two bytes accepted there — a peer could park another frame's header in the gap |
| VMess "repaired" an unknown security byte by falling back to AES-128-GCM | security 0/1/2/5/6/15 accepted and dispatched, then decrypted under the wrong cipher |
| VMess never validated the command or option bits | Global padding and authenticated length change the chunk layout; ignoring them desyncs the stream |

The parsers themselves live in `flux-protocol` and were already hardened by earlier
cycles; the defects were in the glue and in two inline post-auth UDP frame readers.

#### TUIC + Hysteria 2 inbounds — 22 defects (66 tests)

TUIC: no deadline on the CONNECT header read (an idle bi-stream parked a task for
the connection's lifetime); the user list consulted **before** the token, returning
early on an unknown UUID (an oracle for which UUIDs exist); the authenticated
identity was a bare `bool`, so multi-user sessions carried no `user` in QUIC mode;
an **unbounded** UDP association table (65 536 slots per connection, each a channel
and two tasks) freed only on DISSOCIATE, so a dead association leaked its sender
forever; one oversized reply killing its association; a u16 reply length wrapping
silently; no cap on the received datagram size.

Hysteria 2: a malformed datagram **panicked** (slice index) instead of erroring;
destinations of ≥64 bytes were **silently dropped** because the QUIC varint length
was read as a raw byte, and the reply encoder wrote a byte where the protocol uses
a varint — a real interop bug on both sides; the password was compared with `==`
(memcmp early exit); an unknown command silently became TCP; 64 KiB allocated
pre-auth from a client length; no deadline at any handshake stage; `frag_total == 0`
accepted as "unfragmented"; `udp_sessions` keyed on a 32-bit client id and never
removed; `Hysteria-CC-RX` never parsed at all.

Both files were refactored so the parsing/dispatch core is pure functions
(`parse_connect_header`, `ConnAuth`, `UdpAssocTable`, `parse_udp_datagram`,
`read_varint`, …) and `start()` is a thin wire-up — that is what made them testable
at all.

**Premise correction:** the brief assumed both protocols are multi-user. Hysteria 2
has a single password and no user concept; that is stated rather than papered over.

#### Routed findings, fixed here

- `quic.rs` advertised a **4 MiB datagram receive buffer**, which is the peer's
  `max_datagram_frame_size`: quinn would allocate and hand an inbound a 4 MiB
  datagram per packet before any check ran. Now 64 KiB.
- `BrutalPacer::new` multiplied before clamping, overflowing for `mbps > ~1.8e13`
  (panic in debug, wrap to zero in release) and then dividing by zero in `pace()`.

#### Management API — request framing

`Content-Length` was parsed last-one-wins and `Transfer-Encoding` was ignored
entirely. Behind a reverse proxy that is the classic request-smuggling pair. A
`Transfer-Encoding` header is now refused outright (chunked bodies are not
implemented, so ignoring it was never safe), a non-numeric `Content-Length` is a
400, and two conflicting ones are a 400 rather than a choice. Three of the five new
tests fail on the previous code.

### Open: a ~5 s stall on the first Hysteria 2 request

Measured independently: `test_hy2_salamander_obfs_e2e` takes **5.67 s** although the
server answers the auth request in **27 µs**, and every Hysteria 2 test (including
one in `flux-transport`) carries the same ~5.5 s. The deliberate "reject a plain
client" test takes 10.11 s, which is its own 10 s timeout and is expected. A 5 s
gap with a microsecond reply smells like a QUIC retransmission timer or a poll
interval on the first request — it inflates the suite and every real client's first
request, and deserves its own cycle with a phase-instrumented reproduction.

### State

**762 tests, 0 failed** (was 646). fmt/clippy/audit/deny/doc green.

---

## Cycle 5 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 576 tests, audit, deny, doc — green at `6f8b7a4`.

### Theme: the two least-tested transports, and they were the worst yet

Cycle 4's method — test the camouflage layers against their specs — was applied to
the files it had not reached. **23 defect groups** between them.

#### `websocket.rs` — 13 defect groups (4 → 44 tests)

The silent ones:

| Defect | Consequence |
|---|---|
| `poll_shutdown` never sent a close frame | A peer could only ever report abnormal closure `1006` |
| A bare TCP EOF was `Ok(0)` | Reported as a clean end of stream instead of abnormal closure |
| Masking never checked against our role | The server accepted unmasked client frames; the client accepted masked server frames |
| No UTF-8 validation at all | Invalid text frames delivered verbatim; a code point split across fragments was never checked |
| A frame declaring `2^63-1` bytes | Parked the stream **forever** instead of being refused; non-minimal lengths and a 64-bit length with the high bit set accepted |
| Fragmentation sequencing unenforced | An orphan continuation was delivered as data; a new data frame inside a fragmented message was merged into it |
| Close frames never read, replied to or validated | Codes `0, 999, 1005, 1006, 1015, 5000, 65535` all accepted |
| Client accepted `HTTP/1.0 101` and a 101 with no `Upgrade`/`Connection` | A captive portal could be taken for a tunnel |
| CRLF in host/path/header value | Split the request on the wire — the same class as cycle 4's httpupgrade finding |
| Server upgraded 8 malformed requests | Duplicate key/version headers resolved last-wins, no `Host`, key not 16 bytes, colon-less header |

Streaming is preserved: validation is per-frame with an incremental UTF-8 state
machine carried across fragments, so a tunnel keeps its unbounded-message property.

#### `shadowtls.rs` — 10 defects (2 → 26 tests)

- **No replay protection at all** — the hello's HMAC is a bearer credential, so a
  captured hello authenticated again. Fixed with a bounded session-id LRU.
- **The `server_names` allow-list was never enforced**: the SNI was not even parsed.
- **Three tag comparisons were short-circuiting slice equality** — a timing oracle
  on a 32-bit tag. Replaced with an OR-reduction and proved by a test that counts
  bytes touched.
- Two buffered-byte bugs of the class already found in `reality.rs` and TUN: a
  poll-local decoy-skip counter that consumed the next record's bytes, and an
  authenticated empty frame not recognised as the switch point (relayed to the
  cover site, chain desynced, hang until timeout).
- `poll_write` could report **more bytes than the caller supplied** (panics
  `write_all`), spun forever on an inner `Ok(0)`, and the length check ran after
  reading the tag.

#### Config: two fields that went nowhere

The ShadowTLS `version` was destructured away (`{ password, sni, .. }`), so a v1/v2
config was **silently served as v3**; and the inbound's `server_names` was a
`vec![]` literal in the builder, so the allow-list added in the transport could not
be configured at all. Both fixed: an unimplemented version is refused with an error
naming both values, the field defaults to 3, and `server_names` is a real config
field. Mutation-tested.

### Also fixed: my own flaky test

`test_tls_fingerprint_length_fields_are_enforced` asserted that shortening the last
extension's length field must be rejected — but rustls shuffles extension order per
connection and emits some extensions (e.g. `session_ticket`) with an empty body, so
when a zero-length extension lands last the "mutation" is a no-op and the assertion
compares 0 with 0. The test now skips the degenerate case, with the reason in a
comment. It was caught by the full run after passing in isolation — which is the
argument for running the whole suite before claiming anything.

### State

**646 tests, 0 failed** (was 576). fmt/clippy/audit/deny/doc green.

---

## Cycle 4 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 552 tests, audit, deny, doc — green at `90b5a8c`.

### Theme: the camouflage and the rule engine — code whose bugs are silent

Both areas share a property: when they break, nothing errors. The connection still
"works" or the config still loads, and the damage shows up somewhere else. Eight
defects were found this cycle, all proved by tests that fail on the old code.

#### `httpupgrade` — 6 defects (2 → 14 tests)

| # | Defect | Consequence |
|---|---|---|
| D1 | The client accepted **any 2xx** as a protocol switch | A captive portal or proxy error page became "a tunnel": the first ciphertext bytes were written into someone's HTML response — silent failure plus a data leak |
| D2 | Status matched with `contains("101")` | `1010`, `500 Internal Server Error: 101`, `400 101 Switching Protocols` all accepted |
| D3 | `host`, `path`, header names/values interpolated unvalidated | A `\r\n` in any of them **injected a header or a second request** into the tunnel |
| D4 | Server accepted a request line with no HTTP version | Request-line smuggling surface |
| D5 | Server never inspected `Connection`; duplicate `Upgrade` won last-one-wins | A plain `GET` carrying `Upgrade` was promoted to a raw tunnel (RFC 9110 §7.8 wants both tokens) |
| D6 | Header lines without a colon were silently ignored | obs-fold / smuggling ambiguity |

Everything is now validated **before a single byte is written** (the tests assert
the peer sees 0 bytes), the client requires `HTTP/1.1 101`, and the server enforces
the request-line and header grammar. Wire format unchanged: 42 sing-box and 5 xray
interop tests pass against the stricter server.

#### `ruleset` — a broken feed could silently erase working rules

- `parse_rule_line` accepted almost any line: an HTML error page became a rule
  (`</html>` contains a slash, so it parsed as an IP-CIDR) and any bare word became
  a domain suffix. A captive-portal response therefore produced a rule set that
  looked **non-empty** and matched nothing — the worst outcome, because every
  `rule_set` rule silently falls through to the final outbound.
- `apply_content` always swapped, so a refresh that parsed to zero usable entries
  replaced a working rule set with an empty one. `try_apply_content` now keeps the
  previous contents and the refresh loop says so.

For a proxy this is a privacy bug in one direction (traffic meant to be tunnelled
goes direct) or a leak in the other, and it is now covered by 8 tests: five garbage
shapes must yield zero entries, sixteen legitimate shapes must parse exactly as
before, an empty refresh keeps the old rules while a partial one is still applied.

#### `reality` — the ClientHello had no ALPN

Every browser offers `h2` and `http/1.1`; ours offered nothing, which is a louder
non-browser signal than anything the extension set contains. Added, with a test
that walks the emitted extension block, validates every length, rejects duplicates
and requires SNI/supported_versions/supported_groups/key_share/signature_algorithms/
ALPN. Verified by mutation: deleting the ALPN block fails the test with
"no ALPN extension — a browser always sends one".

### Premise correction: `fingerprint.rs` does not encode a ClientHello

The brief assumed it did. It is 103 lines of policy tables — the profile enum plus
three provider builders that set only cipher suites and kx groups; rustls owns the
encoder. Its tests (2 → 8) therefore pin what it actually controls, plus the
structural integrity of the emitted ClientHello. Two facts had to be measured
rather than assumed: rustls **shuffles order-insensitive extensions per
connection** (a fixed-order assertion was flaky and was fixed to assert set
equality), and it appends the renegotiation SCSV `0x00ff` when TLS 1.2 is enabled.

### Recorded gap (not a code bug): our TLS fingerprint is not a browser's

rustls gives no GREASE, no record padding and no control over extension order; the
emitted set is 11 extensions against ~15 + 2×GREASE for Chrome, and ALPS,
`compress_certificate`, `delegated_credentials`, SCT, `renegotiation_info` and ECH
are absent. JA3/JA4 equivalence needs a uTLS-style encoder — a design change, not a
test fix. Documented so it is a known limit rather than an assumption of stealth.

### Measurement trap worth recording

After reverting the unfinished GSO work, the benchmark reported **5–7 MB/s** for a
tree that had just measured 143 MB/s three times. The cause was not a regression:
`bench_wireguard` spawns `target/release/flux-core`, and that binary had been built
from the reverted-in-source but still-on-disk edited state. `git checkout` restores
sources; it does not rebuild. Rebuilding restored 138.7 MB/s (min 136.9, max 141.5).

This is the same class of error as the withdrawn 205.6 MB/s figure: the measurement
harness spawns the binary, so *the binary is part of the experiment*. Every cycle
from here on rebuilds `--release` after any revert, and the audit protocol now says
so explicitly.

### Open: the inbound-GSO stall (investigated, not solved)

Enabling GSO on the *inbound* egress reaches 205–215 MB/s but is bimodal: 12/12
runs at 9.8–25.6 MB/s with it, 12/12 at 139–146 without. Nothing is lost (kernel
drop counters 0, zero AEAD rejections, peer datagram count matches), and the peer's
RTT stays ~100 µs through a collapse, so it is a stall bounded by a 1 s TCP RTO, not
loss. The shipped configuration keeps per-datagram `sendmmsg` on the inbound and
records the evidence at the call site.

A second attempt at this ran for over two hours, produced ~760 lines of diagnostic
instrumentation and no verified mechanism, and was **stopped and reverted**: the
tree is back to the committed, verified state rather than carrying unreviewed
probes. The honest status is "reproducible, mechanism unknown" — worth +40 % on this
path when someone finds it, and the deterministic repro (`WG_NO_GSO_TX=1` against a
run where the inbound also coalesces) is documented.

---

## Cycle 3 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 525 tests, audit, deny, doc — green at `a45d9f5`.

### The weakest measured dimension: WireGuard — 58 → 143 MB/s

| | cycle 0 | cycle 1 | cycle 3 |
|---|---|---|---|
| throughput | 58 MB/s | 93.6 MB/s | **143 MB/s** |
| CPU per GB | 50.3 s | 21.4 s | **13.5 s** |

What did it, in the order it was found and attributed:

1. **ring's ChaCha20-Poly1305** instead of the RustCrypto crate (the same backend
   gap cycle 2 found for AES-GCM in three other protocols). The profile showed the
   Poly1305 *per-message key setup*, not bulk throughput; the schedule is now
   expanded once per session. Isolated with a null-cipher build: AEAD cost
   5.9 → 2.2 s/GB. `97.6 → 125.5 MB/s`.
2. **UDP GSO (`UDP_SEGMENT`) on the outbound egress only**: equal-sized datagrams
   to the peer become one super-packet, so N datagrams cost one syscall, one route
   lookup and one skb. Kernel floor per datagram, measured standalone: plain
   `sendto` 5.0 CPU s/GB, `sendmmsg` 4.28, `sendmsg`+`UDP_SEGMENT` **0.80**.
   Sender-side only, so a stock WireGuard peer sees ordinary datagrams.
   `125.5 → 143 MB/s`.
3. Inbound frame channel: backpressure instead of a silent drop (correctness — a
   dropped frame inside a TCP tunnel costs the flow a retransmit timeout).

#### Correction: a number in this log was wrong, and here is why

An earlier revision of this entry claimed **205.6 MB/s at 9.34 s/GB** and committed
it (`317f057`). That figure is **not reproducible** and has been withdrawn.

What happened: the build in that commit also enabled GSO on the *inbound* egress.
That configuration is **bimodal** — 12/12 runs at 205–215 MB/s when only the
outbound uses GSO, 12/12 runs at 9.8–25.6 MB/s when the inbound does too. The
first measurement recorded showed `min 14.9 MB/s`, which is the collapse mode in
plain sight; it was dismissed as cold-start, and a second run at a different size
happened to land entirely in the fast mode. The commit was made on one lucky
sample.

Corrected state (`2e24dfc`): inbound GSO reverted, per-datagram `sendmmsg` kept
there, evidence written at the call site. Re-measured independently three times
after the revert: 143.3 / 142.8 / 143.9 MB/s (min 139.5), CPU 13.1–13.6 s/GB,
integrity byte-verified, RSS 28 MiB.

The lesson is recorded deliberately: an outlier in the minimum is a signal about
the *configuration*, not about the first round being cold — and a single lucky
sample is not a measurement.

#### The TUN window prior did not transfer

A window sweep was run first, as the TUN finding from cycle 2 suggested
(9 rounds per point, 4 interleaved passes, A/A noise ±1.2 %): 64 KiB 97.1,
128 KiB 99.1, 256 KiB 101.2, 384 KiB 100.4, 512 KiB 99.8 MB/s — +4 % total and CPU
per byte *rising*. Unlike TUN, this pump already keeps a burst in flight, so 64 KiB
covers the bandwidth-delay product. `WG_TCP_BUF` stays 64 KiB and the stale
"measured, no effect" comment was replaced with this table.

#### Honest ceiling

At MTU 1420 the kernel alone charges ~4.25 CPU s/GB per direction to move one
datagram per packet even when batched; plus 2.2 for the AEAD ⇒ ~10.7 s/GB ⇒
**~190 MB/s** is the limit of a per-datagram design at that MTU, and only if the
inbound send path also gets GSO (the work that had to be given back). The same code
at inner MTU 8192 measures **231 MB/s at 9.1 s/GB**, so the honest lever past 200
is a configurable inner MTU — left at the interop value 1420 and recorded as the
next item rather than silently changed.

### Fixed: the mux teardown race (closed, not deferred)

The one-off `mux stream closed before the server status byte` was investigated by
exhaustion of the teardown paths and turned out to be a **legitimate** session
teardown, not a premature close. The actual defect was the diagnostic: six
distinct events shared one byte-identical message, one of them described falsely,
and it was `InvalidData` rather than `UnexpectedEof`. Reading those paths also
found a real hang (`open_stream` racing `close()`), now fixed. Five deterministic
reproductions fail on the old code (27 passed / 5 failed) and pass on the new
(32 / 0). See `docs/mux-teardown-race.md`.

### Fixed: test-suite port collisions — including one I caused myself

Two `AddrInUse` failures traced to the port allocator probing with `bind()` while
every flux listener holds ports with `SO_REUSEPORT`, so a leftover listener was
invisible to the probe. The probe now also *connects*: a free port refuses.

The honest part: the first version of that fix put a test in `tests/common/mod.rs`
that **wrote to the shared port counter**, and because that module is compiled into
every integration binary, the test ran concurrently with real tests and handed out
duplicate ports — the exact failure it was meant to prevent. It now tests the pure
`port_is_free` helper and never touches the counter.

### State

**552 tests, 0 failed** (was 525). fmt/clippy/audit/deny/doc green.

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

### Closed: the rare mux teardown race

One full-suite run failed with, in `test_mux_vless_flux_to_singbox`:

```
read echo: InvalidData: "mux stream closed before the server status byte"
```

Reproduction attempts: **30 clean runs** (20 isolated, 10 with eight CPU-saturating
background loops and 8 test threads each) — not reproducible. The message is
raised when the client's handshake is still waiting for the server's status byte
and the underlying session reports EOF (`mux.rs:1209`/`:1217`), i.e. a teardown
race between the peer closing the session and the reply arriving, not a data
corruption. **Cycle 3 verdict (see `docs/mux-teardown-race.md`):**

- The observed failure was a **legitimate** session teardown (the transport went
  away: peer EOF or a socket read/write error), not a premature close by us. This
  was proved by exhaustion: `Shared::close()` is the only way a session ends, its
  call sites are a closed set, and none of the mux layer's own teardown paths can
  fire inside that test.
- The **actual defect was the error itself**: one byte-identical message for six
  distinct events, one of which it described *falsely* (it claimed the status byte
  never arrived when it had), reported as `InvalidData` ("corrupt") rather than
  `UnexpectedEof`. The next occurrence now prints, for example:
  `mux stream 3 closed before the server status byte (no status byte received;
  0 response byte(s) received; session closed: peer closed the connection
  (1 stream(s) open at teardown))`
- Reading the teardown paths also turned up a **genuine hang**: `open_stream()`
  could register a stream after `close()` had cleared the stream map, leaving its
  only sender alive in a map nobody drains, so the stream's first read waited
  forever instead of failing. Fixed with a re-check under the map lock.
- Five deterministic reproductions (duplex fake peers stopping at chosen points)
  fail on the previous code (27 passed / 5 failed) and pass now (32 / 0). 100
  additional stress runs under eight CPU burners produced no teardown.

The test-infra half of this class was fixed separately: the port allocator now
also *connects* to a candidate port, so a live listener (including one held with
`SO_REUSEPORT`, which every flux listener sets) is skipped instead of handed out.
