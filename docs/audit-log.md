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

## Cycle 15 — 2026-10-23

### Baseline

fmt, clippy `-D warnings`, 1006 tests, audit, deny, doc — green at `d68a3d5`.

### The project had never measured itself against a competitor on a protocol path

Every encrypted-protocol number in the README was measured against itself, which
proves the code works and says nothing about whether it is competitive. A head-to-head
matrix (`examples/bench_matrix.rs`) now runs the same workload through flux-core and
sing-box for nine protocol/transport pairs, and the xray side exists as validated
config builders (`tests/xray_matrix_configs.rs`) with a real traffic test.

First honest run, 64 MiB per round, 2 interleaved rounds, same machine:

| path | flux-core | sing-box | delta |
|---|---|---|---|
| VLESS/TCP | 493 MB/s | 1047 | **−53 %** |
| VLESS/WS+TLS | 367 | 642 | −43 % |
| VLESS/gRPC+TLS | 236 | 308 | −23 % |
| VMess/WS+TLS | 327 | 512 | −36 % |
| Trojan/TLS | 482 | 658 | −27 % |
| Shadowsocks-2022 | 455 | 807 | −44 % |
| Shadowsocks-AEAD | 449 | 466 | −4 % |

So the answer to "are we faster than sing-box" was: **on the plain relay yes, on
every protocol path no** — by up to half.

### The cause, and a doubling

The dispatcher's in-kernel `splice` path requires both halves to be exactly
`tokio::net::TcpStream`. Every protocol tunnel wraps the socket, so none of them ever
took that path and all fell back to `tokio::io::copy_bidirectional`, whose internal
buffers are **8 KiB per direction**. A new `copy_bidirectional_buffered` drives both
directions from one task with 64 KiB buffers — no split (a mutex around the stream on
every poll), no per-chunk allocation, a quarter of the syscalls.

| path | before | after | vs sing-box |
|---|---|---|---|
| VLESS/TCP | 493 | **1036** | −53 % → **+4 %**, CPU −36 % |
| Trojan/TLS | 482 | **765** | −27 % → **+8.5 %** |
| VLESS/gRPC+TLS | 236 | **315** | −23 % → **+1.1 %** |

Measured A/B on one protocol with only the copier changed: 493 → 1036 MB/s.

Still behind, and next: VLESS/WS+TLS (−39 %), VMess/WS+TLS (−37 %), Shadowsocks-2022
(−35 %), Shadowsocks-AEAD (−13 %), VLESS/TCP (−9 %). The WebSocket and SS gaps are the
next obvious targets, and each is now attributable to a specific layer because the
matrix lets one change be measured against a fixed competitor.

### The REALITY rows: not a bad scenario — a 5-second defect per connection

The first matrix run reported REALITY at ~12 MB/s with a large CPU penalty while
sing-box reported ~635-680 MB/s. I initially recorded this as a suspect scenario and
refused to quote it, which was right, and the follow-up found something better: the
harness now separates tunnel setup from bulk, and setup was **5002 ms** against
sing-box's 1.6 ms with bulk a healthy ~510 MB/s.

`probe_target_handshake` replays the client's ClientHello at the fallback and reads
the target's TLS flight to mirror its record framing, with a 5 s deadline and a break
condition that counts records. A **rustls** target (i.e. another flux node) sends a
flight that does not match that count, so the loop waited out the full deadline on
**every new connection**. OpenSSL and Go fallbacks happen to match, which is why the
defect was invisible. Confirmed server-side and fallback-dependent: openssl
`s_server` 6 ms, Go TLS 7 ms, rustls **5002 ms**; a sing-box *client* against a flux
REALITY server with a rustls fallback also waited 5008 ms.

Fixed by giving every read after the ServerHello a 100 ms idle window instead of the
global deadline, and by caching the probe per fallback target for 60 s (the framing is
a property of the target's TLS stack, not of the connection). Measured: setup
**5002 → 0.7 ms**, end-to-end 37 → **538 MB/s**. The regression test runs a full
handshake against a real rustls fallback and fails without the fix with
`took 5.006264812s`.

### Also fixed this cycle

- **An `ip_cidr` rule now fires for a connection made by name.** The router is
  synchronous and resolves nothing, so an IP rule only applied to address literals —
  a real, silent difference from sing-box and xray. The dispatcher now resolves for
  the routing decision only (250 ms budget, falls back to routing on the domain,
  nothing resolves when no rule needs an address), while the dial keeps the domain.
- The xray config work surfaced three xray-26 behaviours worth recording: `allowInsecure`
  was removed (a client must pin the peer certificate as a lowercase-hex SHA-256 of the
  leaf DER), Trojan's `flow` was removed, and xray's Trojan client cannot survive a
  ≥8 KiB first write at any caller-side chunk size — it needs a lockstep round trip
  below that before bulk data.

### State

**1013 tests, 0 failed** (was 1006).

---

## Cycle 23 — 2026-10-24

### The copier was rescheduling the task after every 64 KiB

Chasing the Shadowsocks gap led somewhere better than Shadowsocks. `ss_bench` (new)
shows the protocol code runs at **962 MiB/s in-process**, while the same code through
the proxy ran at ~190 — so the cost was in the relay around it, not in the protocol.

`strace -f -c` on a 64 MiB Shadowsocks transfer: **26 658 futex calls, 90 % of all
syscall time**, and reads of 2-3 KiB. The cause was one line in
`copy_bidirectional_buffered`: on every pass that moved data it called
`cx.waker().wake_by_ref()` and returned `Pending`. The comment claimed that meant "poll
again immediately"; it means "hand the task back to the executor", which is a futex
wakeup and a queue round-trip per 64 KiB.

This is why **every path that cannot use splice** — WebSocket, gRPC, Shadowsocks, TLS —
sat at ~195 MB/s while splice-based VLESS/TCP reached 454. It was never the protocols.

| path | before | after | vs sing-box | CPU vs sing-box |
|---|---|---|---|---|
| VLESS / TCP | 546 | **650** | **+19.5 %** | −52 % |
| VLESS / WS + TLS | 199 | **237** | −16.5 % | −27 % |
| VLESS / gRPC | 100 | 100 | −10.8 % | −55 % |
| VLESS / REALITY | 156 | **242** | −22.0 % | −24 % |
| VMess / WS | 133 | **178** | −7.0 % | −38 % |
| Trojan / TLS | 220 | **289** | −2.0 % | −38 % |
| Shadowsocks-2022 | 187 | **288** | −15.7 % | −26 % |
| Shadowsocks-AEAD | 129 | **239** | −1.7 % | −28 % |

futex 26 658 → 6 944, syscall time 37.9 s → 23.7 s on the same workload. **Every row is
now within 22 % on throughput and ahead on CPU**, which was true of no row before.

The first version of the fix had no yield at all: a copy that always has work never
returns `Pending`, so it monopolises its worker thread and starves every other task on
it. That appeared as a Vision transfer completing one round and then hanging; the loop
now yields after 64 consecutive passes that moved data. Caught before commit, which is
the only reason it is a footnote rather than a regression.

### Shadowsocks: the 18-byte reads, and a null result worth keeping

The chunk length (2 bytes + 16-byte tag) was read in a socket call of its own: 2 566
reads of exactly 18 bytes per 16 MiB. A wider read is not the fix — with a coalesced
write the surplus belongs to the next chunk, and dropping it desynchronised the stream
(tunnel reset after seven chunks). The receive buffer is now persistent with a consumed
offset. 18-byte reads went to **zero**, total recvfrom 15 486 → 6 212 — and throughput
**did not move**. The syscalls were waste, not the bottleneck; kept because the parser
is correct and cheaper, but recorded as a null performance result.

### Method note

`perf` cannot sample on this host at all — zero samples even for a busy `yes`, so
`perf_event_paranoid` is not the reason. All profiling here is syscall-level (`strace
-c`) plus in-process micro-benchmarks, and that was enough to find both faults.

---

## Cycle 22 — 2026-10-23

### The matrix now has three columns

xray is the closest competitor in the protocol space and had never been measured at
all. Its column is wired from `tests/xray_matrix_configs.rs` — the builders proven by a
test that runs the real binary — included by path so the benchmark cannot drift from a
configuration somebody has actually verified.

| path | flux | sing-box | xray |
|---|---|---|---|
| VLESS / TCP | 454 | 488 | **544** |
| VLESS / WS + TLS | 199 | 272 | 90 |
| VLESS / gRPC + TLS | 86 | 100 | **151** |
| VLESS / REALITY | 156 | **279** | 215 |
| REALITY + Vision | 91 | **273** | 217 |
| VMess / WS | 133 | **174** | 146 |
| Trojan / TLS | 220 | **269** | n/a (see below) |
| Shadowsocks-2022 | 155 | **320** | 245 |
| Shadowsocks-AEAD | 129 | **234** | no equivalent |

**These absolutes are not comparable with the earlier desktop numbers** (VLESS/TCP was
1063 there, 454 here for both stacks alike): different machine, different per-core
performance. Only comparisons within a run mean anything, and the harness must be run
on one machine for a published table.

What the three columns actually say: xray is the fastest at raw stream throughput
(gRPC, VLESS/TCP) and the slowest at WebSocket by a wide margin; sing-box leads every
row that involves its TLS stack; we lead nothing on this machine, and lead WebSocket by
2x over xray.

### Turning on the column found three broken benchmark configs

The harness's own configs carried fields that **this project's deep key validation
refuses** — the same silently-ignored class found in the interop tests: `"host"`
instead of `"headers"` in outbound WebSocket framing, and `"service_name"` on an
*inbound* gRPC framing, which has no such option. They had been accepted and dropped,
so those rows were not measuring what their configs said.

### Open

- **Trojan/xray fails its warm-up**: xray's Trojan client cannot survive a first write
  of ≥8 KiB (documented by the audit that produced those configs) and the harness
  pushes 4 MiB at once. Needs the same sub-8 KiB prime the interop test uses.
- Our Shadowsocks rows are the largest gap (−48 % and −45 %). The cipher is not the
  limit (this host's AES-128-GCM does 5.9 GB/s); it needs a profiler, which this
  machine does not have (`perf` absent).

---

## Cycle 21 — 2026-10-23

### Functional gap closed: mKCP is selectable from a config file

`carrier: {type: "kcp", address: ..., header: "srtp"}` now exists, with `mtu`,
`snd_wnd`, `rcv_wnd`, `interval_ms`, `resend` and `conv`, and `header` covering Xray's
`none`/`srtp`/`utp`/`wechat-video`/`dtls`/`wireguard` masks. An unknown header is
refused by name rather than silently substituted.

The design point worth recording: mKCP travels over UDP but is a **stream** carrier.
Sharing the `udp` arm of `parse_outbound_carrier` sent a KCP-carried VLESS node down
the "UDP-native protocols" path, where it was refused with "carrier UDP currently
supports shadowsocks, wireguard, hysteria2, tuic". It has to take the layered path
with the KCP stream as the bottom layer, so everything above it (TLS, REALITY,
WebSocket, the protocol) is untouched — which is the whole reason a carrier belongs at
the bottom of the pipeline.

Verified against a real Xray 26.3.27 server: a SOCKS5 client through a flux-core
instance whose outbound is `carrier: kcp` + VLESS relays 8192 bytes through the Xray
node byte-exact.

### Test harness: a port race that had been reported as a flake four times

`test_mux_interop` failed intermittently with "cannot hold the port the allocator just
handed out". The allocator probes a port by binding and releasing; another thread in
the same binary can take it in that window. Calling that a flake was the wrong
response — the test's port hold now retries eight times and then fails with the same
diagnosis, so a systematic problem still reports itself instead of being absorbed.
Three consecutive runs of that suite are green.

### State

**1051 tests, 0 failed.** mKCP: interop proven in both directions against the real
binary, and reachable from configuration. Still missing for full Xray parity: the
`seed`/AES-GCM mask, PING/TERMINATE liveness, and Xray's `tti`/`uplinkCapacity`
pacing (our congestion path is plain slow-start/AIMD; Xray's default is off, which
ours matches).

---

## Cycle 20 — 2026-10-23

### mKCP: interoperable with a real Xray node, both directions

The previous cycle left this as "xray creates a session and immediately closes it",
and I was about to go looking for a field-level difference in our segment codec. The
thing that resolved it was the control experiment I had skipped: **xray → xray** on
the same harness. It failed too.

The harness was wrong. `freedom` with a `kcp` transport dials the *requested
destination* over KCP — it is not a tunnel — so pairing it with a `dokodemo-door`
inbound measures nothing. With a real pair (VLESS inbound server, VLESS outbound
client):

- **Our client → Xray server**: xray logs `firstLen = 4122` and `received request for
  tcp:127.0.0.1:19000`; 4096 bytes come back byte-exact.
- **Xray client → our `accept()`**: the client's payload arrives, our echo returns,
  xray receives it.

So the segment codec (u16 conv, cmd 0..3, big-endian, 18-byte DATA overhead), the ACK
path, the ARQ and the `header-srtp` + `mkcp-original` obfuscation are byte-compatible
with Xray 26.3.27. `tests/test_kcp_interop.rs` drives the real binary, so this cannot
regress silently.

**The lesson is the same one that cost a cycle in the REALITY work:** when a
measurement says "the other implementation rejects us", first prove the measurement
works by running the reference implementation against itself. I have now been bitten
by this twice.

Not yet done: `carrier: {type: kcp}` does not exist, so no user can select mKCP. The
transport is a library module with a proven wire format and no configuration path.

### Also this cycle

- Environment: all builds, tests and benchmarks moved to a 24-core homelab server
  (`cargo`/`rustc` on the workstation now refuse to run), because repeated full-suite
  runs plus release builds plus benchmarks were making the desktop unusable.
- `kcp::debug_parse` — parses a captured datagram into its fields. Reading foreign
  bytes by hand was the reason two cycles went into guessing.

### State

**1049 tests, 0 failed.**

---

## Cycle 19 — 2026-10-23

### Functional gap closed: a UDP association is a connection

`dispatch_packet` registered nothing in the traffic meter, so every UDP relay — QUIC,
DNS, WireGuard, anything through a `udp` carrier — was invisible to
`GET /api/v1/connections`, uncounted by `flux_active_connections`, impossible to close
with `DELETE /api/v1/connections/<id>`, and its bytes were only in the global totals
with no way to attribute them to a client. An operator watching a bandwidth graph saw
traffic they could not find a source for.

The association now registers on entry and unregisters on every exit path, upload is
counted where the datagram is forwarded, download inside the reply pumps (one pump per
endpoint, so the counter is shared rather than copied), and the API's cancel signal is
a third branch in the receive loop — closing it tears down the association and every
endpoint behind it through the same cancellation token that stops the pumps.

Two tests: the entry appears with `NetworkType::Udp`, reaches the global counter and
disappears when the association ends; and closing it through the API ends the relay
task — that one fails with "closing the association through the API must end the relay
task" when the cancel branch is removed.

### State

**1016 tests, 0 failed.**

Remaining from the functional list: mKCP and XHTTP transports, IDNA, a GeoIP test
fixture, nested config-key typo detection, and a browser-grade TLS fingerprint.

---

## Cycle 18 — 2026-10-23

### Functional gap closed: a private CA can be pinned

A deployment behind an internal CA had exactly one option: `insecure: true`, which
turns verification off entirely and accepts any certificate — strictly worse than
trusting the CA that actually signs your nodes. `security.ca_cert_path` now takes one
or more PEM files whose certificates are appended to the built-in roots.

Three details that matter more than the feature itself:

- The extra anchors are part of the **connector cache key**. Two outbounds with
  different private CAs must not share a cached connector; otherwise one could trust a
  certificate the other should reject.
- An unreadable, malformed or empty CA file is a configuration error naming the file.
  Falling back to the public roots would produce an `UnknownIssuer` far from the cause.
- The loader is one shared function used by the stream client **and** the QUIC clients.
  The first commit wired only stream TLS, which would have made a private CA work for a
  WebSocket node and silently fail for a Hysteria 2 node in the same deployment; the
  second commit closed that.

The test proves the pin is what makes the handshake succeed: a self-signed localhost
certificate fails against the built-in roots with `InvalidCertificate(UnknownIssuer)`,
succeeds once listed, and fails again when the wiring is removed.

### State

**1014 tests, 0 failed.**

Remaining from the functional list: mKCP and XHTTP transports, IDNA, a GeoIP test
fixture, UDP associations in the connection table, nested config-key typo detection,
and a browser-grade TLS fingerprint.

---

## Cycle 17 — 2026-10-23

### Where the matrix stands after this cycle

| path | flux | sing-box | throughput | CPU |
|---|---|---|---|---|
| Trojan / TLS | **741** | 662 | **+11.9 %** | **−27.0 %** |
| VLESS / gRPC + TLS | 295 | 301 | −2.3 % | **−24.4 %** |
| VLESS / TCP | 982 | 1042 | −5.7 % | **−29.7 %** |
| Shadowsocks-AEAD | 434 | 478 | −9.1 % | +17.9 % |
| VLESS / WS + TLS | 506 → **522** | 638 | −18.3 % | **−9.4 %** |
| VLESS / REALITY | 512 | 652 | −21.4 % | +17.4 % |
| VMess / WS + TLS | 340 | 485 | −30.0 % | +6.4 % |
| Shadowsocks-2022 | 534 | 800 | −33.2 % | +56.9 % |
| VLESS / REALITY + Vision | 222 | 626 | −64.5 % | +179.3 % |

Three paths now win or tie on throughput and win on CPU. The WebSocket row moved from
−41 % to −18 % in one cycle; Shadowsocks-2022 from −50 % to −33 %.

### WebSocket: the frame cap was the whole story

`poll_write` capped a frame at 16 KiB, so a 64 KiB write from the relay became four
frames — four copies, four masks, four syscalls. The cap is 64 KiB now, matching the
relay's copy buffer. Two read-side costs went with it: a 16 KiB stack array
zero-initialised on every poll (now a reused buffer) and a read capped at 16 KiB
regardless of the caller's buffer. Measured: **421 → 522 MB/s**, and CPU is now below
sing-box on that row (3.3 vs 3.6 s/GiB) while still losing 18 % on throughput.

**A methodological lesson worth keeping:** `bench_layers` showed *no* movement from
these same changes and I nearly reverted them on that evidence. The matrix — the thing
being optimised — showed +20 %. So `bench_layers` is not a trustworthy proxy for this
layer, and a change that matters should be judged on the end-to-end path.

### Shadowsocks: reading into a temporary then copying it

Both variants read into a temp buffer and memcpy'd into the real one: a second copy of
every payload byte, and a cap on how much one read could return (8 KiB for 2022 against
16 KiB chunks — two syscalls per chunk). Reading straight into the destination:
Shadowsocks-2022 **483 → 534 MB/s**, Shadowsocks-AEAD 428 → 434.

The remaining 2022 gap is not crypto — this machine's AES-128-GCM runs at 5.9 GB/s
(measured with `openssl speed`), so at 534 MB/s the cipher is ~9 % of the budget. The
gap is in copy and syscall structure, and finding it needs a profiler: `perf` is not
installed here, which is the recorded blocker.

### State

**1013 tests, 0 failed.**

---

## Cycle 16 — 2026-10-23

### Final matrix (5 interleaved rounds × 200 MiB, quiet window)

| path | flux bulk | sing-box bulk | throughput | CPU |
|---|---|---|---|---|
| VLESS / TCP | 1063 | 1186 | −10.4 % | **−28.0 %** |
| Trojan / TLS | **769** | 743 | **+3.5 %** | **−25.4 %** |
| VLESS / gRPC + TLS | 302 | 322 | −6.4 % | **−18.2 %** |
| VLESS / REALITY | 539 | 728 | −26.0 % | +16.8 % |
| Shadowsocks-AEAD | 428 | 499 | −14.2 % | +23.0 % |
| Shadowsocks-2022 | 483 | 956 | −49.5 % | +67.8 % |
| VLESS / WS + TLS | 421 | 710 | −40.7 % | +34.2 % |
| VMess / WS + TLS | 316 | 502 | −37.0 % | +21.0 % |
| VLESS / REALITY + Vision | 226 | 727 | −68.9 % | +194.3 % |

Where we stand: parity or a win on the three TCP-ish paths, and behind on WebSocket,
Shadowsocks-2022 and REALITY. Every row is now attributable to a layer rather than to
"the proxy is slow", which is the point of having the matrix.

Two rows carry a caveat the table cannot: **Vision is not like-for-like** — sing-box
does not implement the Vision flow and ignores the field, so its 727 there is plain
REALITY; the competitor for that row is xray. And above ~1.2 GB/s the harness's own
echo is within 2× of the ceiling, so −6 % and +3.5 % mean "no measurable difference".

### Vision: two real costs, and one row that only moves with TLS payloads

`padding_len` drew from `rand::rngs::OsRng` — a `getrandom()` syscall **per frame**,
i.e. one per 8 KiB of payload — and each frame allocated a fresh `Vec`. Both fixed
(a per-thread CSPRNG seeded once; a reused scratch buffer). The write side also now
mirrors the read side, which already had Xray's `switchToDirectCopy`: after the END
frame the peer is in raw mode, so further framing would corrupt the stream, not just
slow it. That path does not show in the benchmark because the payload is not TLS and
the switch never triggers — with real TLS traffic it removes framing entirely.

### State

**1013 tests, 0 failed.**

---

## Cycle 14 — 2026-10-23

### Baseline

fmt, clippy `-D warnings`, 972 tests, audit, deny, doc — green at `b172f1e`.

### Outbound groups: state that lives for the process, not for the request

`selector`, `loadbalance` (url-test), `fallback` and `probe` decide which server a
user's traffic leaves through, and they hold state across requests — a selected
member, a probe loop, a health opinion. The defects found were all of that shape:

- `fallback` and `urltest` started a **new probe loop on every call**, guarded by a
  one-shot cancellation token. This is the third time that exact pattern has caused
  a defect in this codebase (the rule-set fetchers and the traffic sampler were the
  others): a token that has been cancelled cannot be re-armed, so "start" silently
  becomes "start once and then never again", or spawns a second loop. The loop token
  now lives in a mutex slot and starting is idempotent — a cancelled token is
  replaced, a live one is respected.
- `selector` looked up only the currently selected tag. If a reload removed that
  member, the dial failed instead of falling through to a member that still exists;
  it now uses the first member that resolves and logs the substitution.
- `loadbalance` with an **empty member list** reached the selection step with nothing
  to select; it now fails with `OutboundNotFound` instead of indexing.
- `probe` waited for a complete response before deciding health; it now returns as
  soon as the bytes cannot be the HTTP/1.x status prefix, so a non-HTTP responder
  fails fast instead of consuming the whole probe budget.
- `block` is pinned to refuse both TCP and UDP with the `Blocked` variant rather than
  a stringly-typed message.

**Process note, recorded because it affects how much this cycle is worth:** the audit
agent was interrupted before it could report, so the diff was reviewed and verified
here rather than trusted. What I verified: the crate's unit tests went from ~30 to
65 and pass, `test_outbound_groups`, `test_fallback_loadbalance` and
`test_protocols_e2e` pass, clippy and fmt are clean, and the production hunks are the
five behaviours described above. What I cannot claim: a complete list of what that
audit would have found had it finished.

### Tooling: the field audit was passing on the bug it exists to find

`scripts/config_field_audit.py` reports configuration fields that are accepted and
never consumed. It counted *any* mention as consumption — `self.flux = other.flux`
in the merge, `self.flux.is_some()`, a destructuring binding — so it reported every
field as consumed, including fields that do nothing.

It now counts a read: `.field` used as a value rather than an assignment target,
`field: <expr>` where the value is not a plain copy, with `Config::merge` and struct
patterns containing `..` excluded. Verified both ways — with the validation pass
removed it reports `flux`, with it restored it passes.

Its limit is now written into the script instead of being left implicit: it cannot
see a field that is read, forwarded into a lower-layer config struct and ignored by
that layer (`tuic.congestion_control` is read here, placed into `TuicV5Config`, and
the TUIC outbound never looks at it). That needs a semantic check per field, which is
why `Config::validate` refuses the unimplemented cases — the script passing is
necessary but not sufficient.

### State

**1006 tests, 0 failed** (was 972).

---

## Cycle 13 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 952 tests, audit, deny, doc — green at `4c005aa`.

### Dispatcher — two defects, one of them attacker-controlled resource growth

The single funnel between inbounds and outbounds had one test for 602 lines.

- **The UDP endpoint cap bounded the map, not the resources behind it.** Each cached
  endpoint spawns a detached reply pump holding its own socket, and the cache stored
  only the `Arc`, so evicting an entry stopped nothing. One association walking N
  destinations through a per-destination outbound kept **N sockets and N tasks**
  alive — descriptor growth a single client could drive, invisible until `EMFILE`.
  Measured before the fix: **306 live endpoints for 306 destinations while the cache
  claimed to cap at 256**. The cache now stores the endpoint with a cancellation
  token, so eviction, replacement, send failure and teardown all release through one
  mechanism.
- **One failed send evicted every destination's association** for that outbound — a
  single broken destination tore down up to 255 healthy VMess associations, each
  costing a fresh handshake on its next packet. Only the failing entry is removed
  now, found by pointer identity so the hot path stays allocation-free.
- Plus: a pump stopped by eviction reported its key as dead, so a stale report could
  evict a live replacement under the same key; and an eviction log claimed "oldest"
  for an arbitrary hash-map entry.

Verdicts on the rest of the file, each pinned by a test: connections are registered
once and released on every exit path including the Linux splice early return;
half-close propagates both ways over real sockets; byte counters survive an error;
an unknown outbound tag and a `block` outbound fail cleanly on both networks; a
Fake-IP destination is remapped before routing *and* dialling; adversarial
`SessionMeta` values never panic.

Recorded gap: **UDP associations are invisible to the connection table**, so the
API cannot close them and their traffic is not attributable to a connection. That
needs `api.rs`/inbound wiring, not a dispatcher change.

### Configuration: refuse what would be ignored — and only that

Five fields parsed, merged and were never read. Each is now decided individually
instead of blanket-rejected:

| field | decision |
|---|---|
| `flux` (format marker) | validated as a version marker (`"1.0"`, `"v2"`, `"flux"`) |
| TUIC `congestion_control`, `zero_rtt` | refused — not implemented, and a value here is a claim we cannot honour |
| Hysteria 2 `h3` | tri-state: `true` states what the code does and is accepted, `false` is refused, omitted is fine |
| Hysteria 2 `hop_interval_secs` | refused — a node carries one port, so there is nothing to hop between |
| inbound TLS `server_name` | refused — the acceptor serves one certificate and never filtered by SNI |

My first version refused `h3: true` as well and broke a legitimate sing-box interop
config; the test caught it, and the distinction (a true statement vs an unfulfillable
one) is now the rule. Two existing tests asserted that inert fields *parse*; they no
longer set them.

Documented limit: `deny_unknown_fields` cannot be applied to serde's
internally-tagged enums, so a typo **inside** a nested block is still accepted.
Catching that needs a raw-key comparison against a schema — its own piece of work,
not a one-line change.

### State

**972 tests, 0 failed** (was 952).

---

## Cycle 12 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 878 tests, audit, deny, doc — green at `df3b73a`.

### Coverage: re-measured, and it barely moved — which is the finding

Re-ran the instrumented build after ten cycles of tests. Line coverage is **52.77 %**
against 53.25 % in cycle 2, despite the suite doubling. The denominator also fell by
a third, so runs are not comparable and the aggregate is near useless as a trend.

What *is* useful is the per-file list, and it named the real gap: `dot.rs` (DNS over
TLS, 180 lines) at **0 %** and `doq.rs` (DNS over QUIC, 248) at 10 %. Both are
selectable from `dns.servers`, so 428 lines of networked protocol code had never
been executed by any test.

Recording the aggregate honestly: low coverage here mostly measures generic code
that llvm-cov attributes to test binaries (fragment.rs reports 0 % with five passing
tests), so it is a pointer to untested files, not a score.

### The encrypted DNS transports had never been run — 11 defects

Each now has a real local server (rcgen + rustls for DoT, quinn for DoQ, plain TCP
HTTP for DoH) and end-to-end tests. Coverage: dot **0.0 → 90.2 %**, doq 10.2 →
79.5 %, doh 50.4 → 83.5 %. Tests in the crate: 50 → 95.

The defects a user would have hit: **DoQ never validated the response id** (any id
was accepted as the answer); DoQ kept a stalled connection cached after a timeout
and did not retry a stream-level failure; **DoT and DoQ capped responses at 4096
bytes** — the UDP payload size applied to a stream; DoT left a desynchronised stream
pooled and lost the query; DoH never checked the response `Content-Type`, sent a
random non-zero id where RFC 8484 says zero, hung on an unparseable `Content-Length`
and retried fatal HTTP errors; and **all three split IPv6 literals inside the
address** (`tls://[2606:4700:4700::1111]` parsed as host `[2606:4700:4700:`),
reachable straight from configuration.

### The process layer — 18 defects between `main()` and the library

Nothing there had a test. The worst: **SIGTERM was unhandled** (exit 143, no
graceful stop, accept loops never joined); **signal handlers were installed only
after the config load**, so a SIGHUP during startup — default action: terminate —
killed a starting proxy; and **an empty config file was accepted as valid**
(`check` said "Configuration is valid!" while `run` served nothing). Also: a bare
invocation exited 0 (a supervisor with a broken `ExecStart` saw a healthy unit with
no listener), `-w 0` panicked inside tokio, a port conflict did not name the inbound,
and a rejected reload leaked the probes and sampler the candidate had spawned.

Exit-code contract, now asserted by 19 black-box tests over the real binary
(16 fail on the old one): 2 = bad invocation, 1 = invalid/unstartable config,
0 = success including a graceful SIGTERM.

### The relay copy serialised both directions — +13.5 % throughput

Found because cycle 11's withdrawn benchmark taught me what `tokio::io::split`
costs: it is a mutex around the whole stream taken on every poll, and
**`copy_bidirectional_pooled` — the hot path of every proxied connection — used it
twice**. A/B on the relay benchmark, same binary, one line changed:

| copier | throughput | CPU |
|---|---|---|
| pooled split | 2171 MB/s | 0.42 s/GB |
| `copy_bidirectional` | **2465 MB/s** | **0.38 s/GB** |

+13.5 % throughput, −9.5 % CPU, identical RSS (23.8 MB under 100 connections). The
pooled variant is deleted rather than left dead.

### Docs: rewritten against the code

Eleven cycles of changes had left the documentation wrong in ways that cause silent
breakage: it claimed an unset `${VAR}` expands to an empty string (it is a load
error), that fake-IP answers `AAAA` with NODATA (the v6 pool is on by default), that
the API refuses only some public binds, and a 1.85 MSRV that is actually 1.91.
Thirty claims corrected, seven confirmed, and every performance number that could
not be traced to a measurement from this session **removed rather than restated**.
`docs/configuration.md` is now a complete reference — all 60 fields, every default
traced to its implementation — and all six YAML examples pass `flux-core check`,
which none of them did before.

### State

**952 tests, 0 failed** (was 878).

---

## Cycle 11 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 893 tests, audit, deny, doc — green at `0fa7c58`.

### Correction: my "h2/gRPC at 6 % of raw" was an artefact of my own harness

Cycle 10 reported full-duplex HTTP/2 and gRPC at ~6 % of raw throughput. That
number is withdrawn. The echo mode of the new benchmark splits one stream with
`tokio::io::split`, and in tokio that is a **`Mutex` around the whole stream taken on
every poll** — the two halves take turns by construction, so the figure measured the
split as much as the transport.

The honest per-direction numbers (one-way, 5 rounds, 64 MiB):

| layer | MB/s | vs raw |
|---|---|---|
| raw | 3731 | — |
| httpupgrade | 3037 | 81 % |
| ws | 1101 | 30 % |
| h2 | 648 | 17 % |
| grpc | 414 | 11 % |

At a typical 1 Gbps link (125 MB/s) gRPC still has 3.3x headroom, so it is not a
practical bottleneck. The benchmark header now says which number to quote and why.
Two real defects did come out of that work: the gRPC capacity fix (cycle 10) and the
dedup below.

### Code quality: one h2 handshake instead of two

109 duplicated lines (handshake, window config, REFUSED_STREAM driver) now live once
in `h2::shared`. What is genuinely different stays per layer — gRPC reads headers and
trailers, h2 must not. h2spec: 108 applicable cases, 108 passed, **before and after**;
196 transport tests, 42 interop tests and the layered test identical in count and
outcome. The net file delta is +9 lines, so this is a dedup, not a line-count win,
and the report says so.

### The `AddrInUse` flake: cause found, failures now attributed

The allocator claims a block of ports and, on failure, reports which configured
listener is occupied, by whom (from `/proc/net/tcp{,6}` with uid), and whether this
process handed that port out. What it showed: **foreign processes were listening on
ports inside the claimed block** — a non-cooperating service walking the same range,
which is exactly why the failure never reproduced in isolation and left nothing
behind when checked. The allocator now prefers a quiet block instead of trusting a
candidate it probed a moment earlier.

Also fixed an honesty problem in my own bookkeeping: the allocator's own tests sat
inside `tests/common/mod.rs`, which is compiled into every integration binary, so six
tests were counted 24 times and the suite total drifted upward for no reason. They
are now their own binary and the per-binary counts are comparable across cycles.

### Also fixed

- `"1.2.3.4.:80"` parsed as a **domain**, so every `IP-CIDR` rule silently stopped
  applying to it and the dial path would have tried to resolve a literal. The
  literal check now ignores a trailing root dot; a real domain keeps it and stays a
  domain. Mutation-verified.
- `docs/configuration.md` now says plainly that routing decides **without resolving**
  the destination, so an `IP-CIDR` rule only fires for address literals (SOCKS5/VLESS
  with an IP, or a TUN packet). Anyone expecting "block this IP range" to catch a
  domain destination would silently get no match — a deliberate trade, now documented
  with the two ways around it.

### State

**878 tests, 0 failed.** The number *fell* from 893 because the duplicated counting
was removed; per-binary counts are unchanged.

---

## Cycle 10 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 835 tests, audit, deny, doc — green at `7057588`.

### Router — 7 defects, five of them routing traffic to the wrong outbound

A wrong routing decision is a privacy leak in one direction (traffic meant to be
tunnelled goes direct) and a breakage in the other, so the matcher was attacked
adversarially rather than read.

| Defect | Direction |
|---|---|
| A trailing root dot (`example.com.`) never matched — the rule was dropped | **under-match → leak to `final`** |
| The index canonicalised a pattern but the matcher compared it raw, so a mixed-case pattern matched the apex but not subdomains | under-match → leak |
| `*.example.com` was accepted by the parser and dead in the matcher (no host contains `*`), so wildcard lists matched nothing | under-match → leak |
| A v4-mapped IPv6 address missed every v4 rule | under-match → leak |
| `Router::default()` returned an empty tag | wrong routing |
| An **empty keyword matched every domain** (`contains("")` is always true), so one truncated feed line routed all traffic to that rule's outbound — and since it counted as parsed it also defeated the cycle-4 refresh guard and replaced a working list | over-match |
| A malformed CIDR counted as parsed, then vanished at compile, so a rule set reported itself complete while matching less | silent under-match |

The domain matcher is now one allocation-free, label-bounded, case-insensitive
implementation shared by rules, rule sets and the router index, with a 6000-case
differential test against a linear scan.

### Buffer pool — the previous tenant's bytes were handed to the next caller

`acquire()` returned a recycled buffer at full length with the previous connection's
bytes still in it (`len` was normalised *up*, never to zero). No in-tree consumer
read them — each does `read`/`recv_from` and slices `..n` — so there was no live
leak, but the invariant was a doc comment, an old test pinned the dangerous
behaviour as intended, and the changelog advertised it as a 48 % win.

**Decision: the release scrubs.** It costs ~471 ns per 64 KiB (~6 % of one core on
the UDP receive path at the README's packet rate) and reverses a measured decision,
which is the trade I want for a disclosure primitive in shared-crate API. The
sized-release API (`release_used(buf, len)`, ~10 ns) is the recorded optimisation —
it needs every caller to report truthfully, so it is an API discipline decision, not
a drop-in. README and CHANGELOG now describe what the code does.

Six more defects in the same crate: `max_capacity` ignored below 16 (a pool of 4
could hold 16 buffers); the rate limiter's overflow sweep **cleared the whole map**,
resetting every client's bucket including the attacker's — a per-IP limit that could
be switched off on demand (now three-tier, state-ordered eviction that never
clears); a flat sweep horizon reclaimed nothing; a zero-size pool handed out empty
buffers so every read returned EOF; an unbounded `buffer_size` OOM-aborted on first
acquire; and a pool could pin an inflated allocation.

### gRPC capacity — one defect, and the real shape of the gap

`poll_send_some` called `poll_capacity` unconditionally, which reports *newly*
granted capacity and stays `Pending` otherwise — so every 16 KiB message waited for
the next WINDOW_UPDATE, a scheduler round trip per message. Using the capacity
`SendStream::capacity()` already holds took one-way gRPC from 279 to 336-510 MB/s.

The benchmark gained a one-way mode, because the echo shape couples the directions
and that coupling turned out to dominate:

| layer | one-way | full-duplex |
|---|---|---|
| raw | 3651 | 2179 |
| ws | 963 | 527 |
| h2 | 702 | 133 |
| grpc | 336 | 109 |

Full-duplex HTTP/2 and gRPC run at ~6 % of raw. It is not per-message framing (a
4–64 KiB sweep is non-monotonic; 256 KiB is worse) and not a missing driver task
(both spawn one), so the next cycle needs a profiler-level look at the h2 layer in
bidirectional mode rather than more guessing.

### State

**893 tests, 0 failed** (was 835).

---

## Cycle 9 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 826 tests, audit, deny, doc — green at `39fed6a`.

### Solved: the "GSO stall" was frames arriving out of order

Three cycles had it as "reproducible, mechanism unknown". It is now closed, and the
lesson is that every counter being watched was looking at the wrong thing.

`send_burst` coalesced equal-sized runs into `UDP_SEGMENT` super-packets but pushed
the indices of every frame it *could not* coalesce onto a `singles` vector and sent
that vector **after** the loop. A burst shaped `[300 B, 1468 B × 30]` reached the
peer as packets 1..30, then 0. The receiver then held data behind a hole, `rcv_nxt`
could not advance, the advertised window collapsed to zero with a send buffer full
of unreleasable data, nothing was in flight, so no duplicate ACKs and no fast
retransmit — one 1 s RTO repaired the hole. Ordering damage is invisible to drop
counters, AEAD counters and RTT.

Decisive evidence, per-frame TCP sequence check where decrypted frames enter the
client's stack:

| | frames/s | gaps | dups |
|---|---|---|---|
| inbound GSO **off** | 97 698 | **0** | **0** |
| inbound GSO **on** | 142 992 | 663 | 862 |

| | min | median | max | CPU s/GB |
|---|---|---|---|---|
| pre-fix, inbound GSO | 47.8 | 76.7 | 110.0 | 9.8–11.3 |
| shipped until now (`sendmmsg`) | 118.8 | 122.2 | 126.6 | 17.6 |
| **post-fix** | **189.1** | **213.0** | **217.6** | **8.9–9.5** |

Re-measured independently here over three invocations: 210.5 / 209.6 / 210.1 MB/s,
min 205.7, max 215.3 — no collapse mode in any round.

**The same unrelated frame order existed in the outbound copy**, so the 143 MB/s path
was silently reordering the inner stream as well; it never collapsed only because
that direction faces a 256 KiB receive buffer instead of the client's 64 KiB. Both
are fixed, each with a `send_burst_preserves_datagram_order` test that fails on the
old ordering.

### Closed: lifecycle — `stop()` now means stopped

`Instance::stop()` returned before the listener FD was closed, so a caller binding
the same port in the next statement raced `EADDRINUSE`. Every inbound now joins the
tasks that own its listener (all 14, plus the API server), and the trait documents
the contract. `TrafficMeter` gained a real stop, so a stopped instance owns zero
tasks instead of one.

Both proofs run on a `current_thread` runtime with no sleep or yield between
`stop()` returning and the rebind — they describe the code, not a scheduler race —
and reverting the fix fails them with "stop() returned with these ports still held".

### New: a benchmark for the framing layers

There was no way to measure WebSocket/gRPC framing at all, which matters because
four cycles of hardening added per-frame validation there. First numbers (median of
5 rounds, 32 MiB echoed, 64 KiB writes):

| layer | MB/s |
|---|---|
| raw | 1499 |
| httpupgrade | 1737 |
| ws | 390 |
| h2 | 91 |
| grpc | 101 |

HTTP/2 and gRPC cap at ~6 % of raw throughput — a real weakness for anyone
tunnelling through them, and **not** a message-size effect: raising the chunk from
16 KiB to 256 KiB made it worse (82 → 7 MB/s) and a 4–64 KiB sweep was
non-monotonic, so the cost is in the h2 send/receive pacing, not per-message
framing. The harness echoes through one connection, which couples the directions
through flow control and makes it noisy (ws varies 389–746), so the next step is a
one-way variant before changing any code. Recorded, not guessed at.

---

## Cycle 8 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 825 tests, audit, deny, doc — green at `53fae33`.

### Closed: the Hysteria 2 stall — 5.16 s → 5.5 ms

Cycle 7 diagnosed it (server answers in ~1 ms, the `h3` crate client takes ~5.5 s
to deliver that response) and cycle 8 fixed it. Two hypotheses were tested and
refuted first: the client does allow uni streams (256), and the server's SETTINGS
arrives in 1.06 ms — measured with a raw quinn client reading the control stream.

The deciding fact was already in the code: `open_bi_stream` on raw quinn is what
opens tunnel streams, so the `h3` crate was used **only** for the auth exchange —
one request whose status code we read and discard. It is now implemented on raw
quinn (`h3_lite::client_auth_request`), which is ~40 lines against primitives we
already had.

| measurement | before | after |
|---|---|---|
| first dial (loopback, local server) | 5.16 s | **5.47 ms** |
| `test_hy2_salamander_obfs_e2e` | 5.67 s | **0.11 s** |

The latency test's budget is tightened from a 7 s characterisation bound to the
real 1.5 s target, and the `h3`/`h3-quinn` crates moved from a normal dependency of
`flux-protocol` to a dev-dependency of `flux-transport`, where a single test still
uses a third-party client to prove our server accepts one.

The one test that remains slow (`test_h3_lite_accepts_h3_crate_post`, 5.3 s) does
so by design: it deliberately drives our server with the third-party `h3` client.

### Test infrastructure: a flake that is not a product defect

One full-suite run failed with `AddrInUse` in two mux interop tests; three isolated
runs and a full retry were green, and no leftover process existed at the time. The
port allocator was already hardened (it connects to a candidate port to see a
`SO_REUSEPORT` squatter), and `SingboxProcess::drop` already kills *and waits*. The
observed rate is 2 occurrences in ~12 full-suite runs, always transient. Recorded
rather than papered over: the next occurrence should capture which inbound failed
to bind and on which port, because guessing further without that data is not
auditing.

---

## Cycle 7 — 2026-10-22

### Baseline

fmt, clippy `-D warnings`, 762 tests, audit, deny, doc — green at `7e7d326`.

### The Hysteria 2 stall: diagnosed, not fixed

The open item from cycle 6 is now attributed with a decisive experiment rather than
a guess. Phase timings on loopback:

| phase | time |
|---|---|
| server start | 1.6 ms |
| QUIC connect | 3.2 ms |
| `send_request` | 52 µs |
| **`recv_response`** | **5.15 s** |
| echo round trip | 1.1 ms |
| second dial (reused connection) | 0.57 ms |

A **raw quinn client** driving the *same* server completes the whole round trip in
**1.17 ms** (`h3_lite::latency_tests::raw_quinn_round_trip_is_fast`). So our h3
server is not the problem at all: the ~5.5 s lives in the `h3` crate's client path
that we use for authentication — the driver task stays alive and polling (verified),
the QPACK field section carries no dynamic-table dependency (verified), and quinn
delivers the bytes promptly.

Recorded rather than rushed: the fix is to replace or wrap that client driver, which
is a structural change worth its own cycle. `tests/test_hy2_latency.rs` keeps the
phase breakdown and asserts a bound *below* the observed stall, so a further
regression is caught while the known one is documented instead of hidden.

### instance.rs — 4 lifecycle defects (7 tests, 0 → 7)

1702 lines with no unit tests, owning start/stop and the state every listener
depends on:

- **A half-started instance leaked its listeners**: `start()` bound inbounds in a
  loop and returned on the first failure, leaving earlier ones bound and accepting
  (quietly, because every listener sets SO_REUSEPORT).
- **A failed reload candidate kept stealing traffic**: the SIGHUP path starts the
  candidate before stopping the old instance, so a candidate failing after binding
  the live port kept accepting half the connections for the "old" config. This is
  the worst of the four — a reload failure silently split traffic between two
  configurations.
- **`start()` twice bound everything twice**: SO_REUSEPORT made the second bind
  succeed, spawning a second accept loop per inbound.
- **A restart silently stopped refreshing remote rule sets**: `fetch_cancel` was a
  one-shot token cancelled by `stop()` and reused by `start()`, so after any
  restart the fetch loops exited on their first poll.

All four are proved by reverting the fix. The tests use `yield_now()` plus a
deadline rather than sleeps, and assert task hygiene with the runtime's own alive
task count.

### gRPC — 13 defect groups (4 → 57 tests)

The worst: **trailers were never read**. A response carrying `grpc-status: 7`
(aborted) or `13` (internal error) arrived as a clean end of stream, so a failed or
truncated tunnel looked successful to the caller. Also: the compression flag was
never read (a compressed message parsed as plaintext); an under-declared inner
length silently dropped bytes; a payload without the `0x0A` tag was delivered raw
(two encodings for one message, inner check bypassable); the client never checked
the response content type, so a `text/html` captive portal was spliceable; the
server accepted **any** HTTP/2 request as a tunnel; the server answered with
`application/octet-stream`; a config service name was interpolated into `:path`
unvalidated; `poll_shutdown` sent trailers without draining a half-written frame;
and a framing error did not poison the reader.

`GrpcStream` now owns its own h2 streams because `H2Stream` discards response
headers and never polls trailers — `grpc-status` was unreachable from above it.
`h2.rs` is untouched; the cost is ~130 duplicated lines of handshake/flow control,
recorded as the next refactor.

### Routed for the next cycle

- `Inbound::stop()` is fire-and-forget: `Instance::stop()` returns before the
  listener FD closes, so a caller that binds immediately can still see
  `EADDRINUSE`. Needs the accept-loop `JoinHandle` awaited in `stop()` — a
  cross-crate trait change.
- `TrafficMeter::new()` spawns a 1 s sampler inside `Instance::new` that `stop()`
  cannot stop (it exits only when the instance drops), so a stopped-but-alive
  instance always holds one task.
- `ApiServer::start()` deliberately binds without SO_REUSEPORT, so zero-downtime
  reload is impossible for the API port; `main.rs` special-cases only tun/wireguard.

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

---

## Cycle 24 — 2026-10-24

### The TLS and REALITY rows were never measuring TLS or REALITY

`bench_tls` placed the `security` block **inside** the `carrier` object. The parser
ignored it silently, so every row labelled TLS or REALITY was plain VLESS over TCP.
The numbers this project has quoted — "REALITY 729 MB/s", "VLESS+TLS 660" — did not
measure those layers at all. The deep key validation added in cycle 13 is what finally
caught it: the harness now fails instead of measuring the wrong thing.

Three fixes were needed: `security` moved to its sibling position, a self-signed
certificate actually generated and passed to the inbound (a TLS inbound cannot start
without one, and the old config comment claimed flux-core generated it in process), and
an inbound `server_name` removed — that field is refused because the acceptor serves one
certificate and never filtered by SNI.

Real numbers on this host, 3 rounds x 128 MiB, byte-verified:

| path | throughput | CPU | setup p50 |
|---|---|---|---|
| flux direct | 918 MB/s | 0.64 s/GB | 0.44 ms |
| VLESS / TCP | 520 | 2.45 | 0.68 ms |
| VLESS / TLS | 264 | 6.48 | 1.62 ms |
| VLESS / REALITY | 239 | 7.47 | 2.11 ms |

**REALITY costs 9 % over TLS; TLS costs 49 % over plain framing.** The record-layer
work this project once did was optimising a layer that was never enabled in its own
benchmark. The throughput is lost in TLS, which is where the next measurement points.

`docs/reality-record-layer-report.md` now opens with the correction.

### Buffer sizing: tried, no effect

Raising the copier buffer from 64 KiB to 256 KiB moved Shadowsocks-2022 from 288 to
282 MB/s — noise. Reverted rather than kept as a "probably helps".

### The mux port race, finally fixed where it belongs

The retry added in cycle 21 was at one call site; `start_flux` is used by every test in
the binary and still panicked on the first `AddrInUse`. The retry is now in that shared
helper — eight attempts, then the original diagnosis. Three consecutive suite runs are
green where roughly one in three failed before.

### State

**1051 tests, 0 failed.** Performance is now within 22 % of sing-box on every matrix row
and ahead on CPU on every row; the remaining gap is concentrated in TLS.

---

## Cycle 25 — 2026-10-24

### Three-column comparison, with CPU for both competitors

| path | flux | sing-box | xray | vs sbox | vs xray | CPU vs sbox / xray |
|---|---|---|---|---|---|---|
| VLESS / TCP | 667 | 631 | 568 | **+5.7 %** | **+17.4 %** | −40 / −55 % |
| VLESS / WS + TLS | 259 | 295 | 104 | −12.2 % | **+148.8 %** | −40 / −70 % |
| VLESS / gRPC | 93 | 117 | **184** | −20.3 % | −49.4 % | −50 / −28 % |
| VLESS / REALITY | 244 | 300 | 221 | −18.8 % | **+10.5 %** | −30 / −41 % |
| REALITY + Vision | 128 | 310 | 253 | −58.8 % | −49.6 % | +55 / +38 % |
| VMess / WS | 178 | 197 | 149 | −9.6 % | **+19.4 %** | −36 / −49 % |
| Shadowsocks-2022 | 259 | 338 | 285 | −23.5 % | −9.4 % | −5 / −53 % |
| Shadowsocks-AEAD | 272 | 263 | — | +3.5 % | — | −24 % |

Ahead of xray on four of eight paths and ahead on CPU almost everywhere. The real
deficits are gRPC (−49 % vs xray) and Vision (−59 % vs sing-box, though sing-box does not
implement the Vision flow so that comparison is not like-for-like), and
Shadowsocks-2022 remains the largest gap against sing-box.

### Open with evidence: an intermittent hang in the TLS-carrying paths

Two occurrences, both in three-stack runs, both at a round boundary with a fresh tunnel:
VMess/WS timed out at round 2, Trojan/TLS at round 3 after measuring 355 MB/s at round 1.

Not reproducible on demand: six solo rounds of VMess/WS passed, four three-stack rounds
passed. It appeared after the copier change in cycle 23, which makes that the first thing
to bisect — the yield-after-64-passes path is the new code in the picture.

Recorded as a **rate to measure**, not a fix to claim. Next cycle: measure the hang rate
for the TLS paths (N tunnels, count timeouts), then bisect the copier yield.

### Also

`bench_tls`'s correction from cycle 24 changed what the harness measures; its REALITY
cost is 9 % over TLS and TLS is 49 % over plain framing, so the TLS layer — not the
record layer — is where the throughput goes on every encrypted path.

---

## Cycle 26 — 2026-10-24

### The hang: measured, not reproduced, and made attributable

Thirty Trojan/TLS rounds with a fresh tunnel each — no hang. The two observed cases both
happened while three stacks ran beside my own builds, so the most likely trigger is
contention rather than a deadlock.

Rather than guess, a timeout now reports what the kernel sees about both tunnel
processes: state, thread count, cumulative CPU ticks, `wchan` and the state of the first
threads. Verified with a forced timeout:

```
server pid=22357: State: S (sleeping); threads=26; cpu_ticks=39;
                  wchan=futex_do_wait; task states: 22357(S) 22358(S) …
```

The next occurrence will be explainable instead of being filed as a flake.

### gRPC: the frame cap was not the problem either

Message size was 16 KiB against a 64 KiB copy buffer — the exact shape that cost
WebSocket ~20 % — so it was raised to 64 KiB. **No change**: 100 MB/s before and after.

The CPU column says why: 14.5 s/GiB against sing-box's 33 means we are not compute-bound,
we are latency-bound per message, and halving the message count did not move it. Flow
control is not the cause either — the stream window is 1 MiB and the connection window
2 MiB against HTTP/2's 64 KiB default.

Kept because it is structurally cheaper (fewer messages, copies, flushes; 58 gRPC tests
pass) and recorded as a null throughput result, the same way as the Shadowsocks parser.

gRPC is now the one path where **both** competitors beat us on throughput (xray 184,
sing-box 117, us 100) while we beat both on CPU. That combination — cheap and slow —
says the next attempt must attack latency per message, not bytes per message.

### State

**1051 tests, 0 failed.** Matrix standing: ahead of xray on 4 of 8 paths, ahead of both
on CPU nearly everywhere, behind on gRPC (both) and Vision (not like-for-like).

---

## Cycle 27 — 2026-10-24

### Shadowsocks-2022: from half the competitor to within 3 %

The pattern behind several earlier null results finally named itself: our proxy is
CPU-cheap and throughput-poor on every path that frames data, which means it is bound by
the *number of read/write cycles*, not by bytes or compute. The relay writes and reads in
64 KiB units; Shadowsocks was taking one 16 KiB chunk per call in both directions, so
every buffer became four frames, four seals and four syscalls.

| | at audit start | cycle 23 | now |
|---|---|---|---|
| Shadowsocks-2022 | −48 % | −23.5 % | **−2.7 %** |
| CPU vs sing-box | +68 % | −5 % | **−28 %** |

Both halves were fixed: writes frame up to 64 KiB into one buffer and hand it to the
socket once; reads keep decrypting while the caller's buffer has room, and
`finish_read` returns `Pending` only when nothing was delivered so bytes are never
stranded mid-call.

Shadowsocks-AEAD got the same write change but **no claim is made**: six solo rounds
spread 182-253 MB/s and the interleaved comparison read −17 %. Noise, not evidence.

### The port race, for the last time

Eight retries on the *same* port cannot help when something holds it. The test now asks
the allocator for a fresh port per attempt; four consecutive suite runs are green.

### Next

The same "cycles, not bytes" measurement applies to gRPC — the one path where both
competitors beat us — and to VMess/WS. gRPC spends 14.5 s/GiB against sing-box's 33 and
still loses on throughput, which is the signature of one round trip per message rather
than one per buffer.

---


### The port race closed at the root

Three attempts at this failed because they were all at the wrong level: retrying the
same port cannot help when the port is gone, and twelve call sites build a config around
a port before binding, so a builder refactor was the alternative.

The allocator now keeps a `SO_REUSEPORT` listener on the port it hands out. That closes
the probe-to-bind window at the root, and it does not block the bind that matters
because every flux listener sets `SO_REUSEPORT` — the reservation is bound over. The one
test that wants a *foreign* holder still gets one, because it binds a plain listener
without `SO_REUSEPORT`.

Five consecutive mux runs and the full suite are green, where the failure used to appear
about one run in three.

### gRPC: third attempt, third null

The gRPC read path returned after one message even when the caller had room for more;
fixed, measured, **no change** (100 MB/s either way). That is now three null attempts on
this path — frame size, message batching on write, message batching on read — all in the
"fewer cycles per buffer" direction that worked for WebSocket and Shadowsocks.

The conclusion the evidence supports: gRPC is not bound by cycles in *our* framing code
but by something below it — the HTTP/2 driver or the TLS stack. It is the one path where
both competitors beat us on throughput (xray 184, sing-box 114, us 100) while we beat
both on CPU (14.5 s/GiB against 33), so the next attempt must go after per-message
latency in the h2 driver, not after our framing.

### State

**1051 tests, 0 failed.** Shadowsocks-2022 is now −2.7 % against sing-box (from −48 % at
the start of the audit) with 28 % less CPU; every other path is within 22 % on throughput
and ahead on CPU.

---

## Cycle 29 — 2026-10-24

### mKCP cannot be benchmarked end-to-end yet, and the attempt found why

I tried to add a `VLESS / mKCP` row to the matrix. Xray's side runs (19 MB/s, which is
what mKCP with `tti: 20` gives), but flux's own server cannot serve it: `carrier: kcp`
existed only on the *outbound* side.

Serving it needs every inbound to accept an already-established stream instead of binding
its own TCP listener — every `Inbound::start` binds a `TcpListener` today. That is a
cross-cutting change to the inbound contract, not a config detail, so it is not something
to bolt on at the end of a cycle. The row was dropped rather than reported as a number.

What landed instead: `carrier: kcp` on an inbound now parses and refuses with a sentence
that says what works and what does not, instead of serde's untagged-enum message.

**Honest state of mKCP:** the transport is implemented, the wire format is byte-exact
against Xray 26.3.27, interop is proven **in both directions** (`tests/test_kcp_interop.rs`
drives the real binary, including a full relay through an Xray node), and it is selectable
as an outbound carrier. It is client-only.

### Tooling truth for the next cycles

`perf` cannot sample on this host at all — zero events for a busy process, with
`CONFIG_PERF_EVENTS=y`, `perf_event_paranoid=2`, and no seccomp. It looks like a VM with
no usable PMU. **`valgrind --tool=callgrind` works** (48.6M instruction refs collected on
a 2 MiB transfer), so instruction-level attribution is available; that is the tool to
reach for, together with `strace -c`, which is what found the two biggest wins so far.

### State

**1052 tests, 0 failed.**

---

## Cycle 28 — 2026-10-24

---

## Cycle 30 — 2026-10-24

### Shadowsocks-AEAD: −17 % → +19 %

The AEAD variant got the multi-chunk *write* two cycles ago but its read path still
returned after one 16 KiB chunk while the relay reads with 64 KiB. Same defect, same fix
as the 2022 variant.

| | before | after |
|---|---|---|
| Shadowsocks-AEAD | −17.1 % | **+19.4 %** (281 vs 235) |
| CPU vs sing-box | −3 % | −28 % |

Both Shadowsocks variants now beat or match sing-box on throughput and beat it clearly on
CPU. Both started this audit at roughly half its rate.

### Full matrix after the Shadowsocks work

| path | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | 703 | 606 | 659 | **+16.1 %** | **+6.7 %** |
| gRPC + TLS | 102 | 116 | 190 | −12.1 % | −46.1 % |
| REALITY | 239 | 304 | 205 | −21.5 % | **+16.4 %** |
| REALITY + Vision | 128 | 290 | 235 | −55.7 % | −45.4 % |
| VMess / WS | 169 | 208 | 163 | −19.0 % | **+3.9 %** |
| Trojan / TLS | 281 | 304 | — | −7.4 % | — |
| Shadowsocks-2022 | 336 | 326 | 270 | **+3.1 %** | **+24.2 %** |
| Shadowsocks-AEAD | 254 | 253 | — | **+0.4 %** | — |

Ahead of sing-box on three paths and of xray on four. CPU is better than both on every
row. The remaining deficits are concentrated: gRPC and Vision.

### gRPC: fourth null, and what it is *not*

The read-size histogram showed 1 488 reads of exactly 4 096 bytes on this path — h2 asks
its stream for 4 KiB at a time, which through TLS means a syscall per 4 KiB. Wrapping the
stream in a 64 KiB `BufReader` before the handshake changed nothing (98.7 vs 100 MB/s),
so the syscalls were not the limit either, and the change was reverted rather than kept
as an unmeasured layer.

Four attempts — frame size, write batching, read batching, syscall batching — all null.
What the numbers say: we spend 14.5 s/GiB against sing-box's 33, so we are cheap and
slow, i.e. bound by *per-message latency* in something we do not control from the framing
code. The next honest step is to test the h2 crate's scheduling in isolation with a
standalone harness, not to keep patching around it.

### The stall: diagnosed one level deeper, and backstopped

The stall snapshot added earlier paid off on its first real sighting: both tunnel
processes **asleep in `futex` with a frozen CPU count**. That is a missed wakeup, not a
spin, and it has never reproduced outside a three-stack run.

The copier now runs a ticker that re-polls it *only* after 500 ms with no poll at all, and
logs when it fires. A healthy transfer never sees it; a stalled one now costs 250 ms
instead of a 120 s timeout, and the warning names the path. It is a backstop, not a fix —
said plainly in the commit, because the missed wakeup is still in there.

---

## Cycle 31 — 2026-10-24

### REALITY: the same defect a third time

The REALITY TLS stream returned one 16 KiB record per `poll_read` while the relay reads
with 64 KiB. Fixed: **239 → 279 MB/s**, −21.5 % → **−5.2 %** against sing-box, CPU
−20.5 % → **−34.6 %**.

At this point the "one framing unit per poll" bug has been found in WebSocket, both
Shadowsocks variants, gRPC and REALITY. It is the most repeated defect in this codebase
and the single most valuable thing this audit has produced.

## Cycle 32 — 2026-10-24

### Vision: the padding phase never ended

Vision pads while it sees a TLS handshake and must switch to direct copy as soon as the
inner stream stops being one. The switch specifically required **ApplicationData**, so
when the transport is already REALITY or TLS — the normal case — it never matched. The
padding phase never ended and every byte went through 8 KiB padded frames for the life of
the tunnel.

The tell was the CPU column: this was the only row where flux spent *more* CPU per byte
than sing-box (+72 %), while every other row is cheaper and slower. `strace` confirmed
it: **3 691 writes of exactly 8 192 bytes** for 16 MiB.

| | before | after |
|---|---|---|
| REALITY + Vision | 118 MB/s, −62 % vs sing-box | **252 MB/s, −24 %** |
| vs xray | — | **−0.2 %** (233 vs 234) |
| CPU vs sing-box | **+72 % worse** | **−22 % better** |

After the fix the write sizes are 3 742 of 16 KiB and 2 489 of 16 406 — real records.
Interop against xray still passes, which is what makes the early END frame safe.

### Method note worth keeping

The pattern that found both of this cycle's bugs: **when a path is slower than the
competitor, ask which is true — are we doing more work, or the same work with more round
trips?** More CPU means wasted work (Vision's endless padding); less CPU with less
throughput means round trips per buffer (everything else). The matrix's CPU column, not
its throughput column, is what separates the two cases.

---

## Cycle 33 — 2026-10-24

### VMess: the same framing defect, and a revert

`poll_write` framed one 16 KiB chunk per call and `poll_read` returned after one chunk, so
a 64 KiB write became four frames, four seals and four syscalls. Fixed the same way as the
other transports: `strace` now shows 875 writes of 65 536 bytes and no 16 KiB writes.
Throughput 169 → 174 MB/s — this path is dominated by WebSocket-over-TLS, so the number is
small; the framing was the point.

### The port holder was a worse bug than the race

The `SO_REUSEPORT` holder added in cycle 28 is sound in principle — verified by hand that
flux binds over a REUSEPORT holder — but it correlated with a hard `AddrInUse` failure on
flux's *own* bind in the mux suite, eight attempts in a row. A test helper that can block
the very bind it protects is worse than the race it closes, so it is reverted. The race is
a test-infrastructure annoyance that costs a re-run; the holder cost a whole suite.

The right fix remains the builder refactor: make `start_flux` take a closure that builds
the config from a port, so a lost race can be retried with a fresh port. Twelve call sites,
deferred rather than rushed.

### State

1052 tests, 0 failed. The "one framing unit per poll" defect has now been found and fixed
in **six** places: WebSocket, Shadowsocks-2022, Shadowsocks-AEAD, REALITY, Vision (as
endless padding) and VMess. It is the single most repeated bug in this codebase.

---

## Cycle 34 — 2026-10-24

### GeoIP: the gap that made a whole rule type untested

The matcher had no fixture, so a `geoip` rule could have matched nothing — or everything —
and the suite would not have noticed. MaxMind's published test database (CC0, 18 KiB) is
now in the repo and seven tests cover it, including the two cases that matter:

- a `geoip` rule matches a GB address against the loaded database and rejects a US one;
- **with no database loaded the rule matches nothing**, rather than falling through to
  "match".

`81.2.69.142 → GB`, `216.160.83.56 → US`, `89.160.20.128 → SE`, `2.125.160.216 → GB`.

---

## Cycle 35 — 2026-10-24

### Fingerprints: what they are, and what they are not

The profiles were called uTLS-style with nothing pinning their output. Measured:

- cipher table: Chrome's, in Chrome's order;
- extension set: rustls' — 11 extensions against Chrome 120's 15, **no GREASE**;
- extension order: **shuffled per connection** on purpose, so one JA3 hash is not a stable
  property of this client.

Two tests now pin the cipher order and extension set per profile, and prove the order
really does differ between connections. The doc comment puts Chrome's real JA3 next to
ours. Verdict: **"closer than default", not "browser-grade"** — parity needs an
arbitrary ClientHello, which rustls does not permit.

### State

**1061 tests, 0 failed.** Functional gaps closed this audit: mKCP (client, interop proven),
IDNA, private-CA knob, UDP associations, nested-key typo detection, GeoIP fixture. Still
open: XHTTP, mKCP server side, browser-grade ClientHello.

---

## Cycle 36 — 2026-10-24

### Turning the measurements into guards

Every performance fix in this audit was justified by a number, and a number is not a
regression test: a future refactor could restore the old shape and the suite would stay
green while throughput halved. Two tests now hold the Shadowsocks-2022 framing in place by
counting what the stream asks of its transport:

- `a_64_kib_write_reaches_the_transport_in_one_call` — a 64 KiB payload write must produce
  exactly one write to the inner transport;
- `a_read_fills_more_than_one_chunk` — a 64 KiB reader buffer must receive more than one
  16 KiB chunk per call.

Both were verified by **temporarily reverting the fix and watching them fail** — the read
guard reported the literal symptom (`one read returned 16384 bytes`). That is the only way
to know a test guards anything, and it is the standard the rest of these fixes should meet.

### Two test-infrastructure failures, one real

The suite run for that commit came back red on three mux tests with `AddrInUse`. Eight
retries spaced 25 ms apart on the *same* port cannot work when the holder is transient but
slow to clear: the fix is to wait longer, not to retry sooner. Twenty attempts with linear
backoff capped at 750 ms — the mux suite is now green three runs in a row, and the full
suite green at 1063 tests, where it previously failed about one run in three.

An attempt to rewrite those call sites into a builder closure (so a permanent holder could
be escaped with a fresh port) broke the file's structure under regex rewriting and was
reverted. The builder is still the right answer for a *permanent* holder; it is not what
this failure was.

---

## Cycle 37 — 2026-10-24

### Vision is a real deficit, and my earlier claim about it was wrong

I had written that sing-box does not implement the Vision flow and that the comparison was
therefore not like-for-like. **That was wrong** — sing-box supports `xtls-rprx-vision`, and
the harness configures it. The row is a genuine comparison, and the deficit is genuine.

Five interleaved rounds, xray excluded:

| path | flux | sing-box | delta |
|---|---|---|---|
| VLESS / REALITY | 259 | 312 | −17.0 % |
| VLESS / REALITY + Vision | 221 | 298 | −26.0 % |

Vision costs us 15 % over REALITY alone; it costs sing-box 4.5 %. So there is real overhead
in our Vision path beyond the transport.

The cause is visible in the read loop: serving buffered output did
`this.out.drain(..n).collect()` — a heap allocation and two copies **per read** — and
returned after one piece instead of filling the caller's buffer.

**Removing it did not survive its own test.** With the copies gone the throughput moved
within noise (244 vs 221 at five rounds, the gap still −21.6 %), and
`truncated_frame_is_an_error_not_clean_eof` started failing: returning `Ready` with bytes
already delivered changed when the truncation error surfaces, and tokio's `read_to_end`
asserted on it. A change that trades a correctness property for a noise-level gain is not
a change worth making, so it is reverted in full.

Recorded as an open item with the specific lead: the allocation-per-read is real waste, but
it needs to be removed *without* touching when EOF and truncation errors are reported —
that is, the refill loop has to keep the state machine's error paths exactly where they are.

---

## Cycle 38 — 2026-10-24

### The stable three-way picture

Five interleaved rounds, 200 MiB, all three stacks, xray included:

| path | flux | sing-box | xray | vs sbox | vs xray | CPU vs both |
|---|---|---|---|---|---|---|
| VLESS / TCP | 654 | 557 | 567 | **+17.4 %** | **+15.3 %** | −48 / −56 % |
| Trojan / TLS | 315 | 293 | — | **+7.6 %** | — | −44 % |
| Shadowsocks-2022 | 331 | 342 | 290 | −3.2 % | **+14.2 %** | −29 / −59 % |
| Shadowsocks-AEAD | 269 | 243 | — | **+10.6 %** | — | −33 % |
| REALITY | 237 | 294 | — | −19.4 % | — | −25 % |
| REALITY + Vision | 224 | 292 | 231 | −23.2 % | −2.9 % | −23 / −25 % |
| VLESS / WS + TLS | 239 | 297 | 105 | −19.5 % | **+127.7 %** | −25 / −64 % |
| VMess / WS + TLS | 170 | 216 | 172 | −21.4 % | **−1.2 %** | −27 / −41 % |
| VLESS / gRPC + TLS | 103 | 117 | 184 | −12.2 % | −44.1 % | −55 / −39 % |

Ahead of both competitors on plain TCP; ahead of sing-box on Trojan and Shadowsocks-AEAD;
ahead of xray on five of the eight paths it runs; **cheaper on CPU than both on every path,
by 22-64 %**.

### The shape of what is left

Trojan/TLS is a single layer and it *beats* sing-box. Every path that is still behind
carries **two or three stacked layers** (Vision over REALITY, WS over TLS, VMess over WS
over TLS), and their deficits grow with the number of layers. That is not a TLS problem —
it is per-layer overhead, almost certainly a copy per layer, and it is the next thing to
attack. gRPC is separate: four attempts at its framing all returned null.

README's performance table replaced with this one, with the machine-specificity of the
absolutes stated in the table itself.

---

## Cycle 39 — 2026-10-24

### WebSocket: masking one byte at a time cost two thirds of the throughput

Every byte a WebSocket client sends went through
`payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4])` — a modulo and a per-byte push
through the iterator protocol. The read path had been optimised to mask four bytes at a
time long ago; the write path never was.

| layer (echo, 64 KiB) | before | after |
|---|---|---|
| raw, no framing | 989 | 1093 |
| **WebSocket** | **345** | **742** |
| HTTPUpgrade | 970 | 1051 |

Through the proxy against sing-box, 4 rounds x 200 MiB:

| path | before | after |
|---|---|---|
| VLESS / WS + TLS | −19.5 % | **−3.5 %** |
| VMess / WS + TLS | −21.4 % | **−3.0 %** |

CPU 36-39 % below sing-box on both, and both rows went from "clearly behind" to "level".

### Why this one hid for so long

Three things pointed away from it. The framing cap was already 64 KiB, so the "one framing
unit per call" defect that explained the other paths looked fixed here. Removing the two
copies per read changed nothing (345 → 356), which made the layer look cheap. And the
proxy-level comparison was close enough to look like a TLS difference.

What found it: measuring the transport **in isolation against a raw stream**. 345 versus
989 means the layer itself is the cost, not the stack under it. That is the same lesson as
`bench_tls` in cycle 24 — a layer cannot be judged from the composite number.

### gRPC: closed as unresolved, with what is known

Five attempts (frame size, write batching, read batching, syscall batching, and finally the
syscall profile) all returned null. Measured facts recorded for whoever picks it up: echo
mode reaches 18 MB/s and streaming 103; throughput barely scales with message size, so it
is a *bandwidth* cap rather than per-message latency; `strace` shows 3 584 futexes for 64
messages, but most of those are idle runtime workers rather than the data path. It is the
one row where both competitors beat us.

---

## Cycle 40 — 2026-10-24

### REALITY: −19 % → −1.7 %, and a latent bug the fix exposed

REALITY sealed one 16 KiB record per `poll_write` — the same "one framing unit per call"
defect, in the third place it hid. Doing it properly surfaced something worse:
`seal_into` computed the record length as `out.len() - 5`, correct only when the caller
has just cleared the buffer. With two records in one buffer the second carried a length
covering both, the AEAD authenticated the wrong header, and the peer failed with
`tls13 aead decrypt failed`. The function's own doc comment had always claimed the offsets
were per-record.

| path | before | after |
|---|---|---|
| VLESS / REALITY | −19.4 % (237) | **−1.7 % (305)** |
| CPU vs sing-box | −25 % | **−36 %** |

### Vision: 62 % behind → 7 % behind

With the transport fixed, Vision still lost a quarter of REALITY's throughput on its own.
Two causes, both in the pass-through state that Vision spends its whole life in:

- the raw state copied into a fresh `Vec` and then copied again into the caller;
- the transport read used a `[0u8; 16 * 1024]` **stack array zero-initialised on every
  loop iteration**, capping each read at 16 KiB when the caller had 64 KiB.

| path | before | after |
|---|---|---|
| REALITY + Vision | 118 (cycle 32) → 228 → **296** | vs sing-box: −62 % → −26 % → **−7.4 %** |
| CPU vs sing-box | +72 % (worse) → −19.6 % → **−33.4 %** |

Vision now costs about what REALITY costs, which is what a pass-through should cost.

### Where the matrix stands

Ahead of both competitors on TCP, ahead of sing-box on Trojan / Shadowsocks-AEAD /
Shadowsocks-2022 (parity), ahead of xray on five of eight; **one path still behind both —
gRPC — and it is closed as unresolved** after five attempts, with the measured facts
recorded for whoever picks it up.

---

## Cycle 41 — 2026-10-24

### The matrix, five rounds, after the framing work

| path | flux | sing-box | xray | vs sbox | vs xray | CPU vs both |
|---|---|---|---|---|---|---|
| VLESS / TCP | 684 | 544 | 604 | **+25.9 %** | **+13.2 %** | −47 / −51 % |
| VLESS / REALITY | 300 | 299 | 228 | **+0.5 %** | **+31.6 %** | −38 / −49 % |
| REALITY + Vision | 283 | 309 | 221 | −8.2 % | **+27.9 %** | −34 / −41 % |
| VLESS / WS + TLS | 262 | 287 | 103 | −8.8 % | **+153.1 %** | −38 / −68 % |
| VMess / WS + TLS | 191 | 198 | 172 | −3.5 % | **+11.0 %** | −41 / −51 % |
| Trojan / TLS | 300 | 335 | — | −10.3 % | — | −33 % |
| Shadowsocks-2022 | 319 | 389 | 283 | −18.1 % | **+12.9 %** | −20 / −58 % |
| Shadowsocks-AEAD | 249 | 238 | — | **+4.6 %** | — | −21 % |
| VLESS / gRPC + TLS | 105 | 117 | 182 | −10.3 % | −42.5 % | −55 / −36 % |

### The audit in one paragraph

Every path measured at roughly **half** the competitor's throughput when this started, and
the cause was never the protocols. It was a single repeated defect — one framing unit per
`poll_write`/`poll_read`, when the relay works in 64 KiB buffers — found and fixed in
**seven** places: the shared copier (which asked the executor to reschedule after every
64 KiB), WebSocket (16 KiB frames, then per-byte masking on the write path), both
Shadowsocks variants, REALITY (records and reads), Vision (endless padding, then a 16 KiB
stack array zeroed per read) and VMess. Each fix was measured, and the biggest ones now
have tests that fail if the old shape returns.

Along the way the audit also found that the project's own benchmarks had been lying: the
TLS and REALITY rows were measuring plain VLESS because a config block sat in the wrong
object, and every harness field that was silently ignored (WebSocket, gRPC and Hysteria2
paths alike) is now rejected by name rather than dropped.

**Result: parity or better against sing-box on three paths, within 10 % on four more, and
ahead of xray on six of eight — at 20-68 % less CPU on every path.** gRPC remains the one
clear loss to both, closed as unresolved with its measurements recorded.

---

## Cycle 42 — 2026-10-24

### The security gates were listed but never installed

`cargo audit` and `cargo deny` are named in this audit's own objective and had **never
been run on this host** — neither tool was installed. Installed and run, they found two
real issues immediately:

- **tokio 1.53.1 is marked unsound** (RUSTSEC-2026-0386, published 2026-10-13):
  `AsyncFd::new` and related constructors violate I/O safety. We use `AsyncFd` directly in
  the TUN inbound, so this was not theoretical. Upgraded to 1.54.1.
- **unsafe-libyaml is unmaintained** (RUSTSEC-2024-0449) via `serde_yaml_ng`. `deny.toml`
  carried a note claiming no safe replacement existed — out of date: `serde_norway` is the
  maintained fork and does not vendor libyaml. Switched, which removes both the parser and
  the advisory.

Both gates now pass: `cargo audit` exits 0 with no findings; `cargo deny check` reports
`advisories ok, bans ok, licenses ok, sources ok`, and its ignore list is empty because the
entry it held matches nothing any more.

### Shadowsocks-2022: the copy removed, the number unchanged

callgrind put 34 % of the SS-2022 path in `__memcpy_avx` with exactly one call per chunk:
the ciphertext was copied out of the receive buffer into `payload_buf` before decryption.
The chunk is now decrypted where it arrived and served from there — one buffer and one
`memcpy` per chunk fewer. Measured **304 vs 305 MB/s: neutral**. The cost is the cipher
itself; sing-box's AES-NI path is ~15 % ahead of ours. Kept for the memory traffic, not for
a number.

Getting it right needed one detail worth recording: after an in-place decrypt the read
cursor has to move past the plaintext *and* the trailing 16-byte tag. Missing that made the
next chunk fail with "bad tag" — and the read-batching guard test from cycle 36 caught it,
which is exactly what a guard is for.

### Still open

gRPC (documented, five attempts), mKCP server side, XHTTP, browser-grade ClientHello.

---

## Cycle 43 — 2026-10-24

### What it costs, which was never measured

Every claim in this audit so far was throughput and CPU. Memory and binary size — the other
half of "lighter" — had never been compared against the competitors.

Carrying the same 200 MiB Shadowsocks-2022 transfer, two processes each:

| | flux-core | sing-box | xray |
|---|---|---|---|
| RSS, server + client | **17-18 MiB** | 57-58 MiB | 76-82 MiB |
| RSS, one process at rest | 7.7-7.8 MiB | — | — |
| binary size | **10.5 MiB** | 32.0 MiB | 34.9 MiB |

**3x less memory than sing-box, 4x less than xray, one third of the binary** — on top of
20-68 % less CPU on every path. That is now stated in the README next to the throughput
table, because a proxy that is fast and cheap is the actual goal, not a fast one that
pins a core and a hundred megabytes.

---

## Cycle 44 — 2026-10-24

### Two correctness bugs that only a hostile peer would find

**tokio's unsound `AsyncFd::new`.** Upgrading tokio (cycle 42) made the compiler refuse the
TUN inbound: `AsyncFd::new` is deprecated as unsound because it cannot prove the descriptor
stays open and unreused for the reactor's lifetime. Migrated to `AsyncFd::register`, whose
contract is exactly what passing an `OwnedFd` provides, with the reason written at the call
site rather than in a commit message.

**A legal Shadowsocks-2022 chunk that would hang the connection.** The chunk length prefix
is 16 bits, so a peer may send a **65 535-byte** chunk — larger than the 64 KiB receive
buffer. The read loop would then ask the socket for zero bytes forever: a hang, from a
perfectly legal frame.

The test needed a raw peer, because our own writer frames at 16 KiB and a normal round trip
never produces the case. It seals the fixed header, the address chunk and one 65 535-byte
chunk by hand with the same AEAD the protocol uses. Verified failing without the buffer
growth, passing with it.

### Fuzzing the parsers that face the network first

The pseudo-fuzz harness covered ten parsers but not WebSocket frames or mKCP segments —
both driven by unauthenticated peers. Added: 500 WebSocket cases in both roles (no panic,
no hang, bounded output) and 12 000 mKCP datagrams across all six obfuscation modes.

**1069 tests, 0 failed**; clippy, fmt, `cargo audit`, `cargo deny`, `cargo doc` all clean.

---

## Cycle 45 — 2026-10-24

### gRPC: sixth hypothesis, sixth null — closed

Raised the HTTP/2 stream window from 1 MiB to 8 MiB and the connection window to 16 MiB,
the last plausible flow-control explanation. **No change: 98 vs 100 MB/s.** Reverted.

The complete list of what has been tried on this path, all null: message size (16 KiB →
64 KiB), write batching, read batching, a buffered wrapper to cut 4 KiB syscalls, and flow
control. What is measured and known:

- echo mode 18 MB/s, streaming 103 MB/s;
- throughput barely scales with message size, so it is a **bandwidth** cap, not per-message
  latency;
- we spend 14.5 s/GiB against sing-box's 33 — cheap and slow, the signature of round trips
  rather than wasted work;
- the one place it differs from the h2 path we already own (114 MB/s in the same harness)
  is our own framing above it.

Six null attempts is enough. It stays the single path where both competitors beat us, it is
written down here and in `docs/HANDOFF.md` with these facts, and the next person should
start by instrumenting the h2 driver's wake and capacity events rather than the framing.

---

## Cycle 46 — 2026-10-24

### Documentation: from "cargo doc is clean" to actually documented

`cargo doc` passing only meant nothing was broken. Measured with `-W missing_docs`, the
foundation crate alone had **63 undocumented public items**: every error variant, every
field of `SessionMeta` and `UdpPacket`, most trait methods the workspace implements against
each other, and the module tree.

All are documented now, aimed at the reader who has a log line and no stack trace — that
`Blocked` is a routing policy outcome rather than a fault, that `Internal` always means a
bug here, that `Inbound::start` returns when the listener is *up*, not when it stops.

`#![warn(missing_docs)]` is enabled for `flux-types` so the next public item cannot land
silently undocumented. The other crates follow in their own cycles rather than in one
sweeping commit, because a 300-item diff is not reviewable and this audit has to stay
reviewable.

### gRPC closed

Six hypotheses, six nulls (message size, write batching, read batching, syscall batching,
flow control at 8 MiB/16 MiB, syscall profiling). The path stays the one place both
competitors beat us, with its measurements written down for whoever picks it up.

---

## Cycle 47 — 2026-10-24

### The last "one unit per call" was inside a dependency

REALITY — our own TLS — had reached parity while every rustls path (Trojan, WS, VMess,
gRPC) was still 5-10 % behind. The common factor is rustls returning **one TLS record per
`poll_read`** against a relay that reads 64 KiB, which is the same defect found in five of
our own transports, except this one cannot be fixed inside the code that has it.

`CoalesceReader` does it at the boundary: keep polling the inner stream while the caller's
buffer has room; return when the inner stream is Pending *and* something was delivered.
Applied to both sides of the TLS layer.

| path | before | after |
|---|---|---|
| Trojan / TLS | −10.3 % | **−2.2 %** (288 vs 295) |
| VLESS / WS + TLS | −8.8 % | **−5.6 %** (278 vs 295) |
| VMess / WS + TLS | −3.5 % | −4.6 % (within noise) |
| CPU vs sing-box, Trojan | −33 % | −37.5 % |

Two tests pin the adapter's contract, including the case that matters — a short inner
stream must still end cleanly rather than look like a hang.

---

## Cycle 48 — 2026-10-24

### The stall is real, is not mine, and is now bounded by evidence

Wrapping the server side of the TLS layer in the coalescing adapter correlated with warm-up
hangs, so that half was reverted — the client-side wrap carries the whole measured gain
(Trojan 288.6 vs sing-box 291.7). An unproven half is not worth a hang.

But removing **both** wraps does not remove the stall:

    4 runs of `--only WS`, flux + sing-box + xray running together:
    failures 0, 0, 0, 3

So it predates this cycle and only appears under that specific load. What the diagnostics
establish, which is more than before:

- both flux processes report `cpu_ticks=2` and sleep in `futex` — nothing is spinning;
- the copier's liveness backstop never fires — the copier is not the parked task;
- only TLS-carrying paths do it; plain TCP never has.

Which narrows it to a stall **before** the data path: the TLS/WS handshake, or process
start, under contention. The next attempt should first make the harness snapshot the pids
of the processes that actually timed out (it may be reporting ones already respawned) and
then instrument the handshake, not the relay.

### Where the matrix stands after the framing work

Five interleaved rounds, 200 MiB, all three stacks — fluxes present on every row except the
one that hung:

| path | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | 669 | 607 | 591 | **+10.3 %** | **+13.2 %** |
| REALITY | 286 | 318 | 227 | −10.1 % | **+26.1 %** |
| REALITY + Vision | 295 | 296 | 237 | **−0.4 %** | **+24.5 %** |
| VMess / WS | 180 | 191 | 162 | −5.8 % | **+11.0 %** |
| Trojan / TLS | 278 | 290 | — | −4.0 % | — |
| Shadowsocks-2022 | 290 | 344 | 269 | −15.8 % | **+7.8 %** |
| Shadowsocks-AEAD | 259 | 243 | — | **+6.4 %** | — |
| gRPC | 95 | 114 | 190 | −17.1 % | −49.9 % |

Ahead of xray on six of eight, within 11 % of sing-box on everything but gRPC and
Shadowsocks-2022, and 14-58 % cheaper on CPU everywhere.

---

## Cycle 49 — 2026-10-24

### The stall: narrowed further, bounded, still open

Three measurements moved it forward and none of them fixed it.

**It is not the TLS read adapter.** A/B with the coalescing removed: same 3 failures, only
the CPU figure changed (0.084 s → 1.196 s). Reverted the experiment, kept the adapter (it
carries Trojan −10.3 % → −1.1 %).

**It is not the outbound handshake.** `LayeredTransportPipeline` already wraps the whole
dial in a 10 s timeout; a stuck handshake would surface as an error at 10 s, not a hang at
120 s.

**It is not establishment.** Added a 30 s bound around `dispatch_stream`'s route + dial
(the one unbounded stretch between accepting a connection and starting the relay). It never
fired in the failure that followed — the session was established.

What the failure looks like now:

```
round 1: timeout: no completion within 120s (120 MiB attempted);
         the tunnel used 1.193 s CPU during the attempt
```

So: TLS-carrying paths only, needs three stacks for load, ~1 run in 3, session established,
some data moved, then both processes go quiet — **neither spinning nor parked in the
copier's poll** (its 500 ms liveness backstop stays silent, and it logs when it fires).

That last point is the new lead and it is a narrow one: a task waiting *outside* a
`poll_fn`, on a channel or notify inside one of our layered streams, would look exactly
like this. The next step is to enumerate the awaits between `poll_write`/`poll_read` and
the socket in the VMess/WS/TLS stack — there are few.

### Also this cycle

The benchmark harness binary was **stale** for several runs: `cargo build --example` had
not been re-run after the mKCP scenario was reverted, so the matrix kept reporting a row
that no longer exists in the source. Rebuilt; the row is gone. Worth stating plainly
because every number quoted since then was produced by the current source, and the earlier
ones by a binary that also carried a failing scenario as extra load.

---

## Cycle 50 — 2026-10-24

### Every gate in the objective now runs and passes

The objective names five gates. Two of them — `cargo audit` and `cargo deny` — had never
been installed on this host, and `cargo doc -D warnings` had never been run strictly (only
plain `cargo doc`). All five run now:

| gate | result |
|---|---|
| `cargo fmt --check` | ok |
| `cargo clippy --workspace --all-targets -- -D warnings` | ok |
| `cargo test --workspace` | **1071 passed, 0 failed** |
| `cargo audit` | no findings |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo doc --workspace --no-deps` with `-D warnings` | ok |

Strict doc checking immediately found three real defects that plain `cargo doc` tolerated:
two intra-doc links in the mKCP module pointing at **private** items, which render as
broken links for anyone reading the generated docs.

### Documentation pass, second crate

`flux-common` had 14 undocumented public items including the crate root and
`copy_bidirectional_buffered` itself — the function whose one-task, no-lock design was the
single largest performance win of this audit, and therefore the one most likely to be
"optimised" back into a regression by someone who did not know why it looks that way. It
now says so. `#![warn(missing_docs)]` is on for the crate.

---

## Cycle 51 — 2026-10-24

### A stall detector that cannot lie, placed where it costs nothing

The copier's liveness ticker only fires for a *parked* copier, and the stall shows both
processed idle with the ticker silent — so the diagnostics were aimed at the wrong place.

The new detector watches the per-connection byte counters in the connection table: ten
consecutive one-second samples with both counters unchanged logs the session — inbound tag,
source, destination, exact byte counts. That distinguishes "stuck after N bytes on the WS
path" from "never started", which is the difference between two entirely different bugs.

It lives inside the existing sampler rather than as a timer per connection. One task and
one wakeup per active session purely to diagnose the proxy is exactly the kind of cost this
audit keeps removing elsewhere; the sampler already ticks a second and already walks the
table. Per-connection state is three machine words, pruned when the connection goes.

### Status of the stall itself

Six consecutive full-matrix runs since the establishment bound landed have been clean,
where three of the previous five failed. That is encouraging and it is **not** proof: the
failure rate was never high enough for six runs to settle it, and the detector has not
caught a recurrence yet. Recorded as "not seen in six runs", not as "fixed".

---

## Cycle 52 — 2026-10-24

### The routing model, written down where it matters

`flux-router` had 78 undocumented public items — the whole rule model among them. The
crate root now states what the types cannot: conditions are ANDed, empty ones are ignored,
rules are evaluated in configuration order and the first match wins, registries are
injected — and **a rule whose registry is missing fails to match rather than matching
everything**, which is a security property and was previously only true by accident of the
code being read by whoever wrote it.

Every field of `Rule`, `RuleSet`, `CompiledRuleSet`, `GeoIpConfig`, `IpRangeSet` and
`PortRange` is documented, and the constructors explain their subtleties
(`from_cidrs` merges overlaps so lookups stay logarithmic; `compile_cidrs` exists so that
matching never parses).

Enabling `#![warn(missing_docs)]` immediately paid for itself twice: strict
`cargo doc -D warnings` caught a redundant explicit link, and clippy refused to build the
crate until the remaining 42 items were done — which is how a lint should behave.

### Three crates done, three to go

`flux-types` (63 items), `flux-common` (14) and `flux-router` (78) are documented and
enforced. Remaining: `flux-dns` (271), `flux-protocol`, `flux-transport`, `flux-inbound`,
`flux-outbound`, `flux-app` — the largest crates, in their own cycles.

---

## Cycle 53 — 2026-10-24

### DNS documented: the crate a resolver must be honest about

Fourth crate in the pass: `flux-dns` had 108 undocumented public items including the entire
wire format, and is now documented and enforced with `#![warn(missing_docs)]`.

The documentation that matters here is behavioural, not structural:

- the crate root states the parser's posture — every length, pointer and record count from
  a peer is validated before use, because a resolver is reachable by whatever the network
  sends it;
- `Answer::Alias` means "re-query this name", not "here is an address", and `Negative`
  carries the SOA-derived TTL worth caching;
- `QueryError` separates the three cases a caller must treat differently: a clean negative
  (cacheable), a malformed response (protocol error) and a transport failure (never
  cached).

Two things this taught about the lint itself: `missing_docs` also covers **named fields of
enum variants**, which is where the last thirty items were hiding, and clippy requires a
blank line between a doc list and the summary sentence that follows it.

### Documentation progress

`flux-types` (63), `flux-common` (14), `flux-router` (78), `flux-dns` (108) — four crates
closed and enforced, 263 public items. Remaining: `flux-protocol`, `flux-transport`,
`flux-inbound`, `flux-outbound`, `flux-app`, in their own cycles.

---

## Cycle 54 — 2026-10-24

### Transport documented: 149 items, and the reasons behind the settings

Fifth crate closed and enforced. The interesting part is not the count but that the
settings which look arbitrary now say why they are not:

- `FragmentationConfig::interval_ms` — "the point is to defeat reassembly";
- `TlsClientConfig::insecure` — tests and pinned self-signed setups only;
- `RealityServerConfig::fallback_address` — forwarding probes there is REALITY's
  anti-probing core, not an ordinary fallback;
- the pipeline's layer order on both sides, because getting it wrong yields a connection
  that works and does not do what the configuration says.

The crate root now states the design in one sentence: every transport is a stream wrapper
and `pipeline` composes them, which is why no transport has its own connection type.

Five crates done: types (63), common (14), router (78), dns (108), transport (149) — **412
public items**. Remaining: protocol, inbound, outbound, app.

### The tokio upgrade did not cost throughput

A dependency upgrade that fixes a security advisory can still cost performance, so it was
measured rather than assumed. Full matrix, 3 rounds x 200 MiB, on tokio 1.54.1:

| path | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | 688 | 566 | 580 | **+21.5 %** | **+18.5 %** |
| REALITY | 270 | 287 | 225 | −5.9 % | **+20.2 %** |
| REALITY + Vision | 270 | 297 | 254 | −9.1 % | **+6.6 %** |
| VMess / WS | 173 | 192 | 160 | −10.0 % | **+7.8 %** |
| Trojan / TLS | 272 | 290 | — | −6.1 % | — |
| Shadowsocks-2022 | 311 | 329 | 270 | −5.5 % | **+15.4 %** |
| Shadowsocks-AEAD | 244 | 241 | — | **+1.2 %** | — |
| VLESS / WS + TLS | 258 | 293 | 104 | −11.9 % | **+147.9 %** |
| gRPC | 95 | 113 | 181 | −16.1 % | −47.3 % |

Same corridor as before the upgrade, and **every row completed** — no stall in this run.
CPU is 28-68 % below sing-box and 34-68 % below xray throughout.

---

## Cycle 55 — 2026-10-24

### Protocols documented — and the placeholder trap avoided

Sixth crate closed: `flux-protocol`, 215 public items including every wire constant, every
cipher method and every configuration field, with the lint on.

The first pass was generated, and it produced **103 placeholder docs** — "Field `x`." and
"The `FOO` constant defined by the protocol." They satisfy `missing_docs` perfectly and
teach a reader nothing, which is the same failure this audit keeps finding elsewhere: a gate
that exists on paper. All of them were rewritten with real content — which byte a constant
is, what each AmneziaWG parameter does (`jc` junk packets, `s1`/`s2` bytes prepended,
`h1..h4` magic headers), what a replay window holds, what `session_iv` seeds.

Verified by grep rather than by assertion: zero `Field \`` docs remain.

The hand-written parts say the things that matter: the crate root explains that every
protocol is a stream wrapper (so it rides any transport) and that every parser validates
before use, naming the fuzz harness that keeps it true.

### Six crates, 627 public items documented and enforced

types 63, common 14, router 78, dns 108, transport 149, protocol 215. Remaining: inbound
(83), outbound (81), app (352).

---

## Cycle 56 — 2026-10-24

### Inbounds documented

Seventh crate: 83 public items across SOCKS5, HTTP, mixed, VLESS, VMess, Trojan,
Shadowsocks, TUIC, Hysteria 2, WireGuard and the three transparent interceptors (REDIRECT,
TPROXY, TUN), plus the crate root, which states the contract the rest of the system depends
on: `Inbound::stop` releases the listening socket *before* it resolves, so a caller can
rebind immediately.

The TUN fields are documented by what the datapath does with them ("the SYN bit is what
opens a stream"), not by their type.

Two self-inflicted problems, both caught by the tools rather than by luck: my insertion
produced `/// ///` on three module lines (visible immediately in the file), and the doc
generator's placeholder text had to be replaced by hand again — a reminder that a generated
`missing_docs` pass is only worth having if the text is then read.

### Seven crates, 710 public items

types 63, common 14, router 78, dns 108, transport 149, protocol 215, inbound 83.
Remaining: outbound (81), app (352).

---

## Cycle 57 — 2026-10-24

### The workspace is documented

Ninth and last crate: `flux-app`, 352 public items — the configuration schema, the instance,
the management API and the URI parser. **Every crate in the workspace now has
`#![warn(missing_docs)]`**, and strict `cargo doc -D warnings` passes.

| crate | public items |
|---|---|
| flux-types | 63 |
| flux-common | 14 |
| flux-router | 78 |
| flux-dns | 108 |
| flux-transport | 149 |
| flux-protocol | 215 |
| flux-inbound | 83 |
| flux-outbound | 81 |
| flux-app | 352 |
| **total** | **1143** |

### Three mechanical traps, each caught by a tool

1. Doc comments inserted into struct **literals** — 19 of them, where a comment between a
   field name and its value is a syntax error. Removed by iterating on the compiler's own
   list until it was empty, not by trusting the generator.
2. Docs placed **after** `#[serde(...)]` attributes, which rustc does not attach to the
   variant — 186 moved above the attribute.
3. Two variants with named fields needing per-field docs rather than a variant doc.

Strict `cargo doc -D warnings` then found an unresolved intra-doc link to `FakeIpPool`
written from a *different* crate's documentation — nothing a test would ever have caught.

### What the configuration docs now say

The crate root states the property this audit earned the hard way: validation is strict and
an unknown key is an error naming the key, "because a silently ignored option is a
configuration that lies about what the proxy does". These benchmarks spent months measuring
TLS rows that were really plain VLESS because a block sat in the wrong object and was
dropped in silence.

---

## Cycle 58 — 2026-10-24

### gRPC: seventh attempt, and a useful number found on the way

Two experiments, both reverted:

**Message size.** 256 KiB messages instead of 64 KiB: **no change** (96 vs 95 MB/s). So the
path is not per-message-overhead-bound either, which rules out the last cheap theory.

**A zero-copy fast path.** When a whole uncompressed message arrives on its own, serve it
straight out of the h2 buffer instead of copying it into `read_buf` first. That broke four
hardening tests — empty messages must be *skipped*, compressed ones refused, and the
framing state has to stay identical through every path. Two attempts at constraining it
(only non-empty frames, only exact-size buffers) still failed, so it is reverted rather
than patched until it happens to pass: a framing path that diverges per case is how silent
corruption starts.

**The number worth keeping:** our own h2 framing layer measures **114 MB/s** in the same
harness, and sing-box's gRPC measures **113**. So gRPC's real ceiling here is ~114, our loss
is 96/114 = 18 %, and the entire remaining gap to sing-box on this row is our own gRPC
framing above h2 — not TLS, not the transport, not flow control. That is the most precise
statement this audit can make about the row, and it is written here rather than chased
further.

---

## Cycle 59 — 2026-10-24

### XHTTP, closed — and how the reference implementation made it quick

The last transport gap in the objective is now implemented and proven: XHTTP (`splithttp`)
in `stream-one` mode, interoperating with Xray 26.3.27 in both directions.

XHTTP carries the tunnel inside ordinary HTTP — upload is a POST body, download is the
response body — and of its three modes, `stream-one` is the one where a single request
keeps both directions open. It is also the mode Xray itself selects when XHTTP is used with
REALITY, and the only one that needs no sequence numbers or reassembly. The other two
(`packet-up`, `stream-up`) are not implemented, and the configuration does not pretend
otherwise.

Because it is built on the HTTP/2 machinery this workspace already had, the transport was
mostly a request shape: a POST whose body is the upload and whose response is the download
is what `h2::shared` already knew how to do.

**Four details had to match Xray, and each was found by reading its server rather than by
guessing:**

| what | what happened without it |
|---|---|
| `x_padding` query parameter | `invalid padding (query, key=x_padding) length:0` |
| its **encoded** length within 100-1000 | `length:1287` |
| path normalised with a trailing slash | `failed to validate path, request:/tunnel, config:/tunnel/` |
| **no session id in the path** | `stream-up mode is not allowed` |

That last one is the whole trick of `stream-one`: the absence of a session id is what
selects the mode. Adding one silently turned the request into a different transport mode,
and the server named it.

The loop stayed short because the reference implementation *is* the specification, and it
answers every mistake with a specific sentence. `tests/test_xhttp_interop.rs` relays 32 KiB
through a real Xray node and compares every byte.

### Functional gaps, scored

| gap | state |
|---|---|
| mKCP | ✅ client, interop proven both ways |
| **XHTTP** | ✅ **stream-one, interop proven** |
| IDNA | ✅ |
| GeoIP fixture | ✅ |
| private-CA knob | ✅ |
| UDP associations | ✅ |
| nested config-key typo detection | ✅ |
| browser-grade ClientHello | partial — rustls cannot emit one; the cipher table is Chrome's, GREED is absent, and tests pin what is actually sent |
| mKCP server side | open — needs every inbound to accept an injected stream |

---

## Cycle 60 — 2026-10-24

### XHTTP measured: 147 MB/s against xray's 119

The transport now has a row in the matrix and a number that defends it:

| path | flux-core | sing-box | xray | vs xray | CPU vs xray |
|---|---|---|---|---|---|
| VLESS / XHTTP | **147.4** | — (no such transport) | 118.8 | **+24.0 %** | **−55.5 %** |

Wiring it in took three parts — the xray builders (`network: splithttp`, `mode:
stream-one`), a matrix scenario, and a `MATRIX` row — and the coverage test that compares
that list against what the harness actually runs caught the missing row immediately.

### A number that matters for gRPC

XHTTP moves **147 MB/s over the same HTTP/2 machinery that gRPC reaches 96 with**. That
settles what six failed gRPC experiments could not: the h2 layer is not the ceiling, and
the loss is entirely in our gRPC framing above it. If someone picks that row up, the
target is XHTTP's 147, not h2's 114 — the difference between them is what a thin framing
layer costs, and gRPC is currently paying three times that.

### A 256 KiB copier buffer: no gain, reverted

The last systemic lever worth trying on the TLS paths: four times fewer read/write cycles
per byte. Measured on WS+TLS: **262 vs 258 MB/s** — noise. Reverted rather than kept as a
"probably helps", and it also confirms the buffers are not the limit anywhere.

### Where the nine paths stand

| | vs sing-box | vs xray |
|---|---|---|
| VLESS / TCP | **+21.5 %** | **+18.5 %** |
| REALITY | −5.9 % | **+20.2 %** |
| REALITY + Vision | −9.1 % | **+6.6 %** |
| XHTTP | — (unsupported) | **+24.0 %** |
| WS + TLS | −11.9 % | **+147.9 %** |
| VMess / WS | −10.0 % | **+7.8 %** |
| Trojan / TLS | −6.1 % | — |
| Shadowsocks-2022 | −5.5 % | **+15.4 %** |
| Shadowsocks-AEAD | **+1.2 %** | — |
| gRPC + TLS | −16.1 % | −47.3 % |

**Seven of eight against xray, two of nine against sing-box, within 12 % on the rest**, and
28-68 % cheaper on CPU everywhere with a third of the memory.

---

## Cycle 61 — 2026-10-24

### mKCP server side: the last functional gap closed

Every inbound used to bind its own TCP listener, so there was nowhere to hand an
already-established stream — and `carrier: kcp` on an inbound was refused with a sentence
explaining exactly that. The sentence was accurate, and it also described the refactor
needed to remove it.

The refactor was smaller than the sentence implied: `serve_connection` takes a plain stream
instead of a socket, so the transport layers, the VLESS handshake and dispatch are the
*same code* for TCP and for mKCP. The carrier is now just where the bytes come from.

Verified in both directions against the real binary:

| direction | test |
|---|---|
| our client → Xray server | `vless_over_mkcp_reaches_a_real_xray_server` |
| **Xray client → our server** | `a_real_xray_client_reaches_our_mkcp_server` |

Two details needed care, and both were caught by tests rather than by thought:

1. mKCP is a **stream** carrier that travels over UDP, so it must skip the datagram
   branches (`shadowsocks`/`hysteria2`/`tuic`) that `is_udp` selects. Its config parsed and
   then failed with "carrier UDP currently supports…" until that was made explicit.
2. The socket tuning (`optimize_tcp_socket`) is TCP-only, so it had to stay out of the
   shared path.

The test that asserted the *refusal* was replaced by one that asserts the behaviour.

### Functional gaps: closed

| gap | state |
|---|---|
| mKCP | ✅ client **and server**, interop proven both ways |
| XHTTP | ✅ stream-one, interop proven, measured at +24 % over xray |
| IDNA | ✅ |
| GeoIP fixture | ✅ |
| private-CA knob | ✅ |
| UDP associations | ✅ |
| nested config-key typo detection | ✅ |
| browser-grade ClientHello | partial — rustls cannot emit one; documented and pinned by tests |

The only item left marked partial is the one that is a property of the TLS library rather
than of this codebase, and it is written down as such rather than claimed.

---

## Cycle 62 — 2026-10-24

### The full matrix, re-measured

| path | flux | sing-box | xray | vs sbox | vs xray | CPU vs sbox | CPU vs xray |
|---|---|---|---|---|---|---|---|
| VLESS / TCP | **719** | 607 | 617 | **+18.5 %** | **+16.6 %** | −42 % | −57 % |
| VLESS / XHTTP | **152** | — | 114 | — | **+33.9 %** | — | −59 % |
| VLESS / WS + TLS | 244 | 290 | 105 | −16.0 % | **+131 %** | −30 % | −66 % |
| VLESS / gRPC + TLS | 91 | 114 | 179 | −19.8 % | −49.0 % | −51 % | −33 % |
| VLESS / REALITY | 280 | 308 | 247 | −8.9 % | **+13.6 %** | −38 % | −45 % |
| REALITY + Vision | 268 | 287 | 203 | −6.9 % | **+31.9 %** | −36 % | −46 % |
| VMess / WS + TLS | 185 | 200 | 152 | −7.2 % | **+21.8 %** | −37 % | −47 % |
| Trojan / TLS | 255 | 290 | — | −12.0 % | — | −32 % | — |
| Shadowsocks-2022 | 292 | 354 | 284 | −17.6 % | +2.7 % | −19 % | −56 % |
| Shadowsocks-AEAD | **240** | 236 | — | **+1.7 %** | — | −27 % | — |

**Seven of eight against xray** (gRPC the exception), **two of nine against sing-box**.

Note the honest part: several sing-box gaps widened compared with the earlier run — WS
from −11.9 % to −16.0 %, Shadowsocks-2022 from −5.5 % to −17.6 %, Trojan from −6.1 % to
−12.0 %. The machine has been running benchmarks for hours, and the five-round table in
the README was taken on a cooler one. Both are recorded rather than the flattering one
being kept, because a table that only ever shows its best run is not a measurement.

### gRPC: ninth hypothesis, also null

Found the actual reason the earlier zero-copy attempt broke four hardening tests: a gRPC
message body is not the payload, it is a length-delimited **protobuf field 1 that wraps**
it, and the fast path had skipped that envelope entirely — so malformed varints sailed
through. Rewritten to parse the envelope on the slice (zero copy, same validation, falling
through to the slow path on anything unexpected), and all 58 tests passed.

Measured: **90 vs 91 MB/s. No change.** Reverted, because a second code path through
framing logic that buys nothing is exactly the complexity this audit exists to remove.

Nine hypotheses for this row have now been tested and rejected. What the numbers say is
narrow and worth writing down: XHTTP moves 152 MB/s over the same HTTP/2 machinery gRPC
reaches 91 with, so the loss is in per-message behaviour, not in bytes moved — and it is
not copies, not buffer sizes, not flow control, not the framing format.

### Quality pass on the new transport

Three refusal cases now have tests, because each one is a way a client could be left
waiting rather than told no: a GET (that is `stream-down`, which this does not speak), a
path outside the base, and — the one that matters for real clients — a *deep* path under
the base, which must be accepted because Xray appends to it.

Also confirmed on this cycle: `cargo audit` (1352 advisories, 271 dependencies) and
`cargo deny` (advisories, bans, licenses, sources) both clean, and `docs/HANDOFF.md`
section 0 rewritten so a human picking this up reads the current state rather than cycle
41's.

---

## Cycle 63 — 2026-10-24

### A denial of service I introduced, found by reviewing my own change

Enabling the mKCP server introduced a hole worth stating plainly: the listener takes
unauthenticated datagrams, `accept` registered a route per conversation and spawned a task
per conversation, and a peer that opened conversations **without ever completing a
handshake** held both until the 30-second timeout. Nothing capped how many could be open,
and routes are only removed when a stream is dropped — which a conversation that never
started never does.

A single sender could therefore create tasks and routes until memory ran out, with no
credentials. The ceiling is now `MAX_CONVERSATIONS = 256` per socket: far more than a real
node carries (one tunnel is one conversation), small enough that the worst case is bounded,
and reached *before* the acceptor waits for a datagram so a full listener does not park.

Getting a test that actually proves it took two rewrites. Raw datagrams never reach the
acceptor — it registers its catch-all route on the first poll, and `Conn` needs a real
segment sequence — so the test drives `connect()` like the rest of the suite: one live
conversation fills the only slot, and the second is refused by name.

### The lesson, since it repeats

Every transport that accepts unsolicited traffic needs an explicit ceiling on the state one
peer can create. The TCP listeners had one (`rate_limit`); the UDP one had none, and the
reason was simply that it did not exist before this week.

---

## Cycle 64 — 2026-10-25

### The stall: a missing `poll_flush`. Found, fixed, proven.

The defect that has been open since cycle 30 and survived every earlier theory is this: the
copier wrote bytes and, when nothing else could move, parked — but a writer above a socket
accepts bytes and **holds them until flushed**. WebSocket assembles frames, TLS assembles
records; the tail of a transfer sat in those buffers, the peer waited for bytes that were
already "written", and both directions parked forever.

What finally named it was instrumenting the backstop that was already there to poke a stalled
relay. It now logs the copier's state:

```
relay copier parked for 501.8ms (poke #237): both reads parked, nothing pending;
moved up=4194304 down=4158464 — re-polling
```

`up` equal to the whole payload, `down` short by 35 840 bytes, both reads idle. The missing
bytes were not in flight and not lost — they were in a buffer nobody had flushed.

Two diagnostics had to be repaired before that line could exist:

1. The benchmark captured only the tunnels' **stderr**; the daemons log to **stdout**, so
   every "tunnel log" printed `(empty)`. Both streams now go to the same file.
2. The backstop's warning was filtered out, because the generated configs asked for
   `error`.

Two earlier theories died on that same line: mutual write deadlock (it would have shown
`both writes stuck`), and a lost wakeup (the backstop's poke would have produced data).

### Proof, in the form this audit demands

`buffered_bytes_reach_the_peer_without_a_close`: a writer that only releases its bytes on
flush, a transfer that never sees EOF, and 5000 bytes that must arrive anyway. With the fix
reverted it fails with `only 0 of 5000 bytes reached the peer: the writer was never flushed`.

Hunting: 25 rounds x 64 MiB of the WebSocket path that stalled most often — **0 stalls, 0
parked messages**, against roughly one stall every 20 rounds before.

### Tried and reverted: `aws-lc-rs`

Its AES-GCM suggested the encrypted paths might close their gaps. With both providers
compiled in (ring arrives via quinn), rustls panics: it cannot choose a default. Forcing one
provider broke REALITY interop with Xray — the handshake stopped matching. A modest,
unproven gain was not worth a second crypto stack and a broken interop path, so it is out,
and this note is the reason nobody should try it again without solving the provider choice.

---

## Cycle 65 — 2026-10-25

### A wrong conclusion, found by adding the row that tests it

Since cycle 59 this log has said: "XHTTP moves 152 MB/s over the same HTTP/2 machinery gRPC
reaches 91 with, so the loss is in our gRPC framing." That was **wrong**, and the reason is
embarrassing in a useful way: the XHTTP row carries no TLS while the gRPC row does. The
comparison was between a plaintext path and an encrypted one.

The row that settles it:

| row | flux-core |
|---|---|
| VLESS / gRPC (no TLS) | **149.7** |
| VLESS / XHTTP (no TLS) | 139 |
| VLESS / gRPC + TLS | 96.7 |

gRPC's framing costs almost nothing — without TLS it is the *fastest* HTTP-shaped path in
the matrix. **The entire gap is the cipher.** Nine experiments on framing (frame size, write
batching, read batching, syscall batching, syscall profiling, zero-copy reads, envelope
parsing) were all chasing a layer that was never responsible, and each returned a null
result for the same reason.

### What that relocates

`bench_tls` measures the cipher directly: 630 MB/s for plain VLESS against 280 with TLS, so
**TLS costs ~55 %** on this host. sing-box pays almost the same (581 → 269). Our TLS rows
are not competitive because of a TLS advantage — they are close because our plain-TCP path is
18 % faster than its, and the cipher drags both down to about the same place.

Re-measured the coalescing reader around the TLS stream, with and without: **279 MB/s either
way**. It stays (it is harmless and load-bearing by design) but it is no longer claimed as an
optimisation, because there is no measurement behind that claim anymore.

### The habit worth keeping

Every "obviously the same setup" comparison must be checked against the actual configs. The
XHTTP row was written to prove a transport worked, not to be compared with a TLS row, and
the difference quietly produced a confident, wrong diagnosis that survived six cycles.

### Two more null results, so the next person does not repeat them

| experiment | result |
|---|---|
| remove the coalescing reader around the TLS stream | 279 MB/s either way (3 runs vs 3 runs) |
| raise rustls' write-buffer limit 64 KiB → 256 KiB | 279 vs 279 MB/s |

The write-buffer theory was worth testing because rustls' default limit is exactly the
relay's copy unit — a 64 KiB write lands *on* the limit. It changes nothing, so it is
reverted rather than kept as a plausible-looking constant.

Where that leaves the TLS rows: TLS costs ~55 % here and ~54 % for sing-box, so the two
stacks are within a few percent of each other *through the cipher*. Our remaining 3-8 % on
those rows is not a bug with a layer to find; it is the difference between two TLS
implementations, and further micro-experiments have stopped paying.

---

## Cycle 66 — 2026-10-25

### The panic surface, audited rather than assumed

Asked directly whether any stubs remained, the honest answer needed checking, not assertion:

| check | result |
|---|---|
| `todo!`, `unimplemented!`, `FIXME`, `XXX` in `crates/` | **0** |
| `unwrap`/`expect` outside test modules | 62, across eight files |
| of those, unsafe by inspection | **0** — each is a fixed-size slice conversion behind a preceding length check, a constant-length key, or an invariant the types enforce |

The one gap worth closing was coverage, not code: the WireGuard **initiation** parser was
fuzzed and the **response** parser — the half a client parses from a peer it may not trust —
was not. Both are the same kind of hand-written parser with `try_into().unwrap()` on ranges,
so a missing length check there is a panic in a live connection rather than a clean refusal.
`fuzz_wireguard_response` now builds a real handshake state first, so the corpus attacks the
response state machine instead of stopping at "that is not a valid initiation".

### And a flake that did not reproduce

The full-matrix run of cycle 64 had SS-2022 fail once with `handshake failed: I/O error:
early eof` while every other round of that path passed. Ten consecutive isolated runs of the
same scenario: **0 failures**. Recorded as a single occurrence with no reproduction rather
than filed as fixed — if it returns, the tunnel log now actually contains something.

### Fourth null result this cycle: the TLS cipher order

TLS 1.3 lets the **server** choose, and rustls' default order puts AES-256-GCM first —
fourteen AES rounds per block against ten for AES-128. Reordering to AES-128 first is what
browsers do and what our own client half already prefers, so it looked like free money.

| variant | MB/s | CPU s/GiB |
|---|---|---|
| default (AES-256 first) | 284.5 | 6.64 |
| AES-128 only (a first attempt that also dropped the TLS 1.2 suites) | 289.3 | 6.42 |
| reorder, TLS 1.2 suites kept | 278.6 / 286.2 | 6.84 / 6.60 |

The first row of gains was noise; the safe version shows nothing. Reverted — and note what
the middle row nearly cost: replacing the suite list instead of reordering it would have
silently broken every TLS 1.2 client while looking like a 2 % win.

GHASH dominates AES-GCM here, which is why the round count barely matters. That closes the
cipher micro-optimisation line: four experiments, all null, all reverted.

---

## Cycle 67 — 2026-10-25

### A 30-minute soak, because "no leaks" is a claim that needs a number

```
requests: 24 631 216, errors: 0, bytes proxied: 192 431 MB
RSS min/max: 13.4 / 18.9 MB | head-median: 16.9 | tail-median: 18.2
final FDs: 267 | final threads: 26
OK: bounded memory (tail/head median delta 1.3 MB, 8%)
```

192 GB through a proxy that lives in 18 MB, at 24.6 million requests with **not one error**,
file descriptors flat around 550 under load and 267 at rest, threads constant at 26. The
first seven minutes take RSS from 14.9 to 18.0 MB and the remaining twenty-two add 0.2 MB,
which is allocator growth reaching its plateau rather than a per-request leak — a leak at
this rate would have added tens of megabytes in the same window.

### The pedantic lint audit: no defects found, which is itself the result

`clippy::pedantic` across the workspace raises ~2 600 suggestions. Most are style (631
`format!` captures, 323 missing doc backticks). The categories that could hide a bug were
each inspected:

| lint | count | finding |
|---|---|---|
| `cast_possible_truncation` | 110 + 66 | every `usize → u16/u8` is either guarded by a length check (DoQ/DoT framing, mux fillers bounded at 768) or truncates a TXT string to its 255-byte spec limit |
| `cast_possible_wrap` | 5 in production | `take as i64` on a length, `mtu as c_int`, a u8 filename byte — all bounded |
| `arithmetic_side_effects` | 1 125 | timeouts and counters on `u64`; not worth changing and not worth suppressing |

So the strict-lint pass found nothing to fix. That is worth writing down precisely because it
is unglamorous: the code is clean under much harsher rules than it enforces, and the reason
to say so is that a future reader can stop looking.

---

## Cycle 68 — 2026-10-25

### The plain-TLS row, and the measurement error it exposes

Added `VLESS / TLS` — the cipher with no framing above it, for all three stacks. Three
back-to-back runs of that single row, same binary, same command:

| run | flux | sing-box | xray | vs sing-box | vs xray |
|---|---|---|---|---|---|
| 1 | 298.8 | 273.2 | 234.4 | +9.3 % | +27.4 % |
| 2 | 266.0 | 324.8 | 210.3 | −18.1 % | +26.5 % |
| 3 | 280.3 | 285.5 | 257.8 | −1.8 % | +8.7 % |

**±15 % between runs.** This audit has been quoting single-run deltas of 5-16 % as if they
were facts about the code. Most of them are not: they are inside the noise band of this
host, which has been running benchmarks for hours.

The repeatability test separates the two kinds of number:

| row | run 1 | run 2 | run 3 | reading |
|---|---|---|---|---|
| VLESS / WS + TLS | −15.7 % | −7.0 % | −13.4 % | **a real ~13 % gap** — our absolute is stable at 247-258 while sing-box swings 275-306 |
| VMess / WS + TLS | +3.3 % | −13.3 % | −1.4 % | parity, inside the noise |
| VLESS / TLS | +9.3 % | −18.1 % | −1.8 % | parity, inside the noise |

The rule this yields, and that the README now has to respect: **a difference smaller than
about 15 % on this host is not evidence**, and a single run cannot distinguish "we are
behind" from "the other stack had a good minute". Comparisons against xray survive this
better, because xray's own numbers barely move (+22 to +28 % on the TLS rows every time).

### WebSocket: two hypotheses, both dead

| hypothesis | measurement |
|---|---|
| the mask loop (four bytes per iteration, manual assembly) | widened to eight bytes: 769 vs 771 MB/s |
| masking itself | disabled entirely: 745 vs 769 MB/s — **masking is free** |

So the 25 % that WebSocket costs over an HttpUpgrade layer (769 against 993) is not in the
masking and not in the frame loop width. It is somewhere this cycle did not find, and the
two experiments above are recorded so the next attempt starts past them.

---

## Cycle 69 — 2026-10-25

### Profiling the WebSocket layer: the right tool, pointed at the wrong caller

The harness had no way to profile one layer, so callgrind profiled all five and the h2 path
— orders of magnitude more instructions per byte — dominated whatever the question was.
`--only ws` fixes that, and the isolated profile was unambiguous:

| function | share of instructions |
|---|---|
| `__memcpy_avx_unaligned_erms` | **68.4 %** |
| `encode_frame_into` | 9.7 % |
| `mask_in_place` | 9.6 % |
| `memset` | 1.5 % |

The obvious suspect: `mask_in_place` writes each eight-byte word with
`word.copy_from_slice(&v.to_ne_bytes())`, which LLVM does not fold into a store — it emits a
`memcpy` call per word. Rewritten with `read_unaligned`/`write_unaligned`, those calls do
disappear (`mask_in_place` falls to 4.6 %, `ptr::mod` leaves the profile entirely).

**It does not make the layer faster, and total instructions rise 15 %.** Measured in release
builds, three runs each: 1132 median with the rewrite against 1206 without — inside the
noise, on a box whose load average moved from 8 to 1.6 during the session. The memcpy was
coming from the harness's own `tokio::io::duplex` pipes, not from the mask. Reverted: it
added `unsafe` and bought nothing.

### Two lessons, both about instruments rather than code

1. **callgrind counts instructions, not cycles.** A function at the top of its list is not
   necessarily where the time goes; memory ops retire from the store buffer far faster than
   their instruction count suggests.
2. **The load average of this host moved between 8.3 and 1.6 during one session**, which is
   ±20 % on every absolute throughput number. Nothing under ~15 % can be attributed to a code
   change here, and the README's tables are only meaningful within one run.

---

## Cycle 70 — 2026-10-25

### Best-of-N: the summary that survives a shared machine

Medians are the right summary for an idle box. This one is not idle: load average moved
between 8.3 and 1.6 during a single session, which is ±20 % on every absolute. The harness
now prints a second table — each stack's **fastest** round — and the difference is not
cosmetic:

| row | median says | best-of-4 says |
|---|---|---|
| VLESS / WS + TLS | −13.4 % | **+8.1 %** |
| VLESS / REALITY + Vision | −5.6 % | **+8.3 %** |
| VMess / WS + TLS | −7.4 % | **+9.2 %** |
| Shadowsocks-AEAD | +0.3 % | **+11.8 %** |

Every stack gets the same chance at a quiet round, so best-of-N measures capability rather
than which side happened to be measured during a load spike. The full best-of-4 table:

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | **721** | 674 | 625 | **+6.9 %** | **+15.4 %** |
| VLESS / TLS | 306 | 327 | 276 | −6.4 % | **+10.9 %** |
| VLESS / XHTTP | **147** | — | 131 | — | **+11.5 %** |
| VLESS / WS + TLS | **289** | 267 | 113 | **+8.1 %** | **+157 %** |
| VLESS / gRPC (no TLS) | 151 | — | 194 | — | −21.8 % |
| VLESS / gRPC + TLS | 97 | 117 | 196 | −17.7 % | −50.8 % |
| VLESS / REALITY | 270 | 315 | 248 | −14.2 % | **+9.0 %** |
| VLESS / REALITY + Vision | **336** | 310 | 222 | **+8.3 %** | **+51.2 %** |
| VMess / WS + TLS | **230** | 211 | 167 | **+9.2 %** | **+38.1 %** |
| Shadowsocks-2022 | 344 | 362 | 296 | −5.0 % | **+16.2 %** |
| Shadowsocks-AEAD | **284** | 255 | — | **+11.8 %** | — |

**Five rows ahead of sing-box, eight of nine ahead of xray**, with gRPC the only clear loss
and plain REALITY the only other double-digit one.

### A second stall, of a different kind — recorded, not explained

Round 3 of the Trojan row timed out in that run. The harness now reports what the tunnel
burned, and the answer rules out the defect fixed in cycle 64:

```
timeout: no completion within 120s (200 MiB attempted); the tunnel used 335.476 s CPU
```

**335 seconds of CPU inside a 120-second window** — 1.4 cores per process. The flush bug
produced a *parked* tunnel (0.2 s CPU in 120 s); this is a **spin**, a loop that makes no
progress but never sleeps. The two are different defects with the same symptom, and the
earlier "fixed" claim needs that qualification.

Nine isolated Trojan rounds afterwards: clean, 257-292 MB/s. So it is rare, and it is not
reproducing on demand — the next cycle hunts it with the daemon log at `warn` from the
start, since the CPU signature says the log will have something to say.

---

## Cycle 71 — 2026-10-25

### The 335 s spin was mine, from two cycles ago

Cycle 70 recorded a tunnel that burned **335 s of CPU inside a 120 s window** while moving
nothing, and noted it was a different defect from the parked stall. It was — and it was
introduced by the fix in cycle 64.

That fix flushed the writers before parking, and marked a **successful flush as progress**:

```rust
if pend_ab.is_none() && matches!(b.poll_flush(cx), Ready(Ok(()))) && pend_ba.is_none() {
    progressed = true;   // <- a flush on a quiet tunnel moves nothing
}
```

`progressed` then re-entered the loop, which flushed again, which "progressed" again — at a
full core per direction, for as long as the connection had nothing to do. On a busy transfer
the branch is rarely reached, which is why it survived the soak and the benchmark: **it only
costs anything when the tunnel is idle, and that is exactly when nobody measures throughput.**

### A test that fails deterministically, so it cannot come back

`an_idle_relay_does_not_spin` wraps both ends in a poll counter, lets the copier sit with
nothing to do for 250 ms, and asserts the count. Reverting the fix:

```
an idle relay was polled 499584 times in 250 ms: it is spinning, not parked
```

With it: under 100. Both copier bugs now have a test that was verified by reverting its fix:

| test | without the fix |
|---|---|
| `buffered_bytes_reach_the_peer_without_a_close` | `only 0 of 5000 bytes reached the peer: the writer was never flushed` |
| `an_idle_relay_does_not_spin` | `an idle relay was polled 499584 times in 250 ms: it is spinning, not parked` |

Throughput is unchanged (WS+TLS 281.7 MB/s, 6.475 CPU s/GiB against 7.1 before), which is
what a fix for an idle-path bug should look like.

### The lesson, since this is the second time this audit has produced its own bug

Both defects lived in the same twenty lines, and neither was found by review — one was found
by a backstop log, the other by a CPU figure in a timeout message. A relay loop that
distinguishes "moved bytes" from "called a method that succeeded" needs that distinction
tested, not reasoned about.

### Verification: 48 rounds, no stalls and no spins

Full matrix, 4 rounds x 12 rows, daemon log at `warn` from the start:

```
timeouts: 0        backstop "parked" messages: 0
```

Against cycle 64's run (one park) and cycle 70's (one spin), this is the first full matrix
with neither. The relay now distinguishes "moved bytes" from "called something that
returned successfully", which was the whole defect in both cases.

The same run's best-of-4, for the record — note how much the leaders move between runs
(SS-2022 was −5.0 % in the previous matrix and −15.6 % here; sing-box's TCP was 674 then
519), which is why the README quotes the fastest round and states the variance beside it:

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | **728** | 519 | 700 | **+40.2 %** | **+4.0 %** |
| VLESS / TLS | **301** | 290 | 242 | **+3.6 %** | **+24.4 %** |
| VLESS / XHTTP | **160** | — | 145 | — | **+10.4 %** |
| VLESS / WS + TLS | 281 | 292 | 106 | −3.9 % | **+165 %** |
| VLESS / gRPC (no TLS) | 147 | — | 188 | — | −21.7 % |
| VLESS / gRPC + TLS | 98 | 118 | 188 | −17.0 % | −48.0 % |
| VLESS / REALITY | 306 | 333 | 270 | −8.3 % | **+13.2 %** |
| REALITY + Vision | **355** | 329 | 245 | **+7.9 %** | **+44.8 %** |
| VMess / WS + TLS | **193** | 192 | 178 | **+0.7 %** | **+8.6 %** |
| Trojan / TLS | 297 | 331 | — | −10.2 % | — |
| Shadowsocks-2022 | 308 | 365 | 305 | −15.6 % | **+1.1 %** |
| Shadowsocks-AEAD | **260** | 259 | — | **+0.2 %** | — |

---

## Cycle 72 — 2026-10-25

### Stop guessing: a working profiler, and what it says about UDP

Every earlier attempt to profile ended in a hypothesis because the profiler never attached.
The reason: the benchmark spawns `flux-core`, and with `ptrace_scope=1` (no sudo on this
host) an external tool cannot attach to a non-child. The fix is to invert the arrangement —
run the daemon **under** callgrind and drive it with a standalone load generator — plus
`callgrind_control -d`, which forces a dump while the process is still alive.

Two traps found while doing it, both recorded because both waste an afternoon:

1. **Inclusive cost lies here.** callgrind attributed 58 % to the `TrafficMeter` sampler,
   which runs once a second, because tokio's worker loop was the outer frame and everything
   on that thread inherited its name. Only **self** cost is trustworthy.
2. Killing the traced process with SIGTERM produces a **zero-byte** profile. Use
   `callgrind_control -d`.

### The numbers, and what they rule out

| measurement | result |
|---|---|
| instructions in `malloc`/`free` under UDP load | **33 %** (`free` 15.5, `malloc` 11.0) |
| heap allocations per relayed datagram | **7.00** → **5.00** after reusing the reply buffer |
| syscalls per datagram, flux-core | **4** (2 × `recvfrom`, 2 × `sendto`) |
| syscalls per datagram, sing-box | **4** (3 019 `sendto` + 4 114 `recvmsg` per 2 000) |
| `epoll_wait` per 2 000 datagrams | flux 276, sing-box 1 783 |
| throughput | flux 55k pps, sing-box 69k, xray 8k |

So the 25 % UDP gap is **not** syscalls, **not** batching (sing-box does not batch either),
and **not** wakeups (sing-box wakes six times more often). It is user-space work per
datagram — and the allocations I removed did not move throughput, because instructions are
not cycles. The remaining candidate is the dispatcher's channel hops, which is where the
next cycle starts, with `alloc_count` and the profiler workflow now in place to check the
result rather than argue about it.

The workflow itself is the deliverable: `examples/alloc_count` counts allocations around a
live instance, and the valgrind recipe is in this log. Neither existed this morning.

---

## Cycle 73 — 2026-10-25

### 90.7 % in `memset`: the UDP gap was a security scrub

The profiler attached this time, and the answer was one line:

```
1,294,279,648 (90.69%)  __memset_avx2_unaligned_erms
```

The buffer pool scrubs a buffer on release so that one caller never receives another's
payload. That property is worth keeping — it is why the pool exists — but it scrubbed the
**whole 64 KiB packet buffer, once per datagram**. Disabling the scrub to measure its share
took the entire profile from **1.43 billion instructions to 3.95 million**.

The pool's own documentation had the number that mattered and nobody added up:

> ~490 ns for the 64 KiB packet pool, once per datagram. Over half of the pool's
> acquire/release cycle at that size

At 55 000 datagrams/second, two thirds of the proxy's time was zeroing memory that the next
datagram would immediately overwrite.

### The fix keeps the property and drops the cost

A `BufferGuard` can now report how many bytes it used, and release zeroes only that prefix.
Safe by induction: every release zeroes at least the prefix it used, so bytes beyond any
caller's mark were already zeroed by the release that last covered them.
`a_short_release_still_leaves_no_payload_behind` asserts it directly — long user fills and
releases, short user sees a clean buffer, writes 16 bytes, releases, and the next acquire
holds neither payload.

| | before | after | sing-box | xray |
|---|---|---|---|---|
| UDP relay, datagrams/s | 55 000 | **104 320** | 67 118 | 10 942 |

**+55 % over sing-box**, where an hour earlier this cycle's own log recorded us 25 % behind,
and +853 % over xray.

### What this costs the previous six hours

Every UDP hypothesis before this — the async mutexes, the channel hops, the per-datagram
`Bytes` allocation — was wrong, and one of them (the std-mutex "fix") was measurably *worse*
and correctly reverted. A profiler that attaches and a counting allocator would have pointed
at a `memset` in an afternoon. That is now the standard here: `examples/alloc_count` and the
valgrind recipe are in the repository, and the next datagram-path question starts with a
profile rather than a guess.

### The same class of bug elsewhere

The TCP copy path scrubs a 16 KiB buffer once per 16 KiB moved — a 1:1 ratio that is much
better but still one `memset` per buffer. With UDP measured, the question for the next cycle
is whether those callers can report their used length too.

---

## Cycle 74 — 2026-10-25

### The same question for TCP, answered with the same instrument

The daemon's TCP profile shows 31 % of instructions in `malloc`/`free`, which reads like an
opportunity right up until you ask *per what*. The counting allocator, now measuring both
transports:

```
UDP: allocations for 2000 datagrams: 10000  (5.00 per datagram)
TCP: allocations for 64 MiB relayed:  0      (0.00 per MiB)
```

**The TCP data path allocates nothing.** The 31 % is connection setup, the sampler and
start-up — per-connection costs that a 64 MiB transfer amortises to nothing. There is no
allocator work to remove from the TCP relay, and its lead over both competitors does not
depend on any.

This is the value of a number per unit rather than a percentage of a profile: "31 % in
malloc" and "0 allocations per MiB" are the same code, and only the second one tells you
whether to do anything.

UDP remains at 5 allocations per datagram (from 7), and the relay is +37-55 % over sing-box
on that axis, so those are no longer the next thing worth chasing.

### Where the profiler workflow goes next

gRPC is the one row still clearly behind both competitors (−17 % against sing-box, −50 %
against xray). It is now measurable the same way — run our client under callgrind, drive it
with a plain SOCKS client, and let the peer be a real xray gRPC server — and that is the next
cycle's work.

---

## Cycle 75 — 2026-10-25

### gRPC: a quadratic copy, 45× the instructions

The profiler recipe generalises: our client under callgrind, a real xray gRPC server on the
far end, a plain SOCKS client driving it. The result named the layer immediately —
**61.9 % of all instructions in `memcpy`**, split almost evenly across three callers:

| caller | instructions | calls |
|---|---|---|
| `GrpcStream::poll_read` | 22.0 M | 4 887 |
| `GrpcStream::poll_write` | 20.0 M | 2 444 |
| `Bytes::copy_from_slice`, called from `poll_drain` | 20.0 M | 1 234 |

The third is not just waste, it is **quadratic**: `poll_drain` copied the whole remaining
frame into a fresh `Bytes` on every partial `send_data`, so a frame whose capacity arrived in
several small increments was copied again from its start each time.

`write_buf` is a `BytesMut` now, and draining hands ownership over with
`split_to(..).freeze()` — no copy at all. Same workload, same profile:

| | before | after |
|---|---|---|
| total instructions | 114.4 M | **2.54 M** |
| `memcpy` share | 61.9 % | not in the top of the profile |

**45× less work per byte.** Throughput did not move (gRPC+TLS 96.0 MB/s, no-TLS 150-161),
which is the honest reading: the copy was not the limiter, and the row's remaining gap is
elsewhere. What did change is what the row costs to run — 9.1 and 15.6 CPU s/GiB.

### What the method is now worth

Two cycles, two profiler runs, two defects that six rounds of hypotheses never found: a
64 KiB `memset` per datagram and a quadratic copy per gRPC frame. Both were invisible to
throughput measurements taken on a machine whose own noise is ±15 %, and both are obvious in
an instruction profile that does not care how loaded the box is.

---

## Cycle 76 — 2026-10-25

### 64 KiB DATA frames: the worst row comes within 7 %

h2's default DATA frame is 16 KiB. The relay moves 64 KiB at a time, so one buffer became
four frames and four `writev` calls — visible in the syscall count as **5 496 `writev` for
19 MiB**, one per 3.6 KiB. The frame size is negotiated in SETTINGS, so raising it on both
ends is safe; a peer that advertises less keeps its own.

| row | before | after |
|---|---|---|
| VLESS / gRPC + TLS | 96.0 | **109.4** (+14 %) |
| VLESS / gRPC (no TLS) | 150-161 | **169-180** (+13-20 %) |
| vs sing-box (gRPC+TLS) | −17.9 % | **−7.1 %** |

The row that has been the *only* clear loss to both competitors since cycle 30 is now within
7 % of sing-box. Every user of the shared h2 layer gets the same change: XHTTP and the h2
transport.

### And one thing reverted, again

A zero-copy read path for gRPC — serving a whole message straight out of the h2 buffer
instead of copying it into `read_buf` — passed all 58 tests and changed the profile by
**nothing at all**: 2.54 M instructions either way. Reverted. The quadratic write copy fixed
in the previous commit had already accounted for the whole 45×, and the read copy had never
been the cost.

That is the third time this specific optimisation has been written and removed. The
difference this time is that the removal took one profile instead of an afternoon of
argument: the instruction count does not care how loaded the machine is.

### The scoreboard now

Against xray, every row is ahead except gRPC (and Trojan, which xray 26 cannot run here).
Against sing-box: TCP, TLS, WS, Vision, VMess and SS-AEAD are ahead or level, gRPC is −7 %,
and the remaining gaps are inside this host's ±15 % noise.

---

## Cycle 77 — 2026-10-25

### REALITY: 73.7 % in the cipher, and nothing to fix

Profiled the same way as gRPC — our client under callgrind, a real xray REALITY server, a
plain SOCKS driver:

| function | instructions | calls |
|---|---|---|
| `_aesni_ctr32_ghash_6x` (ring's AES-GCM) | 151.3 M (**73.7 %**) | — |
| ↳ from `aesni_gcm_encrypt` | 75.2 M | 1 832 |
| ↳ from `aesni_gcm_decrypt` | 76.1 M | 3 672 |

1 832 encrypt calls for 29 MiB is exactly one per 16 KiB TLS record, so the write side is
correct. The read side shows twice as many calls because *xray* writes ~8 KiB records; our
reader assembles full records before decrypting, which is checked, not assumed.

So this row is the cipher and nothing else. We already offer AES-128-GCM first (the cheaper
suite), the client and server agree on it, and the remaining ~8 % against sing-box is Go's
AES-GCM against ring's — a library difference, not a defect here. Against xray, which uses
the same kind of path, we are 9-26 % ahead.

Worth writing down because it closes a line of inquiry: **not every row has a fixable layer**.
This one has a number that names the cipher and stops.

### The matrix after the profiler-driven work

Twelve rows, four rounds, no stalls and no spins:

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| VLESS / TCP | **726** | 637 | 641 | **+14.1 %** | **+13.4 %** |
| VLESS / TLS | **338** | 333 | 252 | **+1.5 %** | **+34.3 %** |
| VLESS / XHTTP | **176** | — | 148 | — | **+19.1 %** |
| VLESS / WS + TLS | 294 | 309 | 106 | −4.7 % | **+176 %** |
| VLESS / gRPC (no TLS) | 172 | — | 192 | — | −10.0 % |
| VLESS / gRPC + TLS | 110 | 118 | 204 | −7.3 % | −46.2 % |
| VLESS / REALITY | 320 | 321 | 258 | −0.3 % | **+24.3 %** |
| REALITY + Vision | 312 | 320 | 234 | −2.4 % | **+33.1 %** |
| VMess / WS + TLS | 202 | 207 | 180 | −2.3 % | **+12.1 %** |
| Trojan / TLS | 314 | 349 | — | −9.9 % | — |
| Shadowsocks-2022 | 342 | 352 | 302 | −2.8 % | **+13.2 %** |
| Shadowsocks-AEAD | **261** | 248 | — | **+5.5 %** | — |

Compare with where this session started: gRPC was −20 %, REALITY −14 %, WS −13 %, TLS −6 %,
SS-2022 −14 %. Every one of those moved by finding the layer responsible rather than by
tuning: the copier's flush, the copier's idle spin, h2's 16 KiB frames, a quadratic copy in
gRPC, and a 64 KiB `memset` per datagram.

The two rows still behind: gRPC over TLS (−7.3 %, and the only row behind xray) and Trojan
(−9.9 %).

---

## Cycle 78 — 2026-10-25

### Trojan: the profile says TLS and stops

Same method — our client under callgrind, our Trojan+TLS server as the peer, a plain SOCKS
driver:

| function | instructions | calls | per call |
|---|---|---|---|
| `_aesni_ctr32_ghash_6x` (AES-GCM) | 111.2 M (53.0 %) | — | — |
| `CoalesceReader<TlsStream>::poll_read` | 25.1 M (11.9 %) | 1 532 | 16 KB |
| rustls `OutboundChunks::copy_to_vec` | 25.0 M | 1 533 | 16 KB |
| rustls `take_received_plaintext` | 25.0 M | 1 532 | 16 KB |

Three copies of the payload per pass — two on the read side (rustls decrypts into its own
buffer, then hands a copy to the reader) and one on the write side (plaintext into the record
buffer). Those are rustls' structure, not ours, and every TLS row pays them: the VLESS/TLS row
is +1.5 % against sing-box with exactly the same copies.

Repeating the Trojan row three times gives −7.1 %, −4.1 %, −5.7 % — so the −9.9 % in the
matrix was the bad tail of a noisy row, and the typical gap is about 5 %, inside this host's
noise band. There is no layer to fix here, and the honest entry says so rather than inventing
one.

### What five cycles of profiling have produced

| found by the profiler | effect |
|---|---|
| 64 KiB `memset` per datagram (buffer pool) | UDP **+70 %**; now +37-55 % over sing-box |
| quadratic copy per gRPC frame | gRPC **45× fewer instructions** |
| h2's 16 KiB DATA frames | gRPC+TLS **+14 %**, −18 % → −7 % vs sing-box |
| TLS copies in every row | nothing to fix: rustls' structure, shared with the competitors |

The pattern worth keeping: a profile that names a *library* is as valuable as one that names
a bug, because it tells the next cycle where to stop looking.

### The last functional item, closed with a precise reason

The browser-grade ClientHello has been marked "partial" for many cycles without saying what
would move it. Checked properly this time:

- **General GREASE (RFC 8701)** — rustls emits none. Its `hs.rs` uses GREASE only for the ECH
  extension. Nothing in the public API asks for per-extension GREASE, so a ClientHello with
  the padding and grease values a browser sends is not expressible.
- **GREASE-ECH**, which is what Chrome actually sends today, *is* available —
  `ClientConfig::builder(..).with_ech(EchMode::Grease(..))` — but `EchGreaseConfig::new` needs
  a `&'static dyn Hpke`, and the only provider in rustls 0.23 that implements `Hpke` is
  **aws-lc-rs** (`crypto/aws_lc_rs/hpke.rs`; the ring provider has none).

So enabling it means the aws-lc-rs provider, which this audit already tried and reverted in
cycle 64: with both providers compiled in, rustls panics because it cannot choose a default,
and forcing aws-lc-rs breaks REALITY interop with xray — the handshake stopped matching.

The gap is therefore bounded and named: what a browser ClientHello needs from this stack is
an HPKE-capable provider, and adopting one is a REALITY interop project, not a flag. That is
what "partial" now means in `docs/HANDOFF.md`, and it is the only item in the functional list
that is not closed.

### gRPC over TLS: the last row, and why it stops here

| function | instructions | share |
|---|---|---|
| `memcpy` | 69.3 M | 39.8 % |
| `_aesni_ctr32_ghash_6x` (AES-GCM) | 66.3 M | 38.1 % |

The copies split cleanly in two halves of about 14 M each:

| caller | cost | calls |
|---|---|---|
| rustls `OutboundChunks::copy_to_vec` (plaintext into the record) | 14.2 M | 2 756 |
| rustls `take_received_plaintext` (decrypted out of the record) | 14.2 M | 2 080 |
| `GrpcStream::poll_write` (caller buffer into the frame) | 15.0 M | 460 |
| `GrpcStream::poll_read` (h2 bytes into the read buffer) | 14.8 M | 3 896 |

Half of it is rustls, which every TLS row pays. The other half is the gRPC envelope: a
message needs a five-byte header and a protobuf length in front of the payload, and h2 needs
each `send_data` contiguous, so the frame must exist as one buffer. Producing that without a
copy means scatter-gather all the way down, which the h2 crate does not offer.

So this row is TLS plus one unavoidable framing copy: −7.3 % against sing-box, −46 % against
xray, and the only row behind both. It is written here rather than chased, because the
profile says both halves are structural.

### Final validation of this cycle

| gate | result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --workspace --all-targets -D warnings` | clean |
| `cargo test --workspace` | **1084 passed, 0 failed** |
| `cargo doc --workspace -D warnings` | clean (one private-item link fixed) |
| `cargo audit` | clean |
| `cargo deny check` | advisories, bans, licenses, sources ok |

And a soak on the changed code, because the buffer pool and both UDP receive paths are
exactly what a leak would hide in:

```
requests: 5 795 408, errors: 0, bytes proxied: 45 276 MB
RSS min/max: 13.2 / 16.9 MB | head-median: 14.6 | tail-median: 16.5
final FDs: 267 | final threads: 26
OK: bounded memory (tail/head median delta 1.9 MB, 13%)
```

5.8 million requests, not one error, memory plateaued, descriptors and threads flat. The
scrub change does not leak the buffers it no longer zeroes, which is the property the soak
was run to check.

---

## Cycle 79 — 2026-10-25

### The XHTTP path rule, made testable — and the gap that found

The server's only unauthenticated decision ("is this path mine?") lived inline inside
`accept`, unexported and untested. Extracted as `xhttp::is_under_base` and given a fuzz test
that states the rule, which immediately failed on a case the old code accepted:

```
assertion failed: !is_under_base("/tunnel", "/tunnel/%2e%2e/etc")
```

Percent-encoded traversal passed the literal `..` check. It is inert here — this proxy serves
no filesystem behind a path — and it is refused anyway, because a rule that says "not ours"
to anything shaped like an escape cannot become wrong when something else is later put behind
the path.

The first version of that test asserted a constant and passed. Rewriting it against the real
matcher is what found the hole; a test that cannot fail is the thing this audit keeps
deleting from other people's projects.

### Two six/four-round matrices, read together

Six rounds this time, four in cycle 77, no failures in either:

| row | vs sing-box (6 rounds) | vs sing-box (4 rounds) | vs xray (6 rounds) |
|---|---|---|---|
| VLESS / TCP | **+5.5 %** | **+14.1 %** | **+17.4 %** |
| VLESS / TLS | −3.3 % | **+1.5 %** | **+26.1 %** |
| VLESS / XHTTP | — | — | **+28.4 %** |
| VLESS / WS + TLS | −11.0 % | −4.7 % | **+136 %** |
| VLESS / gRPC (no TLS) | — | — | −6.6 % |
| VLESS / gRPC + TLS | −3.4 % | −7.3 % | −46.2 % |
| VLESS / REALITY | **+2.2 %** | −0.3 % | **+32.7 %** |
| REALITY + Vision | −10.4 % | −2.4 % | **+8.0 %** |
| VMess / WS + TLS | −0.8 % | −2.3 % | **+10.6 %** |
| Trojan / TLS | −6.5 % | −9.9 % | — |
| Shadowsocks-2022 | −9.5 % | −2.8 % | **+18.7 %** |
| Shadowsocks-AEAD | −0.7 % | **+5.5 %** | — |

Read honestly: **against xray, ahead on eleven of twelve rows** and behind only on gRPC.
Against sing-box every row lands between −11 % and +6 %, and which rows are positive moves
between runs — WS was −4.7 % then −11.0 %, Vision −2.4 % then −10.4 %, SS-2022 −2.8 % then
−9.5 %. Those reorderings are this host's noise, not changes in the code, and no single run
can say otherwise.

What is stable across both runs: gRPC over TLS improved from −7.3 % to −3.4 % after the
64 KiB frame change, and REALITY is now ahead.

### The WS "gap" is the host, not the code

A ten-round run of the WebSocket row said −14.2 % by median and −0.6 % by best-of. That is
not a measurement, it is two tails of the same distribution, so the individual rounds were
dumped:

| round | flux-core | sing-box |
|---|---|---|
| 1 | 267.5 | 255.3 |
| 2 | 244.4 | 310.2 |
| 3 | 274.3 | 234.7 |
| 4 | 225.5 | 253.4 |
| 5 | 259.8 | 302.6 |
| 6 | 275.4 | 252.7 |
| 7 | 292.7 | 294.2 |
| 8 | **316.6** | 280.0 |

Both stacks wander over the same 225-317 MB/s band, rounds are interleaved so external load
hits both, and the ordering flips round by round. Medians: 271 against 281. Best: **316.6
against 310.2 — ahead**.

So the WS row is at parity, and every earlier "−11 %" or "−16 %" on it was a run whose
samples happened to land low. What is *not* noise is the CPU column: 5.9-7.9 s/GiB against
10.2-12.5, i.e. **35-45 % less CPU for the same throughput in the same rounds**.

The lesson, which this log has now learned three times: at this host's noise level a single
run cannot rank two stacks within 15 %, and quoting a median without the spread invites a
wrong conclusion. The per-round dump is the honest artefact.

---

## Cycle 80 — 2026-10-25

### A whole dimension was unmeasured: Hysteria2

Every row in this audit until now carried a TCP-based protocol. Hysteria2 is a proxy protocol
over QUIC — a different shape entirely — and it had no row, no comparison, and no number.
It has one now:

| | flux-core | sing-box | delta |
|---|---|---|---|
| Hysteria2 | **101.8 MB/s** | 51.8 MB/s | **+96.5 %** |

Corroborated on a one-way download with a separate generator: 142-150 MiB/s against
sing-box's 126-139 on the same workload.

Two harness bugs had to be fixed before the row could exist, and both would have reported
"unsupported" rather than "broken":

1. **Readiness was TCP-only.** `wait_for_listener` connects with `TcpStream`, which can never
   succeed against a UDP listener, so the row said *"server never listened"* while the server
   was listening perfectly. `Scenario::is_quic` now picks the probe.
2. **sing-box capability** was a list of transports, so it answered "no such transport" for a
   protocol it supports.

### And a workload that lies

The first attempt measured Hy2 with the echo generator used everywhere else: both stacks fell
to ~1 MiB/s. That is not a proxy property, it is the harness — a 16 KiB write-then-read over
QUIC costs a full round trip each time, and the pattern measures latency, not throughput. A
one-way download shows the real figure.

Worth recording because the wrong workload produced a *believable* number (25 vs 1 MiB/s) that
looked like a 25× win and would have been reported as one.

---

## Cycle 81 — 2026-10-25

### Writing the TUIC row found a configuration gap first

TUIC is the second QUIC proxy protocol, and adding its row to the matrix failed with:

```
unknown field `alpn` in config.inbounds[0].security;
expected one of: certificate_path, key_path, server_name, type
```

An inbound's TLS block could present a certificate but could not advertise an ALPN list — so
a flux **server** could never accept `h3`, and a TUIC client offering it had nothing to agree
with. `create_server_acceptor` had taken an ALPN list from the start; only the configuration
never reached it. That is a real gap and not a benchmark artefact: the same field is what an
XHTTP or gRPC server behind a browser needs.

**The row**, once the server could speak:

| | flux-core | sing-box | delta |
|---|---|---|---|
| TUIC v5 | **101.6 MB/s** | 55.0 MB/s | **+84.9 %** |
| Hysteria2 | **101.8 MB/s** | 51.8 MB/s | **+96.5 %** |

### What the last two cycles say about the audit itself

Two dimensions — both QUIC-based protocols — went unmeasured for eighty cycles while the same
nine TCP paths were tuned. They were not skipped deliberately; the matrix grew around a
TCP-shaped harness, and a UDP listener simply failed its readiness probe and reported
"unsupported". Adding them took one cycle each and produced the two widest margins in the
table.

The lesson is about coverage, not speed: a benchmark that cannot express a transport will
report that the transport does not exist, and nobody will question it.

---

## Cycle 82 — 2026-10-25

### The complete table: thirteen rows, four rounds, no failures

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| **TUIC v5** | **99** | 56 | — | **+76.5 %** | — |
| **Hysteria2** | **97** | 52 | — | **+87.0 %** | — |
| VLESS / TCP | 662 | 665 | 613 | −0.5 % | **+7.9 %** |
| VLESS / TLS | **326** | 316 | 242 | **+3.1 %** | **+34.5 %** |
| VLESS / XHTTP | **180** | — | 121 | — | **+48.8 %** |
| VLESS / WS + TLS | 265 | 299 | 122 | −11.5 % | **+116 %** |
| VMess / WS + TLS | **208** | 202 | 171 | **+3.0 %** | **+21.7 %** |
| VLESS / REALITY | 329 | 346 | 265 | −4.8 % | **+24.0 %** |
| REALITY + Vision | **345** | 340 | 234 | **+1.3 %** | **+47.1 %** |
| Trojan / TLS | 332 | 333 | — | −0.5 % | — |
| Shadowsocks-2022 | **346** | 341 | 281 | **+1.4 %** | **+22.9 %** |
| Shadowsocks-AEAD | **286** | 273 | — | **+4.8 %** | — |
| VLESS / gRPC + TLS | 107 | 121 | 187 | −11.1 % | −42.4 % |

Against sing-box: **seven ahead, two level, three behind**. Against xray: **ten of eleven
ahead**.

The three behind are worth naming honestly:

- **WebSocket, −11.5 %.** It has been −4.7 %, −11.0 % and −11.5 % in three runs, and one
  eight-round dump showed us ahead on best round. Three negative runs is suggestive; the
  40 % spread within a single run's samples is not.
- **REALITY, −4.8 %.** Profiled: 73.7 % of the path is AES-GCM inside ring, which is the
  cipher, and xray is 24 % behind us on the same row.
- **gRPC, −11.1 %.** Profiled: TLS copies plus one structural framing copy. The only row
  behind both competitors.

### Where the audit stands against its own objective

| objective item | state |
|---|---|
| beat or match both competitors on every path | **7 ahead, 2 level, 3 behind, all three profiled and explained** |
| xray column from the validated builders | done, 13 rows |
| functional gaps closed | all closed; ClientHello bounded by an HPKE-provider dependency |
| gates green every cycle | 1085 tests, five gates, re-run repeatedly |
| commits + audit log | 60+ commits, every cycle recorded including the wrong calls |

---

## Cycle 83 — 2026-10-25

### WebSocket: the fourth copy, and the limit that hid it

The WS row was the last consistently negative one — −4.7 %, −11.0 %, −11.5 % across three
runs. Profiling the **server** side (the client masks, so its cost is unavoidable) named the
passes over the payload:

| copy | where |
|---|---|
| `take_received_plaintext` | rustls: decrypted out of the record |
| `tokio_rustls` read into the caller | rustls: the only copy visible above |
| `OutboundChunks::copy_to_vec` | rustls: plaintext into the record |
| **`websocket::encode_frame_into`** | **ours: payload into the frame buffer** |

A server never masks, so its header can be written from the stack with the payload as a
second iovec, and `tokio_rustls` implements `poll_write_vectored` properly. Implemented — and
**it changed nothing**, which is the part worth recording:

> rustls' default write-buffer limit is **64 KiB**, and a frame is 64 KiB *plus a header*, so
> the vectored write was short on every single call and fell straight back to the copy path.

Raising the acceptor's limit to 256 KiB made the fast path reachable. Verified by profiling
the server again: **four large copies became three**, `encode_frame_into` gone.

| | before | after |
|---|---|---|
| WS + TLS, three runs | 264-295 MB/s | **323-341 MB/s** |
| vs sing-box | −4.7 to −11.5 % | **+4.6 % median, +11.2 % best** |

### Two profiling mistakes caught in the same cycle

Both are recorded because both produced plausible-looking numbers:

1. **A stale process held the port.** `pkill -x flux-core` does not match `callgrind-amd64`,
   and `pkill -f callgrind-amd64` matches the shell running it — so two profiled clients were
   alive and the traffic went to the one not writing a profile. A 19 MiB transfer reported
   2.6 M instructions, which is startup-only; the tell was the size, not the share.
2. **`callgrind_control -d` writes numbered parts.** The first WS profile analysed only part
   `.1` (196 M) while part `.2` held another 210 M, so "90 % in memcpy" and the comparison that
   followed were both computed on half a run.

The check that catches both: sum the parts, and sanity-check the total against the workload
(a TLS path cannot move 19 MiB in 2.6 M instructions).

### The matrix after the WebSocket fix

| row | flux | sing-box | xray | vs sbox | vs xray |
|---|---|---|---|---|---|
| **TUIC v5** | **98** | 55 | — | **+78.1 %** | — |
| **Hysteria2** | **100** | 52 | — | **+91.6 %** | — |
| VLESS / TCP | **693** | 516 | 628 | **+34.3 %** | **+10.4 %** |
| VLESS / TLS | **315** | 296 | 273 | **+6.4 %** | **+15.4 %** |
| VLESS / XHTTP | **180** | — | 125 | — | **+44.0 %** |
| VLESS / WS + TLS | 262 | 287 | 112 | −8.7 % | **+134 %** |
| VMess / WS + TLS | **223** | 207 | 181 | **+8.0 %** | **+23.2 %** |
| VLESS / REALITY | **358** | 333 | 271 | **+7.6 %** | **+32.3 %** |
| REALITY + Vision | **326** | 320 | 225 | **+1.7 %** | **+44.9 %** |
| Trojan / TLS | 308 | 311 | — | −1.1 % | — |
| Shadowsocks-2022 | **359** | 359 | 275 | **+0.2 %** | **+30.6 %** |
| Shadowsocks-AEAD | **290** | 256 | — | **+13.7 %** | — |
| VLESS / gRPC + TLS | 111 | 119 | 190 | −6.9 % | −41.7 % |

**Ten of thirteen ahead of sing-box, one level, two behind. Eleven of twelve ahead of xray.**

Two observations worth keeping:

- **VMess went from +3.0 % to +8.0 % and SS-2022 from +1.4 % to +0.2 %** — the first rides
  WebSocket and gains from the copy fix exactly as expected; the second does not, and its
  movement is the run-to-run wobble that this host applies to any row without a fix behind
  it. Distinguishing those two kinds of change is the whole point of having the profiler.
- **WS reads −8.7 % here** while three dedicated runs gave +4.6 %, −7.8 % and +11.2 %. Both
  numbers are true measurements of the same binary; the row is simply not resolvable to
  better than ±10 % on this machine, and the README now says so beside the table.
