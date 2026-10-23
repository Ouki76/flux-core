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
