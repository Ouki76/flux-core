# The head-to-head tunnel matrix: flux-core vs sing-box

Every encrypted-protocol number this project published before now was measured
against **itself** — `bench_native`, `bench_tls` and `bench_layers` all put one
flux-core tunnel on both ends. That proves the code works; it says nothing about
whether it is competitive. The only number ever measured against a rival was the
plain TCP relay (2622 vs 2300 MB/s), which is the one path where no crypto or
framing is involved.

`examples/bench_matrix.rs` closes that gap: for each supported protocol/transport
pair it runs **the same workload through two self-contained tunnels** — a
flux-core client → flux-core server, and a sing-box client → sing-box server — and
prints one table of throughput and CPU cost per gigabyte.

```
harness ──SOCKS5──> client proxy ══tunnel══> server proxy ──> echo server
                                                   (and back)
```

Measured at `7e938a6`, 16-core desktop, `flux-core 1.3.4` vs `sing-box 1.11.4`
(xray 26.3.27 is installed but is not part of this matrix).

## The table as printed

```
$ cargo run --release --example bench_matrix -- --rounds 5 --mb 200

flux-core  : flux-core 1.3.4  (./target/release/flux-core)
sing-box   : sing-box version 1.11.4  (/home/ouki/.local/bin/sing-box)
echo server: 127.0.0.1:43051 (in this process; not charged to either stack)
TLS decoy  : 127.0.0.1:34269 (REALITY certificate source)
workload   : 200 MiB payload per round, 5 round(s), fresh tunnel connection per round

========================================================================================================================================
TUNNEL THROUGHPUT MATRIX — loopback, 200 MiB payload per round, 5 interleaved round(s), 1 stream
MB/s = MiB/s of payload for a FRESH tunnel connection (setup included); bulk excludes the tunnel setup
========================================================================================================================================
Protocol / transport                 Stack       MB/s e2e       min       max MB/s bulk  setup ms CPU s/GiB   n  status
----------------------------------------------------------------------------------------------------------------------------------------
VLESS / TCP                          flux-core     1068.4    1011.8    1137.9    1070.1       0.3     1.199   5  ok
                                     sing-box      1181.0    1118.6    1223.8    1183.7       0.4     1.733   5  ok
VLESS / WS + TLS                     flux-core      420.1     406.0     433.7     420.7       0.7     4.731   5  ok
                                     sing-box       688.4     675.5     731.0     691.1       1.1     3.370   5  ok
VLESS / gRPC + TLS                   flux-core      305.9     297.2     323.4     306.1       0.7     8.091   5  ok
                                     sing-box       324.5     321.2     332.7     324.6       0.3    10.119   5  ok
VLESS / REALITY                      flux-core       37.3      36.9      37.4     561.3    5002.0     3.365   5  ok
                                     sing-box       793.8     604.5     814.6     797.8       1.4     2.905   5  ok
VLESS / REALITY + Vision             flux-core       34.3      34.0      34.5     242.8    5002.6     8.488   5  ok
                                     sing-box       750.5     703.8     777.8     755.7       1.7     2.852   5  ok
VMess / WS + TLS                     flux-core      338.4     324.7     346.9     338.8       0.6     5.770   5  ok
                                     sing-box       523.9     454.4     576.5     525.5       1.2     5.158   5  ok
Trojan / TLS                         flux-core      785.4     750.4     809.8     787.4       0.6     2.159   5  ok
                                     sing-box       734.2     698.7     748.5     737.2       1.2     3.089   5  ok
Shadowsocks-2022 / blake3-aes-128-gcm flux-core      487.7     448.1     514.4     488.1       0.3     3.954   5  ok
                                     sing-box       899.0     831.8     913.3     900.5       0.4     2.600   5  ok
Shadowsocks-AEAD / aes-256-gcm       flux-core      433.4     396.8     452.9     433.7       0.3     4.457   5  ok
                                     sing-box       503.8     492.5     519.4     504.4       0.5     3.660   5  ok
----------------------------------------------------------------------------------------------------------------------------------------

PAIRWISE SUMMARY (medians; flux-core relative to sing-box)
--------------------------------------------------------------------------------------------------------
Protocol / transport                    flux bulk  sbox bulk  throughput  CPU ratio  setup flux/sbox
--------------------------------------------------------------------------------------------------------
VLESS / TCP                                1070.1     1183.7       -9.6%     -30.8%     0.3 / 0.4 ms
VLESS / WS + TLS                            420.7      691.1      -39.1%     +40.4%     0.7 / 1.1 ms
VLESS / gRPC + TLS                          306.1      324.6       -5.7%     -20.0%     0.7 / 0.3 ms
VLESS / REALITY                             561.3      797.8      -29.6%     +15.8%  5002.0 / 1.4 ms
VLESS / REALITY + Vision                    242.8      755.7      -67.9%    +197.7%  5002.6 / 1.7 ms
VMess / WS + TLS                            338.8      525.5      -35.5%     +11.9%     0.6 / 1.2 ms
Trojan / TLS                                787.4      737.2       +6.8%     -30.1%     0.6 / 1.2 ms
Shadowsocks-2022 / blake3-aes-128-gcm       488.1      900.5      -45.8%     +52.1%     0.3 / 0.4 ms
Shadowsocks-AEAD / aes-256-gcm              433.7      504.4      -14.0%     +21.8%     0.3 / 0.5 ms
--------------------------------------------------------------------------------------------------------
```

`MB/s` is MiB/s of payload counted once (200 MiB in, 200 MiB back out). `CPU s/GiB`
is the CPU burned by the **two tunnel processes** ("MB/s bulk" excludes the
connection-setup phase, "setup ms" is that phase on its own). Per-round samples
are printed above the table.

## Which pairs work

All nine run. Every pair below was driven through both stacks, with a real
handshake, a 200 MiB echo and a byte-exact byte count:

| pair | works | note |
|---|---|---|
| VLESS over TCP (plain) | yes | the baseline; closest to parity (−9.6 %), CPU −31 % |
| VLESS over WebSocket + TLS | yes | −39 %; the largest transport-shaped gap |
| VLESS over gRPC + TLS | yes | −5.7 % on throughput and −20 % CPU: gRPC is bounded by HTTP/2 flow control for **both** stacks, which flattens the difference |
| VLESS + REALITY, Vision off | yes | bulk −29.6 %; plus a **5 s per-connection setup defect** (below) |
| VLESS + REALITY, Vision on | yes | bulk −68 %, CPU +198 %: Vision costs flux 2.3× of its own REALITY bulk rate (561 → 243 MB/s) and sing-box 5 % (798 → 756) |
| VMess over WebSocket + TLS | yes | −35.5 %, CPU +12 % |
| Trojan + TLS | yes | **+6.8 %** — our only throughput win, and CPU −30 % |
| Shadowsocks-2022 (blake3-aes-128-gcm) | yes | −45.8 %, CPU +52 % |
| Shadowsocks AEAD (aes-256-gcm) | yes | −14.0 %, CPU +22 % |

Nothing was silently dropped, and no pair needed a "n/a" row in this run. The
`n/a` paths exist, are exercised by the harness's own tests, and print as
`n/a (reason)` with the full reason repeated below the table:

```
Trojan / TLS          sing-box    -   -   -   -   -   -   0  n/a (not installed (no sing-box binary found))
Trojan / TLS          flux-core   -   -   -   -   -   -   0  n/a (round 1: timeout: no completion within 1s (4000 MiB at…)
```

(the first is `--singbox /nonexistent/sing-box`; the second is `--mb 4000
--timeout 1`, which returns in 2.1 s instead of hanging — a timeout is recorded
as a result, not waited out.)

Two configuration requirements are worth recording because a wrong one looks
like a protocol failure:

* **REALITY needs a genuine TLS 1.3 `fallback`/`handshake` target.** Pointed at a
  plain TCP echo server, the flux REALITY handshake fails with
  `TLS / Crypto error: expected TLS ServerHello`, and sing-box fails with
  `REALITY: processed invalid connection`. Both need a real TLS 1.3 server to play
  the certificate chain from; the harness runs one (rustls) for all REALITY
  scenarios and does not charge it to either stack.
* **The harness must not half-close the tunnel when its upload finishes.** The
  first version of the transfer task dropped the write half when the last chunk
  was written; sing-box tears the whole connection down on EOF in one direction,
  so the download was truncated at a variable offset (0 B … 3.7 MB of a 4 MB
  transfer) and sing-box looked broken at random. The writer now holds the socket
  open until the echo has come back in full. `bench_native`'s copy of the
  transfer is harmless only because it compares SOCKS→direct.

## The REALITY setup defect (the one result that is not about throughput)

`setup ms` is in the table because without it this row is unreadable: flux's
REALITY inbound takes **5.0 s to accept each new connection**, and a fixed 5 s
dominates any "MB/s" computed over a fresh connection.

It is server-side, and it depends on the `fallback` target. Same flux-core binary,
same keypair, same client; only the fallback changed:

| fallback for flux's REALITY inbound | SOCKS connect → tunnel ready |
|---|---|
| openssl `s_server -tls1_3` | **6 ms** |
| sing-box TLS inbound (Go `crypto/tls`) | **7 ms** |
| flux-core's own TLS inbound (rustls) | **5002 ms** |

A **sing-box** client → flux REALITY server with a rustls fallback also waits
5008 ms, so the cost is in the flux server, not the flux client and not the
harness; sing-box's REALITY inbound with the *same* rustls decoy accepts in
1.4 ms. The code path is `probe_target_handshake` in
`crates/flux-transport/src/reality.rs` (~L1788–1800): it replays the client's
ClientHello at the fallback and reads **up to 7 handshake records against a
`now + 5 s` deadline**, `break`ing on timeout rather than treating "the target's
flight is complete" as success. Against a rustls fallback it burns the whole
deadline on every connection; OpenSSL and Go fallbacks end the loop early.

Consequence: any REALITY deployment whose `fallback` is a rustls server (flux's
own TLS inbound is one, and it is a very common server stack) pays 5 s per
connection opening. Bulk throughput is unaffected — 561 MB/s once the connection
is up — so a long-lived tunnel hides it and a browser does not.

## What the numbers do and do not prove

**They do prove**, on one machine with one harness:

* each stack's own client+server pair, doing the same work on the same wire
  formats, with a fixed payload, a fixed number of interleaved rounds and the CPU
  of both tunnel processes charged to it;
* that the gaps are *layer-specific*, not a single global constant: Trojan (−30 %
  CPU, +6.8 % throughput), TCP (−31 % CPU, −9.6 %), gRPC (−20 % CPU, −5.7 %) are
  at or near parity while WebSocket (−39 %), Shadowsocks-2022 (−46 %) and Vision
  (−68 % / +198 % CPU) are not. That is the shape of a few specific hot paths, not
  of a slow runtime.

**They do not prove**, and should not be quoted as if they did:

* **anything about a real network.** This is loopback: no MTU, no packet loss, no
  RTT, no congestion control, no middlebox. A relay that wins here on syscalls per
  byte can lose on a 200 ms path, and vice versa. REALITY/WS/gRPC framing costs are
  amplified or hidden differently once packets are actually routed.
* **anything about multiplexed or multi-stream use.** One stream, one connection
  at a time. `bench_native --streams 8` and `bench_udp` cover other shapes.
* **anything about a shaped or contended machine.** Rounds are interleaved
  (odd rounds flux first, even rounds sing-box first) and reported as
  min/median/max precisely because a single-shot loopback number is not
  reproducible; here the round-to-round spread is a few percent for most rows and
  up to ~13 % for the REALITY rows, and the runs were taken at load average < 1,
  which is the best case. The absolute MB/s will be lower on a busy box; the
  ratio is more stable than either absolute number.
* **that the harness is not the ceiling.** The client endpoint and the echo server
  live in the benchmarking process and are not charged to either stack, but they
  do consume CPU. On the same machine at the same time, `bench_native --rounds 2
  --mb 300` puts a direct loopback echo at 2149 MB/s and a SOCKS→direct relay at
  1716 MB/s, so at the ~1.1–1.2 GB/s both stacks reach on plain VLESS/TCP the
  harness is within a factor of two of being the co-limit. That is exactly why the
  near-parity rows (−5.7 %, −9.6 %, +6.8 %) should be read as "no measurable
  difference", not as "flux-core is 1.07× sing-box".
* **that sing-box and flux-core were configured equally well.** Both were given
  their natural, tested configuration for each protocol (lifted from
  `tests/test_singbox_interop.rs`, which is proven against a real binary), but
  neither was tuned: no buffer-size, mux, or CPU-affinity tuning on either side.
  sing-box's defaults may simply be better than our defaults; the matrix says who
  is faster out of the box, not who can be made faster.
* **the number in isolation.** VLESS/TCP at 1068 MB/s is not "the speed of
  flux-core"; it is the speed of this pair of processes, on this machine, with a
  128 KiB write chunk, at this commit. The commit matters: the matrix was first
  run against a tree without `copy_bidirectional_buffered`, where flux's
  protocol tunnels were at roughly half of these numbers (VLESS/TCP 493 vs 1047).

## Reproducing

```bash
# 1. build (sing-box at ~/.local/bin is picked up automatically)
cargo build --release -p flux-core --bin flux-core --example bench_matrix

# 2. the run behind the table above
./target/release/examples/bench_matrix --rounds 5 --mb 200

# a single pair, or the flux column only
./target/release/examples/bench_matrix --only reality --rounds 3 --mb 200
./target/release/examples/bench_matrix --only "shadowsocks-2022" --no-singbox

# tuning knobs
#   --rounds N      interleaved rounds per pair        (default 3)
#   --mb N          MiB of payload per round           (default 200)
#   --only SUBSTR   filter on protocol name            (case-insensitive)
#   --timeout SECS  per-transfer deadline              (default 120)
#   --no-singbox    skip the sing-box column
#   --flux PATH / --singbox PATH
#   BENCH_MATRIX_LOG=debug  BENCH_MATRIX_KEEP_LOGS=1  BENCH_MATRIX_TRACE=1
```

`BENCH_MATRIX_KEEP_LOGS=1` keeps every generated config and every daemon's stderr
under `/tmp/bench_matrix_<pid>/` — the first thing to reach for when a pair fails.
`BENCH_MATRIX_TRACE=1` timestamps each transfer phase, which is how the 5 s REALITY
setup was separated from the bulk rate.

Gates for this work: `cargo build --release -p flux-core --bin flux-core
--example bench_matrix --example bench_native`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo fmt --all -- --check` — all green.