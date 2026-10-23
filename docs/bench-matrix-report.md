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

Measured on a 16-core desktop from the tree at `90d4933` — `fix(reality): a
rustls fallback cost 5 seconds on every connection`, the fix this matrix forced —
`flux-core 1.3.4` vs `sing-box 1.11.4`. xray 26.3.27 is installed but is not part
of this matrix. The REALITY rows were re-measured after that fix landed and are
confirmed on the committed tree; the Vision row was measured just before
`crates/flux-protocol/src/vision.rs` started changing, so treat it as a lower
bound and re-run before quoting it.

## The table as printed

```
$ cargo run --release --example bench_matrix -- --rounds 5 --mb 200

flux-core  : flux-core 1.3.4  (./target/release/flux-core)
sing-box   : sing-box version 1.11.4  (/home/ouki/.local/bin/sing-box)
echo server: 127.0.0.1:37811 (in this process; not charged to either stack)
TLS decoy  : 127.0.0.1:43311 (REALITY certificate source)
workload   : 200 MiB payload per round, 5 round(s), fresh tunnel connection per round

========================================================================================================================================
TUNNEL THROUGHPUT MATRIX — loopback, 200 MiB payload per round, 5 interleaved round(s), 1 stream
MB/s = MiB/s of payload for a FRESH tunnel connection (setup included); bulk excludes the tunnel setup
========================================================================================================================================
Protocol / transport                 Stack       MB/s e2e       min       max MB/s bulk  setup ms CPU s/GiB   n  status
----------------------------------------------------------------------------------------------------------------------------------------
VLESS / TCP                          flux-core     1060.9    1038.0    1097.6    1062.7       0.3     1.197   5  ok
                                     sing-box      1183.2    1109.5    1239.2    1186.4       0.5     1.664   5  ok
VLESS / WS + TLS                     flux-core      420.5     399.4     435.1     421.2       0.6     4.672   5  ok
                                     sing-box       707.4     701.4     719.2     710.2       1.1     3.482   5  ok
VLESS / gRPC + TLS                   flux-core      301.3     291.6     303.4     301.6       0.6     8.252   5  ok
                                     sing-box       322.1     317.0     326.6     322.3       0.3    10.089   5  ok
VLESS / REALITY                      flux-core      538.0     504.5     547.4     539.0       0.7     3.593   5  ok
                                     sing-box       724.5     696.7     748.3     728.1       1.6     3.078   5  ok
VLESS / REALITY + Vision             flux-core      225.6     222.9     236.5     225.8       0.7     8.967   5  ok
                                     sing-box       722.4     708.0     751.4     726.9       1.6     3.046   5  ok
VMess / WS + TLS                     flux-core      315.9     308.8     329.7     316.3       0.7     6.245   5  ok
                                     sing-box       500.5     461.1     506.7     501.8       1.1     5.161   5  ok
Trojan / TLS                         flux-core      767.5     721.7     797.1     769.1       0.6     2.231   5  ok
                                     sing-box       740.7     690.8     746.8     743.3       1.2     2.990   5  ok
Shadowsocks-2022 / blake3-aes-128-gcm flux-core      482.6     471.5     511.3     482.9       0.3     4.023   5  ok
                                     sing-box       953.9     915.5     974.0     955.7       0.4     2.397   5  ok
Shadowsocks-AEAD / aes-256-gcm       flux-core      427.8     416.6     464.8     428.2       0.3     4.611   5  ok
                                     sing-box       498.6     446.8     516.5     499.1       0.5     3.751   5  ok
----------------------------------------------------------------------------------------------------------------------------------------

PAIRWISE SUMMARY (medians; flux-core relative to sing-box)
--------------------------------------------------------------------------------------------------------
Protocol / transport                    flux bulk  sbox bulk  throughput  CPU ratio  setup flux/sbox
--------------------------------------------------------------------------------------------------------
VLESS / TCP                                1062.7     1186.4      -10.4%     -28.0%     0.3 / 0.5 ms
VLESS / WS + TLS                            421.2      710.2      -40.7%     +34.2%     0.6 / 1.1 ms
VLESS / gRPC + TLS                          301.6      322.3       -6.4%     -18.2%     0.6 / 0.3 ms
VLESS / REALITY                             539.0      728.1      -26.0%     +16.8%     0.7 / 1.6 ms
VLESS / REALITY + Vision                    225.8      726.9      -68.9%    +194.3%     0.7 / 1.6 ms
VMess / WS + TLS                            316.3      501.8      -37.0%     +21.0%     0.7 / 1.1 ms
Trojan / TLS                                769.1      743.3       +3.5%     -25.4%     0.6 / 1.2 ms
Shadowsocks-2022 / blake3-aes-128-gcm       482.9      955.7      -49.5%     +67.8%     0.3 / 0.4 ms
Shadowsocks-AEAD / aes-256-gcm              428.2      499.1      -14.2%     +23.0%     0.3 / 0.5 ms
--------------------------------------------------------------------------------------------------------
```

`MB/s` is MiB/s of payload counted once (200 MiB in, 200 MiB back out). `CPU s/GiB`
is the CPU burned by the **two tunnel processes** — "MB/s bulk" excludes the
connection-setup phase and "setup ms" is that phase on its own. Per-round samples
are printed above the table, and every cell is a median of 5 interleaved rounds.

## Which pairs work

All nine run, each driven through both stacks with a real handshake and a
byte-exact 200 MiB echo:

| pair | works | throughput vs sing-box | CPU vs sing-box |
|---|---|---|---|
| VLESS over TCP (plain) | yes | −10.4 % | **−28.0 %** |
| VLESS over WebSocket + TLS | yes | −40.7 % | +34.2 % |
| VLESS over gRPC + TLS | yes | −6.4 % | **−18.2 %** |
| VLESS + REALITY, Vision off | yes | −26.0 % | +16.8 % |
| VLESS + REALITY, Vision on | yes | **−68.9 %** | **+194.3 %** |
| VMess over WebSocket + TLS | yes | −37.0 % | +21.0 % |
| Trojan + TLS | yes | **+3.5 %** | **−25.4 %** |
| Shadowsocks-2022 (blake3-aes-128-gcm) | yes | **−49.5 %** | +67.8 % |
| Shadowsocks AEAD (aes-256-gcm) | yes | −14.2 % | +23.0 % |

Nothing was silently dropped and no pair needed an `n/a` row in this run. The
`n/a` paths exist, are exercised, and print as `n/a (reason)` with the full reason
repeated under the table:

```
Trojan / TLS          sing-box    -   -   -   -   -   -   0  n/a (not installed (no sing-box binary found))
Trojan / TLS          flux-core   -   -   -   -   -   -   0  n/a (round 1: timeout: no completion within 1s (4000 MiB at…)
```

The first is `--singbox /nonexistent/sing-box`; the second is `--mb 4000
--timeout 1`, which returns in 2.1 s with the timeout recorded instead of hanging.

Two configuration requirements are worth recording, because getting either wrong
looks like a protocol failure:

* **REALITY needs a genuine TLS 1.3 `fallback`/`handshake` target.** Pointed at a
  plain TCP echo server, the flux handshake fails with
  `TLS / Crypto error: expected TLS ServerHello` and sing-box fails with
  `REALITY: processed invalid connection`. Both fetch the certificate chain to
  mimic from that target, so the harness runs a real TLS 1.3 server (rustls) for
  every REALITY scenario and does not charge its CPU to either stack.
* **The harness must not half-close the tunnel when its upload finishes.** The
  first version of the transfer task dropped the write half once the last chunk
  was written; sing-box tears the whole connection down when one direction hits
  EOF, so the download was truncated at a variable offset (0 B … 3.7 MB of a 4 MB
  transfer) and sing-box looked randomly broken. The writer now holds the socket
  open until the echo has come back in full. `bench_native`'s copy of the transfer
  escapes this only because it compares SOCKS → direct.

## The defect the matrix found

The `setup ms` column exists because the first REALITY run reported **37 MB/s**
with a 5 000 ms setup, which is not a throughput number. It was not slow crypto
and it was not a broken scenario: flux's REALITY *inbound* took **5.0 s to accept
each new connection**, and a fixed 5 s dominates anything computed over a fresh
connection.

It was server-side, and it depended on the `fallback` target. Same flux-core
binary, same keypair, same client; only the fallback changed:

| fallback for flux's REALITY inbound | SOCKS connect → tunnel ready |
|---|---|
| openssl `s_server -tls1_3` | 6 ms |
| sing-box TLS inbound (Go `crypto/tls`) | 7 ms |
| flux-core's own TLS inbound (rustls) | **5002 ms** |

A **sing-box** client → flux REALITY server with a rustls fallback also waited
5008 ms, so the cost was in the flux server, not the client and not the harness;
sing-box's REALITY inbound with the *same* rustls decoy accepted in 1.4 ms. The
code was `probe_target_handshake` in `crates/flux-transport/src/reality.rs`: it
replays the client's ClientHello at the fallback and read **up to 7 handshake
records against a `now + 5 s` deadline**, `break`ing on timeout instead of treating
"the target's flight is complete" as success. Against a rustls fallback it burned
the whole deadline on every connection, which is why the defect was invisible in
mixed-stack tests — OpenSSL and Go fallbacks happen to end the loop early.

Fixed in the same cycle (bounded sequel-idle instead of a 5 s deadline, plus a
60 s mimicry cache keyed by target), and re-measured with the same harness:

| VLESS / REALITY, flux-core | before | after |
|---|---|---|
| setup per connection | 5002.0 ms | **0.7 ms** |
| MB/s end-to-end | 37.3 | **538.0** |
| MB/s bulk | 561.3 | 539.0 |
| CPU s/GiB (bulk unaffected) | 3.365 | 3.593 |

That is the whole point of the matrix: a real, user-visible defect that no
self-comparison could ever have surfaced, found and closed by a 5-line table.

## What the numbers do and do not prove

**They do prove**, on one machine with one harness:

* each stack's own client+server pair, doing the same work on the same wire
  formats, with a fixed payload, a fixed number of interleaved rounds, and the CPU
  of both tunnel processes charged to it;
* that the remaining gaps are *layer-specific* rather than one global constant:
  Trojan (+3.5 % throughput, −25 % CPU), VLESS/TCP (−10 %, −28 %) and gRPC (−6 %,
  −18 %) are at or near parity, while WebSocket (−41 %), Shadowsocks-2022 (−50 %)
  and Vision (−69 %, +194 % CPU) are not. That is the shape of a few specific hot
  paths, not of a slow runtime — and it tells you exactly where to look next.

**They do not prove**, and should not be quoted as if they did:

* **anything about a real network.** This is loopback: no MTU, no packet loss, no
  RTT, no congestion control, no middlebox. A relay that wins here on syscalls per
  byte can lose on a 200 ms path, and framing costs are amplified or hidden
  differently once packets are actually routed.
* **anything about multiplexed or multi-stream use.** One stream, one connection
  at a time. `bench_native --streams 8` and `bench_udp` cover other shapes.
* **anything about a contended machine.** Rounds are interleaved (odd rounds
  flux first, even rounds sing-box first) and reported as min/median/max precisely
  because a single-shot loopback number is not reproducible. This run was taken in
  a quiet window (load average ≤ 3 on 16 cores; round-to-round spread mostly a few
  percent, up to ~13 % on the REALITY rows). Absolute MB/s will be lower on a busy
  box; the ratio is more stable than either absolute number.
* **that the harness is not the ceiling.** The client endpoint and the echo server
  live in the benchmarking process and are not charged to either stack, but they
  do consume CPU. On this machine at the same time, `bench_native --rounds 2 --mb
  300` put a direct loopback echo at 2149 MB/s and a SOCKS → direct relay at
  1716 MB/s, so at the ~1.1–1.2 GB/s both stacks reach on plain VLESS/TCP the
  harness is within a factor of two of being the co-limit. That is why the
  near-parity rows (−6.4 %, −10.4 %, +3.5 %) should be read as "no measurable
  difference", not as "flux-core is 1.03× sing-box".
* **that sing-box and flux-core were configured equally well.** Both got their
  natural, tested configuration for each protocol (lifted from
  `tests/test_singbox_interop.rs`, which is proven against a real binary), but
  neither was tuned: no buffer-size, mux or CPU-affinity tuning on either side.
  sing-box's defaults may simply be better than our defaults. The matrix says who
  is faster out of the box, not who can be made faster.
* **the number in isolation.** VLESS/TCP at 1061 MB/s is not "the speed of
  flux-core"; it is the speed of this pair of processes, on this machine, with a
  128 KiB write chunk, at this commit. The commit matters: the matrix was first run
  on a tree without `copy_bidirectional_buffered`, where flux's protocol tunnels
  ran at roughly half of these numbers (VLESS/TCP 493 vs 1047).

## Reproducing

```bash
# 1. build (sing-box at ~/.local/bin is picked up automatically)
cargo build --release -p flux-core --bin flux-core --example bench_matrix

# 2. the run behind the table above
./target/release/examples/bench_matrix --rounds 5 --mb 200

# one pair, or the flux column only
./target/release/examples/bench_matrix --only reality --rounds 3 --mb 200
./target/release/examples/bench_matrix --only "shadowsocks-2022" --no-singbox

# knobs
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

Gates for this work, all green: `cargo build --release -p flux-core --bin
flux-core --example bench_matrix --example bench_native`, `cargo clippy
--workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`.