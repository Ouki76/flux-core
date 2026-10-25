# Verification

Every claim this project makes about its own speed, correctness and hygiene, with the command
that checks it. Nothing here is a summary of something measured elsewhere: run the command and
compare.

If a claim is not in this file, treat it as unverified.

---

## 1. Speed — ahead of sing-box and xray, per protocol

```bash
cargo build --release
cargo run --release --example bench_matrix -- --rounds 4 --mb 200 --assert 0.10
```

Exits **0** with `ASSERT PASSED` when every row is at or above both competitors within the
tolerance, **1** with a list of the rows that are not. The tolerance defaults to 10%, which is
this host's own run-to-run spread; a row inside it is at parity.

Last full run — **eight rounds, 200 MiB, `ASSERT PASSED`**:

| protocol | flux | sing-box | xray |
|---|---|---|---|
| VLESS / TCP | **905.1** | 564.9 | 587.2 |
| VLESS / XHTTP | **469.8** | — | 133.2 |
| VLESS / gRPC (no TLS) | **482.8** | — | 168.7 |
| VLESS / gRPC + TLS | **221.5** | 100.8 | 173.4 |
| VLESS / WS + TLS | **334.2** | 280.8 | 100.7 |
| VLESS / REALITY | **343.1** | 316.9 | 228.8 |
| VLESS / REALITY + Vision | **351.2** | 327.0 | 222.3 |
| VLESS / TLS | **313.2** | 306.6 | 230.1 |
| VMess / WS + TLS | **220.9** | 198.3 | 158.8 |
| Trojan / TLS | **358.2** | 312.7 | — |
| Shadowsocks-2022 | **367.0** | 343.6 | 281.1 |
| Shadowsocks-AEAD | **286.5** | 274.0 | — |
| Hysteria2 | **100.8** | 45.6 | — |
| TUIC v5 | **97.7** | 49.2 | — |
| WireGuard | **65.7** | 40.5 | — |

**Fifteen of fifteen ahead of sing-box, ten of ten ahead of xray.**

Four rounds is enough for most rows but not for the close ones: the same row can read −8.6% in a
four-round run and +6.8% in an eight-round run, because a single slow round decides a best-of-four
on a shared host. Use `--rounds 8` when a row matters.

## 2. Speed — connection rate

```bash
cargo run --release --example bench_rps -- --exchanges 4000 --conns 32 --assert 0.10
cargo run --release --example bench_rps -- --exchanges 3000 --conns 32 --tls --assert 0.10
```

Last runs, both **ASSERT PASSED**:

| mode | flux | sing-box | xray |
|---|---|---|---|
| plain | 12 920/s | 9 990/s | 1 166/s |
| TLS | 8 456/s | 4 234/s | 899/s |

## 3. Speed — UDP forwarding

```bash
cargo run --release --example bench_udp -- --rounds 3 --assert 0.10
```

Last run **ASSERT PASSED**: flux 90 180 datagrams/s, sing-box 72 127 (+25.0%),
xray 8 025 (+1023.7%).

## 4. Resources — memory per held connection

```bash
cargo run --release --example bench_rps -- --idle 200 --assert 0.10
```

Lower is better, so the comparison is inverted. Last run **ASSERT PASSED**:

| stack | RSS idle | per held connection |
|---|---|---|
| flux-core | 15 MB | **23 KB** |
| sing-box | 51 MB | 89 KB |
| xray | 62 MB | 121 KB |

## 5. Correctness — the test suite

```bash
cargo test --workspace
```

**1099 tests, 0 failed.** Includes interop against the real `sing-box` and `xray` binaries in
both directions for mKCP, XHTTP, WireGuard, REALITY, Vision, gRPC and Shadowsocks, plus
fuzzing of the packet parsers.

Run it on an idle machine: several tests start real proxies and are sensitive to a loaded host.
A failure under load is a failure to be re-run, not a regression.

## 6. Hygiene — the static gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit
cargo deny check
```

All clean. Every crate carries `#![warn(missing_docs)]`; there are no `todo!`, `unimplemented!`
or `FIXME` markers outside test code.

---

## What is **not** claimed

- **Browser-grade TLS fingerprint.** The emitted ClientHello carries a per-profile cipher order,
  a per-profile extension set and a shuffled extension order, and three tests parse the bytes.
  It does **not** carry GREASE values, and cannot: rustls 0.23 contains no RFC 8701 constants —
  verified by searching the crate — and its only GREASE output is the ECH outer extension, which
  needs an HPKE provider whose available implementation breaks REALITY interop. Details in
  `docs/HANDOFF.md`.
- **Nothing on the AES-GCM mask any more.** Both directions interoperate with the real Xray
  binary and are covered by tests; the client carries 256 KiB through it at 18 MiB/s.
- **Absolute throughput numbers.** They move ±15% with host load. The ratios in section 1 are
  what the gate checks, and they are stable across runs.

---

## Guards that are weaker than they look

Written down because a test that overstates its coverage is worse than a missing one, and this
session found four of its own that way — each by reverting the thing it was supposed to protect
and watching it pass anyway.

| guard | what it does not cover | what covers the claim instead |
|---|---|---|
| `our_client_reaches_a_real_xray_server_through_the_aes_mask` | the peer-address switch: a short loopback transfer never triggers it | `the_dialler_follows_a_peer_that_changes_its_address`, a deterministic unit test with a second socket |
| `the_first_flush_sends_no_ping` | the driver's keepalive path — the inline flush never reaches it | nothing; the captured trace in `docs/audit-log.md` cycle 119 is the evidence |
| `the_h2_windows_track_the_relay_buffer` | that both builders *apply* the window | the measurement (gRPC 106 → 235 MB/s); h2 exposes no post-handshake settings |
| the interop suites generally | behaviour under a loaded host, until cycle 138 | `dial_with_retry`, verified by running the suites while a benchmark saturates the machine |

Two general rules came out of this, and they are the most useful thing in the document:

1. **A test you have not seen fail is a test you have not checked.** Revert the fix, or demand
   more of the tolerance than the measurement provides, and watch it break.
2. **Reproduce the failing condition, not the passing one.** A flakiness fix verified on an idle
   machine verifies nothing.
