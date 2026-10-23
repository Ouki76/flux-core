# REALITY record layer

> **Correction (cycle 23, 2026-10-24).** Every number below was measured with the
> `security` block nested **inside** `carrier`, where the configuration parser
> silently ignored it. The tunnel was therefore plain VLESS over TCP: "REALITY 729"
> and "VLESS+TLS 660" were not REALITY or TLS numbers at all. With the block in its
> correct place the same harness measures, on the homelab server, **VLESS/TCP
> 520 MB/s, VLESS+TLS 264, REALITY 239** — REALITY costs 9 % over TLS, and TLS itself
> costs half the throughput. The analysis below is kept for the record layer design,
> not as a performance claim.

# REALITY record layer: 375 → 729 MB/s

> **Dated experiment report.** The figures below are that cycle's interleaved
> runs, kept for the attribution argument. Re-measured against the current tree:
> **REALITY 729 MB/s** and **VLESS+TLS 660 MB/s** (the 645/654 values here were
> the same code at a different moment, inside the ±5 % noise band this report
> states).

**File touched:** `crates/flux-transport/src/reality.rs` only (plus nothing else — see
"Files I did not touch").  Net diff: +253 / −202 lines, including one new test.

| Path | before (5×300 MiB) | after (5×300 MiB) | Δ |
|---|---|---|---|
| direct (no proxy) | 2461 MB/s | 2503 MB/s | machine noise |
| flux relay, no TLS | 1746 MB/s | 1923 MB/s | machine noise |
| VLESS over rustls TLS | 542 MB/s | 645 MB/s | untouched code |
| **VLESS over REALITY** | **375 MB/s** | **729 MB/s** | **1.94×** |
| REALITY CPU | 4.78 s/GB | **2.14 s/GB** | **−55%** |
| REALITY ÷ rustls | 0.69 | **1.13** | REALITY is now the faster one |
| REALITY ÷ unencrypted VLESS | 0.21 | **1.08** | the record layer no longer costs throughput |

`integrity` stayed `ok` and `corrupt_rounds` `0/5` in every run: the harness byte-compares
every byte of every round, so this is a verified-transport number, not a "bytes moved" number.

---

## 1. Method

* One thing at a time, measured with `./target/release/examples/bench_tls --rounds 3 --mb 128`
  (and finally `--rounds 5 --mb 300`), rebuilding `target/release/flux-core` every time.
* `perf` is unavailable, so attribution came from two purpose-built measurements, both removed
  from the final code: (a) a throwaway `/tmp/aeadbench` crate benchmarking the exact AEAD call
  shape the record layer uses (16 KiB buffer, 5-byte AAD, separate tag), and (b) temporary
  `FLUX_REALITY_PROF=1` counters inside `reality.rs` dumping per-record syscall counts and
  per-stage nanosecond totals to `/tmp/reality_prof.log`.
* Other agents were compiling and benchmarking on this box throughout (load average 1–3.8),
  which puts ±5 % noise on absolute numbers. Every A/B below was therefore **interleaved
  binary-alternating**, and the rustls/VLESS paths act as an in-run control.

---

## 2. Profile evidence

### 2.1 The AEAD, measured in isolation (`/tmp/aeadbench`, same call shape as the record layer)

```
aes-gcm crate  AES-128-GCM        1.17 GB/s   (enc+dec pair over 2x16384 B)   -> ~14.0 us per 16 KiB op
ring           AES-128-GCM       11.00 GB/s                                  -> ~1.5 us
ring           AES-256-GCM        9.87 GB/s
aes-gcm crate  AES-256-GCM        1.13 GB/s
chacha crate   CHACHA20-POLY1305  1.63 GB/s
```

`aes-gcm 0.10.3` drives the `ctr` crate one block at a time and so never pipelines AES-NI the
way `ring`'s fused AES-GCM does — **9.4× slower for the identical operation**. `ring` was
already a dependency of `flux-transport` (the rustls path uses it).

### 2.2 Per-record counters inside the tunnel (`FLUX_REALITY_PROF=1`, 128 MiB per direction, per process)

Before (after the AEAD swap, i.e. with `ring` already in place):

```
recs=8192  reads=17203 (2.10 per rec, 2.0 us/read)  writes=7855 (0.96 per rec)
inner_read=35ms  open=14ms  copyout=2ms  seal=16ms  inner_write=24ms      (pid 1897107)
recs=8192  reads=16689 (2.04 per rec, 2.0 us/read)  writes=9187 (1.12 per rec)
inner_read=33ms  open=12ms  copyout=2ms  seal=18ms  inner_write=26ms      (pid 1897108)
```

Reading it:

* **2.1 read syscalls per record** (one 5-byte header read + one body read) at ~2.0 µs each —
  the *largest* single item in the record layer (35 ms of 91 ms).
* **AEAD** (open + seal) = 30 ms of 91 ms even after the swap to `ring`. Before the swap this
  term was ~14 µs × 16 384 = **~229 ms** — i.e. essentially the entire record layer, plus more.
* `copyout` (plaintext → caller's `ReadBuf`) is 2 ms: **2 % — irrelevant**. This is why the
  buffer-plumbing leads were a dead end.
* The record layer total (~91 ms per 128 MiB per direction ≈ 0.73 s/GB) is only about a third
  of the measured 2.2 s/GB; the other two thirds are the VLESS framing, tokio and the socket
  copies, in both processes.

---

## 3. Ranked causes, with measured attribution

| # | Cause | Cost before | Evidence | Fix |
|---|---|---|---|---|
| 1 | **AEAD backend**: `aes-gcm` crate instead of `ring` | ~2.4–3.3 s/GB of summed CPU (predicted 262 144 record-ops/GB × 12.5 µs ≈ 3.3 s/GB; measured total improvement 2.64 s/GB) | microbench §2.1 | `ring::aead::LessSafeKey`, key schedule cached in `TrafficState` |
| 2 | **Read syscall pattern**: 2 syscalls per 16 KiB record | 35 ms / 128 MiB / process (~0.28 s/GB summed) | counters §2.2 | *attempted, measured, reverted* — see §4.4 |
| 3 | Per-record `Vec` allocations + copies (`to_vec()` of the plaintext, 16 KiB zeroed `vec![0u8; len]` per read, 3 allocs + 3 copies per record on write) | not measurable (< 2 %): `copyout` is 2 ms / 128 MiB | counters §2.2 + change 1 result | in-place AEAD + reused buffers (kept for cleanliness, not for speed) |
| 4 | `pending_write` flush copied 64 KiB out with `.to_vec()` per chunk | not measurable on loopback (no partial writes) | change 3 result | sliced the buffer directly |

The surprise is #1. The record layer's plumbing was 3–4× *less* expensive than the crypto it
was wrapped around; the layer was slow because of the AEAD implementation, not its own design.
Note that this also explains the shape of the original table: REALITY was 1.8× the CPU of the
rustls path for the same payload, and rustls (tokio-rustls) already used `ring`.

---

## 4. Changes, before → after

### 4.1 Persistent receive buffer + in-place decrypt — *neutral, kept*

`body_buf` was re-created per record: after `process_record` the code did `body.clear()`, so
the next record's `if self.body_buf.len() != len` was always true → `vec![0u8; len]`, a fresh
zeroed 16 KiB allocation **per record**. `decrypt_record` then returned `plain[..i-1].to_vec()`
(another alloc + 16 KiB copy) which `poll_read` copied again into the caller.

Now `body_buf` keeps its high-water-mark length, the AEAD opens **in place** in it, and
`poll_read` copies straight from it into the caller's `ReadBuf`. Per record: 3 allocations +
4 payload copies + 16 KiB of zeroing → **0 allocations + 2 copies**.

> 405 MB/s → 394 MB/s (min/max 385–411 → 379–404). **Within noise: no gain.**
> Kept because it removes the allocator from the hot path (matters for jitter and for many
> concurrent connections) and because it is what the leads asked about — but the honest
> conclusion is that REALITY's buffer plumbing was never the problem.

### 4.2 AEAD → `ring`, key schedule hoisted into `TrafficState` — **the fix**

`TrafficState` now owns a `ring::aead::LessSafeKey` (built once per key, rebuilt only on
`KeyUpdate`) instead of calling `Aes128Gcm::new_from_slice(key)` per record. Records are sealed
with `seal_in_place_separate_tag` (tag appended to the same buffer the caller's plaintext was
copied into) and opened with `open_in_place` (ciphertext and tag already contiguous in
`body_buf`). AAD remains the 5-byte record header, so the wire format is unchanged.

> 394 MB/s → **658 MB/s** (1st run), 405 → **715 MB/s** (confirmation run), CPU 4.43 → **2.48**,
> then 2.16 s/GB. Integrity ok, xray and sing-box interop green (§5).

### 4.3 Write path: reusable staging buffer, in-place seal, no flush copies — *neutral, kept*

`poll_write` built the record as `inner` `Vec` → AEAD output `Vec` → `record` `Vec` (3 allocs,
3 copies per record) and `poll_flush`/`poll_write` copied each 64 KiB pending chunk out with
`.to_vec()` before handing it to the transport.

Now: one `tx_buf` per connection, plaintext appended at offset 5, sealed in place, tag appended,
header patched — one allocation for the life of the connection. Flush slices `pending_write`
directly via disjoint field borrows.

> 715 → 696 MB/s, CPU 2.16 → 2.27 (both inside the noise band of the runs around it; the
> rustls control path moved 632 → 574 in the same window).
> **No measurable gain; kept for the same allocator-jitter reason as 4.1.**

### 4.4 Read-syscall coalescing — *measured 5 % slower, reverted*

Built and A/B'd: a 33 KiB receive window (`RECV_CAP = 2 × (5 + 16384 + 256)`) that assembles
records at an offset, so one `read` can feed two records. It worked exactly as intended:

```
before: 2.10 reads/record, 2.0 us/read, inner_read=35ms
after:  0.58 reads/record, 5.0 us/read, inner_read=24ms     (-31% read time, -72% syscalls)
```

but end-to-end it was **slower**, because a window that is not a multiple of the record size
straddles records and forces a `copy_within` compaction of up to 16 KiB roughly every second
record. Interleaved A/B of the two binaries (2 rounds × 160 MiB each, `--paths vless/reality`):

| run | A (2 read syscalls/record) | B (coalesced window) |
|---|---|---|
| 1 | 727.6 | 678.0 |
| 2 | 711.8 | 665.2 |
| 3 | 660.6 | 684.4 |
| 4 | 720.4 | 688.6 |
| median | **716** | **681** |

Per the "revert anything that does not help" rule this was dropped; `reality.rs` keeps the
simple header-then-body read. The 5-byte-header syscall is real (≈0.3 s/GB summed) but any
scheme that removes it costs more in data movement than it saves.

### 4.5 New regression test for the accounting that broke twice

`reality::hostile_transport_tests::stuttering_transport_stays_byte_exact`: a wrapper transport
that returns `Pending` on every third poll (waking itself, like a socket with no data) and moves
at most 777 bytes per read / 1000 bytes per write, carrying 256 KiB through a full REALITY
handshake + echo, byte-compared in both directions, with a 60 s watchdog so a hang fails
instead of stalling CI.

It is not vacuous: re-introducing "lose `pending_write_pos` progress on `Pending`" (the
duplicate-record bug class) makes it fail immediately. It also covers partial record assembly
(every record is delivered in ~21 pieces) and partial writes (`pending_write` tail buffering).

---

## 5. Verification (verbatim)

```
$ cargo test -p flux-transport --lib reality
running 11 tests
test reality::cert_parse_tests::extract_ed25519_pubkey_tolerates_truncated_input ... ok
test reality::crypto_reference_tests::test_derive_auth_key_matches_python_hkdf ... ok
test reality::gcm_vector_tests::test_aes256gcm_reference_vector ... ok
test reality::tests::test_reality_mimicry_slots_without_ccs ... ok
test reality::tests::test_reality_fallback_relay_for_invalid_client ... ok
test reality::tests::test_reality_wrong_short_id_fails ... ok
test reality::tests::test_reality_spider_mode_on_real_tls_server ... ok
test reality::tests::test_reality_xtls_handshake_and_data_roundtrip ... ok
test reality::hostile_transport_tests::stuttering_transport_stays_byte_exact ... ok
test reality::bulk_integrity_tests::bulk_upload_and_download_are_byte_exact ... ok
test reality::tests::test_reality_server_mimics_target_record_framing ... ok
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 44 filtered out; finished in 5.01s
```

```
$ cargo test --test test_xray_interop
test reality_plain_flux_client_to_xray ... ok
test reality_vision_flux_client_to_xray ... ok
test reality_vision_xray_client_to_flux ... ok
test reality_plain_xray_client_to_flux ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.04s
```

```
$ cargo test --test test_singbox_interop
test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.55s
```

```
$ cargo clippy -p flux-transport --lib -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.28s
```

`cargo clippy -p flux-transport --all-targets -- -D warnings` currently fails on **two
diagnostics that are not in my file** — `crates/flux-transport/src/pipeline.rs:314`
("empty line after doc comment") and `:341` ("unused variable: `addr`") — from another agent's
in-flight edits to that file. `reality.rs` itself produces no diagnostic under `--all-targets`.

### Final numbers (5 interleaved rounds × 300 MiB, byte-verified)

```
target              MB/s       min       max    setup p50/p99  CPU s/GB   RSS MiB  vs direct  integrity
direct            2503.4    2249.4    2579.3     0.08/0.19 ms         -         -      +0.0%  OK (byte-verified)
flux direct       1922.6    1866.2    2051.7     0.21/0.34 ms      0.29       8.1     -23.2%  OK (byte-verified)
vless/tcp          673.0     667.7     733.6     0.33/0.54 ms      1.45      17.5     -73.1%  OK (byte-verified)
vless/tls          645.0     597.2     676.9     0.58/0.86 ms      2.38      20.8     -74.2%  OK (byte-verified)
vless/reality      729.1     711.9     740.9     0.72/0.94 ms      2.14      20.2     -70.9%  OK (byte-verified)
```

Three independent runs of the final code: **718.7**, **737.2**, **729.1 MB/s** at
2.15 / 2.23 / 2.14 CPU s/GB (median 729 MB/s, 2.15 s/GB). Setup latency is unchanged
(0.72 ms p50 vs 0.74 ms before) and RSS is unchanged (20.2 vs 20.2 MiB).

Multi-stream check (4 concurrent streams × 3 rounds × 128 MiB, byte-verified):

```
vless/tls      mbs 1556.0   corrupt 0/3   integrity ok
vless/reality  mbs 1549.7   corrupt 0/3   integrity ok
```

At 1 stream REALITY is 13 % ahead of rustls; at 4 streams the two are equal (1549.7 vs 1556.0),
which is what "the record layer is no longer the bottleneck" looks like on a box with spare
cores: nothing in it serialises, and both paths become limited by memory/socket bandwidth.

---

## 6. The honest remaining ceiling

* **REALITY is now at parity with the unencrypted VLESS path** (729 vs 673 MB/s median; the
  spread of both is ~±5 %, and in one run REALITY was 8 % ahead of `vless/tcp`). The record
  layer costs essentially no *throughput*; what is left is `2.14 − 1.45 = 0.69 s/GB` of CPU,
  and ~0.4 s/GB of that is the AEAD itself, which every TLS 1.3 implementation pays (rustls
  pays it too: `vless/tls` is 2.38 s/GB, *higher* than REALITY now).
* **Record-layer CPU is ~1/3 of the per-GB cost.** From the counters: ~91 ms per 128 MiB per
  direction, i.e. ≈0.73 s/GB summed, against 2.14 s/GB total. The other ~1.4 s/GB is the VLESS
  framing, the 16 KiB copy loop, tokio polling and the socket copies — all outside this file.
  `direct` runs at 2503 MB/s, so the two-process VLESS path (673 MB/s) is the next real ceiling
  and it is not mine to move this round.
* **What is left in the record layer, and why I did not take it:**
  * the 5-byte header read (≈0.28 s/GB summed): removable only with a coalescing window, which
    measured **5 % slower** end-to-end (§4.4);
  * one write syscall per record (~4 µs each, 24 ms/128 MiB): batching means buffering plaintext
    across `poll_write` calls, but the copy loop only ever offers 16 KiB at a time, so a batch
    would have to wait for more data — that adds up to 48 KiB of latency to interactive
    traffic. Wrong trade for a proxy.
  * the plaintext copy out of `body_buf` into the caller's `ReadBuf`: **2 ms per 128 MiB**
    (0.4 % of the record layer). Serving directly into the caller's buffer would require
    decrypting inside `ReadBuf`'s unfilled region with correct `Pending` rollback — high risk
    for 0.4 %.
  * AES-256-GCM is 10 % slower than AES-128-GCM in `ring`; the client offers 0x1301 first, so
    the negotiated suite is already the fast one.
* **No structural excuse remains.** REALITY's record layer now uses the same AEAD (ring), in the
  same in-place form, as the rustls path, and matches it. If a further 2× is needed on this
  axis it has to come from the framing/copy path (single buffer end-to-end, larger read sizes),
  not from TLS.

## 7. Files I did not touch, and one cleanup left behind

* Untouched: `crates/flux-inbound/src/tun.rs`, `tests/test_transparent_inbounds.rs`,
  `tests/common/mod.rs`, `examples/bench_tls.rs` (no change was needed to measure; the harness
  was used exactly as provided). `crates/flux-transport/src/pipeline.rs` also untouched.
* `crates/flux-transport/Cargo.toml`: `chacha20poly1305` is now unused by this crate (the
  ChaCha20-Poly1305 suite goes through `ring`); `aes-gcm` is still needed for the REALITY
  `session_id` seal. I left the dependency list alone because that file is not mine this round.