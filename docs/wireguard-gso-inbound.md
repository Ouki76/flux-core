# The inbound-GSO stall: a burst sender that reordered its own stream

*Cycle 4, 2026-10-22. Closes the entry "Open: the inbound-GSO stall (investigated,
not solved)" in [audit-log.md](audit-log.md#open-the-inbound-gso-stall-investigated-not-solved).*

## Verdict

Inbound GSO is **safe to enable and is now enabled unconditionally** on the
WireGuard inbound egress. The bimodality was not a property of GSO, or of the
kernel, or of the peer: it was a bug in the two copies of the burst sender, which
handed the *odd-sized* frames of a burst to the kernel **after** the equal-sized
run that followed them in the stream. The receiving TCP stack saw an
out-of-order segment, opened a hole for it, and — when its receive buffer was
nearly full — that hole closed the advertised window until a retransmit timeout
repaired it. The stall was therefore always exactly one RTO, with no lost
datagrams anywhere, which is why every earlier measurement of drops, AEAD
failures and datagram counts came back clean.

## Reproduction

Harness: `cargo run --release --example bench_wireguard -- --paths wireguard -r 3 -m 256`.
Both tunnel ends are `target/release/flux-core`; one stream, every byte
byte-verified, 256 MiB per round (= 512 MiB of verified traffic per round).

Both configurations below were measured on the same machine, minutes apart, load
average 5–6 throughout:

| build | rounds (MB/s) |
|---|---|
| pre-fix, inbound GSO on, inv 1 | 58.0, 51.2, 56.6 |
| pre-fix, inbound GSO on, inv 2 | 47.8, 110.0, 76.7 |
| pre-fix, inbound GSO on, inv 3 | 77.1, 76.8, 47.9 |
| pre-fix, inbound GSO off (shipped state), 64 MiB | 121.7–136.2 over 6 rounds |
| post-fix, inbound GSO on, 5 invocations x 3 rounds | **189.1 – 217.6**, medians 198.9 / 206.8 / 213.0 / 214.7 / 216.0 |

At 64 MiB per round the pre-fix collapse was intermittent within a run
(`179.6` median with a `27.4` minimum and a `194.4` maximum in one invocation);
at 256 MiB it is universal, because the trigger fires several hundred times per
gigabyte. That is the "bimodality": it was a per-byte probability, not a mode.

The direct evidence, from an instrumented build that compared each decrypted
frame's TCP sequence number with the running expectation at the point where it
enters the receiving stack (`flux-outbound`'s ingress):

```
inbound GSO off, 1 s window:  frames=97698  gaps=0    dups=0
inbound GSO on,  1 s window:  frames=142992 gaps=663  dups=862  missing=664424 B
```

Every gap was followed by the "missing" segment arriving microseconds later —
reordering, not loss. In the collapse itself the client's pump logged

```
idle 1000.884 ms, arm=timer, wait=1s, conns=["Established txq=65536 rxq=0 wnd=0"]
```

that is: a full 1 s stack-timer sleep, a *full* send buffer, and a **zero
advertised window from the peer**. Nothing was in flight, so nothing could
trigger a fast retransmit, so the hole waited out the RTO.

## Mechanism

1. smoltcp emits a burst of inner IP packets: usually full-MSS frames, but at a
   window edge the first one may be short, and the tail always is.
2. `GsoBatch::send_burst` coalesces runs of ≥2 equal-sized datagrams into one
   `UDP_SEGMENT` super-packet. The old loop pushed the index of every run it
   *could not* coalesce onto a `singles` vector and sent that vector **after** the
   loop, i.e. after every super-packet of the burst.
3. So for a burst shaped `[300 B, 1468 B x 30]` the peer received datagrams
   1..30 first and datagram 0 last: one out-of-order segment per affected burst.
4. The receiving smoltcp puts the arrived data behind a hole. `rcv_nxt` cannot
   advance, so the receive window it advertises is computed against a buffer that
   is already full of data it may not release. With a 64 KiB client receive buffer
   against 47 KiB bursts, the window reaches zero.
5. The sender has no window and (being at the end of its own buffer) no reason to
   send anything, so no duplicate ACKs are generated and no fast retransmit can
   fire. The hole is repaired by the retransmit timer: **1 s**.
6. After the RTO the retransmitted segment fills the hole, the window reopens and
   the transfer resumes at full speed — the observed collapse-and-recover shape.

The reordering was not rare because odd frames are rare; it was ~600–1400 events
per second, i.e. every burst that had a short frame anywhere but the end.

## Hypotheses eliminated, and how

| hypothesis | experiment | result |
|---|---|---|
| **#1 The receiver of a super-packet assumes one datagram per `recvmmsg` element / per read** (truncation, `UDP_DGRAM_CAP`, desync) | Standalone C probe (`target/gso_probe.c`): one `sendmsg` with `UDP_SEGMENT` of 32 x 1468 B + a 4 B tail, drained with `recvmmsg(32, 4096-byte slots)` exactly like the datapath | The kernel segments before delivery: 32 datagrams of 1468 B **in order**, then the tail, message lengths exact. No truncation, no re-assembly, `UDP_GRO` not involved |
| **#3 `GSO_MAX_BYTES` / segment size disagrees with the inner MTU, silent desync** | same probe, plus `gso_stress`: 2000 super-packets x 32 segments (66 000 datagrams) vs the same volume by `sendmmsg`, both with a trailing odd frame | Identical: 66 000 datagrams, 0 gaps, 0 duplicates, 0 reordering, both modes. Segment size 1468 = 32 B WG header + 1420 B inner + 16 B tag is exactly what the peer already received per-datagram |
| **#2 The smoltcp actor is woken once and drains one frame per wakeup** | read `tun.rs::run_stack_core`: step 1 drains `pending_frame` **then** loops `frame_src.try_next()` up to 512 frames before polling; the channel is `tokio::sync::mpsc` with cap 2048 | Not the shape. No "poll once then sleep": a 32-frame burst is fully drained in one iteration. (The outbound pump likewise does one `recvmmsg(32)` then one `iface.poll`) |
| **loss / drops / AEAD failures** | `/proc/net/snmp` Udp counters, AEAD reject counts, receiver datagram counts; plus the sequence-number probe above | Zero drops, zero rejects, counts exact — confirmed, and it is *why* the sequence probe was needed: the damage was ordering, which no drop counter can show |
| **per-datagram kernel cost (the reason GSO was wanted)** | `WG_NO_GSO_TX=1` (both egresses per-datagram), 3 invocations x 5 rounds | 118.8–126.6 MB/s, 17.6–17.7 CPU s/GB. GSO is worth +70 % and 8 s/GB; it was never the problem |

## Fix

One change, applied to both copies of the helper
(`crates/flux-outbound/src/wireguard.rs` and `crates/flux-inbound/src/wireguard.rs`,
which are deliberately independent): the leftovers are flushed **before** the
super-packet that would overtake them, and the flush takes a sub-slice instead of
cloning each leftover into a new `Vec`.

```rust
// Nothing may overtake the frames that precede this run.
if flush < i {
    sent += flush_singles(socket, fd, batch, &datagrams[flush..i], dst).await;
    flush = i;
}
match self.send(socket, fd, &datagrams[i..j], dst).await { ... }
```

When GSO is refused (`Ok(false)`/`Err`) the run simply stays in the ordinary
datagrams, still in order, and the process-wide fallback is unchanged. The
inbound now always uses the GSO path; `WG_NO_GSO_TX=1` still turns it off for the
whole datapath, and a kernel without `UDP_SEGMENT` costs one rejected cmsg and
then nothing.

Cost of the fix: at most one extra `sendmmsg` per burst (the tail frame), and it
removes an allocation per leftover. Measured effect: none — the fast path got
*faster* (see below), because the old code cloned every leftover.

### Regression test

`send_burst_preserves_datagram_order` in both crates: a loopback UDP socket pair,
a burst shaped like a window edge (`300 B`, five `1468 B`, `700 B`), and an
assertion on the (tag, length) sequence the receiver observes. Verified to fail on
the pre-fix emission order with exactly the defect:

```
left:  [(2,1468) x5, (1,300), (3,700)]
right: [(1,300), (2,1468) x5, (3,700)]
```

`tests/test_wireguard_half_close.rs` was added for the half-close gate: the peer
replies only after reading the client's FIN, so every received byte proves the
reply travelled back on a half-closed tunnel.

## Before / after

WireGuard path, one stream, byte-verified, 256 MiB per round, 3 rounds per
invocation, load average 5–6 on a 16-CPU box:

| | min | median | max | CPU s/GB | RSS |
|---|---|---|---|---|---|
| pre-fix, inbound GSO on (collapsing) | 47.8 | 76.7 | 110.0 | 9.8–11.3 | 40–43 MiB |
| pre-fix, inbound sendmmsg (shipped until now, 64 MiB rounds) | 118.8 | 122.2 | 126.6 | 17.6 | 27 MiB |
| **post-fix, inbound GSO on** | **189.1** | **213.0** | **217.6** | **8.9–9.5** | **24 MiB** |

Five separate invocations, post-fix: medians 214.7, 216.0, 206.8, 198.9, 213.0;
per-round minimum 189.1, maximum 217.6, 15/15 rounds byte-verified.
Corroborating runs on the same binary: 13 invocations x 5 rounds at 64 MiB
(192–217 MB/s, two load-induced outliers at 175.8 and 125.6 taken while another
agent's test suite ran — the same rounds' `flux direct` control path varied
±15 %, which is this machine's noise band, and neither outlier reproduced in 15
further rounds); and 9 rounds at 256 MiB (191.4–213.0) with no stall.
RTT is unchanged (105–116 µs p50), connect setup unchanged (0.42–0.48 ms p50).

Stability argument for the gate: the failure mode was a *probability of
reordering per burst*; the fix removes reordering by construction (the sender
cannot emit datagram *n+1* before datagram *n*), and the instrumented build
confirms `gaps=0, dups=0` over a full transfer. There is no timer, no window and
no burst-size threshold left in the path that could produce a bimodal result.

## Gates

Verbatim, on the shipped tree:

```
$ cargo test --test test_wireguard_inbound
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p flux-protocol --lib wireguard
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 92 filtered out

$ cargo test --test test_singbox_interop
test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test --test test_wireguard_half_close
test test_wireguard_half_close_reply_after_fin ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo clippy -p flux-outbound -p flux-inbound --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 7.62s
```

## Notes for the next cycle

* The outbound egress has had this bug since GSO was introduced (it is the same
  loop, and its burst shapes include odd ACK frames in front of full-size data),
  so the "known good" 143 MB/s path was silently reordering the inner stream too.
  It never collapsed because that direction faces a 256 KiB receive buffer, which
  tolerates the holes; the client's is 64 KiB.
* The audit log's "Open: the inbound-GSO stall" section still says "reproducible,
  mechanism unknown" and the call-site comment it refers to has been replaced.
  Whoever owns `docs/audit-log.md` should point that section at this file.
* Any future burst sender on this path needs the same invariant, and it is cheap
  to check: the order of the datagrams handed to the kernel must equal the order
  of the inner TCP stream. `send_burst_preserves_datagram_order` is the guard.
