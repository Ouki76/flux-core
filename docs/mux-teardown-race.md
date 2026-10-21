# The smux teardown race: `mux stream closed before the server status byte`

Investigation of the one-off `test_mux_vless_flux_to_singbox` failure recorded in
[`audit-log.md`](audit-log.md) ("Open: a rare mux teardown race").

```
thread 'test_mux_vless_flux_to_singbox' panicked at tests/test_mux_interop.rs:252:10:
read echo: Custom { kind: InvalidData, error: "mux stream closed before the server status byte" }
```

## Verdict

1. **The observed failure is a legitimate session-level teardown, not a premature
   close by us.** The set of things that can close a session is closed and
   enumerable (section 2), and inside that test none of the mux layer's own
   teardown paths can fire: no explicit close, no pool eviction, no drop of the
   session, no idle timeout inside a 10 s deadline, and a peer that does not send
   malformed frames. What remains is the transport going away (peer EOF, or a
   read/write/flush error on the socket). We cannot say *which* transport event
   it was, because the old error did not record it — that is now fixed.
2. **A real defect was found anyway, and it is in the error itself**: the same
   message was produced for four different events, one of which it described
   *falsely* (it claimed the status byte never arrived when it had). It was also
   reported as `InvalidData` ("corrupt data") rather than an EOF, which is what
   retry policy keys off.
3. **A second, genuinely different defect was found by reading the teardown
   paths**: `open_stream()` could register a stream on a session that was closing
   *after* `close()` had cleared the stream map. The stream's only sender then
   stayed alive in a map nobody drains, so the stream's first read waited
   forever instead of failing. Not what was observed (that would have been a
   hang, not this error), but it is a real lost-wakeup-shaped bug and it is fixed.
4. The failing interleaving is now reproduced deterministically (4 tests, no
   timing luck). The one-off itself is **diagnosable, not explained with
   certainty**: the next occurrence prints the reason the session was torn down,
   how many streams it stranded, whether a FIN arrived and how much of the reply
   had been read.

## 1. The teardown paths, as read

* `remote_eof` is set in exactly one place, `MuxStream::poll_next_event`: on
  `StreamEvent::Fin` (peer half-closed this stream) and on `StreamEvent::None`
  (the sender was dropped — session gone, or this stream was reset). Buffered
  `Data` events are always delivered before the channel reports its end (tokio
  mpsc keeps queued items after the sender drops), and `poll_read` drains
  `read_buf` before polling the channel again. So "no status byte received" is a
  real statement about the wire, and a status byte that arrived before a
  teardown is never lost — which is what made the truncation case below
  diagnosable.
* `Shared::close()` is the only session teardown. It flips the flag, records the
  reason, clears the `streams` map (dropping every sender), wakes shutdown
  waiters and wakes writers parked on the frame queue or on window credit.
  Its callers: `peer closed the connection` (read returned 0), `read error`,
  `idle session timeout`, `malformed frame header`, oversized frame, control
  frame carrying a payload, payload read failure/timeout, `peer sent data on
  stream 0`, SYN towards a client, `write error`, `flush error`,
  `session dropped` (`Drop for MuxSession`), and `accept loop finished` (server
  only). Nothing else closes a session.
* **`close()` versus in-flight writes.** Writers parked on the frame queue
  (`park_out`) or on peer credit (`park_credit`) are woken and re-check
  `is_closed()`, returning `BrokenPipe`. A `poll_write` that had already reserved
  a channel permit may still enqueue its frame; the writer task exits on
  shutdown before draining, so the frame is dropped — correct, the stream is
  gone. A detached `send_frame_or_defer` FIN retry ends when the writer exits and
  drops `out_rx` (its `send` returns `Err`). No writer is left parked.
  `Drop for MuxSession` closes first and *then* aborts the worker tasks; that can
  drop a partially written buffer, which is teardown, not a stream-level event.
* **`Drop` for `MuxStream`** sends `FIN` (retried from a task if the queue is
  full), clears the deferred-EOF bookkeeping and unregisters. **`Drop` for
  `MuxSession`** closes with `session dropped` and aborts the reader/writer.
  Note the ownership shape: a `MuxStream` holds `Arc<Shared>`, *not*
  `Arc<MuxSession>`, so the last `Arc<MuxSession>` dropping closes the session
  under its in-flight streams. Today only `MuxClient`'s pool holds sessions and
  the outbound holds the pool, so this is not reachable in the interop test — but
  it is the one remaining hazard of that shape, and it now reports
  `session closed: session dropped`.

## 2. Interleavings that can produce the message

| # | Interleaving | Legitimate? | Old error said |
|---|---|---|---|
| A | Peer closes the transport (EOF) before writing anything for this stream | yes — peer really left | "closed before the server status byte" |
| B | Local socket read error / RST while the reply was pending | yes | same |
| C | Local write or flush error (peer already gone) | yes | same |
| D | Peer sends `FIN` for this stream, session stays up (stream refused) | yes, stream-local | same |
| E | Peer writes status `1` + **truncated** varint/message, then FIN/EOF | yes, but we *had* the status byte | same — **factually false** |
| F | Session resets the stream (receive-buffer overflow) while the session stays healthy | our policy, stream-local | same — blames nothing, blames wrongly |
| G | `MuxSession` dropped (pool eviction / shutdown) mid-stream | teardown by design | "session closed: session dropped" (now) |
| H | Lost wakeup in `poll_read` | would be a bug | cannot produce this message — it would hang. Verified absent: every `Pending` path registers the caller's waker via `poll_recv`, and dropping the sender wakes receivers |
| I | `open_stream`/`register` racing `close()` | **bug (hang)** | n/a — the stream hung instead of erroring |
| J | Frames for unknown/closed stream ids, duplicate SYN | ignored, like smux | cannot produce it |

A–F all produced the byte-identical message before the fix. That is the bug
class: one message for six events, one of them (E) a false statement, and one
(F) a stream-local reset dressed up as a session loss.

Why the observed one is A/B/C and not F: the failing test's streams carry 13 B
and 8 KiB payloads, one frame each (the peer's `MaxFrameSize` is 32 KiB), while
the client queue is 8 frames deep, and the application reads immediately — the
receive-buffer reset cannot fire. And it is not G: `MuxClient` and its pool
outlive every stream in that test. So the session died from a transport event.

## 3. Deterministic reproduction

`tokio::io::duplex` fake peers that speak the wire format and stop at chosen
points, all in `crates/flux-protocol/src/mux.rs` (unit tests, no timers, no
sing-box, no load):

| Test | Interleaving |
|---|---|
| `session_teardown_before_the_status_byte_names_the_reason` | A: peer reads SYN+request, drops the transport |
| `stream_fin_before_the_status_byte_says_the_session_is_alive` | D: peer FINs the stream, session stays up |
| `truncated_error_reply_reports_the_partial_status` | E: status `1`, 12-byte message announced, 2 bytes sent, then FIN |
| `stream_reset_during_the_handshake_does_not_blame_the_session` | F: two-slot queue overflowed mid-handshake |
| `a_stream_registered_after_teardown_is_refused_not_leaked` | I: `register` after `close` |

## 4. Fix (minimal, wire format untouched)

* `Shared` records a `CloseInfo { reason, open_streams }` **before** the senders
  are dropped (`close_info`, mux.rs:401), so a stream woken by the drop can
  report why. `open_streams` is reset to 0 at teardown so the counter cannot go
  stale.
* `MuxStream::closed_before_status_error()` (mux.rs:1260) builds the error from
  the handshake stage (`no status byte received` / `waiting for the message
  length` / `n/m error-message bytes`), the number of response bytes delivered,
  whether a FIN was seen, and the session's recorded teardown. It is an
  `UnexpectedEof`, not `InvalidData` (`smux_eof`, mux.rs:158).
* `Shared::register` (mux.rs:516) re-checks `is_closed()` **while holding the
  map lock that `close()` clears** and returns `false`; `open_stream` fails with
  `session closed` instead of handing out a stream that can only hang, and
  `handle_syn` gets the same guard.
* `tests/test_mux_interop.rs`: a stream that never received a single response
  byte was never served, so `assert_stream_roundtrip` retries **once** on
  exactly that shape (`is_session_teardown_before_reply`) and prints the
  teardown. Protocol rejections, partially received replies, stream resets and a
  second teardown still fail the test.

Wire format: unchanged — no frame, preface, status byte or stream id was touched.

## 5. Before/after

Against `HEAD`'s `mux.rs` with only the new tests applied:

```
test mux::tests::a_stream_registered_after_teardown_is_refused_not_leaked ... FAILED
test mux::tests::session_teardown_before_the_status_byte_names_the_reason ... FAILED
test mux::tests::stream_fin_before_the_status_byte_says_the_session_is_alive ... FAILED
test mux::tests::stream_reset_during_the_handshake_does_not_blame_the_session ... FAILED
test mux::tests::truncated_error_reply_reports_the_partial_status ... FAILED
thread '...session_teardown_before_the_status_byte_names_the_reason' panicked at:
assertion `left == right` failed: a session that went away is an unexpected EOF, not corrupt data:
mux stream closed before the server status byte
  left: InvalidData
 right: UnexpectedEof
test result: FAILED. 27 passed; 5 failed; 0 ignored; 0 measured; 61 filtered out
```

With the fix: `32 passed; 0 failed`.

## 6. What the next occurrence will print

```
mux stream 3 closed before the server status byte (no status byte received;
0 response byte(s) received; session closed: peer closed the connection
(1 stream(s) open at teardown))
```

The reason string is one of the `close()` sites listed in section 1, so the next
occurrence names its own cause instead of requiring another investigation.

## 7. Open, outside this change

* `tests/common/mod.rs`: `NEXT_TCP_PORT` restarts at `TEST_PORT_BASE` in every
  test *process*, and the probe can only see ports that are already bound. Two
  test binaries in a full-workspace run can therefore hand out the same port and
  one of them connects to the other's daemon — which presents as a transport
  teardown exactly like A/B/C. Not proven for this instance, but it is the one
  known source of `AddrInUse` in these tests (audit-log records two).
* `docs/audit-log.md` still lists this flake as open; the entry should be
  updated to point here.
* `MuxStream` keeping its `MuxSession` alive (section 1, last bullet) would make
  pool eviction unable to kill an in-flight stream, at the cost of delaying
  `MuxSession::drop`. Left alone deliberately: not reachable today and it changes
  teardown semantics.