# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.4] - 2026-10-22

Audit cycles 4–8. Five cycles of testing the security-sensitive surfaces against
their specifications found **60 defects**, all proved by tests that fail without the
fix, and one latency bug that made every Hysteria 2 connection slow.

### Performance

- **Hysteria 2 connections: 5.16 s → 5.5 ms.** Authentication used the `h3` crate's
  client, which needed ~5 s to deliver a response our own server produced in ~1 ms.
  The auth exchange is one request whose status code we read and discard, so it is
  now implemented on raw quinn — the same code path the tunnel streams already used.

### Fixed (security)

Seventy-plus defects across the transport and inbound surfaces. The most serious:

- **WebSocket (13 groups)**: `poll_shutdown` never sent a close frame; a bare TCP EOF
  looked like a clean end; masking was never checked against our role; no UTF-8
  validation; a frame declaring 2^63-1 bytes parked the stream forever.
- **gRPC (13 groups)**: trailers were never read, so `grpc-status: 7` (aborted)
  arrived as a clean end of stream — a failed or truncated tunnel looked successful.
  The compression flag was never read, and the server accepted **any** HTTP/2
  request as a tunnel.
- **ShadowTLS (10)**: no replay protection at all (a captured hello authenticated
  again); the SNI allow-list was never enforced; three tag comparisons were
  non-constant-time; a decoy record split across polls consumed the next record's
  bytes.
- **httpupgrade (6)**: the client accepted any 2xx as a protocol switch, so a
  captive portal became a tunnel and ciphertext was written into someone's HTML; the
  status was matched with `contains("101")`; CRLF in the configured host or path
  split the request on the wire.
- **VLESS/Trojan/VMess inbounds (6)**: an unknown command was answered with the
  "authenticated, go ahead" header; a UDP request to the mux destination was parsed
  as mux frames; Trojan's UDP frame terminator was read and discarded; VMess
  "repaired" an unknown security byte by falling back to AES-128-GCM.
- **TUIC/Hysteria 2 inbounds (22)**: an unbounded UDP association table per
  connection, a multi-user oracle, a **panic** on a malformed Hysteria 2 datagram,
  destinations of 64+ bytes silently dropped because a varint was read as a byte,
  and a password compared with `==`.
- **Lifecycle (4)**: a half-started instance leaked listeners; **a failed reload
  candidate kept accepting half the connections for the old config**; `start()`
  twice spawned a second accept loop per inbound; a restart silently stopped
  refreshing remote rule sets.
- **Remote rule sets**: a broken feed could erase working rules (`</html>` parsed as
  an IP-CIDR, and any bare word as a domain), and an empty refresh replaced a
  working set with nothing — silently sending traffic to the final outbound.
- **Management API**: `Content-Length` was last-one-wins and `Transfer-Encoding`
  ignored — the classic request-smuggling pair.
- **REALITY**: the ClientHello had no ALPN, a louder non-browser signal than
  anything in its extension set.

### Added

- `docs/audit-log.md` now records eight cycles with per-defect evidence, the
  measurement mistakes made along the way (a withdrawn 205 MB/s figure from a
  bimodal configuration, a stale-binary measurement), and every remaining gap.
- Test count 478 → 826.

## [1.3.3] - 2026-10-22

Audit cycle 3. The weakest measured path was WireGuard; it is now at 143 MB/s and
the remaining ceiling is documented rather than guessed at.

### Performance

- **WireGuard: 93.6 → 143 MB/s (+53 %), CPU 21.4 → 13.5 s/GB (−37 %).**
  `ring`'s ChaCha20-Poly1305 replaces the RustCrypto crate for data packets (the
  profile pointed at Poly1305 *per-message key setup*, not bulk throughput; a
  null-cipher build isolated AEAD at 5.9 → 2.2 s/GB), and UDP GSO
  (`UDP_SEGMENT`) coalesces equal-sized datagrams on the outbound egress so N
  datagrams cost one syscall, one route lookup and one skb — the kernel floor per
  datagram drops from 5.0 CPU s/GB (`sendto`) to 0.80. GSO is sender-side only, so
  a stock WireGuard peer sees ordinary datagrams; the first rejected control
  message disables it permanently and falls back to `sendmmsg`, and
  `WG_NO_GSO_TX=1` forces it off.
- The TUN "window" finding does **not** transfer: a measured sweep of
  `WG_TCP_BUF` (64 KiB → 512 KiB) is worth +4 % with CPU per byte rising, because
  this pump already keeps a burst in flight. Documented with the table; the stale
  comment claiming "no effect" was replaced by the measurement.

### Fixed

- **smux:** the message a stream reports when it dies during the handshake was
  identical for six distinct events, one of them described falsely, and was typed
  `InvalidData` instead of `UnexpectedEof`. It now names the handshake stage,
  response bytes received, FIN-vs-dead-channel and the session's teardown reason.
  Reading those paths also found a real hang — `open_stream` racing `close()` left
  its only sender in a map nobody drains, so the first read waited forever.
- **Test infrastructure:** the port allocator probed with `bind()` only, which
  cannot see a listener held with `SO_REUSEPORT` (every flux listener sets it), so
  a leftover process was handed out twice and produced `AddrInUse`. The probe now
  also connects: a free port refuses, an occupied one accepts.

### Corrected

A figure published in an earlier revision of `docs/audit-log.md` (205.6 MB/s,
9.34 s/GB) was **withdrawn**: it came from a configuration with GSO on the inbound
egress, which is bimodal (12/12 runs at 205–215 MB/s without it, 12/12 at
9.8–25.6 MB/s with it). The shipped code reverts that path and measures 143 MB/s.
The mistake and its lesson are recorded in the log.

### Known limits

At MTU 1420 the kernel charges ~4.25 CPU s/GB per direction for one datagram per
packet, so ~190 MB/s is the ceiling for a per-datagram design even with batching;
the same code at inner MTU 8192 reaches 231 MB/s, which is why a configurable inner
MTU is the next lever (default stays 1420, the interop value).

## [1.3.2] - 2026-10-22

Audit cycle 2. Coverage was measured for the first time (53 % of lines), then
four workstreams attacked the weakest measured numbers. The dominant finding was
that three separate slownesses had the *same* root cause: the `aes-gcm` crate
drives AES one block at a time and never pipelines AES-NI.

### Performance

- **Shadowsocks-2022, Shadowsocks-AEAD and VMess: 4.5–4.6× faster.**
  `aes-gcm` 0.10 manages 1.75 GB/s where `ring`'s fused AES-GCM reaches
  11.07 GB/s for the identical in-place call. On the protocol loopback:
  SS-2022 805 → 3792 MB/s, SS-AEAD 748 → 3323 MB/s, VMess 767 → 3676 MB/s, with
  CPU per GB falling from ~1.3 to ~0.27. ChaCha20-Poly1305 was switched too
  (ring is 1.9× faster). Key schedules are now built once per session, the stream
  paths seal in place inside the output buffer, and byte-for-byte compatibility is
  proved by 41 sing-box interop tests.
- **REALITY: 375 → 729 MB/s, 4.78 → 2.14 CPU s/GB.** Same root cause. REALITY is
  now *faster* than the rustls TLS path (654 MB/s) and at parity with unencrypted
  VLESS. Per-record allocations were removed too, but measured as neutral — the
  AEAD backend was the whole win.
- **TUN: +33 % at MTU 1500 (349 → 466 MiB/s) and +65 % at jumbo (767 → 1268).**
  The flow was *window*-limited, not syscall-limited: a socket buffer is the
  advertised window and must cover the bandwidth-delay product, not a segment
  count. The floor went from 64 KiB to 256 KiB, which costs 4× per-connection
  memory (128 → 512 KiB) — revert by changing `TCP_SOCKET_BUF_MIN`. Also: an
  inbound frame is now header-peeked instead of fully copied, the pump task is
  merged into the stack actor, and receive buffers are pooled.
- SS-AEAD UDP no longer derives a subkey and builds a cipher per datagram: the
  receive cipher is cached per peer salt and the send path seals in place instead
  of allocating three buffers.

### Added

- **Coverage measurement**: an isolated toolchain in `~/.local/rustup` (the system
  toolchain is untouched) with `-C instrument-coverage`, recorded in
  `docs/audit-log.md`. Baseline: 53.25 % of lines.
- **`pipeline.rs` had no tests at all** (304 lines, the composition point for every
  security and framing layer). Nine now cover a real listener round trip through
  raw, WebSocket, HTTPUpgrade, HTTP/2 and gRPC framing, two composed layers, and
  path-mismatch rejection.

### Notes

- `chacha20poly1305` is no longer a `flux-transport` dependency (ring replaced it).
- Benchmark numbers in `README.md` were stale by one cycle; refreshed.

## [1.3.1] - 2026-10-22

Continuous audit, cycle 1. Three workstreams (smux security, DNS security, both
userspace datapaths) plus hardening found 22 defects; every fix is proved by a
test that fails without it.

### Fixed (security)

- **smux: 8 defects**, including a writer that could hang forever (a `Notify`
  future was dropped while returning `Pending`, deregistering the waiter), a
  leaked stream slot per UDP association, one detached task per FIN frame under
  backpressure, a silently dropped half-close FIN, and a buffering bound that
  allowed 64x the configured budget.
- **DNS: 6 defects**, including 83x reflection amplification (the relay ignored
  the client's UDP payload size), SERVFAIL/REFUSED being cached as "does not
  resolve" for up to an hour, a trailing-dot FQDN bypassing every split-DNS rule
  (a DNS leak), and fake-IP allocations outside their own range.
- **DNS hardening:** per-source-IP query rate limiting on the listener (a DNS port
  is an amplification vector) and a hard budget of 64 upstream exchanges per
  client query, so a CNAME chain cannot amplify with the number of servers.
- **WireGuard:** an unbounded proxy→socket queue held ~500 MiB of resident memory
  during a 512 MiB transfer (measured 1 byte of RSS per byte moved).

### Fixed (throughput / memory)

- **TUN `mtu` was a no-op** — it sized a buffer and was logged, but the device was
  never programmed, so the kernel always segmented at 1500. Now applied via
  `SIOCSIFMTU`, and the default is 9000 (jumbo): **324 → 745 MiB/s**, CPU
  **6.7 → 3.4 s/GB**. Also: socket buffers scale with the MTU (jumbo previously
  collapsed to 58 MiB/s because one segment filled the window), smoltcp's 10 ms
  delayed ACK is disabled (holding an ACK holds the client's window shut), and the
  egress path no longer drops a frame when the device momentarily refuses a write.
- **WireGuard: 58 → 93.6 MB/s (+46 %), CPU 50.3 → 21.4 s/GB (−53 %), RSS on a
  512 MiB transfer 503 → 27 MiB.** The datapath was syscall- and scheduling-bound,
  not crypto-bound: ~4 syscalls per packet because every packet crossed three
  tasks per direction. In-place AEAD (zero allocation), `recvmmsg`/`sendmmsg`
  batching and merging the pump tasks cut syscalls per datagram 2.1 → 0.08 and
  scheduler wakeups 1.03 → 0.27.

### Added

- `tests/test_malformed_input_resilience.rs`: every inbound survives garbage on its
  socket and keeps serving real clients.
- `tests/test_api_auth.rs`: the API's negative paths (no token, wrong token, wrong
  scheme, cross-origin query token) and proof that a rejected request does not
  execute its side effect.
- `scripts/config_field_audit.py`: finds configuration fields that parse and are
  then ignored (all 59 are consumed today).
- `docs/audit-log.md`: the audit protocol, the baseline table and every cycle's
  findings with the command that produced them.

### Measured

`scripts/soak.sh 240` — 3,349,277 requests, 0 errors, 26 GB proxied, RSS flat
(12.5 → 12.6 MB), file descriptors and threads bounded.

## [1.3.0] - 2026-10-22

Closes the four gaps that remained after the 1.2.1 review — a missing feature, an
untested ingress class, and two silent data-corruption bugs found by finally
measuring the data paths.

### Added

- **Stream multiplexing (smux v1)**, verified byte-for-byte against sing-box
  1.11.4 rather than guessed: the session preface, the 8-byte little-endian frame
  header with a **u32** stream id, the `sp.mux.sing-box.arpa:444` signalling
  destination, the per-stream `[flags][socksaddr]` preamble and the optional
  padding layer. Available for VLESS, VMess, Trojan and Shadowsocks, inbound and
  outbound, over any carrier (verified over TCP and WebSocket), including muxed
  UDP. Off by default.
- **VLESS UDP now interoperates in both directions.** `VLESS_CMD_UDP` carries a
  bare `[len][payload]` stream; the old code prefixed every datagram with a SOCKS
  address (Trojan's framing), so VLESS UDP had never worked against sing-box or
  Xray. `VLESS_CMD_PACKETADDR` (what sing-box emits for UDP) is implemented too.
- **DNS: CNAME chains** (followed within one response and across re-queries,
  bounded and loop-safe, minimum TTL), IPv6 fake-IP (`fc00::/18`), PTR,
  APA/TXT/MX/HTTPS-SVCB parsing with unknown types preserved rather than dropped,
  SOA-derived negative TTL, and verbatim forwarding of unmodelled query types.
- **Real end-to-end tests for TUN, REDIRECT and TPROXY**, executed inside a user
  network namespace (`unshare --user --map-root-user --net`) instead of silently
  skipping. Six tests, each asserting a real byte-for-byte round trip.
- **Conformance and interop coverage**: 4 REALITY tests against the real `xray`
  binary (plain and with Vision, both directions), and `h2spec` 2.6.0 against the
  H2 listener — 108/108 applicable cases pass.
- **Benchmark matrix**: concurrency (1/64/512/2048 streams), TLS/REALITY cost
  isolation, WireGuard, TUN; plus release/benchmark/coverage CI workflows,
  `cargo-semver-checks`, a local workflow linter and `docs/quality.md`.

### Fixed (data corruption)

- **REALITY duplicated data under load.** When the transport returned `Pending`
  while writing an encrypted record, the record was buffered and the plaintext was
  *not* acknowledged; on the retry the same buffer was encrypted and appended a
  second time. Sustained transfers diverged within 0.3–11 MB. A `pending_unacked`
  counter now acknowledges the buffered record exactly once. Covered by a
  512 KiB byte-exact record-boundary test.
- **WireGuard truncated replies on half-close.** `TcpClose` cleared the unsent
  queue and closed the socket, so an application that called
  `shutdown(SHUT_WR)` lost the tail of its own response (a 4 MiB echo stalled at
  314 KiB). The connection now sends FIN only after the queue has drained.
- **WireGuard dropped inner frames silently** when the stack channel was full
  (`try_send`); it now applies backpressure.
- **H2 server tore down the whole connection** on any per-stream error, so a peer
  saw `ECONNRESET` instead of `RST_STREAM`/`GOAWAY`; extra streams are refused
  individually.
- **SOCKS5 BIND was rejected by closing the socket** without a reply, leaving the
  client waiting for its own timeout (RFC 1928 §6 requires REP `0x07`). Fixed in
  both the SOCKS and the mixed inbound.
- The TUN datapath dropped queued proxy data, truncated the tail on close, never
  forwarded a peer FIN and dropped frames under backpressure — four separate
  defects found by the new e2e tests.

### Changed

- Config rejects unknown keys (`deny_unknown_fields`), so a misspelled key is an
  error instead of a silently disabled feature.
- `dns.fakeip` gains `inet6_range`.

## [1.2.1] - 2026-10-21

Second-pass audit: an independent review of everything added in 1.1.0/1.2.0 by two
reviewers with fresh eyes, plus a deterministic fuzz run over the new parsers.
Twelve defects were found and fixed — four of them in code written during
1.1.0/1.2.0 itself — together with three test-coverage gaps that had let them hide.

### Fixed (security)

- **SS-2022 UDP replay window was advanced before authentication.** A forged
  datagram carrying a valid session id and a huge packet id pushed the window
  forward, so every later genuine packet looked stale — the tunnel's UDP stopped
  working after a single spoofed packet. Authentication now happens first; a
  regression test proves it.
- **Fake-IP UDP leaked an endpoint per datagram.** The dispatcher's fast path
  rebuilt the cache key from the raw destination instead of the reverse-mapped
  effective one, so with Fake-IP every datagram created a new association, an
  orphaned reply task and a duplicated reply stream.
- **TUIC stream-mode AUTH was replayable for 300 s** despite the comment claiming
  otherwise; the inbound now remembers accepted `(uuid, timestamp)` pairs in a
  bounded set.
- **Rule-set redirects followed cross-origin hops** (SSRF): a hostile rule-set host
  could redirect the fetch at `127.0.0.1` or a metadata endpoint. Redirects to a
  different origin are now refused.
- **Config typos were silently ignored.** `deny_unknown_fields` is on for the root
  objects, so `fake_ip_range` (instead of `fakeip.inet4_range`) is reported instead
  of quietly disabling Fake-IP.
- `constant_time_eq` now uses `subtle::ConstantTimeEq`; the hand-rolled loop had no
  constant-time guarantee. The last local copy (VLESS) is gone.

### Fixed (correctness)

- **The DNS inbound could not survive SIGHUP**: its UDP listener had no
  `SO_REUSEADDR`/`SO_REUSEPORT`, so the reload's new instance failed to bind and the
  whole configuration was rejected. Covered by a reload test that fails without the
  fix.
- **AAAA questions were answered with an `A` record** in plain-resolver mode
  (ANCOUNT=1, rtype A).
- **A DNS inbound re-answered response-shaped packets**, so two nodes pointed at
  each other's listener ping-ponged forever. Queries only now.
- **Over-long or empty DNS labels were silently dropped**, turning `a.<70B>.corp`
  into `a.corp` — a crafted name resolved as a *different* domain. Invalid names are
  rejected up front.
- **Negative DNS caching captured transport failures**, contradicting its own
  contract: a timeout was cached as "does not resolve" for the whole TTL. Error
  kinds are preserved; `contains_cached` no longer reports a negative entry as a
  usable resolution.
- **Vision reported a truncated frame as a clean EOF**, so a half-received record
  looked like a valid end of stream. It also dropped a non-Vision peer's final
  message when it was shorter than 16 bytes.
- **Vision padding was all zero bytes** — itself a length fingerprint. It is random
  now (`OsRng`), matching Xray's use of arbitrary pooled bytes.
- The Vision reader had unbounded work per `poll_read` (a peer streaming 5-byte
  frames could monopolise the executor thread).
- **Group outbounds did not delegate `udp_endpoint_per_destination`**, so a VMess
  member shared one association across all destinations.
- A failed `send_packet` never evicted its endpoint; later datagrams went into a dead
  socket.
- **The DNS inbound spawned one task per datagram without bound**; concurrency is
  capped and the per-packet `DnsInbound`/broadcast-channel construction is gone.
- **Config env expansion ran on comments**, so a commented-out `# secret: ${DB_PASS}`
  aborted the load. Comments are stripped (JSON) or skipped (YAML) first.
- Rule-set fetch: one deadline across all redirect hops (was 30 s per hop), chunked
  bodies terminate at `0\r\n\r\n` instead of waiting for EOF, `Host` carries a
  non-default port, and a missing literal `include` is an error instead of a no-op.
- `include` chains are depth-limited; `${:-x}` (empty variable name) and nested
  `${A:-${B}}` are errors instead of silently producing the wrong value.

### Changed

- Trojan password-hash comparison is byte-exact (it was case-folding). Both sing-box
  and Xray compare the raw 56 lowercase-hex bytes, so the old permissiveness accepted
  what the reference implementations reject; interop is unaffected.

### Added

- Fuzz regression tests for every parser added in 1.1.0/1.2.0: Vision stream reader,
  Salamander, DNS question, HPACK Huffman, SS-2022 UDP, TUIC stream AUTH.

## [1.2.0] - 2026-10-21

Third audit pass: every remaining finding from the crate-by-crate review is
addressed, so there are **no known limitations left**. Behaviour changed in a few
places; this release deliberately drops backward compatibility with earlier
flux-core builds where that was the honest fix.

### Changed (behaviour, not backward compatible)

- **XTLS Vision now implements the real `xtls-rprx-vision` wire format** (UUID
  prefix, `command | contentLen u16 | paddingLen u16`, `[900, 500, 900, 256]`
  padding, raw pass-through after the handshake). Verified against a real
  `xray` binary in both directions. Vision peers built on the old private framing
  cannot talk to it — which is the point.
- **Undefined `${VAR}` in a configuration is now an error** instead of expanding
  to `""`. Use `${VAR:-default}` for an optional value.
- **TUIC stream-mode AUTH** uses a timestamped token (300 s window) instead of a
  static, never-expiring `HMAC(password, uuid)`.
- `--format` now actually forces the parser for the root config file.

### Added

- **Fake-IP DNS responder** (`dns.listen`, protocol `dns`): answers `A` from the
  pool, NODATA for `AAAA`, and makes domain-based routing work for clients that
  resolve names themselves.
- `cargo audit` / `cargo deny` run locally against the RustSec database; two
  vulnerabilities fixed (RUSTSEC-2026-0382, RUSTSEC-2026-0381).

### Fixed (security)

- **SS-2022 UDP replay**: duplicate `(session_id, packet_id)` datagrams were
  accepted for the whole timestamp window; a sliding window now rejects them.
  Per-session subkeys/AEADs are cached instead of re-derived per datagram.
- **WireGuard handshake replay**: the responder remembers the greatest TAI64N per
  peer and rejects anything not strictly newer.
- **VMess replay**: AEAD auth IDs are replay-filtered (120 s window).
- **TUIC stream auth** is bound to a timestamp, so a captured frame cannot be
  reused.
- **Empty credential lists** for VLESS/Trojan are rejected instead of accepting
  everyone.
- Per-session DNS and DoH/DoT/DoQ limits: negative answers are cached briefly,
  transport failures are not; a stalled upstream can no longer wedge resolution.
- Config: invalid `port_range` values, glob patterns that match nothing and
  malformed rule-set URLs are errors; hostile durations clamp instead of
  overflowing; rule-set cache file names are sanitised (no path traversal).

### Fixed (correctness)

- **REALITY record-size mimicry** was shifted by one record when the target sent
  no ChangeCipherSpec (EE's slot was overwritten by the Certificate size).
- **HTTP proxy**: absolute `https://` requests are rejected instead of being sent
  in cleartext to port 80; the rewritten request no longer emits a doubled CRLF;
  the CONNECT status code is parsed rather than substring-matched.
- **WebSocket**: masked frames delivered at most 16 KiB while consuming up to
  64 KiB (silent data loss); the client now verifies `Sec-WebSocket-Accept` and
  parses the status code; the server validates
  `Upgrade`/`Connection`/`Sec-WebSocket-Version`.
- **HTTPUpgrade** requires `GET` and an `Upgrade: websocket` header.
- **HTTP/2**: non-2xx tunnel responses are rejected; zero capacity is an explicit
  error instead of a lost wake-up.
- **Fragmentation** no longer latches off when the ClientHello arrives split
  across writes, and never reports more bytes consumed than supplied.
- **VMess** UDP associations are per destination; the dispatcher caches UDP
  endpoints per destination for protocols that need it.
- **SOCKS5 outbound** UDP control channel travels over its own dialer (layered
  transports no longer fall back to plaintext).
- **Hysteria 2**: the UDP demuxer is rebuilt on reconnect; the HTTP/3 auth budget
  is 10 s instead of 500 ms (3 RTTs cannot fit in 500 ms on most paths).
- **WireGuard**: malformed keys/addresses are configuration errors; runt datagrams
  are rejected; the session table is bounded with collision-checked indices.
- **TPROXY** reports socket-option failures instead of silently routing to itself.
- **Process-name routing** matches only established sockets and bounds its scan
  queue.
- DNS wire format rejects over-long labels; HPACK Huffman decoding uses a flat
  table (was a SipHash lookup per bit) and treats EOS correctly; varints are read
  in one call.

### Removed (dead code)

- Duplicate `constant_time_eq` implementations (five copies) → one shared helper in
  `flux-common`.
- Dead `unwrap_server_stream`, `build_heartbeat_frame`, `VLESS_CMD_MUX`,
  `SALT_LEN`-style leftovers and the never-read `ShadowTlsClientConfig::insecure`
  field, plus unused h3 control-stream mutex.

## [1.1.0] - 2026-10-21

Full code audit: correctness, security, resource-exhaustion and performance fixes.
**Behaviour changes** are listed first — read them before upgrading.

### Changed (behaviour)

- **QUIC outbounds (`hysteria2`, `tuic`) no longer disable certificate
  verification by default.** Omitting the `security` block used to mean
  `insecure: true`; it now means "verify against the system roots". Servers with
  self-signed certificates must opt in explicitly with
  `security: { type: tls, insecure: true }`. When no `server_name` is given, the
  carrier host name is used as SNI (unless it is a bare IP).
- **Salamander obfuscation is now the real Hysteria 2 wire format** (8-byte salt,
  BLAKE2b-256(psk ‖ salt) keystream) instead of a private scheme (16-byte salt,
  BLAKE3). Config-compatible, but older flux-core peers can no longer talk to it —
  which is the point: the previous format interoperated with nothing.
- **Management API**: `PUT/POST /api/v1/outbounds/{group}` no longer acts as
  `/select`; the documented `/select` suffix is required.
- **`https://` proxy share links** now produce a TLS-wrapped HTTP proxy instead of
  a cleartext one on port 443. `security=reality` without `pbk=` is now a hard
  configuration error instead of a silent downgrade to plaintext VLESS.
- **TUN inbound failures are reported**: `start()` returns an error when the
  device cannot be opened instead of logging and returning success.
- Remote rule sets reject compressed responses instead of mis-parsing them, and
  warn when a fetch yields zero usable rules.

### Fixed (security)

- **Unauthenticated remote panic in the WireGuard inbound**: a 4-byte `h4`
  datagram indexed `pkt[4..8]` out of bounds and killed the only receive loop,
  permanently disabling the inbound (DoS). Runts are now rejected before parsing.
- **Management API cross-origin bypass**: the CSRF guard compared `Origin` by
  prefix, so `http://localhost.attacker.tld` was treated as local and could drive
  state-changing endpoints when no secret was configured. The authority is now
  parsed and the host compared exactly.
- **Empty API secret**: `secret: ""` (or an undefined `${VAR}`) defeated the
  unsafe-bind guard and let `Authorization: Bearer ` authenticate. Empty secrets
  are now treated as unset.
- **API SSRF guard failed open**: a delay-probe target whose name did not resolve
  was allowed through; it now fails closed.
- **API listener no longer sets `SO_REUSEPORT`** (same-uid port hijack).
- **gRPC framing memory DoS**: a 5-byte header could make the proxy buffer 4 GiB.
  Message length is now capped at 16 MiB.
- **REALITY certificate parsing panic**: a hostile certificate ending in the
  Ed25519 OID prefix panicked the dial task before the REALITY HMAC check.
- **VMess client panic** on a peer-controlled response-header length, and VMess
  silently accepting unknown `security` values as AES-128-GCM.
- WireGuard session table is capped and receiver indices are collision-checked.

### Fixed (correctness)

- **Salamander obfuscation** now interoperates with sing-box in both directions
  (two new interop tests).
- **Clash rule-set lines with `,no-resolve`** were folded into the value, made
  unparseable, and silently dropped — i.e. fail-open routing. Values are now the
  second field and modifiers are ignored; unsupported types are counted.
- **Remote rule-set refresh clobbered the config's inline lists** (`domain`,
  `ip_cidr` given alongside `type: remote`); it now merges.
- **Chunked HTTP responses** for remote rule sets are decoded (the `1a2b` size
  lines were being parsed as rules); `Content-Length` is honoured.
- **SOCKS5 method negotiation** compared against a zero-filled 256-byte array, so
  "no auth" was always accepted; the `METHOD_NO_ACCEPTABLE` branch was dead.
- **TUIC stream-mode handshake had no timeout** (slow-loris); one absolute
  deadline now covers the whole handshake.
- **DNS could hang forever**: DoH/DoT/DoQ had no timeouts and held their pool
  mutex indefinitely, wedging all later lookups. Every transport step and the
  overall resolution now have deadlines.
- **Dead UDP endpoints are evicted** from the dispatcher cache instead of being
  reused forever, and Shadowsocks datagram decode errors no longer kill the reply
  pump.
- TUN: idle UDP listener sockets are reaped (each held 512 KiB of smoltcp
  buffers; a port sweep could allocate them without limit), the UDP listener count
  is capped, proxy→socket buffering is bounded (real backpressure instead of
  unbounded growth), the stack actor no longer busy-spins at 100% CPU once its
  frame channel closes, and graceful FIN is no longer converted into a RST.
- Remote rule-set fetch timeouts now cover connect/resolve, and redirects are
  resolved relative to the request.

### Performance

- **Buffer pool scrubs on release again (audit cycle 10).** A later audit showed
  the un-scrubbed pool handed a recycled buffer back to the next caller at full
  length with the previous tenant's bytes still in it — no in-tree consumer read
  them, but the invariant was only a doc comment. The memset costs ~6 % of one core
  on the UDP receive path; a sized release (`release_used(buf, len)`) would make it
  ~10 ns instead of ~471 ns and is the recorded optimisation. Superseded entry:
  buffer pool no longer scrubs on release. Every release performed a full
  `memset` of the buffer; the 64 KiB packet pool did so once *per UDP datagram*.
  Measured: **1015 ns → 527 ns** per acquire/release cycle (48% faster).
- **Buffer-pool shard cursor is thread-local** instead of one shared atomic,
  removing cache-line ping-pong between worker threads.
- **UDP dispatch fast path no longer clones** the outbound tag and effective
  destination on every datagram; routing and endpoint lookup are borrowed.
- Added `examples/bench_udp.rs`, resource-cost columns (CPU s/GB, peak RSS) and
  interleaved median reporting to `examples/bench_native.rs`, plus a buffer-pool
  criterion benchmark.

### Testing

- Interop suite made deterministic: ports are allocated below the ephemeral range
  (kernel-assigned ports could steal a reserved one), concurrent sing-box daemons
  are gated (reentrant, so tests that start two cannot deadlock), and every
  failure now prints the daemon's captured stderr instead of an opaque
  "Connection refused".
- New regression tests: WireGuard runt datagrams, Salamander obfs interop (both
  directions), VMess oversized response header, REALITY truncated certificate,
  ruleset `no-resolve`/merge/unsupported types, chunked decoding, URI TLS
  downgrades, API `/select` strictness, buffer-pool reuse.
- 281 tests pass; `cargo clippy --all-targets -- -D warnings` and `cargo fmt
  --check` are clean.

### Fixed (second audit pass)

- **`--format` was accepted and silently ignored**: `load_any_config` dropped the
  argument, so forcing `yaml`/`json` on an extension-less file had no effect. The
  format is now threaded through `load_with_includes`; included files keep
  extension-based detection so mixed trees still work.
- **TLS client connectors are cached**: the `CryptoProvider` and the ~150-entry
  root certificate store were rebuilt on every dial (every DoT/DoH query, latency
  probe and ruleset fetch). Measured **7.95 µs → 60 ns** per dial.
- **HTTP/2**: a non-2xx response to the tunnel request was spliced in as body data
  (silent corruption) — now rejected; zero send capacity returned `Pending`
  (lost wake-up → possible stall) — now a `BrokenPipe` error.
- **WebSocket**: masked frames delivered at most 16 KiB while consuming up to
  64 KiB — silent data loss and stream desync. The chunk size is now clamped to
  what the unmask buffer can carry.
- **TLS fragmentation** latched into pass-through mode when the ClientHello
  arrived split across writes; the leading bytes are now stashed and the decision
  deferred until the record header is complete. `poll_write` also no longer
  reports more bytes consumed than the caller passed.
- **VMess**: AEAD auth IDs are now replay-protected (a captured header could be
  re-injected for 120 s). VMess UDP associations are per-destination — the
  dispatcher used to send every destination's datagrams over the first
  destination's association.
- **SOCKS5 outbound** UDP control channel bypassed its own dialer, so a layered
  (TLS/WS/REALITY-wrapped) SOCKS outbound silently spoke plaintext for UDP.
- **Hysteria 2 outbound**: the per-connection UDP demuxer was cached across
  reconnects, so after a reconnect every datagram reply was dropped.
- **Empty credentials no longer mean "open to everyone"** for VLESS and Trojan
  (protocols where the secret *is* the only authentication).
- **HTTP proxy**: absolute-form `https://` requests are rejected instead of being
  sent in cleartext to the wrong port; the rewritten request no longer emits a
  duplicated CRLF before the body; the CONNECT status code is parsed instead of
  substring-matched.
- **Malformed WireGuard keys / `local_address`** are now hard configuration
  errors instead of being silently dropped.
- **TPROXY** reports a failure to enable `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR`
  instead of running a non-transparent listener that routes to itself.
- **Process-name routing**: only established sockets are matched (a same-port
  listener could be mis-attributed) and the scan queue is bounded (a connection
  flood triggered one `/proc` walk per source port).
- **REALITY record-size mimicry** was shifted by one record when the target sent
  no ChangeCipherSpec: the EncryptedExtensions slot was overwritten by the
  Certificate size and every subsequent record was padded to the wrong length, so
  the server flight no longer matched the decoy. Slots now follow the fixed
  `[SH, CCS, EE, Cert, CV, Fin]` layout. Covered by a byte-level regression test
  that reproduces the shift with the old indexing.

### Known limitations

_(none — see the third audit pass below)_

### Fixed (third audit pass)

- **XTLS Vision now implements the real `xtls-rprx-vision` wire format.** The
  previous framing was a private 4-byte-header scheme that no other client could
  read. The implementation now follows Xray's `XtlsPadding`/`XtlsUnpadding`
  exactly (UUID-prefixed first frame, `command | contentLen u16 | paddingLen u16`,
  `[900, 500, 900, 256]` padding parameters, raw pass-through once the handshake
  finishes) and is verified against a real `xray` binary in **both** directions.
- **Fake-IP is now implemented** instead of inert: a new DNS inbound
  (`dns.listen`, protocol `dns`) answers `A` from the pool, returns NODATA for
  `AAAA`, and the dispatcher maps the address back to the domain so
  domain-based rules apply to clients that resolve names themselves. Covered by
  `tests/test_fakeip_dns.rs` end to end.
- **SS-2022 UDP anti-replay**: duplicate `(session_id, packet_id)` datagrams were
  accepted for the whole timestamp window. A sliding replay window now rejects
  them, and per-session subkeys/AEADs are cached instead of being re-derived
  (BLAKE3 KDF + AES key schedule + three allocations) for every datagram.
- **WireGuard handshake replay**: the responder now remembers the greatest TAI64N
  per peer and rejects anything not strictly newer, as the protocol requires; a
  captured initiation could previously be replayed indefinitely.
- **Supply chain**: two vulnerabilities found by `cargo audit` and fixed —
  RUSTSEC-2026-0382 (rustls-webpki 0.103.15 → 0.103.16) and RUSTSEC-2026-0381
  (webpki-roots 1.0.9 → 1.0.10). `cargo audit` and `cargo deny check` now run
  green (`advisories ok, bans ok, licenses ok, sources ok`).

## [1.0.0] - 2026-10-14

Production-ready release of the flux-core proxy core.

### Added

- **Protocols (inbound & outbound)**: VLESS (REALITY with full XTLS compatibility, `xtls-rprx-vision` flow, TLS, WebSocket), Trojan (SHA-224 over TLS), VMess (AEAD, AES-128-GCM / ChaCha20-Poly1305), Shadowsocks & Shadowsocks-2022 (AEAD, Blake3 2022-ciphers, replay filter), TUIC v5 (spec-compliant QUIC, BBR), Hysteria 2 (spec-compliant QUIC, HTTP/3 auth via built-in H3/QPACK, Brutal pacer, port-hopping, Salamander obfuscation), SOCKS5 (CONNECT + UDP ASSOCIATE, user/password auth), HTTP/HTTP CONNECT, mixed SOCKS5+HTTP auto-detect inbound.
- **Transparent inbounds**: TUN (`smoltcp` userspace TCP/IP stack with retransmission, congestion control, RFC 793 out-of-order reassembly, UDP relay), REDIRECT (`SO_ORIGINAL_DST`), TPROXY (`IP_TRANSPARENT`).
- **WireGuard (AmneziaWG dialect)**: server inbound (Noise IK responder, MAC1 anti-DoS screening, TAI64N freshness, per-peer allow-list with PSKs and `allowed_ips`, session roaming & reaping) and outbound tunnel (embedded `smoltcp` stack, single-demux socket reader, per-flow reply routing, transparent rekey, ICMP echo-reply).
- **Layered transport architecture**: orthogonal Carrier → Security → Framing → Protocol pipeline composition for every inbound/outbound, including REALITY camouflage for Shadowsocks and multi-security cascades.
- **Routing & DNS**: rule engine (domain exact/suffix/keyword, IP CIDR, ports, network, invert), GeoIP/GeoSite rule sets with O(1) hash lookups, **remote URL rule sets** (background fetch, size caps, disk cache, `update_interval` hot-swap, failure-safe), built-in DNS with Fake-IP (`198.18.0.0/15`) and DoH (RFC 8484) client.
- **Outbound groups**: Selector, URLTest (tolerance thresholding), Fallback (healthcheck probing), LoadBalance (round-robin / consistent hashing).
- **Configuration**: YAML/JSON/JSONC with auto-detection, `$include` with glob patterns, `${ENV_VAR}` / `${ENV_VAR:-default}` expansion, proxy-URI outbounds (VLESS/Trojan/SS/SOCKS5/HTTP links), strict dependency-graph validation with cycle detection, `flux-core check` validation subcommand.
- **Performance**: Linux zero-copy `splice(2)`, buffer pooling, SO_REUSEPORT listeners, sharded DNS cache, `LTO=fat` release profile.
- **Security hardening**: per-inbound rate limiting (per-IP token bucket + global concurrent cap, reject before allocation), handshake timeouts on every TCP inbound, bounded API request sizes, anti-replay windows (SS-2022, WireGuard), management API secret enforcement with constant-time comparison, CSRF/cross-origin rejection before dispatch, Prometheus `/api/v1/metrics` endpoint.
- **Management API** (`/api/v1/*`): version, status, metrics (Prometheus), traffic, inbounds, DNS resolve, route test, rules, outbounds (list/select/delay-probe), connections (list/close).
- **Testing infrastructure**: 233 automated tests including 35 sing-box interop tests (TUIC v5 / Hysteria 2 / REALITY), deterministic parser fuzz regression suite, 8 libFuzzer targets, WireGuard e2e (UDP+TCP echo, rogue peer), perf/memory leak tests, 24h soak harness (`scripts/soak.sh`).
- **Operations**: multi-stage Dockerfile (distroless-slim runtime, healthcheck via `flux-core check`), CI pipeline (fmt, clippy `-D warnings`, full test suite with sing-box, release build).

### Security

- OsRng (CSPRNG) entropy across WireGuard, Vision, Hysteria 2, ShadowTLS.
- Supply-chain gate: `cargo audit` + `cargo deny` in CI; fixed RUSTSEC-2026-0285 (rustls 0.23.46), upgraded lru 0.13 → 0.18.5 (unsound advisories).
- Hysteria 2 Salamander obfuscation is now fully wired (custom quinn runtime obfuscating every UDP datagram; plain clients are silently dropped).
- UDP reply address headers (SOCKS5/Trojan/VLESS/SS) now carry the sender address per spec; VMess UDP inbound implemented (was dispatched on the TCP path).

### Performance

- Per-connection RSS 35.6 → 2.9 KB (boxed cold-path copy futures); 2000 held connections: 77 MB → 13 MB (sing-box: 54 MB).
- splice(2) pipe 64 KB → 256 KB: single-stream throughput now matches/beats sing-box (avg +4.2% head-to-head).
- Hardened Hy2 varint-length DoS caps, Fake-IP /32 underflow fix, strict DNS upstream errors, UDP reply-destination normalization, `select!` arm drop fixes (lost UDP replies / first TCP chunks).

## [0.1.0] - 2026-09-10

Initial development snapshot.
