//! XTLS Vision (`xtls-rprx-vision`) padding framing.
//!
//! Vision hides the length signature of the start of a connection: the TLS
//! ClientHello (and the VLESS header that precedes it) are wrapped in frames
//! whose content length is padded to a random size, after which the connection
//! switches to raw pass-through.
//!
//! # Wire format
//!
//! Frames are exchanged only until the TLS handshake finishes; everything after
//! that phase is unframed. Each frame is:
//!
//! ```text
//! [UUID: 16 bytes]        first frame of a direction only
//! [command: 1 byte]       0x00 Continue, 0x01 End, 0x02 Direct
//! [contentLen: u16 BE]
//! [paddingLen: u16 BE]
//! [content: contentLen bytes]
//! [padding: paddingLen zero bytes]
//! ```
//!
//! `Continue` means another frame follows; `End`/`Direct` terminate the padded
//! phase, so the receiver treats the remainder of the stream as raw. The UUID
//! prefix lets the receiver recognise the mode (and identify the user); it is
//! sent once per direction.
//!
//! Padding uses the reference parameters `[900, 500, 900, 256]`: with long padding
//! requested and `contentLen < 900`, `paddingLen = rand(500) + 900 - contentLen`,
//! otherwise `paddingLen = rand(256)`.
//!
//! This follows Xray's `XtlsPadding`/`XtlsUnpadding` (XTLS/Xray-core,
//! `proxy/proxy.go`) byte for byte. Interoperability is covered by
//! `tests/test_singbox_interop.rs::test_interop_vision_*`, which run against a
//! real `xray` binary in both directions.

use rand::RngCore;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// Continue: another padded frame follows.
pub const VISION_CMD_CONTINUE: u8 = 0x00;
/// End: the padded phase is over, the remainder is raw.
pub const VISION_CMD_END: u8 = 0x01;
/// Direct: like `End`; the sender additionally switches to direct copy.
pub const VISION_CMD_DIRECT: u8 = 0x02;

// Xray's default padding parameters (`testseed`).
const PAD_LONG_THRESHOLD: usize = 900; // testseed[0]
const PAD_LONG_RANGE: usize = 500; // testseed[1]
const PAD_LONG_BASE: usize = 900; // testseed[2]
const PAD_SHORT_RANGE: usize = 256; // testseed[3]

/// command + contentLen + paddingLen.
const FRAME_HEADER: usize = 5;
const UUID_LEN: usize = 16;
/// Largest content chunk placed in a single frame.
const MAX_CONTENT: usize = 8 * 1024;

/// Encodes the protobuf flow addon for the VLESS request header.
///
/// Wire format: tag 1, wire type 2 (`0x0a`), length-delimited string.
pub fn encode_vision_addons() -> Vec<u8> {
    let flow_bytes = VISION_FLOW.as_bytes();
    let mut buf = Vec::with_capacity(2 + flow_bytes.len());
    buf.push(0x0a); // protobuf tag: field 1, wire type 2
    buf.push(flow_bytes.len() as u8);
    buf.extend_from_slice(flow_bytes);
    buf
}

/// Chooses the padding length for a frame, mirroring `XtlsPadding`.
fn padding_len(content_len: usize, long: bool) -> usize {
    // A per-thread CSPRNG seeded once from the OS, not a syscall per draw. Vision
    // pads every frame, and at 8 KiB frames the previous `OsRng` meant one
    // `getrandom()` per 8 KiB of payload — the dominant cost of the whole Vision
    // path. The padding only has to be unpredictable to a remote observer, which a
    // per-thread CSPRNG still is.
    let mut rng = rand::thread_rng();
    if content_len < PAD_LONG_THRESHOLD && long {
        ((rng.next_u32() as usize) % PAD_LONG_RANGE) + PAD_LONG_BASE - content_len
    } else {
        (rng.next_u32() as usize) % PAD_SHORT_RANGE
    }
}

/// Appends one frame to `out`.
fn encode_frame(
    out: &mut Vec<u8>,
    uuid: Option<[u8; UUID_LEN]>,
    command: u8,
    content: &[u8],
    long_padding: bool,
) {
    if let Some(uuid) = uuid {
        out.extend_from_slice(&uuid);
    }
    let pad = padding_len(content.len(), long_padding);
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(pad as u16).to_be_bytes());
    out.extend_from_slice(content);
    // Padding must be unpredictable. A run of zero bytes is itself a fingerprint
    // (and pins `contentLen` exactly), which defeats the point of the padding.
    // Xray fills it from a pooled buffer whose contents are arbitrary; random
    // bytes are at least as good.
    if pad > 0 {
        use rand::RngCore;
        let start = out.len();
        out.resize(start + pad, 0);
        rand::rngs::OsRng.fill_bytes(&mut out[start..]);
    }
}

/// True when `buf` starts a TLS ApplicationData record (`0x17 0x03 0xNN`).
fn is_tls_appdata(buf: &[u8]) -> bool {
    buf.len() >= 3 && buf[0] == 0x17 && buf[1] == 0x03
}

/// True when `buf` starts a TLS handshake record (`0x16 0x03 0xNN`).
fn is_tls_handshake(buf: &[u8]) -> bool {
    buf.len() >= 3 && buf[0] == 0x16 && buf[1] == 0x03
}

// ---------------------------------------------------------------------------
// Bidirectional vision stream
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UnpadState {
    /// Not enough bytes buffered yet to tell whether frames are in use.
    Initial,
    /// Reading the 5-byte frame header.
    Header,
    /// Copying `content_left` payload bytes out.
    Content,
    /// Discarding `padding_left` padding bytes.
    Padding,
    /// Padded phase over: pass everything through verbatim.
    Raw,
}

/// A stream with Vision padding, used by both peers.
///
/// Xray pads the *outgoing* handshake of each direction and strips padding from
/// the incoming one, so a single type carries both roles: the write side frames
/// until it sees the first TLS ApplicationData record, the read side unpads until
/// it sees an `End`/`Direct` frame.
pub struct VisionStream<S> {
    inner: S,
    /// The user UUID, used both as the 16-byte frame prefix and for matching.
    uuid: [u8; UUID_LEN],

    // ---- write state
    /// The UUID-prefixed padding frame has not been written yet.
    uuid_pending: bool,
    /// Still framing rather than raw pass-through.
    padding_phase: bool,
    /// The END frame has been queued, so the peer's reader is in raw mode and
    /// everything this side writes from now on must be copied verbatim.
    direct: bool,
    /// Scratch buffer reused for every encoded frame.
    enc_buf: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    /// Bytes of the caller's buffer the pending frame accounts for.
    plain_len: usize,

    // ---- read state
    state: UnpadState,
    command: u8,
    content_left: usize,
    padding_left: usize,
    inbuf: Vec<u8>,
    in_pos: usize,
    out: VecDeque<u8>,
}

impl<S> VisionStream<S> {
    /// Creates a vision stream for the given user UUID.
    pub fn new(inner: S, uuid: [u8; UUID_LEN]) -> Self {
        Self {
            inner,
            uuid,
            uuid_pending: true,
            padding_phase: true,
            direct: false,
            enc_buf: Vec::new(),
            pending: Vec::new(),
            pending_pos: 0,
            plain_len: 0,
            state: UnpadState::Initial,
            command: VISION_CMD_CONTINUE,
            content_left: 0,
            padding_left: 0,
            inbuf: Vec::new(),
            in_pos: 0,
            out: VecDeque::new(),
        }
    }

    fn in_avail(&self) -> usize {
        self.inbuf.len() - self.in_pos
    }

    fn in_slice(&self) -> &[u8] {
        &self.inbuf[self.in_pos..]
    }

    fn in_advance(&mut self, n: usize) {
        self.in_pos += n;
        if self.in_pos == self.inbuf.len() {
            self.inbuf.clear();
            self.in_pos = 0;
        }
    }

    /// Transitions after a frame's content and padding are fully consumed.
    fn end_of_frame(&mut self) {
        if self.command == VISION_CMD_CONTINUE {
            self.state = UnpadState::Header;
        } else {
            self.state = UnpadState::Raw;
        }
    }
}

/// Backwards-compatible names for the two roles.
pub type VisionClientStream<S> = VisionStream<S>;
/// Backwards-compatible names for the two roles.
pub type VisionServerStream<S> = VisionStream<S>;

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Direct copy (Xray's `switchToDirectCopy`): after the END frame both sides
        // are in raw mode, so there is nothing to frame and the bytes go straight
        // through — no per-write allocation, no 8 KiB chunking, no padding.
        if this.direct && this.pending.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        loop {
            // Flush a frame that was only partially written.
            while this.pending_pos < this.pending.len() {
                let pos = this.pending_pos;
                match Pin::new(&mut this.inner).poll_write(cx, &this.pending[pos..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "vision: inner stream accepted no bytes",
                        )));
                    }
                    Poll::Ready(Ok(n)) => this.pending_pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if !this.pending.is_empty() {
                let consumed = this.plain_len;
                // Hand the allocation back for reuse instead of dropping it.
                this.enc_buf = std::mem::take(&mut this.pending);
                this.pending_pos = 0;
                this.plain_len = 0;
                return Poll::Ready(Ok(consumed));
            }

            if !this.padding_phase {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }

            // Reused across frames: the old code allocated a fresh Vec per frame,
            // which is one heap allocation per 8 KiB of payload.
            let mut encoded = std::mem::take(&mut this.enc_buf);
            encoded.clear();
            encoded.reserve(MAX_CONTENT + 2 * FRAME_HEADER + PAD_LONG_BASE);
            // The first frame of a direction is UUID-prefixed and long-padded,
            // blurring the VLESS header length.
            if this.uuid_pending {
                encode_frame(
                    &mut encoded,
                    Some(this.uuid),
                    VISION_CMD_CONTINUE,
                    &[],
                    true,
                );
            }

            let content = &buf[..buf.len().min(MAX_CONTENT)];
            // The first ApplicationData record ends the handshake and with it the
            // padded phase (Xray's `switchToDirectCopy`). After the END frame the
            // peer's reader switches to raw pass-through, so this side must too:
            // our own reader already does exactly that in `end_of_frame`, and a
            // writer that kept framing would corrupt the stream for a real peer.
            // The padding phase exists to blur the TLS handshake, so it ends as soon
            // as the inner stream stops being one. Waiting specifically for
            // ApplicationData meant that a non-TLS inner stream — the normal case
            // when the transport is already REALITY or TLS — never ended it, and every
            // byte was framed into 8 KiB padded frames forever: `strace` counted 3 691
            // writes of exactly 8 192 bytes for 16 MiB, and this path was the only one
            // where flux spent *more* CPU per byte than sing-box.
            let command = if is_tls_appdata(content) || !is_tls_handshake(content) {
                this.padding_phase = false;
                this.direct = true;
                VISION_CMD_END
            } else {
                VISION_CMD_CONTINUE
            };
            if this.direct && command == VISION_CMD_END && !this.pending.is_empty() {
                continue;
            }
            let long_padding =
                command == VISION_CMD_CONTINUE && (is_tls_handshake(content) || content.is_empty());
            encode_frame(&mut encoded, None, command, content, long_padding);
            this.uuid_pending = false;

            this.pending = encoded;
            this.pending_pos = 0;
            this.plain_len = content.len();
        }
    }

    /// # Invariant
    ///
    /// `pending` is non-empty **only** between a `poll_write` that returned
    /// `Pending` and the caller's retry. Such a call consumed *no* bytes of the
    /// caller's buffer (the contract: `Pending` means "nothing accepted"), so the
    /// buffered frame is not ours to deliver: the caller will resend those bytes.
    ///
    /// That is why `poll_flush`/`poll_shutdown` delegate straight through instead
    /// of draining `pending` — writing it here could send the same plaintext
    /// twice if the caller retries after a flush. Any acknowledged frame is
    /// always fully written before `poll_write` returns `Ok`.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // A peer can stream an unbounded run of 5-byte zero-content frames without
        // ever making the transport return `Pending`, monopolising this executor
        // thread. Yield after a bounded number of frames: a spurious wakeup is
        // harmless, whereas returning 0 filled bytes would mean EOF.
        let mut frames_this_call = 0usize;
        const MAX_FRAMES_PER_POLL: usize = 64;

        loop {
            // 1. Serve already-decoded payload.
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                let chunk: Vec<u8> = this.out.drain(..n).collect();
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            // 2. Progress the state machine with buffered input.
            match this.state {
                UnpadState::Initial => {
                    if this.in_avail() >= UUID_LEN {
                        if this.in_slice().starts_with(&this.uuid) {
                            this.in_advance(UUID_LEN);
                            this.state = UnpadState::Header;
                        } else {
                            // Not a vision peer: forward untouched (this is what
                            // Xray's unpadding does too).
                            this.state = UnpadState::Raw;
                        }
                        continue;
                    }
                }
                UnpadState::Header => {
                    if this.in_avail() >= FRAME_HEADER {
                        let h = &this.in_slice()[..FRAME_HEADER];
                        let command = h[0];
                        let content_left = u16::from_be_bytes([h[1], h[2]]) as usize;
                        let padding_left = u16::from_be_bytes([h[3], h[4]]) as usize;
                        this.command = command;
                        this.content_left = content_left;
                        this.padding_left = padding_left;
                        this.in_advance(FRAME_HEADER);
                        if this.content_left > 0 {
                            this.state = UnpadState::Content;
                        } else if this.padding_left > 0 {
                            this.state = UnpadState::Padding;
                        } else {
                            this.end_of_frame();
                        }
                        continue;
                    }
                }
                UnpadState::Content => {
                    if this.in_avail() > 0 {
                        let n = this.in_avail().min(this.content_left);
                        let chunk = this.in_slice()[..n].to_vec();
                        this.in_advance(n);
                        this.content_left -= n;
                        this.out.extend(chunk);
                        if this.content_left == 0 {
                            if this.padding_left > 0 {
                                this.state = UnpadState::Padding;
                            } else {
                                this.end_of_frame();
                            }
                        }
                        continue;
                    }
                }
                UnpadState::Padding => {
                    if this.in_avail() > 0 {
                        let n = this.in_avail().min(this.padding_left);
                        this.in_advance(n);
                        this.padding_left -= n;
                        if this.padding_left == 0 {
                            this.end_of_frame();
                        }
                        continue;
                    }
                }
                UnpadState::Raw => {
                    if this.in_avail() > 0 {
                        let n = this.in_avail().min(buf.remaining());
                        let chunk = this.in_slice()[..n].to_vec();
                        this.in_advance(n);
                        buf.put_slice(&chunk);
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            if frames_this_call >= MAX_FRAMES_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            frames_this_call += 1;

            // 3. Need more bytes from the transport.
            let mut tmp = [0u8; 16 * 1024];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        // EOF. Report it as clean only when the stream ended on a
                        // frame boundary — otherwise a truncated record would be
                        // delivered to the caller as a normal end of stream, which
                        // looks like a short but valid HTTP body / TLS record.
                        return match this.state {
                            UnpadState::Raw => Poll::Ready(Ok(())),
                            UnpadState::Initial if this.in_avail() == 0 => Poll::Ready(Ok(())),
                            // A non-Vision peer that sent fewer than 16 bytes and
                            // closed: hand those bytes over unchanged instead of
                            // discarding them, then report EOF on the next poll.
                            UnpadState::Initial => {
                                this.state = UnpadState::Raw;
                                let n = this.in_avail().min(buf.remaining());
                                let chunk = this.in_slice()[..n].to_vec();
                                this.in_advance(n);
                                buf.put_slice(&chunk);
                                Poll::Ready(Ok(()))
                            }
                            UnpadState::Header if this.in_avail() == 0 => {
                                Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vision: stream ended inside a frame header",
                                )))
                            }
                            UnpadState::Content if this.content_left == 0 => Poll::Ready(Ok(())),
                            UnpadState::Padding if this.padding_left == 0 => Poll::Ready(Ok(())),
                            UnpadState::Header | UnpadState::Content | UnpadState::Padding => {
                                Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vision: stream ended mid-frame",
                                )))
                            }
                        };
                    }
                    this.inbuf.extend_from_slice(&tmp[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; UUID_LEN] = [
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];

    /// The first emitted frame must carry the UUID, a Continue command, an empty
    /// content and a long padding length (>= 900 total frame size).
    #[tokio::test]
    async fn first_frame_matches_reference_layout() {
        let (client, mut wire) = tokio::io::duplex(64 * 1024);
        let mut vision = VisionClientStream::new(client, UUID);
        // A TLS ClientHello prefix.
        let hello = [0x16u8, 0x03, 0x01, 0x00, 0x40];
        vision.write_all(&hello).await.unwrap();
        vision.flush().await.unwrap();
        drop(vision);

        let mut frame = Vec::new();
        wire.read_to_end(&mut frame).await.unwrap();

        assert_eq!(
            &frame[..UUID_LEN],
            &UUID,
            "first frame must be UUID-prefixed"
        );
        assert_eq!(frame[UUID_LEN], VISION_CMD_CONTINUE);
        let content_len = u16::from_be_bytes([frame[UUID_LEN + 1], frame[UUID_LEN + 2]]) as usize;
        let padding_len = u16::from_be_bytes([frame[UUID_LEN + 3], frame[UUID_LEN + 4]]) as usize;
        assert_eq!(content_len, 0, "the UUID frame carries no content");
        let total = UUID_LEN + FRAME_HEADER + content_len + padding_len;
        assert!(
            total >= PAD_LONG_BASE,
            "UUID frame must be padded to at least {PAD_LONG_BASE} bytes, got {total}"
        );
        let _ = client;
    }

    /// Client → server round-trip through the padded phase.
    #[tokio::test]
    async fn roundtrip_through_padded_phase() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let mut writer = VisionClientStream::new(server_io, UUID);
        let mut reader = VisionStream::new(client_io, UUID);

        let payload = b"\x16\x03\x01\x00\x10hello-vision!!".to_vec();
        let payload2 = payload.clone();
        let writer_task = tokio::spawn(async move {
            writer.write_all(&payload2).await.unwrap();
            writer.flush().await.unwrap();
            // Keep the stream open.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_exact(&mut got),
        )
        .await
        .expect("read timed out")
        .unwrap();
        assert_eq!(got, payload);

        writer_task.await.unwrap();
    }

    /// After an ApplicationData record the sender stops framing and the receiver
    /// passes the raw bytes straight through.
    #[tokio::test]
    async fn switches_to_raw_after_handshake() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let mut writer = VisionClientStream::new(server_io, UUID);
        let mut reader = VisionStream::new(client_io, UUID);

        let handshake = b"\x16\x03\x01\x00\x04hs!!".to_vec();
        let appdata = b"\x17\x03\x03\x00\x05hello".to_vec();
        let raw_after = b"RAWDATA".to_vec();
        let (h, a, r) = (handshake.clone(), appdata.clone(), raw_after.clone());
        tokio::spawn(async move {
            writer.write_all(&h).await.unwrap();
            writer.write_all(&a).await.unwrap();
            writer.write_all(&r).await.unwrap();
            writer.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });

        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while got.len() < handshake.len() + appdata.len() + raw_after.len() {
            match tokio::time::timeout_at(deadline, reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        let mut expected = handshake;
        expected.extend_from_slice(&appdata);
        expected.extend_from_slice(&raw_after);
        assert_eq!(got, expected);
    }

    /// A peer that is not in vision mode (wrong UUID prefix) is passed through
    /// untouched instead of being misparsed.
    #[tokio::test]
    async fn non_vision_peer_passes_through() {
        let (mut peer, server_io) = tokio::io::duplex(64 * 1024);
        let mut reader = VisionStream::new(server_io, UUID);
        let plain = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let p = plain.clone();
        tokio::spawn(async move {
            peer.write_all(&p).await.unwrap();
            peer.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let mut got = vec![0u8; plain.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_exact(&mut got),
        )
        .await
        .expect("read timed out")
        .unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn addons_encode_the_flow_name() {
        let addons = encode_vision_addons();
        assert_eq!(addons[0], 0x0a);
        assert_eq!(addons[1] as usize, VISION_FLOW.len());
        assert_eq!(&addons[2..], VISION_FLOW.as_bytes());
    }

    #[test]
    fn padding_respects_reference_parameters() {
        // Long padding: content < 900 yields a total of at least 900.
        for _ in 0..64 {
            let pad = padding_len(10, true);
            assert!((890..=1389).contains(&pad), "unexpected long padding {pad}");
            assert!(10 + pad >= PAD_LONG_BASE);
        }
        // Short padding: always < 256.
        for _ in 0..64 {
            assert!(padding_len(10, false) < PAD_SHORT_RANGE);
        }
        // Content >= 900 never gets long padding.
        for _ in 0..64 {
            assert!(padding_len(2000, true) < PAD_SHORT_RANGE);
        }
    }
}

#[cfg(test)]
mod eof_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stream cut mid-frame must surface as `UnexpectedEof`, not as a clean end
    /// of stream (which downstream code would treat as a complete message).
    #[tokio::test]
    async fn truncated_frame_is_an_error_not_clean_eof() {
        let uuid = [7u8; 16];
        let (mut peer, our_side) = tokio::io::duplex(4096);
        let mut stream = VisionStream::new(our_side, uuid);

        tokio::spawn(async move {
            // A valid UUID prefix followed by a header promising 100 content bytes,
            // then only a fragment of that content.
            let mut frame = Vec::new();
            frame.extend_from_slice(&uuid);
            frame.push(VISION_CMD_CONTINUE);
            frame.extend_from_slice(&100u16.to_be_bytes()); // contentLen
            frame.extend_from_slice(&0u16.to_be_bytes()); // paddingLen
            frame.extend_from_slice(&[0xAB; 10]); // only 10 of 100 bytes
            let _ = peer.write_all(&frame).await;
            let _ = peer.shutdown().await;
        });

        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// A non-Vision peer that sends a short final message and closes must have
    /// those bytes delivered (the documented pass-through fallback).
    #[tokio::test]
    async fn short_non_vision_tail_is_delivered() {
        let (mut peer, our_side) = tokio::io::duplex(4096);
        let mut stream = VisionStream::new(our_side, [7u8; 16]);

        tokio::spawn(async move {
            let _ = peer.write_all(b"short").await; // 5 < 16 bytes
            let _ = peer.shutdown().await;
        });

        let mut out = Vec::new();
        let res = stream.read_to_end(&mut out).await;
        let _ = res;
        assert_eq!(&out, b"short", "short non-vision tails must not be dropped");
    }
}

#[cfg(test)]
mod padding_phase_guard {
    //! The bug this guards against shipped for a long time and was invisible except in
    //! the benchmark: Vision only left its padding phase on TLS ApplicationData, so a
    //! non-TLS inner stream — the normal case under REALITY or TLS — was framed into
    //! 8 KiB padded frames for the entire life of the tunnel. `strace` showed 3 691
    //! writes of exactly 8 192 bytes per 16 MiB and this was the only path where flux
    //! spent *more* CPU per byte than sing-box.

    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Default)]
    struct Counting {
        writes: Vec<usize>,
    }

    impl AsyncWrite for Counting {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push(buf.len());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Counting {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    const UUID: [u8; UUID_LEN] = [
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];

    /// A plain (non-TLS) payload must end the padding phase, and a 64 KiB write after
    /// that must reach the transport as one write of the same size — not as eight
    /// 8 KiB padded frames.
    #[tokio::test]
    async fn a_non_tls_payload_ends_the_padding_phase() {
        let inner = Counting::default();
        let mut stream = VisionStream::new(inner, UUID);

        // First write ends the padding phase (a non-TLS payload). Whatever it does,
        // the write after it must be raw pass-through.
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"start")
            .await
            .expect("first write");
        let after_phase = stream.inner.writes.len();

        let payload = vec![0x42u8; 64 * 1024];
        tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
            .await
            .expect("write payload");

        let writes = stream.inner.writes[after_phase..].to_vec();
        assert_eq!(
            writes,
            vec![payload.len()],
            "after the padding phase, a {} byte write must reach the transport verbatim; \
             got {writes:?} (padded frames are ≤ {MAX_CONTENT} bytes plus headers)",
            payload.len()
        );
    }
}
