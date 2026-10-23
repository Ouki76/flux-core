use base64::Engine;
use flux_types::{AsyncStream, FluxError, FluxResult};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Size of the staging buffer used to unmask client frames.
const UNMASK_CHUNK: usize = 16 * 1024;

/// Largest single frame payload this endpoint accepts. RFC 6455 sets no
/// protocol maximum, but a *declared* length must never be trusted far enough
/// to park a tunnel indefinitely behind a peer that will never send the bytes,
/// and no WebSocket peer frames more than a few KiB at a time.
const MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;

/// Cap on a handshake header block, in bytes.
const MAX_HEADER_BYTES: usize = 8192;

/// Close status codes we may emit (RFC 6455 §7.4.1).
const CLOSE_NORMAL: u16 = 1000;
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_INVALID_PAYLOAD: u16 = 1007;
const CLOSE_TOO_BIG: u16 = 1009;

/// Rejects control bytes in anything that ends up on the request line or in a
/// header. A `\r\n` smuggled through the configuration (path, host or a custom
/// header) would terminate the request early and inject a second request into
/// the tunnel, so this runs before a single byte is written.
fn reject_ctl(what: &str, value: &str) -> FluxResult<()> {
    match value.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
        Some(b) => Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("{what} contains control byte 0x{b:02x}: {value:?}"),
        }),
        None => Ok(()),
    }
}

/// Performs client-side RFC 6455 WebSocket handshake over an underlying stream.
pub async fn client_handshake<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> FluxResult<WebSocketStream<S>>
where
    S: AsyncStream + 'static,
{
    // Validate before writing: a poisoned request must never reach the wire.
    let path = if path.is_empty() { "/" } else { path };
    reject_ctl("request path", path)?;
    if !path.starts_with('/') || path.contains(' ') {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!(
                "invalid request path {path:?}: expected an origin-form target such as \"/tunnel\""
            ),
        });
    }
    reject_ctl("host", host)?;
    if host.is_empty() || host.contains(' ') {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("invalid Host value {host:?}"),
        });
    }
    for (k, v) in headers {
        reject_ctl("header name", k)?;
        reject_ctl("header value", v)?;
        if k.is_empty() || k.contains([' ', ':']) {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: format!("invalid header name {k:?}"),
            });
        }
    }

    let nonce: [u8; 16] = rand::random();
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);

    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );

    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("upgrade")
            && !k.eq_ignore_ascii_case("connection")
            && !k.eq_ignore_ascii_case("sec-websocket-key")
            && !k.eq_ignore_ascii_case("sec-websocket-version")
        {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // Read response headers until \r\n\r\n
    let mut resp_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while resp_buf.len() < MAX_HEADER_BYTES {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: "EOF while reading websocket handshake response".into(),
            });
        }
        resp_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "websocket",
        message: "response header too large or missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&resp_buf[..h_end]);
    let mut lines = header_str.lines();
    let first_line = lines.next().unwrap_or("");

    // A real upgrade is exactly `HTTP/1.1 101` (RFC 7230 §3.1.2, RFC 6455
    // §1.3). Matching the code alone would accept a `HTTP/1.0 101` from a
    // captive portal or a shim that never really switched protocols.
    let mut status_parts = first_line.split_whitespace();
    let http_version = status_parts.next().unwrap_or("");
    let status: Option<u16> = status_parts.next().and_then(|s| s.parse().ok());
    if http_version != "HTTP/1.1" || status != Some(101) {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("server did not switch protocols: {first_line:?}"),
        });
    }

    // RFC 6455 §4.2.2: the accept token is SHA-1(key + GUID), base64 encoded.
    let expected_accept = {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_GUID);
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };

    let mut accept_count = 0usize;
    let mut accept_value: Option<&str> = None;
    let mut upgrade_ok = false;
    let mut connection_ok = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_count += 1;
            accept_value = Some(v);
        } else if k.eq_ignore_ascii_case("upgrade") {
            upgrade_ok |= v.eq_ignore_ascii_case("websocket");
        } else if k.eq_ignore_ascii_case("connection") {
            connection_ok |= v
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
        }
    }

    // Exactly one accept token: a duplicated header is ambiguous, and a proxy
    // that appends its own must never be able to overlay ours.
    if accept_count != 1 {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!(
                "expected exactly one Sec-WebSocket-Accept header, found {accept_count}"
            ),
        });
    }
    if accept_value != Some(expected_accept.as_str()) {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: "websocket handshake returned a mismatched Sec-WebSocket-Accept".into(),
        });
    }
    // A 101 without `Upgrade`/`Connection` is not a protocol switch, however
    // good the accept token looks.
    if !upgrade_ok {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: "101 response without 'Upgrade: websocket'".into(),
        });
    }
    if !connection_ok {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: "101 response without 'Connection: Upgrade'".into(),
        });
    }

    let excess_data = resp_buf[h_end..].to_vec();

    Ok(WebSocketStream::new(stream, excess_data, true))
}

/// Performs server-side RFC 6455 WebSocket handshake.
pub async fn server_handshake<S>(
    mut stream: S,
    expected_path: Option<&str>,
) -> FluxResult<WebSocketStream<S>>
where
    S: AsyncStream + 'static,
{
    let mut req_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while req_buf.len() < MAX_HEADER_BYTES {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: "EOF while reading client websocket handshake".into(),
            });
        }
        req_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "websocket",
        message: "request header too large or missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&req_buf[..h_end]);
    let mut lines = header_str.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let http_version = parts.next().unwrap_or("");

    // RFC 6455 §4.1 requires a `GET` over HTTP/1.1 with nothing else on the
    // request line; anything else is an ordinary HTTP request that must not be
    // promoted to a tunnel.
    if method != "GET" {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("invalid websocket method: {method}"),
        });
    }
    if http_version != "HTTP/1.1" {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("invalid websocket request version: {http_version:?}"),
        });
    }
    if parts.next().is_some() {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("malformed request line: {first_line:?}"),
        });
    }
    if path.is_empty() {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("malformed request line: {first_line:?}"),
        });
    }

    if let Some(exp) = expected_path {
        let actual_path = path.split('?').next().unwrap_or(path);
        if actual_path != exp {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: format!(
                    "websocket path mismatch: expected '{}', got '{}'",
                    exp, actual_path
                ),
            });
        }
    }

    let mut client_key: Option<String> = None;
    let mut has_host = false;
    let mut has_upgrade = false;
    let mut has_connection_upgrade = false;
    let mut version_ok = false;
    let mut upgrade_seen = false;
    let mut connection_seen = false;
    let mut version_seen = false;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: format!("malformed header line (no colon): {line:?}"),
            });
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("sec-websocket-key") {
            if client_key.is_some() {
                return Err(FluxError::Protocol {
                    protocol: "websocket",
                    message: "duplicate Sec-WebSocket-Key header".into(),
                });
            }
            client_key = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("host") {
            has_host = true;
        } else if k.eq_ignore_ascii_case("upgrade") {
            // Duplicates are refused rather than merged: with two `Upgrade`
            // headers a front-end proxy and this endpoint can disagree about
            // what was negotiated, which is how an upgrade gets smuggled.
            if upgrade_seen {
                return Err(FluxError::Protocol {
                    protocol: "websocket",
                    message: "duplicate Upgrade header".into(),
                });
            }
            upgrade_seen = true;
            has_upgrade = v.eq_ignore_ascii_case("websocket");
        } else if k.eq_ignore_ascii_case("connection") {
            if connection_seen {
                return Err(FluxError::Protocol {
                    protocol: "websocket",
                    message: "duplicate Connection header".into(),
                });
            }
            connection_seen = true;
            has_connection_upgrade = v
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
        } else if k.eq_ignore_ascii_case("sec-websocket-version") {
            if version_seen {
                return Err(FluxError::Protocol {
                    protocol: "websocket",
                    message: "duplicate Sec-WebSocket-Version header".into(),
                });
            }
            version_seen = true;
            // RFC 6455 §4.2.1: version 13 is the only one in use.
            version_ok = v == "13";
        }
    }

    // A valid upgrade request must carry all of these; otherwise this is an
    // ordinary HTTP request that must not be upgraded (it would let any GET
    // with a key through as a tunnel).
    if !has_host {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: "missing Host header in client request".into(),
        });
    }
    if !has_upgrade || !has_connection_upgrade || !version_ok {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: "invalid websocket upgrade request (missing Upgrade/Connection/Version)"
                .into(),
        });
    }

    let key = client_key.ok_or_else(|| FluxError::Protocol {
        protocol: "websocket",
        message: "missing Sec-WebSocket-Key in client request".into(),
    })?;
    // RFC 6455 §4.1: the key is a base64 encoded 16-byte nonce. An empty or
    // truncated key still yields a well-formed accept token, so it has to be
    // checked rather than merely hashed.
    let key_len = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .map(|k| k.len())
        .unwrap_or(0);
    if key_len != 16 {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("Sec-WebSocket-Key must be base64 of 16 bytes, got {key_len} bytes"),
        });
    }

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID);
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept
    );

    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    let excess_data = req_buf[h_end..].to_vec();
    Ok(WebSocketStream::new(stream, excess_data, false))
}

// ---------------------------------------------------------------------------
// Frame layer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum ReadState {
    Header,
    ControlPayload,
    Payload,
}

/// Incremental UTF-8 validator. RFC 6455 §8.1 requires the *message* to be
/// valid UTF-8, so a partial code point has to be carried between read chunks
/// and across fragment boundaries instead of being judged per fragment.
#[derive(Default, Clone, Copy)]
struct Utf8Check {
    pending: [u8; 4],
    pending_len: usize,
}

/// Length of the UTF-8 sequence introduced by `first`, or 0 if it can never
/// introduce one (continuation byte, overlong lead 0xC0/0xC1, > U+10FFFF).
fn utf8_seq_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

impl Utf8Check {
    /// Feeds the next chunk. Returns false as soon as the message cannot be
    /// valid; an incomplete trailing sequence is held, not rejected.
    fn feed(&mut self, mut bytes: &[u8]) -> bool {
        if self.pending_len > 0 {
            let need = utf8_seq_len(self.pending[0]);
            if need == 0 || self.pending_len >= need {
                return false;
            }
            let take = (need - self.pending_len).min(bytes.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&bytes[..take]);
            self.pending_len += take;
            bytes = &bytes[take..];
            if self.pending_len < need {
                return true;
            }
            if std::str::from_utf8(&self.pending[..need]).is_err() {
                return false;
            }
            self.pending_len = 0;
        }
        match std::str::from_utf8(bytes) {
            Ok(_) => true,
            Err(e) => {
                if e.error_len().is_some() {
                    return false;
                }
                let rest = &bytes[e.valid_up_to()..];
                if rest.len() > self.pending.len() {
                    return false;
                }
                self.pending[..rest.len()].copy_from_slice(rest);
                self.pending_len = rest.len();
                true
            }
        }
    }

    /// True when the message did not end in the middle of a code point.
    fn is_complete(&self) -> bool {
        self.pending_len == 0
    }
}

/// XORs `data` with `key` starting at `offset` in the key. Masking is its own
/// inverse, and `offset` keeps the key phase continuous across chunks of one
/// frame.
fn mask_in_place(key: [u8; 4], offset: usize, data: &mut [u8]) {
    // Four bytes per iteration with a rotated mask, then a tail. The modulo in the
    // original loop is a division per byte unless the optimiser proves it away, and
    // this runs over every payload byte that crosses a masked WebSocket frame.
    let mut k = [0u8; 4];
    for i in 0..4 {
        k[i] = key[(offset + i) & 3];
    }
    let ku32 = u32::from_ne_bytes(k);
    let mut head = data;
    while head.len() >= 4 {
        let (word, rest) = head.split_at_mut(4);
        let v = u32::from_ne_bytes([word[0], word[1], word[2], word[3]]) ^ ku32;
        word.copy_from_slice(&v.to_ne_bytes());
        head = rest;
    }
    for (i, b) in head.iter_mut().enumerate() {
        *b ^= k[i & 3];
    }
}

/// Serialises one frame. A client masks with a fresh random key per frame, a
/// server never masks (RFC 6455 §5.1).
fn build_frame(is_client: bool, opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    encode_frame_into(&mut frame, is_client, opcode, fin, payload);
    frame
}

/// Same as [`build_frame`], appending to an existing buffer: the write path
/// reuses its staging buffer instead of allocating per frame.
fn encode_frame_into(frame: &mut Vec<u8>, is_client: bool, opcode: u8, fin: bool, payload: &[u8]) {
    frame.push(if fin { 0x80 } else { 0x00 } | opcode);
    let mask_bit = if is_client { 0x80 } else { 0x00 };
    let len = payload.len();
    if len <= 125 {
        frame.push(mask_bit | len as u8);
    } else if len <= 65_535 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if is_client {
        let mask: [u8; 4] = rand::random();
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    } else {
        frame.extend_from_slice(payload);
    }
}

/// RFC 6455 §7.4: 1004/1005/1006/1015 are reserved and must never appear on
/// the wire, 0-999 are unused, 1016-2999 unassigned and >4999 out of range.
fn close_code_valid(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

pub struct WebSocketStream<S> {
    inner: S,
    is_client: bool,
    read_state: ReadState,
    header_buf: [u8; 14],
    header_pos: usize,
    header_len: usize,
    // Current frame.
    frame_opcode: u8,
    frame_fin: bool,
    payload_rem: usize,
    mask_key: Option<[u8; 4]>,
    mask_idx: usize,
    /// A control frame payload (always <= 125 bytes) under construction.
    ctl_payload: Vec<u8>,
    // Message state, for fragmentation and UTF-8.
    in_fragment: bool,
    msg_is_text: bool,
    utf8: Utf8Check,
    // Close state. `close_sent` keeps a reply from being emitted twice,
    // `stop_reading` makes EOF sticky once the peer (or a violation) closed us.
    close_sent: bool,
    stop_reading: bool,
    // Pong/close frames we owe the peer.
    pending_ctl: Vec<u8>,
    pending_ctl_pos: usize,
    buffered_excess: Vec<u8>,
    buffered_pos: usize,
    // Robust writer state machine.
    write_buf: Vec<u8>,
    /// Reused staging buffer for unmasking incoming payload.
    staging: Vec<u8>,
    write_pos: usize,
    pending_chunk_len: usize,
}

impl<S> WebSocketStream<S> {
    pub fn new(inner: S, excess: Vec<u8>, is_client: bool) -> Self {
        Self {
            inner,
            is_client,
            read_state: ReadState::Header,
            header_buf: [0u8; 14],
            header_pos: 0,
            header_len: 2,
            frame_opcode: 0x02,
            frame_fin: true,
            payload_rem: 0,
            mask_key: None,
            mask_idx: 0,
            ctl_payload: Vec::with_capacity(125),
            in_fragment: false,
            msg_is_text: false,
            utf8: Utf8Check::default(),
            close_sent: false,
            stop_reading: false,
            pending_ctl: Vec::new(),
            pending_ctl_pos: 0,
            buffered_excess: excess,
            buffered_pos: 0,
            write_buf: Vec::with_capacity(4096),
            staging: vec![0u8; UNMASK_CHUNK],
            write_pos: 0,
            pending_chunk_len: 0,
        }
    }
}

impl<S> WebSocketStream<S> {
    fn queue_ctl(&mut self, frame: Vec<u8>) {
        self.pending_ctl.extend_from_slice(&frame);
    }

    /// Fails the WebSocket connection: queue one close frame carrying `code`
    /// and build the error the caller sees. The close is written on the next
    /// poll (and by `shutdown`), so it is not lost when the caller stops
    /// reading immediately.
    fn fail(&mut self, code: u16, message: impl Into<String>) -> io::Error {
        let message = message.into();
        self.stop_reading = true;
        if !self.close_sent {
            self.close_sent = true;
            self.queue_ctl(build_frame(self.is_client, 0x8, true, &code.to_be_bytes()));
        }
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket protocol violation: {message}"),
        )
    }
}

/// Reading and writing a control frame needs the transport.
impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    /// Returns the error the caller must see, after one last best-effort
    /// attempt to put the queued close frame on the wire.
    fn abort(&mut self, cx: &mut Context<'_>, err: io::Error) -> Poll<io::Result<()>> {
        let _ = self.poll_drain_ctl(cx);
        Poll::Ready(Err(err))
    }
}

impl<S: AsyncWrite + Unpin> WebSocketStream<S> {
    /// Writes as much of the queued control frames as the socket takes.
    fn poll_drain_ctl(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_ctl_pos < self.pending_ctl.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &self.pending_ctl[self.pending_ctl_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    self.pending_ctl.clear();
                    self.pending_ctl_pos = 0;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write a buffered websocket control frame",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_ctl_pos += n,
                Poll::Ready(Err(e)) => {
                    self.pending_ctl.clear();
                    self.pending_ctl_pos = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_ctl.clear();
        self.pending_ctl_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketStream<S> {
    /// Reads up to `out.len()` bytes from the framing excess or the transport.
    /// A return of 0 means the transport is at EOF; it is never a protocol
    /// conclusion in itself.
    fn poll_fill(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.buffered_pos < self.buffered_excess.len() {
            let avail = self.buffered_excess.len() - self.buffered_pos;
            let n = avail.min(out.len());
            out[..n]
                .copy_from_slice(&self.buffered_excess[self.buffered_pos..self.buffered_pos + n]);
            self.buffered_pos += n;
            return Poll::Ready(Ok(n));
        }
        let mut tmp = ReadBuf::new(out);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(tmp.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Reads a frame header, growing from 2 to 14 bytes as the length form
    /// demands, and validates it.
    fn poll_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            while self.header_pos < self.header_len {
                let need = self.header_len - self.header_pos;
                let mut tmp = [0u8; 14];
                match self.poll_fill(cx, &mut tmp[..need]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            if self.header_pos == 0 {
                                "websocket peer closed the transport without a close frame (abnormal closure, 1006)"
                            } else {
                                "unexpected EOF inside a websocket frame header"
                            },
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        let pos = self.header_pos;
                        self.header_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        self.header_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if self.header_len == 2 {
                let basic = (self.header_buf[1] & 0x7f) as usize;
                let extended = match basic {
                    126 => 2,
                    127 => 8,
                    _ => 0,
                };
                let masked = self.header_buf[1] & 0x80 != 0;
                self.header_len = 2 + extended + if masked { 4 } else { 0 };
                if self.header_len > 2 {
                    continue;
                }
            }

            return match self.parse_header() {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            };
        }
    }

    /// Validates the header now in `header_buf` (RFC 6455 §5.2, §5.4, §5.5) and
    /// selects the state that consumes its payload.
    fn parse_header(&mut self) -> io::Result<()> {
        let b0 = self.header_buf[0];
        let b1 = self.header_buf[1];
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let basic = (b1 & 0x7f) as usize;

        if b0 & 0x70 != 0 {
            return Err(self.fail(
                CLOSE_PROTOCOL_ERROR,
                "RSV1/RSV2/RSV3 set but no extension was negotiated",
            ));
        }
        if !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xa) {
            return Err(self.fail(
                CLOSE_PROTOCOL_ERROR,
                format!("reserved opcode 0x{opcode:x}"),
            ));
        }
        // §5.1: a client MUST mask every frame, a server MUST NOT mask. This is
        // also what stops an active prober from fingerprinting us as something
        // other than a WebSocket endpoint.
        if self.is_client && masked {
            return Err(self.fail(
                CLOSE_PROTOCOL_ERROR,
                "server sent a masked frame (a server MUST NOT mask)",
            ));
        }
        if !self.is_client && !masked {
            return Err(self.fail(
                CLOSE_PROTOCOL_ERROR,
                "client sent an unmasked frame (a client MUST mask every frame)",
            ));
        }

        let is_control = opcode & 0x08 != 0;
        if is_control {
            // §5.5: control frames are never fragmented and carry <= 125 bytes,
            // which also rules out the 16- and 64-bit length forms.
            if !fin {
                return Err(self.fail(
                    CLOSE_PROTOCOL_ERROR,
                    format!("control frame 0x{opcode:x} with FIN=0 (control frames may not be fragmented)"),
                ));
            }
            if basic > 125 {
                return Err(self.fail(
                    CLOSE_PROTOCOL_ERROR,
                    format!("control frame 0x{opcode:x} length {basic} exceeds 125 bytes"),
                ));
            }
        }

        let (len, offset) = match basic {
            126 => {
                let l = u16::from_be_bytes([self.header_buf[2], self.header_buf[3]]) as u64;
                if l < 126 {
                    return Err(self.fail(
                        CLOSE_PROTOCOL_ERROR,
                        format!("non-minimal 16-bit payload length {l}"),
                    ));
                }
                (l, 4)
            }
            127 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.header_buf[2..10]);
                if b[0] & 0x80 != 0 {
                    return Err(self.fail(
                        CLOSE_PROTOCOL_ERROR,
                        "64-bit payload length with the most significant bit set",
                    ));
                }
                let l = u64::from_be_bytes(b);
                if l < 65_536 {
                    return Err(self.fail(
                        CLOSE_PROTOCOL_ERROR,
                        format!("non-minimal 64-bit payload length {l}"),
                    ));
                }
                (l, 10)
            }
            n => (n as u64, 2),
        };

        if len > MAX_FRAME_PAYLOAD {
            return Err(self.fail(
                CLOSE_TOO_BIG,
                format!("frame payload of {len} bytes exceeds the {MAX_FRAME_PAYLOAD} byte limit"),
            ));
        }
        if opcode == 0x8 && len == 1 {
            return Err(self.fail(
                CLOSE_PROTOCOL_ERROR,
                "close frame payload of 1 byte (must be empty or carry a 2-byte status code)",
            ));
        }

        // §5.4: continuation only after a fragmented frame, and a data frame
        // may not interrupt a fragmented message.
        match opcode {
            0x0 => {
                if !self.in_fragment {
                    return Err(self.fail(
                        CLOSE_PROTOCOL_ERROR,
                        "continuation frame without a preceding fragmented message",
                    ));
                }
            }
            0x1 | 0x2 => {
                if self.in_fragment {
                    return Err(self.fail(
                        CLOSE_PROTOCOL_ERROR,
                        "new data frame while a fragmented message is still in progress",
                    ));
                }
                self.msg_is_text = opcode == 0x1;
                self.utf8 = Utf8Check::default();
                self.in_fragment = !fin;
            }
            _ => {}
        }

        self.frame_opcode = opcode;
        self.frame_fin = fin;
        self.mask_key = if masked {
            let mut m = [0u8; 4];
            m.copy_from_slice(&self.header_buf[offset..offset + 4]);
            Some(m)
        } else {
            None
        };
        self.mask_idx = 0;
        self.payload_rem = len as usize;
        self.header_pos = 0;
        self.header_len = 2;
        self.read_state = if is_control {
            self.ctl_payload.clear();
            ReadState::ControlPayload
        } else {
            ReadState::Payload
        };
        Ok(())
    }

    /// Drains the payload of the current control frame, then acts on it.
    fn poll_control_payload(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.payload_rem > 0 {
            let need = self.payload_rem;
            let mut tmp = [0u8; 125];
            match self.poll_fill(cx, &mut tmp[..need]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF inside a websocket control frame",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    if let Some(mask) = self.mask_key {
                        mask_in_place(mask, self.mask_idx, &mut tmp[..n]);
                    }
                    self.mask_idx = (self.mask_idx + n) % 4;
                    self.ctl_payload.extend_from_slice(&tmp[..n]);
                    self.payload_rem -= n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.read_state = ReadState::Header;
        match self.handle_control() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<S> WebSocketStream<S> {
    fn handle_control(&mut self) -> io::Result<()> {
        match self.frame_opcode {
            0x9 => {
                // §5.5.2: echo the ping payload verbatim, nothing else.
                let payload = mem::take(&mut self.ctl_payload);
                self.queue_ctl(build_frame(self.is_client, 0xa, true, &payload));
                Ok(())
            }
            // An unsolicited pong is legal and ignored (§5.5.3).
            0xa => {
                self.ctl_payload.clear();
                Ok(())
            }
            _ => self.handle_close(),
        }
    }

    fn handle_close(&mut self) -> io::Result<()> {
        let payload = mem::take(&mut self.ctl_payload);
        let mut code = CLOSE_NORMAL;
        if payload.len() >= 2 {
            code = u16::from_be_bytes([payload[0], payload[1]]);
            if !close_code_valid(code) {
                return Err(self.fail(
                    CLOSE_PROTOCOL_ERROR,
                    format!("close frame carries the invalid status code {code}"),
                ));
            }
            if std::str::from_utf8(&payload[2..]).is_err() {
                return Err(self.fail(
                    CLOSE_INVALID_PAYLOAD,
                    "close frame reason is not valid UTF-8",
                ));
            }
        }
        // Reply exactly once, then stop reading. A close is the end of the
        // conversation: anything the peer pipelines after it is not data.
        self.stop_reading = true;
        if !self.close_sent {
            self.close_sent = true;
            self.queue_ctl(build_frame(self.is_client, 0x8, true, &code.to_be_bytes()));
        }
        Ok(())
    }

    /// Called when a data frame's payload is fully consumed.
    fn finish_data_frame(&mut self) -> io::Result<()> {
        self.read_state = ReadState::Header;
        if !self.frame_fin {
            return Ok(());
        }
        if self.msg_is_text && !self.utf8.is_complete() {
            return Err(self.fail(
                CLOSE_INVALID_PAYLOAD,
                "text message ends in the middle of a UTF-8 sequence",
            ));
        }
        self.in_fragment = false;
        self.msg_is_text = false;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            // A pong or close we owe the peer must never stall *reading*.
            let _ = this.poll_drain_ctl(cx);
            if this.stop_reading {
                // EOF, and no byte is ever parsed again.
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            match this.read_state {
                ReadState::Header => match this.poll_header(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return this.abort(cx, e),
                    Poll::Pending => return Poll::Pending,
                },

                ReadState::ControlPayload => match this.poll_control_payload(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(e)) => return this.abort(cx, e),
                    Poll::Pending => return Poll::Pending,
                },

                ReadState::Payload => {
                    if this.payload_rem == 0 {
                        match this.finish_data_frame() {
                            Ok(()) => continue,
                            Err(e) => return this.abort(cx, e),
                        }
                    }
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    // No 16 KiB cap: the staging buffer is reused and grows, so a
                    // reader with a 64 KiB buffer gets its payload in one go instead
                    // of four round trips through this state machine.
                    let want = this.payload_rem.min(buf.remaining());
                    // A stack array here was zero-initialised on every poll — 16 KiB
                    // of memset per read, on the hottest path of the transport.
                    let mut staging = std::mem::take(&mut this.staging);
                    if staging.len() < want {
                        staging.resize(want, 0);
                    }
                    let res = this.poll_fill(cx, &mut staging[..want]);
                    this.staging = staging;
                    match res {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF in websocket payload",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            let chunk = &mut this.staging[..n];
                            if let Some(mask) = this.mask_key {
                                mask_in_place(mask, this.mask_idx, chunk);
                            }
                            this.mask_idx = (this.mask_idx + n) % 4;
                            if this.msg_is_text && !this.utf8.feed(chunk) {
                                return Poll::Ready(Err(this.fail(
                                    CLOSE_INVALID_PAYLOAD,
                                    "text message is not valid UTF-8",
                                )));
                            }
                            buf.put_slice(chunk);
                            this.payload_rem -= n;
                            if this.payload_rem == 0 {
                                match this.finish_data_frame() {
                                    Ok(()) => {}
                                    Err(e) => return this.abort(cx, e),
                                }
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Step 0: control frames owed to the peer go first.
        match this.poll_drain_ctl(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Step 1: If a previously framed chunk is in progress, finish flushing it first
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write buffered websocket frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let chunk_len = this.pending_chunk_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                return Poll::Ready(Ok(chunk_len));
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Step 2: Frame a new payload chunk. The cap used to be 16 KiB, so a 64 KiB
        // write became four frames — four copies, four masks and four syscalls — on
        // the single hottest path of this transport. 64 KiB matches the relay's copy
        // buffer, so a normal write is framed once.
        let chunk_len = buf.len().min(64 * 1024);
        this.write_buf.clear();
        encode_frame_into(
            &mut this.write_buf,
            this.is_client,
            0x02,
            true,
            &buf[..chunk_len],
        );
        this.write_pos = 0;
        this.pending_chunk_len = chunk_len;

        // Step 3: Write out as much as possible
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write buffered websocket frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                return Poll::Ready(Ok(chunk_len));
            }
        }

        Poll::Pending
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_drain_ctl(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to flush buffered websocket frame",
                )));
            }
            this.write_pos += n;
        }
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_chunk_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        // §5.5.1: an endpoint that closes the connection sends a close frame,
        // exactly once. Without it the peer can only report 1006.
        if !this.close_sent {
            this.close_sent = true;
            this.queue_ctl(build_frame(
                this.is_client,
                0x8,
                true,
                &CLOSE_NORMAL.to_be_bytes(),
            ));
        }
        // Best effort: the peer may already be gone, and its absence must not
        // turn our clean teardown into an error for the caller.
        let _ = this.poll_drain_ctl(cx);
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to flush buffered websocket frame during shutdown",
                )));
            }
            this.write_pos += n;
        }
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_chunk_len = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The sample key/accept pair from RFC 6455 §1.3, so the Accept computation
    /// is checked against the spec's own vector rather than against itself.
    const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const SAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    const GOOD_REQ: &str = "GET /tunnel HTTP/1.1\r\n\
         Host: example.com\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n";

    // ---------------------------------------------------------------- wire

    /// Builds a frame exactly as RFC 6455 §5.2 lays it out, with the minimal
    /// length form (which is what every real implementation emits).
    fn encode_frame(opcode: u8, fin: bool, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut f = Vec::with_capacity(payload.len() + 14);
        f.push(if fin { 0x80 } else { 0x00 } | opcode);
        let mask_bit = if mask.is_some() { 0x80 } else { 0x00 };
        let len = payload.len();
        if len <= 125 {
            f.push(mask_bit | len as u8);
        } else if len <= 65_535 {
            f.push(mask_bit | 126);
            f.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            f.push(mask_bit | 127);
            f.extend_from_slice(&(len as u64).to_be_bytes());
        }
        match mask {
            Some(k) => {
                f.extend_from_slice(&k);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => f.extend_from_slice(payload),
        }
        f
    }

    /// A frame as a peer would legitimately send it to the stream in `role`:
    /// a client masks, a server does not (RFC 6455 §5.1).
    fn inbound(is_client_role: bool, opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mask = if is_client_role {
            None
        } else {
            Some([0xA1, 0xB2, 0xC3, 0xD4])
        };
        encode_frame(opcode, fin, payload, mask)
    }

    #[derive(Debug)]
    struct WireFrame {
        fin: bool,
        opcode: u8,
        mask: Option<[u8; 4]>,
        payload: Vec<u8>,
    }

    /// Decodes one frame from what the stream under test wrote. Bounded in
    /// time: "nothing was written" is a test failure, not a hung test.
    async fn read_wire_frame<R: AsyncRead + Unpin>(r: &mut R) -> WireFrame {
        tokio::time::timeout(Duration::from_secs(2), read_wire_frame_inner(r))
            .await
            .expect("no frame was written within 2s")
    }

    async fn read_wire_frame_inner<R: AsyncRead + Unpin>(r: &mut R) -> WireFrame {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await.expect("truncated frame header");
        let fin = h[0] & 0x80 != 0;
        let opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let mut len = (h[1] & 0x7f) as usize;
        if len == 126 {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).await.expect("truncated 16-bit length");
            len = u16::from_be_bytes(b) as usize;
        } else if len == 127 {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).await.expect("truncated 64-bit length");
            len = u64::from_be_bytes(b) as usize;
        }
        let mask = if masked {
            let mut k = [0u8; 4];
            r.read_exact(&mut k).await.expect("truncated mask key");
            Some(k)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload).await.expect("truncated payload");
        if let Some(k) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= k[i % 4];
            }
        }
        WireFrame {
            fin,
            opcode,
            mask,
            payload,
        }
    }

    // ------------------------------------------------------------ harnesses

    /// Feeds `frames` to a stream in `role` and reads until the stream errors,
    /// returning whatever was delivered plus the error text.
    async fn read_until_error(is_client_role: bool, frames: &[Vec<u8>]) -> (Vec<u8>, String) {
        let (ours, mut peer) = tokio::io::duplex(256 * 1024);
        for f in frames {
            peer.write_all(f).await.unwrap();
        }
        let mut ws = WebSocketStream::new(ours, Vec::new(), is_client_role);
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf)).await {
                // Neither refused nor answered: the frame was accepted and the
                // stream is now parked waiting for payload that never comes.
                Err(_) => return (out, "STALLED".to_string()),
                Ok(Ok(0)) => return (out, "EOF".to_string()),
                Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => return (out, e.to_string()),
            }
        }
    }

    /// Collection form of [`expect_frame_error`]: returns the description of
    /// every frame that was *not* refused, so one run lists all of them.
    async fn unrefused(is_client_role: bool, cases: &[(String, Vec<u8>)]) -> Vec<String> {
        let mut bad = Vec::new();
        for (name, frame) in cases {
            let (out, err) = read_until_error(is_client_role, std::slice::from_ref(frame)).await;
            if err == "EOF" || err == "STALLED" || !out.is_empty() {
                let what = match err.as_str() {
                    "EOF" => "treated as a clean close".to_string(),
                    "STALLED" => "accepted and left waiting for payload".to_string(),
                    other => format!("delivered {} bytes then: {other}", out.len()),
                };
                bad.push(format!("{name}: {what}"));
            }
        }
        bad
    }

    /// Asserts that a single malformed frame is refused, and that refusing it
    /// does not hang (a hung framed stream is a stuck tunnel).
    async fn expect_frame_error(is_client_role: bool, bytes: &[u8]) -> String {
        let (out, err) = read_until_error(is_client_role, &[bytes.to_vec()]).await;
        assert!(
            out.is_empty(),
            "malformed frame delivered {} bytes before the error: {out:?}",
            out.len()
        );
        assert!(
            err != "EOF" && err != "STALLED",
            "malformed frame was not refused ({err})"
        );
        err
    }

    /// Feeds `frames` and collects exactly `want` delivered bytes.
    async fn read_exactly(is_client_role: bool, frames: &[Vec<u8>], want: usize) -> Vec<u8> {
        let (ours, mut peer) = tokio::io::duplex(256 * 1024);
        for f in frames {
            peer.write_all(f).await.unwrap();
        }
        let mut ws = WebSocketStream::new(ours, Vec::new(), is_client_role);
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while out.len() < want {
            let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
                .await
                .expect("read timed out")
                .expect("read failed");
            assert_ne!(n, 0, "stream ended after {} of {want} bytes", out.len());
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            out.len(),
            want,
            "delivered more bytes than the message holds"
        );
        out
    }

    fn accept_for(key: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_GUID);
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    }

    fn response_with(status_line: &str, accept: Option<&str>, extra: &str) -> Vec<u8> {
        let mut s = format!("{status_line}\r\n");
        if let Some(a) = accept {
            s.push_str(&format!("Sec-WebSocket-Accept: {a}\r\n"));
        }
        s.push_str(extra);
        s.push_str("\r\n");
        s.into_bytes()
    }

    const HDR_UPGRADE: &str = "Upgrade: websocket\r\nConnection: Upgrade\r\n";

    /// Runs `server_handshake` against a raw request; returns the error text or
    /// the raw response.
    async fn server_handshake_raw(req: &str) -> Result<String, String> {
        let (ours, peer) = tokio::io::duplex(16 * 1024);
        let (mut pr, mut pw) = tokio::io::split(peer);
        let req = req.as_bytes().to_vec();
        let feeder = tokio::spawn(async move {
            let _ = pw.write_all(&req).await;
            let _ = pw.flush().await;
            std::future::pending::<()>().await;
        });
        let res = tokio::time::timeout(Duration::from_secs(2), server_handshake(ours, None)).await;
        feeder.abort();
        match res {
            Err(_) => Err("server_handshake hung".into()),
            Ok(Err(e)) => Err(e.to_string()),
            Ok(Ok(ws)) => {
                drop(ws);
                let mut out = Vec::new();
                let mut buf = [0u8; 512];
                loop {
                    match tokio::time::timeout(Duration::from_secs(2), pr.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => {
                            out.extend_from_slice(&buf[..n]);
                            if out.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                Ok(String::from_utf8_lossy(&out).into_owned())
            }
        }
    }

    /// Runs `client_handshake` against a response built from the request's key
    /// and its correct accept token.
    async fn client_handshake_raw<F>(build: F) -> Result<(), String>
    where
        F: FnOnce(&str, &str) -> Vec<u8> + Send + 'static,
    {
        let (ours, mut peer) = tokio::io::duplex(16 * 1024);
        let helper = tokio::spawn(async move {
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = peer.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&req).into_owned();
            let mut key = String::new();
            for line in req.lines() {
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("sec-websocket-key")
                {
                    key = v.trim().to_string();
                }
            }
            let accept = accept_for(&key);
            let resp = build(&key, &accept);
            let _ = peer.write_all(&resp).await;
            let _ = peer.flush().await;
            std::future::pending::<()>().await;
        });
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            client_handshake(ours, "example.com", "/chat", &HashMap::new()),
        )
        .await;
        helper.abort();
        match res {
            Err(_) => Err("client_handshake hung".into()),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
        }
    }

    // ============================================================== masking
    // RFC 6455 §5.1: a client MUST mask every frame, a server MUST NOT mask.

    #[tokio::test]
    async fn server_rejects_an_unmasked_client_frame() {
        // 0x81 0x03 "abc": a perfectly framed but unmasked client frame.
        let err = expect_frame_error(false, &[0x81, 0x03, b'a', b'b', b'c']).await;
        assert!(
            err.contains("unmasked"),
            "expected an unmasked-frame rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn client_rejects_a_masked_server_frame() {
        let err =
            expect_frame_error(true, &encode_frame(0x1, true, b"abc", Some([1, 2, 3, 4]))).await;
        assert!(
            err.contains("masked"),
            "expected a masked-frame rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn client_masks_outbound_frames_with_a_fresh_key_per_frame() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let mut ws = WebSocketStream::new(ours, Vec::new(), true);
        for i in 0..3u8 {
            ws.write_all(&[i; 5]).await.unwrap();
            ws.flush().await.unwrap();
        }
        let mut keys = Vec::new();
        for i in 0..3u8 {
            let f = read_wire_frame(&mut peer).await;
            assert_eq!(f.opcode, 0x2, "client must send binary frames");
            assert!(f.fin, "client must send whole messages");
            let key = f.mask.expect("client frame must be masked");
            assert_eq!(f.payload, vec![i; 5], "payload must round-trip");
            keys.push(key);
        }
        assert!(
            keys[0] != keys[1] || keys[1] != keys[2],
            "every frame needs a fresh random mask key, got {keys:?}"
        );
    }

    #[tokio::test]
    async fn server_never_masks_outbound_frames() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        ws.write_all(b"server to client").await.unwrap();
        ws.flush().await.unwrap();
        let f = read_wire_frame(&mut peer).await;
        assert_eq!(f.opcode, 0x2);
        assert!(f.mask.is_none(), "a server MUST NOT mask: {f:?}");
        assert_eq!(f.payload, b"server to client");
    }

    // ====================================================== control frames
    // RFC 6455 §5.5: at most 125 bytes, never fragmented, one close only.

    #[tokio::test]
    async fn ping_is_answered_with_an_identical_pong() {
        for is_client_role in [false, true] {
            let (ours, mut peer) = tokio::io::duplex(64 * 1024);
            let mut ws = WebSocketStream::new(ours, Vec::new(), is_client_role);
            peer.write_all(&inbound(is_client_role, 0x9, true, b"ping-payload"))
                .await
                .unwrap();
            // A data frame after the ping forces the read to return, which
            // means the echo must already be on the wire.
            peer.write_all(&inbound(is_client_role, 0x2, true, b"data"))
                .await
                .unwrap();
            let mut buf = [0u8; 16];
            let n = ws.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"data");
            let pong = read_wire_frame(&mut peer).await;
            assert_eq!(pong.opcode, 0xA, "ping must be answered with pong");
            assert_eq!(pong.payload, b"ping-payload", "pong must echo the payload");
            // The echo is a frame we originate, so it obeys our own role.
            assert_eq!(
                pong.mask.is_some(),
                is_client_role,
                "pong masking must follow our role"
            );
        }
    }

    #[tokio::test]
    async fn pong_is_not_answered() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        peer.write_all(&inbound(false, 0xA, true, b"unsolicited"))
            .await
            .unwrap();
        peer.write_all(&inbound(false, 0x2, true, b"data"))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = ws.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"data");
        let mut stray = [0u8; 8];
        let echoed = tokio::time::timeout(Duration::from_millis(100), peer.read(&mut stray)).await;
        assert!(
            echoed.is_err(),
            "an unsolicited pong must not be answered, got {echoed:?}"
        );
    }

    #[tokio::test]
    async fn control_frame_longer_than_125_bytes_is_rejected() {
        let err = expect_frame_error(
            false,
            &encode_frame(0x9, true, &[0u8; 128], Some([1, 2, 3, 4])),
        )
        .await;
        assert!(
            err.contains("control") || err.contains("125"),
            "expected a control-frame length rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn fragmented_control_frame_is_rejected() {
        let cases: Vec<(String, Vec<u8>)> = [0x8u8, 0x9, 0xA]
            .iter()
            .map(|op| {
                (
                    format!("opcode 0x{op:x} with FIN=0"),
                    inbound(false, *op, false, b"x"),
                )
            })
            .collect();
        let bad = unrefused(false, &cases).await;
        assert!(
            bad.is_empty(),
            "fragmented control frames were accepted: {bad:#?}"
        );
    }

    #[tokio::test]
    async fn close_status_code_round_trips_and_reading_stops() {
        for is_client_role in [false, true] {
            let (ours, mut peer) = tokio::io::duplex(64 * 1024);
            let mut ws = WebSocketStream::new(ours, Vec::new(), is_client_role);
            let mut payload = 1000u16.to_be_bytes().to_vec();
            payload.extend_from_slice(b"bye");
            peer.write_all(&inbound(is_client_role, 0x8, true, &payload))
                .await
                .unwrap();
            let mut buf = [0u8; 16];
            let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
                .await
                .expect("close must not hang")
                .expect("a close frame is a clean EOF, not an error");
            assert_eq!(n, 0, "a close frame must surface as EOF");

            let reply = read_wire_frame(&mut peer).await;
            assert_eq!(reply.opcode, 0x8, "the close frame must be answered");
            assert!(
                reply.payload.len() <= 2,
                "the reply may carry only the status code: {:?}",
                reply.payload
            );
            assert_eq!(
                u16::from_be_bytes([reply.payload[0], reply.payload[1]]),
                1000,
                "the peer's status code must round-trip"
            );

            // A second read must stay at EOF: nothing may be parsed after close.
            let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
                .await
                .expect("second read after close must not hang")
                .expect("second read after close must stay EOF");
            assert_eq!(n, 0);
        }
    }

    #[tokio::test]
    async fn nothing_is_delivered_after_a_close_frame() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        let mut close_payload = 1000u16.to_be_bytes().to_vec();
        close_payload.extend_from_slice(b"bye");
        peer.write_all(&inbound(false, 0x8, true, &close_payload))
            .await
            .unwrap();
        // Pipelined straight after the close: must never be delivered, and its
        // bytes must never be misparsed as a frame header.
        peer.write_all(&inbound(false, 0x2, true, b"after-close"))
            .await
            .unwrap();
        let mut out = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut out))
            .await
            .expect("close must not hang")
            .unwrap();
        assert_eq!(n, 0);
        let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut out))
            .await
            .expect("the stream must stay closed, not parse the leftover close payload")
            .unwrap();
        assert_eq!(n, 0, "data after close must not be delivered");
    }

    #[tokio::test]
    async fn eof_without_a_close_frame_is_an_abnormal_closure() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&inbound(false, 0x2, true, b"partial"))
            .await
            .unwrap();
        peer.shutdown().await.unwrap();
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        let mut buf = [0u8; 64];
        let n = ws.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"partial");
        let res = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
            .await
            .expect("must not hang at EOF");
        let err = res.expect_err("a bare EOF without a close frame is an abnormal closure");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    // ======================================================= data frames
    // RFC 6455 §5.4: fragmentation and control-frame interleaving.

    #[tokio::test]
    async fn continuation_without_a_preceding_fragment_is_rejected() {
        let err = expect_frame_error(false, &inbound(false, 0x0, true, b"orphan")).await;
        assert!(
            err.contains("continuation"),
            "expected a continuation rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn a_new_data_frame_inside_a_fragmented_message_is_rejected() {
        let (out, err) = read_until_error(
            false,
            &[
                inbound(false, 0x1, false, b"start"),
                inbound(false, 0x2, true, b"interrupt"),
            ],
        )
        .await;
        assert_eq!(
            out, b"start",
            "the first fragment is legal and must be delivered"
        );
        assert_ne!(err, "EOF");
        assert!(
            err.contains("fragment"),
            "a new data frame mid-message must be a protocol error, got: {err}"
        );
    }

    #[tokio::test]
    async fn fragmented_message_with_an_interleaved_ping_reassembles() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        peer.write_all(&inbound(false, 0x1, false, b"frag1"))
            .await
            .unwrap();
        peer.write_all(&inbound(false, 0x9, true, b"in-between"))
            .await
            .unwrap();
        peer.write_all(&inbound(false, 0x0, true, b"frag2"))
            .await
            .unwrap();
        let want = b"frag1frag2";
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        while out.len() < want.len() {
            let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
                .await
                .expect("interleaved ping must not stall reassembly")
                .expect("interleaved ping must not break reassembly");
            assert_ne!(n, 0);
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, want, "a control frame must not corrupt reassembly");
        let pong = read_wire_frame(&mut peer).await;
        assert_eq!(pong.opcode, 0xA);
        assert_eq!(pong.payload, b"in-between");
    }

    #[tokio::test]
    async fn zero_length_frames_do_not_stall_the_stream() {
        let out = read_exactly(
            false,
            &[
                inbound(false, 0x2, true, b""),
                inbound(false, 0x1, true, b""),
                inbound(false, 0x2, true, b"real"),
            ],
            4,
        )
        .await;
        assert_eq!(out, b"real");
    }

    #[tokio::test]
    async fn reserved_opcodes_are_rejected() {
        let cases: Vec<(String, Vec<u8>)> = [0x3u8, 0x7, 0xB, 0xF]
            .iter()
            .map(|op| {
                (
                    format!("reserved opcode 0x{op:x}"),
                    inbound(false, *op, true, b"x"),
                )
            })
            .collect();
        let bad = unrefused(false, &cases).await;
        assert!(
            bad.is_empty(),
            "reserved opcodes were accepted as data: {bad:#?}"
        );
    }

    #[tokio::test]
    async fn reserved_bits_are_rejected() {
        let cases: Vec<(String, Vec<u8>)> = [0x40u8, 0x20, 0x10]
            .iter()
            .map(|bit| {
                let mut frame = inbound(false, 0x2, true, b"x");
                frame[0] |= bit;
                (format!("RSV bit 0x{bit:02x}"), frame)
            })
            .collect();
        let bad = unrefused(false, &cases).await;
        assert!(
            bad.is_empty(),
            "frames with RSV bits set were accepted: {bad:#?}"
        );
    }

    // ======================================================= length encoding
    // RFC 6455 §5.2: 7/16/64-bit forms, MSB of the 64-bit form MUST be 0.

    #[tokio::test]
    async fn sixty_four_bit_length_with_the_high_bit_set_is_rejected() {
        let mut frame = vec![0x82, 0xFF];
        frame.extend_from_slice(&0x8000_0000_0000_0001u64.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]);
        let err = expect_frame_error(false, &frame).await;
        assert!(
            err.contains("high bit") || err.contains("64-bit"),
            "expected a high-bit rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn non_minimal_length_encoding_is_rejected() {
        // 16-bit form carrying a value that fits in 7 bits.
        let mut frame = vec![0x82, 0x80 | 126, 0x00, 0x05];
        frame.extend_from_slice(&[1, 2, 3, 4]);
        frame.extend_from_slice(b"hello");
        expect_frame_error(false, &frame).await;

        // 64-bit form carrying a value that fits in 16 bits.
        let mut frame = vec![0x82, 0x80 | 127];
        frame.extend_from_slice(&200u64.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]);
        frame.extend_from_slice(&[0u8; 200]);
        expect_frame_error(false, &frame).await;
    }

    #[tokio::test]
    async fn absurd_declared_length_is_rejected_without_hanging() {
        // 2^63-1 declared, nothing behind it: must be refused from the header
        // alone, never buffered and never waited for.
        let mut frame = vec![0x82, 0x80 | 127];
        frame.extend_from_slice(&0x7FFF_FFFF_FFFF_FFFFu64.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]);
        let err = expect_frame_error(false, &frame).await;
        assert!(
            err.contains("too large") || err.contains("payload"),
            "expected a size rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn extended_lengths_are_accepted() {
        let medium = vec![0x5Au8; 200];
        let got = read_exactly(false, &[inbound(false, 0x2, true, &medium)], medium.len()).await;
        assert_eq!(got, medium, "16-bit length form must round-trip");

        let large = vec![0x5Au8; 70_000];
        let got = read_exactly(true, &[inbound(true, 0x2, true, &large)], large.len()).await;
        assert_eq!(got, large, "64-bit length form must round-trip");
    }

    #[tokio::test]
    async fn a_payload_shorter_than_declared_is_an_error() {
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        // Declares 100 bytes, delivers 10, then EOF.
        let mut frame = vec![0x82, 0x80 | 100];
        frame.extend_from_slice(&[1, 2, 3, 4]);
        frame.extend_from_slice(&[0u8; 10]);
        peer.write_all(&frame).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        let mut buf = [0u8; 256];
        let mut err = None;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
                .await
                .expect("must not hang on a truncated payload")
            {
                Ok(0) => panic!("a truncated frame must not look like a clean close"),
                Ok(_) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let err = err.expect("truncated payload must eventually error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    // ================================================================ UTF-8
    // RFC 6455 §5.6: text payloads must be UTF-8, checked per message.

    #[tokio::test]
    async fn invalid_utf8_in_a_text_frame_is_rejected() {
        let err = expect_frame_error(false, &inbound(false, 0x1, true, b"ab\xffcd")).await;
        assert!(
            err.contains("UTF-8") || err.contains("utf-8"),
            "expected a UTF-8 rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn valid_utf8_split_across_fragments_is_accepted() {
        let text = "héllo wörld ✓";
        let bytes = text.as_bytes();
        for split in 0..bytes.len() {
            let out = read_exactly(
                false,
                &[
                    inbound(false, 0x1, false, &bytes[..split]),
                    inbound(false, 0x0, true, &bytes[split..]),
                ],
                bytes.len(),
            )
            .await;
            assert_eq!(
                std::str::from_utf8(&out).unwrap(),
                text,
                "a code point split at byte {split} must reassemble"
            );
        }
    }

    #[tokio::test]
    async fn invalid_utf8_across_a_fragment_boundary_is_rejected() {
        // 0xC3 starts a 2-byte sequence; 0x28 cannot be its continuation, so
        // the message is invalid only once the fragments are joined.
        let (out, err) = read_until_error(
            false,
            &[
                inbound(false, 0x1, false, b"ok\xc3"),
                inbound(false, 0x0, true, b"\x28"),
            ],
        )
        .await;
        assert_eq!(out, b"ok\xc3");
        assert!(
            err.contains("UTF-8") || err.contains("utf-8"),
            "invalid UTF-8 spanning fragments must be rejected, got: {err}"
        );
    }

    #[tokio::test]
    async fn binary_frames_are_not_utf8_validated() {
        let got = read_exactly(false, &[inbound(false, 0x2, true, b"\xff\xfe\x00")], 3).await;
        assert_eq!(got, b"\xff\xfe\x00", "binary payloads are opaque bytes");
    }

    // ============================================================ handshake

    #[tokio::test]
    async fn accept_matches_the_rfc6455_sample() {
        assert_eq!(accept_for(SAMPLE_KEY), SAMPLE_ACCEPT);
        let resp = server_handshake_raw(GOOD_REQ)
            .await
            .expect("a well formed upgrade must be accepted");
        assert!(
            resp.starts_with("HTTP/1.1 101"),
            "expected a 101 response, got: {resp:?}"
        );
        assert!(
            resp.contains(&format!("Sec-WebSocket-Accept: {SAMPLE_ACCEPT}")),
            "the accept token must match RFC 6455 §1.3, got: {resp:?}"
        );
    }

    #[tokio::test]
    async fn client_rejects_a_bad_status_line() {
        let mut accepted = Vec::new();
        for status_line in [
            "HTTP/1.1 200 OK",
            "HTTP/1.1 403 Forbidden",
            "HTTP/1.0 101 Switching Protocols",
            "HTTP/1.1 1001 Almost",
        ] {
            let res = client_handshake_raw(|_key: &str, accept: &str| {
                response_with(status_line, Some(accept), HDR_UPGRADE)
            })
            .await;
            if res.is_ok() {
                accepted.push(status_line);
            }
        }
        assert!(
            accepted.is_empty(),
            "client accepted these status lines: {accepted:?}"
        );
    }

    #[tokio::test]
    async fn client_rejects_a_missing_wrong_or_duplicate_accept() {
        type RespBuilder = fn(&str) -> Vec<u8>;
        let cases: Vec<(&str, RespBuilder)> = vec![
            ("missing accept", |_a: &str| {
                response_with("HTTP/1.1 101 Switching Protocols", None, HDR_UPGRADE)
            }),
            ("wrong accept", |_a: &str| {
                response_with(
                    "HTTP/1.1 101 Switching Protocols",
                    Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                    HDR_UPGRADE,
                )
            }),
            ("duplicate accept", |a: &str| {
                response_with(
                    "HTTP/1.1 101 Switching Protocols",
                    Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                    &format!("{HDR_UPGRADE}Sec-WebSocket-Accept: {a}\r\n"),
                )
            }),
            ("truncated accept", |a: &str| {
                response_with(
                    "HTTP/1.1 101 Switching Protocols",
                    Some(&a[..10]),
                    HDR_UPGRADE,
                )
            }),
        ];
        for (name, build) in cases {
            let res = client_handshake_raw(move |_key: &str, accept: &str| build(accept)).await;
            assert!(res.is_err(), "client accepted a {name} response");
        }
        // ... and the honest response must still be accepted.
        client_handshake_raw(|_key: &str, accept: &str| {
            response_with(
                "HTTP/1.1 101 Switching Protocols",
                Some(accept),
                HDR_UPGRADE,
            )
        })
        .await
        .expect("a correct 101 response must be accepted");
    }

    #[tokio::test]
    async fn client_rejects_a_101_without_upgrade_headers() {
        let cases: Vec<(&str, &str)> = vec![
            ("no Upgrade", "Connection: Upgrade\r\n"),
            ("no Connection", "Upgrade: websocket\r\n"),
            (
                "Connection: keep-alive",
                "Upgrade: websocket\r\nConnection: keep-alive\r\n",
            ),
            ("Upgrade: h2c", "Upgrade: h2c\r\nConnection: Upgrade\r\n"),
        ];
        let mut accepted = Vec::new();
        for (name, extra) in cases {
            let res = client_handshake_raw(|_key: &str, accept: &str| {
                response_with("HTTP/1.1 101 Switching Protocols", Some(accept), extra)
            })
            .await;
            if res.is_ok() {
                accepted.push(name);
            }
        }
        assert!(
            accepted.is_empty(),
            "client accepted a bare 101 with: {accepted:?}"
        );
    }

    #[tokio::test]
    async fn server_rejects_a_malformed_upgrade_request() {
        let cases: Vec<(&str, String)> = vec![
            ("POST", GOOD_REQ.replacen("GET", "POST", 1)),
            ("HTTP/1.0", GOOD_REQ.replacen("HTTP/1.1", "HTTP/1.0", 1)),
            (
                "missing Upgrade",
                GOOD_REQ.replace("Upgrade: websocket\r\n", ""),
            ),
            (
                "missing Connection",
                GOOD_REQ.replace("Connection: Upgrade\r\n", ""),
            ),
            (
                "Connection: keep-alive",
                GOOD_REQ.replace("Connection: Upgrade", "Connection: keep-alive"),
            ),
            (
                "wrong Upgrade",
                GOOD_REQ.replace("Upgrade: websocket", "Upgrade: h2c"),
            ),
            (
                "version 8",
                GOOD_REQ.replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8"),
            ),
            (
                "no version",
                GOOD_REQ.replace("Sec-WebSocket-Version: 13\r\n", ""),
            ),
            (
                "duplicate key",
                GOOD_REQ.replace(
                    "Sec-WebSocket-Version: 13",
                    "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13",
                ),
            ),
            (
                "duplicate version",
                GOOD_REQ.replace(
                    "Sec-WebSocket-Version: 13",
                    "Sec-WebSocket-Version: 8\r\nSec-WebSocket-Version: 13",
                ),
            ),
            (
                "no key",
                GOOD_REQ.replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""),
            ),
            (
                "empty key",
                GOOD_REQ.replace(
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Key:",
                ),
            ),
            (
                "key is not 16 bytes",
                GOOD_REQ.replace(
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Key: c2hvcnQ=",
                ),
            ),
            ("no Host", GOOD_REQ.replace("Host: example.com\r\n", "")),
            (
                "header without a colon",
                GOOD_REQ.replace("Host: example.com", "Broken header"),
            ),
            (
                "trailing junk on the request line",
                GOOD_REQ.replacen("HTTP/1.1", "HTTP/1.1 junk", 1),
            ),
        ];
        let mut accepted = Vec::new();
        for (name, req) in &cases {
            if server_handshake_raw(req).await.is_ok() {
                accepted.push(*name);
            }
        }
        assert!(
            accepted.is_empty(),
            "server upgraded these malformed requests: {accepted:?}"
        );
    }

    #[tokio::test]
    async fn server_accepts_a_well_formed_request() {
        // Header names are case-insensitive and Connection is a token list.
        let req = "GET /tunnel?ed=2048 HTTP/1.1\r\n\
             HOST: example.com\r\n\
             UPGRADE: WebSocket\r\n\
             CONNECTION: keep-alive, Upgrade\r\n\
             SEC-WEBSOCKET-KEY: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             SEC-WEBSOCKET-VERSION: 13\r\n\
             User-Agent: test\r\n\r\n";
        let resp = server_handshake_raw(req)
            .await
            .expect("a case-insensitive upgrade request must be accepted");
        assert!(
            resp.contains(&format!("Sec-WebSocket-Accept: {SAMPLE_ACCEPT}")),
            "got: {resp:?}"
        );
    }

    /// The client must refuse a poisoned request *before writing a byte*: a
    /// `\r\n` smuggled through configuration would split the request and
    /// inject a second one into the tunnel.
    async fn assert_client_refuses(host: &str, path: &str, headers: HashMap<String, String>) {
        let (client_io, mut peer) = tokio::io::duplex(4096);
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            client_handshake(client_io, host, path, &headers),
        )
        .await;
        match res {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("client accepted a poisoned request: host={host:?} path={path:?}"),
            Err(_) => panic!("client hung instead of refusing host={host:?} path={path:?}"),
        }
        let mut seen = [0u8; 256];
        let wrote = tokio::time::timeout(Duration::from_millis(100), peer.read(&mut seen)).await;
        if let Ok(Ok(n)) = wrote {
            assert_eq!(
                n,
                0,
                "the poisoned request reached the wire: {:?}",
                String::from_utf8_lossy(&seen[..n])
            );
        }
    }

    #[tokio::test]
    async fn client_refuses_to_smuggle_control_bytes_into_the_request() {
        let mut headers = HashMap::new();
        headers.insert("X-Test".to_string(), "v\r\nInjected: 1".to_string());
        assert_client_refuses("example.com", "/", headers).await;
        assert_client_refuses("exa\r\nmple.com", "/", HashMap::new()).await;
        assert_client_refuses("example.com", "/x HTTP/1.1\r\nEvil: 1", HashMap::new()).await;
        assert_client_refuses("example.com", "/\r\nHost: evil", HashMap::new()).await;
    }

    // ========================================================= bounded reads

    #[tokio::test]
    async fn oversized_handshake_header_is_rejected() {
        // No CRLFCRLF in 64 KiB: the reader must give up, in bounded memory.
        let req = "A".repeat(64 * 1024);
        let err = server_handshake_raw(&req)
            .await
            .expect_err("an endless header must be refused");
        assert!(
            err.contains("too large") || err.contains("header"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn a_frame_header_split_byte_by_byte_still_parses() {
        // The decoder must not care how the transport segments the header.
        let frame = inbound(false, 0x2, true, &vec![0x33u8; 300]);
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let mut ws = WebSocketStream::new(ours, Vec::new(), false);
        let writer = tokio::spawn(async move {
            for chunk in frame.chunks(1) {
                peer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            std::future::pending::<()>().await;
        });
        let got = read_exactly_inline(&mut ws, 300).await;
        writer.abort();
        assert_eq!(got, vec![0x33u8; 300]);
    }

    async fn read_exactly_inline<S>(ws: &mut WebSocketStream<S>, want: usize) -> Vec<u8>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        while out.len() < want {
            let n = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf))
                .await
                .expect("read timed out")
                .expect("read failed");
            assert_ne!(n, 0);
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    // ============================================================ primitives

    #[test]
    fn masking_round_trips_at_every_offset() {
        // Masking is its own inverse, and the key phase must survive the
        // payload being handed over in several chunks: that is what keeps a
        // masked frame consistent when it is copied through a staging buffer.
        for key in [[0u8, 0, 0, 0], [1, 2, 3, 4], [0xff, 0x80, 0x7f, 0x00]] {
            for len in 0..=8usize {
                let plain: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(1))
                    .collect();
                let mut masked = plain.clone();
                mask_in_place(key, 0, &mut masked);
                if len > 0 && key != [0u8, 0, 0, 0] {
                    assert_ne!(masked, plain, "a key must actually change the bytes");
                }
                let mut round_trip = masked.clone();
                mask_in_place(key, 0, &mut round_trip);
                assert_eq!(round_trip, plain, "unmask(mask(x)) must be x");

                let mut chunked = plain.clone();
                let mut idx = 0;
                for part in chunked.chunks_mut(3) {
                    mask_in_place(key, idx, part);
                    idx = (idx + part.len()) % 4;
                }
                assert_eq!(chunked, masked, "masking must not depend on chunking");
            }
        }
    }

    #[test]
    fn incremental_utf8_checker_holds_partial_code_points() {
        // "aé✓😀" split at every byte boundary must still validate.
        let bytes = "aé✓😀".as_bytes();
        for split in 0..=bytes.len() {
            let mut check = Utf8Check::default();
            assert!(
                check.feed(&bytes[..split]),
                "prefix of {split} bytes rejected"
            );
            assert!(
                check.feed(&bytes[split..]),
                "suffix after {split} bytes rejected"
            );
            assert!(
                check.is_complete(),
                "split at {split} left a partial code point"
            );
        }

        // Byte at a time.
        let mut check = Utf8Check::default();
        for b in bytes {
            assert!(check.feed(&[*b]), "single byte {b:02x} rejected");
        }
        assert!(check.is_complete());

        // A lone lead byte is held, not accepted as a message.
        let mut check = Utf8Check::default();
        assert!(check.feed(&[0xc3]));
        assert!(!check.is_complete(), "0xC3 alone is an incomplete sequence");
        // Continuation byte where one cannot go.
        assert!(!Utf8Check::default().feed(&[0xc3, 0x28]));
        // Never a lead byte at all.
        assert!(!Utf8Check::default().feed(&[0xff]));
        // Overlong 2-byte form for U+0000.
        assert!(!Utf8Check::default().feed(&[0xc0, 0x80]));
        // Surrogate half, valid lead but invalid sequence.
        assert!(!Utf8Check::default().feed(&[0xed, 0xa0, 0x80]));
    }

    #[tokio::test]
    async fn close_status_codes_are_validated() {
        let mut accepted = Vec::new();
        for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65_535] {
            let (out, err) =
                read_until_error(false, &[inbound(false, 0x8, true, &code.to_be_bytes())]).await;
            if err == "EOF" || err == "STALLED" || !out.is_empty() {
                accepted.push(code);
            }
        }
        assert!(
            accepted.is_empty(),
            "close frames with these invalid codes were accepted: {accepted:?}"
        );

        for code in [
            1000u16, 1001, 1002, 1003, 1007, 1011, 1012, 1013, 3000, 4999,
        ] {
            let (out, err) =
                read_until_error(false, &[inbound(false, 0x8, true, &code.to_be_bytes())]).await;
            assert_eq!(err, "EOF", "close code {code} must be a clean close");
            assert!(out.is_empty());
        }
    }

    #[tokio::test]
    async fn close_reason_must_be_valid_utf8() {
        let mut payload = 1000u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0xff, 0xfe]);
        let err = expect_frame_error(false, &inbound(false, 0x8, true, &payload)).await;
        assert!(
            err.contains("UTF-8"),
            "expected a UTF-8 rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn shutdown_sends_a_single_close_frame() {
        for is_client_role in [false, true] {
            let (ours, mut peer) = tokio::io::duplex(4096);
            let mut ws = WebSocketStream::new(ours, Vec::new(), is_client_role);
            ws.shutdown().await.unwrap();
            let f = read_wire_frame(&mut peer).await;
            assert_eq!(f.opcode, 0x8, "shutdown must send a close frame");
            assert!(f.fin);
            assert_eq!(f.payload, 1000u16.to_be_bytes(), "a normal closure is 1000");
            assert_eq!(f.mask.is_some(), is_client_role);

            // Exactly once: a second shutdown must not emit a second close.
            ws.shutdown().await.unwrap();
            let mut extra = [0u8; 8];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(100), peer.read(&mut extra)).await
            {
                assert_eq!(n, 0, "a second close frame was sent");
            }
        }
    }

    // ======================================================= original tests

    #[tokio::test]
    async fn test_websocket_handshake_and_bidirectional_data() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, Some("/chat")).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = ws_server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Hello from client over WS!");
            ws_server
                .write_all(b"Hello from server over WS!")
                .await
                .unwrap();
            ws_server.flush().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut headers = HashMap::new();
            headers.insert("User-Agent".into(), "flux-test".into());
            let mut ws_client = client_handshake(client_io, "example.com", "/chat", &headers)
                .await
                .unwrap();
            ws_client
                .write_all(b"Hello from client over WS!")
                .await
                .unwrap();
            ws_client.flush().await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = ws_client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Hello from server over WS!");
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_large_pipelined_payload() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);

        let large_msg = vec![0x42u8; 32 * 1024]; // 32 KB payload
        let large_msg_clone = large_msg.clone();

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, None).await.unwrap();
            let mut buf = vec![0u8; large_msg_clone.len()];
            ws_server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, large_msg_clone);
        });

        let client_task = tokio::spawn(async move {
            let mut ws_client = client_handshake(client_io, "test.local", "/", &HashMap::new())
                .await
                .unwrap();
            ws_client.write_all(&large_msg).await.unwrap();
            ws_client.flush().await.unwrap();
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_close_frame_eof() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, None).await.unwrap();
            // Send Close frame: 0x88, length 0
            ws_server.inner.write_all(&[0x88, 0x00]).await.unwrap();
            ws_server.inner.flush().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut ws_client = client_handshake(client_io, "test.local", "/", &HashMap::new())
                .await
                .unwrap();
            let mut buf = [0u8; 32];
            let n = ws_client.read(&mut buf).await.unwrap();
            assert_eq!(n, 0); // Clean EOF!
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_shutdown_drains_buffer() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, None).await.unwrap();
            let mut buf = vec![0u8; b"buffered on shutdown".len()];
            ws_server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"buffered on shutdown");
        });

        let client_task = tokio::spawn(async move {
            let mut ws_client = client_handshake(client_io, "test.local", "/", &HashMap::new())
                .await
                .unwrap();
            ws_client.write_all(b"buffered on shutdown").await.unwrap();
            ws_client.shutdown().await.unwrap();
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }
}
