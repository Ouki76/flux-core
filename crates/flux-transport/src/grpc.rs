//! gRPC-over-HTTP/2 ("gun") transport framing.
//!
//! The proxy tunnels a byte stream through a single gRPC request/response pair.
//! This module owns the gRPC message layer *and* the HTTP/2 streams underneath
//! it, because the parts of gRPC that decide whether a tunnel actually succeeded
//! — the response `:status`, the `content-type`, and the terminal `grpc-status`
//! trailer — only exist at the HTTP/2 level. Wrapping [`crate::h2::H2Stream`]
//! would hide all three, so a peer answering `grpc-status: 12` or `text/html`
//! would look exactly like a clean end of stream. The generic HTTP/2 transport in
//! `crate::h2` is untouched and still serves the `h2` framing layer.

use bytes::{Bytes, BytesMut};
use flux_types::{AsyncStream, FluxError, FluxResult};
use h2::{RecvStream, SendStream};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Length of the gRPC message prefix: `[compressed u8][length u32 BE]`.
pub const GRPC_HEADER_LEN: usize = 5;

/// Maximum accepted length for a single length-prefixed gRPC message.
///
/// The length is four raw wire bytes, so a peer may legally claim up to
/// `u32::MAX`; without a cap a single 5-byte header makes the proxy buffer
/// 4 GiB before it can emit anything (unauthenticated remote memory DoS).
/// 16 MiB is far above any legitimate proxy frame (the tunnel streams in
/// `read_buf`-sized chunks) and keeps the worst case bounded.
pub const MAX_GRPC_MESSAGE: usize = 16 * 1024 * 1024;

/// Largest payload the proxy puts into one outbound gRPC message. Keeping this
/// small bounds the per-write allocation and keeps a frame inside one HTTP/2
/// flow-control window.
/// Largest payload placed in one gRPC message.
///
/// This was 16 KiB, so a 64 KiB write from the relay became four messages with four
/// copies, four length prefixes and four flushes — the same defect that cost the
/// WebSocket transport ~20 % until its cap was matched to the copy buffer.
const MAX_WRITE_CHUNK: usize = 64 * 1024;

/// Longest `:path` accepted on the server side. A gRPC method path is a few tens
/// of bytes; anything larger is a probe or an attempt to grow our buffers.
const MAX_PATH_LEN: usize = 1024;

/// Longest service name accepted from configuration.
const MAX_SERVICE_LEN: usize = 128;

/// Bound on the `grpc-message` text copied into an error.
const MAX_STATUS_TEXT: usize = 256;

/// How long a rejected request keeps the connection alive so the refusal is
/// actually flushed to the peer before the socket closes.
const REJECT_LINGER: std::time::Duration = std::time::Duration::from_millis(500);

/// The protobuf envelope this transport carries: field 1, length delimited.
const FIELD_TAG: u8 = 0x0A;

/// gRPC stream wrapper applying the gRPC wire format:
/// `[compressed flag u8: 0x00][message length u32 BE][protobuf field 1 envelope]`.
pub struct GrpcStream {
    send: SendStream<Bytes>,
    recv: RecvState,
    read_buf: BytesMut,
    unread_payload: Bytes,
    unread_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    pending_chunk_len: usize,
    trailers_sent: bool,
    /// Set once framing has failed. An `io::Error` from a framed stream is
    /// terminal: without this a caller that ignores one error would keep reading
    /// a desynchronised byte stream.
    poisoned: bool,
}

enum RecvState {
    /// Client side: the request is out, the response HEADERS are not in yet.
    Negotiating(h2::client::ResponseFuture),
    /// Body readable.
    Body(RecvStream),
    /// The terminal condition has already been reported.
    Ended,
}

/// What one pass over `read_buf` found.
enum FrameStep {
    /// A complete message carrying tunnel bytes.
    Payload(Bytes),
    /// A complete message that carries nothing (nothing to hand to the caller).
    Empty,
    /// Header buffered, body still missing.
    Incomplete,
}

impl GrpcStream {
    fn new_client(send: SendStream<Bytes>, response: h2::client::ResponseFuture) -> Self {
        Self::with_state(send, RecvState::Negotiating(response))
    }

    fn new_server(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self::with_state(send, RecvState::Body(recv))
    }

    fn with_state(send: SendStream<Bytes>, recv: RecvState) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::with_capacity(16 * 1024),
            unread_payload: Bytes::new(),
            unread_pos: 0,
            write_buf: Vec::with_capacity(MAX_WRITE_CHUNK + GRPC_HEADER_LEN + 10),
            write_pos: 0,
            pending_chunk_len: 0,
            trailers_sent: false,
            poisoned: false,
        }
    }

    fn poison(&mut self, error: io::Error) -> io::Error {
        self.poisoned = true;
        error
    }

    /// Splits one complete gRPC message off the front of `read_buf`.
    fn parse_frame(&mut self) -> io::Result<FrameStep> {
        debug_assert!(self.read_buf.len() >= GRPC_HEADER_LEN);
        let frame_len = u32::from_be_bytes([
            self.read_buf[1],
            self.read_buf[2],
            self.read_buf[3],
            self.read_buf[4],
        ]) as usize;
        if frame_len > MAX_GRPC_MESSAGE {
            return Err(self.poison(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "gRPC message length {frame_len} exceeds the {MAX_GRPC_MESSAGE}-byte limit"
                ),
            )));
        }
        let total = GRPC_HEADER_LEN + frame_len;
        if self.read_buf.len() < total {
            // Reserve for exactly this message: growing by 8 KiB reads and
            // doubling would cost up to twice the declared length.
            self.read_buf.reserve(total - self.read_buf.len());
            return Ok(FrameStep::Incomplete);
        }

        let frame = self.read_buf.split_to(total).freeze();
        let flag = frame[0];
        // No compressor is negotiated (we never advertise one), so a message
        // marked compressed can never be decoded. Accepting the flag would hand
        // the caller ciphertext and parse the protobuf envelope from it.
        if flag != 0 {
            return Err(self.poison(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "gRPC message declares compressed flag {flag} but no compression was \
                     negotiated"
                ),
            )));
        }

        let body = frame.slice(GRPC_HEADER_LEN..);
        if body.is_empty() {
            return Ok(FrameStep::Empty);
        }
        if body[0] != FIELD_TAG {
            return Err(self.poison(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "gRPC payload is not a length-delimited protobuf field 1 (first byte {:#04x})",
                    body[0]
                ),
            )));
        }
        let rest = body.slice(1..);
        let (declared, consumed) = decode_varint(&rest).map_err(|e| self.poison(e))?;
        let payload = rest.slice(consumed..);
        // The inner length must describe the whole message. A shorter value used
        // to be accepted and its trailing bytes silently dropped.
        if declared != payload.len() {
            return Err(self.poison(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "gRPC protobuf field length {declared} does not match the {} byte payload",
                    payload.len()
                ),
            )));
        }
        if payload.is_empty() {
            Ok(FrameStep::Empty)
        } else {
            Ok(FrameStep::Payload(payload))
        }
    }

    /// Polls the HTTP/2 side. `Ok(None)` means the stream ended, `Ok(Some(n))`
    /// that `n` bytes were appended to `read_buf`.
    fn poll_next_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        loop {
            match std::mem::replace(&mut self.recv, RecvState::Ended) {
                RecvState::Negotiating(mut response) => match Pin::new(&mut response).poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        if let Err(e) = check_response(&response) {
                            self.poisoned = true;
                            return Poll::Ready(Err(e));
                        }
                        self.recv = RecvState::Body(response.into_body());
                    }
                    Poll::Ready(Err(e)) => {
                        let e = io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("gRPC response error: {e}"),
                        );
                        self.poisoned = true;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.recv = RecvState::Negotiating(response);
                        return Poll::Pending;
                    }
                },
                RecvState::Body(mut recv) => match recv.poll_data(cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        let _ = recv.flow_control().release_capacity(bytes.len());
                        let len = bytes.len();
                        self.read_buf.extend_from_slice(&bytes);
                        self.recv = RecvState::Body(recv);
                        return Poll::Ready(Ok(Some(len)));
                    }
                    Poll::Ready(Some(Err(e))) => {
                        let e = io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("gRPC stream error: {e}"),
                        );
                        self.poisoned = true;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(None) => match recv.poll_trailers(cx) {
                        Poll::Ready(Ok(trailers)) => {
                            let outcome = grpc_status(&trailers);
                            if outcome.is_err() {
                                self.poisoned = true;
                            }
                            return Poll::Ready(outcome);
                        }
                        Poll::Ready(Err(e)) => {
                            let e = io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!("gRPC trailer error: {e}"),
                            );
                            self.poisoned = true;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            self.recv = RecvState::Body(recv);
                            return Poll::Pending;
                        }
                    },
                    Poll::Pending => {
                        self.recv = RecvState::Body(recv);
                        return Poll::Pending;
                    }
                },
                RecvState::Ended => return Poll::Ready(Ok(None)),
            }
        }
    }

    fn frame_chunk(&mut self, data: &[u8]) -> usize {
        let chunk = data.len().min(MAX_WRITE_CHUNK);
        let mut varint = [0u8; 10];
        let mut len = 0;
        let mut value = chunk as u64;
        while value >= 0x80 {
            varint[len] = (value as u8 & 0x7f) | 0x80;
            value >>= 7;
            len += 1;
        }
        varint[len] = value as u8;
        len += 1;

        let proto_len = 1 + len + chunk;
        self.write_buf.clear();
        self.write_buf.reserve(GRPC_HEADER_LEN + proto_len);
        self.write_buf.push(0x00); // not compressed
        self.write_buf
            .extend_from_slice(&(proto_len as u32).to_be_bytes());
        self.write_buf.push(FIELD_TAG);
        self.write_buf.extend_from_slice(&varint[..len]);
        self.write_buf.extend_from_slice(&data[..chunk]);
        self.write_pos = 0;
        self.pending_chunk_len = chunk;
        chunk
    }

    /// Pushes one slice of `write_buf` into the HTTP/2 stream.
    fn poll_send_some(
        &mut self,
        cx: &mut Context<'_>,
        remaining: usize,
    ) -> Poll<io::Result<usize>> {
        // Use the capacity h2 has *already* granted before asking for more.
        // `poll_capacity` reports newly granted capacity and stays `Pending` when
        // nothing new arrived, so calling it unconditionally made every frame wait
        // for the next WINDOW_UPDATE — a scheduler round trip per 16 KiB message,
        // which is what capped this transport at ~280 MB/s instead of ~3 GB/s.
        let capacity = self.send.capacity();
        if capacity > 0 {
            return Poll::Ready(Ok(capacity));
        }
        self.send.reserve_capacity(remaining);
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                if capacity == 0 {
                    // After `reserve_capacity`, `poll_capacity` stays pending
                    // until the peer grants something: a zero here means it never
                    // will.
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "gRPC stream can no longer accept data",
                    )));
                }
                Poll::Ready(Ok(capacity))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Writes out the frame currently held in `write_buf`.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let remaining = self.write_buf.len() - self.write_pos;
            let capacity = match self.poll_send_some(cx, remaining) {
                Poll::Ready(Ok(capacity)) => capacity,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let take = remaining.min(capacity);
            let end = self.write_pos + take;
            let chunk = Bytes::copy_from_slice(&self.write_buf[self.write_pos..end]);
            if let Err(e) = self.send.send_data(chunk, false) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    e.to_string(),
                )));
            }
            self.write_pos = end;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        if this.poisoned {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gRPC stream is desynchronised after an earlier framing error",
            )));
        }
        // A zero-capacity buffer must complete immediately: falling through to a
        // socket read parks the caller until the peer happens to send data.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Deliver as much as the caller asked for, not one message per poll. The
        // relay reads with a 64 KiB buffer and a message is 64 KiB, so returning
        // after a single one made every buffer a separate read/parse cycle.
        let mut put = 0usize;

        loop {
            // Drain payload left over from a message larger than `buf`.
            if this.unread_pos < this.unread_payload.len() {
                let available = this.unread_payload.len() - this.unread_pos;
                let take = available.min(buf.remaining());
                buf.put_slice(&this.unread_payload[this.unread_pos..this.unread_pos + take]);
                this.unread_pos += take;
                put += take;
                if this.unread_pos == this.unread_payload.len() {
                    this.unread_payload = Bytes::new();
                    this.unread_pos = 0;
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            if this.read_buf.len() >= GRPC_HEADER_LEN {
                match this.parse_frame() {
                    Ok(FrameStep::Payload(payload)) => {
                        let take = payload.len().min(buf.remaining());
                        buf.put_slice(&payload[..take]);
                        put += take;
                        if take < payload.len() {
                            this.unread_payload = payload;
                            this.unread_pos = take;
                        }
                        if buf.remaining() == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        continue;
                    }
                    Ok(FrameStep::Empty) => continue,
                    Ok(FrameStep::Incomplete) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            let more = match this.poll_next_chunk(cx) {
                Poll::Ready(Ok(more)) => more,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // Nothing more right now: if bytes were delivered, that is a
                // successful read.
                Poll::Pending => {
                    return if put > 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            };
            match more {
                Some(_) => continue,
                None => {
                    if !this.read_buf.is_empty() {
                        let buffered = this.read_buf.len();
                        return Poll::Ready(Err(this.poison(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "unexpected EOF inside a gRPC message ({buffered} bytes buffered)"
                            ),
                        ))));
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Finish a frame a previous call could not flush. The caller retries with
        // the same bytes after `Pending` (AsyncWrite contract), so the number
        // accepted is the size of the frame being drained.
        if this.write_pos < this.write_buf.len() {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {
                    let flushed = this.pending_chunk_len;
                    this.write_buf.clear();
                    this.write_pos = 0;
                    this.pending_chunk_len = 0;
                    return Poll::Ready(Ok(flushed));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk = this.frame_chunk(buf);
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                Poll::Ready(Ok(chunk))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Never end the stream while a frame is still half-written: trailers carry
        // END_STREAM and would truncate the message the caller just handed us.
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_chunk_len = 0;
        if !this.trailers_sent {
            this.trailers_sent = true;
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            let _ = this.send.send_trailers(trailers);
        }
        let _ = this.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

/// Decodes a protobuf varint, returning the value and the bytes consumed.
fn decode_varint(buf: &[u8]) -> io::Result<(usize, usize)> {
    let mut value: u64 = 0;
    for (index, &byte) in buf.iter().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            // The tenth byte may only carry the one remaining bit of a u64.
            if index == 9 && byte > 0x01 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf varint length overflows 64 bits",
                ));
            }
            let value = usize::try_from(value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf varint length does not fit in usize",
                )
            })?;
            return Ok((value, index + 1));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "malformed or unterminated protobuf varint length",
    ))
}

/// `application/grpc` and `application/grpc+proto`, with parameters ignored.
fn is_grpc_content_type(value: &str) -> bool {
    let media = value.split(';').next().unwrap_or_default().trim();
    media.eq_ignore_ascii_case("application/grpc")
        || media.eq_ignore_ascii_case("application/grpc+proto")
}

/// Reads a header as text, ignoring values that are not ASCII.
fn header_str<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Interprets gRPC trailers. `Ok(None)` is a successful end of stream.
fn grpc_status(trailers: &Option<http::HeaderMap>) -> io::Result<Option<usize>> {
    let Some(headers) = trailers else {
        // The gun peers (sing-box, Xray and this proxy) end a stream with
        // END_STREAM and never send trailers at all: there is no status channel
        // in that dialect, so this is a plain end of stream rather than a status
        // we are ignoring.
        return Ok(None);
    };
    let Some(raw) = headers.get("grpc-status") else {
        // Trailers *are* the status channel: if the peer used it and left the
        // status out, that is a protocol violation, not an implicit OK.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC trailers carried no grpc-status (a missing status is not a successful end of stream)",
        ));
    };
    let text = raw.to_str().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC grpc-status trailer is not valid ASCII",
        )
    })?;
    let code: u32 = text.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("gRPC grpc-status {text:?} is not a status code"),
        )
    })?;
    if code == 0 {
        return Ok(None);
    }
    let message: String = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .chars()
        .take(MAX_STATUS_TEXT)
        .collect();
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("gRPC peer ended the tunnel with grpc-status {code}: {message}"),
    ))
}

/// Client side: the response must be a 200 that speaks gRPC.
fn check_response(response: &Response<RecvStream>) -> io::Result<()> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "gRPC peer rejected the tunnel with HTTP status {}",
                response.status()
            ),
        ));
    }
    let content_type = header_str(response.headers(), "content-type").unwrap_or_default();
    if !is_grpc_content_type(content_type) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "gRPC peer answered with Content-Type {content_type:?}, expected application/grpc"
            ),
        ));
    }
    Ok(())
}

/// A service name goes straight into the `:path` pseudo-header, so it may only
/// contain characters that cannot change the path's shape or break out of it.
fn validate_service_name(service: &str) -> Result<(), String> {
    if service.is_empty() {
        return Err("gRPC service name must not be empty".into());
    }
    if service.len() > MAX_SERVICE_LEN {
        return Err(format!(
            "gRPC service name is {} bytes, limit is {MAX_SERVICE_LEN}",
            service.len()
        ));
    }
    // A leading dot is not a proto identifier and would make `/./`-style
    // normalisation turn the method path into something else.
    if !service.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(format!(
            "gRPC service name {service:?} must start with an ASCII alphanumeric"
        ));
    }
    for byte in service.bytes() {
        let allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~');
        if !allowed {
            return Err(format!(
                "gRPC service name contains the invalid byte {byte:#04x}; \
                 only ASCII alphanumerics and . - _ ~ are allowed"
            ));
        }
    }
    Ok(())
}

/// Splits a gRPC method path into `(service, method)`, rejecting anything that is
/// not exactly `/<service>/<method>`.
fn split_grpc_path(path: &str) -> Result<(&str, &str), String> {
    if path.len() > MAX_PATH_LEN {
        return Err(format!(
            "gRPC path is {} bytes, limit is {MAX_PATH_LEN}",
            path.len()
        ));
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(format!("gRPC path {path:?} does not start with '/'"));
    };
    let mut parts = rest.split('/');
    let service = parts.next().unwrap_or_default();
    let method = parts
        .next()
        .ok_or_else(|| format!("gRPC path {path:?} is not /<service>/<method>"))?;
    if parts.next().is_some() {
        return Err(format!(
            "gRPC path {path:?} has more than the service and method segments"
        ));
    }
    if service.is_empty() {
        return Err(format!("gRPC path {path:?} has an empty service name"));
    }
    if method.is_empty() {
        return Err(format!("gRPC path {path:?} has an empty method name"));
    }
    for segment in [service, method] {
        if !segment.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(format!(
                "gRPC path {path:?} contains control or non-ASCII bytes"
            ));
        }
        if segment.contains(['?', '\u{5c}', '#']) {
            // `\` is a path separator to some servers, and normalising
            // infrastructure can collapse `/../`. Neither can reach a gun peer.
            return Err(format!(
                "gRPC path {path:?} contains a query, fragment or path separator"
            ));
        }
    }
    Ok((service, method))
}

/// Server side: only a well formed gRPC request may open a tunnel. Anything else
/// is answered like a plain gRPC endpoint would answer it, so an active prober
/// learns nothing from the connection.
fn validate_request(request: &Request<RecvStream>) -> Result<(), String> {
    if request.method() != Method::POST {
        return Err(format!(
            "gRPC tunnel requires POST, got {}",
            request.method()
        ));
    }
    if request.uri().query().is_some() {
        return Err("gRPC path must not carry a query string".into());
    }
    split_grpc_path(request.uri().path())?;
    let content_type = header_str(request.headers(), "content-type")
        .ok_or("gRPC tunnel requires a Content-Type header")?;
    if !is_grpc_content_type(content_type) {
        return Err(format!(
            "gRPC tunnel requires Content-Type application/grpc, got {content_type:?}"
        ));
    }
    match header_str(request.headers(), "te") {
        Some(value) if value.trim().eq_ignore_ascii_case("trailers") => {}
        Some(value) => {
            return Err(format!("gRPC requires TE: trailers, got TE: {value:?}"));
        }
        None => return Err("gRPC requires the TE: trailers header".into()),
    }
    if let Some(encoding) = header_str(request.headers(), "grpc-encoding") {
        let encoding = encoding.trim();
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            // Refusing here is the only safe answer: we have no decompressor, so
            // the messages that follow could never be decoded.
            return Err(format!(
                "unsupported grpc-encoding {encoding:?}: this endpoint has no compressor"
            ));
        }
    }
    Ok(())
}

/// gRPC framing over HTTP/2.
pub struct GrpcTransport;

impl GrpcTransport {
    /// Client-side gRPC handshake (Gun / Multi-mode).
    pub async fn client_handshake<S>(
        stream: S,
        host: &str,
        service_name: &str,
        headers: &HashMap<String, String>,
    ) -> FluxResult<GrpcStream>
    where
        S: AsyncStream + 'static,
    {
        validate_service_name(service_name).map_err(|message| FluxError::Protocol {
            protocol: "grpc",
            message,
        })?;
        let path = format!("/{service_name}/Tun");

        let mut client = crate::h2::shared::client_handshake(stream, "grpc").await?;

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header("host", host)
            .header("user-agent", "flux-core/h2")
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        for (name, value) in headers {
            // The framing headers are not configurable: a duplicate
            // `content-type` (HTTP header maps are case sensitive) would leave
            // the peer picking one of two values arbitrarily.
            if is_framing_header(name) {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder.body(()).map_err(|e| FluxError::Protocol {
            protocol: "grpc",
            message: format!("failed to build gRPC request: {e}"),
        })?;

        let (response, send) =
            client
                .send_request(request, false)
                .map_err(|e| FluxError::Protocol {
                    protocol: "grpc",
                    message: format!("failed to send gRPC request: {e}"),
                })?;
        Ok(GrpcStream::new_client(send, response))
    }

    /// Server-side gRPC handshake.
    pub async fn server_handshake<S>(stream: S) -> FluxResult<GrpcStream>
    where
        S: AsyncStream + 'static,
    {
        let mut connection = crate::h2::shared::server_handshake(stream, "grpc").await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or_else(|| FluxError::Protocol {
                protocol: "grpc",
                message: "gRPC client closed the connection before sending a request".into(),
            })?
            .map_err(|e| FluxError::Protocol {
                protocol: "grpc",
                message: format!("error receiving gRPC request: {e}"),
            })?;

        if let Err(message) = validate_request(&request) {
            // Answer exactly like a real single-purpose gRPC endpoint (sing-box
            // replies 404 to a bad path, method or content type), then let the
            // connection close.
            let refusal = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .expect("static refusal response");
            let _ = respond.send_response(refusal, true);
            crate::h2::shared::spawn_connection_driver(connection, Some(REJECT_LINGER));
            return Err(FluxError::Protocol {
                protocol: "grpc",
                message,
            });
        }

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-accept-encoding", "identity")
            .body(())
            .map_err(|e| FluxError::Protocol {
                protocol: "grpc",
                message: format!("failed to build gRPC response: {e}"),
            })?;
        let send = respond
            .send_response(response, false)
            .map_err(|e| FluxError::Protocol {
                protocol: "grpc",
                message: format!("failed to send gRPC response: {e}"),
            })?;

        let recv = request.into_body();
        crate::h2::shared::spawn_connection_driver(connection, None);
        Ok(GrpcStream::new_server(send, recv))
    }
}

/// Headers the transport sets itself and config may not duplicate.
fn is_framing_header(name: &str) -> bool {
    ["content-type", "te", "host", "user-agent"]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_grpc_stream_encapsulation() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let srv = tokio::spawn(async move {
            let mut srv_stream = GrpcTransport::server_handshake(server_io).await.unwrap();
            let mut buf = [0u8; 13];
            srv_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"grpc request!");
            srv_stream.write_all(b"grpc reply!!").await.unwrap();
            srv_stream.flush().await.unwrap();
            let _ = done_rx.await;
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            cli_stream.write_all(b"grpc request!").await.unwrap();
            cli_stream.flush().await.unwrap();

            let mut buf = [0u8; 12];
            cli_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"grpc reply!!");
            let _ = done_tx.send(());
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_grpc_stream_backpressure_and_partial_writes() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let data_len = 1_500_000; // 1.5 MB, larger than H2 initial window (1MB)
        let original_data: Vec<u8> = (0..data_len).map(|i| (i % 251) as u8).collect();
        let expected_data = original_data.clone();

        let srv = tokio::spawn(async move {
            let mut srv_stream = GrpcTransport::server_handshake(server_io).await.unwrap();
            let mut received = Vec::with_capacity(data_len);
            let mut buf = vec![0u8; 8192];
            while received.len() < data_len {
                let n = srv_stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(received.len(), expected_data.len());
            assert_eq!(received, expected_data);
            let _ = done_tx.send(());
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            cli_stream.write_all(&original_data).await.unwrap();
            cli_stream.flush().await.unwrap();
            let _ = done_rx.await;
        });

        cli.await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_grpc_unterminated_protobuf_varint_rejected() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let srv = tokio::spawn(async move {
            let mut srv_h2 = crate::h2::H2Transport::server_handshake(server_io)
                .await
                .unwrap();
            // Send gRPC frame: 5-byte header indicating 3 bytes of payload
            // Payload is 0x0A (field 1 tag) followed by unterminated varint [0x80, 0x80]
            let frame = vec![0x00, 0x00, 0x00, 0x00, 3, 0x0A, 0x80, 0x80];
            srv_h2.write_all(&frame).await.unwrap();
            srv_h2.flush().await.unwrap();
            srv_h2.shutdown().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            let mut buf = vec![0u8; 64];
            let err = cli_stream.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}

/// Hardening tests for the gRPC-over-HTTP/2 framing layer.
///
/// The class of defect these look for is the one the parallel cycles found in
/// the WebSocket and ShadowTLS layers: a peer that is allowed to stay inside the
/// protocol can make the proxy mis-frame, silently drop bytes, treat a failure as
/// a clean end of stream, or park a task forever. Every test therefore drives a
/// *hostile* peer (a raw HTTP/2 endpoint that answers however the test wants)
/// rather than only the proxy's own client, and every read is wrapped in a
/// timeout so a hang fails the test instead of wedging the suite.
#[cfg(test)]
mod hardening_tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    /// Generous upper bound for any single step; a healthy implementation needs
    /// milliseconds, so hitting this means a hang.
    const T: Duration = Duration::from_secs(5);

    // ---------------------------------------------------------------- helpers

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    /// A gRPC message with an arbitrary compression flag and body.
    fn frame_with(flag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![flag];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// The gun envelope this proxy speaks: `0x0A || varint(len) || payload`.
    fn gun_frame(payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0x0A];
        body.extend_from_slice(&varint(payload.len() as u64));
        body.extend_from_slice(payload);
        frame_with(0, &body)
    }

    /// A well-formed envelope whose inner length field claims `declared`.
    fn envelope(declared: u64, tail: &[u8]) -> Vec<u8> {
        let mut body = vec![0x0A];
        body.extend_from_slice(&varint(declared));
        body.extend_from_slice(tail);
        frame_with(0, &body)
    }

    /// A proxy client and server talking to each other over an in-memory pipe.
    async fn grpc_pair() -> (GrpcStream, GrpcStream) {
        let (cli_io, srv_io) = tokio::io::duplex(4 * 1024 * 1024);
        let srv = tokio::spawn(async move { GrpcTransport::server_handshake(srv_io).await });
        let cli = timeout(
            T,
            GrpcTransport::client_handshake(cli_io, "grpc.example.com", "Svc", &HashMap::new()),
        )
        .await
        .expect("client handshake hung")
        .expect("client handshake");
        let srv = timeout(T, srv)
            .await
            .expect("server handshake join hung")
            .expect("server handshake join")
            .expect("server handshake");
        (cli, srv)
    }

    /// How a hostile peer terminates the response stream.
    enum Ending {
        /// END_STREAM on an empty DATA frame, no trailers at all: what the gun
        /// peers (sing-box, Xray) do.
        CleanEnd,
        /// gRPC trailers.
        Trailers(Vec<(&'static str, &'static str)>),
        /// RST_STREAM.
        Reset(h2::Reason),
        /// Leave the stream open forever.
        Stall,
    }

    /// The response a hostile peer sends.
    struct PeerScript {
        status: u16,
        content_type: Option<&'static str>,
        extra_headers: Vec<(&'static str, &'static str)>,
        frames: Vec<Vec<u8>>,
        ending: Ending,
        /// Write every frame one byte at a time, so a message arrives across many
        /// DATA frames and the reader must hold a partial frame.
        paced: bool,
    }

    impl PeerScript {
        /// A textbook gRPC response: 200, `application/grpc`, clean end.
        fn ok() -> Self {
            Self {
                status: 200,
                content_type: Some("application/grpc"),
                extra_headers: Vec::new(),
                frames: Vec::new(),
                ending: Ending::CleanEnd,
                paced: false,
            }
        }

        fn frames(frames: Vec<Vec<u8>>) -> Self {
            Self {
                frames,
                ..Self::ok()
            }
        }

        fn ending(mut self, ending: Ending) -> Self {
            self.ending = ending;
            self
        }

        fn content_type(mut self, content_type: Option<&'static str>) -> Self {
            self.content_type = content_type;
            self
        }

        fn status(mut self, status: u16) -> Self {
            self.status = status;
            self
        }

        fn paced(mut self) -> Self {
            self.paced = true;
            self
        }
    }

    /// Writes `data` respecting HTTP/2 flow control, so the peer produces real
    /// multi-frame DATA sequences instead of one giant frame.
    async fn peer_write(stream: &mut h2::SendStream<Bytes>, mut data: Bytes) {
        while !data.is_empty() {
            stream.reserve_capacity(data.len());
            let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .expect("capacity poll failed")
                .expect("peer stream closed while writing");
            let take = capacity.min(data.len());
            let rest = data.split_off(take);
            stream.send_data(data, false).expect("peer send_data");
            data = rest;
        }
    }

    /// Connects the proxy's gRPC client to a raw HTTP/2 peer driven by `script`.
    async fn peer_with(
        script: PeerScript,
        capture: Option<tokio::sync::oneshot::Sender<HeaderMap>>,
        headers: HashMap<String, String>,
    ) -> GrpcStream {
        peer_with_body(script, capture, None, headers).await
    }

    /// As `peer_with`, but can also hand the request body it read to the test.
    async fn peer_with_body(
        script: PeerScript,
        capture: Option<tokio::sync::oneshot::Sender<HeaderMap>>,
        capture_body: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
        headers: HashMap<String, String>,
    ) -> GrpcStream {
        let PeerScript {
            status,
            content_type,
            extra_headers,
            frames,
            ending,
            paced,
        } = script;
        let (cli_io, srv_io) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(256 * 1024);
            let mut conn = builder
                .handshake::<_, Bytes>(srv_io)
                .await
                .expect("peer h2 handshake");
            let (request, mut respond) = conn
                .accept()
                .await
                .expect("peer accept")
                .expect("peer expects one stream");
            // h2 only writes queued frames while the connection future is polled.
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            if let Some(tx) = capture {
                let _ = tx.send(request.headers().clone());
            }
            // Keeping the request body alive matters: dropping it resets the
            // stream and the response would never reach the client.
            let mut request_body = request.into_body();

            if let Ending::Reset(reason) = ending {
                respond.send_reset(reason);
            } else {
                let mut response = Response::builder().status(status);
                if let Some(content_type) = content_type {
                    response = response.header("content-type", content_type);
                }
                for (name, value) in &extra_headers {
                    response = response.header(*name, *value);
                }
                let mut send = respond
                    .send_response(response.body(()).expect("peer response"), false)
                    .expect("peer send_response");
                for frame in &frames {
                    if paced {
                        for byte in frame {
                            peer_write(&mut send, Bytes::from(vec![*byte])).await;
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                    } else {
                        peer_write(&mut send, Bytes::from(frame.clone())).await;
                    }
                }
                if let Some(tx) = capture_body {
                    let mut collected = Vec::new();
                    while let Ok(Some(chunk)) =
                        timeout(Duration::from_millis(250), request_body.data()).await
                    {
                        match chunk {
                            Ok(bytes) => collected.extend_from_slice(&bytes),
                            Err(_) => break,
                        }
                    }
                    let _ = tx.send(collected);
                }
                match ending {
                    Ending::CleanEnd => {
                        let _ = send.send_data(Bytes::new(), true);
                    }
                    Ending::Trailers(ref pairs) => {
                        let mut trailers = HeaderMap::new();
                        for (name, value) in pairs {
                            trailers.insert(
                                HeaderName::from_static(name),
                                HeaderValue::from_static(value),
                            );
                        }
                        let _ = send.send_trailers(trailers);
                    }
                    Ending::Reset(_) | Ending::Stall => {}
                }
            }

            // Hold the stream open briefly: dropping the handles sends RST_STREAM,
            // which can overtake the tail of the response. `Stall` holds long
            // enough that the stream is still open when the test gives up.
            let hold = match ending {
                Ending::Stall => 60_000,
                _ => 300,
            };
            tokio::time::sleep(Duration::from_millis(hold)).await;
            drop(request_body);
        });
        timeout(
            T,
            GrpcTransport::client_handshake(cli_io, "grpc.example.com", "Svc", &headers),
        )
        .await
        .expect("client handshake hung")
        .expect("client handshake")
    }

    async fn hostile_peer(script: PeerScript) -> GrpcStream {
        peer_with(script, None, HashMap::new()).await
    }

    /// A gRPC request as the proxy's own client would write it.
    fn grpc_request(path: &str) -> Request<()> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("request")
    }

    /// One raw HTTP/2 exchange against the proxy's gRPC *server*: the verdict of
    /// the handshake plus whatever the client saw on the wire.
    async fn probe_server(
        request: Request<()>,
    ) -> (
        Result<GrpcStream, flux_types::FluxError>,
        Option<(StatusCode, HeaderMap)>,
    ) {
        let (cli_io, srv_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move { GrpcTransport::server_handshake(srv_io).await });
        let (mut client, conn) = h2::client::handshake(cli_io)
            .await
            .expect("raw client h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let (response_fut, mut send) = client.send_request(request, false).expect("send_request");
        let seen = match timeout(Duration::from_secs(2), response_fut).await {
            Ok(Ok(response)) => Some((response.status(), response.headers().clone())),
            _ => None,
        };
        // Half-close the request body so the server side sees a complete request.
        let _ = send.send_data(Bytes::new(), true);
        let verdict = timeout(T, server)
            .await
            .expect("server handshake hung")
            .expect("server handshake join");
        (verdict, seen)
    }

    async fn expect_read_error(stream: &mut GrpcStream, what: &str) -> io::Error {
        let mut buf = [0u8; 64];
        match timeout(T, stream.read(&mut buf)).await {
            Ok(Ok(n)) => panic!(
                "{what}: expected an error, got {n} payload bytes {:?}",
                &buf[..n]
            ),
            Ok(Err(e)) => e,
            Err(_) => panic!("{what}: read hung"),
        }
    }

    async fn expect_eof(stream: &mut GrpcStream, what: &str) {
        let mut buf = [0u8; 64];
        match timeout(T, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{what}: expected end of stream, got {n} payload bytes"),
            Ok(Err(e)) => panic!("{what}: expected end of stream, got error: {e}"),
            Err(_) => panic!("{what}: read hung"),
        }
    }

    async fn expect_payload(stream: &mut GrpcStream, expected: &[u8], what: &str) {
        let mut buf = vec![0u8; expected.len().max(1)];
        let n = match timeout(T, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("{what}: unexpected error: {e}"),
            Err(_) => panic!("{what}: read hung"),
        };
        assert_eq!(&buf[..n], expected, "{what}: wrong payload");
    }

    // ------------------------------------------------- 1. gRPC message framing

    /// A message carrying the compression flag must be refused: no compressor is
    /// negotiated, so the body is opaque and passing it on desynchronises the
    /// tunnel. The flag used to be skipped entirely.
    #[tokio::test]
    async fn compressed_flag_is_refused() {
        let mut cli = hostile_peer(PeerScript::frames(vec![frame_with(
            0x01,
            &[0x0A, 0x03, b'a', b'b', b'c'],
        )]))
        .await;
        let err = expect_read_error(&mut cli, "compressed message").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(
            err.to_string().contains("compress"),
            "error should name the compression flag: {err}"
        );
    }

    /// The same, for a "compressed" body that does not even look like the gun
    /// envelope: previously it was handed to the caller as if it were plaintext.
    #[tokio::test]
    async fn compressed_flag_hiding_raw_payload_is_refused() {
        let mut cli = hostile_peer(PeerScript::frames(vec![frame_with(
            0x01,
            b"not-an-envelope",
        )]))
        .await;
        let err = expect_read_error(&mut cli, "compressed raw message").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// A zero-length message carries no tunnel bytes. It must be skipped, not
    /// surfaced as a zero-length read (which every caller reads as EOF).
    #[tokio::test]
    async fn empty_message_is_skipped_and_the_next_frame_is_delivered() {
        let mut cli = hostile_peer(PeerScript::frames(vec![
            frame_with(0, &[]),
            gun_frame(b"after the empty message"),
        ]))
        .await;
        expect_payload(&mut cli, b"after the empty message", "empty frame skip").await;
    }

    /// A pure stream of empty messages is an end of stream, never a hang.
    #[tokio::test]
    async fn only_empty_messages_then_clean_end_is_eof() {
        let mut cli = hostile_peer(PeerScript::frames(vec![
            frame_with(0, &[]),
            frame_with(0, &[]),
            frame_with(0, &[]),
        ]))
        .await;
        expect_eof(&mut cli, "empty message stream").await;
    }

    /// After a framing failure the byte stream is desynchronised, so the reader
    /// must not quietly resume at the next frame.
    #[tokio::test]
    async fn a_framing_error_poisons_the_stream() {
        let mut cli = hostile_peer(PeerScript::frames(vec![
            frame_with(0x01, &[0x0A, 0x01, b'x']),
            gun_frame(b"never-delivered"),
        ]))
        .await;
        let first = expect_read_error(&mut cli, "compressed then valid").await;
        assert_eq!(first.kind(), io::ErrorKind::InvalidData, "{first}");
        let second = expect_read_error(&mut cli, "after a framing error").await;
        assert!(
            second.to_string().contains("desynchronised"),
            "a read after a framing error must fail too, got: {second}"
        );
    }

    /// A message dribbled one byte at a time (many DATA frames, many reads) must
    /// be reassembled byte for byte, and a partial message must never be handed
    /// to the caller.
    #[tokio::test]
    async fn message_split_across_frames_is_reassembled() {
        let mut cli =
            hostile_peer(PeerScript::frames(vec![gun_frame(b"dribbled-payload")]).paced()).await;
        expect_payload(&mut cli, b"dribbled-payload", "paced message").await;
        expect_eof(&mut cli, "paced message").await;
    }

    /// A message whose header promises 20 bytes but delivers four is a truncated
    /// stream, not a short read. (The peer here announces itself as gRPC; the
    /// old version of this test used a raw HTTP/2 peer, which is now refused at
    /// the handshake because it answers with a non-gRPC content type.)
    #[tokio::test]
    async fn truncated_message_body_is_an_unexpected_eof() {
        let mut frame = vec![0x00, 0x00, 0x00, 0x00, 20];
        frame.extend_from_slice(b"abcd");
        let mut cli = hostile_peer(PeerScript::frames(vec![frame])).await;
        let err = expect_read_error(&mut cli, "truncated body").await;
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    /// A header split across reads is held, and a header that stops half way is
    /// an error rather than a short read.
    #[tokio::test]
    async fn partial_header_then_clean_end_is_an_error() {
        let mut cli = hostile_peer(PeerScript::frames(vec![vec![0x00, 0x00, 0x00]]).paced()).await;
        let err = expect_read_error(&mut cli, "half a header").await;
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    /// The inner protobuf length must describe the *whole* message body. A
    /// shorter claim used to silently drop the trailing bytes (data loss).
    #[tokio::test]
    async fn inner_length_shorter_than_payload_is_refused() {
        let mut cli = hostile_peer(PeerScript::frames(vec![envelope(2, b"abc")])).await;
        let err = expect_read_error(&mut cli, "short inner length").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(
            err.to_string().contains("does not match"),
            "error should explain the length mismatch: {err}"
        );
    }

    /// And a longer claim is equally invalid.
    #[tokio::test]
    async fn inner_length_longer_than_payload_is_refused() {
        let mut cli = hostile_peer(PeerScript::frames(vec![envelope(10, b"abc")])).await;
        let err = expect_read_error(&mut cli, "long inner length").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// An inner length of zero is an empty message: skip it, keep the stream.
    #[tokio::test]
    async fn inner_length_zero_is_an_empty_message() {
        let mut cli = hostile_peer(PeerScript::frames(vec![
            envelope(0, b""),
            gun_frame(b"still alive"),
        ]))
        .await;
        expect_payload(&mut cli, b"still alive", "zero inner length").await;
    }

    /// The payload must be field 1 of the protobuf envelope. Without the tag the
    /// framing is ambiguous (two encodings for the same bytes) and a peer could
    /// bypass the inner length check by prefixing a byte.
    #[tokio::test]
    async fn payload_without_the_field_tag_is_refused() {
        let mut cli = hostile_peer(PeerScript::frames(vec![frame_with(0, b"abc")])).await;
        let err = expect_read_error(&mut cli, "missing field tag").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(
            err.to_string().contains("field 1"),
            "error should name the missing field tag: {err}"
        );
    }

    /// An unterminated varint, and an overlong one, are both refused.
    #[tokio::test]
    async fn malformed_varints_are_refused() {
        // Continuation bit set on the last available byte.
        let mut cli =
            hostile_peer(PeerScript::frames(vec![frame_with(0, &[0x0A, 0x80, 0x80])])).await;
        let err = expect_read_error(&mut cli, "unterminated varint").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");

        // Eleven continuation bytes: longer than any u64.
        let mut body = vec![0x0A];
        body.extend_from_slice(&[0x80; 11]);
        let mut cli = hostile_peer(PeerScript::frames(vec![frame_with(0, &body)])).await;
        let err = expect_read_error(&mut cli, "overlong varint").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    // ------------------------------------------------------------ 2. trailers

    /// A non-zero `grpc-status` is a failure, not a clean end of stream. Ignoring
    /// it turns an error into a silent truncation.
    #[tokio::test]
    async fn non_zero_grpc_status_is_an_error() {
        let mut cli = hostile_peer(PeerScript::ok().ending(Ending::Trailers(vec![
            ("grpc-status", "7"),
            ("grpc-message", "permission denied"),
        ])))
        .await;
        let err = expect_read_error(&mut cli, "grpc-status 7").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// The status code and message reach the caller's error text, so a failure is
    /// diagnosable rather than an anonymous "connection closed".
    #[tokio::test]
    async fn grpc_status_and_message_reach_the_error() {
        let mut cli = hostile_peer(PeerScript::ok().ending(Ending::Trailers(vec![
            ("grpc-status", "13"),
            ("grpc-message", "internal explosion"),
        ])))
        .await;
        let err = expect_read_error(&mut cli, "grpc-status 13").await;
        let text = err.to_string();
        assert!(text.contains("13"), "{text}");
        assert!(text.contains("internal explosion"), "{text}");
    }

    /// Status 0 with data in front of it is the normal gRPC ending.
    #[tokio::test]
    async fn zero_grpc_status_ends_cleanly() {
        let mut cli = hostile_peer(
            PeerScript::frames(vec![gun_frame(b"payload")])
                .ending(Ending::Trailers(vec![("grpc-status", "0")])),
        )
        .await;
        expect_payload(&mut cli, b"payload", "status 0").await;
        expect_eof(&mut cli, "status 0").await;
    }

    /// Trailers that carry no status at all are a protocol violation, not an
    /// implicit OK.
    #[tokio::test]
    async fn trailers_without_grpc_status_are_refused() {
        let mut cli =
            hostile_peer(PeerScript::ok().ending(Ending::Trailers(vec![("x-trace", "abc")]))).await;
        let err = expect_read_error(&mut cli, "trailers without status").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(
            err.to_string().contains("grpc-status"),
            "error should name the missing trailer: {err}"
        );
    }

    /// The gun peers (sing-box, Xray, this proxy) end a stream with END_STREAM
    /// and never send trailers; that is a plain end of stream and must stay
    /// working. Pinned here because the check above must not become stricter
    /// than the wire format allows.
    #[tokio::test]
    async fn clean_end_without_trailers_is_eof() {
        let mut cli = hostile_peer(PeerScript::frames(vec![gun_frame(b"last bytes")])).await;
        expect_payload(&mut cli, b"last bytes", "trailer-less close").await;
        expect_eof(&mut cli, "trailer-less close").await;
    }

    /// A peer that vanishes without saying anything is still just an end of
    /// stream, and must not hang.
    #[tokio::test]
    async fn silent_clean_end_is_eof() {
        let mut cli = hostile_peer(PeerScript::ok()).await;
        expect_eof(&mut cli, "silent close").await;
    }

    /// A reset in the middle of a message surfaces as an error.
    #[tokio::test]
    async fn reset_mid_message_is_an_error() {
        let mut partial = gun_frame(b"0123456789");
        partial.truncate(7);
        let mut cli = hostile_peer(
            PeerScript::frames(vec![partial]).ending(Ending::Reset(h2::Reason::INTERNAL_ERROR)),
        )
        .await;
        let err = expect_read_error(&mut cli, "reset mid message").await;
        assert_ne!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    /// A reset before any response at all is an error, not an empty tunnel.
    #[tokio::test]
    async fn reset_before_response_is_an_error() {
        let mut cli =
            hostile_peer(PeerScript::ok().ending(Ending::Reset(h2::Reason::CANCEL))).await;
        let err = expect_read_error(&mut cli, "reset before response").await;
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset, "{err}");
    }

    // ------------------------------------------- 3. content type and :path

    #[tokio::test]
    async fn wrong_content_type_is_refused() {
        let (verdict, seen) = probe_server(
            Request::builder()
                .method("POST")
                .uri("/Svc/Tun")
                .header("content-type", "text/plain")
                .header("te", "trailers")
                .body(())
                .unwrap(),
        )
        .await;
        assert!(verdict.is_err(), "a text/plain request was accepted");
        assert_eq!(
            seen.map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND),
            "a rejected request should look like a plain gRPC endpoint refusal"
        );
    }

    #[tokio::test]
    async fn missing_content_type_is_refused() {
        let (verdict, _) = probe_server(
            Request::builder()
                .method("POST")
                .uri("/Svc/Tun")
                .header("te", "trailers")
                .body(())
                .unwrap(),
        )
        .await;
        assert!(
            verdict.is_err(),
            "a request without a content type was accepted"
        );
    }

    #[tokio::test]
    async fn grpc_proto_content_type_is_accepted() {
        let (verdict, seen) = probe_server(
            Request::builder()
                .method("POST")
                .uri("/Svc/Method")
                .header("content-type", "application/grpc+proto")
                .header("te", "trailers")
                .body(())
                .unwrap(),
        )
        .await;
        assert!(verdict.is_ok(), "application/grpc+proto must be accepted");
        assert_eq!(seen.map(|(status, _)| status), Some(StatusCode::OK));
    }

    #[tokio::test]
    async fn lookalike_content_types_are_refused() {
        for content_type in [
            "application/grpc-web",
            "application/grpcc",
            "application/grpc+json",
            "application/octet-stream",
        ] {
            let (verdict, _) = probe_server(
                Request::builder()
                    .method("POST")
                    .uri("/Svc/Tun")
                    .header("content-type", content_type)
                    .header("te", "trailers")
                    .body(())
                    .unwrap(),
            )
            .await;
            assert!(
                verdict.is_err(),
                "content type {content_type:?} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn malformed_paths_are_refused() {
        for path in [
            "/",
            "//Tun",
            "/Svc/",
            "/Svc",
            "/Svc/Tun/extra",
            "/Svc//Tun",
            "/Svc/Tun?x=1",
        ] {
            let (verdict, _) = probe_server(grpc_request(path)).await;
            assert!(verdict.is_err(), "path {path:?} was accepted");
        }
    }

    #[tokio::test]
    async fn a_plain_two_segment_path_is_accepted() {
        let (verdict, _) = probe_server(grpc_request("/Service/Tun")).await;
        assert!(verdict.is_ok(), "a well formed gRPC path was refused");
    }

    /// A config-supplied service name must not be able to add path segments.
    #[tokio::test]
    async fn client_refuses_a_service_name_with_a_slash() {
        for service in ["a/b", "/a/b/", "../x", "a b"] {
            let (cli_io, _peer) = tokio::io::duplex(64 * 1024);
            let result = GrpcTransport::client_handshake(
                cli_io,
                "grpc.example.com",
                service,
                &HashMap::new(),
            )
            .await;
            assert!(
                result.is_err(),
                "service name {service:?} was accepted into the :path"
            );
        }
    }

    /// Control bytes would be an attempt to break out of the pseudo-header.
    #[tokio::test]
    async fn client_refuses_control_bytes_in_the_service_name() {
        for service in ["svc\r\nX-Injected: 1", "svc\0", "svc\n", "svc\t"] {
            let (cli_io, _peer) = tokio::io::duplex(64 * 1024);
            let result = GrpcTransport::client_handshake(
                cli_io,
                "grpc.example.com",
                service,
                &HashMap::new(),
            )
            .await;
            assert!(result.is_err(), "service name {service:?} was accepted");
        }
    }

    #[tokio::test]
    async fn client_refuses_an_empty_service_name() {
        let (cli_io, _peer) = tokio::io::duplex(64 * 1024);
        let result =
            GrpcTransport::client_handshake(cli_io, "grpc.example.com", "", &HashMap::new()).await;
        assert!(result.is_err(), "an empty service name produced `//Tun`");
    }

    /// The server must announce the content type it just demanded.
    #[tokio::test]
    async fn server_announces_grpc_content_type() {
        let (verdict, seen) = probe_server(grpc_request("/Svc/Tun")).await;
        assert!(verdict.is_ok(), "a well formed gRPC request was refused");
        let (_, headers) = seen.expect("response headers");
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/grpc"),
            "the tunnel response must carry the gRPC content type"
        );
    }

    /// Config-supplied headers are the other injection surface: they must not be
    /// able to replace the framing headers the transport depends on.
    #[tokio::test]
    async fn config_headers_cannot_override_the_framing_headers() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());
        headers.insert("x-extra".to_string(), "kept".to_string());
        let _cli = peer_with(PeerScript::ok(), Some(tx), headers).await;
        let seen = timeout(T, rx)
            .await
            .expect("no request captured")
            .expect("capture");
        // Exactly one of each: a peer's `Header.Get` (Go, which sing-box is
        // built on) resolves duplicates to an unspecified one of them, so
        // emitting a config-supplied `content-type: text/plain` next to ours is
        // a coin flip on the wire.
        let content_types: Vec<&str> = seen
            .get_all("content-type")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(
            content_types,
            vec!["application/grpc"],
            "the request must carry exactly one gRPC content type"
        );
        let te: Vec<&str> = seen
            .get_all("te")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(te, vec!["trailers"], "TE must appear exactly once");
        assert_eq!(
            seen.get("x-extra").and_then(|v| v.to_str().ok()),
            Some("kept"),
            "unrelated config headers must still be forwarded"
        );
    }

    // -------------------------------------------------- 4. HTTP/2 semantics

    #[tokio::test]
    async fn non_post_method_is_refused() {
        for method in ["GET", "PUT", "DELETE"] {
            let (verdict, _) = probe_server(
                Request::builder()
                    .method(method)
                    .uri("/Svc/Tun")
                    .header("content-type", "application/grpc")
                    .header("te", "trailers")
                    .body(())
                    .unwrap(),
            )
            .await;
            assert!(verdict.is_err(), "method {method} was accepted");
        }
    }

    #[tokio::test]
    async fn missing_te_trailers_is_refused() {
        let (verdict, _) = probe_server(
            Request::builder()
                .method("POST")
                .uri("/Svc/Tun")
                .header("content-type", "application/grpc")
                .body(())
                .unwrap(),
        )
        .await;
        assert!(
            verdict.is_err(),
            "a request without TE: trailers was accepted"
        );
    }

    /// `TE` may only ever carry `trailers`. The `h2` crate refuses to *send* any
    /// other value, so the exchange must fail somewhere; if a future h2 lets it
    /// through, the server-side check has to catch it.
    #[tokio::test]
    async fn wrong_te_value_is_refused() {
        let (cli_io, srv_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move { GrpcTransport::server_handshake(srv_io).await });
        let (mut client, conn) = h2::client::handshake(cli_io)
            .await
            .expect("raw client h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = Request::builder()
            .method("POST")
            .uri("/Svc/Tun")
            .header("content-type", "application/grpc")
            .header("te", "gzip")
            .body(())
            .expect("request");
        let refused_on_the_wire = client.send_request(request, false).is_err();
        let verdict = if refused_on_the_wire {
            None
        } else {
            Some(
                timeout(T, server)
                    .await
                    .expect("server handshake hung")
                    .expect("join"),
            )
        };
        match verdict {
            None => {}
            Some(Err(_)) => {}
            Some(Ok(_)) => panic!("TE: gzip was accepted as a tunnel"),
        }
    }

    /// We have no compressor, so a peer that announces one would send messages we
    /// cannot decode. Refuse it at the handshake instead of corrupting the stream.
    #[tokio::test]
    async fn unsupported_grpc_encoding_is_refused() {
        let (verdict, _) = probe_server(
            Request::builder()
                .method("POST")
                .uri("/Svc/Tun")
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .header("grpc-encoding", "gzip")
                .body(())
                .unwrap(),
        )
        .await;
        assert!(verdict.is_err(), "grpc-encoding: gzip was accepted");
    }

    /// A non-200 response must never be spliced into the tunnel as data.
    #[tokio::test]
    async fn non_200_response_is_an_error() {
        let mut cli = hostile_peer(PeerScript::ok().status(502)).await;
        let err = expect_read_error(&mut cli, "502 response").await;
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err}");
    }

    /// A response that is not gRPC at all (a captive portal, a CDN error page)
    /// must be refused rather than read as payload.
    #[tokio::test]
    async fn non_grpc_response_content_type_is_an_error() {
        let mut cli = hostile_peer(PeerScript::ok().content_type(Some("text/html"))).await;
        let err = expect_read_error(&mut cli, "text/html response").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");

        let mut cli = hostile_peer(PeerScript::ok().content_type(None)).await;
        let err = expect_read_error(&mut cli, "response without content type").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// `content-length` that disagrees with the body is a protocol error, not a
    /// shorter stream.
    #[tokio::test]
    async fn content_length_mismatch_is_an_error() {
        let (cli_io, srv_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move { GrpcTransport::server_handshake(srv_io).await });
        let (mut client, conn) = h2::client::handshake(cli_io)
            .await
            .expect("raw client h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = Request::builder()
            .method("POST")
            .uri("/Svc/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("content-length", "10")
            .body(())
            .expect("request");
        let (_response_fut, mut send) = client.send_request(request, false).expect("send_request");
        let mut tunnel = timeout(T, server)
            .await
            .expect("server handshake hung")
            .expect("join")
            .expect("server handshake");
        // Five of the ten promised bytes, then the request is closed.
        send.send_data(Bytes::from_static(b"12345"), true)
            .expect("send_data");
        let err = expect_read_error(&mut tunnel, "content-length mismatch").await;
        assert_ne!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    /// A request whose body is empty and already closed is accepted (there is
    /// simply nothing to read), not treated as a malformed handshake.
    #[tokio::test]
    async fn end_stream_request_is_accepted() {
        let (verdict, seen) = probe_server(grpc_request("/Svc/Tun")).await;
        assert!(verdict.is_ok(), "an empty-bodied gRPC request was refused");
        assert_eq!(seen.map(|(status, _)| status), Some(StatusCode::OK));
    }

    // ------------------------------------------------------------- 5. bounds

    /// A declared length of four gigabytes must be refused from the header alone:
    /// no buffering, no hang.
    #[tokio::test]
    async fn huge_declared_length_is_refused_from_the_header_alone() {
        let mut cli =
            hostile_peer(PeerScript::frames(vec![vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]])).await;
        let err = timeout(
            Duration::from_secs(2),
            expect_read_error(&mut cli, "u32::MAX length"),
        )
        .await
        .expect("refusing a huge length must not wait for the body");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("limit"), "{err}");
    }

    /// One byte over the limit is refused too, so the bound is not off by one.
    #[tokio::test]
    async fn length_one_over_the_limit_is_refused() {
        let declared = (MAX_GRPC_MESSAGE + 1) as u32;
        let mut cli = hostile_peer(PeerScript::frames(vec![vec![
            0x00,
            declared.to_be_bytes()[0],
            declared.to_be_bytes()[1],
            declared.to_be_bytes()[2],
            declared.to_be_bytes()[3],
        ]]))
        .await;
        let err = expect_read_error(&mut cli, "limit + 1").await;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// A peer that dribbles a header byte at a time and then leaves must not hang
    /// or panic the reader.
    #[tokio::test]
    async fn dribbled_header_then_close_is_an_error() {
        let (cli_io, peer_io) = tokio::io::duplex(64 * 1024);
        // Answer the request headers, then dribble a partial gRPC header.
        tokio::spawn(async move {
            let builder = h2::server::Builder::new();
            let mut conn = builder
                .handshake::<_, Bytes>(peer_io)
                .await
                .expect("peer handshake");
            let (request, mut respond) = conn.accept().await.expect("accept").expect("stream");
            let mut send = respond
                .send_response(
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .expect("response"),
                    false,
                )
                .expect("send_response");
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let _hold = request;
            for byte in [0x00u8, 0x00, 0x00, 0x10] {
                peer_write(&mut send, Bytes::from(vec![byte])).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let _ = send.send_data(Bytes::new(), true);
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let mut cli = timeout(
            T,
            GrpcTransport::client_handshake(cli_io, "grpc.example.com", "Svc", &HashMap::new()),
        )
        .await
        .expect("client handshake hung")
        .expect("client handshake");
        let err = expect_read_error(&mut cli, "dribbled header").await;
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
    }

    /// A zero-capacity read buffer must complete immediately instead of parking
    /// the caller until the peer happens to send something.
    #[tokio::test]
    async fn zero_length_read_buffer_returns_immediately() {
        let mut cli = hostile_peer(PeerScript::ok().ending(Ending::Stall)).await;
        let mut empty: [u8; 0] = [];
        let polled = std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut cli).poll_read(cx, &mut tokio::io::ReadBuf::new(&mut empty))
        });
        timeout(Duration::from_millis(500), polled)
            .await
            .expect("a zero-capacity read buffer parked the caller")
            .expect("zero-capacity read failed");
    }

    // --------------------------------------------------------- 6. round trip

    /// Shutdown must not end the stream while a message is still being flushed:
    /// trailers carry END_STREAM and would cut the frame in half.
    #[tokio::test]
    async fn shutdown_waits_for_a_half_flushed_frame() {
        // This peer never reads the request body, so the send window closes part
        // way through the payload and a frame is left half written.
        let mut cli = hostile_peer(PeerScript::ok().ending(Ending::Stall)).await;
        let payload = vec![7u8; 512 * 1024];
        let write = timeout(Duration::from_millis(300), cli.write_all(&payload)).await;
        assert!(write.is_err(), "the peer granted more window than expected");
        let shutdown = std::future::poll_fn(|cx| std::pin::Pin::new(&mut cli).poll_shutdown(cx));
        let result = timeout(Duration::from_millis(300), shutdown).await;
        assert!(
            result.is_err(),
            "shutdown reported success while a frame was still half written"
        );
    }

    /// A payload spanning many DATA frames must survive both directions.
    #[tokio::test]
    async fn large_payload_round_trips_both_ways() {
        let (cli, mut srv) = grpc_pair().await;
        let up: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..2 * 1024 * 1024 + 12345)
            .map(|i| (i % 241) as u8)
            .collect();
        let up_expected = up.clone();
        let down_expected = down.clone();
        let up_len = up.len();

        let down_len = down.len();
        let (mut cli_read, mut cli_write) = tokio::io::split(cli);
        let writer = tokio::spawn(async move {
            cli_write.write_all(&up).await.expect("uplink write");
            cli_write.flush().await.expect("uplink flush");
            cli_write
        });
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; down_len];
            cli_read.read_exact(&mut got).await.expect("downlink read");
            got
        });
        let server = tokio::spawn(async move {
            let mut got = vec![0u8; up_len];
            srv.read_exact(&mut got).await.expect("uplink read");
            srv.write_all(&down).await.expect("downlink write");
            srv.flush().await.expect("downlink flush");
            (got, srv)
        });
        let (got, _srv) = timeout(Duration::from_secs(30), server)
            .await
            .expect("server hung")
            .expect("server join");
        assert_eq!(got, up_expected, "uplink corrupted");
        let _cli_write = writer.await.expect("writer join");
        let got = timeout(Duration::from_secs(30), reader)
            .await
            .expect("client hung")
            .expect("reader join");
        assert_eq!(got, down_expected, "downlink corrupted");
    }

    /// Sizes around the 16 KiB frame chunk: an off-by-one in the writer or the
    /// reader shows up exactly here.
    #[tokio::test]
    async fn payloads_around_the_chunk_boundary_round_trip() {
        for size in [1usize, 16_383, 16_384, 16_385, 2 * 16_384 + 7] {
            let (mut cli, mut srv) = grpc_pair().await;
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            let writer = tokio::spawn(async move {
                cli.write_all(&payload).await.expect("write");
                cli.flush().await.expect("flush");
                // Keep the stream alive until the reader is done: dropping it
                // resets the HTTP/2 stream and truncates the transfer.
                cli
            });
            let mut got = vec![0u8; size];
            timeout(T, srv.read_exact(&mut got))
                .await
                .unwrap_or_else(|_| panic!("read of {size} bytes hung"))
                .unwrap_or_else(|e| panic!("read of {size} bytes failed: {e}"));
            assert_eq!(got, expected, "round trip of {size} bytes mismatched");
            let _cli = writer.await.expect("writer join");
        }
    }

    /// The bytes this proxy puts on the wire are the gun envelope sing-box and
    /// Xray parse: `00 | len u32 BE | 0x0A | varint(len) | payload`. Pinned byte
    /// for byte, because a reader that agrees with a matching writer would still
    /// be wrong against a real peer.
    #[tokio::test]
    async fn outbound_frame_matches_the_gun_wire_format() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut cli = peer_with_body(PeerScript::ok(), None, Some(tx), HashMap::new()).await;
        cli.write_all(b"abc").await.expect("write");
        cli.flush().await.expect("flush");
        let seen = timeout(T, rx)
            .await
            .expect("no body captured")
            .expect("capture");
        assert_eq!(seen, gun_frame(b"abc"), "outbound framing drifted");
        assert_eq!(
            seen,
            vec![0x00, 0x00, 0x00, 0x00, 0x05, 0x0A, 0x03, b'a', b'b', b'c']
        );
    }

    /// The trailers the server emits at shutdown must satisfy its own client:
    /// a proxy that sent an invalid status would break itself against itself.
    #[tokio::test]
    async fn server_trailers_are_accepted_by_its_own_client() {
        let (mut cli, mut srv) = grpc_pair().await;
        cli.write_all(b"hello").await.expect("write");
        cli.flush().await.expect("flush");
        let mut got = [0u8; 5];
        timeout(T, srv.read_exact(&mut got))
            .await
            .expect("read hung")
            .expect("read");
        srv.write_all(b"bye").await.expect("write");
        srv.flush().await.expect("flush");
        srv.shutdown().await.expect("shutdown");
        expect_payload(&mut cli, b"bye", "reply before shutdown").await;
        expect_eof(&mut cli, "grpc-status 0 trailer").await;
    }

    /// Many small writes, each its own gRPC message, must stay in order and
    /// complete.
    #[tokio::test]
    async fn many_small_messages_round_trip() {
        let (mut cli, mut srv) = grpc_pair().await;
        let payloads: Vec<Vec<u8>> = (0..200)
            .map(|i| vec![(i % 256) as u8; (i * 37) % 300 + 1])
            .collect();
        let expected: Vec<u8> = payloads.concat();
        let total = expected.len();
        let writer = tokio::spawn(async move {
            for payload in payloads {
                cli.write_all(&payload).await.expect("write");
            }
            cli.flush().await.expect("flush");
            cli
        });
        let mut got = Vec::with_capacity(total);
        let mut buf = vec![0u8; 4096];
        while got.len() < total {
            let n = timeout(T, srv.read(&mut buf))
                .await
                .expect("read hung")
                .expect("read failed");
            assert_ne!(n, 0, "premature end of stream at {} of {total}", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, expected, "message stream corrupted");
        let _cli = writer.await.expect("writer join");
    }

    // ------------------------------------------------- pure framing helpers

    #[test]
    fn content_type_matching_is_strict() {
        for accepted in [
            "application/grpc",
            "Application/GRPC",
            "application/grpc+proto",
            "application/grpc; charset=utf-8",
            "  application/grpc  ",
        ] {
            assert!(
                is_grpc_content_type(accepted),
                "{accepted:?} should be accepted"
            );
        }
        for refused in [
            "",
            "application/grpc-web",
            "application/grpcc",
            "application/grpc+json",
            "text/plain",
            "application/octet-stream",
        ] {
            assert!(
                !is_grpc_content_type(refused),
                "{refused:?} should be refused"
            );
        }
    }

    #[test]
    fn path_shape_is_enforced() {
        assert_eq!(split_grpc_path("/svc/Tun").ok(), Some(("svc", "Tun")));
        assert_eq!(split_grpc_path("/a.b/C").ok(), Some(("a.b", "C")));
        assert_eq!(split_grpc_path("/%41/x").ok(), Some(("%41", "x")));
        for refused in [
            "",
            "/",
            "//Tun",
            "/svc/",
            "/svc",
            "/svc/Tun/x",
            "/sv/Tun?q=1",
            "/sv c/Tun",
            "/svc/T\\un",
            "/svc/Tun\n",
        ] {
            assert!(
                split_grpc_path(refused).is_err(),
                "{refused:?} should be refused"
            );
        }
        let long = format!("/{}/Tun", "a".repeat(MAX_PATH_LEN));
        assert!(
            split_grpc_path(&long).is_err(),
            "an oversized path should be refused"
        );
    }

    #[test]
    fn service_names_cannot_shape_the_path() {
        for accepted in ["GunService", "vless-grpc-tunnel", "a.b_c~d", "S1"] {
            assert!(
                validate_service_name(accepted).is_ok(),
                "{accepted:?} should be accepted"
            );
        }
        for refused in [
            "",
            "a/b",
            "/a",
            "a b",
            "a\r\nX-Injected: 1",
            "a\0",
            ":path",
            "..",
            "ä",
        ] {
            assert!(
                validate_service_name(refused).is_err(),
                "{refused:?} should be refused"
            );
        }
        let long = "a".repeat(MAX_SERVICE_LEN + 1);
        assert!(
            validate_service_name(&long).is_err(),
            "an oversized service name should be refused"
        );
    }

    #[test]
    fn varint_decoding_matches_the_wire_format() {
        for (value, encoded) in [
            (0usize, vec![0x00u8]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xff, 0x7f]),
            (16_384, vec![0x80, 0x80, 0x01]),
        ] {
            assert_eq!(decode_varint(&encoded).ok(), Some((value, encoded.len())));
        }
        // Continuation bit with nothing after it.
        assert!(decode_varint(&[0x80]).is_err());
        assert!(decode_varint(&[]).is_err());
        // Eleven continuation bytes cannot be a u64.
        assert!(decode_varint(&[0x80; 11]).is_err());
        // A tenth byte may only carry the last bit.
        assert!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]).is_err()
        );
    }
}
