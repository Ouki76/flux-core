//! XHTTP (Xray's `splithttp`), `stream-one` mode.
//!
//! XHTTP carries the tunnel inside ordinary HTTP: the upload is a POST body, the download
//! is the response body. It has three modes, and this implements the simplest one:
//! `stream-one`, where a single request keeps both directions open at once. That is what
//! HTTP/2 gives natively on one stream, and it is the mode Xray itself selects when it is
//! used with REALITY.
//!
//! The other two modes split the directions across separate requests and therefore need
//! sequence numbers and reassembly (`packet-up`) or two long-lived requests (`stream-up`);
//! they are not implemented here, and the configuration says so rather than silently
//! negotiating something else.

use crate::h2::H2Stream;
use crate::h2::shared;
use bytes::Bytes;
use flux_types::error::{FluxError, FluxResult};
use flux_types::traits::AsyncStream;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Default request path, matching Xray's default.
pub const DEFAULT_XHTTP_PATH: &str = "/";

/// Client half: opens one bidirectional request and returns it as a stream.
///
/// The path gets a per-connection suffix, which is how Xray tells sessions apart; the
/// server only matches the prefix.
pub async fn connect<S>(
    stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
    xpadding: Option<&str>,
) -> FluxResult<H2Stream>
where
    S: AsyncStream + 'static,
{
    let mut client = shared::client_handshake(stream, "xhttp").await?;
    // `stream-one` is identified by the *absence* of a session id in the path: Xray's
    // handler routes a request with no session to the stream-one branch, which answers
    // on the same request instead of waiting for a separate download stream. Appending a
    // session here made it a `stream-up` request and the server refused it by name.
    let base = normalize_path(path);
    let full = base;

    // Xray validates padding on every request and refuses one without it. The padding
    // goes in the query string (`x_padding`) as base64url, and its purpose is to make the
    // request line's length vary instead of being a fixed signature.
    let full = format!("{full}?x_padding={}", padding_param(xpadding));

    let mut builder = Request::builder()
        .method("POST")
        .uri(full.as_str())
        .header("Host", host)
        // Xray's own body type. A middlebox sees a POST with an unknown body type, which
        // is exactly what an upload looks like.
        .header("content-type", "application/octet-stream");
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let request = builder.body(()).map_err(|e| FluxError::Protocol {
        protocol: "xhttp",
        message: format!("failed to build the XHTTP request: {e}"),
    })?;

    let (response, send) =
        client
            .send_request(request, false)
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to send the XHTTP request: {e}"),
            })?;

    Ok(H2Stream::new_client_pending(send, response))
}

/// Client half of `stream-up`: an uploading POST and a downloading GET, joined into one stream.
///
/// Xray splits the directions in this mode. The upload is a POST whose body streams for the life of
/// the session; the download is a separate GET answered as an event stream. Both carry the same
/// `session` value — which is how the server pairs them — and both travel on one HTTP/2 connection.
///
/// The returned stream's receive half is **still pending** when this returns, which is what makes
/// the mode work: a peer that answers the GET only after reading the POST would otherwise deadlock
/// against a client that waits for the response before writing.
pub async fn connect_stream_up<S>(
    stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
    xpadding: Option<&str>,
) -> FluxResult<H2Stream>
where
    S: AsyncStream + 'static,
{
    let mut client = shared::client_handshake(stream, "xhttp").await?;
    let session = session_id();
    // The session goes in the **path**, not the query. Xray routes a request with no session to the
    // stream-one branch — which is why an upload carrying `?session=` was decoded as stream-one and
    // its reply went into the POST's response body, while our separate GET was answered with an empty
    // body and the download stayed at zero bytes.
    let url = format!(
        "{base}{session}?x_padding={padding}",
        base = normalize_path(path),
        padding = padding_param(xpadding)
    );
    let build = |method: &'static str| -> FluxResult<Request<()>> {
        let mut builder = Request::builder()
            .method(method)
            .uri(url.as_str())
            .header("Host", host)
            .header("content-type", "application/octet-stream");
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder.body(()).map_err(|e| FluxError::Protocol {
            protocol: "xhttp",
            message: format!("failed to build the XHTTP {method} request: {e}"),
        })
    };
    let (upload_response, upload) =
        client
            .send_request(build("POST")?, false)
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to send the XHTTP upload: {e}"),
            })?;
    // The upload's response must not merely be awaited — its **body** must be drained and held.
    // Dropping a `ResponseFuture` resets the stream, and dropping the `RecvStream` of a response
    // whose body has not been read sends `RST_STREAM CANCEL`, which is exactly what xray saw:
    // `Reset { stream_id: 1, error_code: CANCEL }` on the upload while the tunnel was setting up.
    tokio::spawn(async move {
        if let Ok(response) = upload_response.await {
            let mut body = response.into_body();
            while let Some(chunk) = body.data().await {
                if chunk.is_err() {
                    break;
                }
            }
        }
    });
    let (download_response, _) =
        client
            .send_request(build("GET")?, true)
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to send the XHTTP download: {e}"),
            })?;
    Ok(H2Stream::new_client_split(upload, download_response))
}

/// A session identifier; opaque to Xray, 16 random bytes in hex.
fn session_id() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// A `packet-up` upload: each write becomes its own POST, numbered per session.
///
/// `stream-up` keeps one request body open for the life of the session, which is why its write half
/// can be a bare `SendStream`. `packet-up` does the opposite — every chunk is a separate request to
/// `/<base>/<session>/<seq>`, established against the real binary in C7.12 — so the write half cannot
/// be a stream at all: it has to queue chunks for a task that numbers and posts them. The read half is
/// unchanged, because the download is the same GET `stream-up` uses.
pub struct PacketUpStream {
    /// Download half. It starts as a **pending** response, exactly like `stream-up`: awaiting it
    /// before returning would deadlock against a peer that answers the download only once an upload
    /// exists, which is the circular wait C7.6 hit one layer up.
    recv: PacketUpRecv,
    read_buf: Bytes,
    read_pos: usize,
    read_done: bool,
    /// Upload half: chunks waiting to be posted.
    ///
    /// Unbounded on purpose. A bounded channel would need the writer to hold a `reserve` future across
    /// polls to wake correctly, and that future is not `Sync`, which the boxed stream must be. The
    /// queue is fed by the relay's 64 KiB reads and drained by a poster on the same task set, so its
    /// depth is bounded in practice by how far the relay runs ahead of the tunnel.
    tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
}

/// The download half's state. The response is resolved before the stream is handed out — a `packet-up`
/// client must not post until the download has been answered (C7.23) — so there is no pending case.
enum PacketUpRecv {
    Ready(RecvStream),
    Done,
}

impl std::fmt::Debug for PacketUpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketUpStream").finish_non_exhaustive()
    }
}

impl AsyncRead for PacketUpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
                this.read_pos += to_copy;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf = Bytes::new();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_done {
                return Poll::Ready(Ok(()));
            }
            match &mut this.recv {
                PacketUpRecv::Ready(recv) => match Pin::new(recv).poll_data(cx) {
                    Poll::Ready(Some(Ok(data))) => {
                        this.read_buf = data;
                        this.read_pos = 0;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                    }
                    Poll::Ready(None) => {
                        this.read_done = true;
                        this.recv = PacketUpRecv::Done;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                PacketUpRecv::Done => {
                    this.read_done = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for PacketUpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        let chunk = Bytes::copy_from_slice(buf);
        let len = chunk.len();
        match this.tx.send(chunk) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(_) => {
                tracing::warn!("packet-up: channel closed, {len} bytes lost");
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the packet-up poster has stopped",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The poster ends when the last sender drops, which happens with the stream itself.
        self.read_done = true;
        Poll::Ready(Ok(()))
    }
}

/// Xray's default for `scMaxEachPostBytes`: 1 MB.
pub const DEFAULT_MAX_EACH_POST_BYTES: usize = 1_000_000;

/// The `packet-up` settings that change its behaviour rather than its wire shape.
#[derive(Debug, Clone, Default)]
pub struct PacketUpOptions {
    /// Largest body one POST may carry; a larger write is split across several.
    pub max_each_post_bytes: Option<usize>,
    /// Minimum gap between consecutive POSTs.
    pub min_posts_interval: Option<std::time::Duration>,
    /// Path for the download request, when `downloadSettings` overrides the upload's.
    pub download_path: Option<String>,
    /// Headers for the download request, overriding or extending the upload's.
    pub download_headers: HashMap<String, String>,
}

/// Splits one write into POST bodies no larger than `max_post`.
///
/// `scMaxEachPostBytes` is Xray's limit on a single POST; the relay writes in 64 KiB units, which is
/// under the 1 MB default but not under a configured smaller limit. A limit of zero cannot mean
/// "unlimited" here — it would produce an infinite loop — so it falls back to the default.
fn split_posts(chunk: Bytes, max_post: usize) -> Vec<Bytes> {
    let max_post = if max_post == 0 {
        DEFAULT_MAX_EACH_POST_BYTES
    } else {
        max_post
    };
    if chunk.len() <= max_post {
        return vec![chunk];
    }
    chunk.chunks(max_post).map(Bytes::copy_from_slice).collect()
}

/// Client half of `packet-up`.
pub async fn connect_packet_up<S>(
    stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
    xpadding: Option<&str>,
    options: &PacketUpOptions,
) -> FluxResult<Box<dyn AsyncStream>>
where
    S: AsyncStream + 'static,
{
    let mut client = shared::client_handshake(stream, "xhttp").await?;
    let session = session_id();
    let base = normalize_path(path);
    let padding = padding_param(xpadding);

    // Download: the same GET as `stream-up`, unless `downloadSettings` gives it its own path.
    let download_base = match options.download_path.as_deref() {
        Some(p) => normalize_path(p),
        None => base.clone(),
    };
    let download_url = format!("{download_base}{session}?x_padding={padding}");
    let mut builder = Request::builder()
        .method("GET")
        .uri(download_url.as_str())
        .header("Host", host)
        .header("content-type", "application/octet-stream");
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    for (k, v) in &options.download_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let download_request = builder.body(()).map_err(|e| FluxError::Protocol {
        protocol: "xhttp",
        message: format!("failed to build the XHTTP download request: {e}"),
    })?;
    let (download_response, _) =
        client
            .send_request(download_request, true)
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to send the XHTTP download: {e}"),
            })?;
    // The download must be answered **before** the first POST: several POSTs issued while the server
    // is still sending its download response leave that stream in a state h2 considers
    // already-answered, and the server refuses it with `unexpected frame type` (C7.23).
    let download_response = download_response.await.map_err(|e| FluxError::Protocol {
        protocol: "xhttp",
        message: format!("the XHTTP download was refused: {e}"),
    })?;
    let recv_pending = PacketUpRecv::Ready(download_response.into_body());

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    let host = host.to_string();
    let headers = headers.clone();
    let max_post = options
        .max_each_post_bytes
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_EACH_POST_BYTES);
    let min_interval = options.min_posts_interval;
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        tracing::debug!("packet-up: poster started");
        while let Some(chunk) = rx.recv().await {
            // One write can exceed the configured POST size, so it is split rather than being sent
            // as a body the peer would refuse.
            let pieces = split_posts(chunk, max_post);
            for piece in pieces {
                if let Some(interval) = min_interval
                    && !interval.is_zero()
                {
                    tokio::time::sleep(interval).await;
                }
                let url = format!("{base}{session}/{seq}?x_padding={padding}");
                seq += 1;
                let mut builder = Request::builder()
                    .method("POST")
                    .uri(url.as_str())
                    .header("Host", host.as_str())
                    .header("content-type", "application/octet-stream");
                for (k, v) in &headers {
                    builder = builder.header(k.as_str(), v.as_str());
                }
                let Ok(request) = builder.body(()) else {
                    tracing::warn!("packet-up: could not build the POST request");
                    return;
                };
                // The chunk **is** the request body, and this request ends with it: `end_of_stream =
                // false` above only opens the stream so a body can follow. Without the `send_data` the
                // POST stays open forever and the peer never answers — which is exactly what the
                // counters showed: the poster queued seq 0 and then waited for a response that could
                // not come.
                let (posted, mut body) = match client.send_request(request, false) {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!("packet-up: send_request failed for seq {seq}: {e}");
                        return;
                    }
                };
                if let Err(e) = body.send_data(piece, true) {
                    tracing::warn!("packet-up: sending the body for seq {seq} failed: {e}");
                    return;
                }
                // The request body completes this POST, and the response is **drained**: a response body
                // dropped unread sends `RST_STREAM CANCEL`, which is the fault C7.8 took three cycles to
                // find on the stream-up upload path.
                match posted.await {
                    Ok(response) if response.status().is_success() => {
                        tracing::trace!("packet-up: seq posted, status {}", response.status());
                        let mut body = response.into_body();
                        while let Some(chunk) = body.data().await {
                            if chunk.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(response) => {
                        tracing::warn!("packet-up: POST rejected with {}", response.status());
                        return;
                    }
                    Err(e) => {
                        tracing::warn!("packet-up: POST failed: {e}");
                        return;
                    }
                }
            }
        }
    });

    Ok(Box::new(PacketUpStream {
        recv: recv_pending,
        read_buf: Bytes::new(),
        read_pos: 0,
        read_done: false,
        tx,
    }))
}

/// A duplex over two channels: reads come from `rx`, writes go to `tx`.
///
/// The server half of `packet-up` needs exactly this shape. Its upload is not a stream at all — it is
/// a series of separate POSTs reassembled by sequence — so the read side is fed by the POST handlers
/// through a channel; and its download is an h2 response body, so the write side is drained into that
/// `SendStream` by a task.
pub struct ChannelDuplex {
    rx: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    read_buf: Bytes,
    read_pos: usize,
    /// Fired when this tunnel is dropped. The connection it was served on carries exactly one tunnel,
    /// and a peer pools connections: leaving ours open fills the pool with connections nobody can
    /// reuse, which is the wall measured in C7.59/C7.60.
    close: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ChannelDuplex {
    fn drop(&mut self) {
        if let Some(close) = self.close.take() {
            let _ = close.send(());
        }
    }
}

impl std::fmt::Debug for ChannelDuplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelDuplex").finish_non_exhaustive()
    }
}

impl AsyncRead for ChannelDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
                this.read_pos += to_copy;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf = Bytes::new();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(data)) if data.is_empty() => {
                    // The watchdog for `scStreamUpServerSecs` closes the upload by sending an empty
                    // chunk, which is indistinguishable from a clean end — and is one.
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(data)) => {
                    this.read_buf = data;
                    this.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for ChannelDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.tx.send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the download writer has stopped",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Reassembles `packet-up` POSTs for one session.
#[derive(Debug)]
struct Reassembly {
    /// Chunks that have arrived but cannot be delivered yet, keyed by sequence.
    pending: std::collections::BTreeMap<u64, Bytes>,
    /// The next sequence number expected.
    next: u64,
    /// Chunks that became deliverable **before** the download stream existed. They must not be
    /// dropped: the client posts as soon as it has data, and the server's download request may be
    /// accepted a moment later. Losing them would corrupt the stream silently.
    ready: VecDeque<Bytes>,
    /// How many out-of-order chunks may be held. This is Xray's `scMaxBufferedPosts`, and it exists
    /// because a peer that never fills the gap would otherwise make the server buffer without bound.
    max_buffered: usize,
}

impl Default for Reassembly {
    fn default() -> Self {
        Self {
            pending: std::collections::BTreeMap::new(),
            ready: VecDeque::new(),
            next: 0,
            max_buffered: DEFAULT_MAX_BUFFERED_POSTS,
        }
    }
}

/// Xray's default for `scMaxBufferedPosts`.
const DEFAULT_MAX_BUFFERED_POSTS: usize = 32;

impl Reassembly {
    /// Takes one POST's chunk and returns whatever became deliverable, in order.
    ///
    /// A duplicate or already-delivered sequence is dropped rather than delivered twice — a retried
    /// POST must not corrupt the stream above it.
    fn accept(&mut self, seq: u64, chunk: Bytes) -> Vec<Bytes> {
        if seq < self.next {
            return Vec::new();
        }
        if self.pending.len() >= self.max_buffered {
            // Refuse rather than grow: an unbounded buffer here is a memory lever a peer controls.
            tracing::warn!(
                "packet-up: {} out-of-order chunks already held, dropping seq {seq}",
                self.pending.len()
            );
            return Vec::new();
        }
        self.pending.insert(seq, chunk);
        let mut out = Vec::new();
        while let Some(chunk) = self.pending.remove(&self.next) {
            self.next += 1;
            out.push(chunk);
        }
        out
    }
}

/// Whether a path suffix is a session id.
///
/// Two shapes are accepted, and both are exact on purpose: any looser rule turns an ordinary
/// sub-path into a split-session request, and the server then waits for a second request that a
/// `stream-one` client will never send — which is a hang, not an error.
///
/// - 32 hex characters: what our own client generates;
/// - a UUID, `8-4-4-4-12` hex with dashes: what Xray's client generates.
fn looks_like_a_session(suffix: &str) -> bool {
    let hex = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    if suffix.len() == 32 && hex(suffix) {
        return true;
    }
    let parts: Vec<&str> = suffix.split('-').collect();
    matches!(parts.len(), 5)
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(want, part)| part.len() == *want && hex(part))
}

/// A `packet-up`/`stream-up` session, shared across connections.
///
/// The upload and the download of one session may travel on **different h2 connections** — Xray's
/// client is free to split them, and our own client happens not to. Keeping this map inside a single
/// connection made the split case fail intermittently: the POSTs landed on a connection whose map had
/// no such session, the chunk was buffered against a download nobody would ever drain, and the request
/// timed out. That is the whole of the xray-only flakiness recorded in C7.32.
#[derive(Debug)]
struct Session {
    /// Where reassembled upload bytes go; the download half reads from it.
    tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    /// Ordering state for numbered POSTs.
    state: Reassembly,
    /// When the session was opened, for expiry.
    opened: std::time::Instant,
}

/// Sessions live for at most this long, whether or not their peer is still around. A registry that
/// outlives connections must not leak, so expiry is not optional.
const SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(120);

fn sessions() -> &'static std::sync::Mutex<std::collections::HashMap<String, Session>> {
    static SESSIONS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Session>>,
    > = std::sync::OnceLock::new();
    SESSIONS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn with_sessions<R>(f: impl FnOnce(&mut std::collections::HashMap<String, Session>) -> R) -> R {
    let mut guard = sessions().lock().unwrap_or_else(|e| e.into_inner());
    guard.retain(|_, s| s.opened.elapsed() < SESSION_TTL);
    f(&mut guard)
}

/// Server half: accepts one bidirectional request and returns it as a stream.
///
/// `path` is the configured base path. Anything under it is accepted, because the client
/// appends a per-session suffix; anything else is refused with 404, like a web server
/// serving only its own tree.
pub async fn accept<S>(
    stream: S,
    path: &str,
    no_sse_header: bool,
    max_buffered_posts: Option<u64>,
    stream_up_server_secs: Option<u64>,
) -> FluxResult<Box<dyn AsyncStream>>
where
    S: AsyncStream + 'static,
{
    // A stable id per connection, so a session's download and its uploads can be told apart when
    // xray multiplexes and may put them on different connections (C7.45).
    static CONN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let conn_id = CONN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut connection = shared::server_handshake(stream, "xhttp").await?;
    let buffered_bound = max_buffered_posts
        .map(|n| n as usize)
        .unwrap_or(DEFAULT_MAX_BUFFERED_POSTS);
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or_else(|| FluxError::Protocol {
            protocol: "xhttp",
            message: "the client closed the connection before sending a request".into(),
        })?
        .map_err(|e| FluxError::Protocol {
            protocol: "xhttp",
            message: format!("error receiving the XHTTP request: {e}"),
        })?;

    let uri_path = request.uri().path().to_string();
    let under_base = is_under_base(path, &uri_path);
    tracing::debug!(
        "xhttp: conn#{conn_id} first request: {} {}",
        request.method(),
        uri_path
    );
    tracing::debug!(
        "xhttp server: first request {} {} (under_base={under_base})",
        request.method(),
        uri_path
    );
    // The session is the path segment after the base — the form Xray actually pairs on. A query
    // parameter does not switch Xray into a split mode at all: it decodes the request as stream-one
    // and answers on the same request, which is why an earlier attempt saw the upload work and the
    // download stay empty.
    let base = normalize_path(path);
    let path_session = uri_path
        .strip_prefix(base.as_str())
        .map(|suffix| suffix.trim_matches('/').to_string())
        // Only a real session id counts: 32 lowercase hex characters, which is what our client sends
        // and what Xray generates. Without this, any request carrying a sub-path was treated as the
        // upload half of a split session and the server waited forever for a download that stream-one
        // clients never send.
        // A session is a single path segment of hex-or-alphanumeric characters and a plausible
        // length. Demanding exactly 32 hex characters refused Xray's own client, whose session ids
        // do not have that shape, so the split modes worked only against our own client.
        .filter(|suffix| looks_like_a_session(suffix));

    // `packet-up` download: a GET naming a session with no sequence. It opens the session, and the
    // chunks arrive as separate POSTs on this same connection, so the returned stream reads from a
    // channel the POST handler feeds and writes into this response body.
    if request.method() == Method::GET
        && under_base
        && let Some(session) = path_session.clone()
    {
        let (upload_tx, upload_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let (down_tx, mut down_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();
        with_sessions(|map| {
            map.insert(
                session.clone(),
                Session {
                    tx: upload_tx.clone(),
                    state: Reassembly {
                        max_buffered: buffered_bound,
                        ..Reassembly::default()
                    },
                    opened: std::time::Instant::now(),
                },
            );
        });
        // `scStreamUpServerSecs`: an upload stream must not live forever. The watchdog closes it by
        // sending the empty end-of-upload marker; a peer that keeps uploading simply reopens one.
        if let Some(secs) = stream_up_server_secs.filter(|n| *n > 0) {
            let closer = upload_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                let _ = closer.send(Bytes::new());
            });
        }
        // Anything already reassembled before the download opened is delivered first.
        // Drain what was reassembled before the download opened, but **keep the state**: removing it
        // reset the expected sequence to zero, so every later POST arrived "out of order" behind a gap
        // that could never fill and the session delivered nothing. That is the intermittent failure
        // seen only against xray's client, which posts early enough to fill this queue.
        with_sessions(|map| {
            if let Some(entry) = map.get_mut(&session) {
                for piece in entry.state.ready.drain(..) {
                    let _ = down_tx.send(piece);
                }
            }
        });
        let body_type = if no_sse_header {
            "application/octet-stream"
        } else {
            "text/event-stream"
        };
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", body_type)
            .body(())
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to build the XHTTP download response: {e}"),
            })?;
        let mut send: SendStream<Bytes> =
            respond
                .send_response(response, false)
                .map_err(|e| FluxError::Protocol {
                    protocol: "xhttp",
                    message: format!("failed to send the XHTTP download response: {e}"),
                })?;
        tokio::spawn(async move {
            while let Some(chunk) = down_rx.recv().await {
                if send.send_data(chunk, false).is_err() {
                    break;
                }
            }
            let _ = send.send_data(Bytes::new(), true);
        });
        // The connection must keep **accepting** after this download request: the uploads arrive as
        // further POSTs on the same connection, and a bare connection driver would pump frames
        // without ever handing them to anyone. That is why nothing moved before — the POSTs were
        // never read, not misrouted.
        tokio::spawn(async move {
            loop {
                let mut closing = false;
                let accepted = tokio::select! {
                    // The tunnel this connection serves is finished. Announce a graceful shutdown so
                    // the peer can retire the connection and its pool can replace it; the driver keeps
                    // running below so already-queued response frames are flushed before the socket
                    // is closed. Tearing the socket down here instead truncated the response — the
                    // transport test caught it immediately.
                    _ = &mut close_rx => {
                        connection.graceful_shutdown();
                        closing = true;
                        connection.accept().await
                    }
                    next = connection.accept() => next,
                };
                let _ = closing;
                let Some(Ok((post, mut post_respond))) = accepted else {
                    break;
                };
                let post_path = post.uri().path().to_string();
                // `/<base>/<session>/<seq>` for packet-up, `/<base>/<session>` for stream-up. Taking
                // the last segment as a sequence unconditionally made the session "x" for the
                // unnumbered form, which is why xray's stream-up never delivered anything.
                let last = post_path.rsplit('/').next().unwrap_or("");
                let (session_of_post, seq_str) = match last.parse::<u64>() {
                    Ok(_) => match post_path.rsplit_once('/') {
                        Some((rest, seq)) => {
                            (rest.rsplit('/').next().unwrap_or("").to_string(), seq)
                        }
                        None => (String::new(), ""),
                    },
                    Err(_) => (last.to_string(), ""),
                };
                // A POST carrying a number is `packet-up`; one without is `stream-up`, where the whole
                // upload is a single streaming body. Both land here because both follow the session's
                // download GET, and treating the unnumbered form as sequential keeps one code path.
                let seq: Option<u64> = seq_str.parse().ok();
                let mut body = post.into_body();
                let ack = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("static ack response");
                let _ = post_respond.send_response(ack, true);
                // A `stream-up` POST carries a **streaming** body: its DATA frames arrive after the
                // headers, so reading it inline would block this accept loop and the connection would
                // stall after the first chunk. A numbered `packet-up` POST is complete when it
                // arrives, so it is read here.
                if seq.is_none() {
                    let sender =
                        with_sessions(|map| map.get(&session_of_post).map(|e| e.tx.clone()));
                    tokio::spawn(async move {
                        while let Some(frame) = body.data().await {
                            match frame {
                                Ok(data) => {
                                    if let Some(sender) = &sender
                                        && !data.is_empty()
                                        && sender.send(data).is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    continue;
                }
                let mut chunk = Vec::new();
                while let Some(frame) = body.data().await {
                    match frame {
                        Ok(data) => chunk.extend_from_slice(&data),
                        Err(_) => break,
                    }
                }
                let chunk = Bytes::from(chunk);
                let seq = seq.expect("numbered");
                let delivered = with_sessions(|map| {
                    if let Some(entry) = map.get_mut(&session_of_post) {
                        let ready = entry.state.accept(seq, chunk);
                        let n: usize = ready.iter().map(|p| p.len()).sum();
                        for piece in ready {
                            let _ = entry.tx.send(piece);
                        }
                        Some(n)
                    } else {
                        None
                    }
                });
                tracing::debug!(
                    "packet-up: conn#{conn_id} POST seq={seq:?} session={} delivered={delivered:?}",
                    &session_of_post[..session_of_post.len().min(8)]
                );
            }
        });
        return Ok(Box::new(ChannelDuplex {
            rx: upload_rx,
            tx: down_tx,
            read_buf: Bytes::new(),
            read_pos: 0,
            close: Some(close_tx),
        }));
    }

    // `packet-up` uploads: `/<base>/<session>/<seq>`, each POST carrying one chunk. They are
    // reassembled here and delivered to the session's download stream, which is a separate request.
    if request.method() == Method::POST && under_base && uri_path.matches('/').count() >= 3 {
        let (session, seq) = match uri_path.rsplit_once('/') {
            Some((rest, seq)) => (rest.rsplit('/').next().unwrap_or("").to_string(), seq),
            None => (String::new(), ""),
        };
        let seq: u64 = seq.parse().unwrap_or_default();
        let mut body = request.into_body();
        let mut chunk = Vec::new();
        while let Some(frame) = body.data().await {
            match frame {
                Ok(data) => chunk.extend_from_slice(&data),
                Err(_) => break,
            }
        }
        let ack = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .expect("static ack response");
        let _ = respond.send_response(ack, true);
        let chunk = Bytes::from(chunk);
        with_sessions(|map| {
            if let Some(entry) = map.get_mut(&session) {
                let ready = entry.state.accept(seq, chunk);
                for piece in ready {
                    let _ = entry.tx.send(piece);
                }
            }
        });
        shared::spawn_connection_driver(connection, None);
        return Err(FluxError::Protocol {
            protocol: "xhttp",
            message: format!("packet-up chunk {seq} for session {session} accepted"),
        });
    }

    if let Some(session) = path_session
        && request.method() == Method::POST
        && under_base
    {
        let (download, mut download_respond) = match connection.accept().await {
            Some(Ok(pair)) => pair,
            _ => {
                return Err(FluxError::Protocol {
                    protocol: "xhttp",
                    message: format!("the {session} upload closed before its download arrived"),
                });
            }
        };
        let download_path = download.uri().path().to_string();
        let download_session = download_path
            .strip_prefix(base.as_str())
            .map(|suffix| suffix.trim_matches('/').to_string());
        if download.method() != Method::GET || download_session.as_deref() != Some(session.as_str())
        {
            let refusal = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .expect("static refusal response");
            let _ = download_respond.send_response(refusal, true);
            shared::spawn_connection_driver(
                connection,
                Some(std::time::Duration::from_millis(250)),
            );
            return Err(FluxError::Protocol {
                protocol: "xhttp",
                message: format!("the download for session {session} did not match its upload"),
            });
        }
        let recv: RecvStream = request.into_body();
        let ack = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .expect("static ack response");
        let _ = respond.send_response(ack, true);
        let body_type = if no_sse_header {
            "application/octet-stream"
        } else {
            "text/event-stream"
        };
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", body_type)
            .body(())
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to build the XHTTP download response: {e}"),
            })?;
        let send: SendStream<Bytes> =
            download_respond
                .send_response(response, false)
                .map_err(|e| FluxError::Protocol {
                    protocol: "xhttp",
                    message: format!("failed to send the XHTTP download response: {e}"),
                })?;
        shared::spawn_connection_driver(connection, None);
        return Ok(Box::new(H2Stream::new(send, recv)));
    }

    // Xray only ever uses POST for a streaming upload; anything else is not this
    // transport and gets a plain 404 rather than a stream that would never work.
    if request.method() != Method::POST || !under_base {
        let refusal = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .expect("static refusal response");
        let _ = respond.send_response(refusal, true);
        shared::spawn_connection_driver(connection, Some(std::time::Duration::from_millis(250)));
        return Err(FluxError::Protocol {
            protocol: "xhttp",
            message: format!("{} {uri_path} is not an XHTTP request", request.method()),
        });
    }

    // Xray answers a download stream with `text/event-stream` so it looks like a long-poll, and
    // `noSSEHeader` suppresses that. The body is identical either way; only the label changes.
    let body_type = if no_sse_header {
        "application/octet-stream"
    } else {
        "text/event-stream"
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", body_type)
        .body(())
        .map_err(|e| FluxError::Protocol {
            protocol: "xhttp",
            message: format!("failed to build the XHTTP response: {e}"),
        })?;
    let send: SendStream<Bytes> =
        respond
            .send_response(response, false)
            .map_err(|e| FluxError::Protocol {
                protocol: "xhttp",
                message: format!("failed to send the XHTTP response: {e}"),
            })?;

    let recv: RecvStream = request.into_body();
    // Same release as the split path: one tunnel per connection, so when it ends the connection must
    // go back to the peer's pool instead of lingering (C7.63).
    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut connection = connection;
        loop {
            let next = tokio::select! {
                _ = &mut close_rx => {
                    connection.graceful_shutdown();
                    connection.accept().await
                }
                next = connection.accept() => next,
            };
            if !matches!(next, Some(Ok(_))) {
                break;
            }
        }
    });
    Ok(Box::new(H2Stream::new(send, recv).with_close(close_tx)))
}

/// Normalises a configured path the way Xray does: leading and trailing slashes.
///
/// Xray compares with `strings.HasPrefix(request.URL.Path, config.Path)` after
/// normalising its own path to have both, so a request without the trailing slash is
/// refused with 404 even though it names the same endpoint.
/// Whether a request path belongs to this listener.
///
/// Public and separately testable: this is the one decision an unauthenticated HTTP client
/// can steer, so it must be total and must not be loose. `../` segments are rejected
/// outright rather than normalised, because a proxy that resolves them for a peer is a
/// proxy that can be walked out of its own tree.
pub fn is_under_base(base: &str, request_path: &str) -> bool {
    // Refuse anything that reads as a traversal attempt, literal or percent-encoded. This
    // proxy serves no filesystem behind a path, so an encoded `..` would in fact be inert —
    // but a rule that says "not ours" to a path shaped like an escape is a rule that cannot
    // become wrong when someone later puts something else behind it.
    let lowered = request_path.to_ascii_lowercase();
    if lowered.contains("..") || lowered.contains("%2e") {
        return false;
    }
    let base = normalize_path(base);
    if base == "/" {
        return request_path.starts_with('/');
    }
    let base_no_slash = base.trim_end_matches('/');
    request_path == base_no_slash || request_path.starts_with(&base)
}

fn normalize_path(path: &str) -> String {
    let mut p = path.trim();
    if p.is_empty() {
        return DEFAULT_XHTTP_PATH.to_string();
    }
    let stripped = p.trim_start_matches('/');
    p = stripped;
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}/")
    }
}

/// The encoded length range for `x_padding`: Xray's default, or the configured one.
///
/// `xpaddingBytes` is written as `"100-1000"`; a bare number means "exactly that length", which
/// Xray also accepts. The range bounds the **encoded** value, so the raw entropy is sized to land
/// inside it after base64's 4/3 expansion.
fn padding_range(configured: Option<&str>) -> (usize, usize) {
    let parse = |raw: &str| -> Option<(usize, usize)> {
        let raw = raw.trim().trim_matches('"');
        if raw.is_empty() {
            return None;
        }
        match raw.split_once('-') {
            Some((lo, hi)) => Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?)),
            None => {
                let n = raw.parse().ok()?;
                Some((n, n))
            }
        }
    };
    configured.and_then(parse).unwrap_or((100, 1000))
}

/// A random padding parameter inside the configured range.
fn padding_param(configured: Option<&str>) -> String {
    use rand::RngCore;
    let (lo, hi) = padding_range(configured);
    let (lo, hi) = (lo.max(4), hi.max(lo));
    let encoded_target = lo + (rand::random::<u16>() as usize % (hi - lo + 1));
    // base64 expands by 4/3; round **up** so the encoded string is at least the target, then cut
    // it to exactly the target length. Rounding down and hoping leaves the last few characters
    // outside a range the server validates, which is how an exact-length configuration such as
    // `"1000"` produced 1003 and was refused.
    let target = (encoded_target * 3).div_ceil(4).max(1);
    let mut raw = vec![0u8; target];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let mut encoded = base64url(&raw);
    encoded.truncate(encoded_target);
    encoded
}

/// base64url without padding, which is what a query parameter can carry unescaped.
fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_session_carries_bytes_both_ways() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, None)
                .await
                .expect("server accept");
            let mut buf = vec![0u8; 5];
            s.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"hello");
            s.write_all(b"world").await.expect("server write");
            let _ = s.shutdown().await;
        });

        let mut c = connect(client_io, "example.com", "/tunnel", &HashMap::new(), None)
            .await
            .expect("client connect");
        c.write_all(b"hello").await.expect("client write");
        let mut buf = vec![0u8; 5];
        c.read_exact(&mut buf).await.expect("client read");
        assert_eq!(&buf, b"world");
        let _ = c.shutdown().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }

    #[test]
    fn base64url_matches_the_standard_vectors() {
        // RFC 4648 section 10 with the URL-safe alphabet and no padding. If any of these
        // is wrong, Xray decodes garbage out of `x_padding` and refuses the request.
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff, 0xfe], "-__-"),
        ];
        for (input, expected) in cases {
            assert_eq!(&base64url(input), expected, "encoding {input:?}");
        }
    }

    #[test]
    fn the_padding_stays_inside_the_range_xray_accepts() {
        // The server checks the length of the *encoded* value against its configured
        // range, 100-1000 by default. A value outside it is refused with the length
        // quoted back, which is how this was found the first time.
        for _ in 0..500 {
            let value = padding_param(None);
            assert!(
                (100..=1000).contains(&value.len()),
                "padding length {} is outside 100-1000",
                value.len()
            );
            assert!(!value.contains('='), "padding must be unpadded: {value}");
            assert!(
                !value.contains('+') && !value.contains('/'),
                "must be URL-safe"
            );
        }
    }

    #[test]
    fn paths_are_normalised_the_way_xray_compares_them() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("tunnel"), "/tunnel/");
        assert_eq!(normalize_path("/tunnel"), "/tunnel/");
        assert_eq!(normalize_path("/tunnel/"), "/tunnel/");
        assert_eq!(normalize_path("//tunnel//"), "/tunnel/");
    }

    #[tokio::test]
    async fn a_get_is_refused() {
        // `stream-one` is the POST branch; a GET belongs to `stream-down`, which this
        // implementation does not speak. Answering 200 would leave a client waiting for
        // a download stream that never carries anything.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            accept(server_io, "/tunnel", false, None, None)
                .await
                .is_err()
        });
        let mut client = shared::client_handshake(client_io, "xhttp")
            .await
            .expect("client");
        let request = Request::builder()
            .method(Method::GET)
            .uri("/tunnel/")
            .body(())
            .unwrap();
        let _ = client.send_request(request, false);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .expect("must not hang")
                .expect("task")
        );
    }

    #[tokio::test]
    async fn a_deep_path_under_the_base_is_accepted() {
        // Xray appends things to the base path; the prefix rule must not be exact-match.
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, None)
                .await
                .expect("accept");
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).await.expect("read");
            s.write_all(&buf).await.expect("write");
            let _ = s.shutdown().await;
        });
        let mut client = shared::client_handshake(client_io, "xhttp")
            .await
            .expect("client");
        let request = Request::builder()
            .method(Method::POST)
            .uri("/tunnel/session-a")
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, false).expect("send");
        let response = response.await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        send.send_data(Bytes::from_static(b"abc"), false)
            .expect("data");
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body.data())
            .await
            .expect("must not hang")
            .expect("chunk")
            .expect("ok");
        assert_eq!(&chunk[..], b"abc");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }

    #[tokio::test]
    async fn a_path_outside_the_base_is_refused() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            accept(server_io, "/tunnel", false, None, None)
                .await
                .is_err()
        });
        let mut client = shared::client_handshake(client_io, "xhttp")
            .await
            .expect("client");
        let request = Request::builder()
            .method("POST")
            .uri("/elsewhere/abc")
            .body(())
            .unwrap();
        let _ = client.send_request(request, false);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .expect("must not hang")
                .expect("task"),
            "a request outside the base path must be refused"
        );
    }
}

#[cfg(test)]
mod padding_tests {
    use super::padding_range;

    /// The default is Xray's own: 100–1000 characters of encoded padding.
    #[test]
    fn the_default_range_is_xrays() {
        assert_eq!(padding_range(None), (100, 1000));
        assert_eq!(padding_range(Some("")), (100, 1000));
        assert_eq!(padding_range(Some("garbage")), (100, 1000));
    }

    /// `xpaddingBytes` is honoured, both spellings Xray accepts.
    #[test]
    fn a_configured_range_is_used() {
        assert_eq!(padding_range(Some("500-600")), (500, 600));
        assert_eq!(padding_range(Some("42")), (42, 42));
        assert_eq!(padding_range(Some(" 300 - 400 ")), (300, 400));
    }

    /// The padding a request actually carries stays inside the configured range — the property
    /// beyond the parse, and the one Xray validates.
    #[test]
    fn generated_padding_lands_inside_the_configured_range() {
        for cfg in ["200-300", "1000"] {
            let (lo, hi) = padding_range(Some(cfg));
            for _ in 0..64 {
                let p = super::padding_param(Some(cfg));
                assert!(
                    p.len() >= lo && p.len() <= hi,
                    "padding of {} chars outside {lo}-{hi} for {cfg}",
                    p.len()
                );
            }
        }
    }
}

#[cfg(test)]
mod two_stream_probe {
    /// Can this h2 layer carry **two concurrent requests on one connection** at all?
    ///
    /// `stream-up` is built on exactly that: an uploading POST and a downloading GET, paired by the
    /// server. If the substrate cannot do it, no amount of mode code above it will work, and every
    /// later failure would be misread as a pairing bug.
    #[tokio::test]
    async fn the_server_accepts_two_requests_on_one_connection() {
        use crate::h2::shared;
        use http::{Request, Response, StatusCode};

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server = tokio::spawn(async move {
            let mut connection = shared::server_handshake(server_io, "probe")
                .await
                .expect("server handshake");
            let (first, mut respond_first) = connection
                .accept()
                .await
                .expect("first request")
                .expect("first request ok");
            let first_path = first.uri().path().to_string();
            let (second, mut respond_second) = connection
                .accept()
                .await
                .expect("second request")
                .expect("second request ok");
            let second_path = second.uri().path().to_string();

            // Answer both: the first with an open body, the second with a complete one.
            let send = respond_first
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("resp"),
                    false,
                )
                .expect("first response");
            drop(send);
            let _ = respond_second.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .expect("resp"),
                true,
            );
            shared::spawn_connection_driver(connection, None);
            (first_path, second_path)
        });

        let client = tokio::spawn(async move {
            let mut client = shared::client_handshake(client_io, "probe")
                .await
                .expect("client handshake");
            let (resp_a, _send_a) = client
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("/a")
                        .body(())
                        .expect("req"),
                    false,
                )
                .expect("first send");
            let (resp_b, _send_b) = client
                .send_request(
                    Request::builder()
                        .method("GET")
                        .uri("/b")
                        .body(())
                        .expect("req"),
                    true,
                )
                .expect("second send");
            let a = tokio::time::timeout(std::time::Duration::from_secs(5), resp_a)
                .await
                .expect("first response timed out")
                .expect("first response");
            let b = tokio::time::timeout(std::time::Duration::from_secs(5), resp_b)
                .await
                .expect("second response timed out")
                .expect("second response");
            (a.status(), b.status())
        });

        let (paths, statuses) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            (server.await.expect("server"), client.await.expect("client"))
        })
        .await
        .expect("two requests on one connection must both complete");

        assert_eq!(paths, ("/a".to_string(), "/b".to_string()));
        assert_eq!(statuses.0, StatusCode::OK);
        assert_eq!(statuses.1, StatusCode::OK);
    }
}

#[cfg(test)]
mod stream_up_end_to_end {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `connect_stream_up` against `accept`, over one real duplex socket.
    ///
    /// This is the test that failed before `H2Stream::new_client_split`: the client waited for the
    /// download response before writing, the server waited for the upload before flushing it, and
    /// the two deadlocked.
    #[tokio::test]
    async fn stream_up_moves_bytes_both_ways() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, None)
                .await
                .expect("server must pair the session");
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf))
                .await
                .expect("server read timed out")
                .expect("server read");
            assert_eq!(&buf[..n], b"ping");
            s.write_all(b"pong").await.expect("server write");
            // `shutdown` ends the stream with END_STREAM. Dropping it instead sends RST_STREAM
            // CANCEL, and the reader loses the bytes that were queued: the same cancel-on-drop
            // that C7.4 recorded.
            s.shutdown().await.expect("server shutdown");
        });

        let client = tokio::spawn(async move {
            let mut c =
                connect_stream_up(client_io, "example.com", "/tunnel", &HashMap::new(), None)
                    .await
                    .expect("client stream-up");
            c.write_all(b"ping").await.expect("client write");
            c.flush().await.expect("client flush");
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), c.read(&mut buf))
                .await
                .expect("client read timed out")
                .expect("client read");
            assert_eq!(&buf[..n], b"pong");
        });

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            server.await.expect("server task");
            client.await.expect("client task");
        })
        .await
        .expect("stream-up must move data in both directions");
    }

    #[test]
    fn session_ids_are_unique_and_hex() {
        let (a, b) = (session_id(), session_id());
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[cfg(test)]
mod packet_up_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `connect_packet_up` against `accept`, over one real duplex socket.
    ///
    /// The upload goes through a queue, a poster task, one POST per chunk and server-side
    /// reassembly; the download comes back on a separate GET. Nothing else exercises all of that at
    /// once, and the two halves failed separately before this existed.
    #[tokio::test]
    async fn packet_up_moves_bytes_both_ways() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, None)
                .await
                .expect("server must open the packet-up session");
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf))
                .await
                .expect("server read timed out")
                .expect("server read");
            assert_eq!(&buf[..n], b"ping");
            s.write_all(b"pong").await.expect("server write");
            s.shutdown().await.expect("server shutdown");
        });

        let client = tokio::spawn(async move {
            let mut c = connect_packet_up(
                client_io,
                "example.com",
                "/tunnel",
                &HashMap::new(),
                None,
                &PacketUpOptions::default(),
            )
            .await
            .expect("client packet-up");
            c.write_all(b"ping").await.expect("client write");
            c.flush().await.expect("client flush");
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), c.read(&mut buf))
                .await
                .expect("client read timed out")
                .expect("client read");
            assert_eq!(&buf[..n], b"pong");
        });

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            server.await.expect("server task");
            client.await.expect("client task");
        })
        .await
        .expect("packet-up must move data in both directions");
    }

    /// `scMaxEachPostBytes`: one write becomes several POST bodies, none larger than the limit, and
    /// the pieces join back into exactly the original bytes.
    #[test]
    fn a_write_is_split_to_the_configured_post_size() {
        let data: Vec<u8> = (0..200u32).map(|n| (n % 251) as u8).collect();
        let pieces = split_posts(Bytes::from(data.clone()), 64);
        assert_eq!(pieces.len(), 4, "200 bytes at 64 per POST");
        for piece in &pieces {
            assert!(piece.len() <= 64, "no POST may exceed the limit");
        }
        let joined: Vec<u8> = pieces.iter().flat_map(|p| p.to_vec()).collect();
        assert_eq!(joined, data, "the pieces must rejoin to the original bytes");
    }

    /// A write inside the limit is one POST and is not copied again.
    #[test]
    fn a_small_write_stays_one_post() {
        let pieces = split_posts(Bytes::from_static(b"ping"), 1024);
        assert_eq!(pieces.len(), 1);
        assert_eq!(&pieces[0][..], b"ping");
    }

    /// A zero limit must not mean "unlimited": that would loop forever. It falls back to the default.
    #[test]
    fn a_zero_limit_falls_back_to_the_default() {
        let pieces = split_posts(Bytes::from_static(b"ping"), 0);
        assert_eq!(pieces.len(), 1);
    }

    /// Out-of-order chunks are held until the gap fills, and a duplicate is dropped rather than
    /// delivered twice — a retried POST must not corrupt the stream above it.
    #[test]
    fn reassembly_delivers_in_order_and_drops_duplicates() {
        let mut r = Reassembly::default();
        assert!(r.accept(1, Bytes::from_static(b"b")).is_empty(), "gap at 0");
        assert!(
            r.accept(0, Bytes::from_static(b"a")).len() == 2,
            "0 unblocks 1"
        );
        assert_eq!(r.next, 2);
        assert!(
            r.accept(0, Bytes::from_static(b"a")).is_empty(),
            "duplicate dropped"
        );
        assert_eq!(r.next, 2, "a duplicate must not advance the index");
    }
}

#[cfg(test)]
mod split_write_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `scMinPostsIntervalMs`: the poster must actually wait between POSTs.
    ///
    /// 200 bytes at 64 per POST is four requests, so with a 50 ms interval the transfer cannot finish
    /// in less than 150 ms. Without the pacing this completes almost instantly — which is the
    /// difference the setting is supposed to make.
    #[tokio::test]
    async fn posts_are_paced_by_the_configured_interval() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let expected: Vec<u8> = (0..200u32).map(|n| (n % 251) as u8).collect();
        let want = expected.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<std::time::Duration>();

        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, None)
                .await
                .expect("server must open the session");
            let started = std::time::Instant::now();
            let mut got = vec![0u8; 200];
            let mut filled = 0;
            while filled < 200 {
                let n = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    s.read(&mut got[filled..]),
                )
                .await
                .expect("server read timed out")
                .expect("server read");
                if n == 0 {
                    break;
                }
                filled += n;
            }
            assert_eq!(got, want);
            let _ = done_tx.send(started.elapsed());
        });

        let client = tokio::spawn(async move {
            let options = PacketUpOptions {
                max_each_post_bytes: Some(64),
                min_posts_interval: Some(std::time::Duration::from_millis(50)),
                ..Default::default()
            };
            let mut c = connect_packet_up(
                client_io,
                "example.com",
                "/tunnel",
                &HashMap::new(),
                None,
                &options,
            )
            .await
            .expect("client packet-up");
            c.write_all(&expected).await.expect("write");
            c.flush().await.expect("flush");
        });

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            server.await.expect("server");
            client.await.expect("client");
        })
        .await
        .expect("paced transfer must complete");
        let elapsed = done_rx.await.expect("server timing");
        assert!(
            elapsed >= std::time::Duration::from_millis(150),
            "four POSTs at a 50 ms interval cannot arrive in {elapsed:?}"
        );
    }

    /// `scStreamUpServerSecs`: the server must not keep an upload stream open forever.
    ///
    /// With a one-second lifetime the read returns end-of-stream on its own, without the client
    /// closing anything.
    #[tokio::test]
    async fn the_upload_stream_closes_on_its_own_lifetime() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, Some(1))
                .await
                .expect("server must open the session");
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
                .await
                .expect("first read timed out")
                .expect("first read");
            assert_eq!(&buf[..n], b"ping");
            // Nothing else is written; the lifetime must end the stream by itself.
            let started = std::time::Instant::now();
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
                .await
                .expect("the stream should close on its own lifetime")
                .expect("second read");
            assert_eq!(n, 0, "the lifetime must end the stream");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(4),
                "it should close near the configured second, not later"
            );
        });

        let client = tokio::spawn(async move {
            let mut c = connect_packet_up(
                client_io,
                "example.com",
                "/tunnel",
                &HashMap::new(),
                None,
                &PacketUpOptions::default(),
            )
            .await
            .expect("client packet-up");
            c.write_all(b"ping").await.expect("write");
            c.flush().await.expect("flush");
            // Keep the client alive; the server must end the stream, not the client.
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            server.await.expect("server");
            client.await.expect("client");
        })
        .await
        .expect("the server must close the upload stream itself");
    }

    /// `scMaxEachPostBytes`: a write split across several POSTs must arrive byte-for-byte.
    ///
    /// The write is delayed by 100 ms because a POST that is in flight while the server is still
    /// sending the download response puts the h2 stream into a state the server rejects with
    /// `unexpected frame type`. In real use the relay writes only after the tunnel is up, so this
    /// delay models the real ordering; the race itself is recorded as a known limitation in the
    /// audit log rather than hidden here.
    #[tokio::test]
    async fn a_split_write_arrives_intact() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let expected: Vec<u8> = (0..200u32).map(|n| (n % 251) as u8).collect();
        let want = expected.clone();

        let server = tokio::spawn(async move {
            let mut s = accept(server_io, "/tunnel", false, None, None)
                .await
                .expect("server must open the session");
            let mut got = vec![0u8; 200];
            let mut filled = 0;
            while filled < 200 {
                let n = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    s.read(&mut got[filled..]),
                )
                .await
                .expect("server read timed out")
                .expect("server read");
                if n == 0 {
                    break;
                }
                filled += n;
            }
            assert_eq!(filled, 200);
            assert_eq!(got, want);
        });

        let client = tokio::spawn(async move {
            let options = PacketUpOptions {
                max_each_post_bytes: Some(64),
                ..Default::default()
            };
            let mut c = connect_packet_up(
                client_io,
                "example.com",
                "/tunnel",
                &HashMap::new(),
                None,
                &options,
            )
            .await
            .expect("client packet-up");
            c.write_all(&expected).await.expect("write");
            c.flush().await.expect("flush");
        });

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            server.await.expect("server");
            client.await.expect("client");
        })
        .await
        .expect("split write must reassemble");
    }
}
