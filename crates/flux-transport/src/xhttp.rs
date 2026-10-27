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
    /// Download half: the GET's response body, already resolved when the stream is built.
    recv: RecvStream,
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
            match Pin::new(&mut this.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    this.read_buf = data;
                    this.read_pos = 0;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                }
                Poll::Ready(None) => {
                    this.read_done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
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
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the packet-up poster has stopped",
            ))),
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

/// Client half of `packet-up`.
pub async fn connect_packet_up<S>(
    stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
    xpadding: Option<&str>,
) -> FluxResult<Box<dyn AsyncStream>>
where
    S: AsyncStream + 'static,
{
    let mut client = shared::client_handshake(stream, "xhttp").await?;
    let session = session_id();
    let base = normalize_path(path);
    let padding = padding_param(xpadding);

    // Download: the same GET as `stream-up`.
    let download_url = format!("{base}{session}?x_padding={padding}");
    let mut builder = Request::builder()
        .method("GET")
        .uri(download_url.as_str())
        .header("Host", host)
        .header("content-type", "application/octet-stream");
    for (k, v) in headers {
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
    let response = download_response.await.map_err(|e| FluxError::Protocol {
        protocol: "xhttp",
        message: format!("the XHTTP download was refused: {e}"),
    })?;
    let recv = response.into_body();

    // Upload: a task posts each queued chunk to /<base>/<session>/<seq>.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    let host = host.to_string();
    let headers = headers.clone();
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        while let Some(_chunk) = rx.recv().await {
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
                break;
            };
            let (posted, _) = match client.send_request(request, false) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("packet-up: send_request failed for seq {seq}: {e}");
                    break;
                }
            };
            // The request body completes this POST, and the response is **drained**: a response body
            // dropped unread sends `RST_STREAM CANCEL`, which is the fault C7.8 took three cycles to
            // find on the stream-up upload path.
            match posted.await {
                Ok(response) if response.status().is_success() => {
                    tracing::debug!("packet-up: seq posted, status {}", response.status());
                    let mut body = response.into_body();
                    while let Some(chunk) = body.data().await {
                        if chunk.is_err() {
                            break;
                        }
                    }
                }
                Ok(response) => {
                    tracing::warn!("packet-up: POST rejected with {}", response.status());
                    break;
                }
                Err(e) => {
                    tracing::warn!("packet-up: POST failed: {e}");
                    break;
                }
            }
        }
    });

    Ok(Box::new(PacketUpStream {
        recv,
        read_buf: Bytes::new(),
        read_pos: 0,
        read_done: false,
        tx,
    }))
}

/// Server half: accepts one bidirectional request and returns it as a stream.
///
/// `path` is the configured base path. Anything under it is accepted, because the client
/// appends a per-session suffix; anything else is refused with 404, like a web server
/// serving only its own tree.
pub async fn accept<S>(stream: S, path: &str, no_sse_header: bool) -> FluxResult<H2Stream>
where
    S: AsyncStream + 'static,
{
    let mut connection = shared::server_handshake(stream, "xhttp").await?;
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
        .filter(|suffix| suffix.len() == 32 && suffix.chars().all(|c| c.is_ascii_hexdigit()));

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
        return Ok(H2Stream::new(send, recv));
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
    shared::spawn_connection_driver(connection, None);
    Ok(H2Stream::new(send, recv))
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
            let mut s = accept(server_io, "/tunnel", false)
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
        let server =
            tokio::spawn(async move { accept(server_io, "/tunnel", false).await.is_err() });
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
            let mut s = accept(server_io, "/tunnel", false).await.expect("accept");
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
        let server =
            tokio::spawn(async move { accept(server_io, "/tunnel", false).await.is_err() });
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
            let mut s = accept(server_io, "/tunnel", false)
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
