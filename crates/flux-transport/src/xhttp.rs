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
            let mut s = accept(server_io, "/tunnel", false).await.expect("server accept");
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
        let server = tokio::spawn(async move { accept(server_io, "/tunnel", false).await.is_err() });
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
        let server = tokio::spawn(async move { accept(server_io, "/tunnel", false).await.is_err() });
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
