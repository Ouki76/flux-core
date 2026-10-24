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
    let full = format!("{full}?x_padding={}", padding_param());

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
pub async fn accept<S>(stream: S, path: &str) -> FluxResult<H2Stream>
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

    let base = normalize_path(path);
    let uri_path = request.uri().path().to_string();
    let under_base = if base == "/" {
        uri_path.starts_with('/')
    } else {
        uri_path == base || uri_path.starts_with(&format!("{}/", base.trim_end_matches('/')))
    };

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

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
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

/// A random padding parameter, in the length range Xray normalises its own to.
fn padding_param() -> String {
    use rand::RngCore;
    // Xray validates the length of the *encoded* value against its configured range
    // (100-1000 by default), so the entropy is sized to land inside it: base64 expands
    // by 4/3, and a 150..750 byte source encodes to 200..1000 characters.
    let target = 150 + (rand::random::<u16>() % 601) as usize;
    let mut raw = vec![0u8; target];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    base64url(&raw)
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
            let mut s = accept(server_io, "/tunnel").await.expect("server accept");
            let mut buf = vec![0u8; 5];
            s.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"hello");
            s.write_all(b"world").await.expect("server write");
            let _ = s.shutdown().await;
        });

        let mut c = connect(client_io, "example.com", "/tunnel", &HashMap::new())
            .await
            .expect("client connect");
        c.write_all(b"hello").await.expect("client write");
        let mut buf = vec![0u8; 5];
        c.read_exact(&mut buf).await.expect("client read");
        assert_eq!(&buf, b"world");
        let _ = c.shutdown().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }

    #[tokio::test]
    async fn a_path_outside_the_base_is_refused() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { accept(server_io, "/tunnel").await.is_err() });
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
