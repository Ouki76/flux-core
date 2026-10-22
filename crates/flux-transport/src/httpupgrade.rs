use flux_common::copy::PrefixedStream;
use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Rejects control bytes in anything that ends up on the request line or in a
/// header. A `\r\n` smuggled through the configuration (path, host or a custom
/// header) would terminate the request early and inject a second request into
/// the tunnel, so this is checked before a single byte is written.
fn reject_ctl(what: &str, value: &str) -> FluxResult<()> {
    match value.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
        Some(b) => Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!("{what} contains control byte 0x{b:02x}: {value:?}"),
        }),
        None => Ok(()),
    }
}

/// Performs an HTTP/1.1 Upgrade handshake (RFC 7230), switching the connection
/// to raw bi-directional streaming once `101 Switching Protocols` is returned.
pub async fn client_handshake<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> FluxResult<BoxedStream>
where
    S: AsyncStream + 'static,
{
    // Validate before writing: a poisoned request must never reach the wire.
    let path = if path.is_empty() { "/" } else { path };
    reject_ctl("request path", path)?;
    if !path.starts_with('/') || path.contains(' ') {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!(
                "invalid request path {path:?}: expected an origin-form target such as \"/tunnel\""
            ),
        });
    }
    reject_ctl("host", host)?;
    if host.is_empty() || host.contains(' ') {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!("invalid Host value {host:?}"),
        });
    }
    for (k, v) in headers {
        reject_ctl("header name", k)?;
        reject_ctl("header value", v)?;
        if k.is_empty() || k.contains([' ', ':']) {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: format!("invalid header name {k:?}"),
            });
        }
    }

    let upgrade_val = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("websocket");

    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n",
        path, host, upgrade_val
    );

    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("connection")
            && !k.eq_ignore_ascii_case("upgrade")
        {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // Read response headers
    let mut resp_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while resp_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: "EOF while reading HTTP upgrade response".into(),
            });
        }
        resp_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "httpupgrade",
        message: "response header missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&resp_buf[..h_end]);
    let first_line = header_str.lines().next().unwrap_or("");
    // Parse the status line instead of substring-matching: `contains("101")`
    // also matched reason phrases and four-digit statuses such as 1010, and
    // treating `200 OK` as success promoted a proxy error page to a tunnel.
    // Only a real `HTTP/1.1 101` switches protocols (RFC 9110 6.2.1), which is
    // also exactly what sing-box's HTTPUpgrade client requires.
    let mut status_parts = first_line.split_whitespace();
    let version = status_parts.next().unwrap_or("");
    let status: Option<u16> = status_parts.next().and_then(|s| s.parse().ok());
    if version != "HTTP/1.1" || status != Some(101) {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!("server rejected upgrade: {}", first_line),
        });
    }
    // A header line without a colon means the peer is not speaking HTTP
    // (obs-fold continuations excepted): refuse rather than trust it.
    for line in header_str.lines().skip(1) {
        if line.trim().is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if !line.contains(':') {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: format!("malformed header line in the upgrade response: {line:?}"),
            });
        }
    }

    let excess = resp_buf[h_end..].to_vec();
    if excess.is_empty() {
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(PrefixedStream::new(stream, excess)))
    }
}

/// Performs a server-side HTTP/1.1 Upgrade handshake, validating path and upgrade headers.
pub async fn server_handshake<S>(
    mut stream: S,
    expected_path: Option<&str>,
) -> FluxResult<BoxedStream>
where
    S: AsyncStream + 'static,
{
    let mut req_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while req_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: "EOF while reading HTTP upgrade request".into(),
            });
        }
        req_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "httpupgrade",
        message: "request header missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&req_buf[..h_end]);
    let mut lines = header_str.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let version = parts.next();
    let trailing = parts.next();
    // HTTPUpgrade is a `GET` upgrade. Requiring the method, a real HTTP/1.x
    // request line and the `Upgrade`/`Connection` pair keeps an ordinary request
    // (or a non-HTTP client) from being promoted to a raw tunnel.
    if method != "GET" {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!("expected GET for the upgrade request, got '{method}'"),
        });
    }
    // `method SP request-target SP HTTP-version CRLF`. Without the version this
    // is not an HTTP/1.x request at all (an HTTP/2 preface, for example), and
    // promoting it would hand a raw tunnel to something that never asked for one.
    match version {
        Some(v) if v.starts_with("HTTP/1.") => {}
        _ => {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: format!("malformed request line: {first_line:?}"),
            });
        }
    }
    if trailing.is_some() {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!("request line has trailing tokens: {first_line:?}"),
        });
    }

    let mut has_upgrade_header = false;
    let mut has_connection_upgrade = false;
    for line in header_str.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        // Every non-empty header line must be `name: value`; a colon-less line
        // is either smuggling or a broken peer, and both must be refused.
        let Some((k, v)) = line.split_once(':') else {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: format!("malformed header line (no colon): {line:?}"),
            });
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("upgrade") {
            // Duplicated `Upgrade` headers with different values are ambiguous
            // (last-one-wins differs between stacks); require every one of them
            // to be the token we switch to.
            if !v.eq_ignore_ascii_case("websocket") {
                return Err(FluxError::Protocol {
                    protocol: "httpupgrade",
                    message: format!("unexpected Upgrade value: {v:?}"),
                });
            }
            has_upgrade_header = true;
        } else if k.eq_ignore_ascii_case("connection") {
            has_connection_upgrade |= v
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        }
    }
    if !has_upgrade_header {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: "missing 'Upgrade: websocket' header".into(),
        });
    }
    // RFC 9110 7.8: a protocol switch requires both tokens. Requiring
    // `Connection: Upgrade` keeps an ordinary GET that happens to carry an
    // `Upgrade` header from being promoted to a tunnel (the websocket path in
    // this crate enforces the same pair).
    if !has_connection_upgrade {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: "missing 'Connection: Upgrade' header".into(),
        });
    }

    if let Some(exp) = expected_path {
        let actual_path = path.split('?').next().unwrap_or(path);
        if actual_path != exp {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: format!("path mismatch: expected '{}', got '{}'", exp, actual_path),
            });
        }
    }

    let resp =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    let excess = req_buf[h_end..].to_vec();
    if excess.is_empty() {
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(PrefixedStream::new(stream, excess)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A well-formed request, used as the baseline for the rejection tables.
    const GOOD_REQUEST: &[u8] = b"GET /tunnel HTTP/1.1\r\nHost: example.org\r\n\
        Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    const GOOD_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
        Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

    fn assert_protocol_error<T>(result: FluxResult<T>, what: &str) {
        assert_protocol_error_matching(result, what, None);
    }

    /// Asserts rejection *and* that a specific rule fired, so a test cannot pass
    /// because some unrelated check happened to fail first.
    fn assert_protocol_error_matching<T>(result: FluxResult<T>, what: &str, expect: Option<&str>) {
        match result {
            Err(FluxError::Protocol { protocol, message }) => {
                assert_eq!(protocol, "httpupgrade", "{what}: wrong protocol tag: {message}");
                assert!(!message.is_empty(), "{what}: empty diagnostic");
                if let Some(expect) = expect {
                    assert!(
                        message.contains(expect),
                        "{what}: expected a diagnostic containing {expect:?}, got {message:?}"
                    );
                }
            }
            Err(other) => panic!("{what}: expected a protocol error, got: {other}"),
            Ok(_) => panic!("{what}: expected rejection, but the handshake succeeded"),
        }
    }

    /// Every handshake driven by a test must either finish or be rejected; a
    /// hang here means a test bug (or a real deadlock in the code under test).
    async fn within<F: std::future::Future>(what: &str, fut: F) -> F::Output {
        match tokio::time::timeout(Duration::from_secs(5), fut).await {
            Ok(v) => v,
            Err(_) => panic!("{what}: handshake neither completed nor was rejected"),
        }
    }

    fn header_end(buf: &[u8]) -> bool {
        buf.windows(4).any(|w| w == b"\r\n\r\n")
    }

    /// Runs the client handshake against a scripted server, returning the
    /// result and the exact bytes the client put on the wire.
    async fn client_against(chunks: &[&[u8]]) -> (FluxResult<()>, Vec<u8>) {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let chunks: Vec<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();
        let srv = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !header_end(&seen) {
                match server_io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            for chunk in chunks {
                if server_io.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = server_io.flush().await;
            seen
        });
        let res = within(
            "client_against",
            client_handshake(client_io, "example.org", "/tunnel", &HashMap::new()),
        )
        .await
        .map(|_| ());
        let written = srv.await.unwrap();
        (res, written)
    }

    /// Feeds `request` to the server handshake, signals EOF behind it, and
    /// returns the result together with the bytes the server replied with.
    /// An in-memory stream: yields `input` once and then EOF, capturing every
    /// byte the code under test writes. Unlike a duplex pair this signals EOF
    /// deterministically, so a truncated request can be tested without a race.
    struct ScriptedIo {
        input: Vec<u8>,
        pos: usize,
        output: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl ScriptedIo {
        fn new(input: &[u8]) -> (Self, Arc<std::sync::Mutex<Vec<u8>>>) {
            let output = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    input: input.to_vec(),
                    pos: 0,
                    output: output.clone(),
                },
                output,
            )
        }
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = (self.input.len() - self.pos).min(buf.remaining());
            if n == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            let start = self.pos;
            buf.put_slice(&self.input[start..start + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.output.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Feeds `request` to the server handshake (then EOF) and returns the
    /// result plus everything the server wrote back.
    async fn server_against(
        request: &[u8],
        expected_path: Option<&str>,
    ) -> (FluxResult<()>, Vec<u8>) {
        let (io, output) = ScriptedIo::new(request);
        let res = within("server_against", server_handshake(io, expected_path))
            .await
            .map(|_| ());
        let written = output.lock().unwrap().clone();
        (res, written)
    }

    async fn assert_server_rejects(
        request: &[u8],
        expected_path: Option<&str>,
        what: &str,
        expect: &str,
    ) {
        let (res, response) = server_against(request, expected_path).await;
        assert_protocol_error_matching(res, what, Some(expect));
        assert!(
            response.is_empty(),
            "{what}: server wrote {} bytes before rejecting the request",
            response.len()
        );
    }

    // ---- existing round-trip coverage ---------------------------------------

    #[tokio::test]
    async fn test_httpupgrade_handshake_and_bidirectional_data() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let mut server_stream = server_handshake(server_io, Some("/tunnel")).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = server_stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Client payload through HTTPUpgrade");
            server_stream
                .write_all(b"Server reply through HTTPUpgrade")
                .await
                .unwrap();
            server_stream.flush().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut headers = HashMap::new();
            headers.insert("X-Custom-Header".into(), "flux-val".into());
            let mut client_stream = client_handshake(client_io, "example.org", "/tunnel", &headers)
                .await
                .unwrap();
            client_stream
                .write_all(b"Client payload through HTTPUpgrade")
                .await
                .unwrap();
            client_stream.flush().await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = client_stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Server reply through HTTPUpgrade");
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_httpupgrade_path_mismatch_rejected() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let res = server_handshake(server_io, Some("/expected-path")).await;
            assert!(res.is_err());
        });

        let client_task = tokio::spawn(async move {
            let _ =
                client_handshake(client_io, "example.org", "/wrong-path", &HashMap::new()).await;
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    // ---- request shape ------------------------------------------------------

    #[tokio::test]
    async fn test_httpupgrade_client_request_shape() {
        // Default: the canonical three headers, then custom ones, then the
        // terminating blank line. Header order and CRLF-only line endings are
        // what a real client would produce.
        let (res, written) = client_against(&[GOOD_RESPONSE]).await;
        res.unwrap();
        let request = String::from_utf8(written).unwrap();
        assert_eq!(
            request,
            "GET /tunnel HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\n\r\n",
            "the upgrade request must be byte-exact"
        );
        assert_eq!(request.matches("Host:").count(), 1, "exactly one Host header");
        assert!(
            !request.replace("\r\n", "").contains('\n'),
            "a bare LF in a request is a fingerprint"
        );

        // A caller-supplied upgrade token wins, and Host/Connection/Upgrade are
        // never duplicated even when the map spells them differently.
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut headers = HashMap::new();
        headers.insert("HOST".to_string(), "evil.example".to_string());
        headers.insert("Connection".to_string(), "close".to_string());
        headers.insert("Upgrade".to_string(), "spdy".to_string());
        headers.insert("X-Trace".to_string(), "1".to_string());
        let srv = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !header_end(&seen) {
                match server_io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = server_io.write_all(GOOD_RESPONSE).await;
            let _ = server_io.flush().await;
            seen
        });
        client_handshake(client_io, "example.org", "/tunnel", &headers)
            .await
            .unwrap();
        let written = srv.await.unwrap();
        let request = String::from_utf8(written).unwrap();
        assert_eq!(request.matches("Host:").count(), 1, "Host must not be duplicated");
        assert_eq!(
            request.matches("Connection:").count(),
            1,
            "Connection must not be duplicated"
        );
        assert_eq!(request.matches("Upgrade:").count(), 1, "Upgrade must not be duplicated");
        assert!(request.contains("Host: example.org\r\n"), "the argument wins over the header");
        assert!(request.contains("Upgrade: spdy\r\n"), "an explicit upgrade token is honoured");
        assert!(request.contains("X-Trace: 1\r\n"));

        // An empty path must still produce an origin-form request target.
        let (res, written) = client_handshake_probe("", &HashMap::new()).await;
        res.unwrap();
        assert!(String::from_utf8(written).unwrap().starts_with("GET / HTTP/1.1\r\n"));
    }

    /// Like `client_against`, but with control over path and headers.
    async fn client_handshake_probe(
        path: &str,
        headers: &HashMap<String, String>,
    ) -> (FluxResult<()>, Vec<u8>) {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let headers = headers.clone();
        let path = path.to_string();
        let srv = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !header_end(&seen) {
                match server_io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = server_io.write_all(GOOD_RESPONSE).await;
            let _ = server_io.flush().await;
            seen
        });
        let res = within(
            "client_handshake_probe",
            client_handshake(client_io, "example.org", &path, &headers),
        )
        .await
        .map(|_| ());
        (res, srv.await.unwrap())
    }

    // ---- request splitting --------------------------------------------------

    /// Asserts the client refuses a poisoned request *before* putting a single
    /// byte on the wire: a `\r\n` smuggled through the config would otherwise
    /// turn the upgrade into two requests on the tunnel.
    async fn assert_rejected_before_writing(
        host: &str,
        path: &str,
        headers: HashMap<String, String>,
        what: &str,
        expect: &str,
    ) {
        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let res = within(what, client_handshake(client_io, host, path, &headers)).await;
        assert_protocol_error_matching(res, what, Some(expect));
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(200), server_io.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!(
                "{what}: {} bytes of a poisoned request reached the wire: {:?}",
                n,
                String::from_utf8_lossy(&buf[..n])
            ),
            Ok(Err(e)) => panic!("{what}: unexpected I/O error: {e}"),
            Err(_) => panic!("{what}: the stream was left open, so a peer could hang on it"),
        }
    }

    #[tokio::test]
    async fn test_httpupgrade_client_rejects_poisoned_request_parts() {
        assert_rejected_before_writing(
            "example.org\r\nX-Injected: yes",
            "/tunnel",
            HashMap::new(),
            "CRLF in host",
            "control byte",
        )
        .await;
        assert_rejected_before_writing(
            "example.org",
            "/a\r\nX-Injected: yes",
            HashMap::new(),
            "CRLF in path",
            "control byte",
        )
        .await;
        assert_rejected_before_writing("example.org", "/tunnel", {
            let mut h = HashMap::new();
            h.insert("X-Bad\r\nX-Injected: yes".to_string(), "v".to_string());
            h
        }, "CRLF in header name", "control byte")
        .await;
        assert_rejected_before_writing("example.org", "/tunnel", {
            let mut h = HashMap::new();
            h.insert("X-Bad".to_string(), "v\r\nX-Injected: yes".to_string());
            h
        }, "CRLF in header value", "control byte")
        .await;
        // A request target cannot contain a space, and must be origin-form.
        assert_rejected_before_writing("example.org", "/a b", HashMap::new(), "space in path", "invalid request path").await;
        assert_rejected_before_writing("example.org", "tunnel", HashMap::new(), "relative path", "invalid request path").await;
        assert_rejected_before_writing("", "/tunnel", HashMap::new(), "empty host", "invalid Host value").await;
        assert_rejected_before_writing("exa mple.org", "/tunnel", HashMap::new(), "space in host", "invalid Host value").await;
        assert_rejected_before_writing("example.org", "/tunnel", {
            let mut h = HashMap::new();
            h.insert("Bad:Name".to_string(), "v".to_string());
            h
        }, "colon in header name", "invalid header name")
        .await;
    }

    // ---- response status ----------------------------------------------------

    #[tokio::test]
    async fn test_httpupgrade_client_rejects_non_101_responses() {
        // Anything but a real 101 must be refused: a captive portal, a proxy
        // error page or a websocket endpoint answering 200 is not our tunnel.
        let rejected: &[(&str, &[u8])] = &[
            ("200 OK", b"HTTP/1.1 200 OK\r\n\r\n"),
            ("200 with body", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
            ("1010", b"HTTP/1.1 1010 Not A Status\r\n\r\n"),
            ("500 mentioning 101", b"HTTP/1.1 500 Internal Server Error: 101\r\n\r\n"),
            ("404", b"HTTP/1.1 404 Not Found\r\n\r\n"),
            ("301", b"HTTP/1.1 301 Moved Permanently\r\n\r\n"),
            ("204", b"HTTP/1.1 204 No Content\r\n\r\n"),
            ("101 as a reason phrase", b"HTTP/1.1 400 101 Switching Protocols\r\n\r\n"),
            ("HTTP/1.0 101", b"HTTP/1.0 101 Switching Protocols\r\n\r\n"),
            ("HTTP/2 101", b"HTTP/2 101 Switching Protocols\r\n\r\n"),
            ("ICY 101", b"ICY 101 Switching Protocols\r\n\r\n"),
            ("empty status line", b"\r\n\r\n"),
            ("garbage", b"SMTP ready\r\n\r\n"),
            ("header without colon", b"HTTP/1.1 101 Switching Protocols\r\nBadHeaderLine\r\n\r\n"),
        ];
        for (what, response) in rejected {
            let (res, _) = client_against(&[response]).await;
            assert_protocol_error(res, what);
        }
    }

    #[tokio::test]
    async fn test_httpupgrade_client_accepts_101() {
        // The canonical response, and a bare 101 with no headers: RFC 7230 says
        // a 101 must carry `Upgrade`, but real CDNs and older sing-box releases
        // have shipped a bare one and refusing it breaks interop for no
        // camouflage gain (we do not parse the response headers for identity).
        for (what, response) in [
            ("canonical", GOOD_RESPONSE),
            ("bare 101", &b"HTTP/1.1 101 Switching Protocols\r\n\r\n"[..]),
            ("status only", &b"HTTP/1.1 101\r\n\r\n"[..]),
            ("extra headers", &b"HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\n\
                Date: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: Upgrade\r\n\
                Upgrade: websocket\r\nX-Extra: 1\r\n\r\n"[..]),
        ] {
            let (res, _) = client_against(&[response]).await;
            assert!(res.is_ok(), "{what}: a valid 101 must be accepted");
        }
    }

    #[tokio::test]
    async fn test_httpupgrade_client_eof_before_response() {
        let (res, _) = client_against(&[]).await;
        assert_protocol_error(res, "server closed before the response");
    }

    // ---- piggybacked data must not be lost ---------------------------------

    #[tokio::test]
    async fn test_httpupgrade_client_preserves_piggybacked_data() {
        // A server that answers and immediately starts streaming in the same
        // write must lose nothing: the excess bytes belong to the tunnel.
        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = server_io.read(&mut buf).await;
            let mut flight = GOOD_RESPONSE.to_vec();
            flight.extend_from_slice(b"early-bytes");
            server_io.write_all(&flight).await.unwrap();
            server_io.flush().await.unwrap();
            server_io
        });
        let mut stream = client_handshake(client_io, "example.org", "/tunnel", &HashMap::new())
            .await
            .unwrap();
        drop(srv.await.unwrap()); // close the server side so the read can finish
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"early-bytes", "bytes after the 101 must be preserved");
    }

    #[tokio::test]
    async fn test_httpupgrade_server_preserves_piggybacked_data() {
        // Same on the server: a client that pipelines payload right behind its
        // request must not have that payload swallowed by the header reader.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut request = GOOD_REQUEST.to_vec();
        request.extend_from_slice(b"pipelined");
        let mut client_io = client_io;
        client_io.write_all(&request).await.unwrap();
        client_io.flush().await.unwrap();
        let mut stream = server_handshake(server_io, Some("/tunnel")).await.unwrap();
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pipelined", "bytes after the request must be preserved");
    }

    // ---- server-side request validation ------------------------------------

    #[tokio::test]
    async fn test_httpupgrade_server_rejects_hostile_requests() {
        let cases: &[(&str, &[u8], &str)] = &[
            ("POST", b"POST /tunnel HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "expected GET"),
            ("no version", b"GET /tunnel\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "malformed request line"),
            ("trailing junk", b"GET /tunnel HTTP/1.1 junk\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "trailing tokens"),
            ("http/2 preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "expected GET"),
            ("missing Upgrade", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\n\r\n", "missing 'Upgrade: websocket'"),
            ("wrong Upgrade", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n", "unexpected Upgrade value"),
            ("missing Connection", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n", "missing 'Connection: Upgrade'"),
            ("wrong Connection", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n", "missing 'Connection: Upgrade'"),
            ("conflicting Upgrade", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: h2c\r\n\r\n", "unexpected Upgrade value"),
            ("conflicting Upgrade reversed", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nUpgrade: websocket\r\n\r\n", "unexpected Upgrade value"),
            ("header without colon", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nBroken header\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "no colon"),
            ("no blank line", b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n", "EOF while reading"),
            ("empty", b"", "EOF while reading"),
            ("blank lines only", b"\r\n\r\n", "expected GET"),
            ("path mismatch", b"GET /other HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "path mismatch"),
        ];
        for (what, request, expect) in cases {
            assert_server_rejects(request, Some("/tunnel"), what, expect).await;
        }

        // An absurdly long header line must be refused, not buffered forever.
        let mut huge = b"GET /tunnel HTTP/1.1\r\nX-Pad: ".to_vec();
        huge.extend(std::iter::repeat_n(b'a', 16 * 1024));
        huge.extend_from_slice(b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        assert_server_rejects(&huge, None, "16 KiB header line", "missing terminal CRLF")
            .await;
    }

    #[tokio::test]
    async fn test_httpupgrade_server_accepts_valid_variants() {
        let cases: &[(&str, &[u8], Option<&str>)] = &[
            ("canonical", GOOD_REQUEST, Some("/tunnel")),
            ("no expected path", GOOD_REQUEST, None),
            (
                "uppercase header names",
                b"GET /tunnel HTTP/1.1\r\nHOST: h\r\nCONNECTION: Upgrade\r\nUPGRADE: WebSocket\r\n\r\n",
                Some("/tunnel"),
            ),
            (
                "connection token list",
                b"GET /tunnel HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
                Some("/tunnel"),
            ),
            (
                "reversed header order",
                b"GET /tunnel HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: h\r\n\r\n",
                Some("/tunnel"),
            ),
            (
                "query string",
                b"GET /tunnel?ed=2048 HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                Some("/tunnel"),
            ),
            (
                "extra whitespace",
                b"GET  /tunnel  HTTP/1.1\r\nHost:   h   \r\nConnection: Upgrade\r\nUpgrade:   websocket  \r\n\r\n",
                Some("/tunnel"),
            ),
            (
                "extra unknown headers",
                b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0\r\n\
                  Connection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n",
                Some("/tunnel"),
            ),
        ];
        for (what, request, expected) in cases {
            let (res, response) = server_against(request, *expected).await;
            assert!(res.is_ok(), "{what}: a valid upgrade request must be accepted");
            assert_eq!(
                response, GOOD_RESPONSE,
                "{what}: the server response must be the canonical 101"
            );
        }
    }

    #[tokio::test]
    async fn test_httpupgrade_server_response_shape() {
        let (res, response) = server_against(GOOD_REQUEST, Some("/tunnel")).await;
        res.unwrap();
        // Byte-exact: casing, order and the absence of a body all matter.
        assert_eq!(response, GOOD_RESPONSE);
        let text = String::from_utf8(response).unwrap();
        assert_eq!(
            text.lines().filter(|l| !l.is_empty()).count(),
            3,
            "status line plus exactly two headers"
        );
        assert!(
            !text.replace("\r\n", "").contains('\n'),
            "a bare LF is a fingerprint"
        );
    }

    // ---- bounded reads ------------------------------------------------------

    /// Never returns EOF and never produces a header terminator: models a peer
    /// that tries to make the handshake buffer unlimited data.
    struct EndlessReader {
        reads: Arc<AtomicUsize>,
    }

    impl AsyncRead for EndlessReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf.remaining().min(512);
            let filler = [b'A'; 512];
            buf.put_slice(&filler[..n]);
            self.reads.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for EndlessReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_httpupgrade_header_block_is_bounded() {
        const MAX_READS: usize = 20; // 8192-byte cap at <=512 bytes per read

        let reads = Arc::new(AtomicUsize::new(0));
        let res = client_handshake(
            EndlessReader { reads: reads.clone() },
            "example.org",
            "/tunnel",
            &HashMap::new(),
        )
        .await;
        assert_protocol_error(res, "endless response headers");
        assert!(
            reads.load(Ordering::SeqCst) <= MAX_READS,
            "client performed {} reads before giving up",
            reads.load(Ordering::SeqCst)
        );

        let reads = Arc::new(AtomicUsize::new(0));
        let res = server_handshake(EndlessReader { reads: reads.clone() }, None).await;
        assert_protocol_error(res, "endless request headers");
        assert!(
            reads.load(Ordering::SeqCst) <= MAX_READS,
            "server performed {} reads before giving up",
            reads.load(Ordering::SeqCst)
        );
    }

    // ---- throughput sanity --------------------------------------------------

    #[tokio::test]
    async fn test_httpupgrade_full_duplex_large_payload() {
        const LEN: usize = 256 * 1024;
        let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_payload = payload.clone();

        let srv = tokio::spawn(async move {
            let mut stream = server_handshake(server_io, Some("/bulk")).await.unwrap();
            let mut got = vec![0u8; LEN];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, server_payload, "server must receive every byte");
            stream.write_all(&server_payload).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut stream = client_handshake(client_io, "example.org", "/bulk", &HashMap::new())
            .await
            .unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echo = vec![0u8; LEN];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, payload, "client must receive every byte back");
        srv.await.unwrap();
    }
}
