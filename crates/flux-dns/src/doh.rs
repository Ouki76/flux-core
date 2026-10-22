use crate::dot::split_host_port;
use crate::wire::{Answer, DnsMessage, Name, QTYPE_A, QueryError};
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{BoxedStream, FluxError, FluxResult};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

const DOH_POOL_SIZE: usize = 4;

/// Hard cap on an HTTP response body, chunked or close-delimited.
///
/// A DNS message never needs more than 64 KiB, so a body larger than this is
/// either broken or hostile; it must not be buffered.
const MAX_DOH_BODY: usize = 65536;

/// Deadline for each DoH network step (connect, request/response).
///
/// Without it a black-holed or MITM-stalled upstream holds the pool slot's
/// mutex forever, and every later lookup to that server queues behind it —
/// which in turn starves `dial_outbound` and leaks connection tasks.
const DOH_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Decodes as much of a chunked body as `input` holds.
///
/// `Ok(Some(body))` means the terminating zero-length chunk was reached and
/// `body` is complete. `Ok(None)` means the buffer ends mid-chunk and the caller
/// should read more — which is what makes this usable on a **keep-alive**
/// connection, where waiting for EOF (or for a `Content-Length` that a chunked
/// response does not have) would hang until the read deadline. `Err` is a
/// framing error.
fn decode_chunked_partial(input: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut rest = input;
    let mut out = Vec::with_capacity(input.len());
    loop {
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else {
            // No complete chunk-size line yet.
            return Ok(None);
        };
        let size_str = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| "non-UTF-8 chunk size")?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let size = usize::from_str_radix(&size_str, 16)
            .map_err(|_| format!("invalid chunk size '{size_str}'"))?;
        let after = &rest[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        // The chunk must be followed by its CRLF before the next size line.
        if after.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&after[..size]);
        let tail = &after[size..];
        if !tail.starts_with(b"\r\n") {
            return Err("chunk not terminated by CRLF".into());
        }
        rest = &tail[2..];
    }
}

/// The DNS message id a DoH request carries (RFC 8484 §4.1: SHOULD be 0).
const DOH_MESSAGE_ID: u16 = 0;

/// Why an HTTP exchange did not produce a DNS body.
enum DoHFailure {
    /// The connection broke: a fresh one may work.
    Io(std::io::Error),
    /// The peer answered, but not with an `application/dns-message` body.
    Fatal(String),
}

impl From<std::io::Error> for DoHFailure {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// One HTTP/1.1 POST on an already-connected stream, returning the DNS body.
///
/// Split out of [`DohClient::query_doh`] so the framing — status line,
/// `Content-Type`, `Content-Length`, chunked bodies — can be driven over any
/// stream in the tests, with no TLS and no socket in the way.
async fn exchange_http_on<S>(
    stream: &mut S,
    head: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, DoHFailure>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(head).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    // Headers, up to the blank line.
    let mut header_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 256];
    let mut header_end = None;
    while header_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(DoHFailure::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF reading DoH header",
            )));
        }
        header_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }
    let h_end =
        header_end.ok_or_else(|| DoHFailure::Fatal("DoH response headers exceed 8 KiB".into()))?;
    let header_str = String::from_utf8_lossy(&header_buf[..h_end]);

    // A captive portal or an error page returns a 200-less body that must not
    // be parsed as DNS.
    let status: u16 = header_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| DoHFailure::Fatal("malformed DoH status line".into()))?;
    if status != 200 {
        return Err(DoHFailure::Fatal(format!(
            "DoH server returned HTTP {status}"
        )));
    }

    let mut content_type: Option<String> = None;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in header_str.lines().skip(1) {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-type") {
            content_type = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("content-length") {
            // Present but unparseable is not the same as absent: treating it as
            // absent would take the close-delimited path on a keep-alive
            // connection, which never ends.
            content_length = Some(
                v.parse()
                    .map_err(|_| DoHFailure::Fatal(format!("invalid DoH Content-Length '{v}'")))?,
            );
        } else if k.eq_ignore_ascii_case("transfer-encoding")
            && v.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    // RFC 8484 §4.1: the body is `application/dns-message`. Anything else —
    // typically a captive portal's HTML page served with a 200 — must not reach
    // the DNS parser, which would only report a confusing "unparseable response".
    let Some(media_type) = content_type
        .as_deref()
        .map(|v| v.split(';').next().unwrap_or_default().trim())
    else {
        return Err(DoHFailure::Fatal(
            "DoH response carries no Content-Type".into(),
        ));
    };
    if !media_type.eq_ignore_ascii_case("application/dns-message") {
        return Err(DoHFailure::Fatal(format!(
            "DoH response Content-Type is '{media_type}', expected 'application/dns-message'"
        )));
    }

    if content_length.is_some_and(|l| l > MAX_DOH_BODY) {
        return Err(DoHFailure::Fatal(
            "response body too large for a DNS message".into(),
        ));
    }

    let mut body = header_buf[h_end..].to_vec();
    if chunked {
        // `Transfer-Encoding: chunked` is self-delimiting: decode as the bytes
        // arrive and stop at the terminating chunk. Reading to EOF instead (as
        // a close-delimited body does) can never complete on the keep-alive
        // connection this client asks for.
        loop {
            match decode_chunked_partial(&body)
                .map_err(|m| DoHFailure::Fatal(format!("malformed chunked body: {m}")))?
            {
                Some(decoded) => {
                    body = decoded;
                    break;
                }
                None => {
                    if body.len() > MAX_DOH_BODY {
                        return Err(DoHFailure::Fatal("response body too large".into()));
                    }
                    let n = stream.read(&mut chunk).await?;
                    if n == 0 {
                        return Err(DoHFailure::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF before the final chunk",
                        )));
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
            }
        }
    } else {
        match content_length {
            Some(expected) => {
                // The body must be exactly as long as promised: a short body is
                // an error (EOF above), not a shorter message.
                while body.len() < expected {
                    let needed = expected - body.len();
                    let to_read = needed.min(chunk.len());
                    let n = stream.read(&mut chunk[..to_read]).await?;
                    if n == 0 {
                        return Err(DoHFailure::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF reading DoH body",
                        )));
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                // Anything beyond Content-Length belongs to the next response
                // on this keep-alive connection.
                body.truncate(expected);
            }
            None => loop {
                // No Content-Length (close-delimited): read to EOF with a hard
                // cap instead of assuming an empty body.
                if body.len() > MAX_DOH_BODY {
                    return Err(DoHFailure::Fatal("response body too large".into()));
                }
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            },
        }
    }

    Ok(body)
}

#[derive(Clone)]
pub struct DohClient {
    pub server_ip: String,
    pub server_port: u16,
    pub host_header: String,
    pub path: String,
    pub is_tls: bool,
    streams: Arc<[Mutex<Option<BoxedStream>>]>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for DohClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohClient")
            .field("server_ip", &self.server_ip)
            .field("server_port", &self.server_port)
            .field("host_header", &self.host_header)
            .field("path", &self.path)
            .field("is_tls", &self.is_tls)
            .finish()
    }
}

impl DohClient {
    pub fn new(url: &str) -> Self {
        let is_tls = !url.starts_with("http://");
        let clean = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let (host_port, path) = clean.split_once('/').unwrap_or((clean, "dns-query"));

        let default_port = if is_tls { 443 } else { 80 };
        let (host, port) = split_host_port(host_port, default_port);

        let streams: Vec<Mutex<Option<BoxedStream>>> =
            (0..DOH_POOL_SIZE).map(|_| Mutex::new(None)).collect();

        Self {
            server_ip: host.clone(),
            server_port: port,
            host_header: host,
            path: format!("/{}", path),
            is_tls,
            streams: streams.into(),
            counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    async fn connect_stream(&self) -> FluxResult<BoxedStream> {
        let connect_addr: SocketAddr = if let Ok(ip) = self.server_ip.parse() {
            SocketAddr::new(ip, self.server_port)
        } else {
            let addr_str = format!("{}:{}", self.server_ip, self.server_port);
            let mut addrs = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(FluxError::Io)?;
            addrs.next().ok_or_else(|| {
                FluxError::Dns(format!(
                    "failed to resolve DoH server host '{}'",
                    self.server_ip
                ))
            })?
        };

        let tcp_stream = TcpTransport::connect(connect_addr, Duration::from_secs(4)).await?;

        if self.is_tls {
            let tls_cfg =
                TlsClientConfig::new(&self.host_header).with_alpn(vec!["http/1.1".into()]);
            TlsTransport::connect(tcp_stream, &tls_cfg).await
        } else {
            Ok(Box::new(tcp_stream))
        }
    }

    /// Connects to the DoH server with connection reuse and queries `name` for
    /// `qtype`.
    ///
    /// Returns the parsed [`Answer`] rather than an address so the caller can
    /// follow a CNAME returned without its target record and can tell a clean
    /// NODATA from a transport failure (which decides negative caching).
    pub async fn query_doh(&self, name: &Name, qtype: u16) -> Result<Answer, QueryError> {
        // RFC 8484 §4.1: the ID of a DoH query SHOULD be 0. There is no
        // transaction-id matching on this transport — HTTP/1.1 on a dedicated
        // connection pairs the request with its response — and a zero id keeps
        // the request cache-friendly instead of looking unique per query.
        let query_wire = DnsMessage::build_query_for_name(name, qtype, None, DOH_MESSAGE_ID);

        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path,
            self.host_header,
            query_wire.len()
        );

        let idx = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % DOH_POOL_SIZE;
        let mut guard = self.streams[idx].lock().await;
        let mut last_error: Option<QueryError> = None;

        for _attempt in 0..2 {
            if guard.is_none() {
                // A stalled/hostile upstream must not hold this pool slot (and
                // its mutex) forever: every network step is deadline-bounded.
                match tokio::time::timeout(DOH_IO_TIMEOUT, self.connect_stream()).await {
                    Ok(Ok(s)) => *guard = Some(s),
                    Ok(Err(e)) => {
                        last_error = Some(QueryError::Transport(e));
                        continue;
                    }
                    Err(_) => {
                        last_error = Some(QueryError::Transport(FluxError::Timeout(format!(
                            "DoH connect to {} timed out",
                            self.server_ip
                        ))));
                        continue;
                    }
                }
            }

            let exchange = {
                let Some(stream) = guard.as_mut() else {
                    continue;
                };
                tokio::time::timeout(
                    DOH_IO_TIMEOUT,
                    exchange_http_on(&mut **stream, req.as_bytes(), &query_wire),
                )
                .await
            };

            match exchange {
                // The connection itself is still healthy, so it stays pooled
                // even when the body turns out to be unparseable as DNS.
                Ok(Ok(body)) => return DnsMessage::parse_response(&body, name, qtype),
                Ok(Err(DoHFailure::Fatal(reason))) => {
                    // The peer answered, but not with a DoH answer (captive
                    // portal, HTML error page, mismatched length). Retrying an
                    // identical request cannot help, so report it as-is.
                    *guard = None;
                    return Err(QueryError::Transport(FluxError::Dns(reason)));
                }
                Ok(Err(DoHFailure::Io(e))) => {
                    *guard = None;
                    last_error = Some(QueryError::Transport(FluxError::Io(e)));
                    continue;
                }
                Err(_) => {
                    *guard = None;
                    last_error = Some(QueryError::Transport(FluxError::Timeout(format!(
                        "DoH query to {} timed out",
                        self.server_ip
                    ))));
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            QueryError::Transport(FluxError::Dns(format!(
                "DoH query to {} failed after reconnect",
                self.server_ip
            )))
        }))
    }

    /// Queries the DoH server and returns IPv4.
    pub async fn resolve_ipv4(&self, domain: &str) -> FluxResult<Ipv4Addr> {
        let name = Name::from_str(domain).map_err(|e| FluxError::Dns(e.to_string()))?;
        match self
            .query_doh(&name, QTYPE_A)
            .await
            .map_err(QueryError::into_flux)?
        {
            Answer::Address {
                ip: IpAddr::V4(v4), ..
            } => Ok(v4),
            Answer::Address { .. } => Err(FluxError::Dns(
                "expected IPv4 address from DoH, got IPv6".into(),
            )),
            other => Err(FluxError::Dns(format!(
                "DoH returned no A record for {domain}: {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_doh_client_pool_init() {
        let doh = DohClient::new("https://1.1.1.1/dns-query");
        assert_eq!(doh.streams.len(), DOH_POOL_SIZE);
        assert_eq!(doh.server_ip, "1.1.1.1");
        assert_eq!(doh.server_port, 443);
        assert_eq!(doh.path, "/dns-query");
        assert!(doh.is_tls);
        assert_eq!(doh.counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_doh_client_rotation_and_mock_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    if let Ok(n) = sock.read(&mut buf).await
                        && n > 0
                    {
                        // Synthesize valid DNS A response (1.2.3.4)
                        let dns_resp = vec![
                            0x12, 0x34, // ID
                            0x81, 0x80, // Response, NoError
                            0x00, 0x01, // QDCOUNT = 1
                            0x00, 0x01, // ANCOUNT = 1
                            0x00, 0x00, 0x00, 0x00, // QNAME: example.com
                            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
                            0x00, 0x00, 0x01, 0x00, 0x01, // Type A, Class IN
                            // ANSWER: Name pointer to QNAME (0xc00c)
                            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, // Type A, Class IN
                            0x00, 0x00, 0x01, 0x2c, // TTL 300
                            0x00, 0x04, // RDLENGTH 4
                            0x01, 0x02, 0x03, 0x04, // 1.2.3.4
                        ];
                        let http_resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            dns_resp.len()
                        );
                        let _ = sock.write_all(http_resp.as_bytes()).await;
                        let _ = sock.write_all(&dns_resp).await;
                        let _ = sock.flush().await;
                    }
                });
            }
        });

        let url = format!("http://{}/dns-query", srv_addr);
        let doh = DohClient::new(&url);

        // Perform multiple parallel queries and verify round-robin rotation
        let name = Name::from_str("example.com").unwrap();
        let ans1 = doh.query_doh(&name, QTYPE_A).await.unwrap();
        assert_eq!(
            ans1,
            Answer::Address {
                ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                ttl: 300,
            }
        );

        let ans2 = doh.query_doh(&name, QTYPE_A).await.unwrap();
        assert_eq!(ans2, ans1);

        assert!(doh.counter.load(Ordering::Relaxed) >= 2);
    }
}

#[cfg(test)]
mod body_decoding_tests {
    use super::decode_chunked_partial;

    /// Convenience for the tests: the complete body, or the reason it never
    /// completes.
    fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
        decode_chunked_partial(input)?.ok_or_else(|| "truncated chunked body".to_string())
    }

    #[test]
    fn decodes_chunked_bodies() {
        let body = b"4\r\ntest\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"test");
    }

    #[test]
    fn decodes_multiple_chunks_with_extensions() {
        let body = b"3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"abcde");
    }

    #[test]
    fn rejects_truncated_and_malformed() {
        assert!(decode_chunked(b"5\r\nab").is_err());
        assert!(decode_chunked(b"zz\r\nx\r\n").is_err());
        assert!(decode_chunked(b"no-crlf").is_err());
        // A chunk that is not followed by CRLF is framing corruption, not a
        // "need more data" case: it must not be retried forever.
        assert!(decode_chunked(b"3\r\nabcXX").is_err());
    }

    /// The incremental contract: a prefix reports `None` (more data needed)
    /// instead of an error, and decoding the whole buffer reports the body. This
    /// is what lets a keep-alive chunked response complete without EOF.
    #[test]
    fn incomplete_prefixes_ask_for_more_data() {
        let full = b"5\r\nhello\r\n0\r\n\r\n";
        // Everything before the terminating chunk-size line is incomplete. (The
        // zero-length chunk line is enough to finish the body; any trailer after
        // it belongs to the next message and is ignored.)
        for cut in 0..13 {
            assert_eq!(
                decode_chunked_partial(&full[..cut]),
                Ok(None),
                "prefix of {cut} bytes must ask for more data"
            );
        }
        assert_eq!(
            decode_chunked_partial(full).unwrap(),
            Some(b"hello".to_vec())
        );
        // Trailing bytes after the terminator are ignored (the body is complete).
        let mut with_trailer = full.to_vec();
        with_trailer.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(
            decode_chunked_partial(&with_trailer).unwrap(),
            Some(b"hello".to_vec())
        );
    }
}

/// Tests for the HTTP framing of the DoH client.
///
/// The fake servers are plain TCP on loopback, which is why the client's
/// `http://` form exists: no TLS is needed to prove the framing, and the TLS
/// handshake itself is covered by the DoT/DoQ tests and by
/// `TlsTransport`'s own suite.
#[cfg(test)]
mod framing_tests {
    use super::*;
    use crate::dot::test_support::{expected_address, response_for};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::{TcpListener, TcpStream};

    /// Reads one complete HTTP request (head + `Content-Length` body).
    async fn read_request(sock: &mut TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                let len = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < pos + 4 + len {
                    let n = sock.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                return Some(buf);
            }
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// The DNS message in a request (everything after the blank line).
    fn request_body(req: &[u8]) -> &[u8] {
        let pos = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        &req[pos + 4..]
    }

    /// A DNS answer to `req`'s query, echoing its id.
    fn answer_for(req: &[u8], answers: usize) -> Vec<u8> {
        response_for(request_body(req), None, answers)
    }

    /// `200 OK` with the given raw body and content type.
    fn http_response(status: u16, content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status} X\r\n").into_bytes();
        if let Some(ct) = content_type {
            out.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A DNS answer as a well-formed DoH response.
    fn doh_answer(req: &[u8], answers: usize) -> Vec<u8> {
        http_response(
            200,
            Some("application/dns-message"),
            &answer_for(req, answers),
        )
    }

    struct FakeDohServer {
        addr: SocketAddr,
        accepts: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl FakeDohServer {
        fn client(&self) -> DohClient {
            DohClient::new(&format!("http://{}/dns-query", self.addr))
        }

        fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }

        fn last_request(&self) -> Vec<u8> {
            self.requests.lock().unwrap().last().cloned().unwrap()
        }
    }

    /// Spawns a mock DoH server. `close_after_response` models a peer that does
    /// not honour `Connection: keep-alive`.
    async fn spawn_doh_server<F>(handler: F, close_after_response: bool) -> FakeDohServer
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + Clone + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let counter = accepts.clone();
        let seen = requests.clone();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let handler = handler.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    while let Some(req) = read_request(&mut sock).await {
                        seen.lock().unwrap().push(req.clone());
                        let resp = handler(&req);
                        if !resp.is_empty() && sock.write_all(&resp).await.is_err() {
                            return;
                        }
                        let _ = sock.flush().await;
                        if close_after_response {
                            return;
                        }
                    }
                });
            }
        });

        FakeDohServer {
            addr,
            accepts,
            requests,
        }
    }

    async fn ask(client: &DohClient) -> Result<Answer, QueryError> {
        let name = Name::from_str("example.com").unwrap();
        client.query_doh(&name, QTYPE_A).await
    }

    // -- request shape ----------------------------------------------------

    /// RFC 8484 §4.1: POST, `application/dns-message` in and out, and a message
    /// id of 0 in the request body.
    #[tokio::test]
    async fn posts_an_rfc8484_request_with_a_zero_id() {
        let srv = spawn_doh_server(|req| doh_answer(req, 1), false).await;
        let client = srv.client();

        let answer = ask(&client)
            .await
            .expect("a conforming server must be answered");
        assert_eq!(answer, expected_address());

        let req = srv.last_request();
        let head =
            String::from_utf8_lossy(&req[..req.len() - request_body(&req).len()]).to_string();
        assert!(
            head.starts_with("POST /dns-query HTTP/1.1\r\n"),
            "head: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/dns-message"),
            "head: {head}"
        );

        let body = request_body(&req);
        assert_eq!(
            u16::from_be_bytes([body[0], body[1]]),
            0,
            "RFC 8484 §4.1: the DoH query id SHOULD be 0"
        );
        let announced = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .expect("the request must carry a Content-Length");
        assert_eq!(announced, body.len(), "Content-Length must match the body");
    }

    // -- response validation ----------------------------------------------

    /// A 200 with the wrong media type is not a DoH answer: a captive portal's
    /// HTML page must never be handed to the DNS parser.
    #[tokio::test]
    async fn rejects_a_response_with_the_wrong_content_type() {
        let srv = spawn_doh_server(
            |_| {
                http_response(
                    200,
                    Some("text/html"),
                    b"<html><body>login required</body></html>",
                )
            },
            false,
        )
        .await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a wrong content type must fail fast")
            .expect_err("an HTML page is not a DNS answer");
        assert!(
            err.to_string().contains("Content-Type"),
            "unexpected error: {err}"
        );
        assert_eq!(srv.request_count(), 1, "this is not worth a retry");
    }

    /// A response with no `Content-Type` at all is equally unusable.
    #[tokio::test]
    async fn rejects_a_response_without_a_content_type() {
        let srv =
            spawn_doh_server(|req| http_response(200, None, &answer_for(req, 1)), false).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a missing content type must fail fast")
            .expect_err("a body of unknown type is not a DNS answer");
        assert!(
            err.to_string().contains("Content-Type"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_a_non_200_status() {
        let srv =
            spawn_doh_server(|_| http_response(503, Some("text/plain"), b"busy"), false).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a 503 must fail fast")
            .expect_err("HTTP 503 is not an answer");
        assert!(err.to_string().contains("503"), "unexpected error: {err}");
    }

    /// A `Content-Length` that lies (body cut short) is a transport failure, and
    /// the truncated body is never parsed as a message.
    #[tokio::test]
    async fn rejects_a_body_shorter_than_content_length() {
        let srv = spawn_doh_server(
            |req| {
                let mut resp = Vec::new();
                resp.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 400\r\n\r\n",
                );
                let body = answer_for(req, 1);
                resp.extend_from_slice(&body[..body.len() / 2]);
                resp
            },
            true,
        )
        .await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a short body must not hang")
            .expect_err("a body shorter than Content-Length must be rejected");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
    }

    /// `Content-Length: nope` must not be treated as "no Content-Length": on a
    /// keep-alive connection that would wait for EOF forever.
    #[tokio::test]
    async fn rejects_an_unparseable_content_length() {
        let srv = spawn_doh_server(
            |_| b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: nope\r\n\r\n".to_vec(),
            false,
        )
        .await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("an unparseable length must fail fast")
            .expect_err("an unusable Content-Length is an error");
        assert!(
            err.to_string().contains("Content-Length"),
            "unexpected error: {err}"
        );
    }

    /// The DNS id in a DoH response is *not* used for correlation — HTTP/1.1 on
    /// a dedicated connection pairs the response with the request — so a server
    /// that answers with a different id is still usable. This is deliberate:
    /// the DoT/DoQ clients reject a mismatched id because a length-prefixed
    /// stream has no other correlation mechanism.
    #[tokio::test]
    async fn accepts_a_response_whose_dns_id_is_not_echoed() {
        let srv = spawn_doh_server(
            |req| {
                let mut body = answer_for(req, 1);
                body[0] = 0x12;
                body[1] = 0x34;
                http_response(200, Some("application/dns-message"), &body)
            },
            false,
        )
        .await;
        let client = srv.client();

        let answer = ask(&client)
            .await
            .expect("HTTP framing, not the DNS id, correlates a DoH response");
        assert_eq!(answer, expected_address());
    }

    /// A 5000-byte answer is a normal DNS message (the 64 KiB ceiling applies).
    #[tokio::test]
    async fn accepts_a_response_larger_than_4_kib() {
        let srv = spawn_doh_server(|req| doh_answer(req, 300), false).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a 4.8 KiB body must not stall")
            .expect("a 4.8 KiB DoH answer must be accepted");
        assert_eq!(answer, expected_address());
    }

    // -- chunked ----------------------------------------------------------

    #[tokio::test]
    async fn completes_a_chunked_response() {
        let srv = spawn_doh_server(
            |req| {
                let body = answer_for(req, 1);
                let mut resp = Vec::new();
                resp.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n");
                for part in body.chunks(16) {
                    resp.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    resp.extend_from_slice(part);
                    resp.extend_from_slice(b"\r\n");
                }
                resp.extend_from_slice(b"0\r\n\r\n");
                resp
            },
            false,
        )
        .await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a chunked body must not wait for EOF")
            .expect("a chunked body must be decoded");
        assert_eq!(answer, expected_address());
    }

    /// A chunked body that never reaches its terminating chunk is an error, not
    /// an endless wait.
    #[tokio::test]
    async fn rejects_a_chunked_body_that_never_terminates() {
        let srv = spawn_doh_server(
            |_| {
                b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello".to_vec()
            },
            true,
        )
        .await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a truncated chunked body must not hang")
            .expect_err("an unfinished chunked body must be rejected");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
    }

    /// A body with no `Content-Length` and not chunked is close-delimited: the
    /// client must read it to EOF instead of assuming an empty body.
    #[tokio::test]
    async fn completes_a_close_delimited_body() {
        let srv = spawn_doh_server(
            |req| {
                let mut resp = Vec::new();
                resp.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n",
                );
                resp.extend_from_slice(&answer_for(req, 1));
                resp
            },
            true,
        )
        .await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a close-delimited body must not hang")
            .expect("a close-delimited body must be read to EOF");
        assert_eq!(answer, expected_address());
    }

    // -- reuse, pooling, timeouts -----------------------------------------

    /// `Connection: keep-alive` is honoured: the next query on the same pool
    /// slot reuses the socket. (The pool rotates over four slots, so the counter
    /// is reset to land on slot 0 again.)
    #[tokio::test]
    async fn reuses_a_keepalive_connection() {
        let srv = spawn_doh_server(|req| doh_answer(req, 1), false).await;
        let client = srv.client();

        ask(&client).await.unwrap();
        client.counter.store(DOH_POOL_SIZE, Ordering::Relaxed);
        ask(&client).await.unwrap();

        assert_eq!(srv.accepts(), 1, "the kept-alive connection must be reused");
    }

    /// A pooled connection the peer closed must be replaced, not reused.
    #[tokio::test]
    async fn reconnects_when_the_pooled_connection_was_closed() {
        let srv = spawn_doh_server(|req| doh_answer(req, 1), true).await;
        let client = srv.client();

        ask(&client).await.expect("first query must succeed");
        client.counter.store(DOH_POOL_SIZE, Ordering::Relaxed);

        let second = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("the second query must not hang")
            .expect("a closed pooled connection must be replaced");
        assert_eq!(second, expected_address());
        assert_eq!(srv.accepts(), 2, "the client must have reconnected");
    }

    /// A server that reads the request and never answers must time out.
    #[tokio::test]
    async fn times_out_on_a_silent_server() {
        let srv = spawn_doh_server(|_| Vec::new(), false).await;
        let client = srv.client();

        let started = std::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(30), ask(&client))
            .await
            .expect("a silent server must not hang the resolver")
            .expect_err("a silent server is a timeout, not an answer");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "took {:?}",
            started.elapsed()
        );
    }

    /// `resolve_ipv4` is the thin wrapper the resolver path uses.
    #[tokio::test]
    async fn resolve_ipv4_returns_the_a_record() {
        let srv = spawn_doh_server(|req| doh_answer(req, 1), false).await;
        let client = srv.client();

        let ip = client.resolve_ipv4("example.com").await.unwrap();
        assert_eq!(ip, std::net::Ipv4Addr::new(10, 0, 0, 0));
    }

    // -- configuration ----------------------------------------------------

    #[test]
    fn parses_url_forms_including_ipv6() {
        let plain = DohClient::new("https://dns.google/dns-query");
        assert_eq!(plain.server_ip, "dns.google");
        assert_eq!(plain.server_port, 443);
        assert_eq!(plain.path, "/dns-query");
        assert!(plain.is_tls);

        let no_path = DohClient::new("https://dns.google");
        assert_eq!(no_path.path, "/dns-query");

        let v6 = DohClient::new("https://[2606:4700:4700::1111]/dns-query");
        assert_eq!(v6.server_ip, "2606:4700:4700::1111");
        assert_eq!(v6.server_port, 443);

        let v6_port = DohClient::new("https://[2606:4700:4700::1111]:8443/dns-query");
        assert_eq!(v6_port.server_ip, "2606:4700:4700::1111");
        assert_eq!(v6_port.server_port, 8443);

        assert!(format!("{plain:?}").contains("DohClient"));

        let plain_http = DohClient::new("http://127.0.0.1:8080/dns-query");
        assert_eq!(plain_http.server_port, 8080);
        assert!(!plain_http.is_tls);
    }

    /// A real resolver, when the network is there. Ignored by default.
    #[tokio::test]
    #[ignore = "needs the public internet"]
    async fn queries_a_real_doh_resolver() {
        if let Err(e) = TcpStream::connect("1.1.1.1:443").await {
            eprintln!("SKIP live DoH test: no route to 1.1.1.1:443 ({e})");
            return;
        }
        let client = DohClient::new("https://1.1.1.1/dns-query");
        let name = Name::from_str("example.com").unwrap();
        let answer = client
            .query_doh(&name, QTYPE_A)
            .await
            .expect("a real DoH resolver must answer");
        assert!(matches!(answer, Answer::Address { .. }), "got {answer:?}");
    }
}
