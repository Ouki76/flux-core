use crate::wire::{DnsMessage, QTYPE_A};
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{BoxedStream, FluxError, FluxResult};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const DOH_POOL_SIZE: usize = 4;

/// Deadline for each DoH network step (connect, request/response).
///
/// Without it a black-holed or MITM-stalled upstream holds the pool slot's
/// mutex forever, and every later lookup to that server queues behind it —
/// which in turn starves `dial_outbound` and leaks connection tasks.
const DOH_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Decodes an HTTP/1.1 chunked body.
fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut rest = input;
    let mut out = Vec::with_capacity(input.len());
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated chunk size line")?;
        let size_str = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| "non-UTF-8 chunk size")?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let size = usize::from_str_radix(&size_str, 16)
            .map_err(|_| format!("invalid chunk size '{size_str}'"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            return Err("chunk shorter than declared".into());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
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
        let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
        } else {
            (host_port.to_string(), default_port)
        };

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

    /// Connects to the DoH server with connection reuse and resolves domain name to an IP.
    /// Queries the DoH server for the given record type, returning the first
    /// matching address together with its real TTL from the response.
    pub async fn query_doh(&self, domain: &str, qtype: u16) -> FluxResult<(IpAddr, u32)> {
        let query_wire = DnsMessage::build_query(domain, qtype);

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

        for attempt in 0..2 {
            if guard.is_none() {
                // A stalled/hostile upstream must not hold this pool slot (and
                // its mutex) forever: every network step is deadline-bounded.
                let connect = tokio::time::timeout(DOH_IO_TIMEOUT, self.connect_stream()).await;
                match connect {
                    Err(_) => {
                        if attempt == 1 {
                            return Err(FluxError::Timeout(format!(
                                "DoH connect to {} timed out",
                                self.server_ip
                            )));
                        }
                        continue;
                    }
                    Ok(Err(e)) => {
                        if attempt == 1 {
                            return Err(e);
                        }
                        continue;
                    }
                    Ok(Ok(s)) => *guard = Some(s),
                }
            }
            let Some(s) = guard.as_mut() else {
                continue;
            };

            let query_fut = async {
                s.write_all(req.as_bytes()).await?;
                s.write_all(&query_wire).await?;
                s.flush().await?;

                // Read HTTP response headers until \r\n\r\n
                let mut header_buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 256];
                let mut header_end = None;

                while header_buf.len() < 8192 {
                    let n = s.read(&mut chunk).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF reading DoH header",
                        ));
                    }
                    header_buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        break;
                    }
                }

                let h_end = header_end.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "missing CRLF")
                })?;
                let header_str = String::from_utf8_lossy(&header_buf[..h_end]);

                // Status line: a captive portal or an error page returns 200-less
                // bodies that must not be parsed as DNS.
                let status: u16 = header_str
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "malformed DoH status line",
                        )
                    })?;
                if status != 200 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("DoH server returned HTTP {status}"),
                    ));
                }

                let mut content_length: Option<usize> = None;
                let mut chunked = false;
                for line in header_str.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        let k = k.trim();
                        let v = v.trim();
                        if k.eq_ignore_ascii_case("content-length") {
                            content_length = v.parse().ok();
                        } else if k.eq_ignore_ascii_case("transfer-encoding")
                            && v.to_ascii_lowercase().contains("chunked")
                        {
                            chunked = true;
                        }
                    }
                }

                if content_length.is_some_and(|l| l > 65536) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response body too large",
                    ));
                }

                let mut body = header_buf[h_end..].to_vec();
                match content_length {
                    Some(expected) if !chunked => {
                        while body.len() < expected {
                            let needed = expected - body.len();
                            let to_read = needed.min(chunk.len());
                            let n = s.read(&mut chunk[..to_read]).await?;
                            if n == 0 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "EOF reading DoH body",
                                ));
                            }
                            body.extend_from_slice(&chunk[..n]);
                        }
                        body.truncate(expected);
                    }
                    _ => {
                        // No Content-Length (chunked or close-delimited): read to
                        // EOF with a hard cap instead of assuming an empty body,
                        // which made every such server fail.
                        loop {
                            if body.len() > 65536 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "response body too large",
                                ));
                            }
                            let n = s.read(&mut chunk).await?;
                            if n == 0 {
                                break;
                            }
                            body.extend_from_slice(&chunk[..n]);
                        }
                    }
                }

                let body = if chunked {
                    decode_chunked(&body)
                        .map_err(|m| std::io::Error::new(std::io::ErrorKind::InvalidData, m))?
                } else {
                    body
                };

                Ok(body)
            };

            let query_res = match tokio::time::timeout(DOH_IO_TIMEOUT, query_fut).await {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DoH query timed out",
                )),
            };

            match query_res {
                Ok(body) => {
                    return DnsMessage::parse_specific_record_with_ttl(&body, qtype);
                }
                Err(_) => {
                    *guard = None;
                }
            }
        }

        Err(FluxError::Dns(format!(
            "DoH query to {} failed after reconnect",
            self.server_ip
        )))
    }

    /// Queries the DoH server and returns IPv4.
    pub async fn resolve_ipv4(&self, domain: &str) -> FluxResult<Ipv4Addr> {
        match self.query_doh(domain, QTYPE_A).await?.0 {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(FluxError::Dns(
                "expected IPv4 address from DoH, got IPv6".into(),
            )),
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
        let (ip1, ttl1) = doh.query_doh("example.com", QTYPE_A).await.unwrap();
        assert_eq!(ip1, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(ttl1, 300);

        let (ip2, _) = doh.query_doh("example.com", QTYPE_A).await.unwrap();
        assert_eq!(ip2, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        assert!(doh.counter.load(Ordering::Relaxed) >= 2);
    }
}

#[cfg(test)]
mod body_decoding_tests {
    use super::decode_chunked;

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
    }
}
