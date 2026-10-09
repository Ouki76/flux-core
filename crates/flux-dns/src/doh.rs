use crate::wire::{DnsMessage, QTYPE_A};
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{BoxedStream, FluxError, FluxResult};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct DohClient {
    pub server_ip: String,
    pub server_port: u16,
    pub host_header: String,
    pub path: String,
    pub is_tls: bool,
    stream: Arc<Mutex<Option<BoxedStream>>>,
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

        Self {
            server_ip: host.clone(),
            server_port: port,
            host_header: host,
            path: format!("/{}", path),
            is_tls,
            stream: Arc::new(Mutex::new(None)),
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
    pub async fn query_doh(&self, domain: &str) -> FluxResult<IpAddr> {
        let query_wire = DnsMessage::build_query(domain, QTYPE_A);

        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path,
            self.host_header,
            query_wire.len()
        );

        let mut guard = self.stream.lock().await;

        for attempt in 0..2 {
            if guard.is_none() {
                match self.connect_stream().await {
                    Ok(s) => *guard = Some(s),
                    Err(e) => {
                        if attempt == 1 {
                            return Err(e);
                        }
                        continue;
                    }
                }
            }

            let Some(s) = guard.as_mut() else {
                continue;
            };

            let query_res = async {
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

                let mut content_length = 0usize;
                for line in header_str.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }

                if content_length > 65536 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response body too large",
                    ));
                }

                let mut body = header_buf[h_end..].to_vec();
                while body.len() < content_length {
                    let needed = content_length - body.len();
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

                Ok(body)
            }
            .await;

            match query_res {
                Ok(body) => {
                    return DnsMessage::parse_ip_record(&body);
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
        match self.query_doh(domain).await? {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(FluxError::Dns(
                "expected IPv4 address from DoH, got IPv6".into(),
            )),
        }
    }
}
