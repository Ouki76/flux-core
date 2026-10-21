use crate::wire::{Answer, DnsMessage, Name, QueryError};
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{BoxedStream, FluxError, FluxResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Deadline for each DoT network step (connect, write, read).
const DOT_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct DotClient {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    stream: Arc<Mutex<Option<BoxedStream>>>,
}

impl std::fmt::Debug for DotClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotClient")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("sni", &self.sni)
            .finish()
    }
}

impl DotClient {
    pub fn new(url_or_addr: &str) -> Self {
        let clean = url_or_addr
            .strip_prefix("tls://")
            .or_else(|| url_or_addr.strip_prefix("dot://"))
            .unwrap_or(url_or_addr);

        let (host, port) = if let Some((h, p)) = clean.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(853))
        } else {
            (clean.to_string(), 853)
        };

        Self {
            sni: host.clone(),
            server_host: host,
            server_port: port,
            stream: Arc::new(Mutex::new(None)),
        }
    }

    async fn connect_stream(&self) -> FluxResult<BoxedStream> {
        let connect_addr: SocketAddr = if let Ok(ip) = self.server_host.parse() {
            SocketAddr::new(ip, self.server_port)
        } else {
            let addr_str = format!("{}:{}", self.server_host, self.server_port);
            let mut addrs = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(FluxError::Io)?;
            addrs.next().ok_or_else(|| {
                FluxError::Dns(format!(
                    "failed to resolve DoT server host '{}'",
                    self.server_host
                ))
            })?
        };

        let tcp_stream = TcpTransport::connect(connect_addr, Duration::from_secs(4)).await?;
        let tls_cfg = TlsClientConfig::new(&self.sni).with_alpn(vec!["dot".into()]);
        TlsTransport::connect(tcp_stream, &tls_cfg).await
    }

    /// Queries DNS-over-TLS (RFC 7858) server with connection reuse across queries.
    ///
    /// Returns the parsed [`Answer`] so the caller can follow a CNAME that came
    /// back without its target record and distinguish a clean NODATA from a
    /// transport failure (which decides negative caching).
    pub async fn query_dot(
        &self,
        name: &Name,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<Answer, QueryError> {
        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_for_name(name, qtype, ecs, tx_id);
        let len_bytes = (query.len() as u16).to_be_bytes();

        let mut guard = self.stream.lock().await;

        for attempt in 0..2 {
            if guard.is_none() {
                // Bound connect/query: a stalled upstream must never hold this
                // connection (and its mutex) indefinitely.
                match tokio::time::timeout(DOT_IO_TIMEOUT, self.connect_stream()).await {
                    Ok(Ok(s)) => *guard = Some(s),
                    Ok(Err(e)) => {
                        if attempt == 1 {
                            return Err(QueryError::Transport(e));
                        }
                        continue;
                    }
                    Err(_) => {
                        if attempt == 1 {
                            return Err(QueryError::Transport(FluxError::Timeout(format!(
                                "DoT connect to {} timed out",
                                self.server_host
                            ))));
                        }
                        continue;
                    }
                }
            }

            let Some(s) = guard.as_mut() else {
                continue;
            };
            let write_res = match tokio::time::timeout(DOT_IO_TIMEOUT, async {
                s.write_all(&len_bytes).await?;
                s.write_all(&query).await?;
                s.flush().await
            })
            .await
            {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DoT write timed out",
                )),
            };

            if write_res.is_err() {
                *guard = None;
                continue;
            }

            let read_fut = async {
                let mut resp_len_buf = [0u8; 2];
                s.read_exact(&mut resp_len_buf).await?;
                let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
                if resp_len > 4096 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response too large",
                    ));
                }
                let mut resp_buf = vec![0u8; resp_len];
                s.read_exact(&mut resp_buf).await?;
                Ok(resp_buf)
            };

            let read_res = match tokio::time::timeout(DOT_IO_TIMEOUT, read_fut).await {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DoT read timed out",
                )),
            };

            match read_res {
                Ok(resp_buf) => {
                    // An error RCODE (NXDOMAIN/NODATA) is a valid answer, not a
                    // broken connection: only the header is checked here.
                    DnsMessage::validate_response_header(&resp_buf, tx_id)
                        .map_err(QueryError::Transport)?;
                    return DnsMessage::parse_response(&resp_buf, name, qtype);
                }
                Err(_) => {
                    *guard = None;
                }
            }
        }

        Err(QueryError::Transport(FluxError::Dns(format!(
            "DoT query to {} failed after reconnect",
            self.server_host
        ))))
    }
}
