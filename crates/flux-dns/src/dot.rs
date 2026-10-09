use crate::wire::{DnsMessage, QTYPE_A};
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{BoxedStream, FluxError, FluxResult};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

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
    pub async fn query_dot(
        &self,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
    ) -> FluxResult<(IpAddr, u32)> {
        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_with_ecs_id(domain, QTYPE_A, ecs, tx_id);
        let len_bytes = (query.len() as u16).to_be_bytes();

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
            let write_res = async {
                s.write_all(&len_bytes).await?;
                s.write_all(&query).await?;
                s.flush().await
            }
            .await;

            if write_res.is_err() {
                *guard = None;
                continue;
            }

            let read_res = async {
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
            }
            .await;

            match read_res {
                Ok(resp_buf) => {
                    DnsMessage::validate_response(&resp_buf, tx_id)?;
                    return DnsMessage::parse_ip_record_with_ttl(&resp_buf);
                }
                Err(_) => {
                    *guard = None;
                }
            }
        }

        Err(FluxError::Dns(format!(
            "DoT query to {} failed after reconnect",
            self.server_host
        )))
    }
}
