use crate::wire::{DnsMessage, QTYPE_A};
use flux_types::{FluxError, FluxResult};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Clone)]
pub struct DoqClient {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    connection: Arc<tokio::sync::Mutex<Option<quinn::Connection>>>,
    endpoint: Arc<tokio::sync::Mutex<Option<quinn::Endpoint>>>,
}

impl std::fmt::Debug for DoqClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoqClient")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("sni", &self.sni)
            .finish()
    }
}

impl DoqClient {
    pub fn new(url_or_addr: &str) -> Self {
        let clean = url_or_addr
            .strip_prefix("quic://")
            .or_else(|| url_or_addr.strip_prefix("doq://"))
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
            connection: Arc::new(tokio::sync::Mutex::new(None)),
            endpoint: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn get_connection(&self, connect_addr: SocketAddr) -> FluxResult<quinn::Connection> {
        let mut conn_guard = self.connection.lock().await;
        if let Some(ref conn) = *conn_guard
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }

        let mut ep_guard = self.endpoint.lock().await;
        let endpoint = if let Some(ref ep) = *ep_guard
            && ep
                .local_addr()
                .map(|a| a.is_ipv6() == connect_addr.is_ipv6())
                .unwrap_or(false)
        {
            ep.clone()
        } else {
            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut crypto = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            crypto.alpn_protocols = vec![b"doq".to_vec()];

            let client_cfg = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                    FluxError::Crypto(format!("failed to configure QUIC client: {}", e))
                })?,
            ));

            let bind_addr = if connect_addr.is_ipv6() {
                SocketAddr::from(([0; 16], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };

            let mut ep = quinn::Endpoint::client(bind_addr).map_err(FluxError::Io)?;
            ep.set_default_client_config(client_cfg);
            *ep_guard = Some(ep.clone());
            ep
        };

        let conn = endpoint
            .connect(connect_addr, &self.sni)
            .map_err(|e| FluxError::Network(format!("QUIC connection setup failed: {}", e)))?
            .await
            .map_err(|e| FluxError::Network(format!("DoQ connection failed: {}", e)))?;

        *conn_guard = Some(conn.clone());
        Ok(conn)
    }

    /// Queries DNS-over-QUIC (RFC 9250) server.
    pub async fn query_doq(
        &self,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
    ) -> FluxResult<(IpAddr, u32)> {
        let connect_addr: SocketAddr = if let Ok(ip) = self.server_host.parse() {
            SocketAddr::new(ip, self.server_port)
        } else {
            let addr_str = format!("{}:{}", self.server_host, self.server_port);
            let mut addrs = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(FluxError::Io)?;
            addrs.next().ok_or_else(|| {
                FluxError::Dns(format!(
                    "failed to resolve DoQ server host '{}'",
                    self.server_host
                ))
            })?
        };

        let connection = self.get_connection(connect_addr).await?;
        let (mut send_stream, mut recv_stream) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(_) => {
                // If stream open failed (connection stale), clear cached connection and force reconnect
                *self.connection.lock().await = None;
                let connection = self.get_connection(connect_addr).await?;
                connection
                    .open_bi()
                    .await
                    .map_err(|e| FluxError::Network(format!("failed to open DoQ stream: {}", e)))?
            }
        };

        let query = DnsMessage::build_query_with_ecs(domain, QTYPE_A, ecs);
        let len_bytes = (query.len() as u16).to_be_bytes();

        send_stream
            .write_all(&len_bytes)
            .await
            .map_err(|e| FluxError::Network(e.to_string()))?;
        send_stream
            .write_all(&query)
            .await
            .map_err(|e| FluxError::Network(e.to_string()))?;
        send_stream
            .finish()
            .map_err(|e| FluxError::Network(format!("DoQ finish failed: {}", e)))?;

        let mut len_buf = [0u8; 2];
        recv_stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| FluxError::Network(e.to_string()))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len > 4096 {
            return Err(FluxError::Dns(format!(
                "DoQ response size {} exceeds 4096 bytes",
                resp_len
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        recv_stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| FluxError::Network(e.to_string()))?;

        DnsMessage::parse_ip_record_with_ttl(&resp_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_doq_endpoint_family_switch() {
        let resolver = DoqClient::new("quic://127.0.0.1:853");

        let addr_v4: SocketAddr = "127.0.0.1:853".parse().unwrap();
        let addr_v6: SocketAddr = "[::1]:853".parse().unwrap();

        {
            let mut ep_guard = resolver.endpoint.lock().await;
            let ep_v4 = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
            *ep_guard = Some(ep_v4);
        }

        {
            let ep_guard = resolver.endpoint.lock().await;
            let matches = ep_guard
                .as_ref()
                .and_then(|ep| ep.local_addr().ok())
                .map(|a| a.is_ipv6() == addr_v4.is_ipv6())
                .unwrap_or(false);
            assert!(matches);

            let matches_v6 = ep_guard
                .as_ref()
                .and_then(|ep| ep.local_addr().ok())
                .map(|a| a.is_ipv6() == addr_v6.is_ipv6())
                .unwrap_or(false);
            assert!(!matches_v6);
        }
    }
}
