use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use flux_types::{FluxError, FluxResult};
use crate::wire::{DnsMessage, QTYPE_A};

#[derive(Clone, Debug)]
pub struct DohClient {
    pub server_ip: String,
    pub server_port: u16,
    pub host_header: String,
    pub path: String,
}

impl DohClient {
    pub fn new(url: &str) -> Self {
        // e.g. https://1.1.1.1/dns-query or 1.1.1.1
        let clean = url.strip_prefix("https://").unwrap_or(url);
        let (host_port, path) = clean.split_once('/').unwrap_or((clean, "dns-query"));

        let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (host_port.to_string(), 443)
        };

        Self {
            server_ip: host.clone(),
            server_port: port,
            host_header: host,
            path: format!("/{}", path),
        }
    }

    /// Queries the DoH server over plain HTTP or TLS socket.
    pub async fn resolve_ipv4<S>(&self, mut stream: S, domain: &str) -> FluxResult<Ipv4Addr>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let query_wire = DnsMessage::build_query(domain, QTYPE_A);

        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path, self.host_header, query_wire.len()
        );

        stream.write_all(req.as_bytes()).await.map_err(FluxError::Io)?;
        stream.write_all(&query_wire).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        // Read HTTP response
        let mut resp_buf = Vec::with_capacity(1024);
        stream.read_to_end(&mut resp_buf).await.map_err(FluxError::Io)?;

        // Separate header and body
        let header_end = resp_buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .ok_or_else(|| FluxError::Dns("invalid HTTP response from DoH server".into()))?;

        let body = &resp_buf[header_end..];
        DnsMessage::parse_a_record(body)
    }
}
