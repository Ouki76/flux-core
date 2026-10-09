use async_trait::async_trait;
use flux_protocol::tuic::{TUIC_CMD_CONNECT, TUIC_CMD_PACKET, TuicV5Config, TuicV5Protocol};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub struct TuicOutbound {
    tag: String,
    config: TuicV5Config,
    resolver: Arc<flux_dns::DnsResolver>,
    endpoint: Arc<Mutex<Option<quinn::Endpoint>>>,
    connection: Arc<Mutex<Option<quinn::Connection>>>,
}

impl TuicOutbound {
    pub fn new(
        tag: impl Into<String>,
        config: TuicV5Config,
        resolver: Arc<flux_dns::DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            config,
            resolver,
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
        }
    }

    async fn get_connection(&self) -> FluxResult<quinn::Connection> {
        let peer_addr = self
            .resolver
            .resolve_domain(&self.config.server, self.config.server_port)
            .await?;

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
                .map(|a| a.is_ipv6() == peer_addr.is_ipv6())
                .unwrap_or(false)
        {
            ep.clone()
        } else {
            let alpn = vec![b"tuic-v5".to_vec(), b"h3".to_vec()];
            let ep = QuicTransport::create_client_endpoint(peer_addr.is_ipv6(), alpn, false)?;
            *ep_guard = Some(ep.clone());
            ep
        };

        let conn = QuicTransport::connect(&endpoint, peer_addr, &self.config.server).await?;
        *conn_guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "tuic"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let conn = self.get_connection().await?;
        let mut stream = QuicTransport::open_bi_stream(&conn).await?;

        // Send TUIC v5 Auth frame + Connect command over the encrypted QUIC stream
        let auth_frame = TuicV5Protocol::build_auth_frame(&self.config.uuid, &self.config.password);
        let cmd_frame = TuicV5Protocol::build_command_frame(TUIC_CMD_CONNECT, &meta.destination);

        stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
        stream.write_all(&cmd_frame).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        Ok(Box::new(stream))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let conn = self.get_connection().await?;
        let mut stream = QuicTransport::open_bi_stream(&conn).await?;

        let auth_frame = TuicV5Protocol::build_auth_frame(&self.config.uuid, &self.config.password);
        let cmd_frame = TuicV5Protocol::build_command_frame(TUIC_CMD_PACKET, &meta.destination);

        stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
        stream.write_all(&cmd_frame).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Box::new(TuicPacketEndpoint {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            destination: meta.destination.clone(),
        }))
    }
}

pub struct TuicPacketEndpoint {
    reader: Arc<Mutex<tokio::io::ReadHalf<QuicBiStream>>>,
    writer: Arc<Mutex<tokio::io::WriteHalf<QuicBiStream>>>,
    destination: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for TuicPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let len = packet.payload.len() as u16;
        let mut guard = self.writer.lock().await;
        guard
            .write_all(&len.to_be_bytes())
            .await
            .map_err(FluxError::Io)?;
        guard
            .write_all(&packet.payload)
            .await
            .map_err(FluxError::Io)?;
        guard.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.reader.lock().await;
        let mut len_buf = [0u8; 2];
        guard
            .read_exact(&mut len_buf)
            .await
            .map_err(FluxError::Io)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        guard
            .read_exact(&mut payload)
            .await
            .map_err(FluxError::Io)?;

        Ok(UdpPacket::new(
            payload.into(),
            self.destination.clone(),
            self.destination.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_tuic_endpoint_family_matching() {
        let cfg = TuicV5Config {
            server: "127.0.0.1".into(),
            server_port: 8443,
            uuid: uuid::Uuid::nil(),
            password: "test".into(),
            congestion_control: "bbr".into(),
            zero_rtt: false,
        };
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));
        let outbound = TuicOutbound::new("tuic-out", cfg, resolver);

        let peer_v4: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let peer_v6: SocketAddr = "[::1]:8443".parse().unwrap();

        assert!(outbound.endpoint.lock().await.is_none());

        {
            let mut ep_guard = outbound.endpoint.lock().await;
            let ep_v4 = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
            *ep_guard = Some(ep_v4);
        }

        {
            let ep_guard = outbound.endpoint.lock().await;
            let matches_v4 = ep_guard
                .as_ref()
                .and_then(|ep| ep.local_addr().ok())
                .map(|a| a.is_ipv6() == peer_v4.is_ipv6())
                .unwrap_or(false);
            assert!(matches_v4);

            let matches_v6 = ep_guard
                .as_ref()
                .and_then(|ep| ep.local_addr().ok())
                .map(|a| a.is_ipv6() == peer_v6.is_ipv6())
                .unwrap_or(false);
            assert!(!matches_v6);
        }
    }
}
