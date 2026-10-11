use async_trait::async_trait;
use flux_protocol::hysteria2::{
    BrutalPacer, HYSTERIA2_CMD_TCP, HYSTERIA2_CMD_UDP, Hysteria2Config, Hysteria2Protocol,
    PortHopper,
};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub struct Hysteria2Outbound {
    tag: String,
    config: Hysteria2Config,
    resolver: Arc<flux_dns::DnsResolver>,
    port_hopper: Arc<Mutex<PortHopper>>,
    pacer: Arc<Mutex<BrutalPacer>>,
    endpoint: Arc<Mutex<Option<quinn::Endpoint>>>,
    connection: Arc<Mutex<Option<quinn::Connection>>>,
    h3_handle: Arc<Mutex<Option<Box<dyn std::any::Any + Send + Sync>>>>,
    dialer: Option<Arc<dyn flux_types::StreamDialer>>,
}

impl Hysteria2Outbound {
    pub fn new(
        tag: impl Into<String>,
        config: Hysteria2Config,
        resolver: Arc<flux_dns::DnsResolver>,
    ) -> Self {
        let hopper = PortHopper::new(config.ports.clone(), config.hop_interval_secs);
        let pacer = BrutalPacer::new(config.up_mbps);

        Self {
            tag: tag.into(),
            config,
            resolver,
            port_hopper: Arc::new(Mutex::new(hopper)),
            pacer: Arc::new(Mutex::new(pacer)),
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
            h3_handle: Arc::new(Mutex::new(None)),
            dialer: None,
        }
    }

    pub fn new_with_dialer(
        tag: impl Into<String>,
        config: Hysteria2Config,
        dialer: Arc<dyn flux_types::StreamDialer>,
    ) -> Self {
        let hopper = PortHopper::new(config.ports.clone(), config.hop_interval_secs);
        let pacer = BrutalPacer::new(config.up_mbps);
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));

        Self {
            tag: tag.into(),
            config,
            resolver,
            port_hopper: Arc::new(Mutex::new(hopper)),
            pacer: Arc::new(Mutex::new(pacer)),
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
            h3_handle: Arc::new(Mutex::new(None)),
            dialer: Some(dialer),
        }
    }

    pub fn pacer(&self) -> &Arc<Mutex<BrutalPacer>> {
        &self.pacer
    }

    async fn get_connection(&self) -> FluxResult<quinn::Connection> {
        let port = self.port_hopper.lock().await.current_port();
        let peer_addr = self
            .resolver
            .resolve_domain(&self.config.server, port)
            .await?;

        let mut conn_guard = self.connection.lock().await;
        if let Some(ref conn) = *conn_guard
            && conn.close_reason().is_none()
            && conn.remote_address().port() == port
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
            let alpn = vec![b"h3".to_vec(), b"hysteria2".to_vec()];
            let ep = QuicTransport::create_client_endpoint(
                peer_addr.is_ipv6(),
                alpn,
                self.config.insecure,
            )?;
            *ep_guard = Some(ep.clone());
            ep
        };

        let sni = self
            .config
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let conn = QuicTransport::connect(&endpoint, peer_addr, sni).await?;
        if self.config.h3 {
            let h3 = Hysteria2Protocol::client_authenticate_h3(conn.clone(), &self.config.password)
                .await?;
            *self.h3_handle.lock().await = Some(h3);
        }
        *conn_guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "hysteria2"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(ref d) = self.dialer {
            let mut stream = d.dial().await?;
            let auth_frame = Hysteria2Protocol::build_auth_frame(&self.config.password);
            let req_frame =
                Hysteria2Protocol::build_request_frame(HYSTERIA2_CMD_TCP, &meta.destination);

            stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
            stream.write_all(&req_frame).await.map_err(FluxError::Io)?;
            stream.flush().await.map_err(FluxError::Io)?;
            Ok(stream)
        } else {
            let conn = self.get_connection().await?;
            let mut stream = QuicTransport::open_bi_stream(&conn).await?;
            if self.config.h3 {
                let req_frame = Hysteria2Protocol::encode_tcp_request(&meta.destination);
                stream.write_all(&req_frame).await.map_err(FluxError::Io)?;
                stream.flush().await.map_err(FluxError::Io)?;
                Hysteria2Protocol::read_tcp_response(&mut stream).await?;
            } else {
                let auth_frame = Hysteria2Protocol::build_auth_frame(&self.config.password);
                let req_frame =
                    Hysteria2Protocol::build_request_frame(HYSTERIA2_CMD_TCP, &meta.destination);
                stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
                stream.write_all(&req_frame).await.map_err(FluxError::Io)?;
                stream.flush().await.map_err(FluxError::Io)?;
            }
            Ok(Box::new(stream))
        }
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let conn = self.get_connection().await?;
        let mut stream = QuicTransport::open_bi_stream(&conn).await?;

        let auth_frame = Hysteria2Protocol::build_auth_frame(&self.config.password);
        let req_frame =
            Hysteria2Protocol::build_request_frame(HYSTERIA2_CMD_UDP, &meta.destination);

        stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
        stream.write_all(&req_frame).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Box::new(Hysteria2PacketEndpoint {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            pacer: self.pacer.clone(),
            destination: meta.destination.clone(),
        }))
    }
}

pub struct Hysteria2PacketEndpoint {
    reader: Arc<Mutex<tokio::io::ReadHalf<QuicBiStream>>>,
    writer: Arc<Mutex<tokio::io::WriteHalf<QuicBiStream>>>,
    pacer: Arc<Mutex<BrutalPacer>>,
    destination: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for Hysteria2PacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        self.pacer.lock().await.pace(packet.payload.len() + 2).await;
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
    async fn test_hysteria2_endpoint_family_matching() {
        let cfg = Hysteria2Config {
            server: "127.0.0.1".into(),
            ports: vec![443],
            password: "test".into(),
            up_mbps: 100,
            down_mbps: 100,
            hop_interval_secs: 30,
            insecure: false,
            server_name: None,
            obfs: None,
            h3: false,
        };
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));
        let outbound = Hysteria2Outbound::new("hy2-out", cfg, resolver);

        let peer_v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_v6: SocketAddr = "[::1]:443".parse().unwrap();

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
