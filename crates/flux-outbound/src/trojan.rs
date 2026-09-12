use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    TargetAddress, UdpPacket,
};
use flux_dns::DnsResolver;
use flux_protocol::trojan::TrojanProtocol;
use flux_protocol::udp::encode_trojan_udp;
use flux_protocol::socks5::Socks5Handshake;
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};

pub struct TrojanOutbound {
    tag: String,
    server_address: TargetAddress,
    password: String,
    resolver: Arc<DnsResolver>,
    tls_config: TlsClientConfig,
    connect_timeout: Duration,
}

impl TrojanOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        password: impl Into<String>,
        resolver: Arc<DnsResolver>,
        tls_config: TlsClientConfig,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            password: password.into(),
            resolver,
            tls_config,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let tcp_stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        // Trojan always runs over TLS
        let mut tls_stream = TlsTransport::connect(tcp_stream, &self.tls_config).await?;

        TrojanProtocol::write_request_header(
            &mut tls_stream,
            &self.password,
            NetworkType::Tcp,
            &meta.destination,
        )
        .await?;

        Ok(tls_stream)
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let tcp_stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;
        let mut tls_stream = TlsTransport::connect(tcp_stream, &self.tls_config).await?;

        TrojanProtocol::write_request_header(
            &mut tls_stream,
            &self.password,
            NetworkType::Udp,
            &meta.destination,
        )
        .await?;

        Ok(Box::new(TrojanPacketEndpoint {
            stream: Arc::new(Mutex::new(tls_stream)),
            server_target: meta.destination.clone(),
        }))
    }
}

pub struct TrojanPacketEndpoint {
    stream: Arc<Mutex<BoxedStream>>,
    server_target: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for TrojanPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let encoded = encode_trojan_udp(&packet);
        let mut guard = self.stream.lock().await;
        guard.write_all(&encoded).await.map_err(FluxError::Io)?;
        guard.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.stream.lock().await;

        let mut atyp_buf = [0u8; 1];
        guard.read_exact(&mut atyp_buf).await.map_err(FluxError::Io)?;
        let target = Socks5Handshake::read_address(&mut *guard, atyp_buf[0]).await?;

        let mut len_buf = [0u8; 2];
        guard.read_exact(&mut len_buf).await.map_err(FluxError::Io)?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;

        let mut crlf = [0u8; 2];
        guard.read_exact(&mut crlf).await.map_err(FluxError::Io)?;

        let mut payload = vec![0u8; payload_len];
        guard.read_exact(&mut payload).await.map_err(FluxError::Io)?;

        Ok(UdpPacket::new(
            bytes::Bytes::from(payload),
            self.server_target.clone(),
            target,
        ))
    }
}
