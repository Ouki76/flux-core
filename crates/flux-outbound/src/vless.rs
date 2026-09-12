use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    TargetAddress, UdpPacket,
};
use flux_dns::DnsResolver;
use flux_protocol::vless::{VlessProtocol, VLESS_VERSION};
use flux_protocol::udp::encode_vless_udp;
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_transport::reality::{RealityClientConfig, RealityHandshake};

pub struct VlessOutbound {
    tag: String,
    server_address: TargetAddress,
    uuid: Uuid,
    flow: Option<String>,
    resolver: Arc<DnsResolver>,
    tls_config: Option<TlsClientConfig>,
    reality_config: Option<RealityClientConfig>,
    connect_timeout: Duration,
}

impl VlessOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        uuid: Uuid,
        flow: Option<String>,
        resolver: Arc<DnsResolver>,
        tls_config: Option<TlsClientConfig>,
        reality_config: Option<RealityClientConfig>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            uuid,
            flow,
            resolver,
            tls_config,
            reality_config,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let tcp_stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        let mut stream: BoxedStream = if let Some(reality_cfg) = &self.reality_config {
            let mut s = tcp_stream;
            RealityHandshake::client_handshake(&mut s, reality_cfg).await?;
            Box::new(s)
        } else if let Some(tls_cfg) = &self.tls_config {
            TlsTransport::connect(tcp_stream, tls_cfg).await?
        } else {
            Box::new(tcp_stream)
        };

        VlessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Tcp,
            &meta.destination,
            self.flow.as_deref(),
        )
        .await?;

        if self.flow.as_deref() == Some(flux_protocol::vision::VISION_FLOW) {
            let vless_client = flux_protocol::vless::VlessClientStream::new(stream);
            let vision_stream = flux_protocol::vision::VisionStream::new(vless_client);
            Ok(Box::new(vision_stream))
        } else {
            Ok(Box::new(flux_protocol::vless::VlessClientStream::new(stream)))
        }
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let tcp_stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        let mut stream: BoxedStream = if let Some(reality_cfg) = &self.reality_config {
            let mut s = tcp_stream;
            RealityHandshake::client_handshake(&mut s, reality_cfg).await?;
            Box::new(s)
        } else if let Some(tls_cfg) = &self.tls_config {
            TlsTransport::connect(tcp_stream, tls_cfg).await?
        } else {
            Box::new(tcp_stream)
        };

        VlessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Udp,
            &meta.destination,
            None,
        )
        .await?;

        Ok(Box::new(VlessPacketEndpoint {
            stream: Arc::new(Mutex::new(stream)),
            header_stripped: Arc::new(Mutex::new(false)),
            destination: meta.destination.clone(),
        }))
    }
}

pub struct VlessPacketEndpoint {
    stream: Arc<Mutex<BoxedStream>>,
    header_stripped: Arc<Mutex<bool>>,
    destination: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for VlessPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let encoded = encode_vless_udp(&packet.payload);
        let mut guard = self.stream.lock().await;
        guard.write_all(&encoded).await.map_err(FluxError::Io)?;
        guard.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.stream.lock().await;
        let mut stripped_guard = self.header_stripped.lock().await;

        if !*stripped_guard {
            // Strip 2-byte VLESS response header: [version, addon_len]
            let mut hdr = [0u8; 2];
            guard.read_exact(&mut hdr).await.map_err(FluxError::Io)?;
            if hdr[0] != VLESS_VERSION {
                return Err(FluxError::Protocol {
                    protocol: "vless-udp",
                    message: format!("invalid vless version in response: {}", hdr[0]),
                });
            }
            let addon_len = hdr[1] as usize;
            if addon_len > 0 {
                let mut drain = vec![0u8; addon_len];
                guard.read_exact(&mut drain).await.map_err(FluxError::Io)?;
            }
            *stripped_guard = true;
        }

        let mut len_buf = [0u8; 2];
        guard.read_exact(&mut len_buf).await.map_err(FluxError::Io)?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;

        let mut payload = vec![0u8; payload_len];
        guard.read_exact(&mut payload).await.map_err(FluxError::Io)?;

        Ok(UdpPacket::new(
            bytes::Bytes::from(payload),
            self.destination.clone(),
            self.destination.clone(),
        ))
    }
}
