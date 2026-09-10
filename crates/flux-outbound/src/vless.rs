use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use uuid::Uuid;
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    TargetAddress,
};
use flux_dns::DnsResolver;
use flux_protocol::vless::VlessProtocol;
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

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Protocol {
            protocol: "vless-out",
            message: "VLESS UDP outbound not yet configured".into(),
        })
    }
}
