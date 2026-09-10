use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    TargetAddress,
};
use flux_dns::DnsResolver;
use flux_protocol::trojan::TrojanProtocol;
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

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Protocol {
            protocol: "trojan-out",
            message: "Trojan UDP outbound not yet configured".into(),
        })
    }
}
