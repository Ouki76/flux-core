use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
};
use flux_dns::DnsResolver;
use flux_protocol::socks5::{Socks5Handshake, CMD_CONNECT};
use flux_transport::tcp::TcpTransport;

pub struct SocksOutbound {
    tag: String,
    server_address: TargetAddress,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
}

impl SocksOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            resolver,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let mut stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        Socks5Handshake::client_handshake(&mut stream, CMD_CONNECT, &meta.destination).await?;

        Ok(Box::new(stream))
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Protocol {
            protocol: "socks5-out",
            message: "UDP associate over socks outbound not yet configured".into(),
        })
    }
}
