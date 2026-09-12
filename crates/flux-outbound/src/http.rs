use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
};
use flux_dns::DnsResolver;
use flux_protocol::http::HttpHandshake;
use flux_transport::tcp::TcpTransport;

pub struct HttpOutbound {
    tag: String,
    server_address: TargetAddress,
    auth: Option<(String, String)>,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
}

impl HttpOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            auth: None,
            resolver,
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let mut stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        let auth_ref = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        HttpHandshake::client_handshake_with_auth(&mut stream, &meta.destination, auth_ref).await?;

        Ok(Box::new(stream))
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Protocol {
            protocol: "http-out",
            message: "UDP not supported over HTTP proxy".into(),
        })
    }
}
