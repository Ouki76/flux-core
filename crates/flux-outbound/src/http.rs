use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_protocol::http::HttpHandshake;
use flux_transport::tcp::TcpTransport;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, StreamDialer,
    TargetAddress,
};
use std::sync::Arc;
use std::time::Duration;

pub struct HttpOutbound {
    tag: String,
    server_address: TargetAddress,
    auth: Option<(String, String)>,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
    dialer: Option<Arc<dyn StreamDialer>>,
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
            dialer: None,
        }
    }

    pub fn new_with_dialer(
        tag: impl Into<String>,
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            auth: None,
            resolver,
            connect_timeout: Duration::from_secs(10),
            dialer: Some(dialer),
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

    fn protocol(&self) -> &'static str {
        "http"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let mut stream: BoxedStream = if let Some(ref d) = self.dialer {
            d.dial().await?
        } else {
            let server_addr = self.resolver.resolve(&self.server_address).await?;
            Box::new(TcpTransport::connect(server_addr, self.connect_timeout).await?)
        };

        let auth_ref = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        let excess_opt =
            HttpHandshake::client_handshake_with_auth(&mut stream, &meta.destination, auth_ref)
                .await?;

        if let Some(excess) = excess_opt {
            Ok(Box::new(flux_common::copy::PrefixedStream::new(
                stream, excess,
            )))
        } else {
            Ok(stream)
        }
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Protocol {
            protocol: "http-out",
            message: "UDP not supported over HTTP proxy".into(),
        })
    }
}
