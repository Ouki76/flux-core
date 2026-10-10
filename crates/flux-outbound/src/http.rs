use async_trait::async_trait;
use flux_protocol::http::HttpHandshake;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, StreamDialer,
};
use std::sync::Arc;

pub struct HttpOutbound {
    tag: String,
    auth: Option<(String, String)>,
    dialer: Arc<dyn StreamDialer>,
}

impl HttpOutbound {
    pub fn new(tag: impl Into<String>, dialer: Arc<dyn StreamDialer>) -> Self {
        Self {
            tag: tag.into(),
            auth: None,
            dialer,
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
        let mut stream = self.dialer.dial().await?;
        let auth_ref = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        HttpHandshake::client_handshake_with_auth(&mut stream, &meta.destination, auth_ref).await?;
        Ok(stream)
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Protocol {
            protocol: "http",
            message: "HTTP outbound does not support UDP relay".into(),
        })
    }
}
