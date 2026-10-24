use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_transport::pipeline::{FramingLayer, LayeredTransportPipeline, SecurityLayer};
use flux_types::{BoxedStream, FluxResult, StreamDialer, TargetAddress};
use std::sync::Arc;
use std::time::Duration;

/// An asynchronous dialer that resolves the target address dynamically via `DnsResolver`
/// and executes the layered transport pipeline (Carrier ──► Security ──► Framing).
pub struct LazyPipelineDialer {
    /// mKCP carrier, when the node's `carrier` is `kcp`.
    pub kcp: Option<flux_transport::KcpConfig>,
    /// The address the peer knows this server by, before resolution.
    pub server_address: TargetAddress,
    /// Used when `server_address` is a name.
    pub resolver: Arc<DnsResolver>,
    /// Security layers, applied outermost last.
    pub securities: Vec<SecurityLayer>,
    /// Framing layers, applied innermost first.
    pub framings: Vec<FramingLayer>,
    /// Bound on the whole dial, handshakes included.
    pub connect_timeout: Duration,
}

impl LazyPipelineDialer {
    /// A dialer for `server_address` with the given layers.
    pub fn new(
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
        security: SecurityLayer,
        framing: FramingLayer,
    ) -> Self {
        Self {
            kcp: None,
            server_address,
            resolver,
            securities: vec![security],
            framings: vec![framing],
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// A dialer with no layers, for a plain connection.
    pub fn new_raw(server_address: TargetAddress, resolver: Arc<DnsResolver>) -> Self {
        Self {
            kcp: None,
            server_address,
            resolver,
            securities: Vec::new(),
            framings: Vec::new(),
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// A dialer for several server addresses, tried in order.
    pub fn new_multi(
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
        securities: Vec<SecurityLayer>,
        framings: Vec<FramingLayer>,
    ) -> Self {
        Self {
            kcp: None,
            server_address,
            resolver,
            securities,
            framings,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Replaces the dial timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

#[async_trait]
impl StreamDialer for LazyPipelineDialer {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let resolved = self.resolver.resolve(&self.server_address).await?;
        let mut pipeline = LayeredTransportPipeline::new(self.server_address.clone(), resolved)
            .with_timeout(self.connect_timeout);
        if let Some(kcp) = &self.kcp {
            pipeline = pipeline.with_kcp(*kcp);
        }
        let pipeline = pipeline
            .with_securities(self.securities.clone())
            .with_framings(self.framings.clone())
            .with_host_header(self.server_address.host());
        pipeline.dial().await
    }
}
