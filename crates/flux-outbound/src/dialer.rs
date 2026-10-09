use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_transport::pipeline::{FramingLayer, LayeredTransportPipeline, SecurityLayer};
use flux_types::{BoxedStream, FluxResult, StreamDialer, TargetAddress};
use std::sync::Arc;
use std::time::Duration;

/// An asynchronous dialer that resolves the target address dynamically via `DnsResolver`
/// and executes the layered transport pipeline (Carrier ──► Security ──► Framing).
pub struct LazyPipelineDialer {
    pub server_address: TargetAddress,
    pub resolver: Arc<DnsResolver>,
    pub security: SecurityLayer,
    pub framing: FramingLayer,
    pub connect_timeout: Duration,
}

impl LazyPipelineDialer {
    pub fn new(
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
        security: SecurityLayer,
        framing: FramingLayer,
    ) -> Self {
        Self {
            server_address,
            resolver,
            security,
            framing,
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

#[async_trait]
impl StreamDialer for LazyPipelineDialer {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let resolved = self.resolver.resolve(&self.server_address).await?;
        let pipeline = LayeredTransportPipeline::new(self.server_address.clone(), resolved)
            .with_timeout(self.connect_timeout)
            .with_security(self.security.clone())
            .with_framing(self.framing.clone())
            .with_host_header(self.server_address.host());
        pipeline.dial().await
    }
}
