use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta,
};

pub struct BlockOutbound {
    tag: String,
}

impl BlockOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        Err(FluxError::Blocked(format!(
            "traffic to {} blocked by outbound '{}'",
            meta.destination, self.tag
        )))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Blocked(format!(
            "UDP traffic to {} blocked by outbound '{}'",
            meta.destination, self.tag
        )))
    }
}
