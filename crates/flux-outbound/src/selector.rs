use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct SelectorOutbound {
    tag: String,
    outbounds: Vec<String>,
    selected: Arc<RwLock<String>>,
    lookup: Arc<dyn OutboundLookup>,
}

impl SelectorOutbound {
    pub fn new(
        tag: impl Into<String>,
        outbounds: Vec<String>,
        default: Option<String>,
        lookup: Arc<dyn OutboundLookup>,
    ) -> Self {
        let initial = default
            .filter(|d| outbounds.contains(d))
            .or_else(|| outbounds.first().cloned())
            .unwrap_or_else(|| "direct".into());

        Self {
            tag: tag.into(),
            outbounds,
            selected: Arc::new(RwLock::new(initial)),
            lookup,
        }
    }

    pub fn current(&self) -> String {
        self.selected.read().clone()
    }

    fn get_active(&self) -> FluxResult<Arc<dyn Outbound>> {
        let current_tag = self.current();
        self.lookup.get(&current_tag).ok_or_else(|| {
            FluxError::OutboundNotFound(format!(
                "selector '{}': selected outbound '{}' not found in registry",
                self.tag, current_tag
            ))
        })
    }
}

#[async_trait]
impl Outbound for SelectorOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "selector"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let active = self.get_active()?;
        active.dial_stream(meta).await
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let active = self.get_active()?;
        active.dial_packet(meta).await
    }

    fn is_group(&self) -> bool {
        true
    }

    fn group_type(&self) -> Option<&'static str> {
        Some("selector")
    }

    fn select(&self, tag: &str) -> FluxResult<()> {
        if !self.outbounds.iter().any(|t| t == tag) {
            return Err(FluxError::OutboundNotFound(format!(
                "outbound '{}' is not in selector '{}' list",
                tag, self.tag
            )));
        }
        let mut guard = self.selected.write();
        *guard = tag.to_string();
        Ok(())
    }

    fn current_selected(&self) -> Option<String> {
        Some(self.current())
    }

    fn candidate_outbounds(&self) -> Vec<String> {
        self.outbounds.clone()
    }
}
