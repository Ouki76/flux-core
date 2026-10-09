use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::warn;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BalanceStrategy {
    #[default]
    RoundRobin,
    ConsistentHashing,
}

impl BalanceStrategy {
    pub fn parse_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "consistent-hashing" | "hash" | "sticky" => Self::ConsistentHashing,
            _ => Self::RoundRobin,
        }
    }
}

pub struct LoadBalanceOutbound {
    tag: String,
    outbounds: Vec<String>,
    strategy: BalanceStrategy,
    counter: AtomicUsize,
    lookup: Arc<dyn OutboundLookup>,
}

impl LoadBalanceOutbound {
    pub fn new(
        tag: impl Into<String>,
        outbounds: Vec<String>,
        strategy: Option<BalanceStrategy>,
        lookup: Arc<dyn OutboundLookup>,
    ) -> Self {
        Self {
            tag: tag.into(),
            outbounds,
            strategy: strategy.unwrap_or_default(),
            counter: AtomicUsize::new(0),
            lookup,
        }
    }

    fn select_index(&self, meta: &SessionMeta) -> usize {
        if self.outbounds.is_empty() {
            return 0;
        }

        match self.strategy {
            BalanceStrategy::RoundRobin => {
                self.counter.fetch_add(1, Ordering::Relaxed) % self.outbounds.len()
            }
            BalanceStrategy::ConsistentHashing => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                meta.destination.hash(&mut hasher);
                meta.source.ip().hash(&mut hasher);
                let hash_u64 = hasher.finish();
                (hash_u64 as usize) % self.outbounds.len()
            }
        }
    }
}

#[async_trait]
impl Outbound for LoadBalanceOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "loadbalance"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if self.outbounds.is_empty() {
            return Err(FluxError::OutboundNotFound(format!(
                "loadbalance group '{}' has no candidate outbounds",
                self.tag
            )));
        }

        let start_idx = self.select_index(meta);
        let n = self.outbounds.len();

        for i in 0..n {
            let idx = (start_idx + i) % n;
            let candidate_tag = &self.outbounds[idx];

            if let Some(outbound) = self.lookup.get(candidate_tag) {
                match outbound.dial_stream(meta).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => {
                        warn!(
                            "[{}] LoadBalance candidate '{}' failed dial: {}. Trying next...",
                            self.tag, candidate_tag, e
                        );
                    }
                }
            }
        }

        Err(FluxError::Network(format!(
            "all candidates in loadbalance group '{}' failed",
            self.tag
        )))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        if self.outbounds.is_empty() {
            return Err(FluxError::OutboundNotFound(format!(
                "loadbalance group '{}' has no candidate outbounds",
                self.tag
            )));
        }

        let start_idx = self.select_index(meta);
        let n = self.outbounds.len();

        for i in 0..n {
            let idx = (start_idx + i) % n;
            let candidate_tag = &self.outbounds[idx];

            if let Some(outbound) = self.lookup.get(candidate_tag) {
                match outbound.dial_packet(meta).await {
                    Ok(ep) => return Ok(ep),
                    Err(e) => {
                        warn!(
                            "[{}] LoadBalance candidate '{}' failed UDP dial: {}. Trying next...",
                            self.tag, candidate_tag, e
                        );
                    }
                }
            }
        }

        Err(FluxError::Network(format!(
            "all candidates in loadbalance group '{}' failed for UDP",
            self.tag
        )))
    }

    fn is_group(&self) -> bool {
        true
    }

    fn group_type(&self) -> Option<&'static str> {
        Some("loadbalance")
    }

    fn current_selected(&self) -> Option<String> {
        self.outbounds.first().cloned()
    }

    fn candidate_outbounds(&self) -> Vec<String> {
        self.outbounds.clone()
    }
}
