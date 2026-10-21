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

    fn udp_endpoint_per_destination(&self) -> bool {
        // Conservative: if *any* member needs one association per destination,
        // treat the group that way. Over-splitting costs an extra association;
        // under-splitting (the old behaviour) silently mixes destinations.
        self.outbounds.iter().any(|tag| {
            self.lookup
                .get(tag)
                .map(|m| m.udp_endpoint_per_destination())
                .unwrap_or(false)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lb(strategy: BalanceStrategy, tags: &[&str]) -> LoadBalanceOutbound {
        LoadBalanceOutbound::new(
            "lb",
            tags.iter().map(|s| s.to_string()).collect(),
            Some(strategy),
            crate::selector::test_support::FakeRegistry::of(&[
                ("a", false),
                ("b", false),
                ("c", false),
            ]),
        )
    }

    /// Round-robin must actually rotate over the members, not pin the first one.
    #[test]
    fn round_robin_visits_every_member() {
        let r = lb(BalanceStrategy::RoundRobin, &["a", "b", "c"]);
        let m = crate::selector::test_support::meta();
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(r.outbounds[r.select_index(&m)].clone());
        }
        assert_eq!(seen, vec!["a", "b", "c", "a", "b", "c"]);
    }

    /// Consistent hashing must be stable for the same destination…
    #[test]
    fn consistent_hashing_is_stable_per_destination() {
        let r = lb(BalanceStrategy::ConsistentHashing, &["a", "b", "c"]);
        let m = crate::selector::test_support::meta();
        let first = r.select_index(&m);
        for _ in 0..20 {
            assert_eq!(r.select_index(&m), first);
        }
        // …and must actually spread across members for different destinations.
        let mut spread = std::collections::HashSet::new();
        for i in 0..64 {
            let mut m = crate::selector::test_support::meta();
            m.destination = format!("host{i}.example:443").parse().unwrap();
            spread.insert(r.select_index(&m));
        }
        assert!(
            spread.len() > 1,
            "hashing pinned every destination to one member"
        );
    }

    #[test]
    fn empty_group_is_not_a_panic() {
        let r = lb(BalanceStrategy::RoundRobin, &[]);
        assert_eq!(r.select_index(&crate::selector::test_support::meta()), 0);
    }

    /// The group must report the per-destination requirement if *any* member
    /// needs one association per destination.
    #[test]
    fn reports_per_destination_if_any_member_needs_it() {
        let reg = crate::selector::test_support::FakeRegistry::of(&[("a", false), ("vm", true)]);
        let r = LoadBalanceOutbound::new("lb", vec!["a".to_string(), "vm".to_string()], None, reg);
        assert!(r.udp_endpoint_per_destination());
    }

    #[test]
    fn plain_members_do_not_require_per_destination() {
        let r = lb(BalanceStrategy::RoundRobin, &["a", "b"]);
        assert!(!r.udp_endpoint_per_destination());
    }
}
