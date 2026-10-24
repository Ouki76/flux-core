use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::warn;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
/// /// How connections are spread across the members.
pub enum BalanceStrategy {
    #[default]
    /// Each connection to the next member in turn.
    RoundRobin,
    /// The same destination to the same member, so caches stay warm.
    ConsistentHashing,
}

impl BalanceStrategy {
    /// Parses a strategy name, defaulting to round robin.
    pub fn parse_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "consistent-hashing" | "hash" | "sticky" => Self::ConsistentHashing,
            _ => Self::RoundRobin,
        }
    }
}

/// /// Spreads connections across several outbounds.
pub struct LoadBalanceOutbound {
    tag: String,
    outbounds: Vec<String>,
    strategy: BalanceStrategy,
    counter: AtomicUsize,
    lookup: Arc<dyn OutboundLookup>,
}

impl LoadBalanceOutbound {
    /// A group named `tag` over `members` with `strategy`.
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
    use crate::selector::test_support::ScriptedOutbound;

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

    // -----------------------------------------------------------------------
    // Dial behaviour
    // -----------------------------------------------------------------------

    /// A group with no members must say so with the variant that means "no such
    /// outbound", not with a generic network error: the caller can tell a
    /// misconfiguration from every member being down.
    #[tokio::test]
    async fn an_empty_group_reports_outbound_not_found() {
        let reg = crate::selector::test_support::FakeRegistry::over(vec![]);
        let r = LoadBalanceOutbound::new("lb", vec![], None, reg);
        let err = match r.dial_stream(&crate::selector::test_support::meta()).await {
            Err(e) => e,
            Ok(_) => panic!("an empty group cannot dial"),
        };
        assert!(matches!(err, FluxError::OutboundNotFound(_)), "{err:?}");
        let err = match r.dial_packet(&crate::selector::test_support::meta()).await {
            Err(e) => e,
            Ok(_) => panic!("an empty group cannot dial"),
        };
        assert!(matches!(err, FluxError::OutboundNotFound(_)), "{err:?}");
    }

    /// Round-robin must actually spread sessions over the members at dial time,
    /// not just in the index helper.
    #[tokio::test]
    async fn round_robin_spreads_dials_across_members() {
        let a = Arc::new(ScriptedOutbound::new("a", true));
        let b = Arc::new(ScriptedOutbound::new("b", true));
        let reg = crate::selector::test_support::LiveRegistry::over(vec![a.clone(), b.clone()]);
        let r = LoadBalanceOutbound::new(
            "lb",
            vec!["a".to_string(), "b".to_string()],
            Some(BalanceStrategy::RoundRobin),
            reg,
        );

        for _ in 0..6 {
            assert!(
                r.dial_stream(&crate::selector::test_support::meta())
                    .await
                    .is_ok()
            );
        }
        assert_eq!(a.stream_dials(), 3);
        assert_eq!(b.stream_dials(), 3);
    }

    /// A member that is not in the registry is skipped, and the session is
    /// carried by a member that does exist.
    #[tokio::test]
    async fn a_missing_member_is_skipped() {
        let b = Arc::new(ScriptedOutbound::new("b", true));
        let reg = crate::selector::test_support::LiveRegistry::over(vec![b.clone()]);
        let r = LoadBalanceOutbound::new(
            "lb",
            vec!["a".to_string(), "b".to_string()],
            Some(BalanceStrategy::RoundRobin),
            reg,
        );
        for _ in 0..4 {
            assert!(
                r.dial_stream(&crate::selector::test_support::meta())
                    .await
                    .is_ok()
            );
        }
        assert_eq!(b.stream_dials(), 4);
    }

    /// Every member down: each is dialed exactly once and the error names the
    /// group. The rotation must not lose track of a member (that is how a group
    /// ends up with a member that is never dialed again).
    #[tokio::test]
    async fn all_members_down_tries_each_once() {
        let a = Arc::new(ScriptedOutbound::new("a", false));
        let b = Arc::new(ScriptedOutbound::new("b", false));
        let reg = crate::selector::test_support::LiveRegistry::over(vec![a.clone(), b.clone()]);
        let r = LoadBalanceOutbound::new(
            "lb",
            vec!["a".to_string(), "b".to_string()],
            Some(BalanceStrategy::RoundRobin),
            reg,
        );

        let err = match r.dial_stream(&crate::selector::test_support::meta()).await {
            Err(e) => e,
            Ok(_) => panic!("both members are down"),
        };
        assert!(matches!(err, FluxError::Network(_)), "{err:?}");
        assert_eq!(a.stream_dials(), 1);
        assert_eq!(b.stream_dials(), 1);

        // A member that comes back is used again on the very next dial.
        b.set_healthy(true);
        assert!(
            r.dial_stream(&crate::selector::test_support::meta())
                .await
                .is_ok()
        );
    }

    /// The rotation counter is a `usize` shared by every dialer. At the end of
    /// its range it must wrap, not panic in a debug build, and the index must
    /// stay inside the list.
    #[tokio::test]
    async fn the_rotation_counter_wraps_without_panicking() {
        let r = lb(BalanceStrategy::RoundRobin, &["a", "b", "c"]);
        r.counter.store(usize::MAX - 1, Ordering::SeqCst);
        for _ in 0..8 {
            let idx = r.select_index(&crate::selector::test_support::meta());
            assert!(
                idx < r.outbounds.len(),
                "index {idx} outside the member list"
            );
        }
    }

    /// Many tasks dialing at once: no panic, and every dial is carried by a
    /// configured member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_dials_stay_within_the_members() {
        let a = Arc::new(ScriptedOutbound::new("a", true));
        let b = Arc::new(ScriptedOutbound::new("b", true));
        let c = Arc::new(ScriptedOutbound::new("c", true));
        let reg = crate::selector::test_support::LiveRegistry::over(vec![
            a.clone(),
            b.clone(),
            c.clone(),
        ]);
        let r = Arc::new(LoadBalanceOutbound::new(
            "lb",
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            Some(BalanceStrategy::RoundRobin),
            reg,
        ));

        let mut tasks = Vec::new();
        for _ in 0..12 {
            let r = r.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..40 {
                    assert!(
                        r.dial_stream(&crate::selector::test_support::meta())
                            .await
                            .is_ok()
                    );
                    let selected = r.current_selected().expect("groups report a selection");
                    assert!(
                        ["a", "b", "c"].contains(&selected.as_str()),
                        "selection left the member list: {selected}"
                    );
                }
            }));
        }
        for task in tasks {
            task.await.expect("no task may panic");
        }
        let total = a.stream_dials() + b.stream_dials() + c.stream_dials();
        assert_eq!(
            total,
            12 * 40,
            "every session was carried by exactly one member"
        );
        assert!(a.stream_dials() > 0 && b.stream_dials() > 0 && c.stream_dials() > 0);
    }
}
