use async_trait::async_trait;
use dashmap::DashMap;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
    TargetAddress,
};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

pub struct UrlTestOutbound {
    tag: String,
    outbounds: Vec<String>,
    url: String,
    target_addr: TargetAddress,
    host_header: String,
    request_path: String,
    is_tls: bool,
    interval: Duration,
    tolerance: Duration,
    current_best: Arc<RwLock<Option<String>>>,
    latencies: Arc<DashMap<String, Duration>>,
    lookup: Arc<dyn OutboundLookup>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl UrlTestOutbound {
    pub fn new(
        tag: impl Into<String>,
        outbounds: Vec<String>,
        url: Option<String>,
        interval: Option<Duration>,
        tolerance: Option<Duration>,
        lookup: Arc<dyn OutboundLookup>,
    ) -> Self {
        let tag = tag.into();
        let url_str = url.unwrap_or_else(|| "http://cp.cloudflare.com/generate_204".into());
        let (target_addr, host_header, request_path, is_tls) =
            flux_types::parse_probe_url(&url_str);

        let initial_best = outbounds.first().cloned();

        Self {
            tag,
            outbounds,
            url: url_str,
            target_addr,
            host_header,
            request_path,
            is_tls,
            interval: interval.unwrap_or(Duration::from_secs(300)),
            tolerance: tolerance.unwrap_or(Duration::from_millis(50)),
            current_best: Arc::new(RwLock::new(initial_best)),
            latencies: Arc::new(DashMap::new()),
            lookup,
            cancel_token: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Spawns the background health check probe loop.
    pub fn start_probing(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let interval = self.interval;
        let token = self.cancel_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = async {
                    if let Some(this) = weak.upgrade() {
                        this.probe_all().await;
                    }
                } => {}
            }
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = sleep(interval) => {
                        let Some(this) = weak.upgrade() else {
                            break;
                        };
                        this.probe_all().await;
                    }
                }
            }
        });
    }

    pub async fn probe_all(&self) {
        use futures_util::future::join_all;
        let futures: Vec<_> = self
            .outbounds
            .iter()
            .map(|tag| {
                let t = tag.clone();
                async move {
                    let res = self.probe_candidate(&t).await;
                    (t, res)
                }
            })
            .collect();

        let results = join_all(futures).await;
        for (tag, maybe_rtt) in results {
            if let Some(rtt) = maybe_rtt {
                self.latencies.insert(tag.clone(), rtt);
                debug!("[{}] Candidate '{}' RTT: {:?}", self.tag, tag, rtt);
            } else {
                self.latencies.remove(&tag);
                debug!(
                    "[{}] Candidate '{}' probe failed / unreachable",
                    self.tag, tag
                );
            }
        }
        self.recalculate_best();
    }

    async fn probe_candidate(&self, tag: &str) -> Option<Duration> {
        let outbound = self.lookup.get(tag)?;
        crate::probe::probe_outbound(
            &outbound,
            &self.target_addr,
            &self.host_header,
            &self.request_path,
            self.is_tls,
            &format!("{}-healthcheck", self.tag),
            Duration::from_secs(5),
        )
        .await
    }

    fn recalculate_best(&self) {
        let mut best_tag: Option<String> = None;
        let mut min_rtt = Duration::MAX;

        for tag in &self.outbounds {
            if let Some(rtt_entry) = self.latencies.get(tag) {
                let rtt = *rtt_entry.value();
                if rtt < min_rtt {
                    min_rtt = rtt;
                    best_tag = Some(tag.clone());
                }
            }
        }

        if let Some(new_best) = best_tag {
            let mut guard = self.current_best.write();
            if let Some(current) = guard.as_ref()
                && let Some(cur_rtt_entry) = self.latencies.get(current)
            {
                let cur_rtt = *cur_rtt_entry.value();
                // Apply tolerance: only switch if new_best is significantly better
                if cur_rtt <= min_rtt + self.tolerance {
                    return;
                }
            }
            info!(
                "[{}] Switched best outbound to '{}' (RTT: {:?})",
                self.tag, new_best, min_rtt
            );
            *guard = Some(new_best);
        }
    }

    pub fn current_best_tag(&self) -> Option<String> {
        self.current_best.read().clone()
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn get_active(&self) -> FluxResult<Arc<dyn Outbound>> {
        let best = self
            .current_best_tag()
            .or_else(|| self.outbounds.first().cloned())
            .ok_or_else(|| {
                FluxError::OutboundNotFound(format!(
                    "urltest '{}': no outbounds configured",
                    self.tag
                ))
            })?;

        self.lookup.get(&best).ok_or_else(|| {
            FluxError::OutboundNotFound(format!(
                "urltest '{}': active outbound '{}' not found in registry",
                self.tag, best
            ))
        })
    }
}

#[async_trait]
impl Outbound for UrlTestOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "urltest"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let active = self.get_active()?;
        active.dial_stream(meta).await
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let active = self.get_active()?;
        active.dial_packet(meta).await
    }

    fn udp_endpoint_per_destination(&self) -> bool {
        // Delegate to the member that actually carries the datagrams: a VMess
        // member behind a group still needs one association per destination,
        // and the dispatcher's cache key must agree with the member's behaviour.
        self.get_active()
            .map(|m| m.udp_endpoint_per_destination())
            .unwrap_or(false)
    }

    fn is_group(&self) -> bool {
        true
    }

    fn group_type(&self) -> Option<&'static str> {
        Some("urltest")
    }

    fn current_selected(&self) -> Option<String> {
        self.current_best_tag()
    }

    fn candidate_outbounds(&self) -> Vec<String> {
        self.outbounds.clone()
    }

    fn stop(&self) {
        self.cancel_token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urltest(tolerance_ms: u64) -> UrlTestOutbound {
        UrlTestOutbound::new(
            "ut",
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            None,
            None,
            Some(Duration::from_millis(tolerance_ms)),
            crate::selector::test_support::FakeRegistry::of(&[
                ("a", false),
                ("b", false),
                ("c", false),
            ]),
        )
    }

    fn record(t: &UrlTestOutbound, tag: &str, ms: u64) {
        t.latencies
            .insert(tag.to_string(), Duration::from_millis(ms));
    }

    #[test]
    fn starts_on_the_first_candidate_before_any_probe() {
        assert_eq!(urltest(50).current_best_tag(), Some("a".to_string()));
    }

    /// The fastest member wins when no measurement exists for the incumbent.
    #[test]
    fn switches_to_the_fastest_member() {
        let t = urltest(50);
        record(&t, "a", 200);
        record(&t, "b", 30);
        record(&t, "c", 100);
        t.recalculate_best();
        assert_eq!(t.current_best_tag(), Some("b".to_string()));
    }

    /// Hysteresis: a marginally faster member must not cause flapping.
    #[test]
    fn tolerance_prevents_flapping() {
        let t = urltest(50);
        record(&t, "a", 100);
        record(&t, "b", 80); // 20 ms better, inside the 50 ms tolerance
        t.recalculate_best();
        assert_eq!(
            t.current_best_tag(),
            Some("a".to_string()),
            "a 20 ms improvement must not beat the 50 ms tolerance"
        );
    }

    /// …but a clearly faster member still wins.
    #[test]
    fn switches_when_the_improvement_exceeds_tolerance() {
        let t = urltest(50);
        record(&t, "a", 200);
        record(&t, "b", 20); // 180 ms better
        t.recalculate_best();
        assert_eq!(t.current_best_tag(), Some("b".to_string()));
    }

    /// A member with no successful probe must never be selected.
    #[test]
    fn unmeasured_members_are_never_selected() {
        let t = urltest(50);
        record(&t, "b", 10);
        record(&t, "c", 5);
        t.recalculate_best();
        // `a` has no latency entry, so `c` wins despite being listed first.
        assert_eq!(t.current_best_tag(), Some("c".to_string()));
    }

    #[test]
    fn reports_its_candidates() {
        let t = urltest(50);
        assert!(t.is_group());
        assert_eq!(t.group_type(), Some("urltest"));
        assert_eq!(
            t.candidate_outbounds(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert_eq!(t.url(), "http://cp.cloudflare.com/generate_204");
    }
}
