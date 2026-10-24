use async_trait::async_trait;
use dashmap::DashMap;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
    TargetAddress,
};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

/// /// Measures each member against a URL and uses the fastest.
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
    /// The token of the running probe loop, if any. `None` before the first
    /// `start_probing()`; holds a cancelled token after `stop()` so that a
    /// later start can install a fresh one.
    probe_loop: Mutex<Option<tokio_util::sync::CancellationToken>>,
}

impl UrlTestOutbound {
    /// A group named `tag` over `members`, probing `url`.
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
            probe_loop: Mutex::new(None),
        }
    }

    /// Spawns the background health check probe loop.
    ///
    /// Idempotent while the loop runs: a second call must not add a second loop,
    /// which would double every member's probe rate. Re-armable after `stop()`:
    /// an `Instance` can be stopped and started again, and a group that came
    /// back from a stop with a permanently cancelled token would never probe
    /// again for the rest of the process's life.
    pub fn start_probing(self: &Arc<Self>) {
        let token = {
            let mut slot = self.probe_loop.lock();
            if slot.as_ref().is_some_and(|t| !t.is_cancelled()) {
                return;
            }
            let token = tokio_util::sync::CancellationToken::new();
            *slot = Some(token.clone());
            token
        };

        let weak = Arc::downgrade(self);
        let interval = self.interval;
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

    /// Probes every member once and updates the choice.
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

    /// The fastest member from the last probe, if any succeeded.
    pub fn current_best_tag(&self) -> Option<String> {
        self.current_best.read().clone()
    }

    /// The URL being probed.
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

        if let Some(outbound) = self.lookup.get(&best) {
            return Ok(outbound);
        }

        // The remembered best can go stale (a reload rebuilt the registry). Dial
        // a candidate that still exists instead of failing every session: the
        // latency table is advisory, the member list is the contract. The
        // remembered tag is left alone — the next probe round replaces it.
        for candidate in &self.outbounds {
            if let Some(outbound) = self.lookup.get(candidate) {
                debug!(
                    "[{}] best outbound '{}' is no longer in the registry; dialing '{}' instead",
                    self.tag, best, candidate
                );
                return Ok(outbound);
            }
        }

        Err(FluxError::OutboundNotFound(format!(
            "urltest '{}': active outbound '{}' not found in registry, and no candidate resolves",
            self.tag, best
        )))
    }

    /// Cancels the probe loop. Idempotent, and does not prevent a later
    /// `start_probing()` from arming a new one.
    pub fn stop_probing(&self) {
        if let Some(token) = self.probe_loop.lock().as_ref() {
            token.cancel();
        }
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
        self.stop_probing();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::test_support::{
        FakeRegistry, LiveRegistry, ScriptedOutbound, http_responder, meta,
    };

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

    // -----------------------------------------------------------------------
    // Failover, staleness and the probe loop
    // -----------------------------------------------------------------------

    /// The remembered best tag can go stale under a live group: a reload
    /// rebuilds the registry, so the member it names is gone while another
    /// candidate is alive. Failing every session for ever is not acceptable.
    #[tokio::test]
    async fn dials_a_live_candidate_when_the_best_is_gone() {
        let live: Arc<dyn Outbound> = Arc::new(ScriptedOutbound::new("b", true));
        let t = UrlTestOutbound::new(
            "ut",
            vec!["a".to_string(), "b".to_string()],
            None,
            None,
            None,
            FakeRegistry::over(vec![live]),
        );
        assert_eq!(t.current_best_tag(), Some("a".to_string()));
        assert!(
            t.dial_stream(&meta()).await.is_ok(),
            "the group must dial the member that still exists"
        );
        assert!(t.dial_packet(&meta()).await.is_ok());
    }

    /// Selection follows the measurements in both directions: a member that
    /// starts failing is dropped, and a member that recovers is selectable
    /// again. A failed probe is never a permanent death sentence.
    #[tokio::test]
    async fn a_recovered_member_is_selected_again() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", false).with_responder(responder));
        let b = Arc::new(ScriptedOutbound::new("b", true).with_responder(responder));
        let reg = LiveRegistry::over(vec![a.clone(), b.clone()]);
        let t = UrlTestOutbound::new(
            "ut",
            vec!["a".to_string(), "b".to_string()],
            None,
            None,
            None,
            reg,
        );

        t.probe_all().await;
        assert!(
            t.latencies.get("a").is_none(),
            "a failed probe must not leave a measurement behind"
        );
        assert_eq!(t.current_best_tag(), Some("b".to_string()));

        a.set_healthy(true);
        b.set_healthy(false);
        t.probe_all().await;
        assert_eq!(
            t.current_best_tag(),
            Some("a".to_string()),
            "the recovered member must be selectable again"
        );
        assert!(t.dial_stream(&meta()).await.is_ok());
    }

    /// A member that disappears from the registry must not be resurrected by a
    /// probe result that arrived for it: its measurement is dropped, and the
    /// group keeps dialing the members it still has.
    #[tokio::test]
    async fn a_vanished_member_is_not_resurrected() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", true).with_responder(responder));
        let b = Arc::new(ScriptedOutbound::new("b", true).with_responder(responder));
        let reg = LiveRegistry::over(vec![a.clone(), b.clone()]);
        let t = UrlTestOutbound::new(
            "ut",
            vec!["a".to_string(), "b".to_string()],
            None,
            None,
            Some(Duration::ZERO),
            reg.clone(),
        );

        t.probe_all().await;
        assert!(t.latencies.contains_key("a") && t.latencies.contains_key("b"));

        reg.remove("a");
        t.probe_all().await;
        assert!(
            !t.latencies.contains_key("a"),
            "a member that no longer exists must not keep a latency"
        );
        assert_eq!(t.current_best_tag(), Some("b".to_string()));
        assert!(t.dial_stream(&meta()).await.is_ok());
    }

    /// One group owns one probe loop: a repeated `start_probing()` must not
    /// double the probe rate (twice the connections, twice the load on the
    /// members), and a group that was stopped must be able to resume — an
    /// `Instance` can be stopped and started again.
    #[tokio::test]
    async fn the_probe_loop_is_single_and_resumable() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", true).with_responder(responder));
        let group = Arc::new(UrlTestOutbound::new(
            "ut",
            vec!["a".to_string()],
            None,
            Some(Duration::from_millis(40)),
            None,
            FakeRegistry::over(vec![a.clone()]),
        ));

        group.start_probing();
        group.start_probing();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let while_running = a.stream_dials();
        assert!(
            while_running >= 4,
            "the probe loop never ran: {while_running} probes in 400 ms"
        );
        assert!(
            while_running < 16,
            "a second start_probing() doubled the probe rate: {while_running} probes in 400 ms at a 40 ms interval"
        );
        assert!(
            group.current_best_tag().is_some(),
            "a healthy member must have been measured"
        );

        group.stop();
        tokio::time::sleep(Duration::from_millis(150)).await; // let an in-flight round end
        let stopped = a.stream_dials();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(a.stream_dials(), stopped, "stop() must end the probe loop");

        group.start_probing();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            a.stream_dials() > stopped,
            "a stopped group must resume probing when it is started again"
        );
    }

    /// When every member is down the group keeps its last selection instead of
    /// dropping to "no member at all": the next dial still names a member (and
    /// fails on its own error), and a probe round that finds a healthy member
    /// recovers the group.
    #[tokio::test]
    async fn an_all_unhealthy_group_keeps_a_member_to_dial() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", true).with_responder(responder));
        let b = Arc::new(ScriptedOutbound::new("b", true).with_responder(responder));
        let t = UrlTestOutbound::new(
            "ut",
            vec!["a".to_string(), "b".to_string()],
            None,
            None,
            Some(Duration::ZERO),
            LiveRegistry::over(vec![a.clone(), b.clone()]),
        );

        t.probe_all().await;
        assert!(t.current_best_tag().is_some());

        a.set_healthy(false);
        b.set_healthy(false);
        t.probe_all().await;
        assert!(
            t.current_best_tag().is_some(),
            "an unhealthy group must still name a member to dial"
        );
        assert!(t.latencies.is_empty(), "no measurement survived");
        assert!(t.dial_stream(&meta()).await.is_err());

        b.set_healthy(true);
        t.probe_all().await;
        assert_eq!(t.current_best_tag(), Some("b".to_string()));
        assert!(t.dial_stream(&meta()).await.is_ok());
    }

    /// An empty group must probe and dial without panicking.
    #[tokio::test]
    async fn an_empty_group_is_not_a_panic() {
        let t = UrlTestOutbound::new(
            "ut",
            vec![],
            None,
            None,
            None,
            crate::selector::test_support::FakeRegistry::over(vec![]),
        );
        t.probe_all().await;
        assert_eq!(t.current_best_tag(), None);
        assert!(t.dial_stream(&meta()).await.is_err());
        assert!(t.dial_packet(&meta()).await.is_err());
    }

    /// Probing and dialing from many tasks at once: no panic, no deadlock, and
    /// the selection is always one of the configured members.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_probing_and_dialing_stay_consistent() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", true).with_responder(responder));
        let b = Arc::new(ScriptedOutbound::new("b", true).with_responder(responder));
        let t = Arc::new(UrlTestOutbound::new(
            "ut",
            vec!["a".to_string(), "b".to_string()],
            None,
            None,
            Some(Duration::ZERO),
            LiveRegistry::over(vec![a, b]),
        ));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let t = t.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..24 {
                    t.probe_all().await;
                    let best = t.current_best_tag();
                    assert!(
                        matches!(best.as_deref(), Some("a") | Some("b")),
                        "selection left the member list: {best:?}"
                    );
                    assert!(t.dial_stream(&meta()).await.is_ok());
                    assert!(t.dial_packet(&meta()).await.is_ok());
                }
            }));
        }
        for task in tasks {
            task.await.expect("no task may panic");
        }
        assert!(matches!(
            t.current_best_tag().as_deref(),
            Some("a") | Some("b")
        ));
    }
}
