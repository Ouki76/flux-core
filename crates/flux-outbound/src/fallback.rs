use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

/// /// Uses the first candidate that works, and remembers a failing one.
pub struct FallbackOutbound {
    tag: String,
    outbounds: Vec<String>,
    current_active: Arc<RwLock<String>>,
    url: Option<String>,
    interval: Duration,
    lookup: Arc<dyn OutboundLookup>,
    /// The token of the running probe loop, if any. `None` before the first
    /// `start_probing()`; holds a cancelled token after `stop()` so a later
    /// start can install a fresh one.
    probe_loop: Mutex<Option<tokio_util::sync::CancellationToken>>,
}

impl FallbackOutbound {
    /// A fallback group over `candidates`, in preference order.
    pub fn new(
        tag: impl Into<String>,
        outbounds: Vec<String>,
        url: Option<String>,
        interval: Option<Duration>,
        lookup: Arc<dyn OutboundLookup>,
    ) -> Self {
        let initial = outbounds
            .first()
            .cloned()
            .unwrap_or_else(|| "direct".into());
        Self {
            tag: tag.into(),
            outbounds,
            current_active: Arc::new(RwLock::new(initial)),
            url,
            interval: interval.unwrap_or(Duration::from_secs(300)),
            lookup,
            probe_loop: Mutex::new(None),
        }
    }

    /// The candidate currently in use.
    pub fn current(&self) -> String {
        self.current_active.read().clone()
    }

    /// Arms the probe loop.
    ///
    /// Idempotent while the loop runs: a second call must not add a second
    /// loop, which would double every member's probe rate. Re-armable after
    /// `stop()`: an `Instance` can be stopped and started again, and a group
    /// whose token stays cancelled would never probe again.
    pub fn start_probing(self: &Arc<Self>) {
        if self.url.is_none() {
            return;
        }

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
                        this.probe_candidates().await;
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
                        this.probe_candidates().await;
                    }
                }
            }
        });
    }

    /// The members in the order they must be tried: the primary first (the
    /// documented "first healthy candidate wins"), then the currently selected
    /// member, then the rest in configuration order — each member exactly once.
    ///
    /// Trying the primary first is what makes the group fail *back*, and the
    /// dedup is what keeps a failover cheap: without it the primary was dialed
    /// twice per session once the group had moved to a backup.
    fn dial_order<'a>(&'a self, active: &'a str) -> Vec<&'a str> {
        let mut order: Vec<&str> = Vec::with_capacity(self.outbounds.len() + 2);
        if let Some(primary) = self.outbounds.first() {
            order.push(primary.as_str());
        }
        if !order.contains(&active) {
            order.push(active);
        }
        // A linear `contains` check is smaller and faster than a `HashSet` for
        // the handful of members a group has, and it allocates nothing per
        // member on a path that runs once per session.
        for candidate in &self.outbounds {
            if !order.contains(&candidate.as_str()) {
                order.push(candidate.as_str());
            }
        }
        order
    }

    /// Cancels the probe loop. Idempotent, and does not prevent a later
    /// `start_probing()` from arming a new one.
    pub fn stop_probing(&self) {
        if let Some(token) = self.probe_loop.lock().as_ref() {
            token.cancel();
        }
    }

    /// Re-tests candidates after the active one failed.
    pub async fn probe_candidates(&self) {
        let Some(ref test_url) = self.url else {
            return;
        };

        let (target_addr, host_header, request_path, is_tls) =
            flux_types::parse_probe_url(test_url);

        for candidate_tag in &self.outbounds {
            let Some(outbound) = self.lookup.get(candidate_tag) else {
                continue;
            };

            let probe_result = crate::probe::probe_outbound(
                &outbound,
                &target_addr,
                &host_header,
                &request_path,
                is_tls,
                &format!("{}-fallback-probe", self.tag),
                Duration::from_secs(4),
            )
            .await
            .is_some();

            if probe_result {
                let mut guard = self.current_active.write();
                if *guard != *candidate_tag {
                    debug!(
                        "[{}] Fallback switched primary to '{}'",
                        self.tag, candidate_tag
                    );
                    *guard = candidate_tag.clone();
                }
                return;
            }
        }
    }
}

#[async_trait]
impl Outbound for FallbackOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "fallback"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let active = self.current();

        for candidate_tag in self.dial_order(&active) {
            let Some(outbound) = self.lookup.get(candidate_tag) else {
                continue;
            };
            match outbound.dial_stream(meta).await {
                Ok(stream) => {
                    if candidate_tag != active {
                        debug!(
                            "[{}] Switched active fallback to '{}'",
                            self.tag, candidate_tag
                        );
                        *self.current_active.write() = candidate_tag.to_string();
                    }
                    return Ok(stream);
                }
                Err(e) => {
                    warn!(
                        "[{}] Fallback candidate '{}' failed dial: {}. Trying next...",
                        self.tag, candidate_tag, e
                    );
                }
            }
        }

        Err(FluxError::Network(format!(
            "all candidate outbounds in fallback group '{}' failed",
            self.tag
        )))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        // Same priority order and the same recovery as `dial_stream`: whether a
        // group is currently on its primary must not depend on which protocol
        // was dialed last.
        let active = self.current();

        for candidate_tag in self.dial_order(&active) {
            let Some(outbound) = self.lookup.get(candidate_tag) else {
                continue;
            };
            match outbound.dial_packet(meta).await {
                Ok(endpoint) => {
                    if candidate_tag != active {
                        debug!(
                            "[{}] Switched active fallback UDP to '{}'",
                            self.tag, candidate_tag
                        );
                        *self.current_active.write() = candidate_tag.to_string();
                    }
                    return Ok(endpoint);
                }
                Err(e) => {
                    warn!(
                        "[{}] Fallback UDP candidate '{}' failed: {}. Trying next...",
                        self.tag, candidate_tag, e
                    );
                }
            }
        }

        Err(FluxError::Network(format!(
            "all candidate outbounds in fallback group '{}' failed for UDP",
            self.tag
        )))
    }

    fn udp_endpoint_per_destination(&self) -> bool {
        // Delegate to the member that actually carries the datagrams: a VMess
        // member behind a group still needs one association per destination, and
        // the dispatcher's cache key must agree with the member's behaviour.
        let active = self.current();
        self.lookup
            .get(&active)
            .map(|m| m.udp_endpoint_per_destination())
            .unwrap_or(false)
    }

    fn is_group(&self) -> bool {
        true
    }

    fn group_type(&self) -> Option<&'static str> {
        Some("fallback")
    }

    fn current_selected(&self) -> Option<String> {
        Some(self.current())
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
    use crate::selector::test_support::{LiveRegistry, ScriptedOutbound, http_responder, meta};

    fn fallback(tags: &[&str]) -> FallbackOutbound {
        FallbackOutbound::new(
            "fb",
            tags.iter().map(|s| s.to_string()).collect(),
            None,
            None,
            crate::selector::test_support::FakeRegistry::of(&[("a", false), ("b", false)]),
        )
    }

    /// The group starts on its primary member, in the configured order.
    #[test]
    fn starts_on_the_primary_member() {
        assert_eq!(fallback(&["a", "b"]).current(), "a");
    }

    /// With no members the group must fall back to `direct` rather than an empty
    /// tag that would never resolve.
    #[test]
    fn empty_group_falls_back_to_direct() {
        assert_eq!(fallback(&[]).current(), "direct");
    }

    #[test]
    fn reports_its_candidates_and_current_selection() {
        let f = fallback(&["a", "b"]);
        assert!(f.is_group());
        assert_eq!(f.group_type(), Some("fallback"));
        assert_eq!(f.current_selected(), Some("a".to_string()));
        assert_eq!(
            f.candidate_outbounds(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    /// A per-destination member must make the whole group per-destination.
    #[test]
    fn delegates_per_destination_flag() {
        let reg = crate::selector::test_support::FakeRegistry::of(&[("vm", true), ("a", false)]);
        let f = FallbackOutbound::new("fb", vec!["vm".into(), "a".into()], None, None, reg);
        assert!(f.udp_endpoint_per_destination());
    }

    // -----------------------------------------------------------------------
    // Failover
    // -----------------------------------------------------------------------

    /// Two scripted members plus the registry that holds them, so a test can
    /// read the per-member dial counters and flip health at runtime.
    fn scripted(
        tags: &[&str],
    ) -> (
        Arc<ScriptedOutbound>,
        Arc<ScriptedOutbound>,
        Arc<LiveRegistry>,
    ) {
        let a = Arc::new(ScriptedOutbound::new(tags[0], true));
        let b = Arc::new(ScriptedOutbound::new(tags[1], true));
        let reg = LiveRegistry::over(vec![a.clone(), b.clone()]);
        (a, b, reg)
    }

    fn group(reg: Arc<LiveRegistry>, tags: &[&str]) -> FallbackOutbound {
        FallbackOutbound::new(
            "fb",
            tags.iter().map(|s| s.to_string()).collect(),
            None,
            None,
            reg,
        )
    }

    /// TCP fails over to a live member, and — the documented "first healthy
    /// candidate wins" — returns to the primary once it answers again.
    #[tokio::test]
    async fn tcp_fails_over_and_recovers() {
        let (a, b, reg) = scripted(&["a", "b"]);
        a.set_healthy(false);
        let f = group(reg, &["a", "b"]);

        assert!(f.dial_stream(&meta()).await.is_ok(), "b must serve");
        assert_eq!(f.current(), "b", "the group is now on the backup");

        a.set_healthy(true);
        assert!(f.dial_stream(&meta()).await.is_ok());
        assert_eq!(f.current(), "a", "the recovered primary must win again");
        assert_eq!(b.stream_dials(), 1, "b is only dialed while a is down");
    }

    /// UDP must follow the same policy as TCP: the group is one group, and an
    /// operator's failover must not depend on which protocol happened to be
    /// dialed first. A group that never returns to its primary for datagrams is
    /// stuck on the backup for the life of the process.
    #[tokio::test]
    async fn udp_fails_over_and_recovers() {
        let (a, _b, reg) = scripted(&["a", "b"]);
        a.set_healthy(false);
        let f = group(reg, &["a", "b"]);

        assert!(f.dial_packet(&meta()).await.is_ok(), "b must serve");
        assert_eq!(f.current(), "b");

        a.set_healthy(true);
        assert!(f.dial_packet(&meta()).await.is_ok());
        assert_eq!(
            f.current(),
            "a",
            "UDP must recover to the primary exactly like TCP does"
        );
    }

    /// One failed dial must not cost a second attempt at the same member: the
    /// candidates are tried in priority order, once each. Before this was fixed
    /// the primary was dialed twice (recovery step, then the remaining-candidates
    /// loop), which doubled the failover time of a 2-member group.
    #[tokio::test]
    async fn a_failing_dial_never_retries_a_member() {
        let (a, b, reg) = scripted(&["a", "b"]);
        let f = group(reg, &["a", "b"]);

        // Get the group onto the backup first, then take both members down.
        a.set_healthy(false);
        assert!(f.dial_stream(&meta()).await.is_ok());
        assert_eq!(f.current(), "b");

        b.set_healthy(false);
        let a_before = a.stream_dials();
        let b_before = b.stream_dials();

        let outcome = f.dial_stream(&meta()).await;
        let err = match outcome {
            Err(e) => e,
            Ok(_) => panic!("both members are down, the dial must fail"),
        };
        assert!(
            matches!(err, FluxError::Network(_)),
            "the group must report a network failure, got {err:?}"
        );
        assert_eq!(
            a.stream_dials() - a_before,
            1,
            "the primary must be dialed once, not once per failover step"
        );
        assert_eq!(
            b.stream_dials() - b_before,
            1,
            "the backup must be dialed once"
        );
    }

    /// Both protocols must try every member exactly once when all of them fail
    /// for UDP too.
    #[tokio::test]
    async fn a_failing_udp_dial_never_retries_a_member() {
        let (a, b, reg) = scripted(&["a", "b"]);
        a.set_healthy(false);
        b.set_healthy(false);
        let f = group(reg, &["a", "b"]);

        assert!(f.dial_packet(&meta()).await.is_err());
        assert_eq!(a.packet_dials(), 1);
        assert_eq!(b.packet_dials(), 1);
    }

    /// An empty candidate list cannot be produced by the config validator, but
    /// the group must still dial something rather than fail for ever: it falls
    /// back to `direct`.
    #[tokio::test]
    async fn an_empty_group_still_dials_direct() {
        let direct: Arc<dyn Outbound> = Arc::new(ScriptedOutbound::new("direct", true));
        let reg = LiveRegistry::over(vec![direct]);
        let f = FallbackOutbound::new("fb", vec![], None, None, reg);
        assert_eq!(f.current(), "direct");
        assert!(f.dial_stream(&meta()).await.is_ok());
        assert!(f.dial_packet(&meta()).await.is_ok());
    }

    /// A member removed from the registry must not stop the group from dialing
    /// the members it still has.
    #[tokio::test]
    async fn dials_a_live_member_when_the_active_one_vanishes() {
        let (a, _b, reg) = scripted(&["a", "b"]);
        let f = group(reg.clone(), &["a", "b"]);
        // Fail over to b first so that `active` is a real member that then goes
        // away, which is what a reload does to a group.
        a.set_healthy(false);
        assert!(f.dial_stream(&meta()).await.is_ok());
        // The backup vanishes (a reload) while the primary recovers.
        a.set_healthy(true);
        reg.remove("b");
        assert!(
            f.dial_stream(&meta()).await.is_ok(),
            "the other candidate still exists"
        );
    }

    // -----------------------------------------------------------------------
    // The probe loop
    // -----------------------------------------------------------------------

    /// One group owns one probe loop. A repeated `start_probing()` must not
    /// double the rate, `stop()` must end it, and a stopped group must be able
    /// to resume — an `Instance` can be stopped and started again.
    #[tokio::test]
    async fn the_probe_loop_is_single_and_resumable() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", true).with_responder(responder));
        let reg = LiveRegistry::over(vec![a.clone()]);
        let f = Arc::new(FallbackOutbound::new(
            "fb",
            vec!["a".to_string()],
            Some("http://127.0.0.1:1/generate_204".to_string()),
            Some(Duration::from_millis(40)),
            reg,
        ));

        f.start_probing();
        f.start_probing();
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

        f.stop();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let stopped = a.stream_dials();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(a.stream_dials(), stopped, "stop() must end the probe loop");

        f.start_probing();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            a.stream_dials() > stopped,
            "a stopped group must resume probing when it is started again"
        );
    }

    /// Probing stops at the first healthy candidate in priority order, even when
    /// earlier candidates are dead — and a dead candidate is retried on the next
    /// round, so it can never be permanently written off.
    #[tokio::test]
    async fn probing_skips_dead_members_and_retries_them() {
        let responder = http_responder().await;
        let a = Arc::new(ScriptedOutbound::new("a", false).with_responder(responder));
        let b = Arc::new(ScriptedOutbound::new("b", true).with_responder(responder));
        let reg = LiveRegistry::over(vec![a.clone(), b.clone()]);
        let f = FallbackOutbound::new(
            "fb",
            vec!["a".to_string(), "b".to_string()],
            Some("http://127.0.0.1:1/generate_204".to_string()),
            None,
            reg,
        );

        f.probe_candidates().await;
        assert_eq!(f.current(), "b", "the first healthy candidate wins");
        assert_eq!(a.stream_dials(), 1, "the dead primary must be tried");

        a.set_healthy(true);
        f.probe_candidates().await;
        assert_eq!(f.current(), "a", "a recovered primary must be retried");
    }

    // -----------------------------------------------------------------------
    // Concurrency
    // -----------------------------------------------------------------------

    /// Many tasks dialing while the active member flips: no panic, no deadlock,
    /// and the selection is always one of the configured members.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_dialing_keeps_a_member_selected() {
        let (a, b, reg) = scripted(&["a", "b"]);
        let f = Arc::new(group(reg, &["a", "b"]));

        let mut tasks = Vec::new();
        for worker in 0..12 {
            let f = f.clone();
            let a = a.clone();
            let b = b.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..32 {
                    // Flap the members while other tasks are dialing.
                    if (worker + i) % 7 == 0 {
                        a.set_healthy((worker + i) % 14 == 0);
                        b.set_healthy((worker + i) % 3 != 0);
                    }
                    let _ = f.dial_stream(&meta()).await;
                    let _ = f.dial_packet(&meta()).await;
                    let current = f.current();
                    assert!(
                        current == "a" || current == "b",
                        "selection left the member list: {current}"
                    );
                }
            }));
        }
        for task in tasks {
            task.await.expect("no task may panic");
        }
        a.set_healthy(true);
        b.set_healthy(true);
        assert!(f.dial_stream(&meta()).await.is_ok());
        assert!(matches!(f.current().as_str(), "a" | "b"));
    }
}
