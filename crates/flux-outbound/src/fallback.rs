use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

pub struct FallbackOutbound {
    tag: String,
    outbounds: Vec<String>,
    current_active: Arc<RwLock<String>>,
    url: Option<String>,
    interval: Duration,
    lookup: Arc<dyn OutboundLookup>,
    cancel_token: tokio_util::sync::CancellationToken,
}

impl FallbackOutbound {
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
            cancel_token: tokio_util::sync::CancellationToken::new(),
        }
    }

    pub fn current(&self) -> String {
        self.current_active.read().clone()
    }

    pub fn start_probing(self: &Arc<Self>) {
        if self.url.is_none() {
            return;
        }

        let weak = Arc::downgrade(self);
        let interval = self.interval;
        let token = self.cancel_token.clone();
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

        // 1. If currently active is not the primary candidate, first attempt the primary candidate
        if let Some(primary) = self.outbounds.first()
            && primary != &active
            && let Some(outbound) = self.lookup.get(primary)
            && let Ok(stream) = outbound.dial_stream(meta).await
        {
            debug!(
                "[{}] Primary fallback node '{}' recovered, switching back",
                self.tag, primary
            );
            *self.current_active.write() = primary.clone();
            return Ok(stream);
        }

        // 2. Try the currently active candidate
        if let Some(outbound) = self.lookup.get(&active) {
            match outbound.dial_stream(meta).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    warn!(
                        "[{}] Primary fallback node '{}' failed dial: {}. Falling back to next candidates...",
                        self.tag, active, e
                    );
                }
            }
        }

        // 3. Try remaining candidates in priority order
        for candidate_tag in &self.outbounds {
            if candidate_tag == &active {
                continue;
            }
            if let Some(outbound) = self.lookup.get(candidate_tag)
                && let Ok(stream) = outbound.dial_stream(meta).await
            {
                debug!(
                    "[{}] Switched active fallback to '{}'",
                    self.tag, candidate_tag
                );
                *self.current_active.write() = candidate_tag.clone();
                return Ok(stream);
            }
        }

        Err(FluxError::Network(format!(
            "all candidate outbounds in fallback group '{}' failed",
            self.tag
        )))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let active = self.current();
        if let Some(outbound) = self.lookup.get(&active) {
            match outbound.dial_packet(meta).await {
                Ok(ep) => return Ok(ep),
                Err(e) => {
                    warn!(
                        "[{}] Primary fallback UDP node '{}' failed: {}. Falling back...",
                        self.tag, active, e
                    );
                }
            }
        }

        for candidate_tag in &self.outbounds {
            if candidate_tag == &active {
                continue;
            }
            if let Some(outbound) = self.lookup.get(candidate_tag)
                && let Ok(ep) = outbound.dial_packet(meta).await
            {
                *self.current_active.write() = candidate_tag.clone();
                return Ok(ep);
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
        self.cancel_token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `stop()` must cancel the probe loop so a reload does not leak it.
    #[test]
    fn stop_cancels_probing() {
        let f = std::sync::Arc::new(fallback(&["a"]));
        assert!(!f.cancel_token.is_cancelled());
        f.stop();
        assert!(f.cancel_token.is_cancelled());
    }

    /// A per-destination member must make the whole group per-destination.
    #[test]
    fn delegates_per_destination_flag() {
        let reg = crate::selector::test_support::FakeRegistry::of(&[("vm", true), ("a", false)]);
        let f = FallbackOutbound::new("fb", vec!["vm".into(), "a".into()], None, None, reg);
        assert!(f.udp_endpoint_per_destination());
    }
}
