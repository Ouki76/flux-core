use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint, SessionMeta,
};
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::warn;

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
        if let Some(outbound) = self.lookup.get(&current_tag) {
            return Ok(outbound);
        }

        // The recorded selection can go stale — a reload rebuilds the registry,
        // so the member the user picked may no longer exist while other members
        // are alive. Failing every session forever is not an option when the
        // group still has a usable candidate, so fall through to the first
        // resolvable member. The recorded tag is deliberately *not* rewritten:
        // it is the user's choice, and it may resolve again after the next
        // reload.
        for candidate in &self.outbounds {
            if let Some(outbound) = self.lookup.get(candidate) {
                warn!(
                    "[{}] selected outbound '{}' is no longer in the registry; dialing '{}' instead",
                    self.tag, current_tag, candidate
                );
                return Ok(outbound);
            }
        }

        Err(FluxError::OutboundNotFound(format!(
            "selector '{}': selected outbound '{}' not found in registry, and no candidate resolves",
            self.tag, current_tag
        )))
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

#[cfg(test)]
pub(crate) mod test_support {
    //! Minimal fakes shared by the group-outbound unit tests.

    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;

    /// An outbound that records nothing and never dials: the group tests only
    /// exercise selection logic.
    pub struct FakeOutbound {
        pub tag: String,
        pub per_destination: bool,
    }

    impl FakeOutbound {
        pub fn new(tag: &str) -> Self {
            Self {
                tag: tag.to_string(),
                per_destination: false,
            }
        }

        pub fn per_destination(mut self, yes: bool) -> Self {
            self.per_destination = yes;
            self
        }
    }

    #[async_trait]
    impl Outbound for FakeOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }
        fn protocol(&self) -> &'static str {
            "fake"
        }
        async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            Err(FluxError::Protocol {
                protocol: "fake",
                message: "fake outbound cannot dial".into(),
            })
        }
        async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
            Err(FluxError::Protocol {
                protocol: "fake",
                message: "fake outbound cannot dial".into(),
            })
        }
        fn udp_endpoint_per_destination(&self) -> bool {
            self.per_destination
        }
    }

    /// A UDP association that exists only to prove a packet dial succeeded.
    pub struct FakePacket;

    #[async_trait]
    impl PacketEndpoint for FakePacket {
        async fn send_packet(&self, _packet: flux_types::UdpPacket) -> FluxResult<()> {
            Ok(())
        }
        async fn recv_packet(&self) -> FluxResult<flux_types::UdpPacket> {
            Err(FluxError::Protocol {
                protocol: "fake",
                message: "no packets".into(),
            })
        }
    }

    /// A member whose health and dial outcomes the test controls at runtime, and
    /// which counts every dial attempt it receives.
    ///
    /// A healthy member connects to `responder`, a local server that answers
    /// with an HTTP status line, so a probe through it can genuinely succeed —
    /// the probe loop tests need real measurements, not stubs.
    pub struct ScriptedOutbound {
        pub tag: String,
        healthy: AtomicBool,
        pub stream_dials: AtomicUsize,
        pub packet_dials: AtomicUsize,
        responder: Option<SocketAddr>,
    }

    impl ScriptedOutbound {
        pub fn new(tag: &str, healthy: bool) -> Self {
            Self {
                tag: tag.to_string(),
                healthy: AtomicBool::new(healthy),
                stream_dials: AtomicUsize::new(0),
                packet_dials: AtomicUsize::new(0),
                responder: None,
            }
        }

        pub fn with_responder(mut self, addr: SocketAddr) -> Self {
            self.responder = Some(addr);
            self
        }

        pub fn set_healthy(&self, healthy: bool) {
            self.healthy.store(healthy, Ordering::SeqCst);
        }

        pub fn stream_dials(&self) -> usize {
            self.stream_dials.load(Ordering::SeqCst)
        }

        pub fn packet_dials(&self) -> usize {
            self.packet_dials.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Outbound for ScriptedOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }
        fn protocol(&self) -> &'static str {
            "scripted"
        }
        async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            self.stream_dials.fetch_add(1, Ordering::SeqCst);
            if !self.healthy.load(Ordering::SeqCst) {
                return Err(FluxError::Protocol {
                    protocol: "scripted",
                    message: format!("member '{}' is down", self.tag),
                });
            }
            match self.responder {
                Some(addr) => {
                    let sock = tokio::net::TcpStream::connect(addr)
                        .await
                        .map_err(FluxError::Io)?;
                    Ok(Box::new(sock) as BoxedStream)
                }
                None => {
                    let (client, _server) = tokio::io::duplex(64);
                    Ok(Box::new(client) as BoxedStream)
                }
            }
        }
        async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
            self.packet_dials.fetch_add(1, Ordering::SeqCst);
            if self.healthy.load(Ordering::SeqCst) {
                Ok(Box::new(FakePacket))
            } else {
                Err(FluxError::Protocol {
                    protocol: "scripted",
                    message: format!("member '{}' is down", self.tag),
                })
            }
        }
    }

    /// Spawns a local HTTP/1.1 responder and returns its address. Every probe
    /// connection is answered with a 204 status line, so a member pointed at it
    /// measures a real (small) RTT.
    pub async fn http_responder() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                });
            }
        });
        addr
    }

    pub struct FakeRegistry(pub Vec<Arc<dyn Outbound>>);

    impl FakeRegistry {
        pub fn of(tags: &[(&str, bool)]) -> Arc<Self> {
            Arc::new(Self(
                tags.iter()
                    .map(|(t, per)| {
                        Arc::new(FakeOutbound::new(t).per_destination(*per)) as Arc<dyn Outbound>
                    })
                    .collect(),
            ))
        }

        pub fn over(members: Vec<Arc<dyn Outbound>>) -> Arc<Self> {
            Arc::new(Self(members))
        }
    }

    impl OutboundLookup for FakeRegistry {
        fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
            self.0.iter().find(|o| o.tag() == tag).cloned()
        }
    }

    /// A registry that can change under a live group, like the real one during a
    /// reload: members can disappear (or come back) between two dials.
    #[derive(Default)]
    pub struct LiveRegistry(pub dashmap::DashMap<String, Arc<dyn Outbound>>);

    impl LiveRegistry {
        pub fn over(members: Vec<Arc<dyn Outbound>>) -> Arc<Self> {
            let reg = Arc::new(Self::default());
            for member in members {
                reg.insert(member);
            }
            reg
        }

        pub fn insert(&self, member: Arc<dyn Outbound>) {
            self.0.insert(member.tag().to_string(), member);
        }

        pub fn remove(&self, tag: &str) {
            self.0.remove(tag);
        }
    }

    impl OutboundLookup for LiveRegistry {
        fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
            self.0.get(tag).map(|entry| entry.value().clone())
        }
    }

    pub fn meta() -> SessionMeta {
        SessionMeta::new(
            "127.0.0.1:1000".parse().unwrap(),
            "example.com:443".parse().unwrap(),
            "test",
            flux_types::NetworkType::Tcp,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn selector(default: Option<&str>) -> SelectorOutbound {
        let reg = FakeRegistry::of(&[("a", false), ("b", false)]);
        SelectorOutbound::new(
            "sel",
            vec!["a".into(), "b".into()],
            default.map(String::from),
            reg,
        )
    }

    #[test]
    fn defaults_to_the_first_member() {
        assert_eq!(selector(None).current(), "a");
    }

    #[test]
    fn honours_an_explicit_valid_default() {
        assert_eq!(selector(Some("b")).current(), "b");
    }

    /// A default that is not among the members must not be adopted: otherwise
    /// every dial would fail with "selected outbound not found".
    #[test]
    fn ignores_a_default_outside_the_candidate_list() {
        assert_eq!(selector(Some("nope")).current(), "a");
    }

    #[test]
    fn select_switches_only_to_known_members() {
        let s = selector(None);
        s.select("b").unwrap();
        assert_eq!(s.current(), "b");
        // An unknown target is rejected and the selection is unchanged.
        assert!(s.select("nope").is_err());
        assert_eq!(s.current(), "b");
    }

    #[test]
    fn reports_itself_as_a_selector_group() {
        let s = selector(None);
        assert!(s.is_group());
        assert_eq!(s.group_type(), Some("selector"));
        assert_eq!(
            s.candidate_outbounds(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(s.current_selected(), Some("a".to_string()));
    }

    /// A selection can go stale under the group: a reload can rebuild the
    /// registry, so the tag the group remembers is no longer resolvable while
    /// another candidate is alive. The group must dial the live member instead
    /// of failing every session for the rest of the process's life.
    #[tokio::test]
    async fn dials_a_live_candidate_when_the_selection_is_gone() {
        let live: Arc<dyn Outbound> = Arc::new(ScriptedOutbound::new("b", true));
        let reg = FakeRegistry::over(vec![live]);
        let s = SelectorOutbound::new(
            "sel",
            vec!["a".into(), "b".into()],
            None, // defaults to "a", which the registry does not have
            reg,
        );
        assert_eq!(s.current(), "a");
        let stream = s.dial_stream(&meta()).await;
        assert!(
            stream.is_ok(),
            "the selector must fall through to a live member, got {:?}",
            stream.err().map(|e| e.to_string())
        );
    }

    /// With every candidate missing the group must report the failure rather
    /// than panicking or dialing a made-up tag.
    #[tokio::test]
    async fn reports_an_error_when_no_candidate_resolves() {
        let s = SelectorOutbound::new(
            "sel",
            vec!["a".into(), "b".into()],
            None,
            FakeRegistry::over(vec![]),
        );
        let err = match s.dial_stream(&meta()).await {
            Err(e) => e,
            Ok(_) => panic!("no candidate exists, so the dial must fail"),
        };
        assert!(matches!(err, FluxError::OutboundNotFound(_)), "{err:?}");
        assert!(s.dial_packet(&meta()).await.is_err());
    }

    /// Many tasks switching the selection and dialing at once: no panic, no
    /// deadlock, and whatever is observed must be one of the members.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_select_and_dial_stay_within_the_members() {
        let a: Arc<dyn Outbound> = Arc::new(ScriptedOutbound::new("a", true));
        let b: Arc<dyn Outbound> = Arc::new(ScriptedOutbound::new("b", true));
        let s = Arc::new(SelectorOutbound::new(
            "sel",
            vec!["a".into(), "b".into()],
            None,
            FakeRegistry::over(vec![a, b]),
        ));

        let mut tasks = Vec::new();
        for worker in 0..16 {
            let s = s.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..64 {
                    let target = if (worker + i) % 2 == 0 { "a" } else { "b" };
                    s.select(target).expect("selecting a member must succeed");
                    let current = s.current();
                    assert!(
                        current == "a" || current == "b",
                        "selection left the member list: {current}"
                    );
                    assert!(
                        s.dial_stream(&meta()).await.is_ok(),
                        "both members are healthy"
                    );
                    assert!(
                        s.dial_packet(&meta()).await.is_ok(),
                        "both members are healthy for UDP"
                    );
                }
            }));
        }
        for task in tasks {
            task.await.expect("no task may panic");
        }
        assert!(matches!(s.current().as_str(), "a" | "b"));
    }
}
