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
    }

    impl OutboundLookup for FakeRegistry {
        fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
            self.0.iter().find(|o| o.tag() == tag).cloned()
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
}
