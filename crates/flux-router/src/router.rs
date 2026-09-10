use flux_types::SessionMeta;
use crate::rule::Rule;
use crate::ruleset::RuleSetRegistry;

#[derive(Clone, Debug, Default)]
pub struct Router {
    rules: Vec<Rule>,
    rule_sets: RuleSetRegistry,
    default_outbound: String,
}

impl Router {
    pub fn new(rules: Vec<Rule>, default_outbound: impl Into<String>) -> Self {
        Self {
            rules,
            rule_sets: RuleSetRegistry::new(),
            default_outbound: default_outbound.into(),
        }
    }

    pub fn with_rule_sets(mut self, registry: RuleSetRegistry) -> Self {
        self.rule_sets = registry;
        self
    }

    pub fn route(&self, meta: &SessionMeta) -> &str {
        for rule in &self.rules {
            if rule.matches_with_registry(meta, Some(&self.rule_sets)) {
                return &rule.outbound;
            }
        }
        &self.default_outbound
    }

    pub fn default_outbound(&self) -> &str {
        &self.default_outbound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_types::NetworkType;
    use crate::rule::{DomainMatch, PortRange};

    #[test]
    fn test_router_flow() {
        let rules = vec![
            Rule {
                domains: vec![DomainMatch::Suffix("blocked.com".into())],
                outbound: "block".into(),
                ..Default::default()
            },
            Rule {
                ports: vec![PortRange::single(443)],
                outbound: "vless-out".into(),
                ..Default::default()
            },
        ];

        let router = Router::new(rules, "direct");

        let meta_blocked = SessionMeta::new(
            "127.0.0.1:12345".parse().unwrap(),
            "ads.blocked.com:80".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert_eq!(router.route(&meta_blocked), "block");

        let meta_vless = SessionMeta::new(
            "127.0.0.1:12345".parse().unwrap(),
            "example.com:443".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert_eq!(router.route(&meta_vless), "vless-out");

        let meta_fallback = SessionMeta::new(
            "127.0.0.1:12345".parse().unwrap(),
            "example.com:80".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert_eq!(router.route(&meta_fallback), "direct");
    }
}
