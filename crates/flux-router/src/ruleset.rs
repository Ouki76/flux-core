use std::collections::HashMap;
use std::sync::Arc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use flux_types::SessionMeta;
use crate::rule::DomainMatch;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleSet {
    pub tag: String,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,

    #[serde(skip)]
    pub parsed_cidrs: Vec<IpNet>,
    #[serde(skip)]
    pub parsed_domains: Vec<DomainMatch>,
}

impl RuleSet {
    pub fn compile(&mut self) {
        self.parsed_cidrs = self
            .ip_cidr
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();

        self.parsed_domains.clear();
        for d in &self.domain {
            self.parsed_domains.push(DomainMatch::Exact(d.clone()));
        }
        for s in &self.domain_suffix {
            self.parsed_domains.push(DomainMatch::Suffix(s.clone()));
        }
        for k in &self.domain_keyword {
            self.parsed_domains.push(DomainMatch::Keyword(k.clone()));
        }
    }

    pub fn matches(&self, meta: &SessionMeta) -> bool {
        match &meta.destination {
            flux_types::TargetAddress::Ip(sock) => {
                let ip = sock.ip();
                self.parsed_cidrs.iter().any(|c| c.contains(&ip))
            }
            flux_types::TargetAddress::Domain(domain, _) => {
                self.parsed_domains.iter().any(|dm| dm.matches(domain))
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuleSetRegistry {
    rule_sets: HashMap<String, Arc<RuleSet>>,
}

impl RuleSetRegistry {
    pub fn new() -> Self {
        Self {
            rule_sets: HashMap::new(),
        }
    }

    pub fn insert(&mut self, mut ruleset: RuleSet) {
        ruleset.compile();
        self.rule_sets.insert(ruleset.tag.clone(), Arc::new(ruleset));
    }

    pub fn get(&self, tag: &str) -> Option<Arc<RuleSet>> {
        self.rule_sets.get(tag).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_types::{NetworkType, TargetAddress};

    #[test]
    fn test_ruleset_matching() {
        let mut rs = RuleSet {
            tag: "geosite-social".into(),
            domain_suffix: vec!["instagram.com".into(), "facebook.com".into()],
            ip_cidr: vec!["157.240.0.0/16".into()],
            ..Default::default()
        };
        rs.compile();

        let meta1 = SessionMeta::new(
            "127.0.0.1:1000".parse().unwrap(),
            TargetAddress::domain("cdn.instagram.com", 443),
            "in",
            NetworkType::Tcp,
        );
        assert!(rs.matches(&meta1));

        let meta2 = SessionMeta::new(
            "127.0.0.1:1000".parse().unwrap(),
            TargetAddress::domain("google.com", 443),
            "in",
            NetworkType::Tcp,
        );
        assert!(!rs.matches(&meta2));
    }
}
