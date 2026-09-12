use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use flux_types::SessionMeta;

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
    pub exact_set: HashSet<String>,
    #[serde(skip)]
    pub suffix_set: HashSet<String>,
    #[serde(skip)]
    pub keyword_list: Vec<String>,
}

impl RuleSet {
    pub fn compile(&mut self) {
        self.parsed_cidrs = self
            .ip_cidr
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();

        self.exact_set.clear();
        for d in &self.domain {
            self.exact_set.insert(d.trim().to_ascii_lowercase());
        }

        self.suffix_set.clear();
        for s in &self.domain_suffix {
            let clean = s.trim().trim_start_matches('.').to_ascii_lowercase();
            self.suffix_set.insert(clean);
        }

        self.keyword_list = self
            .domain_keyword
            .iter()
            .map(|k| k.trim().to_ascii_lowercase())
            .collect();
    }

    pub fn matches(&self, meta: &SessionMeta) -> bool {
        match &meta.destination {
            flux_types::TargetAddress::Ip(sock) => {
                let ip = sock.ip();
                self.parsed_cidrs.iter().any(|c| c.contains(&ip))
            }
            flux_types::TargetAddress::Domain(domain, _) => {
                let domain_lower = domain.trim().to_ascii_lowercase();

                // 1. O(1) Exact domain lookup
                if self.exact_set.contains(&domain_lower) {
                    return true;
                }

                // 2. O(L) Suffix domain lookup by climbing domain hierarchy
                if self.suffix_set.contains(&domain_lower) {
                    return true;
                }

                let mut current = domain_lower.as_str();
                while let Some(dot_idx) = current.find('.') {
                    current = &current[dot_idx + 1..];
                    if self.suffix_set.contains(current) {
                        return true;
                    }
                }

                // 3. Keyword scan
                if !self.keyword_list.is_empty()
                    && self.keyword_list.iter().any(|k| domain_lower.contains(k))
                {
                    return true;
                }

                false
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
