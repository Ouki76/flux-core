use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use flux_types::SessionMeta;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleSet {
    pub tag: String,
    #[serde(default)]
    pub path: Option<String>,
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
    pub fn load_from_file(&mut self, path: &str) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(rest) = line.strip_prefix("full:") {
                self.domain.push(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("domain:") {
                self.domain_suffix.push(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("keyword:") {
                self.domain_keyword.push(rest.trim().to_string());
            } else if line.contains('/') || line.parse::<std::net::IpAddr>().is_ok() {
                self.ip_cidr.push(line.to_string());
            } else {
                self.domain_suffix.push(line.to_string());
            }
        }
        Ok(())
    }

    pub fn compile(&mut self) {
        if let Some(p) = &self.path.clone() {
            let _ = self.load_from_file(p);
        }

        self.parsed_cidrs = self
            .ip_cidr
            .iter()
            .filter_map(|s| {
                if s.contains('/') {
                    s.parse::<IpNet>().ok()
                } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                    IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok()
                } else {
                    None
                }
            })
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

    #[test]
    fn test_ruleset_load_from_file() {
        let file_path = std::env::temp_dir().join(format!("test_domains_{}.txt", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&file_path, "full:exact.com\n.subdomain.org\nkeyword:tele\n1.2.3.4/32\n").unwrap();

        let mut rs = RuleSet {
            tag: "file-rules".into(),
            path: Some(file_path.to_str().unwrap().to_string()),
            ..Default::default()
        };
        rs.compile();

        let meta = SessionMeta::new(
            "127.0.0.1:1000".parse().unwrap(),
            TargetAddress::domain("exact.com", 80),
            "in",
            NetworkType::Tcp,
        );
        assert!(rs.matches(&meta));
        let _ = std::fs::remove_file(&file_path);
    }
}
