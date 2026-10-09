use flux_types::SessionMeta;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
    pub ip_range_set: crate::ip_range::IpRangeSet,
    #[serde(skip)]
    pub exact_set: HashSet<String>,
    #[serde(skip)]
    pub suffix_set: HashSet<String>,
    #[serde(skip)]
    pub keyword_list: Vec<String>,
}

impl RuleSet {
    /// Parses a single rule line supporting standard V2Ray/Sing-Box prefixes, Clash formats, and CIDRs.
    pub fn parse_rule_line(&mut self, line: &str) {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim()
            .trim_matches('\'')
            .trim_matches('"');
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("payload:")
        {
            return;
        }

        // Handle Clash comma format: "DOMAIN-SUFFIX,google.com" or "IP-CIDR,1.2.3.4/32"
        if let Some((rule_type, val)) = trimmed.split_once(',') {
            let val = val.trim().trim_matches('\'').trim_matches('"');
            match rule_type.trim().to_ascii_uppercase().as_str() {
                "DOMAIN-SUFFIX" => self.domain_suffix.push(val.to_string()),
                "DOMAIN" | "DOMAIN-FULL" => self.domain.push(val.to_string()),
                "DOMAIN-KEYWORD" => self.domain_keyword.push(val.to_string()),
                "IP-CIDR" | "IP-CIDR6" | "CIDR" => self.ip_cidr.push(val.to_string()),
                _ => {}
            }
            return;
        }

        // Handle V2Ray / Sing-Box prefixes
        if let Some(rest) = trimmed
            .strip_prefix("full:")
            .or_else(|| trimmed.strip_prefix("exact:"))
        {
            self.domain.push(rest.trim().to_string());
        } else if let Some(rest) = trimmed
            .strip_prefix("domain:")
            .or_else(|| trimmed.strip_prefix("suffix:"))
        {
            self.domain_suffix.push(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("keyword:") {
            self.domain_keyword.push(rest.trim().to_string());
        } else if let Some(rest) = trimmed
            .strip_prefix("ip-cidr:")
            .or_else(|| trimmed.strip_prefix("cidr:"))
        {
            self.ip_cidr.push(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("+.") {
            self.domain_suffix.push(rest.trim().to_string());
        } else if trimmed.contains('/') || trimmed.parse::<std::net::IpAddr>().is_ok() {
            self.ip_cidr.push(trimmed.to_string());
        } else {
            self.domain_suffix.push(trimmed.to_string());
        }
    }

    pub fn load_from_file(&mut self, path: &str) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            self.parse_rule_line(line);
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

        self.ip_range_set = crate::ip_range::IpRangeSet::from_cidrs(&self.parsed_cidrs);

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
                self.ip_range_set.contains(&ip)
            }
            flux_types::TargetAddress::Domain(domain, _) => {
                // O(1) Exact domain lookup with ASCII case-insensitivity
                let domain_clean = domain.trim();
                let domain_lower;
                let domain_str = if domain_clean.bytes().any(|b| b.is_ascii_uppercase()) {
                    domain_lower = domain_clean.to_ascii_lowercase();
                    domain_lower.as_str()
                } else {
                    domain_clean
                };

                if self.exact_set.contains(domain_str) {
                    return true;
                }

                // O(L) Suffix lookup
                if self.suffix_set.contains(domain_str) {
                    return true;
                }

                let mut current = domain_str;
                while let Some(dot_idx) = current.find('.') {
                    current = &current[dot_idx + 1..];
                    if self.suffix_set.contains(current) {
                        return true;
                    }
                }

                // Keyword scan
                if !self.keyword_list.is_empty()
                    && self.keyword_list.iter().any(|k| domain_str.contains(k))
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
        self.rule_sets
            .insert(ruleset.tag.clone(), Arc::new(ruleset));
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
        let file_path = std::env::temp_dir().join(format!(
            "test_domains_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &file_path,
            "full:exact.com\n.subdomain.org\nkeyword:tele\n1.2.3.4/32\n",
        )
        .unwrap();

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

    #[test]
    fn test_ruleset_clash_yaml_format() {
        let mut rs = RuleSet {
            tag: "clash_test".into(),
            ..Default::default()
        };

        rs.parse_rule_line("payload:");
        rs.parse_rule_line("  - '+.google.com'");
        rs.parse_rule_line("  - 'DOMAIN-SUFFIX,youtube.com'");
        rs.parse_rule_line("  - 'DOMAIN,netflix.com'");
        rs.parse_rule_line("  - 'IP-CIDR,192.168.1.0/24'");
        rs.compile();

        let meta1 = SessionMeta::new(
            "127.0.0.1:0".parse().unwrap(),
            TargetAddress::domain("sub.google.com", 443),
            "in",
            NetworkType::Tcp,
        );
        assert!(rs.matches(&meta1));

        let meta2 = SessionMeta::new(
            "127.0.0.1:0".parse().unwrap(),
            TargetAddress::domain("music.youtube.com", 443),
            "in",
            NetworkType::Tcp,
        );
        assert!(rs.matches(&meta2));

        let meta3 = SessionMeta::new(
            "127.0.0.1:0".parse().unwrap(),
            TargetAddress::domain("netflix.com", 443),
            "in",
            NetworkType::Tcp,
        );
        assert!(rs.matches(&meta3));

        let meta4 = SessionMeta::new(
            "127.0.0.1:0".parse().unwrap(),
            "192.168.1.50:80".parse().unwrap(),
            "in",
            NetworkType::Tcp,
        );
        assert!(rs.matches(&meta4));
    }
}
