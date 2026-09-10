use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use flux_types::{NetworkType, SessionMeta, TargetAddress};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainMatch {
    Exact(String),
    Suffix(String),
    Keyword(String),
}

impl DomainMatch {
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        match self {
            Self::Exact(pattern) => domain_lower == pattern.to_ascii_lowercase(),
            Self::Suffix(suffix) => {
                let suffix_lower = suffix.to_ascii_lowercase();
                let suffix_trimmed = suffix_lower.strip_prefix('.').unwrap_or(&suffix_lower);
                if domain_lower == suffix_trimmed {
                    return true;
                }
                if let Some(rest) = domain_lower.strip_suffix(suffix_trimmed) {
                    rest.ends_with('.')
                } else {
                    false
                }
            }
            Self::Keyword(kw) => domain_lower.contains(&kw.to_ascii_lowercase()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self { start: port, end: port }
    }

    pub fn range(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Rule {
    pub inbound_tags: Vec<String>,
    pub networks: Vec<NetworkType>,
    pub domains: Vec<DomainMatch>,
    pub ip_cidrs: Vec<IpNet>,
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub rule_set: Vec<String>,
    pub outbound: String,
}

impl Rule {
    pub fn matches(&self, meta: &SessionMeta) -> bool {
        self.matches_with_registry(meta, None)
    }

    pub fn matches_with_registry(
        &self,
        meta: &SessionMeta,
        registry: Option<&crate::ruleset::RuleSetRegistry>,
    ) -> bool {
        // Inbound tag match
        if !self.inbound_tags.is_empty() {
            let matched = self.inbound_tags.iter().any(|tag| tag.as_str() == &*meta.inbound_tag);
            if !matched {
                return false;
            }
        }

        // Network match
        if !self.networks.is_empty() {
            if !self.networks.contains(&meta.network) {
                return false;
            }
        }

        // Port match
        if !self.ports.is_empty() {
            let port = meta.destination.port();
            if !self.ports.iter().any(|r| r.contains(port)) {
                return false;
            }
        }

        // RuleSet match
        if !self.rule_set.is_empty() {
            if let Some(reg) = registry {
                let matched = self.rule_set.iter().any(|tag| {
                    reg.get(tag).map(|rs| rs.matches(meta)).unwrap_or(false)
                });
                if !matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Domain or IP match
        match &meta.destination {
            TargetAddress::Domain(domain, _) => {
                if !self.domains.is_empty() {
                    let domain_match = self.domains.iter().any(|d| d.matches(domain));
                    if !domain_match {
                        return false;
                    }
                } else if !self.ip_cidrs.is_empty() {
                    return false;
                }
            }
            TargetAddress::Ip(sock_addr) => {
                if !self.ip_cidrs.is_empty() {
                    let ip = sock_addr.ip();
                    let ip_match = self.ip_cidrs.iter().any(|cidr| cidr.contains(&ip));
                    if !ip_match {
                        return false;
                    }
                } else if !self.domains.is_empty() {
                    return false;
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_domain_matcher() {
        let suffix = DomainMatch::Suffix("google.com".into());
        assert!(suffix.matches("google.com"));
        assert!(suffix.matches("mail.google.com"));
        assert!(suffix.matches("sub.mail.google.com"));
        assert!(!suffix.matches("notgoogle.com"));

        let exact = DomainMatch::Exact("example.org".into());
        assert!(exact.matches("example.org"));
        assert!(!exact.matches("test.example.org"));

        let kw = DomainMatch::Keyword("telegram".into());
        assert!(kw.matches("api.telegram.org"));
        assert!(kw.matches("telegram.me"));
        assert!(!kw.matches("google.com"));
    }

    #[test]
    fn test_ip_cidr_matching() {
        let cidr = IpNet::from_str("192.168.1.0/24").unwrap();
        let rule = Rule {
            ip_cidrs: vec![cidr],
            outbound: "direct".into(),
            ..Default::default()
        };

        let meta1 = SessionMeta::new(
            "127.0.0.1:50000".parse().unwrap(),
            "192.168.1.55:80".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert!(rule.matches(&meta1));

        let meta2 = SessionMeta::new(
            "127.0.0.1:50000".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert!(!rule.matches(&meta2));
    }
}
