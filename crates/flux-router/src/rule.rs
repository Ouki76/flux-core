use flux_types::{NetworkType, SessionMeta, TargetAddress};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainMatch {
    Exact(String),
    Suffix(String),
    Keyword(String),
}

impl DomainMatch {
    pub fn exact(pattern: impl Into<String>) -> Self {
        Self::Exact(pattern.into().to_ascii_lowercase())
    }

    pub fn suffix(suffix: impl Into<String>) -> Self {
        let s = suffix.into().to_ascii_lowercase();
        let clean = s.strip_prefix('.').unwrap_or(&s).to_string();
        Self::Suffix(clean)
    }

    pub fn keyword(kw: impl Into<String>) -> Self {
        Self::Keyword(kw.into().to_ascii_lowercase())
    }

    #[inline]
    pub fn matches(&self, domain_lower: &str) -> bool {
        match self {
            Self::Exact(pattern) => domain_lower.eq_ignore_ascii_case(pattern),
            Self::Suffix(suffix) => {
                let suffix_clean = suffix.strip_prefix('.').unwrap_or(suffix);
                if domain_lower.eq_ignore_ascii_case(suffix_clean) {
                    return true;
                }
                if let Some(rest) = domain_lower.strip_suffix(suffix_clean) {
                    rest.ends_with('.')
                } else {
                    false
                }
            }
            Self::Keyword(kw) => domain_lower.contains(kw.as_str()),
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
        Self {
            start: port,
            end: port,
        }
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
    #[serde(default)]
    pub geoip: Vec<String>,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(skip)]
    pub ip_range_set: crate::ip_range::IpRangeSet,
    pub outbound: String,
}

impl Rule {
    pub fn compile_cidrs(&mut self) {
        self.ip_range_set = crate::ip_range::IpRangeSet::from_cidrs(&self.ip_cidrs);
    }

    pub fn matches(&self, meta: &SessionMeta) -> bool {
        self.matches_with_context(meta, None, None, None)
    }

    pub fn matches_with_registry(
        &self,
        meta: &SessionMeta,
        registry: Option<&crate::ruleset::RuleSetRegistry>,
    ) -> bool {
        self.matches_with_context(meta, registry, None, None)
    }

    pub fn matches_with_context(
        &self,
        meta: &SessionMeta,
        registry: Option<&crate::ruleset::RuleSetRegistry>,
        geoip_registry: Option<&crate::geoip::GeoIpRegistry>,
        process_resolver: Option<&crate::process::ProcessResolver>,
    ) -> bool {
        let matched = self.matches_conditions(meta, registry, geoip_registry, process_resolver);
        if self.invert { !matched } else { matched }
    }

    fn matches_conditions(
        &self,
        meta: &SessionMeta,
        registry: Option<&crate::ruleset::RuleSetRegistry>,
        geoip_registry: Option<&crate::geoip::GeoIpRegistry>,
        process_resolver: Option<&crate::process::ProcessResolver>,
    ) -> bool {
        // Inbound tag match
        if !self.inbound_tags.is_empty() {
            let matched = self
                .inbound_tags
                .iter()
                .any(|tag| tag.as_str() == &*meta.inbound_tag);
            if !matched {
                return false;
            }
        }

        // Network match
        if !self.networks.is_empty() && !self.networks.contains(&meta.network) {
            return false;
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
                let matched = self
                    .rule_set
                    .iter()
                    .any(|tag| reg.get(tag).map(|rs| rs.matches(meta)).unwrap_or(false));
                if !matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Process Name match
        if !self.process_name.is_empty() {
            if let Some(resolver) = process_resolver {
                if let Some(comm) = resolver.resolve_process_name(meta.source) {
                    let matched = self
                        .process_name
                        .iter()
                        .any(|p| p.eq_ignore_ascii_case(&comm));
                    if !matched {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        // GeoIP country match
        if !self.geoip.is_empty() {
            if let TargetAddress::Ip(sock) = &meta.destination {
                if let Some(geo) = geoip_registry {
                    let matched = self.geoip.iter().any(|code| geo.matches(sock.ip(), code));
                    if !matched {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Domain or IP match
        match &meta.destination {
            TargetAddress::Domain(domain, _) => {
                if !self.ip_cidrs.is_empty() && self.domains.is_empty() {
                    return false;
                }
                if !self.domains.is_empty() {
                    let domain_clean = domain.trim();
                    let domain_lower;
                    let domain_str = if domain_clean.bytes().any(|b| b.is_ascii_uppercase()) {
                        domain_lower = domain_clean.to_ascii_lowercase();
                        domain_lower.as_str()
                    } else {
                        domain_clean
                    };
                    let domain_match = self.domains.iter().any(|d| d.matches(domain_str));
                    if !domain_match {
                        return false;
                    }
                }
            }
            TargetAddress::Ip(sock_addr) => {
                if !self.domains.is_empty() && self.ip_cidrs.is_empty() {
                    return false;
                }
                if !self.ip_cidrs.is_empty() {
                    let ip = sock_addr.ip();
                    let ip_match = if !self.ip_range_set.is_empty() {
                        self.ip_range_set.contains(&ip)
                    } else {
                        self.ip_cidrs.iter().any(|cidr| cidr.contains(&ip))
                    };
                    if !ip_match {
                        return false;
                    }
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

    #[test]
    fn test_invert_rule() {
        let rule = Rule {
            domains: vec![DomainMatch::Exact("blocked.com".into())],
            invert: true,
            outbound: "direct".into(),
            ..Default::default()
        };

        let meta_allowed = SessionMeta::new(
            "127.0.0.1:50000".parse().unwrap(),
            "allowed.com:80".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert!(rule.matches(&meta_allowed));

        let meta_blocked = SessionMeta::new(
            "127.0.0.1:50000".parse().unwrap(),
            "blocked.com:80".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        assert!(!rule.matches(&meta_blocked));
    }
}
