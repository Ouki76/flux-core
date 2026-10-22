use flux_types::{NetworkType, SessionMeta, TargetAddress};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Normalizes a hostname for rule matching: surrounding whitespace and the DNS
/// root label (trailing dots) are dropped and ASCII is lowercased.
///
/// A trailing dot is not a typo — `example.com.` is the absolute form of
/// `example.com`, and clients send it (DoH/DoT names, `getaddrinfo` with
/// `AI_FQDN`, SOCKS5 `ATYP=domain` FQDNs). Treating it as a *different* name
/// meant the rule dropped the session and it fell through to `final`: traffic
/// meant for the proxy went direct.
#[inline]
pub fn normalize_host(host: &str) -> Cow<'_, str> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// True when `haystack` contains `needle`, ASCII case-insensitively.
///
/// An empty needle matches nothing: `DOMAIN-KEYWORD,` (a truncated feed line)
/// used to compile to `""`, and `str::contains("")` is true for every string,
/// so one broken line turned its rule set into "match every domain".
#[inline]
pub fn contains_keyword(haystack: &str, needle: &str) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Canonical form of a `DOMAIN` pattern. Kept identical to what
/// [`DomainMatch::matches`] accepts so an index built from the pattern can never
/// disagree with the matcher.
pub(crate) fn canonical_exact(pattern: &str) -> String {
    pattern.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Canonical form of a `DOMAIN-SUFFIX` pattern: no root dot, no leading dot and
/// no leading `*.` wildcard marker.
///
/// `*.example.com` is what public block lists actually ship. It was stored
/// verbatim, so the label walk could never produce a string containing `*` and
/// the entry matched nothing — a dead rule, i.e. traffic the list asked to
/// block silently fell through to `final`.
pub(crate) fn canonical_suffix(pattern: &str) -> String {
    let p = pattern.trim().trim_end_matches('.');
    let p = p.strip_prefix("*.").unwrap_or(p);
    p.trim_start_matches('.').to_ascii_lowercase()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainMatch {
    Exact(String),
    Suffix(String),
    Keyword(String),
}

impl DomainMatch {
    pub fn exact(pattern: impl Into<String>) -> Self {
        Self::Exact(canonical_exact(&pattern.into()))
    }

    pub fn suffix(suffix: impl Into<String>) -> Self {
        Self::Suffix(canonical_suffix(&suffix.into()))
    }

    pub fn keyword(kw: impl Into<String>) -> Self {
        Self::Keyword(kw.into().trim().to_ascii_lowercase())
    }

    /// Matches `domain` (which need not be pre-normalized) against the pattern.
    ///
    /// Accepts the raw pattern too, not just the canonical form produced by the
    /// constructors: `Rule` and `DomainMatch` are `Deserialize`, so a pattern can
    /// arrive with uppercase or a trailing dot and the matcher must still agree
    /// with the index the router builds from the same pattern.
    #[inline]
    pub fn matches(&self, domain: &str) -> bool {
        let domain = normalize_host(domain);
        let domain = domain.as_ref();
        match self {
            Self::Exact(pattern) => {
                let p = pattern.trim().trim_end_matches('.');
                !p.is_empty() && domain.eq_ignore_ascii_case(p)
            }
            Self::Suffix(suffix) => {
                let p = suffix.trim().trim_end_matches('.');
                let p = p.strip_prefix("*.").unwrap_or(p);
                let p = p.trim_start_matches('.');
                if p.is_empty() {
                    // An empty suffix must never match: `+.` alone in a feed
                    // used to compile to `""`, and `.ends_with('.')` made it
                    // match every trailing-dot domain.
                    return false;
                }
                if domain.eq_ignore_ascii_case(p) {
                    return true;
                }
                // Full-label match only: `notexample.com` must not match
                // `example.com`. Compare bytes so a multi-byte label can never
                // make the slice panic.
                let (d, s) = (domain.as_bytes(), p.as_bytes());
                d.len() > s.len()
                    && d[d.len() - s.len() - 1] == b'.'
                    && d[d.len() - s.len()..].eq_ignore_ascii_case(s)
            }
            Self::Keyword(kw) => contains_keyword(domain, kw),
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
                    let domain_match = self.domains.iter().any(|d| d.matches(domain));
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
                        // Uncompiled rule (`compile_cidrs` not called): same
                        // semantics as the compiled set, including the
                        // v4-mapped IPv6 handling.
                        crate::ip_range::cidr_list_contains(&self.ip_cidrs, ip)
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

#[cfg(test)]
mod adversarial {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn suffix(p: &str) -> DomainMatch {
        DomainMatch::Suffix(p.into())
    }

    /// The classic: a suffix pattern must only match at a *label* boundary.
    /// `strip_suffix` alone would accept `notexample.com` and `ample.com`.
    #[test]
    fn suffix_matches_only_at_label_boundaries() {
        let m = suffix("example.com");
        assert!(m.matches("example.com"), "apex");
        assert!(m.matches("www.example.com"));
        assert!(m.matches("a.b.example.com"));
        assert!(!m.matches("notexample.com"), "label prefix leak");
        assert!(!m.matches("ample.com"), "partial label leak");
        assert!(!m.matches("example.com.evil.net"), "pattern not at the end");
        assert!(!m.matches("example.co"), "shorter TLD");
        assert!(!m.matches("example.company"), "longer TLD");
    }

    /// `example.com.` is the absolute (DNS root) form of `example.com`.
    /// Clients do send it; treating it as a different name dropped the rule and
    /// the session fell through to `final` (traffic meant for the tunnel went
    /// direct).
    #[test]
    fn trailing_root_dot_is_the_same_name() {
        assert!(DomainMatch::Exact("example.com".into()).matches("example.com."));
        assert!(suffix("example.com").matches("example.com."));
        assert!(suffix("example.com").matches("www.example.com."));
        assert!(DomainMatch::Keyword("tele".into()).matches("api.telegram.org."));
        // ... and the pattern may carry the dot too (hand-written configs).
        assert!(DomainMatch::Exact("example.com.".into()).matches("example.com"));
        assert!(suffix("example.com.").matches("www.example.com"));
        assert!(suffix(".example.com.").matches("www.example.com"));
        // Every trailing dot, not just one.
        assert!(suffix("example.com").matches("www.example.com.."));
        // A dot is still a name separator: the dotted form of a *different*
        // name must not match.
        assert!(!suffix("example.com").matches("notexample.com."));
    }

    /// The router indexes rules by a canonical (lowercased) key while the
    /// matcher used to compare the raw pattern, so a pattern that did not come
    /// through `DomainMatch::suffix()` — e.g. deserialized from JSON, or built
    /// with the enum variant — matched the apex but not its subdomains.
    #[test]
    fn raw_pattern_is_matched_case_insensitively() {
        let raw_suffix = DomainMatch::Suffix("Spread.Example.COM".into());
        assert!(raw_suffix.matches("spread.example.com"), "apex");
        assert!(
            raw_suffix.matches("cdn.spread.example.com"),
            "subdomain of a mixed-case pattern"
        );
        assert!(
            raw_suffix.matches("CDN.Spread.Example.Com"),
            "uppercase query"
        );
        let raw_exact = DomainMatch::Exact("Exact.Example".into());
        assert!(raw_exact.matches("exact.example"));
        assert!(raw_exact.matches("EXACT.EXAMPLE"));
        assert!(!raw_exact.matches("sub.exact.example"));
        let raw_kw = DomainMatch::Keyword("TeleGram".into());
        assert!(raw_kw.matches("api.telegram.org"));
    }

    /// Public block lists ship `*.example.com`. It was stored verbatim, so no
    /// host ever contained a `*` and the entry was dead — traffic the list asked
    /// to block went to `final`.
    ///
    /// Decision: a leading `*.` is suffix semantics, apex included. Under-
    /// matching is the failure mode that leaks, so the pattern is widened rather
    /// than narrowed.
    #[test]
    fn wildcard_suffix_pattern_is_live() {
        let m = suffix("*.example.com");
        assert!(m.matches("a.example.com"), "wildcard entry did not match");
        assert!(m.matches("a.b.example.com"));
        assert!(m.matches("example.com"), "documented: apex included");
        assert!(!m.matches("notexample.com"));
        // Same through the constructor and the raw variant.
        assert_eq!(DomainMatch::suffix("*.example.com"), suffix("example.com"));
    }

    /// An empty pattern is not a wildcard. `keyword:` (truncated feed line) used
    /// to compile to `""` and `str::contains("")` is true for every string, so a
    /// single broken line routed *every* domain through that rule's outbound.
    #[test]
    fn empty_patterns_match_nothing() {
        for m in [
            DomainMatch::Keyword(String::new()),
            DomainMatch::Keyword("   ".into()),
            DomainMatch::Exact(String::new()),
            DomainMatch::Exact(".".into()),
            suffix(""),
            suffix("."),
            suffix("*."),
            suffix(".."),
        ] {
            for host in ["", ".", "example.com", "a.example.com", "evil"] {
                assert!(!m.matches(host), "empty-ish pattern {m:?} matched {host:?}");
            }
        }
    }

    /// A single-label pattern is legitimate (`DOMAIN-SUFFIX,localhost`) but a
    /// TLD pattern must still respect label boundaries.
    #[test]
    fn single_label_patterns_are_label_bounded() {
        let com = suffix("com");
        assert!(com.matches("com"));
        assert!(com.matches("example.com"));
        assert!(com.matches("a.b.example.com"));
        assert!(!com.matches("xcom"), "suffix inside a label");
        assert!(!com.matches("communicate.org"));
        assert!(!com.matches("co"));
        let local = suffix("localhost");
        assert!(local.matches("localhost"));
        assert!(!local.matches("notlocalhost"));
    }

    /// IDNs: rules are matched byte-for-byte, so the punycode form works but the
    /// Unicode form is a *different* name for the matcher. Pinned as a known
    /// gap (see the audit report): there is no IDNA conversion, so a config
    /// written as `münchen.de` does not match a client that sends
    /// `xn--mnchen-3ya.de`.
    #[test]
    fn punycode_is_matched_as_a_literal_known_gap() {
        assert!(suffix("xn--mnchen-3ya.de").matches("www.xn--mnchen-3ya.de"));
        assert!(!suffix("münchen.de").matches("xn--mnchen-3ya.de"));
        // Uppercase folding is ASCII-only, which is correct for DNS labels
        // (they are ASCII on the wire).
        assert!(
            DomainMatch::Exact("xn--bcher-kva.example".into()).matches("XN--BCHER-KVA.EXAMPLE")
        );
    }

    /// A `DOMAIN` pattern never sees an IP destination and an `IP-CIDR` pattern
    /// never sees a domain destination: the router has no resolver, so an IP
    /// rule cannot force a DNS lookup (`no-resolve` is honoured by construction).
    #[test]
    fn domain_and_ip_rules_never_cross_families() {
        let domain_rule = Rule {
            domains: vec![DomainMatch::Exact("1.2.3.4".into())],
            outbound: "x".into(),
            ..Default::default()
        };
        let ip_meta = SessionMeta::new(
            "127.0.0.1:1".parse().unwrap(),
            "1.2.3.4:80".parse().unwrap(),
            "in",
            NetworkType::Tcp,
        );
        assert!(!domain_rule.matches(&ip_meta));

        let ip_rule = Rule {
            ip_cidrs: vec![IpNet::from_str("1.2.3.0/24").unwrap()],
            outbound: "y".into(),
            ..Default::default()
        };
        let domain_meta = SessionMeta::new(
            "127.0.0.1:1".parse().unwrap(),
            TargetAddress::domain("host.that.resolves.to.1.2.3.4", 80),
            "in",
            NetworkType::Tcp,
        );
        assert!(
            !ip_rule.matches(&domain_meta),
            "IP rule resolved a domain (there is no resolver in the router)"
        );
    }

    /// `::ffff:a.b.c.d` is the same peer as `a.b.c.d`. An IPv4 rule must apply
    /// to the mapped form or the rule silently disappears for clients that
    /// report mapped addresses — a direct leak when the rule was `direct`/`block`.
    #[test]
    fn v4_mapped_v6_is_the_same_peer() {
        for compiled in [true, false] {
            let mut rule = Rule {
                ip_cidrs: vec![IpNet::from_str("192.168.0.0/16").unwrap()],
                outbound: "lan".into(),
                ..Default::default()
            };
            if compiled {
                rule.compile_cidrs();
            }
            for ip in ["::ffff:192.168.1.5", "192.168.1.5"] {
                let meta = SessionMeta::new(
                    "127.0.0.1:1".parse().unwrap(),
                    TargetAddress::ip(IpAddr::from_str(ip).unwrap(), 80),
                    "in",
                    NetworkType::Tcp,
                );
                assert!(rule.matches(&meta), "{ip} missed 192.168.0.0/16");
            }
            // A non-mapped v6 address is still not a v4 address.
            let v6 = SessionMeta::new(
                "127.0.0.1:1".parse().unwrap(),
                TargetAddress::ip(IpAddr::from_str("2001:db8::1").unwrap(), 80),
                "in",
                NetworkType::Tcp,
            );
            assert!(!rule.matches(&v6));
        }
    }

    /// Network and broadcast addresses belong to the network; the immediate
    /// neighbours do not.
    #[test]
    fn cidr_boundaries_are_inclusive() {
        let mut rule = Rule {
            ip_cidrs: vec![
                IpNet::from_str("10.0.0.0/24").unwrap(),
                IpNet::from_str("10.0.1.0/25").unwrap(),
            ],
            outbound: "x".into(),
            ..Default::default()
        };
        rule.compile_cidrs();
        let hit = |s: &str| {
            rule.matches(&SessionMeta::new(
                "127.0.0.1:1".parse().unwrap(),
                TargetAddress::ip(IpAddr::from_str(s).unwrap(), 1),
                "in",
                NetworkType::Tcp,
            ))
        };
        assert!(hit("10.0.0.0"), "network address");
        assert!(hit("10.0.0.255"), "broadcast");
        assert!(!hit("9.255.255.255"));
        assert!(!hit("10.0.1.128"), "just past 10.0.1.0/25");
        assert!(hit("10.0.1.127"), "last address of 10.0.1.0/25");
    }

    /// Port ranges are inclusive on both ends; a full range covers everything.
    #[test]
    fn port_ranges_are_inclusive() {
        let r = PortRange::range(8000, 8005);
        assert!(!r.contains(7999));
        assert!(r.contains(8000));
        assert!(r.contains(8002));
        assert!(r.contains(8005));
        assert!(!r.contains(8006));
        assert!(PortRange::range(0, u16::MAX).contains(0));
        assert!(PortRange::range(0, u16::MAX).contains(u16::MAX));
    }

    /// Pinned hazard, not a fix: `invert` flips an *undecidable* condition. For
    /// a domain destination an IP condition is false (no resolver), so
    /// `ip_cidr + invert` matches every domain. Operators write this to mean
    /// "everything not in 10/8", which is what they get for IP literals — but
    /// named traffic matches regardless of where it resolves. Documented here so
    /// a future change to "unknown = no match" is a deliberate decision.
    #[test]
    fn inverted_ip_rule_matches_domain_destinations() {
        let mut rule = Rule {
            ip_cidrs: vec![IpNet::from_str("10.0.0.0/8").unwrap()],
            invert: true,
            outbound: "proxy".into(),
            ..Default::default()
        };
        rule.compile_cidrs();
        let domain = SessionMeta::new(
            "127.0.0.1:1".parse().unwrap(),
            TargetAddress::domain("internal.corp", 443),
            "in",
            NetworkType::Tcp,
        );
        assert!(rule.matches(&domain));
    }
}
