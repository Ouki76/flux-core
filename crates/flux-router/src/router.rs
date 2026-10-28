use crate::geoip::GeoIpRegistry;
use crate::process::ProcessResolver;
use crate::rule::Rule;
use crate::ruleset::RuleSetRegistry;
use flux_types::SessionMeta;
use std::collections::HashMap;
use std::sync::Arc;

/// Evaluates rules in order and returns the first outbound tag that matches.
#[derive(Clone)]
pub struct Router {
    rules: Vec<Rule>,
    rule_sets: RuleSetRegistry,
    geoip_registry: Arc<GeoIpRegistry>,
    process_resolver: Arc<ProcessResolver>,
    default_outbound: String,
    exact_domains: HashMap<String, Vec<usize>>,
    suffix_domains: HashMap<String, Vec<usize>>,
    keyword_rules: Vec<usize>,
    ip_rules: Vec<usize>,
    general_rules: Vec<usize>,
}

impl Default for Router {
    /// A router with no rules that sends everything to `direct` — the same
    /// fallback `route.final` defaults to. Deriving `Default` would have given
    /// `default_outbound: ""`, i.e. a router whose `route()` returns a tag that
    /// cannot name an outbound.
    fn default() -> Self {
        Self::new(Vec::new(), "direct")
    }
}

impl Router {
    /// A router over `rules`, falling back to `default_outbound` when none match.
    pub fn new(rules: Vec<Rule>, default_outbound: impl Into<String>) -> Self {
        let mut exact_domains: HashMap<String, Vec<usize>> = HashMap::new();
        let mut suffix_domains: HashMap<String, Vec<usize>> = HashMap::new();
        let mut keyword_rules = Vec::new();
        let mut ip_rules = Vec::new();
        let mut general_rules = Vec::new();

        for (idx, rule) in rules.iter().enumerate() {
            if rule.invert
                || !rule.rule_set.is_empty()
                || !rule.geoip.is_empty()
                || !rule.process_name.is_empty()
            {
                general_rules.push(idx);
                continue;
            }

            let has_domains = !rule.domains.is_empty();
            let has_ips = !rule.ip_cidrs.is_empty() || !rule.ip_range_set.is_empty();

            if !has_domains && !has_ips {
                general_rules.push(idx);
                continue;
            }

            if has_ips {
                ip_rules.push(idx);
            }

            if has_domains {
                let mut has_kw = false;
                for d in &rule.domains {
                    // The index key must be exactly what the matcher accepts:
                    // `canonical_*` is shared with `DomainMatch::matches`, so a
                    // rule can never be indexed under a key the matcher rejects
                    // (or, worse, missed by a lookup the matcher would accept).
                    match d {
                        crate::rule::DomainMatch::Exact(pattern) => {
                            let key = crate::rule::canonical_exact(pattern);
                            if !key.is_empty() {
                                exact_domains.entry(key).or_default().push(idx);
                            }
                        }
                        crate::rule::DomainMatch::Suffix(suffix) => {
                            let key = crate::rule::canonical_suffix(suffix);
                            if !key.is_empty() {
                                suffix_domains.entry(key).or_default().push(idx);
                            }
                        }
                        crate::rule::DomainMatch::Keyword(_) => {
                            has_kw = true;
                        }
                    }
                }
                if has_kw {
                    keyword_rules.push(idx);
                }
            }
        }

        Self {
            rules,
            rule_sets: RuleSetRegistry::new(),
            geoip_registry: Arc::new(GeoIpRegistry::new()),
            process_resolver: Arc::new(ProcessResolver::new()),
            default_outbound: default_outbound.into(),
            exact_domains,
            suffix_domains,
            keyword_rules,
            ip_rules,
            general_rules,
        }
    }

    /// Supplies rule sets; without this a rule naming one never matches.
    pub fn with_rule_sets(mut self, registry: RuleSetRegistry) -> Self {
        self.rule_sets = registry;
        self
    }

    /// Supplies the GeoIP database; without this a `geoip` rule never matches.
    pub fn with_geoip(mut self, geo: Arc<GeoIpRegistry>) -> Self {
        self.geoip_registry = geo;
        self
    }

    /// Supplies the process resolver; without this a `process_name` rule never matches.
    pub fn with_process_resolver(mut self, pr: Arc<ProcessResolver>) -> Self {
        self.process_resolver = pr;
        self
    }

    /// The outbound tag for `meta`: the first matching rule, else the default.
    pub fn route(&self, meta: &SessionMeta) -> &str {
        match &meta.destination {
            flux_types::TargetAddress::Domain(domain, _) => {
                // Same normalization the index keys and `DomainMatch::matches`
                // use: root dot stripped, ASCII lowercased.
                let domain = crate::rule::normalize_host(domain);
                let domain_str = domain.as_ref();

                let mut best_rule_idx: usize = usize::MAX;

                // 1. Exact match O(1)
                if let Some(indices) = self.exact_domains.get(domain_str) {
                    for &idx in indices {
                        if self.rules[idx].matches_with_context(
                            meta,
                            Some(&self.rule_sets),
                            Some(&self.geoip_registry),
                            Some(&self.process_resolver),
                        ) {
                            best_rule_idx = best_rule_idx.min(idx);
                            break;
                        }
                    }
                }

                if best_rule_idx == 0 {
                    return &self.rules[0].outbound;
                }

                // 2. Suffix match O(L)
                let mut cursor = domain_str;
                loop {
                    if let Some(indices) = self.suffix_domains.get(cursor) {
                        for &idx in indices {
                            if idx < best_rule_idx
                                && self.rules[idx].matches_with_context(
                                    meta,
                                    Some(&self.rule_sets),
                                    Some(&self.geoip_registry),
                                    Some(&self.process_resolver),
                                )
                            {
                                best_rule_idx = idx;
                                break;
                            }
                        }
                    }
                    if best_rule_idx == 0 {
                        return &self.rules[0].outbound;
                    }
                    match cursor.find('.') {
                        Some(dot) => cursor = &cursor[dot + 1..],
                        None => break,
                    }
                }

                // 3. Keyword rules (only if smallest keyword rule < best_rule_idx)
                if let Some(&first_kw) = self.keyword_rules.first()
                    && first_kw < best_rule_idx
                {
                    for &idx in &self.keyword_rules {
                        if idx >= best_rule_idx {
                            break;
                        }
                        if self.rules[idx].matches_with_context(
                            meta,
                            Some(&self.rule_sets),
                            Some(&self.geoip_registry),
                            Some(&self.process_resolver),
                        ) {
                            best_rule_idx = idx;
                        }
                    }
                }

                // 4. General rules (only if smallest general rule < best_rule_idx)
                if let Some(&first_gen) = self.general_rules.first()
                    && first_gen < best_rule_idx
                {
                    for &idx in &self.general_rules {
                        if idx >= best_rule_idx {
                            break;
                        }
                        if self.rules[idx].matches_with_context(
                            meta,
                            Some(&self.rule_sets),
                            Some(&self.geoip_registry),
                            Some(&self.process_resolver),
                        ) {
                            best_rule_idx = idx;
                        }
                    }
                }

                if best_rule_idx != usize::MAX {
                    return &self.rules[best_rule_idx].outbound;
                }

                &self.default_outbound
            }
            flux_types::TargetAddress::Ip(_) => {
                let mut ip_idx = 0;
                let mut gen_idx = 0;

                while ip_idx < self.ip_rules.len() || gen_idx < self.general_rules.len() {
                    let next_rule_idx =
                        match (self.ip_rules.get(ip_idx), self.general_rules.get(gen_idx)) {
                            (Some(&r_ip), Some(&r_gen)) => {
                                if r_ip < r_gen {
                                    ip_idx += 1;
                                    r_ip
                                } else {
                                    gen_idx += 1;
                                    r_gen
                                }
                            }
                            (Some(&r_ip), None) => {
                                ip_idx += 1;
                                r_ip
                            }
                            (None, Some(&r_gen)) => {
                                gen_idx += 1;
                                r_gen
                            }
                            (None, None) => break,
                        };

                    if self.rules[next_rule_idx].matches_with_context(
                        meta,
                        Some(&self.rule_sets),
                        Some(&self.geoip_registry),
                        Some(&self.process_resolver),
                    ) {
                        return &self.rules[next_rule_idx].outbound;
                    }
                }

                &self.default_outbound
            }
        }
    }

    /// True when some rule decides on the destination's **address**, so a domain
    /// destination has to be resolved before routing for that rule to be able to
    /// fire.
    ///
    /// Competitors resolve by default (unless a rule says `no-resolve`); this
    /// router deliberately does not resolve on its own, because it is synchronous
    /// and has no resolver. The dispatcher asks this question and resolves when the
    /// answer is yes, which keeps the decision where the async I/O lives.
    /// Whether any rule looks at the destination IP, so the caller knows it must resolve
    /// a domain before routing instead of connecting first.
    pub fn needs_resolved_destination(&self) -> bool {
        self.ip_rules.iter().any(|&idx| {
            let rule = &self.rules[idx];
            !rule.ip_cidrs.is_empty() || !rule.geoip.is_empty() || !rule.rule_set.is_empty()
        })
    }

    /// The outbound used when no rule matches.
    pub fn default_outbound(&self) -> &str {
        &self.default_outbound
    }

    /// The rules, in the order they are evaluated.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{DomainMatch, PortRange};
    use flux_types::NetworkType;

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

    #[test]
    fn test_process_name_matching_rule() {
        let rule = Rule {
            process_name: vec!["telegram-desktop".into()],
            outbound: "proxy-tg".into(),
            ..Default::default()
        };
        let router = Router::new(vec![rule], "direct");

        let meta = SessionMeta::new(
            "127.0.0.1:12345".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        );
        // Without mocked process in /proc, falls back to direct
        assert_eq!(router.route(&meta), "direct");
    }
}

#[cfg(test)]
mod adversarial {
    use super::*;
    use crate::rule::{DomainMatch, PortRange};
    use flux_types::{NetworkType, TargetAddress};

    fn tcp(host: &str, port: u16) -> SessionMeta {
        SessionMeta::new(
            "127.0.0.1:1234".parse().unwrap(),
            format!("{host}:{port}").parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        )
    }

    fn ip(addr: &str, port: u16) -> SessionMeta {
        SessionMeta::new(
            "127.0.0.1:1234".parse().unwrap(),
            format!("{addr}:{port}").parse().unwrap(),
            "socks-in",
            NetworkType::Tcp,
        )
    }

    fn rule(domains: Vec<DomainMatch>, outbound: &str) -> Rule {
        Rule {
            domains,
            outbound: outbound.into(),
            ..Default::default()
        }
    }

    /// End-to-end form of the trailing-dot leak: a client that sends the
    /// absolute (dotted) name must still hit the rule that tunnels it. Before
    /// the fix this fell through to `final`, i.e. traffic meant for the proxy
    /// went out direct.
    #[test]
    fn dotted_fqdn_still_hits_the_rule() {
        let r = Router::new(
            vec![
                rule(vec![DomainMatch::exact("pinned.example")], "proxy"),
                rule(vec![DomainMatch::suffix("tunnelled.example")], "proxy"),
                rule(vec![DomainMatch::keyword("secret")], "proxy"),
            ],
            "direct",
        );
        for host in [
            "pinned.example.",
            "tunnelled.example.",
            "deep.tunnelled.example.",
            "api.secret.example.",
        ] {
            assert_eq!(r.route(&tcp(host, 443)), "proxy", "{host} leaked to final");
        }
    }

    /// First match wins by *rule order*, not by match category: the indexed
    /// lookups (exact, suffix, keyword, general) must all report the smallest
    /// matching index.
    #[test]
    fn first_match_is_rule_order_across_match_kinds() {
        let r = Router::new(
            vec![
                rule(vec![DomainMatch::keyword("ads")], "kw-first"),
                rule(vec![DomainMatch::suffix("x.example")], "suffix-second"),
                rule(vec![DomainMatch::exact("ads.x.example")], "exact-third"),
                rule(vec![DomainMatch::suffix("example")], "suffix-fourth"),
            ],
            "final",
        );
        // Every rule matches this host; the keyword rule is first.
        assert_eq!(r.route(&tcp("ads.x.example", 443)), "kw-first");
        // Exact and suffix both match, suffix (index 1) is earlier than exact.
        assert_eq!(r.route(&tcp("x.example", 443)), "suffix-second");
        // A deeper label only reaches the suffix rules.
        assert_eq!(r.route(&tcp("deep.sub.x.example", 443)), "suffix-second");
        assert_eq!(r.route(&tcp("unrelated.example", 443)), "suffix-fourth");
        assert_eq!(r.route(&tcp("unrelated.test", 443)), "final");
    }

    /// `final` is a fallback, never a competitor: a later rule that matches
    /// still beats it, and an earlier non-matching rule does not shadow it.
    /// `Router::default()` must not hand back an empty outbound tag.
    #[test]
    fn default_router_uses_a_real_tag() {
        let r = Router::default();
        assert_eq!(r.route(&tcp("anything.example", 443)), "direct");
        assert_eq!(r.default_outbound(), "direct");
    }

    /// Upstream gap, reported not fixed    /// Upstream gap, reported not fixed (`flux-types/src/address.rs`):
    /// `"1.2.3.4.:80"` parses as `TargetAddress::Domain("1.2.3.4.")` because
    /// `"1.2.3.4.".parse::<IpAddr>()` fails, so an `IP-CIDR` rule can never apply
    /// to a client that appends the root dot to an IP literal. Pinned: when
    /// flux-types canonicalizes it, this assertion flips and the gap is closed.
    #[test]
    fn ip_literal_with_root_dot_is_out_of_reach_of_ip_rules() {
        let r = Router::new(
            vec![Rule {
                ip_cidrs: vec!["1.2.3.0/24".parse().unwrap()],
                outbound: "by-ip".into(),
                ..Default::default()
            }],
            "final",
        );
        assert_eq!(r.route(&ip("1.2.3.4", 80)), "by-ip");
        let dotted = SessionMeta::new(
            "127.0.0.1:1".parse().unwrap(),
            TargetAddress::domain("1.2.3.4.", 80),
            "in",
            NetworkType::Tcp,
        );
        assert_eq!(
            r.route(&dotted),
            "final",
            "flux-types parsed the dotted literal as a domain"
        );
    }

    /// A rule with no conditions matches everything (the engine has no implicit
    /// MATCH rule; `final` is only consulted when nothing matched). Pinned so
    /// that a conditionless rule is a known, deliberate semantic.
    #[test]
    fn a_conditionless_rule_matches_everything() {
        let r = Router::new(
            vec![
                Rule {
                    outbound: "catch-all".into(),
                    ..Default::default()
                },
                rule(vec![DomainMatch::suffix("example.com")], "never"),
            ],
            "final",
        );
        assert_eq!(r.route(&tcp("a.example.com", 443)), "catch-all");
        assert_eq!(r.route(&ip("8.8.8.8", 53)), "catch-all");
        // ... and `invert` on it matches nothing at all.
        let inverted = Router::new(
            vec![Rule {
                invert: true,
                outbound: "nothing".into(),
                ..Default::default()
            }],
            "final",
        );
        assert_eq!(inverted.route(&tcp("a.example.com", 443)), "final");
    }

    #[test]
    fn final_applies_only_when_nothing_matched() {
        let r = Router::new(
            vec![
                Rule {
                    domains: vec![DomainMatch::exact("unreachable.example")],
                    ports: vec![PortRange::single(1)],
                    outbound: "narrow".into(),
                    ..Default::default()
                },
                rule(vec![DomainMatch::suffix("example")], "broad"),
            ],
            "final",
        );
        assert_eq!(r.route(&tcp("unreachable.example", 443)), "broad");
        assert_eq!(r.route(&tcp("other.test", 443)), "final");

        let empty = Router::new(vec![], "final");
        assert_eq!(empty.route(&tcp("anything.example", 1)), "final");
        assert_eq!(empty.default_outbound(), "final");
    }

    /// A protocol-specific rule must not fire for the other protocol, and a
    /// port rule is about the *destination* port (there is no source-port
    /// condition in this engine; `meta.source` is only used for process lookup).
    #[test]
    fn network_and_port_conditions_do_not_cross() {
        let r = Router::new(
            vec![
                Rule {
                    networks: vec![NetworkType::Udp],
                    outbound: "udp-only".into(),
                    ..Default::default()
                },
                Rule {
                    ports: vec![PortRange::range(8000, 8005)],
                    outbound: "range".into(),
                    ..Default::default()
                },
            ],
            "final",
        );

        // TCP session on a UDP-only rule's port: no match.
        assert_eq!(r.route(&tcp("h.example", 9)), "final");
        // Same port over UDP: the udp rule is first.
        let udp = SessionMeta::new(
            "127.0.0.1:1".parse().unwrap(),
            "h.example:9".parse().unwrap(),
            "socks-in",
            NetworkType::Udp,
        );
        assert_eq!(r.route(&udp), "udp-only");
        // Port range boundaries are inclusive.
        assert_eq!(r.route(&tcp("h.example", 8000)), "range");
        assert_eq!(r.route(&tcp("h.example", 8005)), "range");
        assert_eq!(r.route(&tcp("h.example", 8006)), "final");
        assert_eq!(r.route(&tcp("h.example", 7999)), "final");
        // The *source* port is 1234 in every meta above and must not matter.
        assert_eq!(r.route(&tcp("h.example", 1234)), "final");
    }

    /// An IP rule must never force a DNS lookup: the router has no resolver at
    /// all, so `no-resolve` is honoured by construction, and an IP-only rule
    /// cannot match a domain destination.
    #[test]
    fn ip_rules_never_resolve_domains() {
        let r = Router::new(
            vec![Rule {
                ip_cidrs: vec!["93.184.216.0/24".parse().unwrap()],
                outbound: "by-ip".into(),
                ..Default::default()
            }],
            "final",
        );
        assert_eq!(r.route(&tcp("example.com", 443)), "final");
        assert_eq!(r.route(&ip("93.184.216.34", 443)), "by-ip");
    }

    /// A `rule_set` tag that is missing, or present but empty, is "no match" —
    /// never "match everything". Inline entries of a fetched set still coexist
    /// with the fetched ones.
    #[test]
    fn missing_and_empty_rule_sets_are_no_match() {
        let mut reg = crate::ruleset::RuleSetRegistry::new();
        reg.insert(crate::ruleset::RuleSet {
            tag: "empty".into(),
            ..Default::default()
        })
        .unwrap();
        // Register first, then apply the fetched text — the order the remote
        // fetch path uses (`reg.insert` compiles from the raw lists, so a fetch
        // applied before insertion would be rebuilt away).
        reg.insert(crate::ruleset::RuleSet {
            tag: "inline+f".into(),
            domain: vec!["exact.inline".into()],
            ..Default::default()
        })
        .unwrap();
        reg.get("inline+f")
            .unwrap()
            .apply_content("DOMAIN-SUFFIX,fetched.example\n");

        let r = Router::new(
            vec![
                Rule {
                    rule_set: vec!["missing".into()],
                    outbound: "MISSING".into(),
                    ..Default::default()
                },
                Rule {
                    rule_set: vec!["empty".into()],
                    outbound: "EMPTY".into(),
                    ..Default::default()
                },
                Rule {
                    rule_set: vec!["inline+f".into()],
                    outbound: "RS".into(),
                    ..Default::default()
                },
            ],
            "final",
        )
        .with_rule_sets(reg);

        assert_eq!(r.route(&tcp("evil.example", 443)), "final", "missing tag");
        assert_eq!(r.route(&ip("1.2.3.4", 443)), "final", "empty set");
        assert_eq!(r.route(&tcp("exact.inline", 443)), "RS", "inline entry");
        assert_eq!(
            r.route(&tcp("sub.fetched.example", 443)),
            "RS",
            "fetched entry"
        );
        assert_eq!(r.route(&tcp("notfetched.example", 443)), "final");
    }

    /// Deterministic PRNG (xorshift64*) so failures reproduce exactly.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len() as u64) as usize]
        }
    }

    /// Linear scan over the rules using the public matcher: the reference
    /// semantics the indexed engine must reproduce.
    fn reference_route(
        rules: &[Rule],
        meta: &SessionMeta,
        default: &str,
        reg: &crate::ruleset::RuleSetRegistry,
        geo: &crate::geoip::GeoIpRegistry,
    ) -> String {
        for r in rules {
            if r.matches_with_context(meta, Some(reg), Some(geo), None) {
                return r.outbound.clone();
            }
        }
        default.to_string()
    }

    fn random_host(rng: &mut Rng) -> String {
        const LABELS: [&str; 15] = [
            "a",
            "b",
            "example",
            "com",
            "org",
            "EXAMPLE",
            "xn--mnchen-3ya",
            "münchen",
            "*",
            "",
            "1",
            "adserver",
            "LOCALHOST",
            "x-y",
            "日本",
        ];
        let n = rng.below(4) as usize;
        let mut host = String::new();
        for i in 0..n {
            if i > 0 {
                host.push('.');
            }
            // Indexing directly avoids a `pick` call whose element type inference differs
            // between Rust 1.91 (what CI pins) and 1.97: with `push_str` in the argument
            // position, 1.91 resolves `pick::<str>` and then rejects `&[&str; 15]`.
            let label = LABELS[rng.below(LABELS.len() as u64) as usize];
            host.push_str(label);
        }
        match rng.below(8) {
            0 => host.push('.'),
            1 => host.push_str(".."),
            _ => {}
        }
        match rng.below(10) {
            0 => host = String::new(),
            1 => host.push_str(".leading"),
            2 => {
                // Raw bytes, not necessarily a sensible hostname.
                let mut bytes = vec![0u8; rng.below(12) as usize + 1];
                for b in bytes.iter_mut() {
                    *b = rng.below(256) as u8;
                }
                host = String::from_utf8_lossy(&bytes).into_owned();
            }
            _ => {}
        }
        host
    }

    fn random_domain_match(rng: &mut Rng) -> DomainMatch {
        let host = random_host(rng);
        match rng.below(3) {
            0 => DomainMatch::Exact(host),
            1 => DomainMatch::Suffix(host),
            _ => DomainMatch::Keyword(host),
        }
    }

    fn random_meta(rng: &mut Rng) -> SessionMeta {
        let network = if rng.below(2) == 0 {
            NetworkType::Tcp
        } else {
            NetworkType::Udp
        };
        if rng.below(4) == 0 {
            let port = rng.below(65536) as u16;
            let addr = match rng.below(4) {
                0 => "127.0.0.1",
                1 => "10.1.2.3",
                2 => "2001:db8::5",
                _ => "::ffff:10.1.2.3",
            };
            SessionMeta::new(
                "127.0.0.1:5555".parse().unwrap(),
                format!("[{addr}]:{port}")
                    .parse()
                    .unwrap_or_else(|_| format!("{addr}:{port}").parse().unwrap()),
                "in",
                network,
            )
        } else {
            SessionMeta::new(
                "127.0.0.1:5555".parse().unwrap(),
                TargetAddress::domain(random_host(rng), rng.below(65536) as u16),
                "in",
                network,
            )
        }
    }

    fn random_rule(rng: &mut Rng, tags: &[&'static str]) -> Rule {
        let mut r = Rule {
            outbound: (*rng.pick(tags)).to_string(),
            ..Default::default()
        };
        if rng.below(3) == 0 {
            for _ in 0..rng.below(3) {
                r.domains.push(random_domain_match(rng));
            }
        }
        if rng.below(4) == 0 {
            for _ in 0..rng.below(3) {
                let cidr = match rng.below(5) {
                    0 => "0.0.0.0/0",
                    1 => "10.0.0.0/8",
                    2 => "10.1.2.3/32",
                    3 => "2001:db8::/32",
                    _ => "::ffff:10.0.0.0/104",
                };
                r.ip_cidrs.push(cidr.parse().unwrap());
            }
            r.compile_cidrs();
        }
        if rng.below(4) == 0 {
            let start = rng.below(65536) as u16;
            r.ports.push(PortRange::range(
                start,
                start.saturating_add(rng.below(4) as u16),
            ));
        }
        if rng.below(5) == 0 {
            r.networks.push(if rng.below(2) == 0 {
                NetworkType::Tcp
            } else {
                NetworkType::Udp
            });
        }
        if rng.below(6) == 0 {
            r.inbound_tags.push("in".into());
        }
        if rng.below(7) == 0 {
            r.rule_set
                .push((*rng.pick(&["rs-domains", "rs-cidrs", "rs-empty", "rs-missing"])).into());
        }
        if rng.below(9) == 0 {
            r.geoip.push("CN".into());
        }
        if rng.below(12) == 0 {
            r.invert = true;
        }
        r
    }

    fn fuzz_registry() -> crate::ruleset::RuleSetRegistry {
        let mut reg = crate::ruleset::RuleSetRegistry::new();
        let mut domains = crate::ruleset::RuleSet {
            tag: "rs-domains".into(),
            domain: vec!["exact.rs".into()],
            domain_suffix: vec!["suffix.rs".into(), "*.wild.rs".into()],
            domain_keyword: vec!["kw".into()],
            ..Default::default()
        };
        domains.compile().unwrap();
        reg.insert(domains).unwrap();
        let mut cidrs = crate::ruleset::RuleSet {
            tag: "rs-cidrs".into(),
            ip_cidr: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            ..Default::default()
        };
        cidrs.compile().unwrap();
        reg.insert(cidrs).unwrap();
        reg.insert(crate::ruleset::RuleSet {
            tag: "rs-empty".into(),
            ..Default::default()
        })
        .unwrap();
        reg
    }

    /// The indexed engine must agree with a linear scan of the same rules, for
    /// random rule sets and random (often malformed) session metadata. This is
    /// the property that catches "the index missed a rule the matcher accepts"
    /// — i.e. a silent fall-through to `final`.
    #[test]
    fn indexed_engine_agrees_with_a_linear_scan() {
        const TAGS: [&str; 5] = ["direct", "proxy", "block", "relay", "direct-2"];
        let reg = fuzz_registry();
        let geo = crate::geoip::GeoIpRegistry::new();
        let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);

        for round in 0..24 {
            let n = rng.below(6) as usize;
            let rules: Vec<Rule> = (0..n).map(|_| random_rule(&mut rng, &TAGS)).collect();
            let router = Router::new(rules.clone(), "final").with_rule_sets(reg.clone());

            for _ in 0..250 {
                let meta = random_meta(&mut rng);
                let got = router.route(&meta).to_string();
                let want = reference_route(&rules, &meta, "final", &reg, &geo);
                assert_eq!(
                    got, want,
                    "round {round}: indexed route disagrees with linear scan for {meta:?}\nrules: {rules:?}"
                );
                assert!(
                    TAGS.contains(&got.as_str()) || got == "final",
                    "route returned a tag that is not in the config: {got}"
                );
            }
        }
    }

    /// A random `SessionMeta` must never panic the engine, whatever the host
    /// bytes, port or address family — and the answer must always be a tag that
    /// exists in the config.
    #[test]
    fn random_sessions_never_panic() {
        const TAGS: [&str; 3] = ["direct", "proxy", "block"];
        let mut rng = Rng::new(0xdead_beef_1234_5678);
        let mut rules: Vec<Rule> = (0..12).map(|_| random_rule(&mut rng, &TAGS)).collect();
        // Hand-built nasties on top of the random ones.
        rules.push(rule(vec![DomainMatch::suffix("*.")], "block"));
        rules.push(rule(vec![DomainMatch::exact("")], "proxy"));
        rules.push(rule(vec![DomainMatch::keyword("")], "block"));
        rules.push(Rule {
            ip_cidrs: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            outbound: "direct".into(),
            ..Default::default()
        });
        for r in rules.iter_mut() {
            r.compile_cidrs();
        }
        let router = Router::new(rules, "final").with_rule_sets(fuzz_registry());

        for _ in 0..3000 {
            let meta = random_meta(&mut rng);
            let tag = router.route(&meta);
            assert!(
                TAGS.contains(&tag) || tag == "final",
                "unknown tag {tag:?} for {meta:?}"
            );
        }
    }
}
