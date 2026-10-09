use crate::geoip::GeoIpRegistry;
use crate::process::ProcessResolver;
use crate::rule::Rule;
use crate::ruleset::RuleSetRegistry;
use flux_types::SessionMeta;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Default)]
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

impl Router {
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
                    match d {
                        crate::rule::DomainMatch::Exact(pattern) => {
                            exact_domains
                                .entry(pattern.to_ascii_lowercase())
                                .or_default()
                                .push(idx);
                        }
                        crate::rule::DomainMatch::Suffix(suffix) => {
                            let clean = suffix.trim_start_matches('.').to_ascii_lowercase();
                            suffix_domains.entry(clean).or_default().push(idx);
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

    pub fn with_rule_sets(mut self, registry: RuleSetRegistry) -> Self {
        self.rule_sets = registry;
        self
    }

    pub fn with_geoip(mut self, geo: Arc<GeoIpRegistry>) -> Self {
        self.geoip_registry = geo;
        self
    }

    pub fn with_process_resolver(mut self, pr: Arc<ProcessResolver>) -> Self {
        self.process_resolver = pr;
        self
    }

    pub fn route(&self, meta: &SessionMeta) -> &str {
        match &meta.destination {
            flux_types::TargetAddress::Domain(domain, _) => {
                let domain_clean = domain.trim();
                let domain_lower;
                let domain_str = if domain_clean.bytes().any(|b| b.is_ascii_uppercase()) {
                    domain_lower = domain_clean.to_ascii_lowercase();
                    domain_lower.as_str()
                } else {
                    domain_clean
                };

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

    pub fn default_outbound(&self) -> &str {
        &self.default_outbound
    }

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
