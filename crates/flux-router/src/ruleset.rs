use flux_types::SessionMeta;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Compiled O(1)/O(L) lookup structures derived from the raw rule lists.
/// Lives behind an RwLock so remote (URL-fetched) rule sets can be hot-swapped
/// without touching the running router.
#[derive(Clone, Debug, Default)]
pub struct CompiledRuleSet {
    pub ip_range_set: crate::ip_range::IpRangeSet,
    pub exact_set: HashSet<String>,
    pub suffix_set: HashSet<String>,
    pub keyword_list: Vec<String>,
}

impl CompiledRuleSet {
    fn build(rs: &RuleSet) -> Self {
        let parsed_cidrs: Vec<IpNet> = rs
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

        let ip_range_set = crate::ip_range::IpRangeSet::from_cidrs(&parsed_cidrs);

        let exact_set = rs
            .domain
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .collect();

        let suffix_set = rs
            .domain_suffix
            .iter()
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .collect();

        let keyword_list = rs
            .domain_keyword
            .iter()
            .map(|k| k.trim().to_ascii_lowercase())
            .collect();

        Self {
            ip_range_set,
            exact_set,
            suffix_set,
            keyword_list,
        }
    }
}

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

    /// Remote URL (http:// or https://) fetched asynchronously in the background.
    /// The rule set matches nothing until the first successful fetch completes.
    #[serde(skip)]
    pub remote_url: Option<String>,
    /// Optional periodic refresh interval for remote rule sets.
    #[serde(skip)]
    pub update_interval: Option<std::time::Duration>,
    /// Hot-swappable compiled matcher state.
    #[doc(hidden)]
    #[serde(skip)]
    pub compiled: Arc<parking_lot::RwLock<CompiledRuleSet>>,
    #[serde(skip)]
    #[doc(hidden)]
    pub file_loaded: bool,
    /// Mutable parse statistics (interior mutability: remote rule sets are
    /// refreshed through a shared `&RuleSet`).
    #[serde(skip)]
    pub stats: Arc<RuleSetStats>,
}

/// Line counters for a rule set, shared across refreshes.
#[derive(Default, Debug)]
pub struct RuleSetStats {
    parsed: std::sync::atomic::AtomicUsize,
    unparsed: std::sync::atomic::AtomicUsize,
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

        // Handle Clash comma format: "DOMAIN-SUFFIX,google.com[,no-resolve]".
        //
        // The value is the *second* field; trailing modifiers such as
        // `no-resolve` must be dropped rather than folded into the value —
        // `"1.2.3.4/32,no-resolve"` does not parse as a CIDR, so the rule was
        // silently discarded and the rule set matched less than the user wrote
        // (fail-open routing).
        if let Some((rule_type, rest)) = trimmed.split_once(',') {
            let mut fields = rest
                .split(',')
                .map(|f| f.trim().trim_matches('\'').trim_matches('"'));
            let val = fields.next().unwrap_or_default();
            if val.is_empty() {
                self.stats
                    .unparsed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            match rule_type.trim().to_ascii_uppercase().as_str() {
                "DOMAIN-SUFFIX" => self.domain_suffix.push(val.to_string()),
                "DOMAIN" | "DOMAIN-FULL" => self.domain.push(val.to_string()),
                "DOMAIN-KEYWORD" => self.domain_keyword.push(val.to_string()),
                "IP-CIDR" | "IP-CIDR6" | "CIDR" => self.ip_cidr.push(val.to_string()),
                _ => {
                    // Unsupported Clash rule type (GEOIP, PROCESS-NAME, …): count
                    // it so the operator can see that the rule set is partial.
                    self.stats
                        .unparsed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
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
        } else if trimmed.parse::<std::net::IpAddr>().is_ok() {
            self.ip_cidr.push(trimmed.to_string());
        } else if let Some((addr, prefix)) = trimmed.split_once('/')
            && addr.parse::<std::net::IpAddr>().is_ok()
            && prefix.parse::<u8>().is_ok()
        {
            // A CIDR must actually be `address/prefix`: checking only for a slash
            // made `</html>` from an error page look like an IP rule, so a broken
            // feed produced a "non-empty" rule set that matched nothing.
            self.ip_cidr.push(trimmed.to_string());
        } else if Self::looks_like_domain(trimmed) {
            self.domain_suffix.push(trimmed.to_string());
        } else {
            // A bare word that cannot be a domain — in practice an HTML error
            // page, a captive-portal paragraph, or a JSON blob from a feed that
            // broke. Treating it as a domain suffix produced a rule set that
            // matched nothing meaningful and looked non-empty, which both hid the
            // failure and passed it to the "did this refresh yield anything?"
            // guard.
            self.stats
                .unparsed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// True when `s` can plausibly be a hostname: dot-separated labels of letters,
    /// digits, `-`, `_` and `*` (wildcard feeds exist), each label 1..=63 bytes,
    /// total ≤253. Rejects whitespace, angle brackets, quotes, control characters
    /// and anything else that cannot appear in a domain.
    fn looks_like_domain(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
        })
    }

    pub fn load_from_file(&mut self, path: &str) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            self.parse_rule_line(line);
        }
        Ok(())
    }

    /// Applies fetched content **only if it yields at least one rule**, keeping
    /// the previous contents otherwise.
    ///
    /// This is what a *refresh* must use. A remote feed that starts returning an
    /// error page, a captive-portal response or an empty file used to replace a
    /// working rule set with nothing, so every `rule_set` rule stopped matching
    /// and traffic silently fell through to the final outbound — which, for a
    /// proxy, can redirect traffic that was meant to be tunnelled straight onto
    /// the local network. An empty result is never better than what we have.
    ///
    /// Returns `true` when the new content was applied.
    pub fn try_apply_content(&self, content: &str) -> bool {
        // Parse with the same parser `apply_content` uses, so "usable" means
        // exactly what it will mean after the swap.
        let mut fetched = RuleSet::default();
        for line in content.lines() {
            fetched.parse_rule_line(line);
        }
        // `parse_rule_line` only bumps the *unparsed* counter; usable entries are
        // the parsed lists themselves (this is the same sum `apply_content` stores).
        let fetched_entries = fetched.domain.len()
            + fetched.domain_suffix.len()
            + fetched.domain_keyword.len()
            + fetched.ip_cidr.len();
        // Nothing usable in the new content and we already have something: keep it.
        if fetched_entries == 0 && self.parsed_entry_count() > 0 {
            return false;
        }
        self.apply_content(content);
        true
    }

    /// Atomically replaces the compiled contents with the given text (used by
    /// remote rule set fetches). Takes `&self` so it works through shared Arcs.
    pub fn apply_content(&self, content: &str) {
        // Merge into the lists the configuration supplied alongside
        // `type: remote` instead of replacing them: rebuilding from the fetched
        // text alone silently dropped every inline `domain`/`ip_cidr` entry.
        let mut merged = RuleSet {
            ip_cidr: self.ip_cidr.clone(),
            domain: self.domain.clone(),
            domain_suffix: self.domain_suffix.clone(),
            domain_keyword: self.domain_keyword.clone(),
            ..RuleSet::default()
        };
        for line in content.lines() {
            merged.parse_rule_line(line);
        }
        self.stats.parsed.store(
            merged.domain.len()
                + merged.domain_suffix.len()
                + merged.domain_keyword.len()
                + merged.ip_cidr.len(),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.stats.unparsed.store(
            merged
                .stats
                .unparsed
                .load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
        *self.compiled.write() = CompiledRuleSet::build(&merged);
    }

    /// Number of rule entries successfully parsed from the most recent load.
    pub fn parsed_entry_count(&self) -> usize {
        self.stats.parsed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Number of lines that could not be interpreted (unsupported rule type,
    /// malformed value, …). Non-zero means the rule set is partial.
    pub fn unparsed_entry_count(&self) -> usize {
        self.stats
            .unparsed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Rebuilds the compiled lookup structures from the raw lists and swaps them in.
    fn rebuild_compiled(&mut self) {
        let fresh = CompiledRuleSet::build(self);
        *self.compiled.write() = fresh;
    }

    /// Compiles derived lookup structures. Idempotent: derived sets are rebuilt from scratch,
    /// and the ruleset file is loaded at most once. Remote rule sets skip file loading.
    pub fn compile(&mut self) -> Result<(), String> {
        if self.remote_url.is_none()
            && !self.file_loaded
            && let Some(p) = self.path.clone()
        {
            let tag = self.tag.clone();
            self.load_from_file(&p)
                .map_err(|e| format!("failed to load ruleset '{}' from '{}': {}", tag, p, e))?;
            self.file_loaded = true;
        }

        self.rebuild_compiled();
        Ok(())
    }

    pub fn matches(&self, meta: &SessionMeta) -> bool {
        let compiled = self.compiled.read();
        match &meta.destination {
            flux_types::TargetAddress::Ip(sock) => {
                let ip = sock.ip();
                compiled.ip_range_set.contains(&ip)
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

                if compiled.exact_set.contains(domain_str) {
                    return true;
                }

                // O(L) Suffix lookup
                if compiled.suffix_set.contains(domain_str) {
                    return true;
                }

                let mut current = domain_str;
                while let Some(dot_idx) = current.find('.') {
                    current = &current[dot_idx + 1..];
                    if compiled.suffix_set.contains(current) {
                        return true;
                    }
                }

                // Keyword scan
                if !compiled.keyword_list.is_empty()
                    && compiled.keyword_list.iter().any(|k| domain_str.contains(k))
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

    /// Compiles and inserts a ruleset. Returns an error if the ruleset file cannot be loaded,
    /// so a missing file never silently degrades to an empty (never-matching) ruleset.
    pub fn insert(&mut self, mut ruleset: RuleSet) -> Result<(), String> {
        ruleset.compile()?;
        self.rule_sets
            .insert(ruleset.tag.clone(), Arc::new(ruleset));
        Ok(())
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
        rs.compile().unwrap();

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
        rs.compile().unwrap();

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
        rs.compile().unwrap();

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

#[cfg(test)]
mod parse_tests {
    use super::*;

    fn compiled_from(text: &str) -> RuleSet {
        let mut rs = RuleSet::default();
        for line in text.lines() {
            rs.parse_rule_line(line);
        }
        rs.rebuild_compiled();
        rs
    }

    /// Clash lines carry trailing modifiers such as `no-resolve`; the value is
    /// field 1 and everything after it must be ignored. Folding the modifier
    /// into the value made the CIDR unparseable and the rule silently vanished.
    #[test]
    fn clash_rule_with_no_resolve_is_parsed() {
        let rs =
            compiled_from("IP-CIDR,1.2.3.4/32,no-resolve\nDOMAIN-SUFFIX,example.com,no-resolve\n");
        assert_eq!(rs.ip_cidr, vec!["1.2.3.4/32"]);
        assert_eq!(rs.domain_suffix, vec!["example.com"]);
        assert_eq!(
            rs.parsed_entry_count(),
            0,
            "counters are set on apply_content"
        );
        // And the compiled matcher actually matches.
        assert!(
            rs.compiled
                .read()
                .ip_range_set
                .contains(&"1.2.3.4".parse().unwrap())
        );
        assert!(rs.compiled.read().suffix_set.contains("example.com"));
    }

    #[test]
    fn unsupported_rule_type_is_counted_not_silent() {
        let rs = compiled_from("GEOIP,CN\nPROCESS-NAME,curl\nDOMAIN,ok.example\n");
        assert_eq!(rs.domain, vec!["ok.example"]);
        assert_eq!(rs.unparsed_entry_count(), 2);
    }

    /// A remote refresh must merge with the config's inline lists instead of
    /// discarding them (they are part of the same rule set definition).
    #[test]
    fn apply_content_keeps_inline_lists() {
        let rs = RuleSet {
            domain: vec!["inline.example".into()],
            ip_cidr: vec!["10.0.0.0/8".into()],
            ..RuleSet::default()
        };
        rs.apply_content("DOMAIN-SUFFIX,fetched.example\n");
        let compiled = rs.compiled.read();
        assert!(
            compiled.exact_set.contains("inline.example"),
            "inline domain lost"
        );
        assert!(compiled.suffix_set.contains("fetched.example"));
        assert!(
            compiled.ip_range_set.contains(&"10.1.2.3".parse().unwrap()),
            "inline CIDR lost"
        );
        assert_eq!(rs.parsed_entry_count(), 3);
    }
}

#[cfg(test)]
mod refresh_guard_tests {
    use super::*;

    fn remote_only() -> RuleSet {
        RuleSet::default()
    }

    /// True when `domain` matches through the compiled sets (the same data the
    /// router queries).
    fn matches_domain(rs: &RuleSet, domain: &str) -> bool {
        let compiled = rs.compiled.read();
        compiled.exact_set.contains(domain) || compiled.suffix_set.contains(domain)
    }

    /// A refresh that parses to zero rules must not wipe a working rule set: that
    /// would make every `rule_set` rule stop matching and silently send traffic to
    /// the final outbound.
    #[test]
    fn an_empty_refresh_keeps_the_previous_rules() {
        let rs = remote_only();
        assert!(rs.try_apply_content("DOMAIN-SUFFIX,good.example\n"));
        assert_eq!(rs.parsed_entry_count(), 1);

        // A captive portal / error page / empty file.
        assert!(!rs.try_apply_content("<html><body>Login required</body></html>\n"));
        assert_eq!(
            rs.parsed_entry_count(),
            1,
            "the working rule set was replaced by an empty one"
        );
        assert!(
            matches_domain(&rs, "good.example"),
            "the old rule no longer matches after a failed refresh"
        );
    }

    /// The first successful load legitimately establishes the contents, and an
    /// empty first load is allowed (it only warns).
    #[test]
    fn the_first_load_may_be_empty() {
        let rs = remote_only();
        assert!(rs.try_apply_content(""));
        assert_eq!(rs.parsed_entry_count(), 0);

        assert!(rs.try_apply_content("DOMAIN,late.example\n"));
        assert!(matches_domain(&rs, "late.example"));
    }

    /// Partial-but-usable content is still applied: refusing it would keep stale
    /// rules forever when a feed drops an unsupported line.
    #[test]
    fn partial_content_is_applied() {
        let rs = remote_only();
        assert!(rs.try_apply_content("DOMAIN,first.example\n"));
        assert!(rs.try_apply_content("UNSUPPORTED-TYPE,whatever\nDOMAIN,second.example\n"));
        assert!(matches_domain(&rs, "second.example"));
    }
}

#[cfg(test)]
mod garbage_line_tests {
    use super::*;

    /// An HTML error page, a captive-portal paragraph or a JSON blob must not
    /// become rule entries. It used to: `</html>` contains a slash so it parsed as
    /// an IP-CIDR, and any bare word parsed as a domain suffix — producing a rule
    /// set that looked non-empty, matched nothing, and hid the failure.
    #[test]
    fn a_body_of_garbage_yields_no_rules() {
        for garbage in [
            "<html><body>Login required</body></html>",
            "<!DOCTYPE html><html><head><title>502</title></head></html>",
            "{\"error\":\"not found\"}",
            "Please sign in to continue",
            "\u{0}\u{1}binary junk",
        ] {
            let mut rs = RuleSet::default();
            rs.parse_rule_line(garbage);
            let total = rs.domain.len()
                + rs.domain_suffix.len()
                + rs.domain_keyword.len()
                + rs.ip_cidr.len();
            assert_eq!(total, 0, "garbage line {garbage:?} became a rule");
            assert!(
                rs.stats.unparsed.load(std::sync::atomic::Ordering::Relaxed) > 0,
                "garbage line {garbage:?} was not counted as unparsed"
            );
        }
    }

    /// The legitimate shapes must keep parsing exactly as before.
    #[test]
    fn legitimate_lines_still_parse() {
        let mut rs = RuleSet::default();
        for line in [
            "DOMAIN-SUFFIX,google.com",
            "DOMAIN,exact.example.org",
            "DOMAIN-KEYWORD,telemetry",
            "IP-CIDR,10.0.0.0/8",
            "IP-CIDR6,2001:db8::/32",
            "10.1.2.3/32",
            "192.168.1.1",
            "example.com",
            "full:www.example.net",
            "suffix:cdn.example.net",
            "keyword:ads",
            "ip-cidr:172.16.0.0/12",
            "+.wild.example",
            "*.wildcard.example",
            "xn--80ak6aa92e.com",
            "localhost",
        ] {
            rs.parse_rule_line(line);
        }
        assert_eq!(
            rs.domain_suffix.len(),
            7,
            "suffix entries: {:?}",
            rs.domain_suffix
        );
        assert_eq!(rs.domain.len(), 2);
        assert_eq!(rs.domain_keyword.len(), 2);
        assert_eq!(rs.ip_cidr.len(), 5);
        assert_eq!(
            rs.stats.unparsed.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a legitimate line was rejected"
        );
    }
}
