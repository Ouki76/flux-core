use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRangeSet {
    v4_ranges: Vec<(u32, u32)>,
    v6_ranges: Vec<(u128, u128)>,
}

impl IpRangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_cidrs(cidrs: &[IpNet]) -> Self {
        let mut v4_raw = Vec::new();
        let mut v6_raw = Vec::new();

        for net in cidrs {
            match net {
                IpNet::V4(net4) => {
                    let start = u32::from(net4.network());
                    let end = u32::from(net4.broadcast());
                    v4_raw.push((start, end));
                }
                IpNet::V6(net6) => {
                    let start = u128::from(net6.network());
                    let end = u128::from(net6.broadcast());
                    v6_raw.push((start, end));
                }
            }
        }

        v4_raw.sort_unstable_by_key(|r| r.0);
        v6_raw.sort_unstable_by_key(|r| r.0);

        let v4_ranges = merge_ranges_u32(v4_raw);
        let v6_ranges = merge_ranges_u128(v6_raw);

        Self {
            v4_ranges,
            v6_ranges,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.v4_ranges.is_empty() && self.v6_ranges.is_empty()
    }

    /// True when `ip` is inside the set.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is the *same peer* as
    /// `a.b.c.d`, so v4 ranges apply to it too. Without this a dual-stack
    /// inbound that reports a mapped destination (or a SOCKS5 client using
    /// `ATYP=IPv6` for a v4 literal) missed every v4 rule — the classic leak,
    /// since `IP-CIDR,10.0.0.0/8,direct` then fell through to `final` and the
    /// internal host was tunnelled instead of reached directly.
    ///
    /// An explicit v6 rule still wins: the address is checked against the v6
    /// ranges first, so `IP-CIDR6,::ffff:0:0/96` keeps working.
    #[inline]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(*v4),
            IpAddr::V6(v6) => {
                if self.contains_v6(*v6) {
                    return true;
                }
                match v6.to_canonical() {
                    IpAddr::V4(v4) => self.contains_v4(v4),
                    IpAddr::V6(_) => false,
                }
            }
        }
    }

    #[inline]
    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        if self.v4_ranges.is_empty() {
            return false;
        }
        let val = u32::from(ip);
        self.v4_ranges
            .binary_search_by(|&(s, e)| {
                if val < s {
                    std::cmp::Ordering::Greater
                } else if val > e {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    #[inline]
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        if self.v6_ranges.is_empty() {
            return false;
        }
        let val = u128::from(ip);
        self.v6_ranges
            .binary_search_by(|&(s, e)| {
                if val < s {
                    std::cmp::Ordering::Greater
                } else if val > e {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }
}

/// CIDR-list membership with the same semantics as [`IpRangeSet`], for rules
/// whose ranges were never compiled (`compile_cidrs` is optional).
pub fn cidr_list_contains(cidrs: &[IpNet], ip: IpAddr) -> bool {
    if cidrs.iter().any(|cidr| cidr.contains(&ip)) {
        return true;
    }
    let canonical = ip.to_canonical();
    canonical != ip && cidrs.iter().any(|cidr| cidr.contains(&canonical))
}

fn merge_ranges_u32(sorted: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

fn merge_ranges_u128(sorted: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_range_set_v4() {
        let cidrs = vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/23".parse().unwrap(), // overlaps with 192.168.1.0/24
        ];
        let set = IpRangeSet::from_cidrs(&cidrs);

        assert!(set.contains(&"192.168.1.55".parse().unwrap()));
        assert!(set.contains(&"192.168.0.1".parse().unwrap()));
        assert!(set.contains(&"10.254.1.1".parse().unwrap()));
        assert!(!set.contains(&"172.16.0.1".parse().unwrap()));
        assert!(!set.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ip_range_set_v6() {
        let cidrs = vec![
            "2001:db8::/32".parse().unwrap(),
            "fe80::/10".parse().unwrap(),
        ];
        let set = IpRangeSet::from_cidrs(&cidrs);

        assert!(set.contains(&"2001:db8:1234::1".parse().unwrap()));
        assert!(set.contains(&"fe80::1".parse().unwrap()));
        assert!(!set.contains(&"2606:4700::1".parse().unwrap()));
    }
}

#[cfg(test)]
mod adversarial {
    use super::*;
    use std::str::FromStr;

    fn set(cidrs: &[&str]) -> IpRangeSet {
        let parsed: Vec<IpNet> = cidrs.iter().map(|c| IpNet::from_str(c).unwrap()).collect();
        IpRangeSet::from_cidrs(&parsed)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// `/0` is every address of that family and nothing of the other; `/32`
    /// (and `/128`) is exactly one address.
    #[test]
    fn zero_and_max_prefix() {
        let all4 = set(&["0.0.0.0/0"]);
        assert!(all4.contains(&ip("0.0.0.0")));
        assert!(all4.contains(&ip("255.255.255.255")));
        assert!(all4.contains(&ip("8.8.8.8")));
        assert!(!all4.contains(&ip("2001:db8::1")), "/0 must not cover v6");

        let all6 = set(&["::/0"]);
        assert!(all6.contains(&ip("::")));
        assert!(all6.contains(&ip("2001:db8::1")));
        assert!(!all6.contains(&ip("1.2.3.4")));

        let one = set(&["1.2.3.4/32"]);
        assert!(one.contains(&ip("1.2.3.4")));
        assert!(!one.contains(&ip("1.2.3.5")));
        assert!(!one.contains(&ip("1.2.3.3")));

        let one6 = set(&["2001:db8::1/128"]);
        assert!(one6.contains(&ip("2001:db8::1")));
        assert!(!one6.contains(&ip("2001:db8::2")));
    }

    /// Network and broadcast addresses are members; the neighbours are not.
    #[test]
    fn boundaries() {
        let s = set(&["10.0.0.0/24", "2001:db8::/32"]);
        assert!(s.contains(&ip("10.0.0.0")), "network address");
        assert!(s.contains(&ip("10.0.0.255")), "broadcast address");
        assert!(!s.contains(&ip("10.0.1.0")));
        assert!(!s.contains(&ip("9.255.255.255")));
        assert!(s.contains(&ip("2001:db8::")));
        assert!(s.contains(&ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!s.contains(&ip("2001:db9::")));
    }

    /// Adjacent ranges are merged, so a lookup cannot land in the seam.
    #[test]
    fn adjacent_ranges_merge_without_a_seam() {
        let s = set(&["10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24"]);
        for host in 0..=255u8 {
            assert!(s.contains(&ip(&format!("10.0.0.{host}"))), "10.0.0.{host}");
        }
        assert!(!s.contains(&ip("10.0.2.0")));
        // Two /1s are the whole v4 space, including the join point.
        let half = set(&["0.0.0.0/1", "128.0.0.0/1"]);
        assert!(half.contains(&ip("127.255.255.255")));
        assert!(half.contains(&ip("128.0.0.0")));
        // The merge must not saturate into an accidental /0 extension.
        let tail = set(&["0.0.0.0/1"]);
        assert!(!tail.contains(&ip("128.0.0.0")));
    }

    /// Empty set: never matches (a rule set that is empty must be "no match",
    /// not "match everything").
    #[test]
    fn empty_set_matches_nothing() {
        let s = IpRangeSet::new();
        assert!(s.is_empty());
        assert!(!s.contains(&ip("0.0.0.0")));
        assert!(!s.contains(&ip("::")));
    }

    /// A v4-mapped address is checked against v4 ranges as well, but an explicit
    /// v6 range still wins.
    #[test]
    fn v4_mapped_v6() {
        let s = set(&["203.0.113.0/24"]);
        assert!(s.contains(&ip("::ffff:203.0.113.9")));
        assert!(s.contains(&ip("203.0.113.9")));
        assert!(!s.contains(&ip("::ffff:203.0.114.9")));
        // Not a mapped address: unaffected.
        assert!(!s.contains(&ip("2001:db8::1")));

        let explicit6 = set(&["::ffff:203.0.113.0/120"]);
        assert!(explicit6.contains(&ip("::ffff:203.0.113.9")));
        assert!(
            !explicit6.contains(&ip("203.0.113.9")),
            "a v6-only range must not cover the plain v4 form"
        );
    }

    /// Differential check against a brute-force membership oracle over random
    /// CIDRs (including nested, adjacent and duplicate ones) — the merged
    /// ranges and the binary search must never disagree with linear scanning.
    #[test]
    fn merged_ranges_agree_with_a_linear_oracle() {
        struct Rng(u64);
        impl Rng {
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
        }

        let mut rng = Rng(0x5eed_1234_9876_abcd);
        for round in 0..200 {
            let count = 1 + rng.below(6) as usize;
            let mut cidrs = Vec::new();
            for _ in 0..count {
                // Cluster around a small slice of the v4 space so ranges
                // overlap, nest and touch.
                let prefix = 22 + rng.below(11) as u8; // /22 ..= /32
                let bytes = [
                    (10 + rng.below(2)) as u8,
                    rng.below(3) as u8,
                    rng.below(3) as u8,
                    0,
                ];
                let addr = Ipv4Addr::from(bytes);
                cidrs.push(IpNet::V4(ipnet::Ipv4Net::new(addr, prefix).unwrap()));
            }
            // A v6 range and a full-v4 range now and then.
            if round % 7 == 0 {
                cidrs.push("::/0".parse().unwrap());
            }
            if round % 11 == 0 {
                cidrs.push("0.0.0.0/0".parse().unwrap());
            }
            let compiled = IpRangeSet::from_cidrs(&cidrs);

            for _ in 0..200 {
                let probe = IpAddr::V4(Ipv4Addr::from([
                    (9 + rng.below(5)) as u8,
                    rng.below(4) as u8,
                    rng.below(4) as u8,
                    rng.below(4) as u8,
                ]));
                let oracle = cidrs.iter().any(|c| c.contains(&probe));
                assert_eq!(
                    compiled.contains(&probe),
                    oracle,
                    "round {round}: {probe} vs {cidrs:?}"
                );
            }
        }
    }

    /// The uncompiled fallback used by `Rule::matches` must behave exactly like
    /// the compiled set, including the mapped-v4 handling.
    #[test]
    fn cidr_list_fallback_matches_compiled_semantics() {
        let cidrs: Vec<IpNet> = ["10.0.0.0/8", "203.0.113.1/32"]
            .iter()
            .map(|c| IpNet::from_str(c).unwrap())
            .collect();
        let compiled = IpRangeSet::from_cidrs(&cidrs);
        for probe in [
            "10.1.2.3",
            "203.0.113.1",
            "::ffff:10.1.2.3",
            "::ffff:203.0.113.1",
            "8.8.8.8",
            "2001:db8::1",
        ] {
            let a = ip(probe);
            assert_eq!(
                cidr_list_contains(&cidrs, a),
                compiled.contains(&a),
                "{probe}"
            );
        }
        assert!(cidr_list_contains(&cidrs, ip("::ffff:10.1.2.3")));
        assert!(!cidr_list_contains(&[], ip("10.1.2.3")));
    }
}
