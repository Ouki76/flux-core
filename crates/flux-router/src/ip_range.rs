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

    #[inline]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(*v4),
            IpAddr::V6(v6) => self.contains_v6(*v6),
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
