use ipnet::Ipv4Net;
use lru::LruCache;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};

const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(10000) {
    Some(v) => v,
    None => unreachable!(),
};

#[derive(Debug)]
struct FakeIpCache {
    domain_to_ip: LruCache<String, Ipv4Addr>,
    ip_to_domain: LruCache<Ipv4Addr, String>,
}

#[derive(Debug)]
pub struct FakeIpPool {
    network: Ipv4Net,
    start_ip: u32,
    end_ip: u32,
    current: AtomicU32,
    cache: Mutex<FakeIpCache>,
}

impl FakeIpPool {
    pub fn new(cidr: &str, capacity: usize) -> Result<Self, ipnet::AddrParseError> {
        let network: Ipv4Net = cidr.parse()?;
        let cap = NonZeroUsize::new(capacity).unwrap_or(DEFAULT_CAPACITY);

        // saturating ops guard against degenerate prefixes (/31, /32, 0.0.0.0/32)
        // where broadcast() - 1 or network() + 1 would otherwise underflow/overflow.
        let start_ip = u32::from(network.network()).saturating_add(1);
        let end_ip = u32::from(network.broadcast())
            .saturating_sub(1)
            .max(start_ip);

        Ok(Self {
            network,
            start_ip,
            end_ip,
            current: AtomicU32::new(start_ip),
            cache: Mutex::new(FakeIpCache {
                domain_to_ip: LruCache::new(cap),
                ip_to_domain: LruCache::new(cap),
            }),
        })
    }

    pub fn default_pool() -> Self {
        match Self::new("198.18.0.0/15", 10000) {
            Ok(p) => p,
            Err(_) => {
                let net = Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 15).unwrap_or_default();
                let start = u32::from(net.network()).saturating_add(1);
                let end = u32::from(net.broadcast()).saturating_sub(1).max(start);
                Self {
                    network: net,
                    start_ip: start,
                    end_ip: end,
                    current: AtomicU32::new(start),
                    cache: Mutex::new(FakeIpCache {
                        domain_to_ip: LruCache::new(DEFAULT_CAPACITY),
                        ip_to_domain: LruCache::new(DEFAULT_CAPACITY),
                    }),
                }
            }
        }
    }

    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let domain_lower = domain.to_ascii_lowercase();

        let mut guard = self.cache.lock();

        if let Some(&ip) = guard.domain_to_ip.get(&domain_lower) {
            guard.ip_to_domain.get(&ip); // promote in LRU
            return ip;
        }

        // Allocate next IP atomically
        let next_ip_u32 = loop {
            let curr = self.current.load(Ordering::Relaxed);
            let next = if curr >= self.end_ip {
                self.start_ip
            } else {
                curr + 1
            };
            if self
                .current
                .compare_exchange_weak(curr, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break curr;
            }
        };

        let ip = Ipv4Addr::from(next_ip_u32);

        // If this IP was previously mapped (e.g. after wrap-around), remove old reverse mapping
        if let Some(old_domain) = guard.ip_to_domain.pop(&ip) {
            guard.domain_to_ip.pop(&old_domain);
        }

        // Atomically insert into both LRU caches, synchronizing evictions to prevent
        // orphaned mappings. Each eviction is cross-checked: the reverse mapping is only
        // removed when it still points at the evicted counterpart (the IP may have been
        // re-allocated to another domain after a pool wrap-around in between).
        if let Some((evicted_ip, evicted_domain)) =
            guard.ip_to_domain.push(ip, domain_lower.clone())
            && guard.domain_to_ip.get(&evicted_domain) == Some(&evicted_ip)
        {
            guard.domain_to_ip.pop(&evicted_domain);
        }
        if let Some((evicted_domain, evicted_ip)) = guard.domain_to_ip.push(domain_lower, ip)
            && guard.ip_to_domain.get(&evicted_ip) == Some(&evicted_domain)
        {
            guard.ip_to_domain.pop(&evicted_ip);
        }

        ip
    }

    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let mut guard = self.cache.lock();
                guard.ip_to_domain.get(ipv4).cloned()
            }
            IpAddr::V6(_) => None,
        }
    }

    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.network.contains(ipv4),
            IpAddr::V6(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fakeip_allocation_and_lookup() {
        let pool = FakeIpPool::new("198.18.0.0/24", 50).unwrap();
        let ip1 = pool.allocate("example.com");
        let ip2 = pool.allocate("google.com");

        assert_ne!(ip1, ip2);
        assert!(pool.contains_ip(&IpAddr::V4(ip1)));
        assert!(pool.contains_ip(&IpAddr::V4(ip2)));

        // Re-allocation returns cached IP
        let ip1_repeat = pool.allocate("EXAMPLE.COM");
        assert_eq!(ip1, ip1_repeat);

        // Reverse lookup
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip1)),
            Some("example.com".into())
        );
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip2)),
            Some("google.com".into())
        );

        // Unknown IP returns None
        assert_eq!(pool.lookup_domain(&"1.2.3.4".parse().unwrap()), None);
    }

    #[test]
    fn test_fakeip_degenerate_cidr_no_panic() {
        // /32: broadcast == network, naive `broadcast - 1` would underflow.
        // Allocation must not panic and forward/reverse maps must stay consistent.
        let pool = FakeIpPool::new("10.9.8.7/32", 4).unwrap();
        let ip = pool.allocate("a.example");
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip)),
            Some("a.example".into())
        );

        // /31 must not panic either.
        let pool31 = FakeIpPool::new("192.0.2.0/31", 4).unwrap();
        let _ = pool31.allocate("b.example");
    }

    #[test]
    fn test_fakeip_wraparound_eviction() {
        let pool = FakeIpPool::new("198.18.0.0/30", 100).unwrap();
        let ip1 = pool.allocate("first.com");
        let ip2 = pool.allocate("second.com");
        assert_ne!(ip1, ip2);
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip1)),
            Some("first.com".into())
        );
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip2)),
            Some("second.com".into())
        );

        // 3rd allocation forces wrap-around back to start_ip (reusing ip1)
        let ip3 = pool.allocate("third.com");
        assert_eq!(ip3, ip1);

        // Stale mapping for first.com must have been evicted from both directions
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip3)),
            Some("third.com".into())
        );

        // Allocating first.com again must allocate a new IP (ip2) because old mapping was popped
        let ip1_new = pool.allocate("first.com");
        assert_eq!(ip1_new, ip2);
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip1_new)),
            Some("first.com".into())
        );
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip3)),
            Some("third.com".into())
        );
    }
}
