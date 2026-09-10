use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use ipnet::Ipv4Net;
use lru::LruCache;

#[derive(Debug)]
pub struct FakeIpPool {
    network: Ipv4Net,
    current: Mutex<u32>,
    domain_to_ip: Mutex<LruCache<String, Ipv4Addr>>,
    ip_to_domain: Mutex<LruCache<Ipv4Addr, String>>,
}

impl FakeIpPool {
    pub fn new(cidr: &str, capacity: usize) -> Result<Self, ipnet::AddrParseError> {
        let network: Ipv4Net = cidr.parse()?;
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(10000).unwrap());
        
        // Start from first usable IP in network
        let start_ip = u32::from(network.network()) + 1;

        Ok(Self {
            network,
            current: Mutex::new(start_ip),
            domain_to_ip: Mutex::new(LruCache::new(cap)),
            ip_to_domain: Mutex::new(LruCache::new(cap)),
        })
    }

    pub fn default_pool() -> Self {
        Self::new("198.18.0.0/15", 10000).expect("valid default fake-ip cidr")
    }

    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let domain_lower = domain.to_ascii_lowercase();
        
        let mut d2i = self.domain_to_ip.lock().unwrap();
        let mut i2d = self.ip_to_domain.lock().unwrap();

        if let Some(&ip) = d2i.get(&domain_lower) {
            i2d.get(&ip); // promote in LRU
            return ip;
        }

        // Allocate next IP
        let mut curr = self.current.lock().unwrap();
        let start = u32::from(self.network.network()) + 1;
        let end = u32::from(self.network.broadcast()) - 1;

        let next_ip_u32 = *curr;
        if *curr >= end {
            *curr = start;
        } else {
            *curr += 1;
        }

        let ip = Ipv4Addr::from(next_ip_u32);

        // If this IP was previously mapped to an old domain, remove old mapping
        if let Some(old_domain) = i2d.put(ip, domain_lower.clone()) {
            d2i.pop(&old_domain);
        }
        d2i.put(domain_lower, ip);

        ip
    }

    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let mut i2d = self.ip_to_domain.lock().unwrap();
                i2d.get(ipv4).cloned()
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
        assert_eq!(pool.lookup_domain(&IpAddr::V4(ip1)), Some("example.com".into()));
        assert_eq!(pool.lookup_domain(&IpAddr::V4(ip2)), Some("google.com".into()));
        assert_eq!(pool.lookup_domain(&"8.8.8.8".parse().unwrap()), None);
    }
}
