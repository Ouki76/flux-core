//! Fake-IP pools.
//!
//! A fake-IP pool hands out synthetic addresses for domain names so that a
//! client which resolves names itself (a browser, a TLS stack, anything that
//! does not send a domain in its connect request) still produces a connection
//! the proxy can attribute to a *domain*. The reverse mapping is what makes
//! domain-based routing work for them.
//!
//! There is one pool per address family:
//!
//! * IPv4 is mandatory and defaults to `198.18.0.0/15` (RFC 2544 benchmarking
//!   space — never routable, never assigned).
//! * IPv6 is optional and defaults to `fc00::/18` when enabled. `fc00::/7` is
//!   the RFC 4193 unique-local space: never globally routable and never
//!   assigned to a host, so handing these addresses to clients cannot collide
//!   with anything reachable. With no v6 pool configured, `AAAA` queries are
//!   answered with NODATA and clients fall back to IPv4 exactly as before.
//!
//! Both directions of the mapping are kept in LRU caches that are updated
//! together, so a forward lookup can never point at an IP whose reverse mapping
//! belongs to another name (which would misroute connections).

use ipnet::{Ipv4Net, Ipv6Net};
use lru::LruCache;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};

/// Default IPv4 fake-IP range (RFC 2544 benchmarking space).
pub const DEFAULT_INET4_RANGE: &str = "198.18.0.0/15";
/// Default IPv6 fake-IP range (RFC 4193 unique-local space).
pub const DEFAULT_INET6_RANGE: &str = "fc00::/18";
/// Default number of concurrently mapped names per family.
pub const DEFAULT_FAKEIP_CAPACITY: usize = 10_000;

const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(DEFAULT_FAKEIP_CAPACITY) {
    Some(v) => v,
    None => unreachable!(),
};

/// The inclusive window of addresses a pool hands out inside `[network, broadcast]`.
///
/// The first and last address of a subnet are skipped where they exist (network
/// and broadcast address, as the v4 default range does), and a range with no
/// interior — `/31`, `/32` v4, `/127`, `/128` v6 — falls back to the whole range.
///
/// The result is **always** inside `[network, broadcast]`: that is what makes
/// `contains_ip` agree with `allocate`, and `contains_ip` is what decides whether
/// a destination is treated as a fake-IP (and therefore re-mapped to its domain
/// and routed by name). An address outside the range would be dialled as a
/// literal IP and silently bypass the domain rules.
fn usable_window(network: u128, broadcast: u128) -> (u128, u128) {
    let first = network.saturating_add(1);
    let last = broadcast.saturating_sub(1);
    if first > last || first > broadcast {
        (network, broadcast.max(network))
    } else {
        (first, last)
    }
}

#[derive(Debug)]
struct FakeIpCache {
    domain_to_ip: LruCache<String, Ipv4Addr>,
    ip_to_domain: LruCache<Ipv4Addr, String>,
}

/// IPv6 side of the pool. The allocation cursor and both LRUs share one lock:
/// IPv6 has no 128-bit atomics on stable Rust and the whole operation is a few
/// hash lookups, so a single mutex is both simpler and fast enough.
#[derive(Debug)]
struct V6State {
    next: u128,
    domain_to_ip: LruCache<String, Ipv6Addr>,
    ip_to_domain: LruCache<Ipv6Addr, String>,
}

#[derive(Debug)]
struct V6Pool {
    network: Ipv6Net,
    start: u128,
    end: u128,
    state: Mutex<V6State>,
}

impl V6Pool {
    fn new(cidr: &str, capacity: usize) -> Result<Self, ipnet::AddrParseError> {
        let network: Ipv6Net = cidr.parse()?;
        let cap = NonZeroUsize::new(capacity).unwrap_or(DEFAULT_CAPACITY);

        // Same rule as the v4 pool: the allocatable window is the range minus
        // its network and broadcast addresses, and it always stays *inside* the
        // configured range. A degenerate prefix (/128, /127) has no such
        // interior, so it falls back to the range itself instead of walking out
        // of it.
        let (start, end) = usable_window(
            u128::from(network.network()),
            u128::from(network.broadcast()),
        );

        Ok(Self {
            network,
            start,
            end,
            state: Mutex::new(V6State {
                next: start,
                domain_to_ip: LruCache::new(cap),
                ip_to_domain: LruCache::new(cap),
            }),
        })
    }

    fn allocate(&self, domain: &str) -> Ipv6Addr {
        let domain_lower = domain.to_ascii_lowercase();
        let mut st = self.state.lock();
        let V6State {
            next,
            domain_to_ip,
            ip_to_domain,
        } = &mut *st;

        if let Some(&ip) = domain_to_ip.get(&domain_lower) {
            ip_to_domain.get(&ip); // promote in the LRU
            return ip;
        }

        let ip_u128 = *next;
        *next = if ip_u128 >= self.end {
            self.start
        } else {
            ip_u128 + 1
        };
        let ip = Ipv6Addr::from(ip_u128);

        // A wrapped-around address may still be mapped to an older name.
        if let Some(old_domain) = ip_to_domain.pop(&ip)
            && domain_to_ip.get(&old_domain) == Some(&ip)
        {
            domain_to_ip.pop(&old_domain);
        }

        // Insert into both directions, cross-checking each eviction so the two
        // maps cannot drift apart.
        if let Some((evicted_ip, evicted_domain)) = ip_to_domain.push(ip, domain_lower.clone())
            && domain_to_ip.get(&evicted_domain) == Some(&evicted_ip)
        {
            domain_to_ip.pop(&evicted_domain);
        }
        if let Some((evicted_domain, evicted_ip)) = domain_to_ip.push(domain_lower, ip)
            && ip_to_domain.get(&evicted_ip) == Some(&evicted_domain)
        {
            ip_to_domain.pop(&evicted_ip);
        }

        ip
    }

    fn lookup(&self, ip: &Ipv6Addr) -> Option<String> {
        self.state.lock().ip_to_domain.get(ip).cloned()
    }
}

#[derive(Debug)]
pub struct FakeIpPool {
    network: Ipv4Net,
    start_ip: u32,
    end_ip: u32,
    current: AtomicU32,
    cache: Mutex<FakeIpCache>,
    /// `None` when the v6 side is disabled (the default): `AAAA` queries are
    /// then answered with NODATA.
    v6: Option<V6Pool>,
}

impl FakeIpPool {
    /// Creates the IPv4 pool. The IPv6 side stays disabled; see
    /// [`FakeIpPool::with_inet6`].
    pub fn new(cidr: &str, capacity: usize) -> Result<Self, ipnet::AddrParseError> {
        let network: Ipv4Net = cidr.parse()?;
        let cap = NonZeroUsize::new(capacity).unwrap_or(DEFAULT_CAPACITY);

        // The allocatable window always stays inside the configured range; see
        // `usable_window` for why that invariant matters.
        let (start_ip, end_ip) = usable_window(
            u128::from(u32::from(network.network())),
            u128::from(u32::from(network.broadcast())),
        );
        let (start_ip, end_ip) = (start_ip as u32, end_ip as u32);

        Ok(Self {
            network,
            start_ip,
            end_ip,
            current: AtomicU32::new(start_ip),
            cache: Mutex::new(FakeIpCache {
                domain_to_ip: LruCache::new(cap),
                ip_to_domain: LruCache::new(cap),
            }),
            v6: None,
        })
    }

    /// Enables the IPv6 pool from `cidr`.
    ///
    /// Returns an error (leaving the pool unusable) when the CIDR is not a valid
    /// IPv6 network, so a typo cannot silently disable the feature.
    pub fn with_inet6(
        mut self,
        cidr: &str,
        capacity: usize,
    ) -> Result<Self, ipnet::AddrParseError> {
        self.v6 = Some(V6Pool::new(cidr, capacity)?);
        Ok(self)
    }

    /// Enables the IPv6 pool only when `cidr` asks for one.
    ///
    /// An empty value (or `off`/`none`/`disabled`/`false`) is the documented way
    /// to keep `AAAA` answers at NODATA.
    pub fn with_inet6_opt(
        self,
        cidr: &str,
        capacity: usize,
    ) -> Result<Self, ipnet::AddrParseError> {
        let trimmed = cidr.trim();
        if trimmed.is_empty()
            || matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "off" | "none" | "disabled" | "false" | "no"
            )
        {
            return Ok(self);
        }
        self.with_inet6(trimmed, capacity)
    }

    /// Creates a pool from the two configured ranges in one call.
    ///
    /// `inet6` follows the same "empty or `off` disables" rule as
    /// [`FakeIpPool::with_inet6_opt`], so this is the one-liner the config layer
    /// should use:
    ///
    /// ```ignore
    /// let pool = FakeIpPool::from_ranges(inet4_range, inet6_range.as_deref(), 10000)?;
    /// ```
    pub fn from_ranges(
        inet4: &str,
        inet6: Option<&str>,
        capacity: usize,
    ) -> Result<Self, ipnet::AddrParseError> {
        let pool = Self::new(inet4, capacity)?;
        match inet6 {
            Some(cidr) => pool.with_inet6_opt(cidr, capacity),
            None => Ok(pool),
        }
    }

    pub fn default_pool() -> Self {
        match Self::new(DEFAULT_INET4_RANGE, DEFAULT_FAKEIP_CAPACITY) {
            Ok(p) => p,
            Err(_) => {
                let net = Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 15).unwrap_or_default();
                let (start, end) = usable_window(
                    u128::from(u32::from(net.network())),
                    u128::from(u32::from(net.broadcast())),
                );
                let (start, end) = (start as u32, end as u32);
                Self {
                    network: net,
                    start_ip: start,
                    end_ip: end,
                    current: AtomicU32::new(start),
                    cache: Mutex::new(FakeIpCache {
                        domain_to_ip: LruCache::new(DEFAULT_CAPACITY),
                        ip_to_domain: LruCache::new(DEFAULT_CAPACITY),
                    }),
                    v6: None,
                }
            }
        }
    }

    /// `default_pool()` plus the default IPv6 range (`fc00::/18`).
    pub fn default_dual_stack_pool() -> Self {
        match Self::default_pool().with_inet6(DEFAULT_INET6_RANGE, DEFAULT_FAKEIP_CAPACITY) {
            Ok(p) => p,
            // The default range is a compile-time constant and always parses;
            // falling back to v4-only is still correct behaviour.
            Err(_) => Self::default_pool(),
        }
    }

    pub fn inet4_network(&self) -> Ipv4Net {
        self.network
    }

    /// The configured IPv6 range, `None` when the v6 pool is disabled.
    pub fn inet6_network(&self) -> Option<Ipv6Net> {
        self.v6.as_ref().map(|v| v.network)
    }

    pub fn has_inet6(&self) -> bool {
        self.v6.is_some()
    }

    /// Allocates (or reuses) the IPv4 address for `domain`.
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

    /// Allocates (or reuses) the IPv6 address for `domain`.
    ///
    /// `None` when no v6 pool is configured — the caller must then answer
    /// `AAAA` with NODATA rather than inventing an address.
    pub fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        self.v6.as_ref().map(|v| v.allocate(domain))
    }

    /// Allocates for whichever family the caller asked for.
    pub fn allocate_family(&self, domain: &str, want_v6: bool) -> Option<IpAddr> {
        if want_v6 {
            self.allocate_v6(domain).map(IpAddr::V6)
        } else {
            Some(IpAddr::V4(self.allocate(domain)))
        }
    }

    /// Maps a fake address of either family back to its domain.
    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let mut guard = self.cache.lock();
                guard.ip_to_domain.get(ipv4).cloned()
            }
            IpAddr::V6(ipv6) => self.v6.as_ref().and_then(|v| v.lookup(ipv6)),
        }
    }

    /// True when `ip` belongs to one of the configured fake ranges.
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.network.contains(ipv4),
            IpAddr::V6(ipv6) => self.v6.as_ref().is_some_and(|v| v.network.contains(ipv6)),
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

    #[test]
    fn v6_pool_is_opt_in() {
        let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 64).unwrap();
        assert!(!pool.has_inet6());
        assert_eq!(pool.inet6_network(), None);
        assert_eq!(
            pool.allocate_v6("example.com"),
            None,
            "no v6 pool -> NODATA"
        );
        // A random v6 address is never "inside" a v4-only pool.
        assert!(!pool.contains_ip(&"fc00::1".parse().unwrap()));
        assert_eq!(pool.lookup_domain(&"fc00::1".parse().unwrap()), None);
        // The v4 side still works.
        assert!(pool.allocate_family("example.com", false).is_some());
    }

    #[test]
    fn v6_allocation_and_bidirectional_mapping() {
        let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 64)
            .unwrap()
            .with_inet6(DEFAULT_INET6_RANGE, 64)
            .unwrap();
        assert_eq!(
            pool.inet6_network().map(|n| n.to_string()),
            Some(DEFAULT_INET6_RANGE.to_string())
        );

        let v6 = pool.allocate_v6("example.com").expect("v6 pool");
        assert!(v6.is_unique_local(), "must stay inside fc00::/7");
        assert!(pool.contains_ip(&IpAddr::V6(v6)));
        assert_eq!(
            pool.lookup_domain(&IpAddr::V6(v6)),
            Some("example.com".into())
        );

        // Stable across repeated queries, and case-insensitive.
        assert_eq!(pool.allocate_v6("EXAMPLE.com"), Some(v6));

        // A different name gets a different address.
        let other = pool.allocate_v6("other.com").unwrap();
        assert_ne!(other, v6);

        // Both families map the same name independently.
        let v4 = pool.allocate("example.com");
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(v4)),
            Some("example.com".into())
        );
        assert_eq!(
            pool.lookup_domain(&IpAddr::V6(v6)),
            Some("example.com".into())
        );

        // allocate_family routes by the requested family.
        assert_eq!(
            pool.allocate_family("example.com", true),
            Some(IpAddr::V6(v6))
        );
        assert_eq!(
            pool.allocate_family("example.com", false),
            Some(IpAddr::V4(v4))
        );

        // Unknown v6 address: inside the range but never allocated.
        assert_eq!(pool.lookup_domain(&"fc00::ffff".parse().unwrap()), None);
    }

    #[test]
    fn v6_wraparound_evicts_the_old_mapping() {
        let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 8)
            .unwrap()
            .with_inet6("fc00::/126", 100) // 4 addresses, 2 usable
            .unwrap();
        let a = pool.allocate_v6("a.test").unwrap();
        let b = pool.allocate_v6("b.test").unwrap();
        assert_ne!(a, b);

        // Wrap-around reuses `a` for a third name.
        let c = pool.allocate_v6("c.test").unwrap();
        assert_eq!(c, a);
        assert_eq!(pool.lookup_domain(&IpAddr::V6(c)), Some("c.test".into()));
        assert_eq!(
            pool.lookup_domain(&IpAddr::V6(a)),
            Some("c.test".into()),
            "the stale mapping must be gone"
        );

        // Re-allocating a.test must not resurrect the old address.
        let a2 = pool.allocate_v6("a.test").unwrap();
        assert_ne!(a2, c);
    }

    #[test]
    fn v6_range_can_be_disabled_explicitly() {
        for off in ["", "  ", "off", "DISABLED", "none"] {
            let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 8)
                .unwrap()
                .with_inet6_opt(off, 8)
                .unwrap();
            assert!(!pool.has_inet6(), "'{off}' must disable the v6 pool");
        }
        let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 8)
            .unwrap()
            .with_inet6_opt(DEFAULT_INET6_RANGE, 8)
            .unwrap();
        assert!(pool.has_inet6());
    }

    #[test]
    fn from_ranges_enables_v6_only_when_asked() {
        let v4_only = FakeIpPool::from_ranges(DEFAULT_INET4_RANGE, None, 16).unwrap();
        assert!(!v4_only.has_inet6());

        let dual =
            FakeIpPool::from_ranges(DEFAULT_INET4_RANGE, Some(DEFAULT_INET6_RANGE), 16).unwrap();
        assert!(dual.has_inet6());

        let off = FakeIpPool::from_ranges(DEFAULT_INET4_RANGE, Some("off"), 16).unwrap();
        assert!(!off.has_inet6());

        assert!(FakeIpPool::from_ranges("999.1.1.1/24", None, 16).is_err());
    }

    #[test]
    fn invalid_v6_cidr_is_an_error_not_a_silent_disable() {
        let err = FakeIpPool::new(DEFAULT_INET4_RANGE, 8)
            .unwrap()
            .with_inet6("not-a-subnet", 8);
        assert!(err.is_err());
    }

    #[test]
    fn default_dual_stack_pool_uses_the_documented_ranges() {
        let pool = FakeIpPool::default_dual_stack_pool();
        assert_eq!(pool.inet4_network().to_string(), DEFAULT_INET4_RANGE);
        assert_eq!(
            pool.inet6_network().map(|n| n.to_string()),
            Some(DEFAULT_INET6_RANGE.to_string())
        );
    }
}
