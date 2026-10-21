use crate::doh::DohClient;
use crate::doq::DoqClient;
use crate::dot::DotClient;
use crate::fakeip::FakeIpPool;
use crate::wire::{DnsMessage, QTYPE_A, QTYPE_AAAA};
use flux_types::{FluxError, FluxResult, TargetAddress};
use futures_util::future::{BoxFuture, FutureExt, Shared};
use lru::LruCache;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

use dashmap::DashMap;

const NUM_DNS_CACHE_SHARDS: usize = 16;
const SHARD_DNS_CACHE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(1024) {
    Some(v) => v,
    None => unreachable!(),
};

const DEFAULT_DNS_TTL: Duration = Duration::from_secs(300);
const MIN_DNS_TTL_SECS: u32 = 10;
const MAX_DNS_TTL_SECS: u32 = 86400;
/// How long a failed lookup (NXDOMAIN / no records) is remembered.
const NEGATIVE_DNS_TTL: Duration = Duration::from_secs(10);
const UDP_POOL_SIZE: usize = 16;

// Thread-local scratch buffer for DNS responses (4 KiB is the classic EDNS size).
//
// The buffer is taken for the duration of a query and put back on drop, so a
// cache miss costs no allocation. (Holding a `RefCell` borrow across an `await`
// would make the future non-`Send`, hence the take/return guard.)
thread_local! {
    static DNS_BUF: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

/// Owns the scratch buffer for one query and returns it to the pool on drop.
///
/// The buffer is never absent, so `deref_mut` cannot hand out an empty slice that
/// a caller would then index into.
struct DnsBuf(Vec<u8>);

impl DnsBuf {
    fn take() -> Self {
        let reused = DNS_BUF.with(|b| b.borrow_mut().take());
        let mut buf = reused.unwrap_or_else(|| vec![0u8; 4096]);
        if buf.len() != 4096 {
            buf.resize(4096, 0);
        }
        Self(buf)
    }
}

impl std::ops::Deref for DnsBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for DnsBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for DnsBuf {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.0);
        DNS_BUF.with(|b| *b.borrow_mut() = Some(buf));
    }
}
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Hard ceiling for one full `resolve_domain` call, covering every upstream
/// attempt and retry.
///
/// Individual transports are deadline-bounded, but a single lookup can try
/// several servers (and A+AAAA) in sequence. Connection setup awaits this
/// call, so without an overall ceiling a pathological upstream set can stall
/// `dial_outbound` for a very long time and pile up connection tasks.
const DNS_RESOLVE_DEADLINE: Duration = Duration::from_secs(12);

#[derive(Clone, Debug)]
struct CachedDnsEntry {
    /// `None` = negative entry: the name failed to resolve. Clients retrying a
    /// dead name would otherwise hit the upstream on every attempt.
    ip: Option<IpAddr>,
    expires_at: Instant,
}

/// User-facing split-DNS rule (kept for config compatibility).
#[derive(Clone, Debug, Default)]
pub struct DnsRule {
    pub domains: Vec<String>,
    pub servers: Vec<String>,
    pub client_subnet: Option<ipnet::IpNet>,
}

/// Precompiled split-DNS rule: domains are lowercased and de-dotted exactly once
/// at config load, so per-query matching performs zero allocations.
#[derive(Clone, Debug, Default)]
struct CompiledDnsRule {
    /// Lowercase domain suffixes without leading dot. Each entry matches the
    /// domain itself or any of its subdomains.
    suffixes: Vec<String>,
    servers: Vec<String>,
    client_subnet: Option<ipnet::IpNet>,
}

impl CompiledDnsRule {
    fn from_rule(r: &DnsRule) -> Self {
        let suffixes = r
            .domains
            .iter()
            .map(|d| {
                d.trim()
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            suffixes,
            servers: r.servers.clone(),
            client_subnet: r.client_subnet,
        }
    }

    /// Allocation-free suffix/exact match against an already-lowercased domain.
    fn matches(&self, domain_lower: &str) -> bool {
        self.suffixes.iter().any(|s| {
            if domain_lower.len() == s.len() {
                domain_lower == s
            } else if domain_lower.len() > s.len() {
                domain_lower.ends_with(s.as_str())
                    && domain_lower.as_bytes()[domain_lower.len() - s.len() - 1] == b'.'
            } else {
                false
            }
        })
    }
}

/// Result of an upstream query shared between all concurrent waiters (single-flight).
type SharedQuery = Shared<BoxFuture<'static, Result<(IpAddr, u32), Arc<FluxError>>>>;

#[derive(Clone)]
struct ResolverInner {
    upstream_servers: Vec<String>,
    rules: Vec<CompiledDnsRule>,
    client_subnet: Option<ipnet::IpNet>,
    cache_shards: Arc<[Mutex<LruCache<String, CachedDnsEntry>>]>,
    doh_clients: Arc<DashMap<String, Arc<DohClient>>>,
    dot_clients: Arc<DashMap<String, Arc<DotClient>>>,
    doq_clients: Arc<DashMap<String, Arc<DoqClient>>>,
    udp_socket_pool: Arc<[tokio::sync::Mutex<Option<UdpSocket>>]>,
    socket_counter: Arc<AtomicUsize>,
    inflight: Arc<DashMap<String, SharedQuery>>,
}

#[derive(Clone)]
pub struct DnsResolver {
    fake_ip_pool: Option<Arc<FakeIpPool>>,
    inner: Arc<ResolverInner>,
}

impl DnsResolver {
    pub fn new(fake_ip_pool: Option<Arc<FakeIpPool>>) -> Self {
        let cache_shards: Vec<Mutex<LruCache<String, CachedDnsEntry>>> = (0..NUM_DNS_CACHE_SHARDS)
            .map(|_| Mutex::new(LruCache::new(SHARD_DNS_CACHE_CAPACITY)))
            .collect();

        Self {
            fake_ip_pool,
            inner: Arc::new(ResolverInner {
                upstream_servers: vec![],
                rules: vec![],
                client_subnet: None,
                cache_shards: cache_shards.into(),
                doh_clients: Arc::new(DashMap::new()),
                dot_clients: Arc::new(DashMap::new()),
                doq_clients: Arc::new(DashMap::new()),
                udp_socket_pool: (0..UDP_POOL_SIZE)
                    .map(|_| tokio::sync::Mutex::new(None))
                    .collect::<Vec<_>>()
                    .into(),
                socket_counter: Arc::new(AtomicUsize::new(0)),
                inflight: Arc::new(DashMap::new()),
            }),
        }
    }

    fn cache_shard_index(&self, domain_lower: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        domain_lower.hash(&mut hasher);
        (hasher.finish() as usize) % NUM_DNS_CACHE_SHARDS
    }

    pub fn contains_cached(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        let idx = self.cache_shard_index(&domain_lower);
        let mut cache = self.inner.cache_shards[idx].lock();
        match cache.get(&domain_lower) {
            // A negative entry means "this name does not resolve", which is not a
            // cached resolution.
            Some(entry) if entry.ip.is_some() && Instant::now() < entry.expires_at => true,
            Some(_) => {
                cache.pop(&domain_lower);
                false
            }
            None => false,
        }
    }

    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        Arc::make_mut(&mut self.inner).upstream_servers = servers;
        self
    }

    pub fn with_rules(mut self, rules: Vec<DnsRule>) -> Self {
        Arc::make_mut(&mut self.inner).rules =
            rules.iter().map(CompiledDnsRule::from_rule).collect();
        self
    }

    pub fn with_client_subnet(mut self, ecs: Option<ipnet::IpNet>) -> Self {
        Arc::make_mut(&mut self.inner).client_subnet = ecs;
        self
    }

    pub fn fake_ip(&self) -> Option<&Arc<FakeIpPool>> {
        self.fake_ip_pool.as_ref()
    }

    /// Resolve a TargetAddress into a concrete SocketAddr.
    /// If it is a Fake-IP address, reverse-lookups the domain first.
    pub async fn resolve(&self, target: &TargetAddress) -> FluxResult<SocketAddr> {
        match target {
            TargetAddress::Ip(addr) => {
                if let Some(pool) = &self.fake_ip_pool
                    && pool.contains_ip(&addr.ip())
                {
                    if let Some(domain) = pool.lookup_domain(&addr.ip()) {
                        return self.resolve_domain(&domain, addr.port()).await;
                    }
                    tracing::warn!("Fake-IP mapping not found for {}", addr.ip());
                }
                Ok(*addr)
            }
            TargetAddress::Domain(domain, port) => self.resolve_domain(domain, *port).await,
        }
    }

    pub async fn resolve_domain(&self, domain: &str, port: u16) -> FluxResult<SocketAddr> {
        // Reject invalid names up front: the wire encoder cannot represent them,
        // and silently compiling a *different* name would resolve (and cache) the
        // wrong host.
        if !crate::wire::DnsMessage::is_valid_domain(domain) {
            return Err(FluxError::Dns(format!(
                "invalid DNS name '{}' (empty label, label > 63 bytes, or name > 255 bytes)",
                domain
            )));
        }
        let domain_lower = domain.to_ascii_lowercase();

        // 1. Check sharded LRU DNS cache with TTL expiration
        let shard_idx = self.cache_shard_index(&domain_lower);
        {
            let mut cache = self.inner.cache_shards[shard_idx].lock();
            if let Some(entry) = cache.get(&domain_lower) {
                if Instant::now() < entry.expires_at {
                    return match entry.ip {
                        Some(ip) => Ok(SocketAddr::new(ip, port)),
                        None => Err(FluxError::Dns(format!(
                            "negative DNS cache: '{}' does not resolve (retry after {}s)",
                            domain_lower,
                            entry
                                .expires_at
                                .saturating_duration_since(Instant::now())
                                .as_secs()
                                .max(1)
                        ))),
                    };
                }
                cache.pop(&domain_lower);
            }
        }

        // 2. Single-flight: deduplicate concurrent queries for the same domain.
        let shared: SharedQuery = {
            if let Some(existing) = self.inner.inflight.get(&domain_lower) {
                existing.clone()
            } else {
                let this = self.clone();
                let d = domain_lower.clone();
                let fut: SharedQuery =
                    async move { this.query_uncached(&d).await.map_err(Arc::new) }
                        .boxed()
                        .shared();
                // If another task raced us, prefer the already-stored future.
                match self.inner.inflight.entry(domain_lower.clone()) {
                    dashmap::mapref::entry::Entry::Occupied(e) => {
                        drop(fut);
                        e.get().clone()
                    }
                    dashmap::mapref::entry::Entry::Vacant(v) => {
                        v.insert(fut.clone());
                        fut
                    }
                }
            }
        };

        let result = match tokio::time::timeout(DNS_RESOLVE_DEADLINE, shared).await {
            Ok(r) => r,
            Err(_) => {
                self.inner.inflight.remove(&domain_lower);
                return Err(FluxError::Timeout(format!(
                    "DNS resolution of '{}' exceeded {:?}",
                    domain, DNS_RESOLVE_DEADLINE
                )));
            }
        };
        // Drop the inflight entry so future lookups start a fresh upstream query
        // (the cache below absorbs the thundering herd after success).
        self.inner.inflight.remove(&domain_lower);

        let (ip, ttl) = match result.map_err(|arc_err| match Arc::try_unwrap(arc_err) {
            Ok(e) => e,
            Err(arc) => FluxError::Dns(arc.to_string()),
        }) {
            Ok(v) => v,
            Err(e) => {
                // Cache "this name does not resolve" briefly, but never cache
                // transport failures (timeouts, I/O): those are transient and the
                // next attempt may well succeed.
                if matches!(e, FluxError::Dns(_)) {
                    self.inner.cache_shards[shard_idx].lock().put(
                        domain_lower,
                        CachedDnsEntry {
                            ip: None,
                            expires_at: Instant::now() + NEGATIVE_DNS_TTL,
                        },
                    );
                }
                return Err(e);
            }
        };

        let cache_ttl =
            Duration::from_secs(u64::from(ttl.clamp(MIN_DNS_TTL_SECS, MAX_DNS_TTL_SECS)));
        self.inner.cache_shards[shard_idx].lock().put(
            domain_lower,
            CachedDnsEntry {
                ip: Some(ip),
                expires_at: Instant::now() + cache_ttl,
            },
        );
        Ok(SocketAddr::new(ip, port))
    }

    /// Performs the actual upstream resolution for a cache-missed domain.
    async fn query_uncached(&self, domain_lower: &str) -> FluxResult<(IpAddr, u32)> {
        // 1. Determine target upstream servers via precompiled Split-DNS routing rules.
        let mut target_servers = &self.inner.upstream_servers;
        let mut target_ecs = self.inner.client_subnet;

        for rule in &self.inner.rules {
            if rule.matches(domain_lower) {
                // A matched rule with no servers of its own falls back to the global
                // upstream list — never silently to the system resolver (leak prevention).
                if !rule.servers.is_empty() {
                    target_servers = &rule.servers;
                    if rule.client_subnet.is_some() {
                        target_ecs = rule.client_subnet;
                    }
                }
                break;
            }
        }

        // 2. Race configured upstream servers concurrently (Fastest DNS).
        if !target_servers.is_empty() {
            use futures_util::stream::{FuturesUnordered, StreamExt};
            let mut futures = FuturesUnordered::new();

            for server in target_servers {
                let s = server.clone();
                let d = domain_lower.to_string();
                let ecs = target_ecs;
                let this = self.clone();

                futures.push(async move { this.query_server_dual(&s, &d, ecs).await });
            }

            // Remember a transport-level failure separately: those are transient
            // and must not be cached as "this name does not exist".
            let mut transport_err: Option<FluxError> = None;
            let mut last_err: Option<FluxError> = None;

            while let Some(res) = futures.next().await {
                match res {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        if matches!(
                            e,
                            FluxError::Timeout(_) | FluxError::Io(_) | FluxError::Network(_)
                        ) && transport_err.is_none()
                        {
                            transport_err = Some(match &e {
                                FluxError::Timeout(m) => FluxError::Timeout(m.clone()),
                                FluxError::Io(err) => {
                                    FluxError::Io(std::io::Error::new(err.kind(), err.to_string()))
                                }
                                FluxError::Network(m) => FluxError::Network(m.clone()),
                                other => FluxError::Dns(other.to_string()),
                            });
                        }
                        last_err = Some(e);
                    }
                }
            }

            // Surface the transport failure when there was one: `resolve_domain`
            // only caches `FluxError::Dns` as a negative answer, so collapsing a
            // timeout into `Dns` would pin "does not resolve" for the whole
            // negative TTL against its own contract.
            if let Some(e) = transport_err {
                return Err(e);
            }
            return Err(FluxError::Dns(format!(
                "all configured upstream DNS servers failed to resolve '{}': {} (prevented DNS leak to system resolver)",
                domain_lower,
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no upstream responded".into())
            )));
        }

        // 3. System DNS resolution fallback (only when no custom upstream servers are configured).
        self.query_system(domain_lower).await
    }

    /// Queries one upstream server for both A and AAAA records concurrently.
    /// IPv4 is preferred when available; IPv6 is returned for v6-only domains.
    async fn query_server_dual(
        &self,
        server: &str,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
    ) -> FluxResult<(IpAddr, u32)> {
        let (res_a, res_aaaa) = tokio::join!(
            self.query_server(server, domain, ecs, QTYPE_A),
            self.query_server(server, domain, ecs, QTYPE_AAAA)
        );
        match (res_a, res_aaaa) {
            (Ok(v4), _) => Ok(v4),
            (Err(_), Ok(v6)) => Ok(v6),
            (Err(e), Err(_)) => Err(e),
        }
    }

    async fn query_server(
        &self,
        server: &str,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> FluxResult<(IpAddr, u32)> {
        if server.starts_with("https://") || server.starts_with("http://") {
            let doh = self
                .inner
                .doh_clients
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(DohClient::new(server)))
                .clone();
            doh.query_doh(domain, qtype).await
        } else if server.starts_with("tls://") || server.starts_with("dot://") {
            let dot = self
                .inner
                .dot_clients
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(DotClient::new(server)))
                .clone();
            dot.query_dot(domain, ecs, qtype).await
        } else if server.starts_with("quic://") || server.starts_with("doq://") {
            let doq = self
                .inner
                .doq_clients
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(DoqClient::new(server)))
                .clone();
            doq.query_doq(domain, ecs, qtype).await
        } else {
            let default_dns = SocketAddr::from(([1, 1, 1, 1], 53));
            let parsed: Option<SocketAddr> = if server.contains(':') {
                server.parse().ok()
            } else {
                format!("{}:53", server).parse().ok()
            };
            let srv_addr = match parsed {
                Some(a) => a,
                None => {
                    // Never silently reroute DNS to a hardcoded resolver: misconfiguration
                    // must be visible instead of leaking queries to an unexpected upstream.
                    tracing::error!(
                        "invalid upstream DNS server address '{}'; refusing silent fallback to {}",
                        server,
                        default_dns
                    );
                    return Err(FluxError::Config(format!(
                        "invalid upstream DNS server address: '{}'",
                        server
                    )));
                }
            };
            self.query_upstream_udp(srv_addr, domain, ecs, qtype).await
        }
    }

    async fn query_system(&self, domain_lower: &str) -> FluxResult<(IpAddr, u32)> {
        let addrs = tokio::net::lookup_host((domain_lower, 0))
            .await
            .map_err(|e| FluxError::Dns(format!("failed to resolve {}: {}", domain_lower, e)))?;

        let list: Vec<SocketAddr> = addrs.collect();
        if let Some(&v4) = list.iter().find(|a| a.is_ipv4()) {
            return Ok((v4.ip(), DEFAULT_DNS_TTL.as_secs() as u32));
        }
        if let Some(first) = list.into_iter().next() {
            return Ok((first.ip(), DEFAULT_DNS_TTL.as_secs() as u32));
        }
        Err(FluxError::Dns(format!(
            "no IP addresses found for {}",
            domain_lower
        )))
    }

    async fn query_upstream_udp(
        &self,
        server: SocketAddr,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> FluxResult<(IpAddr, u32)> {
        let idx = self.inner.socket_counter.fetch_add(1, Ordering::Relaxed) % UDP_POOL_SIZE;
        let mut guard = self.inner.udp_socket_pool[idx].lock().await;

        let needs_v6 = server.is_ipv6();
        let socket_valid = guard
            .as_ref()
            .map(|s| {
                s.local_addr()
                    .map(|a| a.is_ipv6() == needs_v6)
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if !socket_valid {
            let bind_addr = if needs_v6 { "[::]:0" } else { "0.0.0.0:0" };
            let socket = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(_) if needs_v6 => UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?,
                Err(e) => return Err(FluxError::Io(e)),
            };
            *guard = Some(socket);
        }
        let socket = match guard.as_ref() {
            Some(s) => s,
            None => {
                return Err(FluxError::Dns(
                    "failed to initialize DNS client UDP socket".into(),
                ));
            }
        };

        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_with_ecs_id(domain, qtype, ecs, tx_id);

        timeout(DNS_QUERY_TIMEOUT, socket.send_to(&query, server))
            .await
            .map_err(|_| FluxError::Timeout(format!("DNS query to {} timed out", server)))?
            .map_err(FluxError::Io)?;

        let deadline = Instant::now() + DNS_QUERY_TIMEOUT;
        // Reused query buffer: this path runs for every cache miss (and twice for
        // a dual-stack lookup), so a fresh 4 KiB allocation per query is pure
        // churn.
        let mut buf = DnsBuf::take();

        loop {
            let time_left = deadline.saturating_duration_since(Instant::now());
            if time_left.is_zero() {
                return Err(FluxError::Timeout(format!(
                    "DNS response from {} timed out",
                    server
                )));
            }

            let (len, from_addr) = timeout(time_left, socket.recv_from(&mut buf))
                .await
                .map_err(|_| FluxError::Timeout(format!("DNS response from {} timed out", server)))?
                .map_err(FluxError::Io)?;

            // 1. Verify remote sender matches the queried upstream server
            if from_addr != server {
                tracing::warn!(
                    "discarding spoofed/unexpected DNS response from {} (expected {})",
                    from_addr,
                    server
                );
                continue;
            }

            // 2. Validate Transaction ID and response flags to prevent DNS poisoning / desync
            if DnsMessage::validate_response(&buf[..len], tx_id).is_err() {
                tracing::debug!("discarding stale or mismatched DNS packet (tx_id mismatch)");
                continue;
            }

            return DnsMessage::parse_specific_record_with_ttl(&buf[..len], qtype);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolver_ip() {
        let resolver = DnsResolver::new(None);
        let target: TargetAddress = "127.0.0.1:8080".parse().unwrap();
        let addr = resolver.resolve(&target).await.unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_resolver_cache() {
        let resolver = DnsResolver::new(None);
        let target: TargetAddress = "localhost:8080".parse().unwrap();
        let addr1 = resolver.resolve(&target).await.unwrap();
        let addr2 = resolver.resolve(&target).await.unwrap();
        assert_eq!(addr1, addr2);
        assert!(resolver.contains_cached("localhost"));
    }

    #[tokio::test]
    async fn test_split_dns_routing_rule() {
        let rule = DnsRule {
            domains: vec!["internal.corp".into(), "company.lan".into()],
            servers: vec!["10.0.0.1:53".into()],
            client_subnet: None,
        };
        let resolver = DnsResolver::new(None)
            .with_servers(vec!["1.1.1.1:53".into()])
            .with_rules(vec![rule]);

        assert_eq!(resolver.inner.rules.len(), 1);
        assert_eq!(resolver.inner.rules[0].suffixes[0], "internal.corp");
        assert!(resolver.inner.rules[0].matches("host.internal.corp"));
        assert!(resolver.inner.rules[0].matches("internal.corp"));
        assert!(!resolver.inner.rules[0].matches("notinternal.corp"));
        assert!(!resolver.inner.rules[0].matches("internal.corp.evil.com"));
    }

    #[tokio::test]
    async fn test_invalid_upstream_server_errors_instead_of_silent_fallback() {
        // A malformed server address must produce an explicit error rather than
        // silently rerouting DNS queries to a hardcoded 1.1.1.1 upstream.
        let resolver = DnsResolver::new(None).with_servers(vec!["not a valid addr".into()]);
        let res = resolver.resolve_domain("example.com", 80).await;
        assert!(res.is_err());
    }

    #[test]
    fn test_compiled_rule_no_trailing_dot_and_case() {
        let rule = CompiledDnsRule::from_rule(&DnsRule {
            domains: vec![" .Example.COM. ".into()],
            servers: vec![],
            client_subnet: None,
        });
        assert!(rule.matches("example.com"));
        assert!(rule.matches("www.example.com"));
    }
}
