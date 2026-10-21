use crate::doh::DohClient;
use crate::doq::DoqClient;
use crate::dot::DotClient;
use crate::fakeip::FakeIpPool;
use crate::wire::{Answer, DnsMessage, MAX_CNAME_CHAIN, Name, QTYPE_A, QTYPE_AAAA, QueryError};
use flux_types::{FluxError, FluxResult, TargetAddress};
use futures_util::future::{BoxFuture, FutureExt, Shared};
use lru::LruCache;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::str::FromStr;
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
/// Negative-caching TTL used when the upstream sent no SOA record.
const NEGATIVE_DNS_TTL_SECS: u32 = 10;
/// Upper bound for a negative entry taken from SOA MINIMUM (RFC 2308 §5 allows
/// a longer value, but a bogus SOA must not pin "does not resolve" for hours).
const MAX_NEGATIVE_TTL_SECS: u32 = 3600;
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
///
/// The error keeps its [`QueryError`] shape so the cache can tell a clean
/// negative (cacheable, with an SOA-derived TTL) from a transport failure
/// (never cacheable).
type SharedQuery = Shared<BoxFuture<'static, Result<(IpAddr, u32), Arc<QueryError>>>>;

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

    /// Remaining lifetime of the cache entry for `domain`, if any.
    ///
    /// Covers both positive and negative entries. Exposed for tests (the
    /// SOA-derived negative TTL is observable here) and for cache introspection.
    pub fn cached_ttl_remaining(&self, domain: &str) -> Option<Duration> {
        let domain_lower = domain.to_ascii_lowercase();
        let idx = self.cache_shard_index(&domain_lower);
        let mut cache = self.inner.cache_shards[idx].lock();
        let (_, expires_at) = cache
            .get(&domain_lower)
            .map(|e| (e.ip.is_some(), e.expires_at))?;
        let now = Instant::now();
        if now < expires_at {
            Some(expires_at - now)
        } else {
            cache.pop(&domain_lower);
            None
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
            Err(arc) => QueryError::Malformed(arc.to_string()),
        }) {
            Ok(v) => v,
            Err(e) => {
                // Only a *clean* negative answer may be cached ("this name does
                // not resolve"), and only for as long as the upstream's SOA says.
                // Transport failures and malformed responses are transient or
                // suspicious: caching them would pin the failure.
                if let QueryError::Negative { ttl, .. } = &e {
                    let secs = ttl
                        .unwrap_or(NEGATIVE_DNS_TTL_SECS)
                        .clamp(1, MAX_NEGATIVE_TTL_SECS);
                    self.inner.cache_shards[shard_idx].lock().put(
                        domain_lower,
                        CachedDnsEntry {
                            ip: None,
                            expires_at: Instant::now() + Duration::from_secs(u64::from(secs)),
                        },
                    );
                }
                return Err(e.into_flux());
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

    /// Selects the upstream servers (and ECS) for a lowercased domain.
    ///
    /// A rule that matches without its own servers falls back to the global
    /// upstream list — never silently to the system resolver (leak prevention).
    fn route(&self, domain_lower: &str) -> (&[String], Option<ipnet::IpNet>) {
        for rule in &self.inner.rules {
            if rule.matches(domain_lower) {
                // First match wins. A rule with no servers of its own keeps the
                // global list instead of falling through to a later rule.
                let (servers, ecs) = if rule.servers.is_empty() {
                    (
                        self.inner.upstream_servers.as_slice(),
                        self.inner.client_subnet,
                    )
                } else {
                    (
                        rule.servers.as_slice(),
                        rule.client_subnet.or(self.inner.client_subnet),
                    )
                };
                return (servers, ecs);
            }
        }
        (&self.inner.upstream_servers, self.inner.client_subnet)
    }

    /// Performs the actual upstream resolution for a cache-missed domain.
    async fn query_uncached(&self, domain_lower: &str) -> Result<(IpAddr, u32), QueryError> {
        let (target_servers, target_ecs) = self.route(domain_lower);

        // Race configured upstream servers concurrently (Fastest DNS).
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

            // Transport failures and clean negatives are kept apart: the former
            // must never be cached as "this name does not exist", and they win
            // the report because a retry may well succeed.
            let mut transport: Option<FluxError> = None;
            let mut negative: Option<QueryError> = None;
            let mut other: Option<QueryError> = None;

            while let Some(res) = futures.next().await {
                match res {
                    Ok(v) => return Ok(v),
                    Err(QueryError::Transport(e)) => {
                        if transport.is_none() {
                            transport = Some(clone_flux_error(&e));
                        }
                    }
                    Err(e @ QueryError::Negative { .. }) => {
                        if negative.is_none() {
                            negative = Some(e);
                        }
                    }
                    Err(e) => {
                        if other.is_none() {
                            other = Some(e);
                        }
                    }
                }
            }

            if let Some(e) = transport {
                return Err(QueryError::Transport(e));
            }
            if let Some(e) = negative {
                return Err(e);
            }
            return Err(match other {
                Some(QueryError::Malformed(m)) => QueryError::Malformed(format!(
                    "all configured upstream DNS servers failed to resolve '{}': {} (prevented DNS leak to system resolver)",
                    domain_lower, m
                )),
                Some(e) => e,
                None => QueryError::Malformed(format!(
                    "no upstream responded for '{}' (prevented DNS leak to system resolver)",
                    domain_lower
                )),
            });
        }

        // System DNS resolution fallback (only when no custom upstream servers are configured).
        self.query_system(domain_lower).await
    }

    /// Queries one upstream server for both A and AAAA records concurrently.
    /// IPv4 is preferred when available; IPv6 is returned for v6-only domains.
    async fn query_server_dual(
        &self,
        server: &str,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
    ) -> Result<(IpAddr, u32), QueryError> {
        let (res_a, res_aaaa) = tokio::join!(
            self.query_server(server, domain, ecs, QTYPE_A),
            self.query_server(server, domain, ecs, QTYPE_AAAA)
        );
        match (res_a, res_aaaa) {
            (Ok(v4), _) => Ok(v4),
            (_, Ok(v6)) => Ok(v6),
            (Err(a), Err(b)) => Err(match (a, b) {
                // A transport failure must stay a transport failure (uncached).
                (QueryError::Transport(e), _) | (_, QueryError::Transport(e)) => {
                    QueryError::Transport(e)
                }
                // Only a negative both families agree on is safe to remember.
                (QueryError::Negative { ttl, message }, QueryError::Negative { .. }) => {
                    QueryError::Negative { ttl, message }
                }
                (a, _) => a,
            }),
        }
    }

    /// Resolves `name`/`qtype` against one server, following CNAME chains.
    ///
    /// A response that carries a CNAME but no record of the requested type means
    /// the server wants us to ask again for the canonical name; the chain is
    /// followed here, bounded by [`MAX_CNAME_CHAIN`] and loop-checked, and the
    /// cached TTL is the minimum over every link.
    async fn query_server(
        &self,
        server: &str,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<(IpAddr, u32), QueryError> {
        let mut name = Name::from_str(domain)
            .map_err(|e| QueryError::Malformed(format!("invalid DNS name '{domain}': {e}")))?;
        let mut visited = vec![name.clone()];
        let mut chain_ttl: Option<u32> = None;

        loop {
            let answer = self.exchange(server, &name, ecs, qtype).await?;
            match answer {
                Answer::Address { ip, ttl } => {
                    return Ok((ip, chain_ttl.map_or(ttl, |c| c.min(ttl))));
                }
                Answer::Alias { target, ttl } => {
                    chain_ttl = Some(chain_ttl.map_or(ttl, |c| c.min(ttl)));
                    if visited.iter().any(|n| n.eq_ignore_ascii_case(&target)) {
                        return Err(QueryError::Malformed(format!(
                            "CNAME loop while resolving '{domain}' ({} -> {})",
                            name, target
                        )));
                    }
                    if visited.len() > MAX_CNAME_CHAIN {
                        return Err(QueryError::Malformed(format!(
                            "CNAME chain for '{domain}' exceeds {} hops",
                            MAX_CNAME_CHAIN
                        )));
                    }
                    tracing::trace!("following CNAME {} -> {}", name, target);
                    visited.push(target.clone());
                    name = target;
                }
                Answer::Negative { rcode, ttl } => {
                    return Err(QueryError::Negative {
                        ttl,
                        message: format!(
                            "no {} record for '{}' ({}){}{}",
                            qtype_name(qtype),
                            name,
                            server,
                            if rcode == crate::wire::RCODE_NXDOMAIN {
                                ", NXDOMAIN"
                            } else {
                                ""
                            },
                            match ttl {
                                Some(t) => format!(", negative TTL {t}s"),
                                None => String::new(),
                            }
                        ),
                    });
                }
                Answer::CnameLoop { chain } => {
                    return Err(QueryError::Malformed(format!(
                        "CNAME loop in the response for '{}': {}",
                        name,
                        chain
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(" -> ")
                    )));
                }
            }
        }
    }

    /// One round trip against `server` for `name`/`qtype`.
    async fn exchange(
        &self,
        server: &str,
        name: &Name,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<Answer, QueryError> {
        if server.starts_with("https://") || server.starts_with("http://") {
            let doh = self
                .inner
                .doh_clients
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(DohClient::new(server)))
                .clone();
            doh.query_doh(name, qtype).await
        } else if server.starts_with("tls://") || server.starts_with("dot://") {
            let dot = self
                .inner
                .dot_clients
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(DotClient::new(server)))
                .clone();
            dot.query_dot(name, ecs, qtype).await
        } else if server.starts_with("quic://") || server.starts_with("doq://") {
            let doq = self
                .inner
                .doq_clients
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(DoqClient::new(server)))
                .clone();
            doq.query_doq(name, ecs, qtype).await
        } else {
            let srv_addr = self.parse_udp_server(server)?;
            self.query_upstream_udp(srv_addr, name, ecs, qtype).await
        }
    }

    /// Parses `ip[:port]` / `[v6]:port` into a socket address.
    ///
    /// Never silently reroutes DNS to a hardcoded resolver: a misconfiguration
    /// must be visible instead of leaking queries to an unexpected upstream.
    fn parse_udp_server(&self, server: &str) -> Result<SocketAddr, QueryError> {
        let parsed: Option<SocketAddr> = if server.contains(':') {
            server.parse().ok()
        } else {
            format!("{}:53", server).parse().ok()
        };
        parsed.ok_or_else(|| {
            tracing::error!(
                "invalid upstream DNS server address '{}'; refusing silent fallback",
                server
            );
            QueryError::Transport(FluxError::Config(format!(
                "invalid upstream DNS server address: '{}'",
                server
            )))
        })
    }

    async fn query_system(&self, domain_lower: &str) -> Result<(IpAddr, u32), QueryError> {
        let addrs = tokio::net::lookup_host((domain_lower, 0))
            .await
            .map_err(|e| {
                QueryError::Transport(FluxError::Dns(format!(
                    "failed to resolve {}: {}",
                    domain_lower, e
                )))
            })?;

        let list: Vec<SocketAddr> = addrs.collect();
        if let Some(&v4) = list.iter().find(|a| a.is_ipv4()) {
            return Ok((v4.ip(), DEFAULT_DNS_TTL.as_secs() as u32));
        }
        if let Some(first) = list.into_iter().next() {
            return Ok((first.ip(), DEFAULT_DNS_TTL.as_secs() as u32));
        }
        Err(QueryError::Negative {
            ttl: None,
            message: format!("no IP addresses found for {}", domain_lower),
        })
    }

    /// Sends `query` to `server` and returns the validated raw response bytes.
    ///
    /// This is the single UDP exchange used by both the resolving path and the
    /// passthrough path, so socket pooling, spoofing checks and the transaction
    /// ID check cannot drift apart.
    async fn udp_exchange(
        &self,
        server: SocketAddr,
        query: &[u8],
        tx_id: u16,
    ) -> FluxResult<Vec<u8>> {
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

        timeout(DNS_QUERY_TIMEOUT, socket.send_to(query, server))
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

            // 2. Validate Transaction ID and response flags to prevent DNS poisoning / desync.
            //    An error RCODE is accepted here: it is a real answer (NXDOMAIN /
            //    NODATA) that the parser turns into a cacheable negative.
            if DnsMessage::validate_response_header(&buf[..len], tx_id).is_err() {
                tracing::debug!("discarding stale or mismatched DNS packet (tx_id mismatch)");
                continue;
            }

            return Ok(buf[..len].to_vec());
        }
    }

    async fn query_upstream_udp(
        &self,
        server: SocketAddr,
        name: &Name,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<Answer, QueryError> {
        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_for_name(name, qtype, ecs, tx_id);
        let resp = self
            .udp_exchange(server, &query, tx_id)
            .await
            .map_err(QueryError::Transport)?;
        DnsMessage::parse_response(&resp, name, qtype)
    }

    /// Forwards a client's already-encoded query to a plain-UDP upstream and
    /// returns the raw response bytes with the client's transaction ID restored.
    ///
    /// This is what makes the DNS listener a real resolver for the record types
    /// the proxy does not synthesise itself (TXT, MX, HTTPS/SVCB, PTR, DNSSEC
    /// records, ...): the answer is relayed verbatim instead of being re-encoded
    /// or dropped. Only plain-UDP upstreams are used — a DoH/DoT/DoQ-only
    /// configuration has no wire-format passthrough and reports an error, which
    /// the caller turns into a clean NODATA.
    pub async fn forward_query(&self, query: &[u8]) -> FluxResult<Vec<u8>> {
        let (client_id, _flags, qname, _qtype, _end) = DnsMessage::parse_question(query)
            .ok_or_else(|| FluxError::Dns("malformed DNS query".into()))?;
        let domain_lower = qname.to_ascii_lowercase();
        let (servers, _) = self.route(&domain_lower);

        let mut last_err: Option<FluxError> = None;
        for server in servers {
            let Ok(addr) = self.parse_udp_server(server) else {
                continue;
            };
            let tx_id = rand::random::<u16>();
            let mut forwarded = query.to_vec();
            forwarded[0..2].copy_from_slice(&tx_id.to_be_bytes());
            match self.udp_exchange(addr, &forwarded, tx_id).await {
                Ok(mut resp) => {
                    // Restore the client's ID: everything else (question, answer,
                    // rcode, EDNS) is relayed untouched.
                    resp[0..2].copy_from_slice(&client_id.to_be_bytes());
                    return Ok(resp);
                }
                Err(e) => {
                    tracing::debug!("DNS passthrough to {} failed: {}", addr, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            FluxError::Dns(
                "no plain-UDP upstream DNS server configured for query passthrough".into(),
            )
        }))
    }
}

/// Human-readable record type for error messages.
fn qtype_name(qtype: u16) -> String {
    match qtype {
        QTYPE_A => "A".into(),
        QTYPE_AAAA => "AAAA".into(),
        other => format!("type {other}"),
    }
}

/// Recreates a [`FluxError`] (it is not `Clone` because `io::Error` is not).
fn clone_flux_error(e: &FluxError) -> FluxError {
    match e {
        FluxError::Timeout(m) => FluxError::Timeout(m.clone()),
        FluxError::Network(m) => FluxError::Network(m.clone()),
        FluxError::Dns(m) => FluxError::Dns(m.clone()),
        FluxError::Config(m) => FluxError::Config(m.clone()),
        FluxError::Io(err) => FluxError::Io(std::io::Error::new(err.kind(), err.to_string())),
        other => FluxError::Dns(other.to_string()),
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
