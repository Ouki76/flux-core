use crate::doh::DohClient;
use crate::doq::DoqClient;
use crate::dot::DotClient;
use crate::fakeip::FakeIpPool;
use crate::wire::{DnsMessage, QTYPE_A};
use flux_types::{FluxError, FluxResult, TargetAddress};
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
const UDP_POOL_SIZE: usize = 16;

#[derive(Clone, Debug)]
struct CachedDnsEntry {
    ip: IpAddr,
    expires_at: Instant,
}

#[derive(Clone, Debug, Default)]
pub struct DnsRule {
    pub domains: Vec<String>,
    pub servers: Vec<String>,
    pub client_subnet: Option<ipnet::IpNet>,
}

#[derive(Clone)]
pub struct DnsResolver {
    fake_ip_pool: Option<Arc<FakeIpPool>>,
    upstream_servers: Vec<String>,
    rules: Vec<DnsRule>,
    client_subnet: Option<ipnet::IpNet>,
    cache_shards: Arc<[Mutex<LruCache<String, CachedDnsEntry>>]>,
    doh_clients: Arc<DashMap<String, Arc<DohClient>>>,
    dot_clients: Arc<DashMap<String, Arc<DotClient>>>,
    doq_clients: Arc<DashMap<String, Arc<DoqClient>>>,
    udp_socket_pool: Arc<[tokio::sync::Mutex<Option<UdpSocket>>]>,
    socket_counter: Arc<AtomicUsize>,
}

impl DnsResolver {
    pub fn new(fake_ip_pool: Option<Arc<FakeIpPool>>) -> Self {
        let cache_shards: Vec<Mutex<LruCache<String, CachedDnsEntry>>> = (0..NUM_DNS_CACHE_SHARDS)
            .map(|_| Mutex::new(LruCache::new(SHARD_DNS_CACHE_CAPACITY)))
            .collect();

        Self {
            fake_ip_pool,
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
        }
    }

    fn cache_shard_index(&self, domain: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        domain.hash(&mut hasher);
        (hasher.finish() as usize) % NUM_DNS_CACHE_SHARDS
    }

    pub fn contains_cached(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        let idx = self.cache_shard_index(&domain_lower);
        self.cache_shards[idx].lock().contains(&domain_lower)
    }

    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        self.upstream_servers = servers;
        self
    }

    pub fn with_rules(mut self, rules: Vec<DnsRule>) -> Self {
        self.rules = rules;
        self
    }

    pub fn with_client_subnet(mut self, ecs: Option<ipnet::IpNet>) -> Self {
        self.client_subnet = ecs;
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
        let domain_lower = domain.to_ascii_lowercase();

        // 1. Check sharded LRU DNS cache with TTL expiration
        let shard_idx = self.cache_shard_index(&domain_lower);
        {
            let mut cache = self.cache_shards[shard_idx].lock();
            if let Some(entry) = cache.get(&domain_lower) {
                if Instant::now() < entry.expires_at {
                    return Ok(SocketAddr::new(entry.ip, port));
                } else {
                    cache.pop(&domain_lower);
                }
            }
        }

        // 2. Determine target upstream servers via Split-DNS routing rules
        let mut target_servers = &self.upstream_servers;
        let mut target_ecs = self.client_subnet;

        for rule in &self.rules {
            let matched = rule.domains.iter().any(|d| {
                let clean = d.trim_start_matches('.').to_ascii_lowercase();
                domain_lower == clean || domain_lower.ends_with(&format!(".{}", clean))
            });
            if matched {
                target_servers = &rule.servers;
                if rule.client_subnet.is_some() {
                    target_ecs = rule.client_subnet;
                }
                break;
            }
        }

        // 3. Race configured upstream servers concurrently (Fastest DNS)
        if !target_servers.is_empty() {
            use futures_util::stream::{FuturesUnordered, StreamExt};
            let mut futures = FuturesUnordered::new();

            for server in target_servers {
                let s = server.clone();
                let d = domain_lower.clone();
                let ecs = target_ecs;
                let this = self.clone();

                futures.push(async move {
                    if s.starts_with("https://") || s.starts_with("http://") {
                        let doh = this
                            .doh_clients
                            .entry(s.clone())
                            .or_insert_with(|| Arc::new(DohClient::new(&s)))
                            .clone();
                        doh.query_doh(&d).await.map(|ip| (ip, 300))
                    } else if s.starts_with("tls://") || s.starts_with("dot://") {
                        let dot = this
                            .dot_clients
                            .entry(s.clone())
                            .or_insert_with(|| Arc::new(DotClient::new(&s)))
                            .clone();
                        dot.query_dot(&d, ecs).await
                    } else if s.starts_with("quic://") || s.starts_with("doq://") {
                        let doq = this
                            .doq_clients
                            .entry(s.clone())
                            .or_insert_with(|| Arc::new(DoqClient::new(&s)))
                            .clone();
                        doq.query_doq(&d, ecs).await
                    } else {
                        let default_dns = SocketAddr::from(([1, 1, 1, 1], 53));
                        let srv_addr: SocketAddr = if s.contains(':') {
                            s.parse().unwrap_or(default_dns)
                        } else {
                            format!("{}:53", s).parse().unwrap_or(default_dns)
                        };
                        this.query_upstream_udp(srv_addr, &d, ecs).await
                    }
                });
            }

            while let Some(res) = futures.next().await {
                if let Ok((ip, ttl)) = res {
                    let cache_ttl = Duration::from_secs(ttl.clamp(10, 86400) as u64);
                    self.cache_shards[shard_idx].lock().put(
                        domain_lower.clone(),
                        CachedDnsEntry {
                            ip,
                            expires_at: Instant::now() + cache_ttl,
                        },
                    );
                    return Ok(SocketAddr::new(ip, port));
                }
            }

            return Err(FluxError::Dns(format!(
                "all configured upstream DNS servers failed to resolve '{}' (prevented DNS leak to system resolver)",
                domain_lower
            )));
        }

        // 4. System DNS resolution fallback (only when no custom upstream servers are configured)
        let addr_str = format!("{}:{}", domain_lower, port);
        let addrs = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| FluxError::Dns(format!("failed to resolve {}: {}", addr_str, e)))?;

        let list: Vec<SocketAddr> = addrs.collect();
        if let Some(&v4) = list.iter().find(|a| a.is_ipv4()) {
            self.cache_shards[shard_idx].lock().put(
                domain_lower,
                CachedDnsEntry {
                    ip: v4.ip(),
                    expires_at: Instant::now() + DEFAULT_DNS_TTL,
                },
            );
            return Ok(v4);
        }

        if let Some(first) = list.into_iter().next() {
            self.cache_shards[shard_idx].lock().put(
                domain_lower,
                CachedDnsEntry {
                    ip: first.ip(),
                    expires_at: Instant::now() + DEFAULT_DNS_TTL,
                },
            );
            return Ok(first);
        }

        Err(FluxError::Dns(format!(
            "no IP addresses found for {}",
            addr_str
        )))
    }

    async fn query_upstream_udp(
        &self,
        server: SocketAddr,
        domain: &str,
        ecs: Option<ipnet::IpNet>,
    ) -> FluxResult<(IpAddr, u32)> {
        let idx = self.socket_counter.fetch_add(1, Ordering::Relaxed) % UDP_POOL_SIZE;
        let mut guard = self.udp_socket_pool[idx].lock().await;

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
        let socket = guard.as_ref().expect("socket present");

        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_with_ecs_id(domain, QTYPE_A, ecs, tx_id);

        timeout(Duration::from_secs(2), socket.send_to(&query, server))
            .await
            .map_err(|_| FluxError::Timeout(format!("DNS query to {} timed out", server)))?
            .map_err(FluxError::Io)?;

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = vec![0u8; 4096];

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

            return DnsMessage::parse_ip_record_with_ttl(&buf[..len]);
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

        assert_eq!(resolver.rules.len(), 1);
        assert_eq!(resolver.rules[0].domains[0], "internal.corp");
    }
}
