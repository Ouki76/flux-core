use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;
use parking_lot::Mutex;
use lru::LruCache;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use flux_types::{FluxError, FluxResult, TargetAddress};
use crate::fakeip::FakeIpPool;
use crate::wire::{DnsMessage, QTYPE_A};

const DNS_CACHE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(4096) {
    Some(v) => v,
    None => unreachable!(),
};

const DEFAULT_DNS_TTL: Duration = Duration::from_secs(300); // 5 minutes cache

#[derive(Clone, Debug)]
struct CachedDnsEntry {
    ip: Ipv4Addr,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct DnsResolver {
    fake_ip_pool: Option<Arc<FakeIpPool>>,
    upstream_servers: Vec<String>,
    cache: Arc<Mutex<LruCache<String, CachedDnsEntry>>>,
}

impl DnsResolver {
    pub fn new(fake_ip_pool: Option<Arc<FakeIpPool>>) -> Self {
        Self {
            fake_ip_pool,
            upstream_servers: vec![],
            cache: Arc::new(Mutex::new(LruCache::new(DNS_CACHE_CAPACITY))),
        }
    }

    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        self.upstream_servers = servers;
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
            TargetAddress::Domain(domain, port) => {
                self.resolve_domain(domain, *port).await
            }
        }
    }

    pub async fn resolve_domain(&self, domain: &str, port: u16) -> FluxResult<SocketAddr> {
        let domain_lower = domain.to_ascii_lowercase();

        // 1. Check LRU DNS cache with TTL expiration
        {
            let mut cache = self.cache.lock();
            if let Some(entry) = cache.get(&domain_lower) {
                if Instant::now() < entry.expires_at {
                    return Ok(SocketAddr::new(IpAddr::V4(entry.ip), port));
                } else {
                    cache.pop(&domain_lower);
                }
            }
        }

        // 2. If upstream DNS servers configured, attempt wireformat query
        for server in &self.upstream_servers {
            let srv_addr: SocketAddr = if server.contains(':') {
                server.parse().unwrap_or_else(|_| "1.1.1.1:53".parse().unwrap())
            } else {
                format!("{}:53", server).parse().unwrap_or_else(|_| "1.1.1.1:53".parse().unwrap())
            };

            if let Ok(ip) = self.query_upstream_udp(srv_addr, &domain_lower).await {
                // Save to cache
                self.cache.lock().put(
                    domain_lower.clone(),
                    CachedDnsEntry {
                        ip,
                        expires_at: Instant::now() + DEFAULT_DNS_TTL,
                    },
                );
                return Ok(SocketAddr::new(IpAddr::V4(ip), port));
            }
        }

        // 3. System DNS resolution with Happy Eyeballs IPv4 preference
        let addr_str = format!("{}:{}", domain_lower, port);
        let addrs = tokio::net::lookup_host(&addr_str).await.map_err(|e| {
            FluxError::Dns(format!("failed to resolve {}: {}", addr_str, e))
        })?;

        let list: Vec<SocketAddr> = addrs.collect();
        if let Some(&v4) = list.iter().find(|a| a.is_ipv4()) {
            if let IpAddr::V4(ipv4) = v4.ip() {
                self.cache.lock().put(
                    domain_lower,
                    CachedDnsEntry {
                        ip: ipv4,
                        expires_at: Instant::now() + DEFAULT_DNS_TTL,
                    },
                );
            }
            return Ok(v4);
        }

        list.into_iter().next().ok_or_else(|| {
            FluxError::Dns(format!("no IP addresses found for {}", addr_str))
        })
    }

    async fn query_upstream_udp(&self, server: SocketAddr, domain: &str) -> FluxResult<Ipv4Addr> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?;
        let query = DnsMessage::build_query(domain, QTYPE_A);

        timeout(Duration::from_secs(2), socket.send_to(&query, server))
            .await
            .map_err(|_| FluxError::Timeout(format!("DNS query to {} timed out", server)))?
            .map_err(FluxError::Io)?;

        let mut buf = vec![0u8; 512];
        let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .map_err(|_| FluxError::Timeout(format!("DNS response from {} timed out", server)))?
            .map_err(FluxError::Io)?;

        DnsMessage::parse_a_record(&buf[..len])
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
        assert!(resolver.cache.lock().contains("localhost"));
    }
}
