use std::net::SocketAddr;
use std::sync::Arc;
use flux_types::{FluxError, FluxResult, TargetAddress};
use crate::fakeip::FakeIpPool;

#[derive(Clone, Debug)]
pub struct DnsResolver {
    fake_ip_pool: Option<Arc<FakeIpPool>>,
}

impl DnsResolver {
    pub fn new(fake_ip_pool: Option<Arc<FakeIpPool>>) -> Self {
        Self { fake_ip_pool }
    }

    pub fn fake_ip(&self) -> Option<&Arc<FakeIpPool>> {
        self.fake_ip_pool.as_ref()
    }

    /// Resolve a TargetAddress into a concrete SocketAddr.
    /// If it is a Fake-IP address, reverse-lookups the domain first.
    pub async fn resolve(&self, target: &TargetAddress) -> FluxResult<SocketAddr> {
        match target {
            TargetAddress::Ip(addr) => {
                if let Some(pool) = &self.fake_ip_pool {
                    if pool.contains_ip(&addr.ip()) {
                        if let Some(domain) = pool.lookup_domain(&addr.ip()) {
                            return self.resolve_domain(&domain, addr.port()).await;
                        }
                    }
                }
                Ok(*addr)
            }
            TargetAddress::Domain(domain, port) => {
                self.resolve_domain(domain, *port).await
            }
        }
    }

    pub async fn resolve_domain(&self, domain: &str, port: u16) -> FluxResult<SocketAddr> {
        let addr_str = format!("{}:{}", domain, port);
        let mut addrs = tokio::net::lookup_host(&addr_str).await.map_err(|e| {
            FluxError::Dns(format!("failed to resolve {}: {}", addr_str, e))
        })?;

        addrs.next().ok_or_else(|| {
            FluxError::Dns(format!("no IP addresses found for {}", addr_str))
        })
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
}
