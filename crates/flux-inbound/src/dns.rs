//! DNS inbound with fake-IP allocation.
//!
//! Answers `A` queries from the fake-IP pool so that clients connect to a
//! synthetic address inside the pool range; [`crate::dns::FakeIpPool`]'s reverse
//! mapping then turns that address back into the domain name in the dispatcher,
//! which is what makes domain-based routing work for applications that resolve
//! names themselves (browsers, TLS stacks, anything that does not use a SOCKS5
//! domain request).
//!
//! Without this inbound the pool, the reverse mapping and `dns.fakeip.enabled`
//! were inert: nothing ever allocated a fake address.

use async_trait::async_trait;
use flux_dns::fakeip::FakeIpPool;
use flux_dns::resolver::DnsResolver;
use flux_dns::wire::DnsMessage;
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// DNS record type A.
const QTYPE_A: u16 = 1;
/// DNS record type AAAA.
const QTYPE_AAAA: u16 = 28;

/// Maximum number of queries handled concurrently by one DNS inbound.
const MAX_INFLIGHT_QUERIES: usize = 256;

pub struct DnsInbound {
    tag: String,
    listen_addr: SocketAddr,
    resolver: Arc<DnsResolver>,
    /// Fake-IP pool; when absent the inbound behaves as a plain forwarding
    /// resolver (still useful, and what `fakeip.enabled: false` means).
    fake_ip: Option<Arc<FakeIpPool>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl DnsInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        resolver: Arc<DnsResolver>,
        fake_ip: Option<Arc<FakeIpPool>>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            resolver,
            fake_ip,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    /// Produces the response bytes for one query, or `None` when the packet is
    /// not a DNS query we can answer. Thin wrapper over [`answer_query`], used by
    /// the unit tests.
    #[cfg(test)]
    async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        answer_query(query, &self.resolver, self.fake_ip.as_deref()).await
    }
}

/// Answers one DNS query: fake-IP for `A`, NODATA for `AAAA` while fake-IP is on,
/// upstream resolution otherwise.
async fn answer_query(
    query: &[u8],
    resolver: &Arc<DnsResolver>,
    fake_ip: Option<&FakeIpPool>,
) -> Option<Vec<u8>> {
    let (_id, flags, qname, qtype, _end) = DnsMessage::parse_question(query)?;

    // Only answer queries. A response-shaped packet would otherwise be re-answered
    // forever if two nodes were pointed at each other's DNS listener, and an
    // attacker could elicit answers with response flags set.
    const QR_MASK: u16 = 0x8000;
    const OPCODE_MASK: u16 = 0x7800;
    if flags & QR_MASK != 0 || flags & OPCODE_MASK != 0 {
        return None;
    }

    // A root query has nothing to route on.
    if qname.is_empty() {
        return DnsMessage::build_response(query, None);
    }

    match qtype {
        QTYPE_A => {
            if let Some(pool) = fake_ip {
                // Allocate (or reuse) a synthetic address for this name.
                let ip = pool.allocate(&qname);
                return DnsMessage::build_response(query, Some(ip));
            }
            // No pool: answer with the real address when it is IPv4.
            match resolver.resolve_domain(&qname, 443).await {
                Ok(addr) => match addr.ip() {
                    std::net::IpAddr::V4(v4) => DnsMessage::build_response(query, Some(v4)),
                    std::net::IpAddr::V6(_) => DnsMessage::build_response(query, None),
                },
                Err(_) => DnsMessage::build_response(query, None),
            }
        }
        QTYPE_AAAA => {
            // Fake-IP is an IPv4 pool: answer NODATA so the client falls back to A
            // immediately instead of waiting for a timeout.
            if fake_ip.is_some() {
                return DnsMessage::build_response(query, None);
            }
            match resolver.resolve_domain(&qname, 443).await {
                Ok(addr) => match addr.ip() {
                    std::net::IpAddr::V4(v4) => DnsMessage::build_response(query, Some(v4)),
                    std::net::IpAddr::V6(_) => DnsMessage::build_response(query, None),
                },
                Err(_) => DnsMessage::build_response(query, None),
            }
        }
        // A response builder for other types is out of scope: NODATA is a valid,
        // prompt answer and better than SERVFAIL.
        _ => DnsMessage::build_response(query, None),
    }
}

#[async_trait]
impl Inbound for DnsInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "dns"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, _dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        // SO_REUSEADDR/SO_REUSEPORT so a SIGHUP reload can bind the replacement
        // listener before the old instance is stopped (every other inbound does
        // the same). Without them the reload fails with EADDRINUSE and the whole
        // new configuration is rejected.
        let socket = {
            use socket2::{Domain, Protocol, Socket, Type};
            let domain = if self.listen_addr.is_ipv6() {
                Domain::IPV6
            } else {
                Domain::IPV4
            };
            let sock =
                Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(FluxError::Io)?;
            sock.set_nonblocking(true).map_err(FluxError::Io)?;
            sock.set_reuse_address(true).map_err(FluxError::Io)?;
            #[cfg(all(unix, not(target_os = "solaris")))]
            let _ = sock.set_reuse_port(true);
            sock.bind(&self.listen_addr.into()).map_err(|e| {
                FluxError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "dns inbound '{}' failed to bind {}: {}",
                        self.tag, self.listen_addr, e
                    ),
                ))
            })?;
            let std_sock: std::net::UdpSocket = sock.into();
            UdpSocket::from_std(std_sock).map_err(FluxError::Io)?
        };
        let socket = Arc::new(socket);
        self.running.store(true, Ordering::SeqCst);

        info!(
            "[{}] DNS inbound listening on {} (fake-IP: {})",
            self.tag,
            self.listen_addr,
            if self.fake_ip.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        );

        let running = self.running.clone();
        let tag = Arc::<str>::from(self.tag.as_str());
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let resolver = self.resolver.clone();
        let fake_ip = self.fake_ip.clone();

        // Concurrent in-flight queries are capped: fake-IP answers never touch the
        // network, but the NODATA/upstream paths do, and an unbounded task count is
        // a trivial memory/CPU exhaustion vector for a datagram listener.
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_QUERIES));

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (len, peer) = tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    res = socket.recv_from(&mut buf) => match res {
                        Ok(v) => v,
                        Err(e) => {
                            if running.load(Ordering::Relaxed) {
                                warn!("[{}] dns recv error: {}", tag, e);
                            }
                            break;
                        }
                    },
                };
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                // Drop the query when the listener is saturated rather than
                // queueing without bound; the client simply retries.
                let Ok(permit) = inflight.clone().try_acquire_owned() else {
                    debug!("[{}] dns inbound saturated; dropping query", tag);
                    continue;
                };
                let query = buf[..len].to_vec();
                let sock = socket.clone();
                let resolver = resolver.clone();
                let fake_ip = fake_ip.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(resp) = answer_query(&query, &resolver, fake_ip.as_deref()).await {
                        let _ = sock.send_to(&resp, peer).await;
                    }
                });
            }
            debug!("[{}] DNS inbound stopped", tag);
        });

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answers_a_queries_from_the_fake_ip_pool() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15", 128).unwrap());
        let resolver = Arc::new(DnsResolver::new(None));
        let inbound = DnsInbound::new(
            "dns-in",
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            Some(pool.clone()),
        );

        let query = DnsMessage::build_query("example.com", QTYPE_A);
        let resp = inbound.answer(&query).await.expect("must answer");
        let ip = DnsMessage::parse_a_record(&resp).unwrap();
        assert!(
            ip.octets()[0] == 198 && ip.octets()[1] == 18,
            "answer {ip} must come from the 198.18.0.0/15 pool"
        );
        assert_eq!(
            pool.lookup_domain(&std::net::IpAddr::V4(ip)).as_deref(),
            Some("example.com"),
            "the reverse mapping must resolve back to the name"
        );

        // A repeated query returns the same address (no churn).
        let resp2 = inbound.answer(&query).await.unwrap();
        assert_eq!(DnsMessage::parse_a_record(&resp2).unwrap(), ip);
    }

    #[tokio::test]
    async fn aaaa_queries_get_nodata_with_fake_ip() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15", 16).unwrap());
        let resolver = Arc::new(DnsResolver::new(None));
        let inbound = DnsInbound::new(
            "dns-in",
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            Some(pool),
        );
        let query = DnsMessage::build_query("example.com", QTYPE_AAAA);
        let resp = inbound.answer(&query).await.expect("must answer");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
    }

    #[tokio::test]
    async fn garbage_packets_get_no_response() {
        let resolver = Arc::new(DnsResolver::new(None));
        let inbound = DnsInbound::new("dns-in", "127.0.0.1:0".parse().unwrap(), resolver, None);
        assert!(inbound.answer(b"not dns").await.is_none());
    }
}
