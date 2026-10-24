//! DNS inbound with fake-IP allocation.
//!
//! Answers `A` (and, when the pool has a v6 range, `AAAA`) queries from the
//! fake-IP pool so that clients connect to a synthetic address inside the pool
//! range; `FakeIpPool`'s reverse mapping then turns that address back into the
//! domain name in the dispatcher, which is what makes domain-based routing work
//! for applications that resolve names themselves (browsers, TLS stacks,
//! anything that does not use a SOCKS5 domain request).
//!
//! Everything the pool does not synthesise is either reverse-mapped from it
//! (`PTR`) or relayed verbatim to a plain-UDP upstream, so record types the
//! proxy does not model (TXT, MX, HTTPS/SVCB, DNSSEC, ...) are answered for real
//! instead of being dropped. Anything that cannot be answered is answered with
//! NODATA — a prompt, valid answer — never SERVFAIL and never a silent drop.

use async_trait::async_trait;
use flux_dns::fakeip::FakeIpPool;
use flux_dns::resolver::DnsResolver;
use flux_dns::wire::{DnsMessage, Name, QTYPE_A, QTYPE_AAAA, QTYPE_PTR, ptr_name_to_ip};
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Maximum number of queries handled concurrently by one DNS inbound.
const MAX_INFLIGHT_QUERIES: usize = 256;

/// Per-source-IP query rate for the DNS listener.
///
/// A DNS listener is an amplification vector: a 40-byte spoofed query can produce
/// a much larger answer. Without a per-source cap, anyone who can reach the port
/// gets a free reflector, so the rate is bounded even for a loopback bind (where
/// it costs nothing) rather than only for public ones.
const DNS_QUERIES_PER_SEC_PER_IP: u32 = 200;
const DNS_BURST_PER_IP: u32 = 400;

/// /// Answers DNS queries itself or forwards them upstream.
pub struct DnsInbound {
    tag: String,
    listen_addr: SocketAddr,
    resolver: Arc<DnsResolver>,
    /// Fake-IP pool; when absent the inbound behaves as a plain forwarding
    /// resolver (still useful, and what `fakeip.enabled: false` means).
    fake_ip: Option<Arc<FakeIpPool>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
}

impl DnsInbound {
    /// A listener named `tag` on `listen_addr`, answering from `resolver`.
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
            tasks: crate::InboundTasks::new(),
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

/// Answers one DNS query.
///
/// * `A` / `AAAA` with a fake-IP pool: synthetic address (v6 only when the pool
///   was configured with a v6 range, otherwise NODATA so the client falls back).
/// * `PTR` of a fake address: the domain the address was handed out for.
/// * Everything else: relayed to the upstream, or NODATA when there is nothing
///   to relay to.
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
        QTYPE_A => match fake_ip {
            // Allocate (or reuse) a synthetic IPv4 address for this name.
            Some(pool) => {
                DnsMessage::build_response_ip(query, Some(IpAddr::V4(pool.allocate(&qname))))
            }
            None => answer_forwarded(query, resolver, &qname, qtype).await,
        },
        QTYPE_AAAA => match fake_ip {
            Some(pool) => match pool.allocate_v6(&qname) {
                Some(v6) => DnsMessage::build_response_ip(query, Some(IpAddr::V6(v6))),
                // No v6 range configured: NODATA is the correct, honest answer —
                // the client falls back to A immediately instead of waiting, and
                // no real IPv6 address leaks past the fake-IP model.
                None => DnsMessage::build_response(query, None),
            },
            None => answer_forwarded(query, resolver, &qname, qtype).await,
        },
        QTYPE_PTR => {
            // Reverse-map a fake address back to the name it was allocated for.
            let target = fake_ip.and_then(|pool| {
                let ip = ptr_name_to_ip(&Name::from_str(&qname).ok()?)?;
                pool.lookup_domain(&ip)
            });
            match target {
                Some(domain) => match Name::from_str(&domain) {
                    Ok(name) => DnsMessage::build_response_ptr(query, &name),
                    Err(_) => DnsMessage::build_response(query, None),
                },
                // Not one of our addresses: ask the upstream what it knows.
                None => answer_forwarded(query, resolver, &qname, qtype).await,
            }
        }
        // TXT, MX, HTTPS/SVCB, SRV, DNSSEC types, ...: relayed verbatim so the
        // record survives instead of being dropped or re-encoded.
        _ => answer_forwarded(query, resolver, &qname, qtype).await,
    }
}

/// Relays the query to a plain-UDP upstream; falls back to the resolver for
/// address queries so a DoH/DoT/DoQ-only upstream configuration still answers
/// `A`/`AAAA`.
async fn answer_forwarded(
    query: &[u8],
    resolver: &Arc<DnsResolver>,
    qname: &str,
    qtype: u16,
) -> Option<Vec<u8>> {
    match resolver.forward_query(query).await {
        Ok(resp) => return clamp_to_client_udp_size(query, resp),
        Err(e) => {
            debug!("DNS passthrough unavailable for '{}': {}", qname, e);
        }
    }

    if qtype != QTYPE_A && qtype != QTYPE_AAAA {
        return DnsMessage::build_response(query, None);
    }

    // Only an answer of the *requested* family may be returned: putting an A
    // record in an AAAA response (or the reverse) is a protocol error that makes
    // strict clients discard the whole message.
    match resolver.resolve_domain(qname, 443).await {
        Ok(addr) => match (qtype == QTYPE_AAAA, addr.ip()) {
            (false, IpAddr::V4(v4)) => DnsMessage::build_response_ip(query, Some(IpAddr::V4(v4))),
            (true, IpAddr::V6(v6)) => DnsMessage::build_response_ip(query, Some(IpAddr::V6(v6))),
            _ => DnsMessage::build_response(query, None),
        },
        Err(_) => DnsMessage::build_response(query, None),
    }
}

/// Bounds a relayed answer to what the client said it can receive.
///
/// The relay path forwards the upstream's bytes verbatim, and an upstream (or a
/// hostile one) may answer a ~30-byte query with several kilobytes. Sending that
/// back unfiltered is wrong twice over:
///
/// * a client that sent no EDNS0 OPT record expects at most 512 bytes
///   (RFC 1035 §4.2.1) and will drop or truncate anything larger, hiding a
///   perfectly good answer;
/// * with a spoofed source address the listener becomes an amplifier — a
///   ~30-byte datagram in, a multi-kilobyte datagram at the victim out.
///
/// An answer that does not fit is replaced by the protocol-correct stand-in:
/// the question echoed, no records, TC=1, so the client retries over a transport
/// that can carry the full reply (RFC 2181 §9). The answer is relayed verbatim
/// whenever it *does* fit, which is the normal case.
fn clamp_to_client_udp_size(query: &[u8], resp: Vec<u8>) -> Option<Vec<u8>> {
    if resp.len() <= DnsMessage::client_udp_payload_size(query) {
        return Some(resp);
    }
    // Keep the upstream's status so the client sees the same verdict, just
    // without the records it cannot receive.
    let rcode = resp.get(3).map(|b| b & 0x000F).unwrap_or(0);
    DnsMessage::build_truncated_response(query, rcode)
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
            "[{}] DNS inbound listening on {} (fake-IP: {}, inet6: {})",
            self.tag,
            self.listen_addr,
            if self.fake_ip.is_some() {
                "enabled"
            } else {
                "disabled"
            },
            match self.fake_ip.as_ref().and_then(|p| p.inet6_network()) {
                Some(net) => net.to_string(),
                None => "disabled".into(),
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

        if !self.listen_addr.ip().is_loopback() {
            warn!(
                "[{}] DNS inbound is listening on a non-loopback address ({}). Anyone who can \
                 reach it can use it as a resolver; queries are rate-limited per source IP \
                 ({} qps, burst {}) but an ACL is still advisable.",
                self.tag, self.listen_addr, DNS_QUERIES_PER_SEC_PER_IP, DNS_BURST_PER_IP
            );
        }
        let limiter =
            flux_common::RateLimiter::new(DNS_QUERIES_PER_SEC_PER_IP, DNS_BURST_PER_IP, 0);

        self.tasks.spawn(async move {
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
                // Reflective amplification guard: drop queries above the per-IP
                // rate instead of answering them.
                let Some(rate_guard) = limiter.try_acquire(peer.ip()) else {
                    debug!("[{}] dns query from {} rate-limited", tag, peer.ip());
                    continue;
                };
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
                    let _rate_guard = rate_guard;
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
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning here while it is still running leaves
        // the port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_dns::fakeip::DEFAULT_INET4_RANGE;
    use flux_dns::wire::{Message, RData};

    fn pool_v4() -> Arc<FakeIpPool> {
        Arc::new(FakeIpPool::new("198.18.0.0/15", 128).unwrap())
    }

    fn pool_dual() -> Arc<FakeIpPool> {
        Arc::new(
            FakeIpPool::new(DEFAULT_INET4_RANGE, 128)
                .unwrap()
                .with_inet6(flux_dns::fakeip::DEFAULT_INET6_RANGE, 128)
                .unwrap(),
        )
    }

    fn inbound(pool: Option<Arc<FakeIpPool>>) -> DnsInbound {
        DnsInbound::new(
            "dns-in",
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DnsResolver::new(None)),
            pool,
        )
    }

    #[tokio::test]
    async fn answers_a_queries_from_the_fake_ip_pool() {
        let pool = pool_v4();
        let inbound = inbound(Some(pool.clone()));

        let query = DnsMessage::build_query("example.com", QTYPE_A);
        let resp = inbound.answer(&query).await.expect("must answer");
        let ip = DnsMessage::parse_a_record(&resp).unwrap();
        assert!(
            ip.octets()[0] == 198 && ip.octets()[1] == 18,
            "answer {ip} must come from the 198.18.0.0/15 pool"
        );
        assert_eq!(
            pool.lookup_domain(&IpAddr::V4(ip)).as_deref(),
            Some("example.com"),
            "the reverse mapping must resolve back to the name"
        );

        // A repeated query returns the same address (no churn).
        let resp2 = inbound.answer(&query).await.unwrap();
        assert_eq!(DnsMessage::parse_a_record(&resp2).unwrap(), ip);
    }

    #[tokio::test]
    async fn aaaa_queries_get_nodata_with_a_v4_only_pool() {
        let inbound = inbound(Some(pool_v4()));
        let query = DnsMessage::build_query("example.com", QTYPE_AAAA);
        let resp = inbound.answer(&query).await.expect("must answer");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
    }

    #[tokio::test]
    async fn aaaa_queries_get_a_fake_v6_address_when_the_pool_has_one() {
        let pool = pool_dual();
        let inbound = inbound(Some(pool.clone()));

        let query = DnsMessage::build_query("example.com", QTYPE_AAAA);
        let resp = inbound.answer(&query).await.expect("must answer");
        let answer = Message::parse(&resp).unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].rtype, QTYPE_AAAA,
            "the record type must match the question type"
        );
        let RData::Aaaa(v6) = answer.answers[0].rdata else {
            panic!("expected an AAAA record, got {:?}", answer.answers[0]);
        };
        assert!(
            v6.is_unique_local(),
            "fake v6 addresses stay inside fc00::/7"
        );
        assert_eq!(
            pool.lookup_domain(&IpAddr::V6(v6)).as_deref(),
            Some("example.com")
        );

        // Stable across queries, and distinct per name.
        let resp2 = inbound.answer(&query).await.unwrap();
        assert_eq!(DnsMessage::parse_aaaa_record(&resp2).unwrap(), v6);
        let other = inbound
            .answer(&DnsMessage::build_query("other.example", QTYPE_AAAA))
            .await
            .unwrap();
        assert_ne!(DnsMessage::parse_aaaa_record(&other).unwrap(), v6);
    }

    #[tokio::test]
    async fn ptr_queries_reverse_map_fake_addresses() {
        let pool = pool_dual();
        let inbound = inbound(Some(pool.clone()));

        // IPv4
        let v4 = pool.allocate("v4.example");
        let q = DnsMessage::build_query(
            &flux_dns::wire::ip_to_ptr_name(&IpAddr::V4(v4)).to_string(),
            QTYPE_PTR,
        );
        let resp = inbound.answer(&q).await.expect("must answer");
        let msg = Message::parse(&resp).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(
            msg.answers[0].rdata,
            RData::Ptr("v4.example".parse().unwrap())
        );

        // IPv6
        let v6 = pool.allocate_v6("v6.example").unwrap();
        let q6 = DnsMessage::build_query(
            &flux_dns::wire::ip_to_ptr_name(&IpAddr::V6(v6)).to_string(),
            QTYPE_PTR,
        );
        let resp6 = inbound.answer(&q6).await.expect("must answer");
        let msg6 = Message::parse(&resp6).unwrap();
        assert_eq!(
            msg6.answers[0].rdata,
            RData::Ptr("v6.example".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn ptr_for_a_foreign_address_is_nodata_without_an_upstream() {
        let inbound = inbound(Some(pool_v4()));
        let q = DnsMessage::build_query("1.0.0.127.in-addr.arpa", QTYPE_PTR);
        let resp = inbound.answer(&q).await.expect("must answer");
        // No upstream is configured, so there is nothing to relay: NODATA, not a
        // dropped packet and not SERVFAIL.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[tokio::test]
    async fn unmodelled_record_types_get_a_prompt_nodata() {
        let inbound = inbound(Some(pool_v4()));
        for qtype in [15u16, 16, 65, 255] {
            let q = DnsMessage::build_query("example.com", qtype);
            let resp = inbound.answer(&q).await.expect("must answer");
            let msg = Message::parse(&resp).unwrap();
            assert_eq!(msg.rcode(), 0, "NODATA is NOERROR with no answers");
            assert!(msg.answers.is_empty());
        }
    }

    #[tokio::test]
    async fn garbage_packets_get_no_response() {
        let inbound = inbound(None);
        assert!(inbound.answer(b"not dns").await.is_none());
        // A response-shaped packet must not be re-answered.
        let q = DnsMessage::build_query("example.com", QTYPE_A);
        let mut response_shaped = q.clone();
        response_shaped[2] |= 0x80;
        assert!(inbound.answer(&response_shaped).await.is_none());
    }
}
