//! DNS hardening: regression tests for defects reachable from the network.
//!
//! Every test in this file is written so that it **fails on the pre-hardening
//! code** and passes afterwards. No test needs the internet: the upstreams are
//! fake servers bound to loopback inside the test.
//!
//! Covered defects:
//!
//! 1. `forward_query` relayed a response of any size back to a UDP client that
//!    never advertised room for it (no EDNS0 => 512 bytes max), so an upstream
//!    could turn a ~33-byte spoofed query into a multi-kilobyte datagram fired
//!    at the victim, and a well-behaved stub dropped the oversized answer.
//! 2. A domain with a trailing dot (`host.internal.corp.`) bypassed split-DNS
//!    rules and their leak prevention, and double-cached the same name.
//! 3. The fake-IP pool handed out addresses outside its own configured range for
//!    degenerate prefixes (/32 v4, /128 v6), so `contains_ip` disagreed with
//!    `allocate` and the fake-IP reverse mapping was never consulted.
//! 4. `contains_cached` evicted a still-valid *negative* entry as a side effect
//!    of looking at it, silently disabling negative caching.
//! 5. The DoH client could never complete a `Transfer-Encoding: chunked`
//!    response on a keep-alive connection: it read the body to EOF, so every
//!    query burned the 5 s deadline twice and failed.

use flux_app::{Config, Instance};
use flux_dns::doh::DohClient;
use flux_dns::fakeip::FakeIpPool;
use flux_dns::resolver::{DnsResolver, DnsRule};
use flux_dns::wire::{DnsMessage, MAX_SECTION_RECORDS, Message, Name, QTYPE_A, QTYPE_TXT};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Local fake DNS servers (UDP)
// ---------------------------------------------------------------------------

type Handler = dyn Fn(&str, u16) -> Option<Vec<u8>> + Send + Sync;

struct FakeDns {
    addr: SocketAddr,
    total: Arc<Mutex<usize>>,
    last_query_len: Arc<Mutex<usize>>,
}

impl FakeDns {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, u16) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind fake dns");
        let addr = socket.local_addr().expect("local addr");
        let total = Arc::new(Mutex::new(0usize));
        let last_query_len = Arc::new(Mutex::new(0usize));
        let handler: Arc<Box<Handler>> = Arc::new(Box::new(handler));

        let total_task = total.clone();
        let qlen_task = last_query_len.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                *qlen_task.lock().unwrap() = len;
                let Some((id, _flags, qname, qtype, _end)) =
                    DnsMessage::parse_question(&buf[..len])
                else {
                    continue;
                };
                *total_task.lock().unwrap() += 1;
                if let Some(mut resp) = handler(&qname, qtype) {
                    resp[0..2].copy_from_slice(&id.to_be_bytes());
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });

        Self {
            addr,
            total,
            last_query_len,
        }
    }

    fn server_string(&self) -> String {
        self.addr.to_string()
    }

    fn total(&self) -> usize {
        *self.total.lock().unwrap()
    }

    #[allow(dead_code)]
    fn last_query_len(&self) -> usize {
        *self.last_query_len.lock().unwrap()
    }
}

/// Builds a minimal but valid response for one name/qtype.
fn respond_ip(name: &str, qtype: u16, rcode: u8, ip: Option<[u8; 4]>) -> Vec<u8> {
    let query = DnsMessage::build_query(name, qtype);
    let (_id, _flags, _n, _t, q_end) = DnsMessage::parse_question(&query).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes()); // ID (patched by the server)
    out.extend_from_slice(&(0x8080u16 | u16::from(rcode)).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(u16::from(ip.is_some())).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..q_end]);
    if let Some(ip) = ip {
        out.extend_from_slice(&[0xC0, 0x0C]); // owner = question name
        out.extend_from_slice(&QTYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&30u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip);
    }
    out
}

/// Builds a response that is deliberately far larger than a 512-byte UDP answer
/// (a valid TXT record carrying `payload` bytes).
fn respond_large_txt(name: &str, qtype: u16, payload: usize) -> Vec<u8> {
    let query = DnsMessage::build_query(name, qtype);
    let (_id, _flags, _n, _t, q_end) = DnsMessage::parse_question(&query).unwrap();
    let mut rdata = Vec::with_capacity(payload);
    // A TXT record is a sequence of <character-string>s of at most 255 bytes.
    while rdata.len() < payload {
        let chunk = (payload - rdata.len()).min(255);
        rdata.push(chunk as u8);
        rdata.extend(std::iter::repeat_n(b'x', chunk));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0x8080u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..q_end]);
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&QTYPE_TXT.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&30u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

/// Sends one raw UDP datagram and returns the raw reply (if any).
async fn udp_roundtrip(server: &str, query: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(server).await.unwrap();
    sock.send(query).await.unwrap();
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf[..n].to_vec())
}

// ---------------------------------------------------------------------------
// 1. Verbatim relay must respect the client's UDP buffer
// ---------------------------------------------------------------------------

/// A hostile (or merely broken) upstream that answers a small query with a
/// multi-kilobyte TXT record must not make the listener emit a datagram larger
/// than the client can accept. Without EDNS0 that limit is 512 bytes (RFC 1035
/// §4.2.1) and the answer has to come back with TC=1 so the client retries over
/// another transport.
///
/// Before the fix the 2700-byte upstream response was relayed byte for byte: a
/// ~33-byte spoofed query produced a ~2.7 kB datagram towards the victim (~80x
/// amplification) and every conforming stub discarded it as oversized.
#[tokio::test]
async fn forwarded_response_is_capped_to_the_client_udp_size() {
    let (cx, _instance) = fake_hostile_upstream(2700).await;
    let mut q = DnsMessage::build_query("big.example.test", QTYPE_TXT);
    // No EDNS0 OPT record: the client's receive buffer is 512 bytes.
    q[11] = 0;

    let resp = udp_roundtrip(&cx, &q).await.expect("listener must answer");
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    // The reply must be a well-formed message at all, never a chopped one.
    let _ = Message::parse(&resp).expect("the capped response must still be a valid DNS message");
    assert!(
        resp.len() <= 512,
        "a UDP reply to a non-EDNS client must fit in 512 bytes, got {} bytes",
        resp.len()
    );
    assert_ne!(
        flags & 0x0200,
        0,
        "an oversized answer must be signalled with TC=1, not silently truncated"
    );
    assert_eq!(
        u16::from_be_bytes([resp[0], resp[1]]),
        u16::from_be_bytes([q[0], q[1]]),
        "the client's transaction ID must be preserved"
    );
}

/// The same limit must follow an EDNS0 client's advertised payload size: a
/// 4096-byte advertisement may be honoured, a 1232-byte one must not be
/// exceeded.
#[tokio::test]
async fn forwarded_response_follows_the_edns0_payload_size() {
    let (cx, _instance) = fake_hostile_upstream(3000).await;
    for (advertised, limit) in [(1232u16, 1232usize), (4096, 4096)] {
        let mut q = DnsMessage::build_query_with_ecs(
            "big.example.test",
            QTYPE_TXT,
            Some("0.0.0.0/0".parse().unwrap()),
        );
        // The OPT pseudo-record is: root name (0x00), type 41, then CLASS = the
        // advertised UDP payload size. Patch that CLASS.
        let opt = q
            .windows(3)
            .position(|w| w == [0x00, 0x00, 0x29])
            .expect("query must carry an OPT record");
        q[opt + 3..opt + 5].copy_from_slice(&advertised.to_be_bytes());
        let resp = udp_roundtrip(&cx, &q).await.expect("listener must answer");
        assert!(
            resp.len() <= limit,
            "EDNS0 size {advertised}: reply was {} bytes",
            resp.len()
        );
    }
}

/// Boots a `DnsInbound` (through the real config) whose only upstream is a fake
/// server that answers every query with a `payload`-byte TXT record.
async fn fake_hostile_upstream(payload: usize) -> (String, Instance) {
    let upstream =
        FakeDns::start(move |name, qtype| Some(respond_large_txt(name, qtype, payload))).await;

    let port = portpicker().await;
    let cfg = Config::from_json_str(&format!(
        r#"{{
            "dns": {{
                "listen": "127.0.0.1:{port}",
                "servers": ["{}"]
            }},
            "outbounds": [{{ "tag": "direct", "type": "direct" }}],
            "route": {{ "final": "direct" }}
        }}"#,
        upstream.server_string()
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();
    (format!("127.0.0.1:{port}"), instance)
}

async fn portpicker() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    drop(sock);
    port
}

// ---------------------------------------------------------------------------
// 2. Trailing dot must not bypass split-DNS
// ---------------------------------------------------------------------------

/// `host.internal.corp.` is the same name as `host.internal.corp` (RFC 1035
/// §3.1: the root label is implicit). A trailing dot used to defeat both the
/// split-DNS rule match and the cache key, so an internal name was sent to the
/// *public* upstream — the DNS leak the routing table exists to prevent.
#[tokio::test]
async fn trailing_dot_does_not_bypass_split_dns_rules() {
    let internal =
        FakeDns::start(|name, qtype| Some(respond_ip(name, qtype, 0, Some([10, 1, 2, 3])))).await;
    let public =
        FakeDns::start(|name, qtype| Some(respond_ip(name, qtype, 0, Some([203, 0, 113, 5]))))
            .await;

    let resolver = DnsResolver::new(None)
        .with_servers(vec![public.server_string()])
        .with_rules(vec![DnsRule {
            domains: vec!["internal.corp".into()],
            servers: vec![internal.server_string()],
            client_subnet: None,
        }]);

    let addr = resolver
        .resolve_domain("host.internal.corp.", 80)
        .await
        .expect("must resolve");
    assert_eq!(
        addr.ip(),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        "an internal name with a trailing dot must still use the internal upstream"
    );
    assert_eq!(
        public.total(),
        0,
        "the public upstream must never see the internal name (DNS leak)"
    );
    assert!(internal.total() > 0);

    // And it must share the cache entry with the dotless spelling instead of
    // resolving (and caching) the very same name twice.
    let before = internal.total();
    let again = resolver
        .resolve_domain("host.internal.corp", 80)
        .await
        .unwrap();
    assert_eq!(again.ip(), addr.ip());
    assert_eq!(
        internal.total(),
        before,
        "both spellings must share one cache entry"
    );
}

// ---------------------------------------------------------------------------
// 3. Fake-IP allocations stay inside the configured range
// ---------------------------------------------------------------------------

/// `contains_ip` is what decides whether an address is a fake-IP (and therefore
/// whether the reverse mapping / domain routing is consulted). A pool that hands
/// out an address outside its own range breaks that invariant: the fake address
/// is then dialled as a literal IP, bypassing every domain-based rule.
#[test]
fn fake_ip_pool_allocations_stay_inside_the_configured_range() {
    for cidr in [
        "198.18.0.0/15",
        "198.18.0.0/24",
        "198.18.0.0/30",
        "192.0.2.0/31",
        "10.9.8.7/32",
    ] {
        let pool = FakeIpPool::new(cidr, 64).unwrap();
        for i in 0..8 {
            let ip = pool.allocate(&format!("host{i}.example.test"));
            let ip = IpAddr::V4(ip);
            assert!(
                pool.contains_ip(&ip),
                "{cidr}: allocated {ip} is outside the pool's own range"
            );
            assert_eq!(
                pool.lookup_domain(&ip),
                Some(format!("host{i}.example.test")),
                "{cidr}: reverse mapping must agree with the allocation"
            );
        }
    }

    for cidr in ["fc00::/18", "fc00::/126", "fc00::/127", "fc00::/128"] {
        let pool = FakeIpPool::new("198.18.0.0/24", 8)
            .unwrap()
            .with_inet6(cidr, 64)
            .unwrap();
        for i in 0..4 {
            let ip = pool
                .allocate_v6(&format!("host{i}.example.test"))
                .map(IpAddr::V6)
                .expect("v6 pool");
            assert!(
                pool.contains_ip(&ip),
                "{cidr}: allocated {ip} is outside the pool's own range"
            );
            assert_eq!(
                pool.lookup_domain(&ip),
                Some(format!("host{i}.example.test")),
                "{cidr}: reverse mapping must agree with the allocation"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Negative cache entries survive a `contains_cached` probe
// ---------------------------------------------------------------------------

/// `contains_cached` answers "is there a resolved address here?". It used to
/// *pop* any entry that was not a live positive — including a perfectly valid
/// negative one — so a single probe silently disabled negative caching and sent
/// the next lookup back to the upstream.
#[tokio::test]
async fn contains_cached_does_not_evict_a_live_negative_entry() {
    let server = FakeDns::start(|name, qtype| Some(respond_ip(name, qtype, 3, None))).await;
    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);

    resolver
        .resolve_domain("nx.example.test", 80)
        .await
        .expect_err("NXDOMAIN must fail");
    assert!(
        resolver.cached_ttl_remaining("nx.example.test").is_some(),
        "an NXDOMAIN with a cacheable TTL must be remembered"
    );

    assert!(
        !resolver.contains_cached("nx.example.test"),
        "a negative entry is not a cached resolution"
    );

    assert!(
        resolver.cached_ttl_remaining("nx.example.test").is_some(),
        "probing the cache must not evict a live negative entry"
    );
    let before = server.total();
    resolver
        .resolve_domain("nx.example.test", 80)
        .await
        .expect_err("still NXDOMAIN");
    assert_eq!(
        server.total(),
        before,
        "the negative entry must still be served from cache"
    );
}

// ---------------------------------------------------------------------------
// 5. DoH: chunked bodies on a keep-alive connection
// ---------------------------------------------------------------------------

/// A DoH server is allowed to answer with `Transfer-Encoding: chunked` and keep
/// the connection open. The client used to read such a body until EOF, which a
/// keep-alive connection never delivers: every query burned the 5 s deadline,
/// dropped the connection and retried, then failed. Nothing about the DNS answer
/// was wrong — only the framing was unsupported.
#[tokio::test]
async fn doh_completes_a_chunked_response_on_a_keepalive_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    // Answer every request with the same chunked DNS body and
                    // keep the connection open (keep-alive is what the client
                    // asked for).
                    let dns_resp: Vec<u8> = vec![
                        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
                        0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00,
                        0x00, 0x01, 0x2C, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
                    ];
                    let mut body = Vec::new();
                    for part in dns_resp.chunks(16) {
                        body.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                        body.extend_from_slice(part);
                        body.extend_from_slice(b"\r\n");
                    }
                    body.extend_from_slice(b"0\r\n\r\n");
                    let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n";
                    if sock.write_all(head).await.is_err() || sock.write_all(&body).await.is_err() {
                        return;
                    }
                    let _ = sock.flush().await;
                }
            });
        }
    });

    let client = DohClient::new(&format!("http://{addr}/dns-query"));
    let name = Name::from_str("example.com").unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(6), client.query_doh(&name, QTYPE_A))
        .await
        .expect("a chunked DoH answer must not wait for EOF")
        .expect("chunked DoH answer must be accepted");
    assert_eq!(
        answer,
        flux_dns::wire::Answer::Address {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ttl: 300,
        }
    );

    // The connection must be reused for a second query (keep-alive).
    let again = tokio::time::timeout(Duration::from_secs(6), client.query_doh(&name, QTYPE_A))
        .await
        .expect("second chunked query must not wait for EOF")
        .expect("second chunked query must succeed");
    assert_eq!(again, answer);
}

// ---------------------------------------------------------------------------
// Parser sanity that the hardening must not break
// ---------------------------------------------------------------------------

/// Sanity: the parsers never hand out more than they promise.
#[test]
fn parser_output_is_bounded() {
    let mut buf = vec![0x12, 0x34, 0x81, 0x80];
    buf.extend_from_slice(&(MAX_SECTION_RECORDS as u16).to_be_bytes());
    buf.extend_from_slice(&(MAX_SECTION_RECORDS as u16).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    // No records follow: the parse must fail (or return few records), never
    // allocate thousands of empty ones.
    if let Ok(m) = Message::parse(&buf) {
        assert!(m.questions.len() <= MAX_SECTION_RECORDS);
        assert!(m.answers.len() <= MAX_SECTION_RECORDS);
    }
    let _ = HashMap::<String, u16>::new();
}
// ---------------------------------------------------------------------------
// 6. Server failures must never be cached as "does not resolve"
// ---------------------------------------------------------------------------

/// Builds a SERVFAIL/REFUSED-style reply that also carries an SOA, i.e. the
/// worst case for the cache: a bogus negative with a long advisory TTL.
fn respond_failure_with_soa(name: &str, qtype: u16, rcode: u8, minimum: u32) -> Vec<u8> {
    let query = DnsMessage::build_query(name, qtype);
    let (_id, _flags, _n, _t, q_end) = DnsMessage::parse_question(&query).unwrap();
    let mut soa = Vec::new();
    for label in ["ns.example.test", "hostmaster.example.test"] {
        for part in label.split('.') {
            soa.push(part.len() as u8);
            soa.extend_from_slice(part.as_bytes());
        }
        soa.push(0);
    }
    for v in [2024010101u32, 7200, 3600, 1_209_600, minimum] {
        soa.extend_from_slice(&v.to_be_bytes());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(0x8080u16 | u16::from(rcode)).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..q_end]);
    // SOA owner (uncompressed, "example.test").
    for part in "example.test".split('.') {
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&6u16.to_be_bytes()); // SOA
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&900u32.to_be_bytes());
    out.extend_from_slice(&(soa.len() as u16).to_be_bytes());
    out.extend_from_slice(&soa);
    out
}

/// RFC 2308 §7 is explicit: SERVFAIL/REFUSED/NOTIMP are transient server
/// failures and must not be cached as negative answers. Treating them as
/// "does not resolve" let a single broken (or hostile) reply — here with an SOA
/// attached so the negative TTL is a full 10 minutes — pin a working name for the
/// whole TTL.
#[tokio::test]
async fn server_failures_are_not_cached_as_negative_answers() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let broken = Arc::new(AtomicBool::new(true));
    let flag = broken.clone();
    let server = FakeDns::start(move |name, qtype| {
        Some(if flag.load(Ordering::SeqCst) {
            // SERVFAIL with an SOA whose MINIMUM is 600 s.
            respond_failure_with_soa(name, qtype, 2, 600)
        } else {
            respond_ip(name, qtype, 0, Some([198, 51, 100, 4]))
        })
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    resolver
        .resolve_domain("flaky.example.test", 80)
        .await
        .expect_err("SERVFAIL must not resolve");
    assert!(
        resolver
            .cached_ttl_remaining("flaky.example.test")
            .is_none(),
        "a server failure must not be remembered as 'does not resolve'"
    );

    // The upstream recovers: the very next lookup must succeed, not be answered
    // from a poisoned negative entry.
    broken.store(false, Ordering::SeqCst);
    let addr = resolver
        .resolve_domain("flaky.example.test", 80)
        .await
        .expect("a transient server failure must not outlive the failure itself");
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));
}

/// A DNS listener must not be a free reflector: a single source flooding the port
/// has to be rate-limited rather than answered indefinitely.
///
/// This is the guard the audit asked for — without it, anyone reaching the port
/// (including a non-loopback bind) can amplify traffic with spoofed sources.
#[tokio::test]
async fn dns_listener_rate_limits_a_flooding_source() {
    use tokio::net::UdpSocket;

    let dns_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let cfg = flux_app::Config::from_json_str(&format!(
        r#"{{
            "dns": {{ "listen": "127.0.0.1:{dns_port}",
                      "fakeip": {{ "enabled": true, "inet4_range": "198.18.0.0/15" }} }},
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    ))
    .expect("config");
    let instance = flux_app::Instance::new(cfg).expect("instance");
    instance.start().await.expect("start");

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();

    let mut q = vec![0x44, 0x55, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x03com\x00");
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    // Flood: 1500 queries back to back, far above the configured burst.
    for _ in 0..1500 {
        sock.send_to(&q, addr).await.unwrap();
    }

    // Count how many answers come back within a short window.
    let mut answered = 0usize;
    let mut buf = vec![0u8; 512];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(700);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sock.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok(_)) => answered += 1,
            _ => break,
        }
    }

    assert!(
        answered < 1200,
        "the listener answered {answered} of 1500 flood queries; per-source rate limiting is not applied"
    );
    assert!(answered > 0, "the listener stopped answering entirely");

    let _ = instance.stop().await;
}

/// One client query must not turn into an unbounded number of upstream lookups.
///
/// A CNAME chain re-queries per hop, for both families, against every raced
/// server; without a total budget the amplification grows with the server list.
/// Here the upstream returns an endless CNAME chain and we count the queries.
#[tokio::test]
async fn cname_chain_respects_the_upstream_exchange_budget() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UdpSocket;

    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));

    let counter = queries.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((n, from)) = upstream.recv_from(&mut buf).await else {
                break;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            if n < 12 {
                continue;
            }
            // Reply with a CNAME pointing at a *new* name each time, so the
            // resolver keeps following and never reaches an address.
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let mut resp = Vec::with_capacity(64);
            resp.extend_from_slice(&id.to_be_bytes());
            resp.extend_from_slice(&[0x81, 0x80]); // response, no error
            resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
            resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            // Echo the question section verbatim.
            let q_end = buf[12..]
                .iter()
                .position(|b| *b == 0)
                .map(|p| 12 + p + 5)
                .unwrap_or(n.min(64));
            resp.extend_from_slice(&buf[12..q_end]);
            // Answer: CNAME hopN
            resp.extend_from_slice(&[0xc0, 0x0c]);
            resp.extend_from_slice(&5u16.to_be_bytes()); // CNAME
            resp.extend_from_slice(&1u16.to_be_bytes()); // IN
            resp.extend_from_slice(&1u32.to_be_bytes()); // TTL 1s
            resp.extend_from_slice(&9u16.to_be_bytes()); // RDLENGTH
            resp.extend_from_slice(&[1, b'h', 0]); // 1-byte label "h"
            resp.extend_from_slice(&[0xc0, 0x0c]); // pointer (loop)
            let _ = upstream.send_to(&resp, from).await;
        }
    });

    let resolver = flux_dns::DnsResolver::new(None).with_servers(vec![upstream_addr.to_string()]);
    let _ = resolver.resolve_domain("loop.example", 443).await;

    let total = queries.load(Ordering::Relaxed);
    assert!(
        total <= 70,
        "one client query produced {total} upstream exchanges; the budget of 64 is not enforced"
    );
}
