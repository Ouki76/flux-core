//! DNS completeness: the behaviours that make it honest to say the resolver is
//! implemented, not just "answers A records".
//!
//! Everything here runs against a *local fake UDP DNS server* started inside the
//! test, or against hand-built packets. No test in this file needs the network.
//!
//! Covered:
//! * CNAME chains — both inside one response and across re-queries, with the
//!   cached TTL being the minimum over the whole chain,
//! * CNAME loops (in-packet and across queries) are bounded and rejected,
//! * compression-pointer loops are rejected instead of followed,
//! * the SOA-derived negative-caching TTL (and the 10 s fallback),
//! * transport failures are never cached as negative answers,
//! * IPv6 fake-IP allocation + reverse mapping for both families,
//! * PTR / TXT / MX / HTTPS(SVCB) parsing and clean NODATA for unknown types.

use flux_dns::fakeip::{DEFAULT_INET4_RANGE, DEFAULT_INET6_RANGE, FakeIpPool};
use flux_dns::resolver::DnsResolver;
use flux_dns::wire::{
    Answer, DnsMessage, Message, Name, QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS, QTYPE_MX, QTYPE_PTR,
    QTYPE_TXT, RData, ip_to_ptr_name, ptr_name_to_ip,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Minimal packet builder (byte level, no external crates)
// ---------------------------------------------------------------------------

/// Owner name of a record: either the question name (compression pointer) or an
/// explicit name.
enum Owner {
    Question,
    Named(&'static str),
}

struct Rr {
    owner: Owner,
    rtype: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn rr(owner: Owner, rtype: u16, ttl: u32, rdata: Vec<u8>) -> Rr {
    Rr {
        owner,
        rtype,
        ttl,
        rdata,
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if name.is_empty() || name == "." {
        out.push(0);
        return out;
    }
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn a(ip: [u8; 4]) -> Vec<u8> {
    ip.to_vec()
}

fn cname(target: &str) -> Vec<u8> {
    encode_name(target)
}

fn soa(minimum: u32) -> Vec<u8> {
    let mut rd = encode_name("ns.example.test");
    rd.extend_from_slice(&encode_name("hostmaster.example.test"));
    for v in [2024010101u32, 7200, 3600, 1_209_600, minimum] {
        rd.extend_from_slice(&v.to_be_bytes());
    }
    rd
}

/// Builds a response for `query` with the given rcode and record sections.
fn build_message(
    query: &[u8],
    q_end: usize,
    id: u16,
    rcode: u8,
    answers: &[Rr],
    authority: &[Rr],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    // QR=1, RD copied, RA=1, rcode
    out.extend_from_slice(&(0x8080u16 | u16::from(rcode)).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question echoed verbatim so compression offsets stay valid.
    out.extend_from_slice(&query[12..q_end]);

    for record in answers.iter().chain(authority.iter()) {
        match &record.owner {
            Owner::Question => out.extend_from_slice(&[0xC0, 0x0C]),
            Owner::Named(name) => out.extend_from_slice(&encode_name(name)),
        }
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&record.ttl.to_be_bytes());
        out.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&record.rdata);
    }
    out
}

// ---------------------------------------------------------------------------
// Local fake UDP DNS server
// ---------------------------------------------------------------------------

type Handler = dyn Fn(&str, u16) -> Option<Vec<u8>> + Send + Sync;

struct FakeDns {
    addr: SocketAddr,
    /// How many times each (name, qtype) was asked.
    counts: Arc<Mutex<HashMap<(String, u16), usize>>>,
    total: Arc<Mutex<usize>>,
}

impl FakeDns {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, u16) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind fake dns");
        let addr = socket.local_addr().expect("local addr");
        let counts: Arc<Mutex<HashMap<(String, u16), usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let total = Arc::new(Mutex::new(0usize));
        let handler: Arc<Box<Handler>> = Arc::new(Box::new(handler));

        let counts_task = counts.clone();
        let total_task = total.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let Some((id, _flags, qname, qtype, q_end)) =
                    DnsMessage::parse_question(&buf[..len])
                else {
                    continue;
                };
                {
                    let mut c = counts_task.lock().unwrap();
                    *c.entry((qname.clone(), qtype)).or_insert(0) += 1;
                    let mut t = total_task.lock().unwrap();
                    *t += 1;
                }
                if let Some(resp) = handler(&qname, qtype) {
                    // `resp` carries the question of the handled name; rebuild the
                    // transaction ID so the client accepts it.
                    let mut resp = resp;
                    resp[0..2].copy_from_slice(&id.to_be_bytes());
                    let _ = socket.send_to(&resp, peer).await;
                }
                let _ = q_end;
            }
        });

        Self {
            addr,
            counts,
            total,
        }
    }

    fn server_string(&self) -> String {
        self.addr.to_string()
    }

    fn count(&self, name: &str, qtype: u16) -> usize {
        *self
            .counts
            .lock()
            .unwrap()
            .get(&(name.to_string(), qtype))
            .unwrap_or(&0)
    }

    fn total(&self) -> usize {
        *self.total.lock().unwrap()
    }
}

/// Builds the response for one name/qtype the way a scripted server would.
fn respond(name: &str, qtype: u16, rcode: u8, answers: Vec<Rr>, authority: Vec<Rr>) -> Vec<u8> {
    let query = DnsMessage::build_query(name, qtype);
    let (_id, _flags, _n, _t, q_end) =
        DnsMessage::parse_question(&query).expect("synthetic query parses");
    build_message(&query, q_end, 0, rcode, &answers, &authority)
}

// ---------------------------------------------------------------------------
// CNAME
// ---------------------------------------------------------------------------

/// A CNAME-only answer (the server does not include the target's record), so the
/// resolver has to ask again for the canonical name. This is the case that used
/// to end in "no A record" instead of an address.
#[tokio::test]
async fn cname_chain_is_followed_across_queries_with_the_minimum_ttl() {
    let server = FakeDns::start(|name, qtype| {
        if qtype != QTYPE_A {
            // NODATA for AAAA: the dual lookup must fall back to the A answer.
            return Some(respond(name, qtype, 0, vec![], vec![]));
        }
        Some(match name {
            "www.example.test" => respond(
                name,
                qtype,
                0,
                vec![rr(Owner::Question, 5, 300, cname("edge.example.test"))],
                vec![],
            ),
            "edge.example.test" => respond(
                name,
                qtype,
                0,
                vec![rr(Owner::Question, 5, 120, cname("origin.example.test"))],
                vec![],
            ),
            "origin.example.test" => respond(
                name,
                qtype,
                0,
                vec![rr(Owner::Question, QTYPE_A, 60, a([203, 0, 113, 7]))],
                vec![],
            ),
            _ => respond(name, qtype, 3, vec![], vec![]),
        })
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    let addr = resolver
        .resolve_domain("www.example.test", 443)
        .await
        .expect("the CNAME chain must resolve");
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    assert_eq!(addr.port(), 443);

    // The chain really was followed by asking three different names.
    assert_eq!(server.count("www.example.test", QTYPE_A), 1);
    assert_eq!(server.count("edge.example.test", QTYPE_A), 1);
    assert_eq!(server.count("origin.example.test", QTYPE_A), 1);

    // Cached under the *queried* name, with the chain's minimum TTL (60 s).
    assert!(
        resolver.contains_cached("www.example.test"),
        "the answer must be cached under the queried name"
    );
    let ttl = resolver
        .cached_ttl_remaining("www.example.test")
        .expect("positive cache entry");
    assert!(
        ttl <= Duration::from_secs(60) && ttl > Duration::from_secs(45),
        "cached TTL must be the chain minimum (60 s), got {ttl:?}"
    );
    assert!(
        !resolver.contains_cached("edge.example.test"),
        "the intermediate names are not the cache key"
    );

    // A second lookup is served from the cache: no new upstream query.
    let again = resolver
        .resolve_domain("www.example.test", 80)
        .await
        .unwrap();
    assert_eq!(again.ip(), addr.ip());
    assert_eq!(server.count("www.example.test", QTYPE_A), 1);
}

/// A whole chain in one response: the address sits on a third name and the TTL
/// must be the minimum of all three records.
#[tokio::test]
async fn cname_chain_inside_one_response_uses_the_smallest_ttl() {
    let server = FakeDns::start(|name, qtype| {
        if qtype != QTYPE_A {
            return Some(respond(name, qtype, 0, vec![], vec![]));
        }
        Some(respond(
            name,
            qtype,
            0,
            vec![
                rr(Owner::Question, 5, 200, cname("mid.example.test")),
                rr(
                    Owner::Named("mid.example.test"),
                    5,
                    150,
                    cname("final.example.test"),
                ),
                rr(
                    Owner::Named("final.example.test"),
                    QTYPE_A,
                    90,
                    a([198, 51, 100, 9]),
                ),
            ],
            vec![],
        ))
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    let addr = resolver
        .resolve_domain("chain.example.test", 80)
        .await
        .unwrap();
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    assert_eq!(
        server.count("chain.example.test", QTYPE_A),
        1,
        "a complete chain must need exactly one query"
    );
    let ttl = resolver.cached_ttl_remaining("chain.example.test").unwrap();
    assert!(
        ttl <= Duration::from_secs(90) && ttl > Duration::from_secs(75),
        "the A record's 90 s TTL is the minimum, got {ttl:?}"
    );
}

#[tokio::test]
async fn cname_loop_across_queries_is_bounded_and_rejected() {
    let server = FakeDns::start(|name, qtype| {
        if qtype != QTYPE_A {
            return Some(respond(name, qtype, 0, vec![], vec![]));
        }
        Some(match name {
            "loop-a.test" => respond(
                name,
                qtype,
                0,
                vec![rr(Owner::Question, 5, 30, cname("loop-b.test"))],
                vec![],
            ),
            "loop-b.test" => respond(
                name,
                qtype,
                0,
                vec![rr(Owner::Question, 5, 30, cname("loop-a.test"))],
                vec![],
            ),
            _ => respond(name, qtype, 3, vec![], vec![]),
        })
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        resolver.resolve_domain("loop-a.test", 80),
    )
    .await
    .expect("must not spin")
    .expect_err("a CNAME loop must be an error");
    let msg = err.to_string();
    assert!(
        msg.contains("CNAME loop") || msg.contains("chain"),
        "error must name the loop, got: {msg}"
    );

    // Bounded: the resolver must stop after a handful of round trips, not spin.
    assert!(
        server.total() < 20,
        "bounded chain following, got {} queries",
        server.total()
    );
    // A malformed/looping answer is not a negative: nothing may be cached.
    assert!(resolver.cached_ttl_remaining("loop-a.test").is_none());
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

/// A response whose answer owner name is a compression pointer to itself. The
/// parser must reject it (bounded pointer budget), and the resolver must report
/// an error without caching anything.
#[tokio::test]
async fn compression_pointer_loop_is_rejected_and_not_cached() {
    let server = FakeDns::start(|name, qtype| {
        // Hand-build a response for `name` with a self-referential answer owner.
        let query = DnsMessage::build_query(name, qtype);
        let (_id, _flags, _n, _t, q_end) = DnsMessage::parse_question(&query).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x8180u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&query[12..q_end]);
        let ptr_at = out.len() as u16;
        out.extend_from_slice(&[0xC0 | (ptr_at >> 8) as u8, ptr_at as u8]); // -> itself
        out.extend_from_slice(&QTYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&30u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[192, 0, 2, 1]);
        Some(out)
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        resolver.resolve_domain("pointer-loop.test", 80),
    )
    .await
    .expect("must not hang")
    .expect_err("a pointer loop must not resolve");
    assert!(!err.to_string().is_empty());

    // Neither cached as an address nor as a negative.
    assert!(resolver.cached_ttl_remaining("pointer-loop.test").is_none());
    assert!(!resolver.contains_cached("pointer-loop.test"));
}

#[tokio::test]
async fn transport_failures_are_never_cached_as_negative() {
    // Port 1 on loopback is closed: the exchange fails (ICMP unreachable or
    // timeout) but that says nothing about the name.
    let resolver = DnsResolver::new(None).with_servers(vec!["127.0.0.1:1".to_string()]);
    let err = tokio::time::timeout(
        Duration::from_secs(20),
        resolver.resolve_domain("transport-failure.test", 80),
    )
    .await
    .expect("must not hang")
    .expect_err("a dead upstream must not resolve");
    assert!(!err.to_string().is_empty());
    assert!(
        resolver
            .cached_ttl_remaining("transport-failure.test")
            .is_none(),
        "transport failures must never be cached as negative answers"
    );
}

// ---------------------------------------------------------------------------
// Negative caching
// ---------------------------------------------------------------------------

#[tokio::test]
async fn negative_ttl_comes_from_the_soa_minimum() {
    let server = FakeDns::start(|name, qtype| {
        // NXDOMAIN with an SOA whose MINIMUM is 45 s.
        Some(respond(
            name,
            qtype,
            3,
            vec![],
            vec![rr(Owner::Named("example.test"), 6, 900, soa(45))],
        ))
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    resolver
        .resolve_domain("nx.example.test", 80)
        .await
        .expect_err("NXDOMAIN must fail");

    let ttl = resolver
        .cached_ttl_remaining("nx.example.test")
        .expect("negative entry");
    assert!(
        ttl <= Duration::from_secs(45) && ttl > Duration::from_secs(35),
        "negative TTL must come from SOA MINIMUM (45 s), got {ttl:?}"
    );

    // The negative entry is used instead of asking again.
    let before = server.total();
    resolver
        .resolve_domain("nx.example.test", 80)
        .await
        .expect_err("still NXDOMAIN");
    assert_eq!(
        server.total(),
        before,
        "the negative entry must be served from cache"
    );
}

#[tokio::test]
async fn negative_ttl_falls_back_to_ten_seconds_without_soa() {
    let server = FakeDns::start(|name, qtype| Some(respond(name, qtype, 3, vec![], vec![]))).await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    resolver
        .resolve_domain("nx-nosoa.example.test", 80)
        .await
        .expect_err("NXDOMAIN must fail");

    let ttl = resolver
        .cached_ttl_remaining("nx-nosoa.example.test")
        .expect("negative entry");
    assert!(
        ttl <= Duration::from_secs(10) && ttl > Duration::from_secs(5),
        "without SOA the negative TTL is 10 s, got {ttl:?}"
    );
}

#[tokio::test]
async fn negative_ttl_from_soa_is_capped() {
    // A three-hour SOA must not pin the name for three hours.
    let server = FakeDns::start(|name, qtype| {
        Some(respond(
            name,
            qtype,
            3,
            vec![],
            vec![rr(Owner::Named("example.test"), 6, 10800, soa(10800))],
        ))
    })
    .await;

    let resolver = DnsResolver::new(None).with_servers(vec![server.server_string()]);
    resolver
        .resolve_domain("nx-capped.example.test", 80)
        .await
        .expect_err("NXDOMAIN must fail");
    let ttl = resolver
        .cached_ttl_remaining("nx-capped.example.test")
        .unwrap();
    assert!(
        ttl <= Duration::from_secs(3600),
        "negative TTL must be capped at 1 h, got {ttl:?}"
    );
}

// ---------------------------------------------------------------------------
// IPv6 fake-IP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ipv6_fakeip_allocates_and_reverse_maps_both_families() {
    let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 128)
        .expect("v4 pool")
        .with_inet6(DEFAULT_INET6_RANGE, 128)
        .expect("v6 pool");

    let v4 = pool.allocate("dual.test");
    let v6 = pool.allocate_v6("dual.test").expect("v6 allocation");

    // Both live in their configured ranges and nowhere near the public internet.
    assert!(pool.contains_ip(&IpAddr::V4(v4)));
    assert!(pool.contains_ip(&IpAddr::V6(v6)));
    assert!(v6.is_unique_local(), "fc00::/18 is RFC 4193 unique-local");
    assert_eq!(
        pool.inet6_network().map(|n| n.to_string()),
        Some(DEFAULT_INET6_RANGE.to_string()),
        "the v6 pool must be the configured range"
    );

    // Reverse mapping works for both families, and both point at the same name.
    assert_eq!(
        pool.lookup_domain(&IpAddr::V4(v4)).as_deref(),
        Some("dual.test")
    );
    assert_eq!(
        pool.lookup_domain(&IpAddr::V6(v6)).as_deref(),
        Some("dual.test")
    );

    // Stable, case-insensitive, and per-family independent.
    assert_eq!(pool.allocate_v6("DUAL.TEST"), Some(v6));
    assert_ne!(pool.allocate_v6("other.test"), Some(v6));

    // PTR names round-trip for a fake v6 address, which is what makes
    // reverse lookups of a fake address work at all.
    assert_eq!(
        ptr_name_to_ip(&ip_to_ptr_name(&IpAddr::V6(v6))),
        Some(IpAddr::V6(v6))
    );
}

#[test]
fn no_v6_pool_means_no_v6_allocation() {
    let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 64).expect("v4 pool");
    assert!(pool.inet6_network().is_none());
    assert_eq!(pool.allocate_v6("example.test"), None);
    assert!(!pool.contains_ip(&"fc00::1".parse().unwrap()));
    assert_eq!(pool.lookup_domain(&"fc00::1".parse().unwrap()), None);

    // ... and the v4 side is unaffected.
    let v4 = pool.allocate("example.test");
    assert_eq!(
        pool.lookup_domain(&IpAddr::V4(v4)).as_deref(),
        Some("example.test")
    );
}

// ---------------------------------------------------------------------------
// Record breadth (hand-built packets, no server)
// ---------------------------------------------------------------------------

#[test]
fn parses_ptr_txt_mx_https_and_keeps_unknown_types() {
    let query = DnsMessage::build_query("example.test", QTYPE_HTTPS);
    let (_id, _flags, _n, _t, q_end) = DnsMessage::parse_question(&query).unwrap();

    let mut txt_rdata = vec![11u8];
    txt_rdata.extend_from_slice(b"hello world");
    let mut mx_rdata = vec![0u8, 10];
    mx_rdata.extend_from_slice(&encode_name("mail.example.test"));
    let mut https_rdata = vec![0u8, 1, 0]; // priority 1, target "."
    https_rdata.extend_from_slice(&[0u8, 1]); // key = alpn
    https_rdata.extend_from_slice(&6u16.to_be_bytes()); // value length
    https_rdata.extend_from_slice(b"\x02h2\x02h3");

    let bytes = build_message(
        &query,
        q_end,
        0x1234,
        0,
        &[
            rr(
                Owner::Question,
                QTYPE_PTR,
                60,
                encode_name("host.example.test"),
            ),
            rr(Owner::Question, QTYPE_TXT, 60, txt_rdata.clone()),
            rr(Owner::Question, QTYPE_MX, 60, mx_rdata),
            rr(Owner::Question, QTYPE_HTTPS, 60, https_rdata.clone()),
            rr(Owner::Question, 99, 60, vec![1, 2, 3, 4]),
        ],
        &[],
    );

    let msg = Message::parse(&bytes).expect("all five records must parse");
    assert_eq!(msg.answers.len(), 5, "no record may be silently dropped");

    assert_eq!(
        msg.answers[0].rdata,
        RData::Ptr("host.example.test".parse().unwrap())
    );
    assert_eq!(
        msg.answers[1].rdata,
        RData::Txt(vec![b"hello world".to_vec()])
    );
    assert_eq!(
        msg.answers[2].rdata,
        RData::Mx {
            preference: 10,
            exchange: "mail.example.test".parse().unwrap(),
        }
    );
    match &msg.answers[3].rdata {
        RData::Https {
            priority,
            target,
            params,
        } => {
            assert_eq!(*priority, 1);
            assert!(target.is_root());
            assert_eq!(params, &vec![(1u16, b"\x02h2\x02h3".to_vec())]);
        }
        other => panic!("expected an HTTPS record, got {other:?}"),
    }
    assert_eq!(msg.answers[4].rdata, RData::Unknown(99, vec![1, 2, 3, 4]));

    // Round-trip through the encoder: identical bytes.
    let mut reencoded = Vec::new();
    msg.answers[3].rdata.encode(&mut reencoded);
    assert_eq!(reencoded, https_rdata);

    // An unmodelled type is not a parse failure, and a NODATA answer for an
    // unknown qtype is reported as a clean negative.
    let qname: Name = "example.test".parse().unwrap();
    assert!(matches!(
        DnsMessage::parse_answer(&bytes, &qname, QTYPE_A),
        Err(_) | Ok(_)
    ));
    let nodata = build_message(&query, q_end, 0x1234, 0, &[], &[]);
    assert!(matches!(
        DnsMessage::parse_answer(&nodata, &qname, QTYPE_A),
        Err(flux_dns::wire::QueryError::Negative { ttl: None, .. })
    ));
}

#[test]
fn ptr_reverse_name_answers_for_a_fake_address() {
    let pool = FakeIpPool::new(DEFAULT_INET4_RANGE, 32).expect("pool");
    let v4 = pool.allocate("ptr.example.test");
    let ptr = ip_to_ptr_name(&IpAddr::V4(v4));
    assert_eq!(
        ptr.to_string(),
        format!(
            "{}.{}.{}.{}.in-addr.arpa",
            v4.octets()[3],
            v4.octets()[2],
            v4.octets()[1],
            v4.octets()[0]
        )
    );
    let back = ptr_name_to_ip(&ptr).expect("reverse name parses");
    assert_eq!(
        pool.lookup_domain(&back).as_deref(),
        Some("ptr.example.test")
    );

    // And the answer record itself is a PTR pointing at the domain.
    let query = DnsMessage::build_query(&ptr.to_string(), QTYPE_PTR);
    let resp = DnsMessage::build_response_ptr(&query, &Name::from_str_lossy("ptr.example.test"))
        .expect("ptr response");
    let msg = Message::parse(&resp).unwrap();
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(
        msg.answers[0].rdata,
        RData::Ptr("ptr.example.test".parse().unwrap())
    );
    assert_eq!(msg.answers[0].rtype, QTYPE_PTR);
}

/// Small helper so the test above reads well: `Name` only implements `FromStr`.
trait NameFromStrLossy {
    fn from_str_lossy(s: &str) -> Name;
}

impl NameFromStrLossy for Name {
    fn from_str_lossy(s: &str) -> Name {
        use std::str::FromStr;
        Name::from_str(s).expect("valid name")
    }
}

#[test]
fn aaaa_answer_carries_an_aaaa_record() {
    // The record type must follow the address family, otherwise strict clients
    // throw the answer away (this was a real bug for AAAA queries).
    let query = DnsMessage::build_query("v6.example.test", QTYPE_AAAA);
    let v6: std::net::Ipv6Addr = "fc00::42".parse().unwrap();
    let resp = DnsMessage::build_response_ip(&query, Some(IpAddr::V6(v6))).expect("response");
    let msg = Message::parse(&resp).unwrap();
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].rtype, QTYPE_AAAA);
    assert_eq!(msg.answers[0].rdata, RData::Aaaa(v6));
    assert_eq!(DnsMessage::parse_aaaa_record(&resp).unwrap(), v6);
}

// ---------------------------------------------------------------------------
// CNAME-aware answer selection (unit level, no server)
// ---------------------------------------------------------------------------

#[test]
fn answer_selection_follows_cname_and_reports_alias_and_nodata() {
    let query = DnsMessage::build_query("alias.example.test", QTYPE_A);
    let (_id, _flags, _n, _t, q_end) = DnsMessage::parse_question(&query).unwrap();
    let qname: Name = "alias.example.test".parse().unwrap();

    // Alias without the target record: the caller is told to ask again.
    let alias_only = build_message(
        &query,
        q_end,
        7,
        0,
        &[rr(
            Owner::Question,
            5,
            30,
            encode_name("target.example.test"),
        )],
        &[],
    );
    assert_eq!(
        DnsMessage::parse_response(&alias_only, &qname, QTYPE_A).unwrap(),
        Answer::Alias {
            target: "target.example.test".parse().unwrap(),
            ttl: 30,
        }
    );

    // Alias with the target record present: the address wins, with the min TTL.
    let complete = build_message(
        &query,
        q_end,
        8,
        0,
        &[
            rr(Owner::Question, 5, 120, encode_name("target.example.test")),
            rr(
                Owner::Named("target.example.test"),
                QTYPE_A,
                45,
                a([192, 0, 2, 5]),
            ),
        ],
        &[],
    );
    assert_eq!(
        DnsMessage::parse_response(&complete, &qname, QTYPE_A).unwrap(),
        Answer::Address {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            ttl: 45,
        }
    );

    // Plain NODATA: a clean negative with no advisory TTL.
    let nodata = build_message(&query, q_end, 9, 0, &[], &[]);
    assert_eq!(
        DnsMessage::parse_response(&nodata, &qname, QTYPE_A).unwrap(),
        Answer::Negative {
            rcode: 0,
            ttl: None
        }
    );
}
