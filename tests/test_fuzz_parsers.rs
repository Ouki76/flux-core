//! Deterministic pseudo-fuzz regression harness: feeds random and mutated
//! garbage into every network-reachable parser and asserts the process never
//! panics (errors are fine — panics are not).
//!
//! Runs in CI without nightly/cargo-fuzz. Complements, not replaces, real
//! libFuzzer runs (see `fuzz/` when available).

use flux_app::uri::parse_proxy_uri;
use flux_protocol::hysteria2::Hysteria2Protocol;
use flux_protocol::trojan::TrojanProtocol;
use flux_protocol::udp::decode_socks5_udp;
use flux_protocol::vless::VlessProtocol;
use flux_protocol::vmess::VmessProtocol;
use flux_protocol::wireguard::{AwgConfig, WireGuardHandshake};
use flux_types::TargetAddress;
use std::io::Cursor;
use uuid::Uuid;
use x25519_dalek::StaticSecret;

/// Deterministic xorshift64* PRNG so failures reproduce exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

/// Builds a corpus: pure random buffers of assorted lengths + bit-flipped
/// mutations of the given seed inputs.
fn corpus(seed_inputs: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let mut out = Vec::new();
    for len in [
        0usize, 1, 2, 4, 8, 16, 17, 32, 56, 58, 64, 128, 148, 256, 512, 2048,
    ] {
        out.push(rng.bytes(len));
    }
    for seed in seed_inputs {
        for _ in 0..24 {
            let mut mutated = seed.to_vec();
            // Flip 1-8 random byte positions.
            let flips = (rng.next() % 8 + 1) as usize;
            for _ in 0..flips {
                if mutated.is_empty() {
                    break;
                }
                let pos = (rng.next() as usize) % mutated.len();
                mutated[pos] = rng.next() as u8;
            }
            out.push(mutated);
            // Truncations exercise EOF paths.
            if !seed.is_empty() {
                let cut = (rng.next() as usize) % seed.len();
                out.push(seed[..cut].to_vec());
            }
        }
    }
    out
}

#[tokio::test]
async fn fuzz_vless_request_header() {
    let uuid = Uuid::new_v4();
    for input in corpus(&[&[0u8; 17], &uuid.as_bytes()[..]]) {
        let mut cursor = Cursor::new(input);
        let _ = VlessProtocol::read_request_header(&mut cursor, &[uuid]).await;
    }
}

#[tokio::test]
async fn fuzz_trojan_request_header() {
    for input in corpus(&[&[b'a'; 58]]) {
        let mut cursor = Cursor::new(input);
        let _ = TrojanProtocol::read_request_header(&mut cursor, &[]).await;
    }
}

#[tokio::test]
async fn fuzz_vmess_request_header() {
    let uuid = Uuid::new_v4();
    for input in corpus(&[&[0u8; 42]]) {
        let mut cursor = Cursor::new(input);
        let _ = VmessProtocol::read_request_header(&mut cursor, &[uuid]).await;
    }
}

#[tokio::test]
async fn fuzz_hysteria2_frames() {
    for input in corpus(&[&[0x44, 0x01, 0x00]]) {
        let mut cursor = Cursor::new(input.clone());
        let _ = Hysteria2Protocol::read_tcp_request(&mut cursor).await;
        let mut cursor = Cursor::new(input);
        let _ = Hysteria2Protocol::read_tcp_response(&mut cursor).await;
    }
}

#[test]
fn fuzz_dns_wire() {
    for input in corpus(&[&[0u8; 12]]) {
        let _ = flux_dns::wire::DnsMessage::validate_response(&input, 0x1234);
        let _ = flux_dns::wire::DnsMessage::parse_a_record(&input);
        let _ = flux_dns::wire::DnsMessage::parse_aaaa_record(&input);
        let _ = flux_dns::wire::DnsMessage::parse_ip_record(&input);
    }
}

#[test]
fn fuzz_socks5_udp_datagram() {
    let src = TargetAddress::Ip("127.0.0.1:1000".parse().unwrap());
    for input in corpus(&[&[0u8; 10]]) {
        let _ = decode_socks5_udp(src.clone(), input.into());
    }
}

#[test]
fn fuzz_wireguard_initiation() {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let awg = AwgConfig::default();
    for input in corpus(&[&[0u8; 148]]) {
        let _ = WireGuardHandshake::respond_to_initiation(&secret, 42, &awg, &input, None);
    }
}

/// The **response** is what a client parses from a server it may not trust, and it is a
/// different state machine from the initiation above: it reads a message type, indices,
/// an ephemeral key, an empty-mac and a mac. Every slice conversion on that path is an
/// `unwrap` over a range, so a missing length check is a panic rather than an error —
/// and a panic in a proxy is a dead connection.
#[test]
fn fuzz_wireguard_response() {
    use flux_protocol::wireguard::WireGuardHandshake;

    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let awg = AwgConfig::default();
    let peer_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let peer_public = x25519_dalek::PublicKey::from(&peer_secret);
    // A real handshake state, so the fuzzer attacks the *response* parser rather than
    // stopping at "this is not a valid initiation".
    let (_, state) = WireGuardHandshake::create_initiation(&secret, &peer_public, 7, &awg, None);
    for input in corpus(&[&[0u8; 92]]) {
        let _ = WireGuardHandshake::consume_response(state.clone(), &input);
    }
}

#[test]
fn fuzz_proxy_uri_parsing() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let schemes = [
        "vless://",
        "trojan://",
        "ss://",
        "socks5://",
        "http://",
        "hy2://",
        "tuic://",
    ];
    for _ in 0..2000 {
        let scheme = schemes[(rng.next() as usize) % schemes.len()];
        let len = (rng.next() % 120) as usize;
        let mut s = String::from(scheme);
        for b in rng.bytes(len) {
            // Keep it mostly-ASCII to reach deeper parser states.
            s.push(char::from(b % 0x7f));
        }
        let _ = parse_proxy_uri(&s);
    }
}

#[test]
fn fuzz_ruleset_line_parsing() {
    let mut rng = Rng(0x0bad_f00d_1357_9bdf);
    let mut rs = flux_router::RuleSet::default();
    for _ in 0..5000 {
        let len = (rng.next() % 80) as usize;
        let line = String::from_utf8_lossy(&rng.bytes(len)).into_owned();
        rs.parse_rule_line(&line);
    }
    rs.compile().unwrap();
}

#[test]
fn fuzz_config_json_parsing() {
    let mut rng = Rng(0xfeed_face_dead_0001);
    let seeds = [
        r#"{"inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}]}"#,
        r#"{"route": {"rules": [{"domain_suffix": [".com"], "outbound": "direct"}]}}"#,
    ];
    for _ in 0..2000 {
        let seed = seeds[(rng.next() as usize) % seeds.len()];
        let mut mutated = seed.to_string();
        let flips = (rng.next() % 6 + 1) as usize;
        for _ in 0..flips {
            if mutated.is_empty() {
                break;
            }
            let pos = (rng.next() as usize) % mutated.len();
            let byte = (rng.next() % 95 + 32) as u8 as char;
            mutated.replace_range(pos..pos + 1, &byte.to_string());
        }
        let _ = flux_app::Config::from_json_str(&mutated);
    }
}

// ---------------------------------------------------------------------------
// Parsers added in 1.1.0 / 1.2.0
// ---------------------------------------------------------------------------

/// The Vision reader must consume arbitrary byte streams without panicking,
/// hanging, or growing memory without bound.
#[tokio::test]
async fn fuzz_vision_stream_reader() {
    use flux_protocol::vision::VisionStream;
    use tokio::io::AsyncReadExt;

    let uuid = [0x11u8; 16];
    let mut rng = Rng(0xfeed_face_dead_0002);

    for _ in 0..300 {
        let len = (rng.next() % 512) as usize;
        let mut data = rng.bytes(len);
        // Half the cases start with the real UUID so the frame parser is reached.
        if rng.next().is_multiple_of(2) {
            let mut with_uuid = uuid.to_vec();
            with_uuid.extend_from_slice(&data);
            data = with_uuid;
        }
        let (mut peer, our_side) = tokio::io::duplex(64 * 1024);
        let mut stream = VisionStream::new(our_side, uuid);
        let payload = data.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = peer.write_all(&payload).await;
            let _ = peer.shutdown().await;
        });

        let mut out = Vec::new();
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut out),
        )
        .await;
        assert!(res.is_ok(), "vision reader hung on input {data:02x?}");
        // Reading either succeeds (pass-through) or errors; it must not panic.
        let _ = res.unwrap();
        assert!(
            out.len() < 1024 * 1024,
            "vision reader produced unbounded output from {} input bytes",
            data.len()
        );
    }
}

/// Salamander deobfuscation must reject nothing it can panic on.
#[test]
fn fuzz_salamander_deobfuscate() {
    use flux_common::Salamander;
    let obfs = Salamander::new("fuzz-password").unwrap();
    let mut rng = Rng(0xfeed_face_dead_0003);
    for _ in 0..5000 {
        let len = (rng.next() % 256) as usize;
        let data = rng.bytes(len);
        if let Some(plain) = obfs.deobfuscate(&data) {
            assert_eq!(
                plain.len(),
                data.len().saturating_sub(flux_common::SALAMANDER_SALT_LEN)
            );
        }
    }
    // Round-trip must be exact for arbitrary payloads.
    for len in [0usize, 1, 7, 8, 15, 16, 63, 1500] {
        let plain = rng.bytes(len);
        let wire = obfs.obfuscate(&plain);
        assert_eq!(obfs.deobfuscate(&wire).unwrap(), plain);
    }
}

/// The DNS question parser is network-reachable and must not panic.
#[test]
fn fuzz_dns_question_parser() {
    use flux_dns::wire::DnsMessage;
    let mut rng = Rng(0xfeed_face_dead_0004);
    for _ in 0..5000 {
        let len = (rng.next() % 600) as usize;
        let data = rng.bytes(len);
        if let Some((_, _, name, _, end)) = DnsMessage::parse_question(&data) {
            assert!(end <= data.len(), "question end past the packet");
            assert!(name.len() <= 255, "name longer than the DNS limit");
        }
        let _ = DnsMessage::build_response(&data, Some(std::net::Ipv4Addr::LOCALHOST));
    }
}

/// HPACK Huffman decoding must not panic on arbitrary input.
#[test]
fn fuzz_huffman_decode() {
    use flux_transport::h3_lite::huffman_decode;
    let mut rng = Rng(0xfeed_face_dead_0005);
    for _ in 0..5000 {
        let len = (rng.next() % 128) as usize;
        let data = rng.bytes(len);
        let _ = huffman_decode(&data);
    }
}

/// SS-2022 UDP decryption must reject garbage without panicking.
#[tokio::test]
async fn fuzz_ss2022_udp_decrypt() {
    use flux_protocol::shadowsocks2022::{Ss2022CipherMethod, Ss2022UdpPacketCipher};
    let cipher = Ss2022UdpPacketCipher::new(Ss2022CipherMethod::Blake3Aes128Gcm, &[3u8; 16]);
    let mut rng = Rng(0xfeed_face_dead_0006);
    for _ in 0..2000 {
        let len = (rng.next() % 200) as usize;
        let data = rng.bytes(len);
        let _ = cipher.decrypt_packet(&data).await;
    }
}

/// The TUIC stream AUTH frame parser must not panic and must reject short frames.
#[test]
fn fuzz_tuic_stream_auth() {
    use flux_protocol::tuic::TuicV5Protocol;
    let mut rng = Rng(0xfeed_face_dead_0007);
    for _ in 0..3000 {
        let len = (rng.next() % 80) as usize;
        let data = rng.bytes(len);
        let _ = TuicV5Protocol::parse_stream_auth_frame(&data);
        let _ = TuicV5Protocol::parse_auth_frame(&data);
    }
}

// ---------------------------------------------------------------------------
// DNS wire parsers (v1.3.0 CNAME/IPv6-fake-IP/record-parser rewrite)
// ---------------------------------------------------------------------------
//
// The DNS subsystem parses two kinds of untrusted input: the query a hostile
// client sends, and the response a hostile upstream returns. Both reach
// `flux_dns::wire`, so every entry point is exercised here with:
//
//   * structurally valid packets (so the deep record parsers are reached),
//   * **every** truncated prefix of those packets (EOF paths),
//   * deterministic single-byte mutations (0x00 / 0xC0 / 0xFF at each offset),
//   * random multi-byte mutations.
//
// The contract asserted here is the one the module documents: no panic, no
// unbounded allocation, and bounded work per input.

/// Seed packets: a query, an A answer, an in-packet CNAME chain, a negative with
/// SOA, one record of each modelled type, and an ECS query.
fn dns_seed_packets() -> Vec<Vec<u8>> {
    use flux_dns::wire::{
        DnsMessage, QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_HTTPS, QTYPE_MX, QTYPE_PTR, QTYPE_SOA,
        QTYPE_TXT,
    };

    fn name(out: &mut Vec<u8>, name: &str) {
        if name.is_empty() || name == "." {
            out.push(0);
            return;
        }
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// One response with `ID, flags`, the question for `qname`, and raw records.
    fn response(qname: &str, qtype: u16, flags: u16, records: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        name(&mut q, qname);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        let q_end = q.len();

        let mut out = Vec::new();
        out.extend_from_slice(&0x1234u16.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&q[12..q_end]);
        for (rtype, ttl, rdata) in records {
            // Owner name compressed to the question (offset 12).
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    let mut seeds = vec![
        DnsMessage::build_query("www.example.com", QTYPE_A),
        DnsMessage::build_query_with_ecs(
            "ecs.example.com",
            QTYPE_A,
            Some("203.0.113.0/24".parse().unwrap()),
        ),
        DnsMessage::build_query_for_name(
            &"name.example.com".parse().unwrap(),
            QTYPE_AAAA,
            None,
            0xBEEF,
        ),
    ];

    // Plain A + AAAA answer.
    let mut aaaa = vec![0u8; 16];
    aaaa[15] = 1;
    seeds.push(response(
        "www.example.com",
        QTYPE_A,
        0x8180,
        &[(QTYPE_A, 300, vec![192, 0, 2, 1]), (QTYPE_AAAA, 60, aaaa)],
    ));

    // In-packet CNAME chain (two hops, then the address).
    let mut c1 = Vec::new();
    name(&mut c1, "edge.example.com");
    let mut c2 = Vec::new();
    name(&mut c2, "origin.example.com");
    seeds.push(response(
        "www.example.com",
        QTYPE_A,
        0x8180,
        &[
            (QTYPE_CNAME, 300, c1),
            (QTYPE_CNAME, 120, c2),
            (QTYPE_A, 60, vec![198, 51, 100, 7]),
        ],
    ));

    // Negative answer: NXDOMAIN + SOA in the authority section.
    let mut soa = Vec::new();
    name(&mut soa, "ns.example.com");
    name(&mut soa, "hostmaster.example.com");
    for v in [2024u32, 7200, 3600, 1_209_600, 45] {
        soa.extend_from_slice(&v.to_be_bytes());
    }
    seeds.push(response(
        "nope.example.com",
        QTYPE_A,
        0x8183,
        &[(QTYPE_SOA, 900, soa)],
    ));

    // TXT / MX / PTR / HTTPS / unknown, i.e. every rdata branch.
    let mut txt = vec![0u8];
    txt.extend_from_slice(b"v=spf1 -all");
    let mut mx = vec![0u8, 10];
    name(&mut mx, "mail.example.com");
    let mut ptr = Vec::new();
    name(&mut ptr, "host.example.com");
    let mut https = vec![0u8, 1, 0];
    https.extend_from_slice(&[0u8, 1, 0, 6, 2, b'h', b'2', 2, b'h', b'3']);
    seeds.push(response(
        "example.com",
        QTYPE_HTTPS,
        0x8180,
        &[
            (QTYPE_TXT, 30, txt),
            (QTYPE_MX, 30, mx),
            (QTYPE_PTR, 30, ptr),
            (QTYPE_HTTPS, 30, https),
            (99, 30, vec![1, 2, 3, 4]),
        ],
    ));

    // Truncated-by-design response (TC set) and a compressed owner that points
    // back into the header.
    seeds.push(response("tc.example.com", QTYPE_A, 0x8380, &[]));
    let mut bad_ptr = response(
        "ptr.example.com",
        QTYPE_A,
        0x8180,
        &[(QTYPE_A, 30, vec![1, 2, 3, 4])],
    );
    let n = bad_ptr.len();
    bad_ptr[n - 12] = 0xC0;
    bad_ptr[n - 11] = 0x02; // pointer to offset 2 (inside the header)
    seeds.push(bad_ptr);

    seeds
}

/// Every parser reachable from the wire, run on one input. Returns the answer
/// classification so the caller can assert the chain stayed bounded.
fn dns_exercise_all_parsers(input: &[u8]) -> Option<flux_dns::wire::Answer> {
    use flux_dns::wire::{DnsMessage, MAX_NAME_LEN, Message, Name, QTYPE_A, QTYPE_AAAA, QTYPE_TXT};

    // Header-only / question paths (these are what the inbound listener hits).
    let _ = DnsMessage::validate_response(input, 0x1234);
    let _ = DnsMessage::validate_response_header(input, 0x1234);
    let _ = DnsMessage::parse_question(input);
    let _ = DnsMessage::parse_question_name(input);
    let _ = DnsMessage::is_valid_domain(&String::from_utf8_lossy(input));

    // Legacy helpers (still used by the fuzz target and the compat API).
    let _ = DnsMessage::parse_a_record(input);
    let _ = DnsMessage::parse_aaaa_record(input);
    let _ = DnsMessage::parse_ip_record(input);
    let _ = DnsMessage::parse_ip_record_with_ttl(input);
    let _ = DnsMessage::parse_specific_record_with_ttl(input, QTYPE_A);
    let _ = DnsMessage::parse_specific_record_with_ttl(input, QTYPE_AAAA);

    // Response builders: they must reject junk instead of indexing into it.
    let _ = DnsMessage::build_response(input, Some(std::net::Ipv4Addr::new(198, 18, 0, 1)));
    let _ = DnsMessage::build_response_ip(input, Some("fc00::1".parse().unwrap()));
    let _ = DnsMessage::build_response_ptr(input, &Name::root());
    let _ = DnsMessage::build_response_records(
        input,
        3,
        &[(flux_dns::wire::RData::Unknown(65280, vec![0; 40]), 60)],
    );

    // Full message walk plus every accessor.
    let Ok(msg) = Message::parse(input) else {
        return None;
    };
    assert!(
        msg.questions.len() <= flux_dns::wire::MAX_SECTION_RECORDS,
        "question section exceeded the documented bound"
    );
    assert!(
        msg.answers.len() <= flux_dns::wire::MAX_SECTION_RECORDS
            && msg.authority.len() <= flux_dns::wire::MAX_SECTION_RECORDS
            && msg.additional.len() <= flux_dns::wire::MAX_SECTION_RECORDS,
        "a record section exceeded the documented bound"
    );
    for rec in msg
        .answers
        .iter()
        .chain(msg.authority.iter())
        .chain(msg.additional.iter())
    {
        assert!(
            rec.name.wire_len() <= MAX_NAME_LEN,
            "record owner name longer than the DNS limit"
        );
    }
    for q in &msg.questions {
        assert!(
            q.name.wire_len() <= MAX_NAME_LEN,
            "question name longer than the DNS limit"
        );
    }
    let _ = msg.first_address();
    let _ = msg.first_address_of(QTYPE_A);
    let _ = msg.negative_ttl();
    let _ = msg.is_truncated();
    let _ = msg.rcode();

    let qname = msg
        .questions
        .first()
        .map(|q| q.name.clone())
        .unwrap_or_else(Name::root);
    let _ = DnsMessage::parse_response(input, &qname, QTYPE_A);
    let _ = DnsMessage::parse_answer(input, &qname, QTYPE_TXT);
    let answer = msg.answer(&qname, QTYPE_A);
    if let flux_dns::wire::Answer::CnameLoop { chain } = &answer {
        assert!(
            chain.len() <= flux_dns::wire::MAX_CNAME_CHAIN + 1,
            "CNAME chain longer than the documented bound"
        );
    }
    Some(answer)
}

/// The DNS response parser: truncation prefixes, byte mutations and random junk
/// must never panic and must stay bounded.
#[test]
fn fuzz_dns_message_parser_is_bounded() {
    use std::time::Instant;

    let started = Instant::now();
    let seeds = dns_seed_packets();

    // 1. Structural seeds, their full set of truncation prefixes, and a
    //    deterministic mutation set.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for seed in &seeds {
        for cut in 0..=seed.len() {
            cases.push(seed[..cut].to_vec());
        }
        for pos in 0..seed.len() {
            for byte in [0x00u8, 0x01, 0x3F, 0x40, 0x7F, 0x80, 0xC0, 0xBF, 0xFE, 0xFF] {
                let mut m = seed.clone();
                m[pos] = byte;
                cases.push(m);
            }
        }
    }

    // 2. Random buffers plus random multi-byte mutations of the seeds.
    let mut rng = Rng(0xfeed_face_dead_0d05);
    for len in [0usize, 1, 2, 11, 12, 13, 32, 64, 128, 300, 512, 1500, 4096] {
        cases.push(rng.bytes(len));
    }
    for _ in 0..2000 {
        let seed = &seeds[(rng.next() as usize) % seeds.len()];
        let mut m = seed.clone();
        if m.is_empty() {
            continue;
        }
        let flips = (rng.next() % 8 + 1) as usize;
        for _ in 0..flips {
            let pos = (rng.next() as usize) % m.len();
            m[pos] = rng.next() as u8;
        }
        cases.push(m);
    }

    let mut parsed = 0usize;
    for case in &cases {
        if dns_exercise_all_parsers(case).is_some() {
            parsed += 1;
        }
    }
    assert!(
        parsed > 100,
        "the corpus must actually reach the message parser, only {parsed} inputs did"
    );
    // Bound on the *work*: a few 100k small packets must stay well inside this.
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "parsing {} inputs took {elapsed:?}: unbounded work",
        cases.len()
    );
}

/// `Name` parsing and the reverse-name helpers are reachable from a hostile
/// question name; they must reject rather than panic, and must never build a
/// name that cannot be encoded.
#[test]
fn fuzz_dns_names_and_ptr_helpers() {
    use flux_dns::wire::{MAX_NAME_LEN, Name, ip_to_ptr_name, ptr_name_to_ip};
    use std::str::FromStr;

    let mut rng = Rng(0xfeed_face_dead_0d06);
    for _ in 0..5000 {
        let len = (rng.next() % 300) as usize;
        let raw = rng.bytes(len);
        let text = String::from_utf8_lossy(&raw).into_owned();
        if let Ok(name) = Name::from_str(&text) {
            assert!(
                name.wire_len() <= MAX_NAME_LEN,
                "FromStr produced a name that cannot be encoded: {text:?}"
            );
            for label in name.labels() {
                assert!(label.len() <= 63, "label longer than 63 bytes");
            }
            // Re-parsing the display form must give the same name (the escaped
            // form is what the DNS inbound uses as a pool key).
            let round = Name::from_str(&name.to_string()).expect("display form must re-parse");
            assert_eq!(round, name, "display/parse round-trip broke: {name}");
        }
        // Hard-coded pathological names.
        let _ = Name::from_str(&"a".repeat(len));
        let _ = Name::from_str(&vec!["a".repeat(63); (len % 6) + 1].join("."));
        let _ = Name::from_str(&format!(
            "{}..{}",
            "b".repeat(len % 40),
            "c".repeat(len % 70)
        ));
    }

    // Every address must survive the PTR round-trip; no address may produce a
    // name that exceeds the wire limit.
    for _ in 0..2000 {
        let v4 = std::net::Ipv4Addr::from(rng.next() as u32);
        let n = ip_to_ptr_name(&std::net::IpAddr::V4(v4));
        assert!(n.wire_len() <= MAX_NAME_LEN);
        assert_eq!(ptr_name_to_ip(&n), Some(std::net::IpAddr::V4(v4)));

        let octets: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let v6 = std::net::Ipv6Addr::from(octets);
        let n6 = ip_to_ptr_name(&std::net::IpAddr::V6(v6));
        assert!(n6.wire_len() <= MAX_NAME_LEN);
        assert_eq!(ptr_name_to_ip(&n6), Some(std::net::IpAddr::V6(v6)));
    }

    // Arbitrary names must not panic the reverse parser.
    for _ in 0..2000 {
        let len = (rng.next() % 40) as usize;
        let mut labels = Vec::new();
        for _ in 0..len {
            let l = (rng.next() % 8) as usize;
            labels.push(String::from_utf8_lossy(&rng.bytes(l)).into_owned());
        }
        let _ = ptr_name_to_ip(&Name::from_str(&labels.join(".")).unwrap_or_default());
    }
}

// ---------------------------------------------------------------------------
// Transport frame parsers: reachable from an unauthenticated peer
// ---------------------------------------------------------------------------

/// A WebSocket peer can send arbitrary bytes before any handshake completes. The frame
/// reader must consume them without panicking, without hanging and without unbounded
/// memory growth.
#[tokio::test]
async fn fuzz_websocket_frame_reader() {
    use flux_transport::websocket::WebSocketStream;
    use tokio::io::AsyncReadExt;

    let mut rng = Rng(0xfeed_face_dead_0004);

    for role_is_client in [true, false] {
        for _ in 0..250 {
            let len = (rng.next() % 512) as usize;
            let data = rng.bytes(len);

            let (mut peer, ours) = tokio::io::duplex(64 * 1024);
            let mut stream = WebSocketStream::new(ours, Vec::new(), role_is_client);
            let payload = data.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = peer.write_all(&payload).await;
                let _ = peer.shutdown().await;
            });

            let mut out = Vec::new();
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read_to_end(&mut out),
            )
            .await;
            assert!(
                res.is_ok(),
                "websocket reader hung on {} bytes: {data:02x?}",
                data.len()
            );
            assert!(
                out.len() < 1024 * 1024,
                "websocket reader produced {} bytes from {} input bytes",
                out.len(),
                data.len()
            );
        }
    }
}

/// mKCP segments arrive as unauthenticated UDP datagrams, in every obfuscation mode.
#[test]
fn fuzz_kcp_segment_parser() {
    use flux_transport::kcp::{KcpObfs, debug_parse};

    let mut rng = Rng(0xfeed_face_dead_0005);
    let modes = [
        KcpObfs::Srtp,
        KcpObfs::Utp,
        KcpObfs::WechatVideo,
        KcpObfs::Dtls,
        KcpObfs::Wireguard,
        KcpObfs::None,
    ];
    for mode in modes {
        for _ in 0..2000 {
            let len = (rng.next() % 96) as usize;
            let data = rng.bytes(len);
            // `debug_parse` returns a description rather than a value, so reaching the
            // end of the call without a panic is the property under test.
            let _ = debug_parse(mode, &data);
        }
    }
}
