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
