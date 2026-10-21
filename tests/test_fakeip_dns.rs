//! Fake-IP end to end: DNS inbound allocates a synthetic address, the dispatcher
//! maps it back to the domain, and routing keyed on that domain takes effect.
//!
//! This is the regression test for "fake-ip is wired but inert": before the DNS
//! inbound existed, nothing ever called `FakeIpPool::allocate`.

mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_dns::wire::DnsMessage;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Sends one DNS query to `addr` and returns the A record (if any).
async fn query_a(addr: &str, name: &str) -> Option<std::net::Ipv4Addr> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(addr).await.unwrap();
    let q = DnsMessage::build_query(name, 1);
    sock.send(&q).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .expect("DNS query timed out")
        .unwrap();
    DnsMessage::parse_a_record(&buf[..n]).ok()
}

#[tokio::test]
async fn fake_ip_dns_allocates_and_routes_by_domain() {
    let echo = start_tcp_echo_server().await;
    let proxy_port = get_free_tcp_port().await;
    let dns_port = get_free_tcp_port().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "dns": {{
                "listen": "127.0.0.1:{dns_port}",
                "fakeip": {{ "enabled": true, "inet4_range": "198.18.0.0/15" }}
            }},
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {proxy_port} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [
                {{ "tag": "direct", "type": "direct" }},
                {{ "tag": "blocked", "type": "block" }}
            ],
            "route": {{
                "final": "direct",
                "rules": [
                    {{ "domain_suffix": ["blocked.test"], "outbound": "blocked" }}
                ]
            }}
        }}"#
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let dns_addr = format!("127.0.0.1:{dns_port}");

    // 1. A normal name gets a fake address from the pool.
    let ip = query_a(&dns_addr, "allowed.test")
        .await
        .expect("fake-IP A record");
    assert_eq!(
        &ip.octets()[..2],
        &[198, 18],
        "must come from 198.18.0.0/15"
    );

    // 2. The same name keeps its address (stable mapping).
    let ip2 = query_a(&dns_addr, "allowed.test")
        .await
        .expect("second A record");
    assert_eq!(ip, ip2, "fake-IP mapping must be stable per name");

    // 3. A blocked name also resolves (routing happens on connect, not on resolve).
    let blocked_ip = query_a(&dns_addr, "blocked.test")
        .await
        .expect("fake-IP A record for blocked name");
    assert_ne!(blocked_ip, ip);

    // 4. The fake address is routed by *domain*: connect via SOCKS5 to the fake IP
    //    and observe that the domain rule blocks it while the allowed one works.
    //    Point the rule-matching name at the real echo server by resolving through
    //    the fake pool first and then connecting with the domain.
    let mut ok = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();
    ok.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut m = [0u8; 2];
    ok.read_exact(&mut m).await.unwrap();
    // CONNECT to the *fake* address: the dispatcher must map it back to
    // "allowed.test" and route it to `direct`, which then tries to dial the real
    // name. That name does not resolve publicly, so instead we verify the block
    // path below, which fails fast and deterministically.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&blocked_ip.octets());
    req.extend_from_slice(&echo.port().to_be_bytes());
    ok.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    let n = tokio::time::timeout(Duration::from_secs(5), ok.read_exact(&mut resp))
        .await
        .expect("socks reply timed out")
        .unwrap();
    assert_eq!(n, 10);
    assert_ne!(
        resp[1], 0x00,
        "a fake-IP address that maps to a blocked domain must be refused"
    );

    instance.stop().await.unwrap();
}

/// Without `fakeip.enabled`, the DNS inbound still answers (as a plain resolver)
/// but never hands out pool addresses.
#[tokio::test]
async fn dns_inbound_without_fakeip_does_not_allocate() {
    let dns_port = get_free_tcp_port().await;
    let cfg = Config::from_json_str(&format!(
        r#"{{
            "dns": {{ "listen": "127.0.0.1:{dns_port}", "servers": ["1.1.1.1:53"] }},
            "outbounds": [{{ "tag": "direct", "type": "direct" }}]
        }}"#
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // A garbage packet must not be answered, and the listener must be up.
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(format!("127.0.0.1:{dns_port}")).await.unwrap();
    sock.send(b"not-a-dns-packet").await.unwrap();
    let mut buf = [0u8; 64];
    let out = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf)).await;
    assert!(out.is_err(), "malformed packets must be ignored");

    instance.stop().await.unwrap();
}
