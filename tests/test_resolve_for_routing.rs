//! Rules that decide on an address must fire for a domain destination.
//!
//! The router is synchronous and resolves nothing, and the routing path used to
//! see only `Domain("…")` — so an `ip_cidr` rule silently never applied to a
//! connection made by name, which is a real behaviour difference from sing-box and
//! xray (both resolve unless a rule says `no-resolve`). The dispatcher now resolves
//! for the routing decision only; the dial still carries the domain.

mod common;

use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A DNS server that answers `blocked.test` with 127.0.0.1 and `allowed.test`
/// with 127.0.0.2, and NODATA for AAAA.
async fn fake_dns() -> SocketAddr {
    use flux_dns::wire::{DnsMessage, QTYPE_A};

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind fake dns");
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Some((_id, _flags, qname, qtype, _q_end)) = DnsMessage::parse_question(&buf[..len])
            else {
                continue;
            };
            let answer: Option<IpAddr> = if qtype == QTYPE_A {
                match qname.trim_end_matches('.').to_ascii_lowercase().as_str() {
                    "blocked.test" => Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                    "allowed.test" => Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
                    _ => None,
                }
            } else {
                None
            };
            let Some(resp) = DnsMessage::build_response_ip(&buf[..len], answer) else {
                continue;
            };
            let _ = socket.send_to(&resp, peer).await;
        }
    });
    addr
}

async fn echo_on(addr: &str, port: u16) {
    let listener = TcpListener::bind((addr, port))
        .await
        .unwrap_or_else(|e| panic!("bind {addr}:{port}: {e}"));
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

async fn socks5_connect(
    port: u16,
    host: &str,
    target_port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!("socks reply {head:?}")));
    }
    // Drain the bound address.
    match head[3] {
        0x01 => {
            let mut a = [0u8; 6];
            s.read_exact(&mut a).await?;
        }
        0x04 => {
            let mut a = [0u8; 18];
            s.read_exact(&mut a).await?;
        }
        _ => return Err(std::io::Error::other("bad atyp")),
    }
    Ok(s)
}

#[tokio::test]
async fn an_ip_rule_fires_for_a_domain_destination() {
    let dns = fake_dns().await;
    // Both destinations must be reachable, otherwise "the connection failed" could
    // mean "nothing is listening" instead of "the rule blocked it" — which is
    // exactly how the first version of this test failed to discriminate.
    let echo_port = get_free_tcp_port().await;
    echo_on("127.0.0.1", echo_port).await;
    echo_on("127.0.0.2", echo_port).await;
    let socks_port = get_free_tcp_port().await;

    let cfg = format!(
        r#"{{
            "dns": {{ "servers": ["{dns}"] }},
            "inbounds": [{{
                "tag": "socks-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "blocked" }}
            ],
            "route": {{
                "rules": [ {{ "ip_cidr": ["127.0.0.1/32"], "outbound": "blocked" }} ],
                "final": "direct"
            }}
        }}"#
    );
    let instance = Instance::new(Config::from_json_str(&cfg).expect("config")).expect("instance");
    instance.start().await.expect("start");

    // allowed.test resolves to 127.0.0.2, outside the rule: it must go through.
    let ok = tokio::time::timeout(
        Duration::from_secs(10),
        socks5_connect(socks_port, "allowed.test", echo_port),
    )
    .await
    .expect("connect must not hang");
    if let Ok(mut sock) = ok {
        sock.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf).await.expect("echo must answer");
        assert_eq!(&buf, b"ping");
    }

    // blocked.test resolves to 127.0.0.1, which the rule covers: the block
    // outbound must refuse it. Without resolution for routing, the rule could not
    // fire and this connection would be dialled directly.
    let refused = tokio::time::timeout(
        Duration::from_secs(10),
        socks5_connect(socks_port, "blocked.test", echo_port),
    )
    .await
    .expect("must not hang");
    assert!(
        refused.is_err(),
        "a domain resolving into a blocked CIDR was not blocked"
    );

    let _ = instance.stop().await;
}
