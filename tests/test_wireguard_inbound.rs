mod common;

use base64::Engine;
use common::{get_free_tcp_port, start_tcp_echo_server, start_udp_echo_server};
use flux_app::{Config, Instance};
use flux_outbound::WireGuardOutbound;
use flux_protocol::wireguard::WireGuardConfig;
use flux_types::{NetworkType, SessionMeta, TargetAddress, UdpPacket};
use std::sync::Arc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn b64_key(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

/// Full loopback: WireGuard client outbound → WireGuard server inbound →
/// userspace TCP/IP stack → dispatcher → direct outbound → UDP echo server.
#[tokio::test]
async fn test_wireguard_inbound_udp_echo() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let echo_addr = start_udp_echo_server().await;
    let wg_port = get_free_tcp_port().await;

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);

    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "type": "wireguard",
                    "tag": "wg-in",
                    "listen": "127.0.0.1",
                    "listen_port": {},
                    "private_key": "{}",
                    "peers": [
                        {{
                            "public_key": "{}",
                            "allowed_ips": ["10.0.0.0/24"]
                        }}
                    ]
                }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        wg_port,
        b64_key(&server_secret.to_bytes()),
        b64_key(client_pub.as_bytes())
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Client-side WireGuard tunnel (outbound)
    let wg_cfg = WireGuardConfig {
        private_key: client_secret.to_bytes(),
        peer_public_key: *server_pub.as_bytes(),
        preshared_key: None,
        server_address: TargetAddress::Ip(format!("127.0.0.1:{}", wg_port).parse().unwrap()),
        local_address: Some("10.0.0.2".parse().unwrap()),
        keepalive_secs: Some(0),
        awg: None,
    };
    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let outbound = WireGuardOutbound::new("wg-out", wg_cfg, resolver);

    let client_src: std::net::SocketAddr = "10.0.0.2:10000".parse().unwrap();
    let meta = SessionMeta::new(
        client_src,
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Udp,
    );
    let ep = flux_types::Outbound::dial_packet(&outbound, &meta)
        .await
        .expect("wireguard dial_packet must succeed");

    let payload = bytes::Bytes::from_static(b"wireguard-inbound-echo-payload");
    ep.send_packet(UdpPacket::new(
        payload.clone(),
        TargetAddress::Ip(client_src),
        TargetAddress::Ip(echo_addr),
    ))
    .await
    .unwrap();

    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), ep.recv_packet())
        .await
        .expect("timed out waiting for wireguard echo reply")
        .expect("recv_packet must succeed");

    assert_eq!(reply.payload, payload);
    assert_eq!(reply.destination, TargetAddress::Ip(client_src));

    instance.stop().await.unwrap();
}

/// Full loopback TCP: WireGuard client outbound (embedded userspace TCP stack)
/// → WireGuard server inbound → dispatcher → direct → TCP echo server.
#[tokio::test]
async fn test_wireguard_inbound_tcp_echo() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let echo_addr = start_tcp_echo_server().await;
    let wg_port = get_free_tcp_port().await;

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);

    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "type": "wireguard",
                    "tag": "wg-in",
                    "listen": "127.0.0.1",
                    "listen_port": {},
                    "private_key": "{}",
                    "peers": [{{ "public_key": "{}", "allowed_ips": ["10.0.0.0/24"] }}]
                }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        wg_port,
        b64_key(&server_secret.to_bytes()),
        b64_key(client_pub.as_bytes())
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let wg_cfg = WireGuardConfig {
        private_key: client_secret.to_bytes(),
        peer_public_key: *server_pub.as_bytes(),
        preshared_key: None,
        server_address: TargetAddress::Ip(format!("127.0.0.1:{}", wg_port).parse().unwrap()),
        local_address: Some("10.0.0.2".parse().unwrap()),
        keepalive_secs: Some(0),
        awg: None,
    };
    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let outbound = WireGuardOutbound::new("wg-out", wg_cfg, resolver);

    let meta = SessionMeta::new(
        "10.0.0.2:10000".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        flux_types::Outbound::dial_stream(&outbound, &meta),
    )
    .await
    .expect("wireguard TCP dial timed out")
    .expect("wireguard TCP dial must succeed");

    let payload = b"wireguard-tcp-echo-payload";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_exact(&mut buf),
    )
    .await
    .expect("timed out waiting for TCP echo reply")
    .unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

/// Unauthorized peer (not in the allow-list) must never complete a handshake.
#[tokio::test]
async fn test_wireguard_inbound_rejects_unknown_peer() {
    let wg_port = get_free_tcp_port().await;

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let authorized_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let authorized_pub = X25519PublicKey::from(&authorized_secret);
    let rogue_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);

    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "type": "wireguard",
                    "tag": "wg-in",
                    "listen": "127.0.0.1",
                    "listen_port": {},
                    "private_key": "{}",
                    "peers": [{{ "public_key": "{}" }}]
                }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        wg_port,
        b64_key(&server_secret.to_bytes()),
        b64_key(authorized_pub.as_bytes())
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let wg_cfg = WireGuardConfig {
        private_key: rogue_secret.to_bytes(),
        peer_public_key: *server_pub.as_bytes(),
        preshared_key: None,
        server_address: TargetAddress::Ip(format!("127.0.0.1:{}", wg_port).parse().unwrap()),
        local_address: Some("10.0.0.2".parse().unwrap()),
        keepalive_secs: Some(0),
        awg: None,
    };
    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let outbound = WireGuardOutbound::new("wg-rogue", wg_cfg, resolver);

    let meta = SessionMeta::new(
        "10.0.0.2:10000".parse().unwrap(),
        TargetAddress::Ip("127.0.0.1:53".parse().unwrap()),
        "test",
        NetworkType::Udp,
    );
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        flux_types::Outbound::dial_packet(&outbound, &meta),
    )
    .await;
    // handshake failure or timeout: both acceptable; success is a security hole
    if let Ok(Ok(_)) = res {
        panic!("rogue peer must not complete the wireguard handshake");
    }

    instance.stop().await.unwrap();
}

/// Regression: a runt datagram must never take down the inbound's only receive
/// loop. Before the fix, a 4-byte `h4` packet made the handler index `pkt[4..8]`
/// out of bounds, panicking the UDP receive task and silently killing the
/// inbound for every peer (unauthenticated remote DoS).
#[tokio::test]
async fn test_wireguard_inbound_survives_runt_datagrams() {
    let echo_addr = start_udp_echo_server().await;
    let wg_port = get_free_tcp_port().await;

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);

    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "type": "wireguard",
                    "tag": "wg-in",
                    "listen": "127.0.0.1",
                    "listen_port": {},
                    "private_key": "{}",
                    "peers": [{{ "public_key": "{}", "allowed_ips": ["10.0.0.0/24"] }}]
                }}
            ],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        wg_port,
        b64_key(&server_secret.to_bytes()),
        b64_key(client_pub.as_bytes())
    );
    let instance = Instance::new(Config::from_json_str(&raw_config).unwrap()).unwrap();
    instance.start().await.unwrap();

    // Establish a working tunnel first.
    let wg_cfg = WireGuardConfig {
        private_key: client_secret.to_bytes(),
        peer_public_key: *server_pub.as_bytes(),
        preshared_key: None,
        server_address: TargetAddress::Ip(format!("127.0.0.1:{}", wg_port).parse().unwrap()),
        local_address: Some("10.0.0.2".parse().unwrap()),
        keepalive_secs: Some(0),
        awg: None,
    };
    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let outbound = Arc::new(WireGuardOutbound::new("wg-runt", wg_cfg, resolver));
    let meta = SessionMeta::new(
        "10.0.0.2:10000".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Udp,
    );
    let endpoint = flux_types::Outbound::dial_packet(outbound.as_ref(), &meta)
        .await
        .expect("baseline tunnel must be established");
    endpoint
        .send_packet(UdpPacket::new(
            bytes::Bytes::from_static(b"before-runt"),
            TargetAddress::Ip("10.0.0.2:10000".parse().unwrap()),
            TargetAddress::Ip(echo_addr),
        ))
        .await
        .unwrap();
    let before = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.recv_packet())
        .await
        .expect("echo before the runt flood timed out")
        .expect("echo before the runt flood failed");
    assert_eq!(&before.payload[..], b"before-runt");

    // Flood the inbound with runts and other malformed shapes.
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = format!("127.0.0.1:{}", wg_port);
    for junk in [
        &b"\x04\x00\x00\x00"[..], // h4 with no receiver index (the original panic)
        &b"\x04\x00\x00\x00\x01\x02\x03\x04"[..], // h4 + index, no counter/ciphertext
        &b"\x01"[..],             // single byte
        &b""[..],                 // empty datagram
        &b"\x01\x00\x00\x00short"[..], // truncated handshake initiation
    ] {
        let _ = attacker.send_to(junk, &target).await;
    }

    // The tunnel must keep working: same endpoint, plus a brand new one (which
    // requires the receive loop to still be alive for a fresh handshake).
    endpoint
        .send_packet(UdpPacket::new(
            bytes::Bytes::from_static(b"after-runt"),
            TargetAddress::Ip("10.0.0.2:10000".parse().unwrap()),
            TargetAddress::Ip(echo_addr),
        ))
        .await
        .unwrap();
    let after = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.recv_packet())
        .await
        .expect("echo after the runt flood timed out — inbound receive loop died")
        .expect("echo after the runt flood failed");
    assert_eq!(&after.payload[..], b"after-runt");

    instance.stop().await.unwrap();
}

/// Regression: WireGuard requires the responder to reject an initiation that is
/// not strictly newer than the last accepted one for that peer. Only a freshness
/// window was enforced before, so a captured initiation could be replayed
/// indefinitely (four X25519 operations and a session replacement per replay).
#[tokio::test]
async fn test_wireguard_inbound_rejects_replayed_initiation() {
    use flux_protocol::wireguard::{AwgConfig, WireGuardHandshake};

    let wg_port = get_free_tcp_port().await;
    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);

    let raw_config = format!(
        r#"{{
            "inbounds": [{{
                "type": "wireguard", "tag": "wg-in",
                "listen": "127.0.0.1", "listen_port": {},
                "private_key": "{}",
                "peers": [{{ "public_key": "{}", "allowed_ips": ["10.0.0.0/24"] }}]
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        wg_port,
        b64_key(&server_secret.to_bytes()),
        b64_key(client_pub.as_bytes())
    );
    let instance = Instance::new(Config::from_json_str(&raw_config).unwrap()).unwrap();
    instance.start().await.unwrap();

    // Build one initiation and replay the exact same bytes twice.
    let awg = AwgConfig::default();
    let (init, _state) =
        WireGuardHandshake::create_initiation(&client_secret, &server_pub, 0x1234_5678, &awg, None);

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = format!("127.0.0.1:{}", wg_port);

    sock.send_to(&init, &target).await.unwrap();
    let mut buf = [0u8; 2048];
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("first initiation must be answered")
        .expect("recv failed");
    assert!(first.0 > 0);

    // Replay: the responder must stay silent.
    sock.send_to(&init, &target).await.unwrap();
    let replayed = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        sock.recv_from(&mut buf),
    )
    .await;
    assert!(
        replayed.is_err(),
        "a replayed handshake initiation must not be answered"
    );

    instance.stop().await.unwrap();
}
