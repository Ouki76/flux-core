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
