mod common;

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;
use flux_types::{NetworkType, Outbound, SessionMeta, TargetAddress, UdpPacket};
use flux_dns::DnsResolver;
use flux_protocol::socks5::{Socks5Handshake, CMD_UDP_ASSOCIATE};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_outbound::{HttpOutbound, ShadowsocksOutbound, SocksOutbound, TrojanOutbound, VlessOutbound};
use flux_app::{Config, Instance};
use common::{get_free_tcp_port, start_tcp_echo_server, start_udp_echo_server};

// -------------------------------------------------------------
// 1. SOCKS5 Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_01_socks5_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let socks_out = SocksOutbound::new("client", TargetAddress::domain("127.0.0.1", srv_port), resolver);
    let meta = SessionMeta::new("127.0.0.1:40001".parse().unwrap(), TargetAddress::Ip(echo_addr), "test", NetworkType::Tcp);

    let mut stream = socks_out.dial_stream(&meta).await.unwrap();
    let payload = b"SOCKS5 flux client -> server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

// -------------------------------------------------------------
// 2. HTTP CONNECT Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_02_http_connect_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "http", "tag": "in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let http_out = HttpOutbound::new("client", TargetAddress::domain("127.0.0.1", srv_port), resolver);
    let meta = SessionMeta::new("127.0.0.1:40003".parse().unwrap(), TargetAddress::Ip(echo_addr), "test", NetworkType::Tcp);

    let mut stream = http_out.dial_stream(&meta).await.unwrap();
    let payload = b"HTTP flux client -> server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

// -------------------------------------------------------------
// 3. VLESS TCP (plain) Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_03_vless_plain_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let uuid_str = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";
    let uuid = Uuid::parse_str(uuid_str).unwrap();

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": {}, "users": [{{"uuid": "{}"}}] }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, uuid_str
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let vless_out = VlessOutbound::new("client", TargetAddress::domain("127.0.0.1", srv_port), uuid, None, resolver, None, None);
    let meta = SessionMeta::new("127.0.0.1:40005".parse().unwrap(), TargetAddress::Ip(echo_addr), "test", NetworkType::Tcp);

    let mut stream = vless_out.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS plain flux client -> server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

// -------------------------------------------------------------
// 4. VLESS + TLS Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_04_vless_tls_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let uuid_str = "87654321-4321-4321-4321-cba987654321";
    let uuid = Uuid::parse_str(uuid_str).unwrap();

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "tls": {{"enabled": true}}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, uuid_str
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let tls = flux_transport::tls::TlsClientConfig::new("localhost").with_insecure(true);
    let vless_out = VlessOutbound::new("client", TargetAddress::domain("127.0.0.1", srv_port), uuid, None, resolver, Some(tls), None);
    let meta = SessionMeta::new("127.0.0.1:40007".parse().unwrap(), TargetAddress::Ip(echo_addr), "test", NetworkType::Tcp);

    let mut stream = vless_out.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS TLS flux client -> server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

// -------------------------------------------------------------
// 5. Trojan + TLS Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_05_trojan_tls_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "flux-trojan-password-123";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan", "tag": "in", "listen": "127.0.0.1", "listen_port": {},
                "password": ["{}"]
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let tls = flux_transport::tls::TlsClientConfig::new("localhost").with_insecure(true);
    let trojan_out = TrojanOutbound::new("client", TargetAddress::domain("127.0.0.1", srv_port), password, resolver, tls);
    let meta = SessionMeta::new("127.0.0.1:40009".parse().unwrap(), TargetAddress::Ip(echo_addr), "test", NetworkType::Tcp);

    let mut stream = trojan_out.dial_stream(&meta).await.unwrap();
    let payload = b"Trojan TLS flux client -> server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

// -------------------------------------------------------------
// 6. Shadowsocks AEAD Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_06_shadowsocks_aead_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "secret_ss_pass_123";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks", "tag": "in", "listen": "127.0.0.1", "listen_port": {},
                "password": "{}"
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let ss_out = ShadowsocksOutbound::new("client", TargetAddress::domain("127.0.0.1", srv_port), password, resolver);
    let meta = SessionMeta::new("127.0.0.1:40011".parse().unwrap(), TargetAddress::Ip(echo_addr), "test", NetworkType::Tcp);

    let mut stream = ss_out.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks AEAD flux client -> server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    instance.stop().await.unwrap();
}

// -------------------------------------------------------------
// 7. SOCKS5 UDP Associate Relay
// -------------------------------------------------------------

#[tokio::test]
async fn test_07_socks5_udp_associate_relay() {
    let udp_echo = start_udp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    )).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let mut tcp_conn = TcpStream::connect(format!("127.0.0.1:{}", srv_port)).await.unwrap();
    let relay = Socks5Handshake::client_handshake(&mut tcp_conn, CMD_UDP_ASSOCIATE, &TargetAddress::Ip("0.0.0.0:0".parse().unwrap())).await.unwrap().unwrap();

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = UdpPacket::new(bytes::Bytes::from_static(b"UDP ping to flux-core relay"), TargetAddress::Ip(client_udp.local_addr().unwrap()), TargetAddress::Ip(udp_echo));
    client_udp.send_to(&encode_socks5_udp(&pkt), relay).await.unwrap();

    let mut buf = vec![0u8; 65535];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut buf)).await.unwrap().unwrap();
    let dec = decode_socks5_udp(TargetAddress::Ip(from), bytes::Bytes::copy_from_slice(&buf[..n])).unwrap();
    assert_eq!(dec.payload, bytes::Bytes::from_static(b"UDP ping to flux-core relay"));

    instance.stop().await.unwrap();
}
