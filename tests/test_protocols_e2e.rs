mod common;

use base64::Engine;
use common::{get_free_tcp_port, start_tcp_echo_server, start_udp_echo_server};
use flux_app::{Config, Instance};
use flux_dns::DnsResolver;
use flux_outbound::{
    HttpOutbound, ShadowsocksOutbound, SocksOutbound, TrojanOutbound, VlessOutbound,
};
use flux_protocol::socks5::{CMD_UDP_ASSOCIATE, Socks5Handshake};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_types::{NetworkType, Outbound, SessionMeta, TargetAddress, UdpPacket};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

// -------------------------------------------------------------
// 1. SOCKS5 Pair
// -------------------------------------------------------------

#[tokio::test]
async fn test_01_socks5_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new_raw(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver.clone(),
    ));
    let socks_out = SocksOutbound::new(
        "client",
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
        dialer,
    );
    let meta = SessionMeta::new(
        "127.0.0.1:40001".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

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
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "http" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new_raw(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
    ));
    let http_out = HttpOutbound::new("client", dialer);
    let meta = SessionMeta::new(
        "127.0.0.1:40003".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

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
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, uuid_str
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new_raw(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
    ));
    let vless_out = VlessOutbound::new("client", uuid, None, dialer);
    let meta = SessionMeta::new(
        "127.0.0.1:40005".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

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
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{ "type": "tls" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, uuid_str
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let tls = flux_transport::tls::TlsClientConfig::new("localhost").with_insecure(true);
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
        flux_transport::pipeline::SecurityLayer::Tls(tls),
        flux_transport::pipeline::FramingLayer::Raw,
    ));
    let vless_out = VlessOutbound::new("client", uuid, None, dialer);
    let meta = SessionMeta::new(
        "127.0.0.1:40007".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

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
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{ "type": "tls" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let tls = flux_transport::tls::TlsClientConfig::new("localhost").with_insecure(true);
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
        flux_transport::pipeline::SecurityLayer::Tls(tls),
        flux_transport::pipeline::FramingLayer::Raw,
    ));
    let trojan_out = TrojanOutbound::new("client", password, dialer);
    let meta = SessionMeta::new(
        "127.0.0.1:40009".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

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
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "shadowsocks", "password": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(DnsResolver::new(None));
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new_raw(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver.clone(),
    ));
    let ss_out = ShadowsocksOutbound::new(
        "client",
        TargetAddress::domain("127.0.0.1", srv_port),
        password,
        resolver,
        dialer,
    );
    let meta = SessionMeta::new(
        "127.0.0.1:40011".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );

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
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let mut tcp_conn = TcpStream::connect(format!("127.0.0.1:{}", srv_port))
        .await
        .unwrap();
    let relay = Socks5Handshake::client_handshake(
        &mut tcp_conn,
        CMD_UDP_ASSOCIATE,
        &TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = UdpPacket::new(
        bytes::Bytes::from_static(b"UDP ping to flux-core relay"),
        TargetAddress::Ip(client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    client_udp
        .send_to(&encode_socks5_udp(&pkt), relay)
        .await
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let dec = decode_socks5_udp(
        TargetAddress::Ip(from),
        bytes::Bytes::copy_from_slice(&buf[..n]),
    )
    .unwrap();
    assert_eq!(
        dec.payload,
        bytes::Bytes::from_static(b"UDP ping to flux-core relay")
    );

    // Verify TCP control stream can receive data without prematurely closing the UDP association
    tcp_conn
        .write_all(b"probe keepalive data over tcp")
        .await
        .unwrap();
    tcp_conn.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let pkt2 = UdpPacket::new(
        bytes::Bytes::from_static(b"UDP ping 2 after TCP probe"),
        TargetAddress::Ip(client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    client_udp
        .send_to(&encode_socks5_udp(&pkt2), relay)
        .await
        .unwrap();

    let (n, from) = tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let dec = decode_socks5_udp(
        TargetAddress::Ip(from),
        bytes::Bytes::copy_from_slice(&buf[..n]),
    )
    .unwrap();
    assert_eq!(
        dec.payload,
        bytes::Bytes::from_static(b"UDP ping 2 after TCP probe")
    );

    // Verify dropping TCP control stream closes the association
    drop(tcp_conn);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let pkt3 = UdpPacket::new(
        bytes::Bytes::from_static(b"UDP ping 3 after TCP close"),
        TargetAddress::Ip(client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    let _ = client_udp.send_to(&encode_socks5_udp(&pkt3), relay).await;
    let timeout_res =
        tokio::time::timeout(Duration::from_millis(300), client_udp.recv_from(&mut buf)).await;
    assert!(
        timeout_res.is_err(),
        "Relay must terminate after TCP control stream closes"
    );

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_08_mixed_inbound_udp_associate_relay() {
    let udp_echo = start_udp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{"inbounds": [{{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": {}}}], "outbounds": [{{"type": "direct", "tag": "direct"}}]}}"#,
        srv_port
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let mut tcp_conn = TcpStream::connect(format!("127.0.0.1:{}", srv_port))
        .await
        .unwrap();
    let relay = Socks5Handshake::client_handshake(
        &mut tcp_conn,
        CMD_UDP_ASSOCIATE,
        &TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = UdpPacket::new(
        bytes::Bytes::from_static(b"UDP via mixed port"),
        TargetAddress::Ip(client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    client_udp
        .send_to(&encode_socks5_udp(&pkt), relay)
        .await
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let dec = decode_socks5_udp(
        TargetAddress::Ip(from),
        bytes::Bytes::copy_from_slice(&buf[..n]),
    )
    .unwrap();
    assert_eq!(
        dec.payload,
        bytes::Bytes::from_static(b"UDP via mixed port")
    );

    // Verify TCP control stream can receive data without prematurely closing the UDP association
    tcp_conn
        .write_all(b"probe keepalive over mixed tcp")
        .await
        .unwrap();
    tcp_conn.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let pkt2 = UdpPacket::new(
        bytes::Bytes::from_static(b"UDP via mixed port ping 2"),
        TargetAddress::Ip(client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    client_udp
        .send_to(&encode_socks5_udp(&pkt2), relay)
        .await
        .unwrap();

    let (n, from) = tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let dec = decode_socks5_udp(
        TargetAddress::Ip(from),
        bytes::Bytes::copy_from_slice(&buf[..n]),
    )
    .unwrap();
    assert_eq!(
        dec.payload,
        bytes::Bytes::from_static(b"UDP via mixed port ping 2")
    );

    // Verify dropping TCP control stream closes the association
    drop(tcp_conn);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let pkt3 = UdpPacket::new(
        bytes::Bytes::from_static(b"UDP via mixed port ping 3"),
        TargetAddress::Ip(client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    let _ = client_udp.send_to(&encode_socks5_udp(&pkt3), relay).await;
    let timeout_res =
        tokio::time::timeout(Duration::from_millis(300), client_udp.recv_from(&mut buf)).await;
    assert!(
        timeout_res.is_err(),
        "Relay must terminate after TCP control stream closes"
    );

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_09_vless_reality_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let uuid_str = Uuid::new_v4().to_string();

    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub.as_bytes());

    let srv_cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-reality-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{
                    "type": "reality",
                    "server_names": ["www.microsoft.com"],
                    "private_key": "{}",
                    "short_ids": ["01020304"]
                }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, private_key_b64, uuid_str
    ))
    .unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let client_cfg = Config::from_json_str(&format!(
        r#"{{
            "outbounds": [{{
                "tag": "vless-reality-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{
                    "type": "reality",
                    "sni": "www.microsoft.com",
                    "public_key": "{}",
                    "short_id": "01020304"
                }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        srv_port, public_key_b64, uuid_str
    ))
    .unwrap();
    let cli_instance = Instance::new(client_cfg).unwrap();
    let vless_out = cli_instance
        .registry
        .get_outbound("vless-reality-out")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40010".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = vless_out.dial_stream(&meta).await.unwrap();

    let payload = b"VLESS + REALITY encrypted end to end payload!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_10_mixed_inbound_http_auth_enforcement() {
    let _echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{
            "inbounds": [{{
                "type": "mixed",
                "tag": "mixed-auth-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{ "username": "admin", "password": "secretpassword" }}]
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // 1. Unauthenticated HTTP CONNECT request must receive 407 Proxy Authentication Required
    let mut sock = TcpStream::connect(format!("127.0.0.1:{}", srv_port))
        .await
        .unwrap();
    sock.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut resp = [0u8; 128];
    let n = sock.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_str.contains("407 Proxy Authentication Required"),
        "Expected 407 status, got: {}",
        resp_str
    );

    // 2. Authenticated HTTP CONNECT request must succeed with 200 Connection Established
    let mut sock_auth = TcpStream::connect(format!("127.0.0.1:{}", srv_port))
        .await
        .unwrap();
    let creds = base64::engine::general_purpose::STANDARD.encode("admin:secretpassword");
    let req = format!(
        "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nProxy-Authorization: Basic {}\r\n\r\n",
        creds
    );
    sock_auth.write_all(req.as_bytes()).await.unwrap();
    let mut resp_auth = [0u8; 128];
    let n_auth = sock_auth.read(&mut resp_auth).await.unwrap();
    let resp_auth_str = String::from_utf8_lossy(&resp_auth[..n_auth]);
    assert!(
        resp_auth_str.contains("200 Connection Established"),
        "Expected 200 status, got: {}",
        resp_auth_str
    );

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_11_fakeip_domain_routing_recovery() {
    let srv_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{
            "dns": {{
                "fakeip": {{ "enabled": true, "inet4_range": "198.18.0.0/15" }}
            }},
            "inbounds": [{{
                "tag": "socks-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [
                {{ "type": "block", "tag": "block" }},
                {{ "type": "direct", "tag": "direct" }}
            ],
            "route": {{
                "rules": [
                    {{ "domain_suffix": ["blocked.internal"], "outbound": "block" }}
                ],
                "final": "direct"
            }}
        }}"#,
        srv_port
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let fake_ip = instance
        .resolver
        .fake_ip()
        .unwrap()
        .allocate("test.blocked.internal");
    assert!(
        instance
            .resolver
            .fake_ip()
            .unwrap()
            .contains_ip(&std::net::IpAddr::V4(fake_ip))
    );

    let meta = SessionMeta::new(
        "127.0.0.1:50000".parse().unwrap(),
        TargetAddress::ip(std::net::IpAddr::V4(fake_ip), 80),
        "socks-in",
        NetworkType::Tcp,
    );

    let (matched, active) = instance.trace_route(&meta);
    assert_eq!(
        matched, "block",
        "Fake-IP should have reverse-resolved to domain and matched block"
    );
    assert_eq!(active, "block");

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_12_vmess_aead_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let uuid = Uuid::new_v4();

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "socks-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [
                {{
                    "tag": "vmess-out",
                    "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                    "protocol": {{
                        "type": "vmess",
                        "uuid": "{}",
                        "security": "aes-128-gcm"
                    }}
                }},
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        srv_port,
        echo_addr.port(),
        uuid
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    let vmess_out = instance.registry.get_outbound("vmess-out").unwrap();

    let _meta = SessionMeta::new(
        "127.0.0.1:40020".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    assert_eq!(vmess_out.protocol(), "vmess");
    assert_eq!(vmess_out.tag(), "vmess-out");
}

#[tokio::test]
async fn test_13_shadowsocks_2022_end_to_end() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let psk_b64 = base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef");

    let srv_cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "ss2022-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-aes-128-gcm"
                }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, psk_b64
    ))
    .unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_cfg = Config::from_json_str(&format!(
        r#"{{
            "outbounds": [{{
                "tag": "ss2022-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-aes-128-gcm"
                }}
            }}]
        }}"#,
        srv_port, psk_b64
    ))
    .unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let ss_out = cli_instance.registry.get_outbound("ss2022-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40022".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = ss_out.dial_stream(&meta).await.unwrap();

    let payload = b"Shadowsocks-2022 Blake3-AES-128-GCM verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_14_wireguard_amnezia_outbound_init() {
    let dummy_port = get_free_tcp_port().await;
    let priv_k = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    let peer_k = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);

    let cfg_json = format!(
        r#"{{
            "outbounds": [{{
                "tag": "awg-out",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "wireguard",
                    "private_key": "{}",
                    "peer_public_key": "{}",
                    "awg": {{
                        "jc": 3,
                        "jmin": 40,
                        "jmax": 70,
                        "s1": 16,
                        "s2": 16,
                        "h1": 10001,
                        "h2": 10002,
                        "h3": 10003,
                        "h4": 10004
                    }}
                }}
            }}]
        }}"#,
        dummy_port, priv_k, peer_k
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    let wg_out = instance.registry.get_outbound("awg-out").unwrap();
    assert_eq!(wg_out.protocol(), "wireguard");
    assert_eq!(wg_out.tag(), "awg-out");
}

#[tokio::test]
async fn test_15_hysteria2_outbound_init() {
    let cfg_json = r#"{
        "outbounds": [{
            "tag": "hy2-out",
            "carrier": { "type": "udp", "address": "127.0.0.1:443" },
            "protocol": {
                "type": "hysteria2",
                "password": "secret_hy2_password",
                "up_mbps": 50,
                "down_mbps": 100,
                "hop_interval_secs": 15
            }
        }]
    }"#;

    let cfg = Config::from_json_str(cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    let hy2_out = instance.registry.get_outbound("hy2-out").unwrap();
    assert_eq!(hy2_out.protocol(), "hysteria2");
    assert_eq!(hy2_out.tag(), "hy2-out");
}

#[tokio::test]
async fn test_16_tuic_v5_outbound_init() {
    let cfg_json = format!(
        r#"{{
            "outbounds": [{{
                "tag": "tuic-out",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:8443" }},
                "protocol": {{
                    "type": "tuic",
                    "uuid": "{}",
                    "password": "tuic_secret_pw",
                    "congestion_control": "bbr",
                    "zero_rtt": true
                }}
            }}]
        }}"#,
        Uuid::new_v4()
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    let tuic_out = instance.registry.get_outbound("tuic-out").unwrap();
    assert_eq!(tuic_out.protocol(), "tuic");
    assert_eq!(tuic_out.tag(), "tuic-out");
}

#[tokio::test]
async fn test_17_split_dns_routing_e2e() {
    let srv_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{
            "dns": {{
                "servers": ["1.1.1.1:53"],
                "client_subnet": "192.0.2.0/24",
                "rules": [
                    {{
                        "domains": ["corp.local", "internal.lan"],
                        "servers": ["10.0.0.1:53"]
                    }}
                ]
            }},
            "inbounds": [{{
                "tag": "socks-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    assert!(instance.resolver.fake_ip().is_none());
}

#[tokio::test]
async fn test_18_shadowsocks_aead_replay_defense() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "secret_ss_replay_test_pass";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "shadowsocks", "password": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // 1. Shadowsocks TCP Replay Test
    let fixed_salt = [0x55u8; 32];
    let master_key = flux_protocol::shadowsocks::derive_master_key(password);
    let subkey = flux_protocol::shadowsocks::derive_subkey(&master_key, &fixed_salt);
    let mut cipher = flux_protocol::shadowsocks::ShadowsocksCipher::with_kind(
        flux_protocol::shadowsocks::CipherKind::ChaCha20IetfPoly1305,
        &subkey,
    );

    let target = TargetAddress::Ip(echo_addr);
    let addr_bytes = flux_protocol::shadowsocks::encode_ss_address(&target);
    let enc_len = cipher
        .encrypt(&(addr_bytes.len() as u16).to_be_bytes())
        .unwrap();
    let enc_addr = cipher.encrypt(&addr_bytes).unwrap();

    let mut handshake_payload = Vec::new();
    handshake_payload.extend_from_slice(&fixed_salt);
    handshake_payload.extend_from_slice(&enc_len);
    handshake_payload.extend_from_slice(&enc_addr);

    // First TCP connection: should succeed
    let mut tcp1 = TcpStream::connect(format!("127.0.0.1:{}", srv_port))
        .await
        .unwrap();
    tcp1.write_all(&handshake_payload).await.unwrap();
    tcp1.flush().await.unwrap();

    let mut server_salt = [0u8; 32];
    let res = tokio::time::timeout(Duration::from_secs(3), tcp1.read_exact(&mut server_salt)).await;
    assert!(res.is_ok(), "First handshake with salt should succeed");

    // Second TCP connection with identical salt (replay attack): must be rejected!
    let mut tcp2 = TcpStream::connect(format!("127.0.0.1:{}", srv_port))
        .await
        .unwrap();
    tcp2.write_all(&handshake_payload).await.unwrap();
    tcp2.flush().await.unwrap();

    let mut probe = [0u8; 32];
    let read_res = tokio::time::timeout(Duration::from_secs(2), tcp2.read_exact(&mut probe)).await;
    assert!(
        read_res.is_err() || matches!(read_res, Ok(Err(_))),
        "Replayed handshake with reused salt must be rejected by server (got {:?})",
        read_res
    );

    // 2. Shadowsocks UDP Replay Test
    let udp_echo = start_udp_echo_server().await;
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_salt = [0x77u8; 32];
    let udp_subkey = flux_protocol::shadowsocks::derive_subkey(&master_key, &udp_salt);
    let mut udp_cipher = flux_protocol::shadowsocks::ShadowsocksCipher::with_kind(
        flux_protocol::shadowsocks::CipherKind::ChaCha20IetfPoly1305,
        &udp_subkey,
    );
    let udp_target = TargetAddress::Ip(udp_echo);
    let udp_addr_bytes = flux_protocol::shadowsocks::encode_ss_address(&udp_target);
    let udp_payload = b"UDP SS AEAD message";
    let mut plain_udp = Vec::new();
    plain_udp.extend_from_slice(&udp_addr_bytes);
    plain_udp.extend_from_slice(udp_payload);
    let cipher_udp = udp_cipher.encrypt(&plain_udp).unwrap();

    let mut pkt_bytes = Vec::new();
    pkt_bytes.extend_from_slice(&udp_salt);
    pkt_bytes.extend_from_slice(&cipher_udp);

    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", srv_port).parse().unwrap();
    // First UDP packet: should be relayed and receive response
    client_udp.send_to(&pkt_bytes, server_addr).await.unwrap();
    let mut resp_buf = [0u8; 1024];
    let recv_res1 =
        tokio::time::timeout(Duration::from_secs(3), client_udp.recv_from(&mut resp_buf)).await;
    assert!(
        recv_res1.is_ok(),
        "First UDP packet with salt should be processed"
    );

    // Second UDP packet with identical salt (replay): must be dropped!
    client_udp.send_to(&pkt_bytes, server_addr).await.unwrap();
    let recv_res2 = tokio::time::timeout(
        Duration::from_millis(500),
        client_udp.recv_from(&mut resp_buf),
    )
    .await;
    assert!(
        recv_res2.is_err(),
        "Replayed UDP packet with reused salt must be dropped"
    );

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_19_vmess_inbound_server_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let test_uuid_str = "b2c3d4e5-f6a7-8901-2345-6789abcdef01";

    let srv_cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "vmess-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "vmess",
                    "uuid": "{}"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        srv_port, test_uuid_str
    ))
    .unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_cfg = Config::from_json_str(&format!(
        r#"{{
            "outbounds": [{{
                "tag": "vmess-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "vmess",
                    "uuid": "{}",
                    "security": "aes-128-gcm"
                }}
            }}]
        }}"#,
        srv_port, test_uuid_str
    ))
    .unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let vmess_out = cli_instance.registry.get_outbound("vmess-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40030".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = vmess_out.dial_stream(&meta).await.unwrap();

    let payload = b"VMess Server <-> Client End-To-End Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_20_tuic_v5_inbound_server_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let test_uuid_str = "c3d4e5f6-a7b8-9012-3456-789abcdef012";
    let password = "tuic-secret-password";

    let srv_cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "tuic-in",
                "carrier": {{ "type": "udp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "tuic",
                    "uuid": "{}",
                    "password": "{}"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        srv_port, test_uuid_str, password
    ))
    .unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_cfg = Config::from_json_str(&format!(
        r#"{{
            "outbounds": [{{
                "tag": "tuic-out",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "tuic",
                    "uuid": "{}",
                    "password": "{}"
                }}
            }}]
        }}"#,
        srv_port, test_uuid_str, password
    ))
    .unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let tuic_out = cli_instance.registry.get_outbound("tuic-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40032".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = tuic_out.dial_stream(&meta).await.unwrap();

    let payload = b"TUIC v5 Full QUIC Inbound Server Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_21_hysteria2_inbound_server_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "hy2-secret-password";

    let srv_cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "hy2-in",
                "carrier": {{ "type": "udp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "hysteria2",
                    "password": "{}"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_cfg = Config::from_json_str(&format!(
        r#"{{
            "outbounds": [{{
                "tag": "hy2-out",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "hysteria2",
                    "password": "{}"
                }}
            }}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let hy2_out = cli_instance.registry.get_outbound("hy2-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40034".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = hy2_out.dial_stream(&meta).await.unwrap();

    let payload = b"Hysteria 2 Full QUIC Inbound Server Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}
