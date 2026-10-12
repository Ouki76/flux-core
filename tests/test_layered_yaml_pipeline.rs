mod common;

use base64::Engine;
use common::{
    get_free_tcp_port, start_tcp_echo_server, start_tls_echo_server, start_udp_echo_server,
};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[tokio::test]
async fn test_layered_yaml_shadowsocks_reality_ws_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub.as_bytes());

    let srv_yaml = format!(
        r#"
inbounds:
  - tag: ss-stealth-in
    carrier:
      type: tcp
      listen: "127.0.0.1"
      listen_port: {}
    security:
      type: reality
      server_names: ["www.microsoft.com"]
      private_key: "{}"
      short_ids: ["01020304"]
    framing:
      type: ws
      path: "/stealth-ws"
    protocol:
      type: shadowsocks
      password: "secret-ss-password"
      method: "2022-blake3-chacha20-poly1305"

outbounds:
  - type: direct
    tag: direct
"#,
        srv_port, private_key_b64
    );

    let srv_cfg = Config::from_yaml_str(&srv_yaml).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: ss-stealth-out
    carrier:
      type: tcp
      address: "127.0.0.1:{}"
    security:
      type: reality
      sni: "www.microsoft.com"
      public_key: "{}"
      short_id: "01020304"
    framing:
      type: ws
      path: "/stealth-ws"
    protocol:
      type: shadowsocks
      password: "secret-ss-password"
      method: "2022-blake3-chacha20-poly1305"
"#,
        srv_port, public_key_b64
    );

    let cli_cfg = Config::from_yaml_str(&cli_yaml).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let ss_out = cli_instance
        .registry
        .get_outbound("ss-stealth-out")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:50001".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = ss_out.dial_stream(&meta).await.unwrap();

    let payload = b"Shadowsocks + REALITY + WebSocket Layered Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_layered_yaml_shadowsocks_pure_udp_e2e() {
    let udp_echo = start_udp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let srv_yaml = format!(
        r#"
inbounds:
  - tag: ss-udp-in
    carrier:
      type: udp
      listen: "127.0.0.1"
      listen_port: {}
    protocol:
      type: shadowsocks
      password: "secret-udp-password"
      method: "2022-blake3-aes-128-gcm"

outbounds:
  - type: direct
    tag: direct
"#,
        srv_port
    );

    let srv_cfg = Config::from_yaml_str(&srv_yaml).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: ss-udp-out
    carrier:
      type: udp
      address: "127.0.0.1:{}"
    protocol:
      type: shadowsocks
      password: "secret-udp-password"
      method: "2022-blake3-aes-128-gcm"
"#,
        srv_port
    );

    let cli_cfg = Config::from_yaml_str(&cli_yaml).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let ss_out = cli_instance.registry.get_outbound("ss-udp-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:50002".parse().unwrap(),
        TargetAddress::Ip(udp_echo),
        "test",
        NetworkType::Udp,
    );

    let endpoint = ss_out.dial_packet(&meta).await.unwrap();
    let payload = bytes::Bytes::from_static(b"Pure UDP Shadowsocks Datagram Test");
    let packet = UdpPacket::new(
        payload.clone(),
        TargetAddress::Ip("127.0.0.1:50002".parse().unwrap()),
        TargetAddress::Ip(udp_echo),
    );

    endpoint.send_packet(packet).await.unwrap();
    let reply = endpoint.recv_packet().await.unwrap();
    assert_eq!(reply.payload, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_layered_yaml_vless_reality_vision_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let test_uuid_str = Uuid::new_v4().to_string();

    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub.as_bytes());

    let srv_yaml = format!(
        r#"
inbounds:
  - tag: vless-reality-in
    carrier:
      type: tcp
      listen: "127.0.0.1"
      listen_port: {}
    security:
      type: reality
      server_names: ["www.microsoft.com"]
      private_key: "{}"
      short_ids: ["01020304"]
    protocol:
      type: vless
      uuid: "{}"

outbounds:
  - type: direct
    tag: direct
"#,
        srv_port, private_key_b64, test_uuid_str
    );

    let srv_cfg = Config::from_yaml_str(&srv_yaml).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: vless-reality-out
    carrier:
      type: tcp
      address: "127.0.0.1:{}"
    security:
      type: reality
      sni: "www.microsoft.com"
      public_key: "{}"
      short_id: "01020304"
    protocol:
      type: vless
      uuid: "{}"
      flow: xtls-rprx-vision
"#,
        srv_port, public_key_b64, test_uuid_str
    );

    let cli_cfg = Config::from_yaml_str(&cli_yaml).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let vless_out = cli_instance
        .registry
        .get_outbound("vless-reality-out")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:50003".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = vless_out.dial_stream(&meta).await.unwrap();

    let payload = b"VLESS + REALITY + XTLS-Vision Layered Clean Config Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_layered_yaml_chained_multi_security_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub.as_bytes());

    let srv_yaml = format!(
        r#"
inbounds:
  - tag: multi-sec-in
    carrier:
      type: tcp
      listen: "127.0.0.1"
      listen_port: {}
    security:
      - type: shadowtls
        version: 3
        password: "stls-password"
        fallback: "127.0.0.1:{}"
      - type: reality
        server_names: ["www.microsoft.com"]
        private_key: "{}"
        short_ids: ["01020304"]
    framing:
      type: ws
      path: "/cascade-stream"
    protocol:
      type: shadowsocks
      password: "ss-cascade-password"
      method: "2022-blake3-chacha20-poly1305"

outbounds:
  - type: direct
    tag: direct
"#,
        srv_port,
        echo_addr.port(),
        private_key_b64
    );

    let srv_cfg = Config::from_yaml_str(&srv_yaml).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: multi-sec-out
    carrier:
      type: tcp
      address: "127.0.0.1:{}"
    security:
      - type: shadowtls
        version: 3
        password: "stls-password"
        sni: "www.microsoft.com"
      - type: reality
        sni: "www.microsoft.com"
        public_key: "{}"
        short_id: "01020304"
    framing:
      type: ws
      path: "/cascade-stream"
    protocol:
      type: shadowsocks
      password: "ss-cascade-password"
      method: "2022-blake3-chacha20-poly1305"
"#,
        srv_port, public_key_b64
    );

    let cli_cfg = Config::from_yaml_str(&cli_yaml).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let multi_out = cli_instance.registry.get_outbound("multi-sec-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:50004".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = multi_out.dial_stream(&meta).await.unwrap();

    let payload = b"Chained ShadowTLS + REALITY + WS + Shadowsocks Cascade Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_layered_yaml_udp_carrier_rejects_non_shadowsocks() {
    let out_yaml = r#"
outbounds:
  - tag: invalid-udp-vless
    carrier:
      type: udp
      address: "127.0.0.1:8080"
    protocol:
      type: vless
      uuid: "a1b2c3d4-e5f6-7890-1234-56789abcdef0"
"#;
    let cfg = Config::from_yaml_str(out_yaml).unwrap();
    let err = match Instance::new(cfg) {
        Err(e) => e,
        Ok(_) => panic!("expected Instance::new to fail for UDP + VLESS"),
    };
    assert!(err.to_string().contains("carrier UDP currently supports"));

    let in_yaml = r#"
inbounds:
  - tag: invalid-udp-vless-in
    carrier:
      type: udp
      listen: "127.0.0.1"
      listen_port: 8081
    protocol:
      type: vless
      uuid: "a1b2c3d4-e5f6-7890-1234-56789abcdef0"
outbounds:
  - type: direct
    tag: direct
"#;
    let cfg_in = Config::from_yaml_str(in_yaml).unwrap();
    let err_in = match Instance::new(cfg_in) {
        Err(e) => e,
        Ok(_) => panic!("expected Instance::new to fail for inbound UDP + VLESS"),
    };
    assert!(
        err_in
            .to_string()
            .contains("carrier UDP currently supports")
    );
}

#[tokio::test]
async fn test_layered_yaml_missing_carrier_address_fails_gracefully() {
    let bad_carrier_yaml = r#"
outbounds:
  - tag: missing-address
    carrier:
      type: tcp
    protocol:
      type: trojan
      password: "pass"
"#;
    let cfg = Config::from_yaml_str(bad_carrier_yaml).unwrap();
    let err = match Instance::new(cfg) {
        Err(e) => e,
        Ok(_) => panic!("expected Instance::new to fail for missing address"),
    };
    assert!(
        err.to_string()
            .contains("tcp carrier must specify address or server+port")
    );
}

#[tokio::test]
async fn test_layered_yaml_single_security_and_framing_roundtrip() {
    let yaml = r#"
outbounds:
  - tag: single-sec-ws
    carrier:
      type: tcp
      address: "127.0.0.1:443"
    security:
      type: tls
      sni: "example.com"
    framing:
      type: ws
      path: "/ws-single"
    protocol:
      type: trojan
      password: "pass"
"#;
    let cfg = Config::from_yaml_str(yaml).unwrap();
    assert!(Instance::new(cfg).is_ok());
}

#[tokio::test]
async fn test_layered_yaml_hysteria2_over_tcp_reality_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub.as_bytes());

    let srv_yaml = format!(
        r#"
inbounds:
  - tag: hy2-reality-in
    carrier:
      type: tcp
      listen: "127.0.0.1"
      listen_port: {}
    security:
      type: reality
      server_names: ["www.microsoft.com"]
      private_key: "{}"
      short_ids: ["01020304"]
    protocol:
      type: hysteria2
      password: "hy2-stealth-password"

outbounds:
  - type: direct
    tag: direct
"#,
        srv_port, private_key_b64
    );

    let srv_cfg = Config::from_yaml_str(&srv_yaml).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: hy2-reality-out
    carrier:
      type: tcp
      address: "127.0.0.1:{}"
    security:
      type: reality
      sni: "www.microsoft.com"
      public_key: "{}"
      short_id: "01020304"
    protocol:
      type: hysteria2
      password: "hy2-stealth-password"
"#,
        srv_port, public_key_b64
    );

    let cli_cfg = Config::from_yaml_str(&cli_yaml).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let hy2_out = cli_instance
        .registry
        .get_outbound("hy2-reality-out")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:50005".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = hy2_out.dial_stream(&meta).await.unwrap();

    let payload = b"Hysteria 2 over TCP + REALITY End-To-End Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_layered_yaml_tuic_over_tcp_reality_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let private_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let public_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub.as_bytes());

    let tuic_uuid = Uuid::new_v4().to_string();

    let srv_yaml = format!(
        r#"
inbounds:
  - tag: tuic-reality-in
    carrier:
      type: tcp
      listen: "127.0.0.1"
      listen_port: {}
    security:
      type: reality
      server_names: ["www.microsoft.com"]
      private_key: "{}"
      short_ids: ["01020304"]
    protocol:
      type: tuic
      uuid: "{}"
      password: "tuic-stealth-password"

outbounds:
  - type: direct
    tag: direct
"#,
        srv_port, private_key_b64, tuic_uuid
    );

    let srv_cfg = Config::from_yaml_str(&srv_yaml).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: tuic-reality-out
    carrier:
      type: tcp
      address: "127.0.0.1:{}"
    security:
      type: reality
      sni: "www.microsoft.com"
      public_key: "{}"
      short_id: "01020304"
    protocol:
      type: tuic
      uuid: "{}"
      password: "tuic-stealth-password"
"#,
        srv_port, public_key_b64, tuic_uuid
    );

    let cli_cfg = Config::from_yaml_str(&cli_yaml).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let tuic_out = cli_instance
        .registry
        .get_outbound("tuic-reality-out")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:50006".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = tuic_out.dial_stream(&meta).await.unwrap();

    let payload = b"TUIC v5 over TCP + REALITY End-To-End Verified!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_layered_yaml_shadowsocks2022_shadowtls_v3_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let decoy = start_tls_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let yaml = format!(
        r#"
inbounds:
  - tag: stls-in
    carrier:
      type: tcp
      listen: "127.0.0.1"
      listen_port: {}
    security:
      type: shadowtls
      version: 3
      password: "pw123"
      fallback: "127.0.0.1:{}"
    protocol:
      type: shadowsocks
      method: 2022-blake3-aes-128-gcm
      password: "MDEyMzQ1Njc4OWFiY2RlZg=="
outbounds:
  - type: direct
    tag: direct
"#,
        srv_port,
        decoy.port()
    );
    let srv = Instance::new(Config::from_yaml_str(&yaml).unwrap()).unwrap();
    srv.start().await.unwrap();

    let cli_yaml = format!(
        r#"
outbounds:
  - tag: out
    carrier:
      type: tcp
      address: "127.0.0.1:{}"
    security:
      type: shadowtls
      version: 3
      password: "pw123"
      sni: "localhost"
    protocol:
      type: shadowsocks
      method: 2022-blake3-aes-128-gcm
      password: "MDEyMzQ1Njc4OWFiY2RlZg=="
"#,
        srv_port
    );
    let cli = Instance::new(Config::from_yaml_str(&cli_yaml).unwrap()).unwrap();
    let out = cli.registry.get_outbound("out").unwrap();
    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut s = out.dial_stream(&meta).await.unwrap();
    s.write_all(b"ss2022-over-shadowtls").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = vec![0u8; 21];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ss2022-over-shadowtls");
}
