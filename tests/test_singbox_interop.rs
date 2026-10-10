mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct SingboxProcess {
    child: Child,
    _dir: TempDir,
}

impl SingboxProcess {
    pub fn start(config_json: &str) -> (Self, PathBuf) {
        let bin = get_singbox_bin().expect("sing-box binary must be present");
        let dir = TempDir::new().expect("failed to create tempdir");
        let cfg_path = dir.path().join("config.json");
        fs::write(&cfg_path, config_json).expect("failed to write sing-box config");

        let (stdout_cfg, stderr_cfg) = if std::env::var("SINGBOX_LOG").is_ok() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };

        let child = Command::new(&bin)
            .args(["run", "-c", cfg_path.to_str().unwrap()])
            .stdout(stdout_cfg)
            .stderr(stderr_cfg)
            .spawn()
            .expect("failed to spawn sing-box");

        // Give sing-box 100ms to bind ports
        std::thread::sleep(Duration::from_millis(150));

        (Self { child, _dir: dir }, cfg_path)
    }
}

impl Drop for SingboxProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn get_singbox_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SINGBOX_BIN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    let default_path = PathBuf::from("/home/ouki/.local/bin/sing-box");
    if default_path.exists() {
        return Some(default_path);
    }
    which("sing-box")
}

fn which(name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for p in path.split(':') {
            let full = Path::new(p).join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

pub fn generate_self_signed_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "example.com".to_string(),
    ])
    .expect("cert generation");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    (cert_path, key_path)
}

// ---------------------------------------------------------------------------
// 1. SOCKS5 Interoperability (Plain & Auth)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_interop_socks5_plain_flux_to_singbox() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;

    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-socks-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "socks" }}
            }}]
        }}"#,
        sbox_port
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-socks-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Hello sing-box server from flux-core SOCKS5 client!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn test_interop_socks5_plain_singbox_to_flux() {
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let sbox_in_port = get_free_tcp_port().await;

    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-socks-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    flux_inst.start().await.unwrap();

    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "sbox-client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "socks",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {}
            }}]
        }}"#,
        sbox_in_port, flux_port
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload = b"Hello flux-core server from sing-box SOCKS5 client!";
    conn.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    flux_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_socks5_auth_flux_to_singbox() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;

    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"username": "admin", "password": "secretpassword"}}]
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-socks-auth",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "socks", "username": "admin", "password": "secretpassword" }}
            }}]
        }}"#,
        sbox_port
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-socks-auth").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Authenticated SOCKS5 flux-core -> sing-box!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn test_interop_http_connect_flux_to_singbox() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;

    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"username": "admin", "password": "secretpassword"}}]
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-http-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "http", "username": "admin", "password": "secretpassword" }}
            }}]
        }}"#,
        sbox_port
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-http-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"HTTP CONNECT flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn test_interop_shadowsocks_aead_chacha20_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "ss-aead-secret-password-123";

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "chacha20-ietf-poly1305",
                "password": "{}"
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "chacha20-ietf-poly1305"
                }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-ss-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks ChaCha20-Poly1305 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "chacha20-ietf-poly1305"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, password
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-ss-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "chacha20-ietf-poly1305",
                "password": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Shadowsocks ChaCha20 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowsocks_aead_aes256_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "ss-aes256-secret-password-456";

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "aes-256-gcm",
                "password": "{}"
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "aes-256-gcm"
                }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-ss-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks AES-256-GCM flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "aes-256-gcm"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, password
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-ss-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "aes-256-gcm",
                "password": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Shadowsocks AES-256-GCM sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowsocks_aead_aes128_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "ss-aes128-secret-password-789";

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "aes-128-gcm",
                "password": "{}"
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "aes-128-gcm"
                }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-ss-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks AES-128-GCM flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "aes-128-gcm"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, password
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-ss-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "aes-128-gcm",
                "password": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Shadowsocks AES-128-GCM sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowsocks_2022_blake3_aes128_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    // 16-byte key encoded in standard base64
    let raw_key = b"0123456789abcdef";
    let b64_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw_key);

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-2022-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "2022-blake3-aes-128-gcm",
                "password": "{}"
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, b64_key
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-2022-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-aes-128-gcm"
                }}
            }}]
        }}"#,
        sbox_port, b64_key
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-ss-2022-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks 2022 AES-128 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-2022-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-aes-128-gcm"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, b64_key
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-ss-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "2022-blake3-aes-128-gcm",
                "password": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, b64_key
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Shadowsocks 2022 AES-128 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowsocks_2022_blake3_chacha20_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    // 32-byte key encoded in standard base64
    let raw_key = b"0123456789abcdef0123456789abcdef";
    let b64_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw_key);

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-2022-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "2022-blake3-chacha20-poly1305",
                "password": "{}"
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, b64_key
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-2022-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-chacha20-poly1305"
                }}
            }}]
        }}"#,
        sbox_port, b64_key
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-ss-2022-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks 2022 ChaCha20 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-2022-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-chacha20-poly1305"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, b64_key
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-ss-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "2022-blake3-chacha20-poly1305",
                "password": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, b64_key
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Shadowsocks 2022 ChaCha20 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowsocks_2022_blake3_aes256_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    // 32-byte key encoded in standard base64
    let raw_key = b"0123456789abcdef0123456789abcdef";
    let b64_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw_key);

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-2022-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "2022-blake3-aes-256-gcm",
                "password": "{}"
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, b64_key
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-2022-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-aes-256-gcm"
                }}
            }}]
        }}"#,
        sbox_port, b64_key
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-ss-2022-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Shadowsocks 2022 AES-256 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-2022-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "2022-blake3-aes-256-gcm"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, b64_key
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-ss-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "2022-blake3-aes-256-gcm",
                "password": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, b64_key
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Shadowsocks 2022 AES-256 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vless_plain_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";

    // 1. flux-core client -> sing-box server
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}]
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vless-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-vless-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS plain TCP flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, uuid
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-vless-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"VLESS plain TCP sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vless_tls_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "b2c3d4e5-f6a7-8901-2345-6789abcdef01";

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(temp_dir.path());

    // 1. flux-core client -> sing-box server (TLS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-tls-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "tls": {{
                    "enabled": true,
                    "certificate_path": "{}",
                    "key_path": "{}"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port,
        uuid,
        cert_path.display(),
        key_path.display()
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vless-tls-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "tls", "insecure": true, "sni": "example.com" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-vless-tls-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS TLS flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (TLS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-tls-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{
                    "type": "tls",
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port,
        cert_path.display(),
        key_path.display(),
        uuid
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-vless-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "tls": {{
                    "enabled": true,
                    "insecure": true,
                    "server_name": "example.com"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"VLESS TLS sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_trojan_tls_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "trojan-secret-pass-123";

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(temp_dir.path());

    // 1. flux-core client -> sing-box server (Trojan TLS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan",
                "tag": "trojan-tls-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"password": "{}"}}],
                "tls": {{
                    "enabled": true,
                    "certificate_path": "{}",
                    "key_path": "{}"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port,
        password,
        cert_path.display(),
        key_path.display()
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-trojan-tls-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "tls", "insecure": true, "sni": "example.com" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-trojan-tls-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Trojan TLS flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (Trojan TLS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-trojan-tls-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{
                    "type": "tls",
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port,
        cert_path.display(),
        key_path.display(),
        password
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "trojan",
                "tag": "flux-trojan-node",
                "server": "127.0.0.1",
                "server_port": {},
                "password": "{}",
                "tls": {{
                    "enabled": true,
                    "insecure": true,
                    "server_name": "example.com"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Trojan TLS sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_trojan_websocket_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "trojan-ws-secret-pass-456";

    // 1. flux-core client -> sing-box server (Trojan WS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan",
                "tag": "trojan-ws-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"password": "{}"}}],
                "transport": {{
                    "type": "ws",
                    "path": "/trojan-ws"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-trojan-ws-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "websocket", "path": "/trojan-ws", "host": "127.0.0.1" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-trojan-ws-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Trojan WebSocket flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (Trojan WS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-trojan-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "websocket", "path": "/trojan-ws" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, password
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "trojan",
                "tag": "flux-trojan-ws-node",
                "server": "127.0.0.1",
                "server_port": {},
                "password": "{}",
                "transport": {{
                    "type": "ws",
                    "path": "/trojan-ws"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"Trojan WebSocket sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vless_websocket_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "c3d4e5f6-a7b8-9012-3456-789abcdef012";

    // 1. flux-core client -> sing-box server (VLESS WS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-ws-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "transport": {{
                    "type": "ws",
                    "path": "/vless-ws"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid
    );
    let (_sbox, _) = SingboxProcess::start(&sbox_cfg);

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vless-ws-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "websocket", "path": "/vless-ws", "host": "127.0.0.1" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-vless-ws-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS WebSocket flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VLESS WS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "websocket", "path": "/vless-ws" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, uuid
    );
    let flux_server_inst = Instance::new(Config::from_json_str(&flux_server_cfg).unwrap()).unwrap();
    flux_server_inst.start().await.unwrap();

    let sbox_client_in_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-vless-ws-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "transport": {{
                    "type": "ws",
                    "path": "/vless-ws"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let (_sbox_client, _) = SingboxProcess::start(&sbox_client_cfg);

    let mut client_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut client_conn,
        flux_protocol::socks5::CMD_CONNECT,
        &TargetAddress::Ip(echo),
    )
    .await
    .unwrap();

    let payload2 = b"VLESS WebSocket sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}
