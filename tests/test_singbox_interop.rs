mod common;

use base64::Engine;
use common::{get_free_tcp_port, start_tcp_echo_server, start_udp_echo_server};
use flux_app::{Config, Instance};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_types::{NetworkType, SessionMeta, TargetAddress, UdpPacket};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub struct SingboxProcess {
    child: Child,
    _dir: TempDir,
}

impl SingboxProcess {
    /// Starts a sing-box process, or returns `None` when the binary is unavailable
    /// (interop tests degrade to a graceful skip instead of a hard failure).
    pub fn start(config_json: &str) -> Option<(Self, PathBuf)> {
        let bin = get_singbox_bin()?;
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

        // Give sing-box 300ms to bind ports under parallel test load
        std::thread::sleep(Duration::from_millis(300));

        Some((Self { child, _dir: dir }, cfg_path))
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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

#[tokio::test]
async fn test_interop_vless_httpupgrade_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "d4e5f6a7-b8c9-0123-4567-89abcdef0123";

    // 1. flux-core client -> sing-box server (VLESS HTTPUpgrade)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-httpupgrade-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "transport": {{
                    "type": "httpupgrade",
                    "path": "/vless-upgrade"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vless-upgrade-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "httpupgrade", "path": "/vless-upgrade" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-vless-upgrade-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS HTTPUpgrade flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VLESS HTTPUpgrade)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-upgrade-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "httpupgrade", "path": "/vless-upgrade" }},
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
                "tag": "flux-vless-upgrade-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "transport": {{
                    "type": "httpupgrade",
                    "path": "/vless-upgrade"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"VLESS HTTPUpgrade sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_trojan_httpupgrade_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "trojan-upgrade-secret-pass-789";

    // 1. flux-core client -> sing-box server (Trojan HTTPUpgrade)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan",
                "tag": "trojan-httpupgrade-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"password": "{}"}}],
                "transport": {{
                    "type": "httpupgrade",
                    "path": "/trojan-upgrade"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-trojan-upgrade-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "httpupgrade", "path": "/trojan-upgrade" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-trojan-upgrade-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Trojan HTTPUpgrade flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (Trojan HTTPUpgrade)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-trojan-upgrade-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "httpupgrade", "path": "/trojan-upgrade" }},
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
                "tag": "flux-trojan-upgrade-node",
                "server": "127.0.0.1",
                "server_port": {},
                "password": "{}",
                "transport": {{
                    "type": "httpupgrade",
                    "path": "/trojan-upgrade"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"Trojan HTTPUpgrade sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vless_grpc_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "e5f6a7b8-c9d0-1234-5678-9abcdef01234";

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(temp_dir.path());

    // 1. flux-core client -> sing-box server (VLESS gRPC over TLS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-grpc-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "tls": {{
                    "enabled": true,
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "transport": {{
                    "type": "grpc",
                    "service_name": "vless-grpc-tunnel"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port,
        uuid,
        cert_path.display(),
        key_path.display()
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vless-grpc-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "tls", "insecure": true, "sni": "example.com", "alpn": ["h2"] }},
                "framing": {{ "type": "grpc", "service_name": "vless-grpc-tunnel" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-vless-grpc-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS gRPC flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VLESS gRPC over TLS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-grpc-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{
                    "type": "tls",
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "framing": {{ "type": "grpc", "service_name": "vless-grpc-tunnel" }},
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
                "tag": "flux-vless-grpc-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "tls": {{
                    "enabled": true,
                    "insecure": true,
                    "server_name": "example.com"
                }},
                "transport": {{
                    "type": "grpc",
                    "service_name": "vless-grpc-tunnel"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"VLESS gRPC sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_trojan_grpc_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "trojan-grpc-secret-pass-012";

    // 1. flux-core client -> sing-box server (Trojan gRPC)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan",
                "tag": "trojan-grpc-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"password": "{}"}}],
                "transport": {{
                    "type": "grpc",
                    "service_name": "trojan-grpc-tunnel"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-trojan-grpc-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "grpc", "service_name": "trojan-grpc-tunnel" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-trojan-grpc-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Trojan gRPC flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (Trojan gRPC)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-trojan-grpc-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "grpc", "service_name": "trojan-grpc-tunnel" }},
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
                "tag": "flux-trojan-grpc-node",
                "server": "127.0.0.1",
                "server_port": {},
                "password": "{}",
                "transport": {{
                    "type": "grpc",
                    "service_name": "trojan-grpc-tunnel"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"Trojan gRPC sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vless_h2_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "f6a7b8c9-d0e1-2345-6789-abcdef012345";

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(temp_dir.path());

    // 1. flux-core client -> sing-box server (VLESS H2 over TLS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-h2-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "tls": {{
                    "enabled": true,
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "transport": {{
                    "type": "http",
                    "path": "/vless-h2"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port,
        uuid,
        cert_path.display(),
        key_path.display()
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vless-h2-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "tls", "insecure": true, "sni": "example.com", "alpn": ["h2"] }},
                "framing": {{ "type": "h2", "path": "/vless-h2" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-vless-h2-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VLESS H2 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VLESS H2 over TLS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-h2-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{
                    "type": "tls",
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "framing": {{ "type": "h2", "path": "/vless-h2" }},
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
                "tag": "flux-vless-h2-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "tls": {{
                    "enabled": true,
                    "insecure": true,
                    "server_name": "example.com"
                }},
                "transport": {{
                    "type": "http",
                    "path": "/vless-h2"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"VLESS H2 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_trojan_h2_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "trojan-h2-secret-pass-345";

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(temp_dir.path());

    // 1. flux-core client -> sing-box server (Trojan H2 over TLS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan",
                "tag": "trojan-h2-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"password": "{}"}}],
                "tls": {{
                    "enabled": true,
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "transport": {{
                    "type": "http",
                    "path": "/trojan-h2"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port,
        password,
        cert_path.display(),
        key_path.display()
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-trojan-h2-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "tls", "insecure": true, "sni": "example.com", "alpn": ["h2"] }},
                "framing": {{ "type": "h2", "path": "/trojan-h2" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-trojan-h2-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Trojan H2 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (Trojan H2 over TLS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-trojan-h2-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{
                    "type": "tls",
                    "certificate_path": "{}",
                    "key_path": "{}"
                }},
                "framing": {{ "type": "h2", "path": "/trojan-h2" }},
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
                "tag": "flux-trojan-h2-node",
                "server": "127.0.0.1",
                "server_port": {},
                "password": "{}",
                "tls": {{
                    "enabled": true,
                    "insecure": true,
                    "server_name": "example.com"
                }},
                "transport": {{
                    "type": "http",
                    "path": "/trojan-h2"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, password
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"Trojan H2 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_socks5_udp_both_directions() {
    let udp_echo = start_udp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;

    // 1. flux-core client -> sing-box SOCKS5 server (UDP Associate)
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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let mut tcp_conn = TcpStream::connect(format!("127.0.0.1:{}", sbox_port))
        .await
        .unwrap();
    let relay = flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut tcp_conn,
        flux_protocol::socks5::CMD_UDP_ASSOCIATE,
        &TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"Hello sing-box SOCKS5 UDP relay from flux-core!";
    let pkt = UdpPacket::new(
        bytes::Bytes::from_static(payload),
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
    assert_eq!(&dec.payload[..], payload);

    // 2. sing-box client -> flux-core SOCKS5 server (UDP Associate)
    let flux_server_cfg = format!(
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
                "type": "socks",
                "tag": "flux-socks-node",
                "server": "127.0.0.1",
                "server_port": {}
            }}]
        }}"#,
        sbox_client_in_port, flux_port
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let mut sbox_client_tcp = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    let sbox_relay = flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut sbox_client_tcp,
        flux_protocol::socks5::CMD_UDP_ASSOCIATE,
        &TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let sbox_client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload2 = b"Hello flux-core SOCKS5 UDP relay from sing-box client!";
    let pkt2 = UdpPacket::new(
        bytes::Bytes::from_static(payload2),
        TargetAddress::Ip(sbox_client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    sbox_client_udp
        .send_to(&encode_socks5_udp(&pkt2), sbox_relay)
        .await
        .unwrap();

    let mut buf2 = vec![0u8; 65535];
    let (n2, from2) =
        tokio::time::timeout(Duration::from_secs(3), sbox_client_udp.recv_from(&mut buf2))
            .await
            .unwrap()
            .unwrap();
    let dec2 = decode_socks5_udp(
        TargetAddress::Ip(from2),
        bytes::Bytes::copy_from_slice(&buf2[..n2]),
    )
    .unwrap();
    assert_eq!(&dec2.payload[..], payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowsocks_udp_chacha20_both_directions() {
    let udp_echo = start_udp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let password = "ss-udp-chacha20-password-123";

    // 1. flux-core Shadowsocks client -> sing-box Shadowsocks server (UDP)
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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-ss-udp",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
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
    let outbound = flux_inst.registry.get_outbound("sbox-ss-udp").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(udp_echo),
        "test",
        NetworkType::Udp,
    );
    let endpoint = outbound.dial_packet(&meta).await.unwrap();
    let payload =
        bytes::Bytes::from_static(b"Hello sing-box Shadowsocks UDP relay from flux-core!");
    let packet = UdpPacket::new(
        payload.clone(),
        TargetAddress::Ip("127.0.0.1:0".parse().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    endpoint.send_packet(packet).await.unwrap();
    let reply = endpoint.recv_packet().await.unwrap();
    assert_eq!(reply.payload, payload);

    // 2. sing-box Shadowsocks client -> flux-core Shadowsocks server (UDP)
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
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let mut sbox_client_tcp = TcpStream::connect(format!("127.0.0.1:{}", sbox_client_in_port))
        .await
        .unwrap();
    let sbox_relay = flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut sbox_client_tcp,
        flux_protocol::socks5::CMD_UDP_ASSOCIATE,
        &TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let sbox_client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload2 = b"Hello flux-core Shadowsocks UDP relay from sing-box client!";
    let pkt2 = UdpPacket::new(
        bytes::Bytes::from_static(payload2),
        TargetAddress::Ip(sbox_client_udp.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    sbox_client_udp
        .send_to(&encode_socks5_udp(&pkt2), sbox_relay)
        .await
        .unwrap();

    let mut buf2 = vec![0u8; 65535];
    let (n2, from2) =
        tokio::time::timeout(Duration::from_secs(3), sbox_client_udp.recv_from(&mut buf2))
            .await
            .unwrap()
            .unwrap();
    let dec2 = decode_socks5_udp(
        TargetAddress::Ip(from2),
        bytes::Bytes::copy_from_slice(&buf2[..n2]),
    )
    .unwrap();
    assert_eq!(&dec2.payload[..], payload2);
    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vmess_aead_aes128_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";

    // 1. flux-core client -> sing-box server (VMess AEAD AES-128-GCM)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vmess",
                "tag": "vmess-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}]
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vmess-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vmess", "uuid": "{}", "security": "aes-128-gcm" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-vmess-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VMess AEAD AES-128-GCM flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VMess AEAD AES-128-GCM)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vmess-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }}
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
                "type": "vmess",
                "tag": "flux-vmess-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "security": "aes-128-gcm"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"VMess AEAD AES-128-GCM sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vmess_aead_chacha20_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "b2c3d4e5-f6a7-8901-2345-6789abcdef01";

    // 1. flux-core client -> sing-box server (VMess ChaCha20-Poly1305)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vmess",
                "tag": "vmess-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}]
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vmess-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vmess", "uuid": "{}", "security": "chacha20-poly1305" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-vmess-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VMess ChaCha20 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VMess ChaCha20-Poly1305)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vmess-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }}
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
                "type": "vmess",
                "tag": "flux-vmess-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "security": "chacha20-poly1305"
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"VMess ChaCha20 sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_vmess_websocket_both_directions() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let flux_port = get_free_tcp_port().await;
    let uuid = "c3d4e5f6-a7b8-9012-3456-789abcdef012";

    // 1. flux-core client -> sing-box server (VMess WS)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vmess",
                "tag": "vmess-ws-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "transport": {{
                    "type": "ws",
                    "path": "/vmess-ws"
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-vmess-ws-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "websocket", "path": "/vmess-ws", "host": "127.0.0.1" }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }}
            }}]
        }}"#,
        sbox_port, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("sbox-vmess-ws-node")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"VMess WebSocket flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    // 2. sing-box client -> flux-core server (VMess WS)
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vmess-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "websocket", "path": "/vmess-ws" }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }}
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
                "type": "vmess",
                "tag": "flux-vmess-ws-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "security": "aes-128-gcm",
                "transport": {{
                    "type": "ws",
                    "path": "/vmess-ws"
                }}
            }}]
        }}"#,
        sbox_client_in_port, flux_port, uuid
    );
    let Some((_sbox_client, _)) = SingboxProcess::start(&sbox_client_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

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

    let payload2 = b"VMess WebSocket sing-box -> flux-core verified!";
    client_conn.write_all(payload2).await.unwrap();
    let mut buf2 = vec![0u8; payload2.len()];
    client_conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload2);

    flux_server_inst.stop().await.unwrap();
}

#[tokio::test]
async fn test_interop_shadowtls_v3_flux_to_singbox() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let password = "stls-secret-pass-999";
    let raw_key = b"0123456789abcdef";
    let b64_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw_key);

    // flux-core client -> sing-box server (ShadowTLS v3 + Shadowsocks 2022)
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [
                {{
                    "type": "shadowtls",
                    "tag": "st-in",
                    "listen": "127.0.0.1",
                    "listen_port": {},
                    "version": 3,
                    "users": [{{"password": "{}"}}],
                    "handshake": {{
                        "server": "gateway.icloud.com",
                        "server_port": 443
                    }},
                    "detour": "ss-in"
                }},
                {{
                    "type": "shadowsocks",
                    "tag": "ss-in",
                    "listen": "127.0.0.1",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "{}"
                }}
            ],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, password, b64_key
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-stls-node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "shadowtls", "version": 3, "password": "{}", "sni": "gateway.icloud.com" }},
                "protocol": {{ "type": "shadowsocks", "password": "{}", "method": "2022-blake3-aes-128-gcm" }}
            }}]
        }}"#,
        sbox_port, password, b64_key
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-stls-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"ShadowTLS v3 + Shadowsocks 2022 flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn test_interop_hysteria2_quic_flux_to_singbox() {
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let password = "hy2-secret-password-123";

    let temp_dir = TempDir::new().unwrap();
    let (cert_path, key_path) = generate_self_signed_cert(temp_dir.path());

    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "hysteria2",
                "tag": "hy2-in",
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
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "sbox-hy2-node",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
                "security": {{ "type": "tls", "insecure": true, "sni": "localhost" }},
                "protocol": {{ "type": "hysteria2", "password": "{}", "h3": true }}
            }}]
        }}"#,
        sbox_port, password
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst.registry.get_outbound("sbox-hy2-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let payload = b"Hysteria 2 QUIC flux-core -> sing-box verified!";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

#[tokio::test]
async fn test_interop_wireguard_noise_ik_flux_to_singbox() {
    let sbox_port = get_free_tcp_port().await;

    let sbox_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sbox_pub = x25519_dalek::PublicKey::from(&sbox_secret);

    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = x25519_dalek::PublicKey::from(&client_secret);

    let b64_engine = base64::engine::general_purpose::STANDARD;
    let sbox_priv_b64 = b64_engine.encode(sbox_secret.to_bytes());
    let client_pub_b64 = b64_engine.encode(client_pub.to_bytes());

    let sbox_cfg = format!(
        r#"{{
            "endpoints": [{{
                "type": "wireguard",
                "tag": "wg-ep",
                "address": ["10.0.0.1/32"],
                "private_key": "{}",
                "listen_port": {},
                "peers": [{{
                    "public_key": "{}",
                    "allowed_ips": ["10.0.0.2/32"]
                }}]
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_priv_b64, sbox_port, client_pub_b64
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(format!("127.0.0.1:{}", sbox_port))
        .await
        .unwrap();

    let awg = flux_protocol::wireguard::AwgConfig {
        jc: 0,
        s1: 0,
        s2: 0,
        h1: 1,
        h2: 2,
        h3: 3,
        h4: 4,
        ..Default::default()
    };
    let (init_pkt, state) = flux_protocol::wireguard::WireGuardHandshake::create_initiation(
        &client_secret,
        &sbox_pub,
        9999,
        &awg,
        None,
    );

    sock.send(&init_pkt).await.unwrap();

    let mut resp_buf = vec![0u8; 1024];
    let len = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut resp_buf))
        .await
        .expect("timed out waiting for sing-box WireGuard handshake response")
        .expect("failed to receive handshake response packet");

    assert_eq!(len, 92);
    let mut session =
        flux_protocol::wireguard::WireGuardHandshake::consume_response(state, &resp_buf[..len])
            .expect("flux-core must successfully consume and verify sing-box WireGuard response");

    // Session is established: encrypt an IPv4 ICMP packet and verify sing-box receives it
    let ping_ip_pkt = [
        69, 0, 0, 32, 4, 210, 0, 0, 64, 1, 98, 9, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0, 16, 36, 0, 1, 0,
        1, 116, 101, 115, 116,
    ];
    let data_pkt = session.encrypt_data_packet(&ping_ip_pkt).unwrap();
    assert_eq!(&data_pkt[0..4], &4u32.to_le_bytes()); // Type 4 = Data packet
    sock.send(&data_pkt).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

// ---------------------------------------------------------------------------
// N. REALITY (XTLS-compatible) Interoperability
// ---------------------------------------------------------------------------

fn reality_keypair() -> (String, String) {
    use base64::Engine;
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes()),
    )
}

/// Starts a real TLS 1.3 echo server (usable as a REALITY handshake target/decoy).
async fn start_tls_echo_server() -> SocketAddr {
    let dir = TempDir::new().expect("tempdir");
    let (cert_path, key_path) = generate_self_signed_cert(dir.path());
    let (certs, key) = flux_transport::tls::TlsTransport::load_certs_and_key(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
    )
    .unwrap();
    let acceptor =
        flux_transport::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    std::mem::forget(dir); // keep cert files alive for the test duration
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if tls.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// flux-core REALITY client → sing-box REALITY server.
#[tokio::test]
async fn test_interop_reality_flux_client_to_singbox_server() {
    let echo = start_tcp_echo_server().await;
    let decoy = start_tls_echo_server().await; // REALITY requires a real TLS 1.3 target
    let sbox_port = get_free_tcp_port().await;
    let decoy_port = decoy.port();
    let (priv_b64, pub_b64) = reality_keypair();
    let uuid = uuid::Uuid::new_v4().to_string();

    let sbox_cfg = format!(
        r#"{{
            "log": {{"level": "error"}},
            "inbounds": [{{
                "type": "vless",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "tls": {{
                    "enabled": true,
                    "server_name": "www.microsoft.com",
                    "reality": {{
                        "enabled": true,
                        "handshake": {{"server": "127.0.0.1", "server_port": {}}},
                        "private_key": "{}",
                        "short_id": ["01020304"]
                    }}
                }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, uuid, decoy_port, priv_b64
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    let flux_cfg = format!(
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
        sbox_port, pub_b64, uuid
    );
    let flux_inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux_inst
        .registry
        .get_outbound("vless-reality-out")
        .unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = tokio::time::timeout(Duration::from_secs(10), outbound.dial_stream(&meta))
        .await
        .expect("flux REALITY client handshake with sing-box timed out")
        .expect("flux REALITY client must handshake with sing-box server");

    let payload = b"REALITY interop: flux client -> sing-box server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}

/// sing-box REALITY client → flux-core REALITY server.
#[tokio::test]
async fn test_interop_reality_singbox_client_to_flux_server() {
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let sbox_socks_port = get_free_tcp_port().await;
    let (priv_b64, pub_b64) = reality_keypair();
    let uuid = uuid::Uuid::new_v4().to_string();

    // flux-core REALITY server (fallback = echo server, unused by valid clients)
    let flux_cfg = format!(
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
      fallback: "127.0.0.1:{}"
    protocol:
      type: vless
      uuid: "{}"
outbounds:
  - type: direct
    tag: direct
"#,
        flux_port,
        priv_b64,
        echo.port(),
        uuid
    );
    let flux_inst = Instance::new(Config::from_yaml_str(&flux_cfg).unwrap()).unwrap();
    flux_inst.start().await.unwrap();

    let sbox_cfg = format!(
        r#"{{
            "log": {{"level": "error"}},
            "inbounds": [{{
                "type": "socks",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "out",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "tls": {{
                    "enabled": true,
                    "server_name": "www.microsoft.com",
                    "utls": {{"enabled": true, "fingerprint": "chrome"}},
                    "reality": {{
                        "enabled": true,
                        "public_key": "{}",
                        "short_id": "01020304"
                    }}
                }}
            }}]
        }}"#,
        sbox_socks_port, flux_port, uuid, pub_b64
    );
    let Some((_sbox, _)) = SingboxProcess::start(&sbox_cfg) else {
        eprintln!("skipping interop test: sing-box binary not found (set SINGBOX_BIN)");
        return;
    };

    // Drive traffic through sing-box socks inbound → flux REALITY server → echo.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", sbox_socks_port))
        .await
        .unwrap();
    // SOCKS5 handshake: no-auth
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);
    // CONNECT to echo server
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match echo.ip() {
        std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        _ => panic!("echo server must be IPv4"),
    }
    req.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut resp))
        .await
        .expect("sing-box REALITY client → flux server connect timed out")
        .unwrap();
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], 0x00, "sing-box connect must succeed");

    let payload = b"REALITY interop: sing-box client -> flux server";
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
}
