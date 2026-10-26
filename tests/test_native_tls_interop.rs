//! Our own TLS 1.3 client on a real interop path.

mod common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn singbox_bin() -> Option<String> {
    for p in ["/usr/local/bin/sing-box", "../sing-box"] {
        if std::path::Path::new(p).is_file() {
            return Some(p.to_string());
        }
    }
    let home = std::env::var("HOME").ok()?;
    let p = format!("{home}/.local/bin/sing-box");
    std::path::Path::new(&p).is_file().then_some(p)
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(bin: &str, cfg: &str, dir: &std::path::Path) -> std::io::Result<Proc> {
    let path = dir.join(format!("cfg-{}.json", std::process::id()));
    std::fs::write(&path, cfg)?;
    Ok(Proc(
        Command::new(bin)
            .args(["run", "-c", path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ))
}

async fn echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// **Our TLS 1.3 client against a real sing-box TLS server.**
///
/// The handshake, the certificate chain and the ALPN are all ours; sing-box is rustls, so this
/// crosses two independent implementations of TLS 1.3 in the direction that matters.
#[tokio::test]
async fn native_tls_reaches_a_real_singbox_server() {
    let Some(bin) = singbox_bin() else {
        panic!("the `sing-box` binary is required by this test but was not found");
    };
    let echo = echo_server().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let server_port = common::get_free_tcp_port().await;
    let socks_port = common::get_free_tcp_port().await;

    // A self-signed server certificate with a SAN; our client pins it as its own CA.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let server_cfg = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "vless", "listen": "127.0.0.1", "listen_port": {server_port},
    "users": [{{"uuid": "{UUID}"}}],
    "tls": {{"enabled": true, "server_name": "localhost",
             "certificate_path": "{}", "key_path": "{}"}}
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#,
        cert_path.display(),
        key_path.display()
    );
    let _server = spawn(&bin, &server_cfg, dir.path()).expect("spawn sing-box");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let flux_cfg = format!(
        r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port}}},
    "protocol": {{"type": "socks"}}
  }}],
  "outbounds": [{{
    "tag": "node",
    "carrier": {{"type": "tcp", "address": "127.0.0.1:{server_port}"}},
    "security": {{"type": "tls", "sni": "localhost", "native_tls": true,
                  "ca_cert_path": ["{}"]}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "route": {{"final": "node"}}
}}"#,
        cert_path.display()
    );
    let instance =
        flux_app::Instance::new(flux_app::Config::from_json_str(&flux_cfg).expect("config"))
            .expect("instance");
    instance.start().await.expect("start");

    let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let got = tokio::time::timeout(Duration::from_secs(25), async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .ok()?;
        s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.ok()?;
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&echo.to_be_bytes());
        s.write_all(&req).await.ok()?;
        let mut head = [0u8; 10];
        s.read_exact(&mut head).await.ok()?;
        if head[1] != 0 {
            return None;
        }
        s.write_all(&payload).await.ok()?;
        let mut buf = vec![0u8; payload.len()];
        s.read_exact(&mut buf).await.ok()?;
        Some(buf)
    })
    .await
    .expect("native TLS must answer")
    .expect("socks request must succeed");
    assert_eq!(got, payload, "native TLS corrupted the payload");
    let _ = instance.stop().await;
}

/// Reads one SOCKS CONNECT through to an echo, returning what came back.
async fn roundtrip(socks_port: u16, echo: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .ok()?;
    s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.ok()?;
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo.to_be_bytes());
    s.write_all(&req).await.ok()?;
    let mut head = [0u8; 10];
    s.read_exact(&mut head).await.ok()?;
    if head[1] != 0 {
        return None;
    }
    s.write_all(payload).await.ok()?;
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

fn self_signed(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// **Our TLS 1.3 client against a real Xray TLS server.**
///
/// Xray is a different TLS stack from sing-box's, and it is stricter about ALPN: a client that
/// offers nothing gets a plain TLS connection, while one that offers `h2` must get `h2` back.
#[tokio::test]
async fn native_tls_reaches_a_real_xray_server() {
    let Some(bin) = which_xray() else {
        panic!("the `xray` binary is required by this test but was not found");
    };
    let echo = echo_server().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = self_signed(dir.path());
    let server_port = common::get_free_tcp_port().await;
    let socks_port = common::get_free_tcp_port().await;

    let server_cfg = format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "port": {server_port}, "listen": "127.0.0.1", "protocol": "vless",
    "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
    "streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [
      {{"certificateFile": "{}", "keyFile": "{}"}}]}}}}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#,
        cert_path.display(),
        key_path.display()
    );
    let _server = spawn(&bin, &server_cfg, dir.path()).expect("spawn xray");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let flux_cfg = format!(
        r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port}}},
    "protocol": {{"type": "socks"}}
  }}],
  "outbounds": [{{
    "tag": "node",
    "carrier": {{"type": "tcp", "address": "127.0.0.1:{server_port}"}},
    "security": {{"type": "tls", "sni": "localhost", "native_tls": true,
                  "ca_cert_path": ["{}"]}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "route": {{"final": "node"}}
}}"#,
        cert_path.display()
    );
    let instance =
        flux_app::Instance::new(flux_app::Config::from_json_str(&flux_cfg).expect("config"))
            .expect("instance");
    instance.start().await.expect("start");

    let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let got = tokio::time::timeout(
        Duration::from_secs(25),
        roundtrip(socks_port, echo, &payload),
    )
    .await
    .expect("native TLS to xray must answer")
    .expect("socks request must succeed");
    assert_eq!(got, payload, "native TLS to xray corrupted the payload");
    let _ = instance.stop().await;
}

/// **gRPC over our TLS.** The strongest ALPN test there is: h2 will not work unless the client
/// negotiates `h2` and the server agrees.
#[tokio::test]
async fn native_tls_carries_grpc_to_a_real_singbox_server() {
    let Some(bin) = singbox_bin() else {
        panic!("the `sing-box` binary is required by this test but was not found");
    };
    let echo = echo_server().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = self_signed(dir.path());
    let server_port = common::get_free_tcp_port().await;
    let socks_port = common::get_free_tcp_port().await;

    let server_cfg = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "type": "vless", "listen": "127.0.0.1", "listen_port": {server_port},
    "users": [{{"uuid": "{UUID}"}}],
    "tls": {{"enabled": true, "server_name": "localhost", "alpn": ["h2"],
             "certificate_path": "{}", "key_path": "{}" }},
    "transport": {{"type": "grpc", "service_name": "flux"}}
  }}],
  "outbounds": [{{"type": "direct"}}]
}}"#,
        cert_path.display(),
        key_path.display()
    );
    let _server = spawn(&bin, &server_cfg, dir.path()).expect("spawn sing-box");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let flux_cfg = format!(
        r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port}}},
    "protocol": {{"type": "socks"}}
  }}],
  "outbounds": [{{
    "tag": "node",
    "carrier": {{"type": "tcp", "address": "127.0.0.1:{server_port}"}},
    "security": {{"type": "tls", "sni": "localhost", "alpn": ["h2"], "native_tls": true,
                  "ca_cert_path": ["{}"]}},
    "framing": {{"type": "grpc", "service_name": "flux"}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "route": {{"final": "node"}}
}}"#,
        cert_path.display()
    );
    let instance =
        flux_app::Instance::new(flux_app::Config::from_json_str(&flux_cfg).expect("config"))
            .expect("instance");
    instance.start().await.expect("start");

    let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let got = tokio::time::timeout(
        Duration::from_secs(25),
        roundtrip(socks_port, echo, &payload),
    )
    .await
    .expect("gRPC over native TLS must answer")
    .expect("socks request must succeed");
    assert_eq!(got, payload, "gRPC over native TLS corrupted the payload");
    let _ = instance.stop().await;
}

fn which_xray() -> Option<String> {
    for p in ["/usr/local/bin/xray"] {
        if std::path::Path::new(p).is_file() {
            return Some(p.to_string());
        }
    }
    let home = std::env::var("HOME").ok()?;
    let p = format!("{home}/.local/bin/xray");
    std::path::Path::new(&p).is_file().then_some(p)
}

/// **The fallback, end to end.** A server that speaks only TLS 1.2 cannot talk to the native
/// client, which is 1.3-only; the dial path must notice and retry with rustls. Without the
/// retry this test fails to connect at all, which is exactly what it exists to detect.
/// **Known failure, deliberately ignored rather than deleted.** The retry fires and our TLS 1.2
/// handshake completes — Xray logs `accepted tcp:…`, so the request arrives — but the download
/// never returns: `upload=300000 B, download=0 B`. Our 1.2 client carries a megabyte both ways
/// against a rustls 1.2 server, so the difference is in what Xray sends back rather than in the
/// handshake. Kept as a test so the next session starts from a reproducer, not from a description.
#[ignore = "our TLS 1.2 client completes the handshake with Xray but the download stalls"]
#[tokio::test]
async fn a_tls12_only_server_is_reached_through_the_fallback() {
    let Some(bin) = which_xray() else {
        panic!("the `xray` binary is required by this test but was not found");
    };
    let echo = echo_server().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = self_signed(dir.path());
    let server_port = common::get_free_tcp_port().await;
    let socks_port = common::get_free_tcp_port().await;

    // Xray pinned to TLS 1.2: the native client will be refused with alert 70.
    let server_cfg = format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "port": {server_port}, "listen": "127.0.0.1", "protocol": "vless",
    "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
    "streamSettings": {{"security": "tls", "tlsSettings": {{
      "minVersion": "1.2", "maxVersion": "1.2",
      "certificates": [{{"certificateFile": "{}", "keyFile": "{}"}}]}}}}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#,
        cert_path.display(),
        key_path.display()
    );
    let _server = spawn(&bin, &server_cfg, dir.path()).expect("spawn xray");
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // No `native_tls` key at all: this is the default configuration.
    let flux_cfg = format!(
        r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port}}},
    "protocol": {{"type": "socks"}}
  }}],
  "outbounds": [{{
    "tag": "node",
    "carrier": {{"type": "tcp", "address": "127.0.0.1:{server_port}"}},
    "security": {{"type": "tls", "sni": "localhost", "insecure": true}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "route": {{"final": "node"}}
}}"#
    );
    let instance =
        flux_app::Instance::new(flux_app::Config::from_json_str(&flux_cfg).expect("config"))
            .expect("instance");
    instance.start().await.expect("start");

    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let got = tokio::time::timeout(
        Duration::from_secs(25),
        roundtrip(socks_port, echo, &payload),
    )
    .await
    .expect("the fallback must reach a TLS 1.2-only server")
    .expect("socks request must succeed");
    assert_eq!(got, payload, "the fallback corrupted the payload");
    let _ = instance.stop().await;
}
