//! XHTTP (`splithttp`) against a real Xray node, in `stream-one` mode.
//!
//! The transport is our own: an HTTP/2 request whose body is the upload and whose
//! response is the download. Testing it against itself would prove only
//! self-consistency, so this drives the actual `xray` binary.
//!
//! Four things had to match Xray exactly, and each was found by reading its server
//! rather than by guessing (see `docs/audit-log.md`):
//!
//! 1. a `x_padding` query parameter, whose **encoded** length must fall inside the
//!    server's configured range (100-1000 by default);
//! 2. a path normalised with a trailing slash, because Xray compares by prefix;
//! 3. **no session id in the path** — that absence is what selects `stream-one`;
//! 4. a POST, since `stream-one` is the branch a method-less request takes.

mod common;

use common::get_free_tcp_port;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn xray_bin() -> Option<String> {
    if let Ok(p) = std::env::var("XRAY_BIN") {
        return Some(p);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let candidate = format!("{home}/.local/bin/xray");
    if std::path::Path::new(&candidate).exists() {
        return Some(candidate);
    }
    None
}

struct Xray(Child);

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_xray(bin: &str, config: &str, dir: &std::path::Path) -> Xray {
    let path = dir.join("xray-xhttp.json");
    let mut f = std::fs::File::create(&path).expect("write xray config");
    f.write_all(config.as_bytes()).expect("write config");
    drop(f);
    let child = Command::new(bin)
        .args(["run", "-c", path.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn xray");
    Xray(child)
}

async fn echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn wait_for_tcp(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            // The listener answers before the HTTP handler is ready.
            tokio::time::sleep(Duration::from_millis(200)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the xray XHTTP listener on {addr} never came up");
}

/// **Our client → a real Xray server**, through the configuration path.
///
/// Runs a flux-core instance whose outbound is VLESS over XHTTP, points it at an Xray
/// server with `mode: stream-one`, and relays real payload through a SOCKS5 client.
#[tokio::test]
async fn vless_over_xhttp_relays_through_a_real_xray_server() {
    let Some(bin) = xray_bin() else {
        panic!(
            "the `xray` binary is required by this test but was not found.\n\
             Install Xray 26.x and put it on PATH, or point XRAY_BIN at it."
        );
    };
    let echo_port = echo_server().await;
    let server_port = get_free_tcp_port().await;
    let socks_port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");

    let xray_cfg = format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "port": {server_port}, "listen": "127.0.0.1", "protocol": "vless",
    "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
    "streamSettings": {{
      "network": "splithttp",
      "splithttpSettings": {{"path": "/tunnel", "mode": "stream-one"}}
    }}
  }}],
  "outbounds": [{{"protocol": "freedom", "settings": {{}}}}]
}}"#
    );
    let _xray = spawn_xray(&bin, &xray_cfg, dir.path());
    wait_for_tcp(format!("127.0.0.1:{server_port}").parse().unwrap()).await;

    let flux_cfg = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{"tag": "in", "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port}}}, "protocol": {{"type": "socks"}}}}],
  "outbounds": [{{
    "tag": "node",
    "carrier": {{"type": "tcp", "address": "127.0.0.1:{server_port}"}},
    "framing": {{"type": "xhttp", "path": "/tunnel"}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "route": {{"final": "node"}}
}}"#
    );
    let instance = flux_app::Instance::new(
        flux_app::Config::from_json_str(&flux_cfg).expect("parse flux config"),
    )
    .expect("build flux instance");
    instance.start().await.expect("start flux");

    let mut sock = tokio::net::TcpStream::connect(format!("127.0.0.1:{socks_port}"))
        .await
        .expect("connect to socks");
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut hello = [0u8; 2];
    sock.read_exact(&mut hello).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(20), sock.read_exact(&mut rep))
        .await
        .expect("the SOCKS reply must arrive")
        .unwrap();
    assert_eq!(rep[1], 0x00, "the CONNECT must succeed");

    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
    sock.write_all(&payload).await.expect("write payload");
    sock.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), sock.read_exact(&mut got))
        .await
        .expect("the echo must come back through XHTTP")
        .expect("read echo");
    assert_eq!(got, payload, "XHTTP corrupted the payload");

    instance.stop().await.expect("stop flux");
}
