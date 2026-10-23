//! mKCP against a real Xray node.
//!
//! The transport is our own implementation of Xray's reliable stream over UDP:
//! segment codec, ARQ, and the `header-*` + `mkcp-original` obfuscation. Testing it
//! against itself proves only self-consistency, which is why these tests drive the
//! actual `xray` binary in both directions.
//!
//! Note the config shape: the classic `kcpSettings.header` was **removed** in Xray
//! 26 and is refused at load; masks now live in `finalmask.udp`. Discovering that
//! needed the binary, not the documentation.

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
    which_xray()
}

fn which_xray() -> Option<String> {
    let out = Command::new("sh").args(["-c", "command -v xray"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then_some(path)
}

struct Xray(Child);

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_xray(bin: &str, config: &str, dir: &std::path::Path) -> Xray {
    let path = dir.join("xray.json");
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

/// A TCP echo server that outlives the test body.
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

async fn wait_for_udp(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let out = Command::new("sh")
            .args(["-c", &format!("ss -lun 2>/dev/null | grep -q ':{}'", addr.port())])
            .status();
        if matches!(out, Ok(s) if s.success()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the xray kcp listener on {addr} never came up");
}

fn kcp_masks() -> &'static str {
    r#""network": "kcp", "kcpSettings": {"mtu": 1350, "tti": 20}, "finalmask": {"udp": [{"type": "header-srtp"}, {"type": "mkcp-original"}]}"#
}

/// **Our client → a real Xray server.** The direction that decides whether the
/// transport is interoperable rather than merely self-consistent.
///
/// `freedom` + `dokodemo-door` cannot be used as the pair here: with a kcp
/// transport `freedom` dials the *requested destination* over KCP, not the server,
/// so such a test measures nothing. The pair must be a real proxy inbound and
/// outbound, which is why this speaks VLESS.
#[tokio::test]
async fn vless_over_mkcp_reaches_a_real_xray_server() {
    let Some(bin) = xray_bin() else {
        panic!(
            "the `xray` binary is required by this test but was not found.\n\
             Install Xray 26.x and put it on PATH, or point XRAY_BIN at it."
        );
    };
    let echo_port = echo_server().await;
    let server_port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");

    let cfg = format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "port": {server_port}, "listen": "127.0.0.1", "protocol": "vless",
    "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
    "streamSettings": {{ {masks} }}
  }}],
  "outbounds": [{{"protocol": "freedom", "settings": {{}}}}]
}}"#,
        masks = kcp_masks()
    );
    let _xray = spawn_xray(&bin, &cfg, dir.path());
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_udp(server_addr).await;

    let kcp = flux_transport::KcpConfig {
        obfs: flux_transport::KcpObfs::Srtp,
        ..Default::default()
    };
    let mut stream = tokio::time::timeout(Duration::from_secs(10), flux_transport::connect(server_addr, kcp))
        .await
        .expect("kcp connect must not hang")
        .expect("kcp connect");

    let target: flux_types::TargetAddress = format!("127.0.0.1:{echo_port}").parse().unwrap();
    flux_protocol::vless::VlessProtocol::write_request_header(
        &mut stream,
        &UUID.parse().unwrap(),
        flux_types::NetworkType::Tcp,
        &target,
        None,
    )
    .await
    .expect("vless request header");
    let mut stream = flux_protocol::vless::VlessClientStream::new(stream);

    let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.expect("write");
    stream.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut got))
        .await
        .expect("the echo must come back")
        .expect("read echo");
    assert_eq!(got, payload, "the tunnel corrupted the payload");
}
