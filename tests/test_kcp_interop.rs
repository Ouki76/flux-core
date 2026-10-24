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
    let out = Command::new("sh")
        .args(["-c", "command -v xray"])
        .output()
        .ok()?;
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
            .args([
                "-c",
                &format!("ss -lun 2>/dev/null | grep -q ':{}'", addr.port()),
            ])
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
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        flux_transport::connect(server_addr, kcp),
    )
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

/// The configuration path: `carrier: {type: "kcp"}` must reach the same place the
/// library test proves, or the transport is unreachable for a user.
///
/// This drives a real SOCKS5 client through a flux-core `Instance` whose outbound
/// carries VLESS over mKCP into a real Xray server.
#[tokio::test]
async fn a_node_configured_with_a_kcp_carrier_relays_through_xray() {
    let Some(bin) = xray_bin() else {
        panic!("the `xray` binary is required by this test but was not found");
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
    "streamSettings": {{ {masks} }}
  }}],
  "outbounds": [{{"protocol": "freedom", "settings": {{}}}}]
}}"#,
        masks = kcp_masks()
    );
    let _xray = spawn_xray(&bin, &xray_cfg, dir.path());
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_udp(server_addr).await;

    let flux_cfg = format!(
        r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {socks_port}}},
    "protocol": {{"type": "socks"}}
  }}],
  "outbounds": [{{
    "tag": "xray-kcp",
    "carrier": {{"type": "kcp", "address": "127.0.0.1:{server_port}", "header": "srtp"}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "route": {{"final": "xray-kcp"}}
}}"#
    );
    let instance =
        flux_app::Instance::new(flux_app::Config::from_json_str(&flux_cfg).expect("config"))
            .expect("instance");
    instance.start().await.expect("start");

    let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let got = tokio::time::timeout(Duration::from_secs(20), async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .ok()?;
        s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.ok()?;
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&echo_port.to_be_bytes());
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
    .expect("the tunnel must answer")
    .expect("socks request must succeed");

    assert_eq!(got, payload, "a kcp-carried node corrupted the payload");
    let _ = instance.stop().await;
}

/// A header name we do not implement must be a configuration error, not a silent
/// fallback to a different camouflage.
#[tokio::test]
async fn an_unknown_kcp_header_is_refused() {
    let cfg = format!(
        r#"{{
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{"type": "tcp", "listen": "127.0.0.1", "listen_port": {}}},
    "protocol": {{"type": "socks"}}
  }}],
  "outbounds": [{{
    "tag": "n", "carrier": {{"type": "kcp", "address": "127.0.0.1:1", "header": "aes-256-gcm"}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}]
}}"#,
        get_free_tcp_port_blocking()
    );
    let parsed = flux_app::Config::from_json_str(&cfg).expect("config parses");
    let err = match flux_app::Instance::new(parsed) {
        Ok(_) => panic!("an unknown kcp header must be refused"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("kcp header"), "{msg}");
    assert!(
        msg.contains("aes-256-gcm"),
        "the error must name the value: {msg}"
    );
}

fn get_free_tcp_port_blocking() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().unwrap().port()
}

/// **A real Xray client → our mKCP server.**
///
/// The direction that used to be missing: every inbound used to bind its own TCP
/// listener, so there was nowhere to hand an already-established stream. `serve_connection`
/// now takes a plain stream, and the mKCP listener calls it — the handshake, the transport
/// layers and dispatch are the same code that serves TCP, which is what makes this test
/// worth having.
#[tokio::test]
async fn a_real_xray_client_reaches_our_mkcp_server() {
    let Some(bin) = xray_bin() else {
        panic!("the `xray` binary is required by this test but was not found");
    };
    let echo_port = echo_server().await;
    let server_port = get_free_tcp_port().await;
    let socks_port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");

    // Our server: VLESS over mKCP, straight to a direct outbound.
    let server_cfg = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{
    "tag": "in",
    "carrier": {{"type": "kcp", "listen": "127.0.0.1", "listen_port": {server_port}}},
    "protocol": {{"type": "vless", "uuid": "{UUID}"}}
  }}],
  "outbounds": [{{"type": "direct", "tag": "direct"}}],
  "route": {{"final": "direct"}}
}}"#
    );
    let instance = flux_app::Instance::new(
        flux_app::Config::from_json_str(&server_cfg).expect("parse our server config"),
    )
    .expect("build our server");
    instance.start().await.expect("start our server");

    let client_cfg = format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{"port": {socks_port}, "listen": "127.0.0.1", "protocol": "socks",
                 "settings": {{"udp": false}}}}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{"vnext": [{{"address": "127.0.0.1", "port": {server_port},
      "users": [{{"id": "{UUID}", "encryption": "none"}}]}}]}},
    "streamSettings": {{ {masks} }}
  }}]
}}"#,
        masks = kcp_masks()
    );
    let _xray = spawn_xray(&bin, &client_cfg, dir.path());
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut sock = tokio::net::TcpStream::connect(format!("127.0.0.1:{socks_port}"))
        .await
        .expect("connect to the xray socks listener");
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut hello = [0u8; 2];
    sock.read_exact(&mut hello).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(30), sock.read_exact(&mut rep))
        .await
        .expect("the SOCKS reply must arrive over mKCP")
        .unwrap();
    assert_eq!(rep[1], 0x00, "the CONNECT must succeed");

    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    sock.write_all(&payload).await.expect("write payload");
    sock.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), sock.read_exact(&mut got))
        .await
        .expect("the echo must come back through mKCP")
        .expect("read echo");
    assert_eq!(got, payload, "mKCP corrupted the payload");

    instance.stop().await.expect("stop our server");
}
