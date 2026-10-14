//! Transparent inbound e2e tests (TUN / REDIRECT / TPROXY).
//!
//! These require root (CAP_NET_ADMIN + /dev/net/tun). When run unprivileged
//! they skip gracefully — in CI they run in the `privileged` job with sudo.

mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn is_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

fn have_tun_device() -> bool {
    std::path::Path::new("/dev/net/tun").exists()
}

fn sh(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", cmd])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Full TUN e2e: packets routed into the flux TUN interface must be terminated
/// by the userspace TCP stack and proxied to the original destination.
#[tokio::test]
async fn test_tun_inbound_tcp_proxy_e2e() {
    if !is_root() || !have_tun_device() {
        eprintln!("SKIP: TUN e2e requires root and /dev/net/tun");
        return;
    }
    let tun_name = "fluxtun9";
    let fake_ip = "10.99.66.2"; // pretend target, actually hosted on lo
    let echo = start_tcp_echo_server().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "tun", "tag": "tun-in", "interface_name": "{}" }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        tun_name
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bring the interface up, host the "target" IP on loopback, and force
    // traffic to that IP through the TUN device.
    let setup_ok = sh(&format!(
        "ip link set {t} up && \
         ip addr add {ip}/32 dev {t} && \
         ip addr add {ip}/32 dev lo 2>/dev/null; \
         ip route replace {ip}/32 dev {t}",
        t = tun_name,
        ip = fake_ip
    ));
    if !setup_ok {
        eprintln!("SKIP: failed to configure TUN interface (net admin caps?)");
        let _ = instance.stop().await;
        return;
    }

    let result = async {
        let mut s = TcpStream::connect(format!("{}:{}", fake_ip, echo.port())).await?;
        s.write_all(b"tun proxied payload").await?;
        let mut buf = vec![0u8; 19];
        s.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    }
    .await;

    // Teardown network state before assertions.
    sh(&format!("ip route del {}/32 2>/dev/null; true", fake_ip));

    let buf = result.expect("TCP through TUN failed");
    assert_eq!(&buf, b"tun proxied payload", "echo mismatch through TUN");

    instance.stop().await.unwrap();
}

/// TPROXY smoke: the listener must bind with IP_TRANSPARENT and accept a
/// connection without crashing. Full diverted-traffic e2e requires
/// mangle/ip-rule plumbing that is out of scope for CI.
#[tokio::test]
async fn test_tproxy_inbound_bind_and_accept() {
    if !is_root() {
        eprintln!("SKIP: TPROXY test requires root");
        return;
    }
    let port = get_free_tcp_port().await;
    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "tproxy", "tag": "tp-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        port
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A direct connection to the TPROXY listener is accepted (original
    // destination = the listener itself, so the proxy will attempt to dial
    // itself; we only assert the accept path works and the instance stays up).
    let conn = TcpStream::connect(("127.0.0.1", port)).await;
    assert!(conn.is_ok(), "TPROXY listener did not accept a connection");
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    instance.stop().await.unwrap();
}

/// REDIRECT e2e: iptables REDIRECT rule diverts traffic to the flux listener;
/// SO_ORIGINAL_DST must recover the real target.
#[tokio::test]
async fn test_redirect_inbound_socks_e2e() {
    if !is_root() {
        eprintln!("SKIP: REDIRECT e2e requires root");
        return;
    }
    if !sh("iptables -V") {
        eprintln!("SKIP: iptables not available");
        return;
    }
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    // A sacrificial "target" port: nothing listens there; REDIRECT sends the
    // connection to flux, and flux must recover 127.0.0.1:<echo> as the
    // original destination.
    let fake_port = get_free_tcp_port().await;

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{ "type": "redirect", "tag": "redir-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        flux_port
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Divert loopback TCP to echo.port() into the flux REDIRECT listener.
    let rule = format!(
        "iptables -t nat -{} OUTPUT -p tcp -d 127.0.0.1 --dport {} -j REDIRECT --to-ports {}",
        "A",
        echo.port(),
        flux_port
    );
    if !sh(&rule) {
        eprintln!("SKIP: failed to install iptables REDIRECT rule");
        let _ = instance.stop().await;
        return;
    }

    let result = async {
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", echo.port())).await?;
        s.write_all(b"redirect payload").await?;
        let mut buf = vec![0u8; 16];
        s.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    }
    .await;

    sh(&format!(
        "iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport {} -j REDIRECT --to-ports {}",
        echo.port(),
        flux_port
    ));
    let _ = fake_port;

    let buf = result.expect("TCP through REDIRECT failed");
    assert_eq!(&buf, b"redirect payload");

    instance.stop().await.unwrap();
}
