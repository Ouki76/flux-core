//! SIGHUP hot-reload end-to-end: the running binary must swap listeners without
//! process restart when the config file changes.

mod common;

use common::get_free_tcp_port;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_config(path: &std::path::Path, port: u16, marker: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    write!(
        f,
        r#"{{
            "log": {{ "level": "warn" }},
            "inbounds": [{{
                "tag": "{}",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        marker, port
    )
    .unwrap();
}

async fn wait_port_closed(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn wait_port_open(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// SOCKS5 handshake helper: asserts the listener speaks SOCKS5.
async fn socks5_roundtrip(port: u16) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "port {} did not answer SOCKS5", port);
}

#[tokio::test]
async fn test_sighup_hot_reload_swaps_listeners() {
    let port_a = get_free_tcp_port().await;
    let port_b = get_free_tcp_port().await;

    let dir = std::env::temp_dir().join(format!("flux-sighup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");
    write_config(&cfg_path, port_a, "in-a");

    let bin = env!("CARGO_BIN_EXE_flux-core");
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn flux-core");
    let mut child = ChildGuard(child);

    assert!(
        wait_port_open(port_a, Duration::from_secs(5)).await,
        "initial listener on port {} did not start",
        port_a
    );
    socks5_roundtrip(port_a).await;

    // Rewrite config to a different port and send SIGHUP.
    write_config(&cfg_path, port_b, "in-b");
    let pid = child.0.id() as i32;
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    let ret = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(ret, 0, "failed to send SIGHUP");

    assert!(
        wait_port_open(port_b, Duration::from_secs(5)).await,
        "new listener on port {} did not start after SIGHUP",
        port_b
    );
    socks5_roundtrip(port_b).await;

    // Old listener must be released (non-exclusive inbounds stop asynchronously).
    assert!(
        wait_port_closed(port_a, Duration::from_secs(5)).await,
        "old listener on port {} still alive after reload",
        port_a
    );

    // Process must still be alive and healthy.
    assert!(child.0.try_wait().unwrap().is_none(), "process died");

    // Second reload back to A must also work (no state leakage).
    write_config(&cfg_path, port_a, "in-a2");
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    assert!(
        wait_port_open(port_a, Duration::from_secs(5)).await,
        "reload back to port {} failed",
        port_a
    );
    socks5_roundtrip(port_a).await;

    let _ = std::fs::remove_dir_all(&dir);
}

/// SIGHUP with a broken config must keep the old instance running.
#[tokio::test]
async fn test_sighup_invalid_config_keeps_old_instance() {
    let port_a = get_free_tcp_port().await;

    let dir = std::env::temp_dir().join(format!("flux-sighup-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");
    write_config(&cfg_path, port_a, "in-a");

    let bin = env!("CARGO_BIN_EXE_flux-core");
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn flux-core");
    let mut child = ChildGuard(child);

    assert!(wait_port_open(port_a, Duration::from_secs(5)).await);

    // Corrupt the config and reload: process must survive, listener stays.
    std::fs::write(&cfg_path, b"{ this is not valid json ").unwrap();
    let pid = child.0.id() as i32;
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    // Give the reload path a generous window (it re-reads and validates the whole
    // config) before asserting survival, so a loaded machine cannot make this
    // look like a crash.
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("process died on invalid reload: {status}");
        }
    }
    socks5_roundtrip(port_a).await; // old listener still serving

    let _ = std::fs::remove_dir_all(&dir);
}

/// The DNS listener must survive a SIGHUP reload.
///
/// The new instance is started before the old one is stopped, so a UDP listener
/// without SO_REUSEADDR/SO_REUSEPORT fails to bind and the whole reload is
/// rejected. This is a regression test for exactly that.
#[tokio::test]
async fn test_sighup_reload_with_dns_inbound() {
    let socks_port = get_free_tcp_port().await;
    let dns_port: u16 = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };

    let dir = std::env::temp_dir().join(format!("flux-sighup-dns-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");

    let write = |marker: &str| {
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        write!(
            f,
            r#"{{
                "log": {{ "level": "info" }},
                "dns": {{
                    "listen": "127.0.0.1:{}",
                    "fakeip": {{ "enabled": true, "inet4_range": "198.18.0.0/15" }}
                }},
                "inbounds": [{{
                    "tag": "{}",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "socks" }}
                }}],
                "outbounds": [{{ "type": "direct", "tag": "direct" }}]
            }}"#,
            dns_port, marker, socks_port
        )
        .unwrap();
    };

    write("dns-in-a");

    let bin = env!("CARGO_BIN_EXE_flux-core");
    // Capture logs so a rejected reload is visible instead of looking like a
    // successful one that simply kept the old instance.
    let log_path = dir.join("flux.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap(), "-f", "json"])
        // The binary logs on stdout; capturing both keeps the assertions real.
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("failed to spawn flux-core");
    let mut child = ChildGuard(child);

    assert!(
        wait_port_open(socks_port, Duration::from_secs(5)).await,
        "initial listener did not start"
    );

    // Reload onto the same DNS port and the same TCP port: if the UDP listener
    // could not be rebound, the reload would fail and the process would keep the
    // old instance (so this assertion would pass by accident). Verify the reload
    // actually happened by watching the log-free side effect: the listener stays
    // up and answers SOCKS5 after the reload.
    write("dns-in-b");
    let pid = child.0.id() as i32;
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    let ret = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(ret, 0, "failed to send SIGHUP");

    // The process must still be alive (a failed reload must not kill it) and the
    // listener must still answer.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut served = false;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", socks_port)).await {
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            if s.read_exact(&mut resp).await.is_ok() && resp == [0x05, 0x00] {
                served = true;
                break;
            }
        }
    }
    assert!(served, "SOCKS listener stopped answering after reload");
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process exited during the reload"
    );

    // The reload must have been accepted: the DNS UDP listener is rebound before
    // the old one is released, which fails without SO_REUSEADDR/SO_REUSEPORT.
    let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
    for bad in [
        "Address already in use",
        "failed to bind",
        "Failed to start new instance",
        "Failed to initialize new instance",
    ] {
        assert!(!logs.contains(bad), "reload rejected ({bad}); log:\n{logs}");
    }
}

/// Two SIGHUPs in a row must leave the process serving the *last* configuration.
///
/// The second signal usually lands while the first reload is still running. The
/// signal loop awaits each reload instead of detaching it, so the next signal is
/// delivered as soon as the reload returns (tokio counts deliveries that arrive
/// while nobody is polling). Deliveries that pile up before the loop polls again
/// are coalesced into one — that is sound for a level-triggered reload, because
/// every reload re-reads the whole file, so one reload per batch still applies
/// the newest content. What is *not* acceptable, and is what this test guards,
/// is a crash, a hang, or a reload that leaves the process on a stale listener.
#[tokio::test]
async fn test_sighup_burst_keeps_the_last_configuration() {
    let port_a = get_free_tcp_port().await;
    let port_b = get_free_tcp_port().await;
    let port_c = get_free_tcp_port().await;

    let dir = std::env::temp_dir().join(format!("flux-sighup-burst-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.json");
    // Log at info here: this test asserts on the reload's own log lines, which
    // the shared `write_config` (level=warn) deliberately suppresses.
    let write_cfg = |port: u16, marker: &str| {
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        write!(
            f,
            r#"{{
                "log": {{ "level": "info" }},
                "inbounds": [{{
                    "tag": "{}",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "socks" }}
                }}],
                "outbounds": [{{ "type": "direct", "tag": "direct" }}]
            }}"#,
            marker, port
        )
        .unwrap();
    };
    write_cfg(port_a, "in-a");

    let bin = env!("CARGO_BIN_EXE_flux-core");
    let log_path = dir.join("flux.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("failed to spawn flux-core");
    let mut child = ChildGuard(child);

    assert!(
        wait_port_open(port_a, Duration::from_secs(5)).await,
        "initial listener did not start"
    );

    // First reload, brought to completion so the burst starts from a known state.
    write_cfg(port_b, "in-b");
    let pid = child.0.id() as i32;
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    assert!(
        wait_port_open(port_b, Duration::from_secs(5)).await,
        "first reload did not take effect"
    );

    // Write C, then send two SIGHUPs back to back: the second arrives either
    // during the reload or immediately after it.
    write_cfg(port_c, "in-c");
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    // SAFETY: `kill` takes a pid and a signal number; the pid is a live child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);

    assert!(
        wait_port_open(port_c, Duration::from_secs(10)).await,
        "the burst did not apply the last configuration"
    );
    socks5_roundtrip(port_c).await;
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process died during the burst"
    );
    assert!(
        wait_port_closed(port_b, Duration::from_secs(10)).await,
        "port {} was never released after the burst",
        port_b
    );

    let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        logs.contains("Configuration hot-reloaded successfully"),
        "no reload was applied; log:\n{logs}"
    );
    for bad in [
        "hot reload FAILED",
        "hot reload REJECTED",
        "panicked",
        "thread 'main'",
    ] {
        assert!(
            !logs.contains(bad),
            "burst broke the process ({bad}); log:\n{logs}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
