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
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        child.0.try_wait().unwrap().is_none(),
        "process died on invalid reload"
    );
    socks5_roundtrip(port_a).await; // old listener still serving

    let _ = std::fs::remove_dir_all(&dir);
}
