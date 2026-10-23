//! Interop tests for stream multiplexing (`multiplex.protocol = "smux"`).
//!
//! Both directions are exercised against a real `sing-box` binary:
//!
//! * flux-core client (mux on)  -> sing-box server (`multiplex.enabled`)
//! * sing-box client (mux on)   -> flux-core server (`multiplex.enabled`)
//!
//! The wire format asserted here is the one documented in
//! `flux_protocol::mux`: session preface `[version][protocol]` (+ padding),
//! then smux frames `[ver=1][cmd][len:u16 LE][sid:u32 LE]`, with a
//! `[flags:u16][socksaddr]` request as the first payload of each stream and a
//! single status byte coming back.

mod common;

use common::{get_free_tcp_port, start_tcp_echo_server, start_udp_echo_server};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress, UdpPacket};
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// sing-box harness (same approach as tests/test_singbox_interop.rs)
// ---------------------------------------------------------------------------

/// Caps how many sing-box daemons may run at once (tests run in parallel).
static DAEMONS_RUNNING: AtomicUsize = AtomicUsize::new(0);

fn max_concurrent_daemons() -> usize {
    std::env::var("SINGBOX_TEST_PARALLELISM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(4)
}

thread_local! {
    static SLOTS_HELD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct DaemonSlot {
    gated: bool,
}

impl Drop for DaemonSlot {
    fn drop(&mut self) {
        SLOTS_HELD.with(|h| h.set(h.get().saturating_sub(1)));
        if self.gated {
            DAEMONS_RUNNING.fetch_sub(1, AtomicOrdering::SeqCst);
        }
    }
}

fn acquire_daemon_slot() -> DaemonSlot {
    if SLOTS_HELD.with(|h| {
        let n = h.get();
        h.set(n + 1);
        n > 0
    }) {
        return DaemonSlot { gated: false };
    }
    let limit = max_concurrent_daemons();
    let mut spins = 0u32;
    loop {
        let current = DAEMONS_RUNNING.load(AtomicOrdering::SeqCst);
        if current < limit
            && DAEMONS_RUNNING
                .compare_exchange(
                    current,
                    current + 1,
                    AtomicOrdering::SeqCst,
                    AtomicOrdering::SeqCst,
                )
                .is_ok()
        {
            return DaemonSlot { gated: true };
        }
        spins += 1;
        std::thread::sleep(Duration::from_millis(if spins < 100 { 2 } else { 10 }));
    }
}

fn get_singbox_bin() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SINGBOX_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let local = PathBuf::from(&home).join(".local/bin/sing-box");
    if local.is_file() {
        return Some(local);
    }
    for candidate in ["/usr/bin/sing-box", "/usr/local/bin/sing-box"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

struct SingboxProcess {
    child: Child,
    _dir: TempDir,
    stderr_path: PathBuf,
    _slot: DaemonSlot,
}

impl SingboxProcess {
    fn start(config_json: &str) -> Option<Self> {
        let bin = get_singbox_bin()?;
        let slot = acquire_daemon_slot();
        let dir = TempDir::new().expect("tempdir");
        let cfg_path = dir.path().join("config.json");
        fs::write(&cfg_path, config_json).expect("write sing-box config");
        let stderr_path = dir.path().join("sing-box.stderr.log");
        let inherit = std::env::var("SINGBOX_LOG").is_ok();
        let stderr_cfg = if inherit {
            Stdio::inherit()
        } else {
            Stdio::from(fs::File::create(&stderr_path).expect("stderr log"))
        };
        let child = Command::new(&bin)
            .args(["run", "-c", cfg_path.to_str().unwrap()])
            .stdout(if inherit {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(stderr_cfg)
            .spawn()
            .expect("spawn sing-box");

        let mut process = Self {
            child,
            _dir: dir,
            stderr_path,
            _slot: slot,
        };
        process.wait_until_listening(config_json);
        Some(process)
    }

    /// Blocks until every TCP inbound in the config accepts connections.
    fn wait_until_listening(&mut self, config_json: &str) {
        let mut ports = Vec::new();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(config_json)
            && let Some(inbounds) = json.get("inbounds").and_then(|i| i.as_array())
        {
            for inbound in inbounds {
                let kind = inbound.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if matches!(kind, "hysteria2" | "tuic" | "wireguard") {
                    continue;
                }
                if let Some(port) = inbound.get("listen_port").and_then(|p| p.as_u64()) {
                    ports.push(port as u16);
                }
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        for port in ports {
            loop {
                if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                    break;
                }
                if std::time::Instant::now() > deadline {
                    let log = fs::read_to_string(&self.stderr_path).unwrap_or_default();
                    panic!(
                        "sing-box did not listen on {} in time; stderr:\n{}",
                        port, log
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    /// Captured sing-box stderr (useful when a test panics on a daemon death).
    #[allow(dead_code)]
    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

impl Drop for SingboxProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Skips the test when no sing-box binary is available.
macro_rules! require_singbox {
    () => {
        if get_singbox_bin().is_none() {
            eprintln!("skipping mux interop test: sing-box binary not found (set SINGBOX_BIN)");
            return;
        }
    };
}

/// Starts a flux instance from JSON and waits until `port` accepts connections.
///
/// A failed start is the one failure mode whose OS error carries no context at
/// all (`Io(Os { code: 98, kind: AddrInUse })`, with no port and no inbound), so
/// the panic prints [`common::diagnose_bind_failure`]: which configured listener
/// failed, whether this process's allocator handed that port out (and to which
/// test thread), what the kernel says holds it (`/proc/net/*` state, uid, inode,
/// owning pid, plus `ss` when it is usable), what else is sitting in the test
/// range, and whether that range overlaps the kernel's ephemeral range. See
/// "Port forensics" in `tests/common/mod.rs`.
async fn start_flux(json: &str, port: u16) -> Instance {
    // The port allocator probes and releases; a sibling test in this same binary can
    // take the port in that window. Retrying with the same config is right because
    // the *port* is what raced, not the configuration — and a systematic failure
    // still panics, with the same diagnosis as before.
    let mut attempt = 0;
    let instance = loop {
        attempt += 1;
        let instance = Instance::new(Config::from_json_str(json).expect("parse flux config"))
            .expect("build flux instance");
        match instance.start().await {
            Ok(()) => break instance,
            Err(e) if attempt < 8 && e.to_string().contains("already in use") => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => {
                let report = common::diagnose_bind_failure(json, port, &e.to_string());
                // `{e:?}` keeps the historical `Io(Os { code: 98, kind: AddrInUse, … })`
                // shape, so old and new logs of this failure stay comparable.
                panic!("start flux instance after {attempt} attempt(s): {e:?}\n{report}");
            }
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "flux inbound did not listen on {}",
            port
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    instance
}

/// The failure mode that stayed unattributable for a dozen full-suite runs: a
/// bare `Io(Os { code: 98 })` with no port, no inbound, no holder.
///
/// Deterministic, not a flake hunt: this test *holds* the port the config
/// declares with a plain listener (std sets `SO_REUSEADDR` but not
/// `SO_REUSEPORT`, so flux's `SO_REUSEPORT` bind is refused exactly as it is
/// against a foreign squatter). The failure is therefore guaranteed; what is
/// asserted is that it explains itself — the inbound tag and port, the
/// allocator's involvement, and the kernel's view of the holder.
#[tokio::test]
async fn test_start_flux_failure_is_self_diagnosing() {
    use futures_util::FutureExt;

    let port = get_free_tcp_port().await;
    let cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        port, UUID
    );
    // The allocator just probed this port; if it is already gone, say who took it
    // instead of failing on a bare errno. (That is itself a diagnostic of the
    // allocator's probe-to-bind window, so it gets the same report.)
    // The allocator probes and releases; another thread in this binary can take the
    // port in that window. Retrying closes a race that is not the property under
    // test — a *systematic* failure still panics after the retries, with the same
    // diagnosis.
    let mut attempts = 0;
    let squatter = loop {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => break listener,
            Err(e) => {
                attempts += 1;
                if attempts >= 8 {
                    panic!(
                        "cannot hold the port the allocator just handed out after {attempts} \
                         attempts: {e}\n{}",
                        common::diagnose_bind_failure(&cfg, port, &e.to_string())
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    };

    let payload = std::panic::AssertUnwindSafe(start_flux(&cfg, port))
        .catch_unwind()
        .await
        .err()
        .expect("start_flux must fail while another socket holds its port");
    drop(squatter);

    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<panic payload was not a string>");

    // The OS error is still there, verbatim, so existing expectations hold.
    assert!(
        message.contains("AddrInUse") || message.contains("code: 98"),
        "the original bind error vanished from the panic:\n{message}"
    );
    // Which inbound, on which port.
    assert!(
        message.contains("tag='flux-vless-in'") && message.contains(&format!(":{port}")),
        "the panic does not name the inbound and its port:\n{message}"
    );
    assert!(
        message.contains("the inbound that failed is configured[0] tag='flux-vless-in'"),
        "the panic does not identify the failing listener:\n{message}"
    );
    // Whether the allocator handed the port out in this process (it did).
    assert!(
        message.contains("handed out 1 time(s) by this process's allocator"),
        "the panic does not report the allocator's involvement:\n{message}"
    );
    // What the kernel says holds it: this process, because of the test listener.
    assert!(
        message.contains("OCCUPIED") && message.contains("THIS PROCESS"),
        "the panic does not attribute the holder:\n{message}"
    );
}

fn meta(destination: TargetAddress) -> SessionMeta {
    SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        destination,
        "test",
        NetworkType::Tcp,
    )
}

/// Whether `err` is the session going away *before a single response byte*.
///
/// A mux session is a transport: the peer may close it at any time (daemon
/// restart, RST, a connection killed by the host). A stream that never received
/// any part of the reply was therefore never served, so dialling again -- which
/// necessarily uses a fresh session, because the pool drops the dead one -- is
/// the correct reaction, not a retry of a request that may have run.
///
/// This predicate is deliberately narrow: a protocol rejection, a partially
/// received reply (including a truncated error message), a stream-local reset,
/// or a second teardown all fail the test as before. See
/// `docs/audit-log.md` ("rapid mux teardown race") and the diagnostics pinned by
/// the `mux::tests::*_before_the_status_byte_*` unit tests.
fn is_session_teardown_before_reply(err: &std::io::Error) -> bool {
    let message = err.to_string();
    err.kind() == std::io::ErrorKind::UnexpectedEof
        && message.contains("closed before the server status byte")
        && message.contains("no status byte received")
        && message.contains("session closed:")
}

/// Round-trips a payload over a freshly dialled stream.
///
/// If the session dies before the stream's first response byte (see above), the
/// round trip is attempted once more on a new session and the teardown is
/// printed, so a CI log still records that it happened.
async fn assert_stream_roundtrip(
    outbound: &std::sync::Arc<dyn flux_types::Outbound>,
    destination: TargetAddress,
    payload: &[u8],
) {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match stream_roundtrip_once(outbound, &destination, payload).await {
            Ok(()) => return,
            Err(e) if attempt < 2 && is_session_teardown_before_reply(&e) => {
                eprintln!("mux session was torn down before the reply ({e}); redialling once");
            }
            Err(e) => panic!("read echo: {e:?}"),
        }
    }
}

async fn stream_roundtrip_once(
    outbound: &std::sync::Arc<dyn flux_types::Outbound>,
    destination: &TargetAddress,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let mut stream = outbound
        .dial_stream(&meta(destination.clone()))
        .await
        .expect("dial_stream");
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("timed out waiting for the echo")?;
    assert_eq!(echoed, payload);
    Ok(())
}

/// Drives a SOCKS5 CONNECT through sing-box (or anything else) and echoes.
async fn socks_roundtrip(socks_port: u16, destination: TargetAddress, payload: &[u8]) {
    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .expect("connect socks inbound");
    flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut conn,
        flux_protocol::socks5::CMD_CONNECT,
        &destination,
    )
    .await
    .expect("socks handshake");
    conn.write_all(payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut echoed))
        .await
        .expect("timed out waiting for the echo")
        .expect("read");
    assert_eq!(echoed, payload);
}

const UUID: &str = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";

// ---------------------------------------------------------------------------
// flux-core client with mux  ->  sing-box server with mux
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mux_vless_flux_to_singbox() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };

    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true, "protocol": "smux", "max_streams": 8 }}
            }}]
        }}"#,
        sbox_port, UUID
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();

    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"mux vless tcp").await;

    // Several concurrent streams must be isolated and all ride one session.
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let outbound = outbound.clone();
        tasks.push(tokio::spawn(async move {
            let payload = vec![i; 8 * 1024];
            assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), &payload).await;
        }));
    }
    for task in tasks {
        task.await.expect("concurrent stream");
    }

    // A domain destination exercises the FQDN form of the stream request.
    assert_stream_roundtrip(
        &outbound,
        TargetAddress::domain("localhost", echo.port()),
        b"mux vless domain",
    )
    .await;
}

#[tokio::test]
async fn test_mux_vless_udp_flux_to_singbox() {
    require_singbox!();
    let udp_echo = start_udp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}]
        }}"#,
        sbox_port, UUID
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();

    let mut meta = meta(TargetAddress::Ip(udp_echo));
    meta.network = NetworkType::Udp;
    let endpoint = outbound.dial_packet(&meta).await.expect("dial_packet");
    for i in 0..4u8 {
        let payload = vec![i; 512];
        endpoint
            .send_packet(UdpPacket::new(
                payload.clone().into(),
                TargetAddress::Ip(udp_echo),
                TargetAddress::Ip(udp_echo),
            ))
            .await
            .expect("send datagram");
        let reply = tokio::time::timeout(Duration::from_secs(10), endpoint.recv_packet())
            .await
            .expect("timed out waiting for the udp echo")
            .expect("recv datagram");
        assert_eq!(&reply.payload[..], &payload[..]);
    }
}

#[tokio::test]
async fn test_mux_trojan_flux_to_singbox() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "trojan",
                "tag": "trojan-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"password": "hunter2"}}],
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "trojan", "password": "hunter2" }},
                "multiplex": {{ "enabled": true }}
            }}]
        }}"#,
        sbox_port
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();
    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"mux trojan tcp").await;
}

#[tokio::test]
async fn test_mux_vmess_flux_to_singbox() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vmess",
                "tag": "vmess-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}]
        }}"#,
        sbox_port, UUID
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();
    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"mux vmess tcp").await;
}

#[tokio::test]
async fn test_mux_shadowsocks_flux_to_singbox() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "method": "chacha20-ietf-poly1305",
                "password": "muxpassword",
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "shadowsocks", "password": "muxpassword" }},
                "multiplex": {{ "enabled": true }}
            }}]
        }}"#,
        sbox_port
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();
    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"mux shadowsocks tcp").await;
}

#[tokio::test]
async fn test_mux_padding_flux_to_singbox() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true, "padding": true }}
            }}]
        }}"#,
        sbox_port, UUID
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();
    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"mux padded vless").await;
}

// ---------------------------------------------------------------------------
// sing-box client with mux  ->  flux-core server with mux
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mux_vless_singbox_to_flux() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, UUID
    );
    let flux = start_flux(&flux_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "multiplex": {{ "enabled": true, "protocol": "smux" }}
            }}]
        }}"#,
        socks_port, flux_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };

    socks_roundtrip(
        socks_port,
        TargetAddress::Ip(echo),
        b"mux from sing-box client",
    )
    .await;
    // A second connection reuses the same multiplexed session.
    socks_roundtrip(socks_port, TargetAddress::Ip(echo), b"mux session reuse").await;

    flux.stop().await.unwrap();
}

#[tokio::test]
async fn test_mux_udp_singbox_to_flux() {
    require_singbox!();
    let udp_echo = start_udp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, UUID
    );
    let flux = start_flux(&flux_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "socks",
                "tag": "client-in",
                "listen": "127.0.0.1",
                "listen_port": {}
            }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "multiplex": {{ "enabled": true, "protocol": "smux" }}
            }}]
        }}"#,
        socks_port, flux_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };

    // SOCKS5 UDP associate through sing-box, which multiplexes the datagrams.
    let mut control = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .expect("connect socks");
    let relay = flux_protocol::socks5::Socks5Handshake::client_handshake(
        &mut control,
        flux_protocol::socks5::CMD_UDP_ASSOCIATE,
        &TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
    )
    .await
    .expect("udp associate")
    .expect("relay address");

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"mux udp datagram";
    let packet = UdpPacket::new(
        bytes::Bytes::from_static(payload),
        TargetAddress::Ip(socket.local_addr().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    socket
        .send_to(&flux_protocol::udp::encode_socks5_udp(&packet), relay)
        .await
        .unwrap();

    let mut buf = vec![0u8; 2048];
    let (len, from) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .expect("timed out waiting for the udp echo")
        .unwrap();
    let decoded = flux_protocol::udp::decode_socks5_udp(
        TargetAddress::Ip(from),
        bytes::Bytes::copy_from_slice(&buf[..len]),
    )
    .expect("decode socks udp");
    assert_eq!(&decoded.payload[..], payload);

    flux.stop().await.unwrap();
}

#[tokio::test]
async fn test_mux_trojan_singbox_to_flux() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-trojan-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "trojan", "password": "hunter2" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port
    );
    let flux = start_flux(&flux_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "client-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{
                "type": "trojan",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "password": "hunter2",
                "multiplex": {{ "enabled": true, "protocol": "smux" }}
            }}]
        }}"#,
        socks_port, flux_port
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    socks_roundtrip(
        socks_port,
        TargetAddress::Ip(echo),
        b"mux trojan from sing-box",
    )
    .await;
    flux.stop().await.unwrap();
}

#[tokio::test]
async fn test_mux_vmess_singbox_to_flux() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vmess-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, UUID
    );
    let flux = start_flux(&flux_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "client-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{
                "type": "vmess",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "multiplex": {{ "enabled": true, "protocol": "smux" }}
            }}]
        }}"#,
        socks_port, flux_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    socks_roundtrip(
        socks_port,
        TargetAddress::Ip(echo),
        b"mux vmess from sing-box",
    )
    .await;
    flux.stop().await.unwrap();
}

#[tokio::test]
async fn test_mux_shadowsocks_singbox_to_flux() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-ss-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "shadowsocks", "password": "muxpassword" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port
    );
    let flux = start_flux(&flux_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "client-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{
                "type": "shadowsocks",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "method": "chacha20-ietf-poly1305",
                "password": "muxpassword",
                "multiplex": {{ "enabled": true, "protocol": "smux" }}
            }}]
        }}"#,
        socks_port, flux_port
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    socks_roundtrip(socks_port, TargetAddress::Ip(echo), b"mux ss from sing-box").await;
    flux.stop().await.unwrap();
}

#[tokio::test]
async fn test_mux_padding_singbox_to_flux() {
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    // The inbound *requires* padding when `padding` is set (sing-box semantics).
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true, "padding": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, UUID
    );
    let flux = start_flux(&flux_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "client-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "multiplex": {{ "enabled": true, "protocol": "smux", "padding": true }}
            }}]
        }}"#,
        socks_port, flux_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    socks_roundtrip(
        socks_port,
        TargetAddress::Ip(echo),
        b"mux padded from sing-box",
    )
    .await;
    flux.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// flux-core <-> flux-core (no external binary needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mux_flux_to_flux_many_streams() {
    let echo = start_tcp_echo_server().await;
    let server_port = get_free_tcp_port().await;
    let server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true, "max_streams": 16 }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        server_port, UUID
    );
    let server = start_flux(&server_cfg, server_port).await;

    let client_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true, "max_streams": 16 }}
            }}]
        }}"#,
        server_port, UUID
    );
    let client = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
    let outbound = client.registry.get_outbound("node").unwrap();

    // 24 streams across 2 pooled sessions (max_streams = 16).
    let mut tasks = Vec::new();
    for i in 0..24u16 {
        let outbound = outbound.clone();
        tasks.push(tokio::spawn(async move {
            let payload = vec![(i % 251) as u8; 16 * 1024];
            assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), &payload).await;
        }));
    }
    for task in tasks {
        task.await.expect("concurrent stream failed");
    }

    server.stop().await.unwrap();
}

#[tokio::test]
async fn test_mux_disabled_by_default() {
    // Without the `multiplex` block the wire format must be unchanged: a plain
    // VLESS connection to a mux-enabled server still works.
    let echo = start_tcp_echo_server().await;
    let server_port = get_free_tcp_port().await;
    let server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        server_port, UUID
    );
    let server = start_flux(&server_cfg, server_port).await;

    let client_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "plain",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }}
            }}]
        }}"#,
        server_port, UUID
    );
    let client = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
    let outbound = client.registry.get_outbound("plain").unwrap();
    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"no mux").await;
    server.stop().await.unwrap();
}
// ---------------------------------------------------------------------------
// Performance probe (run explicitly: `cargo test --test test_mux_interop
// -- --ignored --nocapture mux_overhead`)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "performance measurement, not a correctness assertion"]
async fn test_mux_overhead() {
    let echo = start_tcp_echo_server().await;

    async fn measure(mux: bool, echo: std::net::SocketAddr) -> (f64, f64, f64) {
        let server_port = get_free_tcp_port().await;
        let mux_block = if mux {
            r#", "multiplex": { "enabled": true, "max_streams": 64 }"#
        } else {
            ""
        };
        let server_cfg = format!(
            r#"{{
                "inbounds": [{{
                    "tag": "perf-in",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "vless", "uuid": "{}" }}{}
                }}],
                "outbounds": [{{"type": "direct", "tag": "direct"}}]
            }}"#,
            server_port, UUID, mux_block
        );
        let server = start_flux(&server_cfg, server_port).await;

        let client_cfg = format!(
            r#"{{
                "outbounds": [{{
                    "tag": "node",
                    "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                    "protocol": {{ "type": "vless", "uuid": "{}" }}{}
                }}]
            }}"#,
            server_port, UUID, mux_block
        );
        let client = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
        let outbound = client.registry.get_outbound("node").unwrap();

        // --- single stream throughput: 64 x 64 KiB up + echo back ---
        let mut stream = outbound
            .dial_stream(&meta(TargetAddress::Ip(echo)))
            .await
            .unwrap();
        let chunk = vec![0x5Au8; 64 * 1024];
        let rounds = 64;
        let started = std::time::Instant::now();
        let mut echoed = vec![0u8; chunk.len()];
        for _ in 0..rounds {
            stream.write_all(&chunk).await.unwrap();
            stream.read_exact(&mut echoed).await.unwrap();
        }
        let elapsed = started.elapsed().as_secs_f64();
        let total_mb = (rounds * chunk.len() * 2) as f64 / (1024.0 * 1024.0);
        let throughput = total_mb / elapsed;

        // --- latency: 200 sequential 1 byte round trips ---
        let mut latency_total = Duration::from_secs(0);
        let pings = 200;
        for _ in 0..pings {
            let started = std::time::Instant::now();
            stream.write_all(b"x").await.unwrap();
            let mut one = [0u8; 1];
            stream.read_exact(&mut one).await.unwrap();
            latency_total += started.elapsed();
        }
        let latency_us = latency_total.as_secs_f64() * 1e6 / pings as f64;

        // --- 8 concurrent streams, 16 x 32 KiB each ---
        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let outbound = outbound.clone();
            tasks.push(tokio::spawn(async move {
                let mut s = outbound
                    .dial_stream(&meta(TargetAddress::Ip(echo)))
                    .await
                    .unwrap();
                let chunk = vec![0x11u8; 32 * 1024];
                let mut echoed = vec![0u8; chunk.len()];
                for _ in 0..16 {
                    s.write_all(&chunk).await.unwrap();
                    s.read_exact(&mut echoed).await.unwrap();
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let conc_elapsed = started.elapsed().as_secs_f64();
        let conc_mb = (8 * 16 * 32 * 1024 * 2) as f64 / (1024.0 * 1024.0);
        let conc_throughput = conc_mb / conc_elapsed;

        drop(stream);
        drop(client);
        server.stop().await.unwrap();
        (throughput, latency_us, conc_throughput)
    }

    // The machine is shared with parallel builds, so take the best of three
    // rounds per mode (highest throughput / lowest latency).
    let mut off_best = (0.0f64, f64::MAX, 0.0f64);
    let mut on_best = (0.0f64, f64::MAX, 0.0f64);
    for _ in 0..3 {
        let (tp, lat, conc) = measure(false, echo).await;
        off_best = (
            off_best.0.max(tp),
            off_best.1.min(lat),
            off_best.2.max(conc),
        );
        let (tp, lat, conc) = measure(true, echo).await;
        on_best = (on_best.0.max(tp), on_best.1.min(lat), on_best.2.max(conc));
    }
    let (off_tp, off_lat, off_conc) = off_best;
    let (on_tp, on_lat, on_conc) = on_best;
    println!(
        "mux OFF: single-stream {off_tp:.1} MiB/s | 8 streams {off_conc:.1} MiB/s | rtt {off_lat:.1} us"
    );
    println!(
        "mux ON : single-stream {on_tp:.1} MiB/s | 8 streams {on_conc:.1} MiB/s | rtt {on_lat:.1} us"
    );
    println!(
        "overhead: throughput {:.1}% | rtt {:+.1}% (loopback, echo doubles the path)",
        (off_tp - on_tp) / off_tp * 100.0,
        (on_lat - off_lat) / off_lat * 100.0
    );
}

#[tokio::test]
async fn test_mux_over_websocket_transport() {
    // Multiplexing sits above the transport pipeline, so it must compose with
    // any framing/security layer. WebSocket both ways proves that.
    require_singbox!();
    let echo = start_tcp_echo_server().await;
    let sbox_port = get_free_tcp_port().await;
    let sbox_cfg = format!(
        r#"{{
            "inbounds": [{{
                "type": "vless",
                "tag": "vless-ws-in",
                "listen": "127.0.0.1",
                "listen_port": {},
                "users": [{{"uuid": "{}"}}],
                "transport": {{ "type": "ws", "path": "/mux-ws" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        sbox_port, UUID
    );
    let Some(_sbox) = SingboxProcess::start(&sbox_cfg) else {
        return;
    };
    let flux_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "node",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{ "type": "websocket", "path": "/mux-ws", "headers": {{ "Host": "127.0.0.1" }} }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}]
        }}"#,
        sbox_port, UUID
    );
    let flux = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = flux.registry.get_outbound("node").unwrap();
    assert_stream_roundtrip(&outbound, TargetAddress::Ip(echo), b"mux over websocket").await;

    // Reverse: sing-box client over ws with mux -> flux server over ws with mux.
    let flux_port = get_free_tcp_port().await;
    let flux_server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "flux-vless-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{ "type": "websocket", "path": "/mux-ws" }},
                "protocol": {{ "type": "vless", "uuid": "{}" }},
                "multiplex": {{ "enabled": true }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#,
        flux_port, UUID
    );
    let server = start_flux(&flux_server_cfg, flux_port).await;

    let socks_port = get_free_tcp_port().await;
    let sbox_client_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "client-in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{
                "type": "vless",
                "tag": "flux-node",
                "server": "127.0.0.1",
                "server_port": {},
                "uuid": "{}",
                "transport": {{ "type": "ws", "path": "/mux-ws" }},
                "multiplex": {{ "enabled": true, "protocol": "smux" }}
            }}]
        }}"#,
        socks_port, flux_port, UUID
    );
    let Some(_sbox_client) = SingboxProcess::start(&sbox_client_cfg) else {
        return;
    };
    socks_roundtrip(
        socks_port,
        TargetAddress::Ip(echo),
        b"mux over websocket from sing-box",
    )
    .await;
    server.stop().await.unwrap();
}
