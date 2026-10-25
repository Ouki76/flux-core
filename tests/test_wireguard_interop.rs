//! WireGuard against sing-box, in both directions.
//!
//! This protocol had **no interop test at all** for a long time: every test in
//! `test_wireguard_inbound.rs` drives this project's own client against this project's own
//! server, which cannot detect a wire-format deviation because both halves share it. Two
//! cycles of the audit then concluded, wrongly, that the interop was broken — the harness was
//! dialling `127.0.0.1` and sing-box (correctly) will not route a loopback destination
//! through a tunnel. The tests here therefore target a non-loopback address and skip
//! honestly when the machine has none.
//!
//! The peer keys are fixed rather than random so a failure is reproducible; they are test
//! keys and protect nothing.

mod common;

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Test-only keypair for the flux side (base64, 32 bytes). These protect nothing.
const FLUX_PRIVATE: &str = "WHZn47P2gYvxnZREdVOZPI15fgsWjWh8EL4T/bOLIHE=";
const FLUX_PEER_PUB: &str = "bHNDnKVogC44UvRVr++6CBusJ3dlEO0RicIeGAnS1G0=";
/// Test-only keypair for the sing-box side.
const SBOX_PRIVATE: &str = "SORi6jKObYLq3t4+vJXhV0SzvOHCRU2+xrV7L68vz38=";
const SBOX_PEER_PUB: &str = "YGWKfUozSjihgplzX2ayTKnoyPuIQdwb28kN0ofrtRQ=";

fn singbox_bin() -> Option<String> {
    if let Ok(p) = std::env::var("SINGBOX_BIN") {
        return Some(p);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let candidate = format!("{home}/.local/bin/sing-box");
    std::path::Path::new(&candidate)
        .exists()
        .then_some(candidate)
}

fn flux_bin() -> String {
    if let Ok(p) = std::env::var("FLUX_BIN") {
        return p;
    }
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    dir.join("flux-core").to_string_lossy().into_owned()
}

/// A routable address of this machine, or `None` when there is only loopback.
///
/// WireGuard tunnels need one: sing-box refuses to carry a packet whose destination is a
/// loopback address, which is exactly the confusion these tests exist to prevent.
fn lan_ipv4() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // Connecting a UDP socket sends nothing; it only asks the kernel which source address
    // it would use to reach the internet.
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(bin: &str, args: &[&str], dir: &std::path::Path, name: &str) -> Proc {
    let log = dir.join(format!("{name}.log"));
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("clone log");
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"));
    Proc(child)
}

fn write_cfg(dir: &std::path::Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).expect("config file");
    f.write_all(body.as_bytes()).expect("write config");
    path.to_string_lossy().into_owned()
}

async fn wait_listening(addr: SocketAddr) -> bool {
    for _ in 0..150 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Reads `want` bytes through a SOCKS5 CONNECT, returning what arrived.
async fn socks_download(socks: u16, target: SocketAddr, want: usize) -> Vec<u8> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks))
        .await
        .expect("socks connect");
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.unwrap();
    let mut req = vec![5, 1, 0, 1];
    match target.ip() {
        IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => panic!("test uses IPv4"),
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut head = [0u8; 10];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0, "SOCKS refused the request: {:?}", head);
    let mut got = Vec::with_capacity(want);
    let mut buf = vec![0u8; 65536];
    while got.len() < want {
        let n = s.read(&mut buf).await.expect("read through tunnel");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    got
}

/// A one-way source: accepts a connection and writes `total` bytes as fast as it can.
async fn spawn_source(total: usize) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let chunk = vec![0x5au8; 65536];
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let chunk = chunk.clone();
            tokio::spawn(async move {
                let mut sent = 0usize;
                while sent < total {
                    let n = chunk.len().min(total - sent);
                    if sock.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    sent += n;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// sing-box's endpoint accepts this client's handshake and carries its traffic.
#[tokio::test]
async fn our_client_reaches_a_page_through_singbox_wireguard() {
    let Some(bin) = singbox_bin() else {
        eprintln!("skipping: sing-box not found");
        return;
    };
    let Some(lan) = lan_ipv4() else {
        eprintln!("skipping: no non-loopback IPv4 address (sing-box refuses loopback targets)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("flux-wg-a-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let server_port = common::get_free_udp_port_sync();
    let source = spawn_source(4 * 1024 * 1024).await;

    let server = format!(
        r#"{{"log":{{"level":"error"}},"endpoints":[{{"type":"wireguard","tag":"wg","system":false,
        "address":["10.9.0.1/24"],"listen_port":{server_port},"private_key":"{SBOX_PRIVATE}",
        "peers":[{{"public_key":"{FLUX_PEER_PUB}","allowed_ips":["0.0.0.0/0"]}}]}}],
        "outbounds":[{{"type":"direct","tag":"d"}}],"route":{{"final":"d"}}}}"#
    );
    let cfg = write_cfg(&dir, "sbox.json", &server);
    let _sbox = spawn(&bin, &["run", "-c", &cfg], &dir, "sbox");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let socks = common::get_free_tcp_port().await;
    let client = format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"tag":"in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{socks}}},"protocol":{{"type":"socks"}}}}],
        "outbounds":[{{"tag":"wg","carrier":{{"type":"udp","address":"127.0.0.1:{server_port}"}},"protocol":{{"type":"wireguard","private_key":"{FLUX_PRIVATE}","peer_public_key":"{SBOX_PEER_PUB}","local_address":"10.9.0.2"}}}}],"route":{{"final":"wg"}}}}"#
    );
    let ccfg = write_cfg(&dir, "flux.json", &client);
    let _flux = spawn(
        &flux_bin(),
        &["run", "-c", &ccfg, "-f", "json"],
        &dir,
        "flux",
    );
    assert!(
        wait_listening(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks)).await,
        "socks never came up"
    );

    let target = SocketAddr::new(IpAddr::V4(lan), source.port());
    let got = socks_download(socks, target, 256 * 1024).await;
    assert!(
        got.len() >= 256 * 1024,
        "sing-box carried only {} bytes through the tunnel",
        got.len()
    );
    assert!(got.iter().all(|b| *b == 0x5a), "payload was corrupted");
    let _ = std::fs::remove_dir_all(&dir);
}

/// sing-box's client is accepted by this project's server.
#[tokio::test]
async fn singbox_client_reaches_a_source_through_our_wireguard() {
    let Some(bin) = singbox_bin() else {
        eprintln!("skipping: sing-box not found");
        return;
    };
    let Some(lan) = lan_ipv4() else {
        eprintln!("skipping: no non-loopback IPv4 address (sing-box refuses loopback targets)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("flux-wg-b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let server_port = common::get_free_udp_port_sync();
    let source = spawn_source(4 * 1024 * 1024).await;

    let server = format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"tag":"wg-in","type":"wireguard","listen":"127.0.0.1","listen_port":{server_port},
        "private_key":"{FLUX_PRIVATE}","peers":[{{"public_key":"{SBOX_PEER_PUB}","allowed_ips":["0.0.0.0/0"]}}]}}],
        "outbounds":[{{"type":"direct","tag":"direct"}}],"route":{{"final":"direct"}}}}"#
    );
    let cfg = write_cfg(&dir, "flux-srv.json", &server);
    let _flux = spawn(
        &flux_bin(),
        &["run", "-c", &cfg, "-f", "json"],
        &dir,
        "flux-srv",
    );
    tokio::time::sleep(Duration::from_millis(800)).await;

    let socks = common::get_free_tcp_port().await;
    let client = format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":{socks}}}],
        "endpoints":[{{"type":"wireguard","tag":"wg","address":["10.9.1.2/24"],
        "private_key":"{SBOX_PRIVATE}","peers":[{{"address":"127.0.0.1","port":{server_port},"public_key":"{FLUX_PEER_PUB}","allowed_ips":["0.0.0.0/0"]}}]}}],
        "route":{{"final":"wg"}}}}"#
    );
    let ccfg = write_cfg(&dir, "sbox-client.json", &client);
    let _sbox = spawn(&bin, &["run", "-c", &ccfg], &dir, "sbox-client");
    assert!(
        wait_listening(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socks)).await,
        "socks never came up"
    );

    let target = SocketAddr::new(IpAddr::V4(lan), source.port());
    let got = socks_download(socks, target, 256 * 1024).await;
    assert!(
        got.len() >= 256 * 1024,
        "our server carried only {} bytes through the tunnel",
        got.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
