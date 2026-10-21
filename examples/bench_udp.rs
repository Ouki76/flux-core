//! UDP relay throughput benchmark (datagrams/second).
//!
//! Measures a pipelined UDP echo through:
//!   1. a direct UDP echo socket (baseline, no proxy),
//!   2. `flux-core` via SOCKS5 UDP ASSOCIATE → direct outbound.
//!
//! The SOCKS5 UDP datagram path exercises the parts of the data plane that TCP
//! cannot: per-datagram buffer pooling, the dispatcher's route cache and UDP
//! endpoint reply pump, and reply-address normalisation.
//!
//! Usage:
//!   cargo run --release --example bench_udp -- [--window N] [--count N] [--rounds N] [--mbps-size N]

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct Args {
    window: usize,
    count: usize,
    rounds: usize,
    payload_size: usize,
    flux_bin: std::path::PathBuf,
}

impl Args {
    fn parse() -> Self {
        let mut a = Self {
            window: 64,
            count: 20_000,
            rounds: 5,
            payload_size: 1200,
            flux_bin: std::path::PathBuf::from("./target/release/flux-core"),
        };
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let val = |i: &mut usize| -> String {
                *i += 1;
                argv.get(*i).cloned().unwrap_or_default()
            };
            match argv[i].as_str() {
                "--window" => a.window = val(&mut i).parse().unwrap_or(a.window),
                "--count" => a.count = val(&mut i).parse().unwrap_or(a.count),
                "--rounds" => a.rounds = val(&mut i).parse().unwrap_or(a.rounds),
                "--payload-size" => a.payload_size = val(&mut i).parse().unwrap_or(a.payload_size),
                "--flux" => a.flux_bin = std::path::PathBuf::from(val(&mut i)),
                other => {
                    eprintln!("unknown argument: {other}");
                    std::process::exit(2);
                }
            }
            i += 1;
        }
        a
    }
}

/// Starts a UDP echo server; the socket is moved into the task, which keeps it
/// alive for the whole benchmark.
async fn start_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

async fn get_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn spawn_flux(bin: &std::path::Path, listen_port: u16) -> Child {
    assert!(
        bin.is_file(),
        "flux-core binary not found: {}",
        bin.display()
    );
    let cfg = format!(
        r#"{{
            "inbounds": [{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {listen_port} }}, "protocol": {{ "type": "socks" }} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    );
    let path = std::env::temp_dir().join("bench_udp_flux.json");
    std::fs::write(&path, cfg).unwrap();
    Command::new(bin)
        .args(["run", "-c", path.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn flux-core")
}

/// Performs the SOCKS5 UDP ASSOCIATE handshake and returns the relay socket
/// address together with the TCP control connection (which must stay open).
async fn socks5_udp_associate(proxy: SocketAddr) -> (SocketAddr, TcpStream) {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 no-auth negotiation failed");
    // UDP ASSOCIATE with an unspecified address (we do not announce a client port).
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 UDP ASSOCIATE was rejected");
    let relay = match reply[3] {
        0x01 => SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
        other => panic!("unexpected SOCKS5 reply address type {other}"),
    };
    (relay, tcp)
}

/// Encapsulates a payload in a SOCKS5 UDP request header.
fn socks5_udp_encapsulate(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, RSV, FRAG
    match target {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(_) => panic!("echo server must be IPv4"),
    }
    out.extend_from_slice(payload);
    out
}

/// Returns UDP round-trips per second.
async fn measure_udp(
    sock: &UdpSocket,
    relay: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
    count: usize,
    window: usize,
) -> f64 {
    // The relay pins the UDP association to the source address of the first
    // datagram, so the caller passes one socket that is reused across rounds.
    let datagram = socks5_udp_encapsulate(target, payload);
    let mut buf = vec![0u8; 65536];

    // Warm-up: also pins the relay's client address.
    let mut got_any = false;
    for _ in 0..window.min(count) {
        sock.send_to(&datagram, relay).await.unwrap();
        match tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
        {
            Ok(Ok(_)) => got_any = true,
            Ok(Err(e)) => eprintln!("warm-up recv error: {e}"),
            Err(_) => eprintln!("warm-up recv timed out (relay {relay})"),
        }
    }
    if !got_any {
        panic!("SOCKS5 UDP relay never answered during warm-up (relay {relay}, target {target})");
    }

    let t0 = Instant::now();
    let mut sent = 0usize;
    let mut received = 0usize;
    while received < count {
        while sent < count && sent - received < window {
            sock.send_to(&datagram, relay).await.unwrap();
            sent += 1;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
        {
            Ok(Ok(_)) => received += 1,
            _ => break, // dropped datagram or timeout ends the measurement
        }
    }
    let elapsed = t0.elapsed().as_secs_f64();
    assert!(
        received > 0,
        "no UDP replies received at all (relay {relay} -> {target})"
    );
    received as f64 / elapsed
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let echo_addr = start_udp_echo().await;

    let proxy_port = get_free_port().await;
    let mut flux = spawn_flux(&args.flux_bin, proxy_port);
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    // Wait for the listener.
    for _ in 0..200 {
        if TcpStream::connect(proxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    let payload = vec![0x5Au8; args.payload_size];
    println!(
        "udp echo: {echo_addr} | payload {} B | window {} | {} datagrams/round × {} rounds",
        args.payload_size, args.window, args.count, args.rounds
    );

    // Direct baseline: plain UDP echo, pipelined with the same window so the
    // comparison isolates the proxy rather than the measurement shape.
    let direct_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    direct_sock.connect(echo_addr).await.unwrap();
    let mut direct_samples = Vec::new();
    for _ in 0..args.rounds {
        let mut buf = vec![0u8; 65536];
        // Warm-up.
        for _ in 0..args.window.min(args.count) {
            direct_sock.send(&payload).await.unwrap();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                direct_sock.recv(&mut buf),
            )
            .await;
        }
        let t0 = Instant::now();
        let mut sent = 0usize;
        let mut done = 0usize;
        while done < args.count {
            while sent < args.count && sent - done < args.window {
                direct_sock.send(&payload).await.unwrap();
                sent += 1;
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                direct_sock.recv(&mut buf),
            )
            .await
            {
                Ok(Ok(_)) => done += 1,
                _ => break,
            }
        }
        direct_samples.push(done as f64 / t0.elapsed().as_secs_f64());
    }

    let (relay, _control) = socks5_udp_associate(proxy_addr).await;
    // One client socket for the whole run: the relay pins the association to it.
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut flux_samples = Vec::new();
    for _ in 0..args.rounds {
        flux_samples.push(
            measure_udp(
                &client_udp,
                relay,
                echo_addr,
                &payload,
                args.count,
                args.window,
            )
            .await,
        );
    }

    let _ = flux.kill();
    let _ = flux.wait();

    let median = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    let d = median(&mut direct_samples);
    let f = median(&mut flux_samples);

    println!("\n{}", "=".repeat(72));
    println!("UDP RELAY — median of {} rounds", args.rounds);
    println!("{}", "=".repeat(72));
    println!("{:<34}{:>18}", "Path", "datagrams/s");
    println!("{}", "-".repeat(72));
    println!("{:<34}{:>18.0}", "Direct UDP echo (baseline)", d);
    println!("{:<34}{:>18.0}", "flux-core (SOCKS5 UDP relay)", f);
    println!("{}", "-".repeat(72));
    println!(
        "flux-core: {:.0} pps, {:.1} Mbit/s payload, {:.1} µs/round-trip",
        f,
        f * args.payload_size as f64 * 8.0 / 1e6,
        1e6 / f
    );
    println!("relay overhead vs direct: {:+.1}%", (f / d - 1.0) * 100.0);
    println!("{}", "=".repeat(72));

    assert!(
        f > 1000.0,
        "UDP relay throughput collapsed to {f:.0} pps — the datagram path is broken"
    );
}
