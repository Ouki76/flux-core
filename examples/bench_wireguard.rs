//! WireGuard (userspace Noise) path benchmark: throughput, latency and cost of
//! the L3 UDP tunnel versus plain TCP.
//!
//! Topology measured:
//!
//! * `direct` — harness → echo server (no proxy).
//! * `flux direct` — SOCKS5 inbound → direct outbound (kernel TCP relay).
//! * `wireguard` — SOCKS5 → WireGuard outbound (Noise IK + smoltcp TCP client)
//!   to a WireGuard inbound (Noise IK responder + smoltcp TCP server) → direct.
//!
//! Path (3) is the interesting one: both ends of the tunnel put every byte
//! through a userspace smoltcp stack, an AEAD (ChaCha20-Poly1305) per IP packet
//! and a UDP `send_to`, so it is the worst case for throughput and the best case
//! for "what does the userspace data path cost".
//!
//! Reported per path:
//!   * throughput (MB/s, median of interleaved rounds, min/max),
//!   * latency: 64-byte request/response round-trip p50/p99 (µs), which exposes
//!     the per-packet cost of the userspace stack + Noise encryption,
//!   * connection setup (TCP connect → first echoed byte) p50/p99,
//!   * CPU seconds per GB for both tunnel processes (client + server),
//!   * peak RSS.
//!
//! Methodology: warm-up, interleaved rounds across all paths, median reported,
//! every received byte byte-compared. Loopback only, single machine.
//!
//! Usage:
//!   cargo run --release --example bench_wireguard -- [options]
//!
//! Options:
//!   --rounds N     interleaved rounds (default 5)
//!   --mb N         megabytes of verified payload per measurement (default 64)
//!   --rtt N        ping-pong samples per latency measurement (default 200)
//!   --flux PATH    flux-core binary (default ./target/release/flux-core)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHUNK: usize = 64 * 1024;

/// Upper bound on a single measured transfer. Generous on purpose: it exists to
/// turn a hung path into a loud failure instead of an apparent freeze.
const TRANSFER_TIMEOUT_SECS: u64 = 120;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    rounds: usize,
    mb: usize,
    rtt_samples: usize,
    flux_bin: PathBuf,
    only: Vec<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            rounds: 5,
            mb: 64,
            rtt_samples: 200,
            flux_bin: PathBuf::from("./target/release/flux-core"),
            only: Vec::new(),
        };
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let take = |i: &mut usize| -> Result<String, String> {
                *i += 1;
                argv.get(*i)
                    .cloned()
                    .ok_or_else(|| format!("missing value for {}", argv[*i - 1]))
            };
            match argv[i].as_str() {
                "--rounds" => args.rounds = take(&mut i)?.parse().map_err(|e| format!("{e}"))?,
                "--mb" => args.mb = take(&mut i)?.parse().map_err(|e| format!("{e}"))?,
                "--rtt" => args.rtt_samples = take(&mut i)?.parse().map_err(|e| format!("{e}"))?,
                "--flux" => args.flux_bin = PathBuf::from(take(&mut i)?),
                "--paths" => {
                    args.only = take(&mut i)?
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
                "--help" | "-h" => {
                    println!("{}", Self::usage());
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }
        if args.rounds == 0 || args.mb == 0 || args.rtt_samples == 0 {
            return Err("--rounds, --mb and --rtt must be >= 1".into());
        }
        Ok(args)
    }

    fn usage() -> &'static str {
        "usage: bench_wireguard [--rounds N] [--mb N] [--rtt N] [--flux PATH]"
    }
}

// ---------------------------------------------------------------------------
// Process accounting
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
struct ProcCost {
    cpu_secs: f64,
    peak_rss_kb: u64,
}

fn read_proc_cost(pid: u32) -> Option<ProcCost> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let peak_rss_kb = status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Some(ProcCost {
        cpu_secs: (utime + stime) as f64 / 100.0,
        peak_rss_kb,
    })
}

/// 1-minute load average, so a run that was disturbed by other work on the
/// machine is self-documenting instead of looking like a proxy regression.
fn load_avg() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

fn median_min_max(samples: &[f64]) -> (f64, f64, f64) {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    let median = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    };
    (median, v[0], v[n - 1])
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

// ---------------------------------------------------------------------------
// Payload + verification
// ---------------------------------------------------------------------------

fn make_pattern() -> Arc<Vec<u8>> {
    let mut v = Vec::with_capacity(CHUNK);
    for i in 0..CHUNK {
        v.push((i as u8) ^ ((i >> 8) as u8) ^ 0x5A);
    }
    Arc::new(v)
}

fn matches_pattern(data: &[u8], mut pos: usize, pat: &[u8]) -> bool {
    let period = pat.len();
    let mut off = 0;
    while off < data.len() {
        let start = pos % period;
        let n = (period - start).min(data.len() - off);
        if data[off..off + n] != pat[start..start + n] {
            return false;
        }
        off += n;
        pos += n;
    }
    true
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

async fn free_ports(n: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(n);
    let mut ports = Vec::with_capacity(n);
    for _ in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.push(l.local_addr().unwrap().port());
        listeners.push(l);
    }
    drop(listeners);
    ports
}

async fn wait_for_listener(addr: SocketAddr, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("{what} did not start listening on {addr}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            // A transient accept() error must not stop the server for the rest
            // of the run: yield and keep accepting.
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => {
                    tokio::task::yield_now().await;
                    continue;
                }
            };
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = socket.into_split();
                let mut buf = vec![0u8; CHUNK];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// SOCKS5 no-auth negotiation + CONNECT. Returns `None` if the proxy refused or
/// the connection died, so a probe can report a failure instead of aborting.
async fn socks5_connect(s: &mut TcpStream, echo: SocketAddr) -> Option<()> {
    if s.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return None;
    }
    let mut resp = [0u8; 2];
    if s.read_exact(&mut resp).await.is_err() {
        return None;
    }
    if resp != [0x05, 0x00] {
        return None;
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match echo {
        SocketAddr::V4(v4) => {
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(_) => panic!("echo server must be IPv4"),
    }
    if s.write_all(&req).await.is_err() {
        return None;
    }
    let mut reply = [0u8; 10];
    if s.read_exact(&mut reply).await.is_err() || reply[1] != 0x00 {
        return None;
    }
    Some(())
}

struct ProxyProc {
    child: Child,
    pid: u32,
}

impl Drop for ProxyProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_proxy(bin: &Path, config: &str, label: &str) -> ProxyProc {
    // Set FLUX_BENCH_LOGS=1 to see the proxy's own logs (handy when a path
    // silently fails to establish).
    let quiet = std::env::var_os("FLUX_BENCH_LOGS").is_none();
    assert!(
        bin.is_file(),
        "proxy binary not found: {} (build it first: cargo build --release -p flux-core)",
        bin.display()
    );
    // Per-process config name: two benchmark runs (or the same one run twice by
    // parallel CI jobs) must not overwrite each other's config file.
    let cfg_path =
        std::env::temp_dir().join(format!("bench_wg_{label}_{}.json", std::process::id()));
    std::fs::write(&cfg_path, config).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap(), "-f", "json"])
        .stdout(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .stderr(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));
    ProxyProc {
        pid: child.id(),
        child,
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Writes the whole payload, then hands the write half back so the caller can
/// keep the connection open while it drains the reply.
///
/// Dropping the write half early would half-close (FIN) the connection; a
/// transport that does not implement half-close correctly would then discard the
/// reply that is still in flight, and the harness would hang waiting for bytes
/// the peer already sent. Measured paths must be given the chance to finish
/// before the FIN is sent, otherwise the benchmark measures a bug, not a cost.
async fn write_all_pattern(
    mut w: tokio::net::tcp::OwnedWriteHalf,
    total: usize,
    pat: Arc<Vec<u8>>,
) -> tokio::net::tcp::OwnedWriteHalf {
    let mut left = total;
    while left > 0 {
        let n = left.min(CHUNK);
        if w.write_all(&pat[..n]).await.is_err() {
            break;
        }
        left -= n;
    }
    w
}

/// Drains exactly `total` bytes, byte-comparing every one of them.
async fn read_and_verify(
    mut r: tokio::net::tcp::OwnedReadHalf,
    total: usize,
    pat: Arc<Vec<u8>>,
    label: &'static str,
) -> (usize, Option<usize>) {
    let mut received = 0usize;
    let mut first_bad: Option<usize> = None;
    let mut buf = vec![0u8; CHUNK];
    while received < total {
        // Never read past `total`: an overshooting read would make the received
        // byte count exceed what was sent and hide a transport fault.
        let want = (total - received).min(CHUNK);
        match r.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if first_bad.is_none() && !matches_pattern(&buf[..n], received, &pat) {
                    eprintln!(
                        "[{label}] payload corruption: first mismatch at stream offset {received}"
                    );
                    first_bad = Some(received);
                }
                received += n;
            }
        }
    }
    (received, first_bad)
}

async fn stream_once(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total: usize,
    pat: Arc<Vec<u8>>,
    label: &'static str,
    ready: tokio::sync::mpsc::Sender<()>,
    mut start: tokio::sync::watch::Receiver<bool>,
) -> (usize, f64, Option<usize>) {
    // A hung proxy must not hang the harness: every setup step is bounded, and
    // a failure panics in *this* task instead of deadlocking the collector.
    let mut s = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_| panic!("[{label}] TCP connect to {addr} timed out"))
        .unwrap_or_else(|e| panic!("[{label}] TCP connect to {addr} failed: {e}"));
    let _ = s.set_nodelay(true);
    if let Some(echo) = target {
        let handshake = tokio::time::timeout(Duration::from_secs(20), socks5_connect(&mut s, echo))
            .await
            .unwrap_or(None);
        if handshake.is_none() {
            panic!("[{label}] SOCKS5 handshake to {addr} failed or timed out");
        }
    }
    let (r, w) = s.into_split();

    // Announce readiness, then wait for the common start signal, so every
    // stream is measured over the same window.
    let _ = ready.send(()).await;
    while !*start.borrow() {
        if start.changed().await.is_err() {
            break;
        }
    }
    let t0 = Instant::now();

    let (w, (received, first_bad)) = tokio::join!(
        write_all_pattern(w, total, pat.clone()),
        read_and_verify(r, total, pat.clone(), label)
    );
    let secs = t0.elapsed().as_secs_f64();
    // The reply is fully drained: only now may the connection be torn down.
    drop(w);
    (received, secs, first_bad)
}

/// One measured transfer: connect, wait for the ready signal, then run.
async fn transfer(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total: usize,
    pat: &Arc<Vec<u8>>,
    label: &'static str,
) -> (f64, usize, Option<usize>) {
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(8);
    let (start_tx, start_rx) = tokio::sync::watch::channel(false);
    let h = tokio::spawn(stream_once(
        addr,
        target,
        total,
        pat.clone(),
        label,
        ready_tx,
        start_rx,
    ));
    ready_rx
        .recv()
        .await
        .unwrap_or_else(|| panic!("[{label}] stream task died before connecting"));
    start_tx.send(true).unwrap();
    // Watchdog: a path that never delivers must fail loudly, not hang the run.
    let (got, secs, bad) = tokio::time::timeout(Duration::from_secs(TRANSFER_TIMEOUT_SECS), h)
        .await
        .unwrap_or_else(|_| {
            panic!("[{label}] transfer of {total} B did not finish in {TRANSFER_TIMEOUT_SECS}s")
        })
        .unwrap_or_else(|e| panic!("[{label}] {e}"));
    assert_eq!(
        got, total,
        "[{label}] stream truncated at {got} of {total} bytes"
    );
    (got as f64 / 1_048_576.0 / secs, got, bad)
}

/// 64-byte request/response round trips over one already-established stream.
/// Returns the sorted RTT samples in microseconds.
async fn rtt_samples(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    n: usize,
    label: &'static str,
) -> (Vec<f64>, usize) {
    let mut out = Vec::with_capacity(n);
    let mut failures = 0usize;
    let mut s = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => return (out, n),
    };
    let _ = s.set_nodelay(true);
    if let Some(echo) = target
        && socks5_connect(&mut s, echo).await.is_none()
    {
        return (out, n);
    }
    let mut buf = [0u8; 64];
    for i in 0..n {
        let send = [i as u8; 64];
        let t0 = Instant::now();
        // A reset mid-sample is a property of the path under test, not a reason
        // to abort the benchmark: count it and keep whatever samples we have.
        if s.write_all(&send).await.is_err() || s.read_exact(&mut buf).await.is_err() {
            failures += 1;
            break;
        }
        assert_eq!(buf, send, "[{label}] echo mismatch during RTT sampling");
        out.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    out.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    (out, failures)
}

/// TCP connect → first echoed byte (includes SOCKS and, for WireGuard, the
/// inner TCP handshake and the Noise handshake when the session is cold).
async fn connect_latency_us(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    n: usize,
    label: &'static str,
) -> (Vec<f64>, usize) {
    let mut out = Vec::with_capacity(n);
    let mut failures = 0usize;
    for _ in 0..n {
        let t0 = Instant::now();
        let Ok(mut s) = TcpStream::connect(addr).await else {
            failures += 1;
            continue;
        };
        let _ = s.set_nodelay(true);
        if let Some(echo) = target
            && socks5_connect(&mut s, echo).await.is_none()
        {
            failures += 1;
            continue;
        }
        let mut buf = [0u8; 64];
        if s.write_all(&[0x5Au8; 64]).await.is_err() || s.read_exact(&mut buf).await.is_err() {
            failures += 1;
            continue;
        }
        assert_eq!(
            buf, [0x5Au8; 64],
            "[{label}] echo payload mismatch on setup probe"
        );
        out.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    out.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    (out, failures)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n{}", Args::usage());
            std::process::exit(2);
        }
    };
    let echo = start_echo_server().await;
    let pat = make_pattern();
    let ports = free_ports(3).await;

    // WireGuard static keypairs (x25519) generated for this run.
    let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let server_priv = hex(server_secret.as_bytes());
    let server_pub = hex(x25519_dalek::PublicKey::from(&server_secret).as_bytes());
    let client_priv = hex(client_secret.as_bytes());
    let client_pub = hex(x25519_dalek::PublicKey::from(&client_secret).as_bytes());

    println!("{}", "=".repeat(100));
    println!("WIREGUARD (userspace Noise + smoltcp) — throughput, latency, cost");
    println!("{}", "=".repeat(100));
    println!(
        "profile:  loopback (127.0.0.1), single machine, {} MiB verified payload, 1 stream",
        args.mb
    );
    println!(
        "machine:  {} logical CPUs, Linux {}",
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(0),
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    println!(
        "rounds:   {} interleaved rounds (all paths per round), median reported",
        args.rounds
    );
    println!(
        "load:     {:.2} (1-minute load average at start; concurrent work on this box inflates every path)",
        load_avg()
    );
    println!("crypto:   WireGuard Noise IK (x25519) + ChaCha20-Poly1305 per IP packet,");
    println!("          inner MTU 1420, userspace TCP stacks on both ends");
    println!("verify:   every received byte byte-compared against the sent pattern");
    println!("{}", "-".repeat(100));

    // ---- path 2: SOCKS → direct ----
    let flux_direct = spawn_proxy(
        &args.flux_bin,
        &format!(
            r#"{{ "inbounds": [{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }}, "protocol": {{ "type": "socks" }} }}], "outbounds": [{{ "type": "direct", "tag": "direct" }}] }}"#,
            ports[0]
        ),
        "direct",
    );

    // ---- path 3: SOCKS → WireGuard outbound ⇄ WireGuard inbound → direct ----
    let wg_server = spawn_proxy(
        &args.flux_bin,
        &format!(
            r#"{{
                "inbounds": [{{ "type": "wireguard", "tag": "wg-in", "listen": "127.0.0.1", "listen_port": {},
                    "private_key": "{server_priv}",
                    "peers": [{{ "public_key": "{client_pub}", "allowed_ips": ["10.66.66.2/32"] }}] }}],
                "outbounds": [{{ "type": "direct", "tag": "direct" }}],
                "route": {{ "final": "direct" }}
            }}"#,
            ports[1]
        ),
        "server",
    );
    let wg_client = spawn_proxy(
        &args.flux_bin,
        &format!(
            r#"{{
                "inbounds": [{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }}, "protocol": {{ "type": "socks" }} }}],
                "outbounds": [{{ "tag": "wg",
                    "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
                    "protocol": {{ "type": "wireguard", "private_key": "{client_priv}",
                        "peer_public_key": "{server_pub}", "local_address": "10.66.66.2",
                        "keepalive_secs": 25 }} }}],
                "route": {{ "final": "wg" }}
            }}"#,
            ports[2], ports[1]
        ),
        "client",
    );

    let direct_addr: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse()?;
    let wg_addr: SocketAddr = format!("127.0.0.1:{}", ports[2]).parse()?;
    wait_for_listener(direct_addr, "flux-core (socks→direct)").await;
    wait_for_listener(wg_addr, "flux-core (socks→wireguard)").await;

    struct Path {
        name: &'static str,
        addr: SocketAddr,
        target: Option<SocketAddr>,
        pids: Vec<u32>,
    }
    let mut paths = vec![
        Path {
            name: "direct",
            addr: echo,
            target: None,
            pids: vec![],
        },
        Path {
            name: "flux direct",
            addr: direct_addr,
            target: Some(echo),
            pids: vec![flux_direct.pid],
        },
        Path {
            name: "wireguard",
            addr: wg_addr,
            target: Some(echo),
            pids: vec![wg_client.pid, wg_server.pid],
        },
    ];

    if !args.only.is_empty() {
        paths.retain(|p| args.only.iter().any(|o| o == p.name));
        assert!(
            !paths.is_empty(),
            "--paths matched no path: {:?}",
            args.only
        );
    }

    let total = args.mb * 1024 * 1024;

    // Warm-up: also performs the initial Noise handshake and brings up the
    // smoltcp stacks on both ends.
    for p in &paths {
        eprintln!("[warmup] {}", p.name);
        let _ = transfer(p.addr, p.target, 4 * 1024 * 1024, &pat, p.name).await;
        let _ = connect_latency_us(p.addr, p.target, 3, p.name).await;
        let _ = rtt_samples(p.addr, p.target, 8, p.name).await;
    }

    struct Acc {
        speed: Vec<f64>,
        cpu: Vec<f64>,
        rtt_p50: Vec<f64>,
        rtt_p99: Vec<f64>,
        setup_ms: Vec<f64>,
        setup_p99: Vec<f64>,
        rss_mib: f64,
        corrupt_rounds: usize,
        first_bad: Option<usize>,
        /// Latency probes that were reset by the path under test.
        probe_failures: usize,
    }
    let mut accs: Vec<Acc> = (0..paths.len())
        .map(|_| Acc {
            speed: Vec::new(),
            cpu: Vec::new(),
            rtt_p50: Vec::new(),
            rtt_p99: Vec::new(),
            setup_ms: Vec::new(),
            setup_p99: Vec::new(),
            rss_mib: 0.0,
            corrupt_rounds: 0,
            first_bad: None,
            probe_failures: 0,
        })
        .collect();

    for round in 1..=args.rounds {
        let mut line = format!("  round {round}:");
        for (idx, p) in paths.iter().enumerate() {
            let cpu_before: f64 = p
                .pids
                .iter()
                .filter_map(|&pid| read_proc_cost(pid))
                .map(|c| c.cpu_secs)
                .sum();
            let (mbs, _, bad) = transfer(p.addr, p.target, total, &pat, p.name).await;
            let cpu_after: f64 = p
                .pids
                .iter()
                .filter_map(|&pid| read_proc_cost(pid))
                .map(|c| c.cpu_secs)
                .sum();
            accs[idx].speed.push(mbs);
            accs[idx].cpu.push(cpu_after - cpu_before);
            if let Some(at) = bad {
                accs[idx].corrupt_rounds += 1;
                accs[idx].first_bad.get_or_insert(at);
            }

            let (rtt, rtt_fail) = rtt_samples(p.addr, p.target, args.rtt_samples, p.name).await;
            if !rtt.is_empty() {
                accs[idx].rtt_p50.push(percentile(&rtt, 50.0));
                accs[idx].rtt_p99.push(percentile(&rtt, 99.0));
            }
            let (lat, lat_fail) = connect_latency_us(p.addr, p.target, 10, p.name).await;
            if !lat.is_empty() {
                accs[idx].setup_ms.push(percentile(&lat, 50.0) / 1e3);
                accs[idx].setup_p99.push(percentile(&lat, 99.0) / 1e3);
            }
            accs[idx].probe_failures += rtt_fail + lat_fail;

            let rss: f64 = p
                .pids
                .iter()
                .filter_map(|&pid| read_proc_cost(pid))
                .map(|c| c.peak_rss_kb as f64)
                .sum::<f64>()
                / 1024.0;
            if rss > 0.0 {
                accs[idx].rss_mib = accs[idx].rss_mib.max(rss);
            }
            line.push_str(&format!("  {:<12} {mbs:8.1}", p.name));
            if !p.pids.is_empty() && accs[idx].corrupt_rounds > 0 {
                line.push_str(" CORRUPT");
            }
        }
        println!("{line}  (MB/s)");
    }

    let gb = (args.rounds * args.mb) as f64 / 1024.0;
    let direct_median = median_min_max(&accs[0].speed).0;

    println!("{}", "-".repeat(100));
    println!(
        "{:<14} {:>10} {:>8} {:>8} {:>10} {:>14} {:>13} {:>9} {:>9}  integrity",
        "target",
        "MB/s",
        "min",
        "max",
        "RTT p50/p99",
        "setup p50/p99",
        "CPU s/GB",
        "RSS MiB",
        "vs direct"
    );
    println!("{}", "-".repeat(100));
    let mut results = Vec::new();
    for (idx, p) in paths.iter().enumerate() {
        let a = &accs[idx];
        let (med, min, max) = median_min_max(&a.speed);
        let (sp50, _, _) = median_min_max(&a.setup_ms);
        let rtt_p50 = median_min_max(&a.rtt_p50).0;
        let rtt_p99 = median_min_max(&a.rtt_p99).0;
        let setup_p99 = a.setup_p99.iter().copied().fold(0.0, f64::max);
        let cpu_per_gb = (a.cpu.iter().sum::<f64>() > 0.0).then(|| a.cpu.iter().sum::<f64>() / gb);
        println!(
            "{:<14} {:>10.1} {:>8.1} {:>8.1} {:>10} {:>14} {:>13} {:>9} {:>9}  {}",
            p.name,
            med,
            min,
            max,
            format!("{:.0}/{:.0} µs", rtt_p50, rtt_p99),
            format!("{sp50:.2}/{setup_p99:.2} ms"),
            cpu_per_gb
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            if a.rss_mib > 0.0 {
                format!("{:.1}", a.rss_mib)
            } else {
                "-".into()
            },
            format!("{:+.1}%", (med / direct_median - 1.0) * 100.0),
            {
                let mut s = if let Some(at) = a.first_bad {
                    format!(
                        "CORRUPT {}/{} rounds, first at offset {at}",
                        a.corrupt_rounds, args.rounds
                    )
                } else {
                    "ok (byte-verified)".to_string()
                };
                if a.probe_failures > 0 && !p.pids.is_empty() {
                    s.push_str(&format!(", {} probe(s) reset", a.probe_failures));
                }
                s
            },
        );
        results.push((
            p.name,
            med,
            min,
            max,
            cpu_per_gb,
            a.rss_mib,
            rtt_p50,
            rtt_p99,
            sp50,
            setup_p99,
            a.first_bad,
        ));
    }
    println!("{}", "-".repeat(100));

    // With `--paths` only a subset of the rows exists; every comparison below is
    // therefore optional instead of assuming all three paths were measured.
    let find = |name: &str| results.iter().find(|r| r.0 == name);
    let d = find("direct");
    let f = find("flux direct");
    let w = find("wireguard");
    println!("\ncomparison:");
    if let Some(f) = f {
        println!(
            "  kernel TCP relay (flux direct): {:.1} MB/s, {:.2} CPU s/GB, {:.0} µs RTT",
            f.1,
            f.4.unwrap_or(0.0),
            f.6
        );
    }
    if let Some(w) = w {
        let rel = |other: Option<&(_, f64, _, _, _, _, _, _, _, _, _)>| match other {
            Some(o) if o.1 > 0.0 => format!(", {:+.1}% vs {}", (w.1 / o.1 - 1.0) * 100.0, o.0),
            _ => String::new(),
        };
        println!(
            "  WireGuard userspace tunnel:     {:.1} MB/s ({:+.1}% vs direct{})",
            w.1,
            d.map(|d| (w.1 / d.1 - 1.0) * 100.0).unwrap_or(0.0),
            rel(f)
        );
        println!(
            "  WireGuard cost:                 {:.2} CPU s/GB tunnel CPU (client+server), {:.1} MiB RSS combined",
            w.4.unwrap_or(0.0),
            w.5
        );
        if let Some(d) = d {
            println!(
                "  WireGuard RTT:                  {:.0} µs p50 / {:.0} µs p99 vs {:.0}/{:.0} µs direct ({:+.0} µs p50)",
                w.6,
                w.7,
                d.6,
                d.7,
                w.6 - d.6
            );
            println!(
                "  WireGuard connect setup:        {:.2} ms p50 vs {:.2} ms direct (inner TCP handshake through smoltcp)",
                w.8, d.8
            );
        }
    }
    println!("{}", "-".repeat(100));

    // Machine-readable lines for scripts/bench_all.sh.
    for r in &results {
        result("wireguard", "1", r.0, "mbs", &format!("{:.1}", r.1));
        result("wireguard", "1", r.0, "mbs_min", &format!("{:.1}", r.2));
        result("wireguard", "1", r.0, "mbs_max", &format!("{:.1}", r.3));
        if let Some(c) = r.4 {
            result("wireguard", "1", r.0, "cpu_s_per_gb", &format!("{c:.2}"));
        }
        if r.5 > 0.0 {
            result("wireguard", "1", r.0, "rss_mib", &format!("{:.1}", r.5));
        }
        result("wireguard", "1", r.0, "rtt_p50_us", &format!("{:.0}", r.6));
        result("wireguard", "1", r.0, "rtt_p99_us", &format!("{:.0}", r.7));
        result(
            "wireguard",
            "1",
            r.0,
            "setup_p50_ms",
            &format!("{:.2}", r.8),
        );
        result(
            "wireguard",
            "1",
            r.0,
            "setup_p99_ms",
            &format!("{:.2}", r.9),
        );
        result(
            "wireguard",
            "1",
            r.0,
            "integrity",
            if r.10.is_some() { "corrupt" } else { "ok" },
        );
    }

    drop((flux_direct, wg_client, wg_server));
    println!("{}", "=".repeat(100));
    Ok(())
}

fn result(profile: &str, level: &str, target: &str, metric: &str, value: &str) {
    println!("@@RESULT|{profile}|{level}|{target}|{metric}|{value}");
}
