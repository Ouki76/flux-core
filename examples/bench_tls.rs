//! TLS-layer cost benchmark: plain TCP vs VLESS vs VLESS-over-TLS vs
//! VLESS-over-REALITY.
//!
//! The project claims TLS (and REALITY) is nearly free. This harness measures
//! what the security layer actually costs by holding everything else constant —
//! same inbound, same outbound, same framing, same payload, same measurement
//! shape — and toggling only the security layer:
//!
//!   1. `direct`        harness → echo server, no proxy at all (baseline),
//!   2. `flux direct`   SOCKS5 inbound → direct outbound (one process),
//!   3. `vless/tcp`     SOCKS5 → VLESS over plain TCP → VLESS inbound → direct,
//!   4. `vless/tls`     the same two-process path with a TLS 1.3 layer,
//!   5. `vless/reality` the same two-process path with the REALITY handshake.
//!
//! (3) exists precisely so the TLS cost can be separated from the cost of the
//! protocol framing and the extra process hop: `vless/tls - vless/tcp` is the
//! TLS layer, `vless/tcp - flux direct` is framing + second hop.
//!
//! Methodology:
//!   * warm-up before every target, then **interleaved** rounds (all five paths
//!     per round) so machine drift cancels; median reported with min/max,
//!   * CPU seconds per GB from `/proc/<pid>/stat` for **both** tunnel processes
//!     (client and server side), reported separately and summed,
//!   * peak RSS from `/proc/<pid>/status`,
//!   * connection setup time (TCP connect → first echoed byte) for a warm
//!     process, which is what a TLS handshake adds to every new connection,
//!   * every received byte is byte-compared against the sent pattern.
//!
//! TLS certificates are self-signed and generated in-process by flux-core for
//! `localhost`; the client uses `insecure: true` because both ends run on this
//! machine. REALITY keys are generated per run with x25519-dalek.
//!
//! Usage:
//!   cargo run --release --example bench_tls -- [options]
//!
//! Options:
//!   --rounds N     interleaved rounds (default 5)
//!   --mb N         megabytes of verified payload per measurement (default 300)
//!   --streams N    concurrent streams per measurement (default 1)
//!   --flux PATH    flux-core binary (default ./target/release/flux-core)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHUNK: usize = 64 * 1024;

/// Upper bound on a single measured transfer, so a hung path fails loudly
/// instead of freezing the run.
const TRANSFER_TIMEOUT_SECS: u64 = 300;
const VLESS_UUID: &str = "6f2a1c94-7b3d-4f2a-9d61-1c0a2b3c4d5e";
const REALITY_SNI: &str = "www.microsoft.com";
const REALITY_SHORT_ID: &str = "0123abcd";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    rounds: usize,
    mb: usize,
    streams: usize,
    flux_bin: PathBuf,
    /// Optional subset of path labels, for isolating one layer while debugging.
    only: Vec<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            rounds: 5,
            mb: 300,
            streams: 1,
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
                "--streams" => args.streams = take(&mut i)?.parse().map_err(|e| format!("{e}"))?,
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
        if args.rounds == 0 || args.mb == 0 || args.streams == 0 {
            return Err("--rounds, --mb and --streams must be >= 1".into());
        }
        Ok(args)
    }

    fn usage() -> &'static str {
        "usage: bench_tls [--rounds N] [--mb N] [--streams N] [--paths a,b] [--flux PATH]"
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

/// Bytes at the start of every `CHUNK` block carry the block's absolute stream
/// offset as a little-endian `u64`; the rest of the block is a deterministic
/// filler. Verifying the counter makes a skip or a duplicate visible as an exact
/// offset delta, not just "the bytes differ"; verifying the filler is a plain
/// `memcmp`, so the check stays cheap at multi-GB/s.
const COUNTER_LEN: usize = 8;

fn make_pattern() -> Arc<Vec<u8>> {
    let mut v = Vec::with_capacity(CHUNK);
    for i in 0..CHUNK {
        v.push(if i < COUNTER_LEN {
            0 // patched per block; the counter is checked separately
        } else {
            (i as u8) ^ ((i >> 8) as u8) ^ 0x5A
        });
    }
    Arc::new(v)
}

fn counter_bytes(block_start: usize) -> [u8; COUNTER_LEN] {
    (block_start as u64).to_le_bytes()
}

/// Verification of one received read at absolute stream offset `pos`.
/// Returns `Err(offset)` for the first byte that does not match.
fn verify_chunk(data: &[u8], mut pos: usize, pat: &[u8]) -> Result<(), usize> {
    let mut off = 0;
    while off < data.len() {
        let in_block = pos % CHUNK;
        if in_block < COUNTER_LEN {
            let n = (COUNTER_LEN - in_block).min(data.len() - off);
            let expect = counter_bytes(pos - in_block);
            if data[off..off + n] != expect[in_block..in_block + n] {
                return Err(pos);
            }
            off += n;
            pos += n;
        } else {
            let n = (CHUNK - in_block).min(data.len() - off);
            if data[off..off + n] != pat[in_block..in_block + n] {
                // Point at the exact byte that differs.
                let bad = data[off..off + n]
                    .iter()
                    .zip(&pat[in_block..in_block + n])
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                return Err(pos + bad);
            }
            off += n;
            pos += n;
        }
    }
    Ok(())
}

/// Writes `len` payload bytes starting at absolute stream offset `pos`,
/// reproducing the counter/filler block layout described above.
async fn write_payload<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    mut pos: usize,
    mut len: usize,
    pat: &[u8],
) -> std::io::Result<()> {
    while len > 0 {
        let in_block = pos % CHUNK;
        if in_block < COUNTER_LEN {
            let n = (COUNTER_LEN - in_block).min(len);
            w.write_all(&counter_bytes(pos - in_block)[in_block..in_block + n])
                .await?;
            pos += n;
            len -= n;
        } else {
            let n = (CHUNK - in_block).min(len);
            w.write_all(&pat[in_block..in_block + n]).await?;
            pos += n;
            len -= n;
        }
    }
    Ok(())
}

/// Reads the block offset a corrupted stream *claims* at the next block
/// boundary, so a skip/duplicate shows up as an exact delta.
fn claimed_block_offset(buf: &[u8]) -> Option<u64> {
    if buf.len() < COUNTER_LEN {
        return None;
    }
    Some(u64::from_le_bytes(buf[..COUNTER_LEN].try_into().ok()?))
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// Reserves `n` loopback ports at once: all listeners are bound simultaneously,
/// so no two ports in the batch can collide.
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

async fn socks5_connect(s: &mut TcpStream, echo: SocketAddr) {
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"\x05\x00", "SOCKS5 method negotiation failed");
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match echo {
        SocketAddr::V4(v4) => {
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(_) => panic!("echo server must be IPv4"),
    }
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT was rejected");
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

fn spawn_proxy(bin: &std::path::Path, config: &str, label: &str) -> ProxyProc {
    assert!(
        bin.is_file(),
        "proxy binary not found: {} (build it first: cargo build --release -p flux-core)",
        bin.display()
    );
    let cfg_path = std::env::temp_dir().join(format!("bench_tls_{label}.json"));
    std::fs::write(&cfg_path, config).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap(), "-f", "json"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

struct Transfer {
    bytes: usize,
    secs: f64,
    /// Time to establish all streams (includes SOCKS + TLS/REALITY handshakes).
    setup_secs: f64,
    /// Per-stream MB/s, ascending; empty for single-stream runs.
    per_stream: Vec<f64>,
    /// First divergence seen on any stream, if the path corrupted payload.
    corrupt: Option<Corrupt>,
}

/// Where and how badly a stream diverged from what was sent.
#[derive(Clone, Copy)]
struct Corrupt {
    at: usize,
    claimed: Option<u64>,
}

/// Writes the whole payload, then hands the write half back.
///
/// Dropping the write half early would half-close (FIN) the connection; a
/// transport that mishandles half-close would then discard the reply still in
/// flight and the harness would hang on bytes the peer already sent. The
/// measured path must be given the chance to finish before the FIN goes out.
async fn write_all_payload(
    mut w: tokio::net::tcp::OwnedWriteHalf,
    total: usize,
    pat: Arc<Vec<u8>>,
) -> tokio::net::tcp::OwnedWriteHalf {
    let mut pos = 0usize;
    while pos < total {
        let n = (CHUNK - pos % CHUNK).min(total - pos);
        if write_payload(&mut w, pos, n, &pat).await.is_err() {
            break;
        }
        pos += n;
    }
    w
}

/// Drains exactly `total` bytes, verifying each block's position counter and
/// every filler byte. The first divergence is recorded (not fatal) so a broken
/// transport still yields a throughput number, annotated as corrupt.
async fn read_and_verify(
    mut r: tokio::net::tcp::OwnedReadHalf,
    total: usize,
    pat: Arc<Vec<u8>>,
    label: &'static str,
) -> (usize, Option<Corrupt>) {
    let mut received = 0usize;
    let mut corrupt: Option<Corrupt> = None;
    let mut buf = vec![0u8; CHUNK];
    while received < total {
        // Never read past `total`: an overshooting read would make the received
        // byte count exceed what was sent and hide a transport fault.
        let want = (total - received).min(CHUNK);
        match r.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if corrupt.is_none()
                    && let Err(at) = verify_chunk(&buf[..n], received, &pat)
                {
                    // Decode the counter of the *next* block boundary inside this
                    // read: with a skipped/duplicated region it names the block
                    // the peer is actually at, i.e. the exact delta.
                    let next_block = at.div_ceil(CHUNK) * CHUNK;
                    let claimed =
                        if next_block >= received && next_block + COUNTER_LEN <= received + n {
                            claimed_block_offset(&buf[next_block - received..])
                        } else {
                            None
                        };
                    eprintln!(
                        "[{label}] payload corruption: first mismatch at stream offset {at} (block {})",
                        at / CHUNK
                    );
                    corrupt = Some(Corrupt { at, claimed });
                }
                received += n;
            }
        }
    }
    (received, corrupt)
}

async fn stream_once(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total: usize,
    pat: Arc<Vec<u8>>,
    label: &'static str,
    ready: tokio::sync::mpsc::Sender<()>,
    mut start: tokio::sync::watch::Receiver<bool>,
) -> (usize, f64, Option<Corrupt>) {
    // A hung proxy must not hang the harness: every setup step is bounded.
    let mut s = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_| panic!("[{label}] TCP connect to {addr} timed out"))
        .unwrap_or_else(|e| panic!("[{label}] TCP connect to {addr} failed: {e}"));
    let _ = s.set_nodelay(true);
    if let Some(echo) = target {
        tokio::time::timeout(Duration::from_secs(20), socks5_connect(&mut s, echo))
            .await
            .unwrap_or_else(|_| panic!("[{label}] SOCKS5 handshake to {addr} timed out"));
    }
    let (r, w) = s.into_split();

    let _ = ready.send(()).await;
    while !*start.borrow() {
        if start.changed().await.is_err() {
            break;
        }
    }
    let t0 = Instant::now();

    let (w, (received, corrupt)) = tokio::join!(
        write_all_payload(w, total, pat.clone()),
        read_and_verify(r, total, pat.clone(), label)
    );
    let secs = t0.elapsed().as_secs_f64();
    // Fully drained: only now may the connection be torn down.
    drop(w);
    (received, secs, corrupt)
}

async fn transfer(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total: usize,
    streams: usize,
    pat: &Arc<Vec<u8>>,
    label: &'static str,
) -> Transfer {
    let per = ((total / streams) / CHUNK) * CHUNK;
    assert!(per >= CHUNK, "payload per stream is smaller than one chunk");
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(streams.max(8));
    let (start_tx, start_rx) = tokio::sync::watch::channel(false);
    let t_spawn = Instant::now();
    let mut handles = Vec::with_capacity(streams);
    for _ in 0..streams {
        handles.push(tokio::spawn(stream_once(
            addr,
            target,
            per,
            pat.clone(),
            label,
            ready_tx.clone(),
            start_rx.clone(),
        )));
    }
    drop(ready_tx);
    for _ in 0..streams {
        ready_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("[{label}] a stream task died before connecting"));
    }
    let setup_secs = t_spawn.elapsed().as_secs_f64();
    start_tx.send(true).unwrap();
    let t0 = Instant::now();

    let mut bytes = 0usize;
    let mut per_stream = Vec::with_capacity(streams);
    let mut corrupt: Option<Corrupt> = None;
    for h in handles {
        let (got, secs, bad) = tokio::time::timeout(Duration::from_secs(TRANSFER_TIMEOUT_SECS), h)
            .await
            .unwrap_or_else(|_| {
                panic!("[{label}] transfer of {per} B did not finish in {TRANSFER_TIMEOUT_SECS}s")
            })
            .unwrap_or_else(|e| panic!("[{label}] {e}"));
        // A short stream is a hard error: the proxy dropped data outright.
        assert_eq!(
            got, per,
            "[{label}] stream truncated at {got} of {per} bytes"
        );
        bytes += got;
        per_stream.push(got as f64 / 1_048_576.0 / secs);
        corrupt = corrupt.or(bad);
    }
    let secs = t0.elapsed().as_secs_f64();
    per_stream.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Transfer {
        bytes,
        secs,
        setup_secs,
        per_stream,
        corrupt,
    }
}

/// TCP connect → first echoed byte, in microseconds. Includes the SOCKS
/// negotiation and (for tunnelled paths) the TLS/REALITY handshake, which is
/// exactly the per-connection cost a security layer adds.
async fn connect_latency_us(addr: SocketAddr, target: Option<SocketAddr>, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let mut s = TcpStream::connect(addr).await.unwrap();
        let _ = s.set_nodelay(true);
        if let Some(echo) = target {
            socks5_connect(&mut s, echo).await;
        }
        s.write_all(&[0xA5u8; 64]).await.unwrap();
        let mut buf = [0u8; 64];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0xA5u8; 64], "echo payload mismatch on setup probe");
        out.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    out.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    out
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn socks_inbound(port: u16) -> String {
    format!(
        r#"{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {port} }}, "protocol": {{ "type": "socks" }} }}"#
    )
}

/// Node (server) side: VLESS inbound with an optional security layer, direct
/// outbound.
fn node_config(port: u16, security: Option<&str>) -> String {
    let sec_inner = security
        .map(|s| format!(r#""security": {s}, "#))
        .unwrap_or_default();
    format!(
        r#"{{
            "inbounds": [{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {port} }}, {sec_inner} "protocol": {{ "type": "vless", "uuid": "{VLESS_UUID}" }} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}],
            "route": {{ "final": "direct" }}
        }}"#
    )
}

/// Edge (client) side: SOCKS inbound, one VLESS outbound to the node with an
/// optional client security layer.
fn edge_config(port: u16, node_port: u16, security: Option<&str>) -> String {
    let sec = security
        .map(|s| format!(r#""security": {s}, "#))
        .unwrap_or_default();
    format!(
        r#"{{
            "inbounds": [{}],
            "outbounds": [{{ "tag": "node", "carrier": {{ "type": "tcp", "address": "127.0.0.1:{node_port}" }}, {sec} "protocol": {{ "type": "vless", "uuid": "{VLESS_UUID}" }} }}],
            "route": {{ "final": "node" }}
        }}"#,
        socks_inbound(port)
    )
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

struct PathRow {
    name: &'static str,
    speed: (f64, f64, f64),
    /// CPU seconds per GB summed over every process on the path.
    cpu_total_per_gb: Option<f64>,
    /// CPU seconds per GB of the first process (the client/edge side).
    cpu_client_per_gb: Option<f64>,
    rss_mib: Option<f64>,
    setup_ms: (f64, f64),
    corrupt_rounds: usize,
    first_corrupt: Option<Corrupt>,
}

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

    // Ports: direct-flux socks, plain node, plain edge, tls node, tls edge,
    // reality node, reality edge.
    let ports = free_ports(7).await;

    // REALITY keypair (x25519), generated for this run.
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let reality_priv = hex(secret.as_bytes());
    let reality_pub = hex(x25519_dalek::PublicKey::from(&secret).as_bytes());

    println!("{}", "=".repeat(104));
    println!("TLS LAYER COST — plain TCP vs VLESS vs VLESS+TLS vs VLESS+REALITY");
    println!("{}", "=".repeat(104));
    println!(
        "profile:  loopback (127.0.0.1), single machine, {} MiB verified payload, {} stream(s)",
        args.mb, args.streams
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
        "rounds:   {} interleaved rounds (all five paths per round), median reported, min/max shown",
        args.rounds
    );
    println!(
        "load:     {:.2} (1-minute load average at start; concurrent work on this box inflates every path)",
        load_avg()
    );
    println!(
        "crypto:   TLS 1.3 (rustls/ring), self-signed cert for localhost, client insecure=true"
    );
    println!("          REALITY: x25519 + ed25519 tagged cert, SNI {REALITY_SNI}");
    println!("verify:   every received byte byte-compared against the sent pattern");
    println!("{}", "-".repeat(104));

    // ---- path 2: single-process SOCKS → direct ----
    let direct_flux = spawn_proxy(
        &args.flux_bin,
        &format!(
            r#"{{ "inbounds": [{}], "outbounds": [{{ "type": "direct", "tag": "direct" }}] }}"#,
            socks_inbound(ports[0])
        ),
        "direct",
    );

    // ---- paths 3/4/5: edge + node pairs ----
    let plain_node = spawn_proxy(&args.flux_bin, &node_config(ports[1], None), "plain_node");
    let plain_edge = spawn_proxy(
        &args.flux_bin,
        &edge_config(ports[2], ports[1], None),
        "plain_edge",
    );

    // The server needs a real certificate: a TLS inbound with only `server_name`
    // does not start, and before this the whole `security` block sat inside
    // `carrier`, where it was silently dropped — so the "TLS" rows were measuring
    // plain VLESS over TCP and the numbers were a lie.
    let cert_dir = std::env::temp_dir().join(format!("bench_tls_certs_{}", std::process::id()));
    std::fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed certificate");
    std::fs::write(&cert_path, generated.cert.pem()).expect("write cert");
    std::fs::write(&key_path, generated.key_pair.serialize_pem()).expect("write key");
    let tls_sec_server = format!(
        r#"{{ "type": "tls", "certificate_path": "{}", "key_path": "{}" }}"#,
        cert_path.display(),
        key_path.display()
    );
    let tls_sec_client = r#"{ "type": "tls", "sni": "localhost", "insecure": true }"#.to_string();
    let tls_node = spawn_proxy(
        &args.flux_bin,
        &node_config(ports[3], Some(&tls_sec_server)),
        "tls_node",
    );
    let tls_edge = spawn_proxy(
        &args.flux_bin,
        &edge_config(ports[4], ports[3], Some(&tls_sec_client)),
        "tls_edge",
    );

    let reality_sec_server = format!(
        r#"{{ "type": "reality", "server_names": ["{REALITY_SNI}"], "private_key": "{reality_priv}", "short_ids": ["{REALITY_SHORT_ID}"] }}"#
    );
    let reality_sec_client = format!(
        r#"{{ "type": "reality", "sni": "{REALITY_SNI}", "public_key": "{reality_pub}", "short_id": "{REALITY_SHORT_ID}" }}"#
    );
    let reality_node = spawn_proxy(
        &args.flux_bin,
        &node_config(ports[5], Some(&reality_sec_server)),
        "reality_node",
    );
    let reality_edge = spawn_proxy(
        &args.flux_bin,
        &edge_config(ports[6], ports[5], Some(&reality_sec_client)),
        "reality_edge",
    );

    let direct_flux_addr: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse()?;
    let plain_node_addr: SocketAddr = format!("127.0.0.1:{}", ports[1]).parse()?;
    let plain_addr: SocketAddr = format!("127.0.0.1:{}", ports[2]).parse()?;
    let tls_node_addr: SocketAddr = format!("127.0.0.1:{}", ports[3]).parse()?;
    let tls_addr: SocketAddr = format!("127.0.0.1:{}", ports[4]).parse()?;
    let reality_node_addr: SocketAddr = format!("127.0.0.1:{}", ports[5]).parse()?;
    let reality_addr: SocketAddr = format!("127.0.0.1:{}", ports[6]).parse()?;

    wait_for_listener(direct_flux_addr, "flux-core (socks→direct)").await;
    wait_for_listener(plain_node_addr, "vless node (plain)").await;
    wait_for_listener(plain_addr, "vless edge (plain)").await;
    wait_for_listener(tls_node_addr, "vless node (tls)").await;
    wait_for_listener(tls_addr, "vless edge (tls)").await;
    wait_for_listener(reality_node_addr, "vless node (reality)").await;
    wait_for_listener(reality_addr, "vless edge (reality)").await;

    // Path table: (label, connect addr, socks target, [pids])
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
            addr: direct_flux_addr,
            target: Some(echo),
            pids: vec![direct_flux.pid],
        },
        Path {
            name: "vless/tcp",
            addr: plain_addr,
            target: Some(echo),
            pids: vec![plain_edge.pid, plain_node.pid],
        },
        Path {
            name: "vless/tls",
            addr: tls_addr,
            target: Some(echo),
            pids: vec![tls_edge.pid, tls_node.pid],
        },
        Path {
            name: "vless/reality",
            addr: reality_addr,
            target: Some(echo),
            pids: vec![reality_edge.pid, reality_node.pid],
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

    // Warm-up: a small transfer and a few connects on every path, so TLS
    // handshake paths, accept loops and buffer pools are hot before round 1.
    for p in &paths {
        eprintln!("[warmup] {}", p.name);
        let _ = transfer(
            p.addr,
            p.target,
            16 * 1024 * 1024,
            args.streams,
            &pat,
            p.name,
        )
        .await;
        let _ = connect_latency_us(p.addr, p.target, 3).await;
    }

    struct Acc {
        speed: Vec<f64>,
        /// Total CPU seconds of every process on the path, per round.
        cpu_total: Vec<f64>,
        /// CPU seconds of the first process (client/edge side), per round.
        cpu_client: Vec<f64>,
        setup_p50: Vec<f64>,
        setup_p99: Vec<f64>,
        rss_mib: f64,
        corrupt_rounds: usize,
        first_corrupt: Option<Corrupt>,
    }
    let mut accs: Vec<Acc> = (0..paths.len())
        .map(|_| Acc {
            speed: Vec::new(),
            cpu_total: Vec::new(),
            cpu_client: Vec::new(),
            setup_p50: Vec::new(),
            setup_p99: Vec::new(),
            rss_mib: 0.0,
            corrupt_rounds: 0,
            first_corrupt: None,
        })
        .collect();

    for round in 1..=args.rounds {
        let mut line = format!("  round {round}:");
        for (idx, p) in paths.iter().enumerate() {
            let before: Vec<f64> = p
                .pids
                .iter()
                .map(|&pid| read_proc_cost(pid).map(|c| c.cpu_secs).unwrap_or(0.0))
                .collect();
            let t = transfer(p.addr, p.target, total, args.streams, &pat, p.name).await;
            let after: Vec<f64> = p
                .pids
                .iter()
                .map(|&pid| read_proc_cost(pid).map(|c| c.cpu_secs).unwrap_or(0.0))
                .collect();
            let mut total_cpu = 0.0;
            for (a, b) in after.iter().zip(before.iter()) {
                total_cpu += (a - b).max(0.0);
            }
            let client_cpu = after
                .first()
                .zip(before.first())
                .map(|(a, b)| (a - b).max(0.0))
                .unwrap_or(0.0);

            let mbs = t.bytes as f64 / 1_048_576.0 / t.secs;
            accs[idx].speed.push(mbs);
            if let Some(c) = t.corrupt {
                accs[idx].corrupt_rounds += 1;
                accs[idx].first_corrupt.get_or_insert(c);
            }
            accs[idx].cpu_total.push(total_cpu);
            accs[idx].cpu_client.push(client_cpu);

            let lat = connect_latency_us(p.addr, p.target, 12).await;
            accs[idx].setup_p50.push(percentile(&lat, 50.0) / 1e3);
            accs[idx].setup_p99.push(percentile(&lat, 99.0) / 1e3);

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
            line.push_str(&format!("  {:<13} {mbs:8.1}", p.name));
            if t.corrupt.is_some() {
                line.push_str(" CORRUPT");
            }
            if args.streams > 1 {
                line.push_str(&format!(
                    " (setup {:.1} ms, p50 {:.1} p99 {:.1} MB/s)",
                    t.setup_secs * 1e3,
                    percentile(&t.per_stream, 50.0),
                    percentile(&t.per_stream, 99.0)
                ));
            }
        }
        println!("{line}  (MB/s)");
    }

    let gb = (args.rounds * args.mb) as f64 / 1024.0;
    let direct_median = median_min_max(&accs[0].speed).0;

    let mut rows = Vec::new();
    for (idx, p) in paths.iter().enumerate() {
        let a = &accs[idx];
        let speed = median_min_max(&a.speed);
        let setup = (
            median_min_max(&a.setup_p50).0,
            a.setup_p99.iter().copied().fold(0.0, f64::max),
        );
        let cpu_total: f64 = a.cpu_total.iter().sum::<f64>() / gb;
        let cpu_client: f64 = a.cpu_client.iter().sum::<f64>() / gb;
        rows.push(PathRow {
            name: p.name,
            speed,
            cpu_total_per_gb: (!p.pids.is_empty()).then_some(cpu_total),
            cpu_client_per_gb: (!p.pids.is_empty()).then_some(cpu_client),
            rss_mib: (a.rss_mib > 0.0).then_some(a.rss_mib),
            setup_ms: setup,
            corrupt_rounds: a.corrupt_rounds,
            first_corrupt: a.first_corrupt,
        });
    }

    println!("{}", "-".repeat(104));
    println!(
        "{:<14} {:>9} {:>9} {:>9} {:>16} {:>9} {:>9} {:>10}  integrity",
        "target", "MB/s", "min", "max", "setup p50/p99", "CPU s/GB", "RSS MiB", "vs direct"
    );
    println!("{}", "-".repeat(104));
    for r in &rows {
        println!(
            "{:<14} {:>9.1} {:>9.1} {:>9.1} {:>16} {:>9} {:>9} {:>10}  {}",
            r.name,
            r.speed.0,
            r.speed.1,
            r.speed.2,
            format!("{:.2}/{:.2} ms", r.setup_ms.0, r.setup_ms.1),
            r.cpu_total_per_gb
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
            r.rss_mib
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            format!("{:+.1}%", (r.speed.0 / direct_median - 1.0) * 100.0),
            if let Some(c) = r.first_corrupt {
                format!(
                    "CORRUPT {}/{} rounds, first at offset {} (stream claims block {})",
                    r.corrupt_rounds,
                    args.rounds,
                    c.at,
                    c.claimed
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                )
            } else {
                "OK (byte-verified)".to_string()
            },
        );
    }
    println!("{}", "-".repeat(104));

    // Decomposed costs: this is the whole point of the harness.
    let get = |name: &str| rows.iter().find(|r| r.name == name).unwrap();
    let d = get("direct");
    let f = get("flux direct");
    let p = get("vless/tcp");
    let t = get("vless/tls");
    let r = get("vless/reality");
    println!("\ncost decomposition (median MB/s; CPU s/GB = total over all tunnel processes):");
    println!("  direct          {:>8.1} MB/s        -", d.speed.0);
    println!(
        "  flux direct     {:>8.1} MB/s   {:>5.2} s/GB   ({:+.1}% vs direct — one process, SOCKS + copy path)",
        f.speed.0,
        f.cpu_total_per_gb.unwrap_or(0.0),
        (f.speed.0 / d.speed.0 - 1.0) * 100.0
    );
    println!(
        "  vless/tcp       {:>8.1} MB/s   {:>5.2} s/GB   ({:+.1}% vs flux direct — framing + second hop)",
        p.speed.0,
        p.cpu_total_per_gb.unwrap_or(0.0),
        (p.speed.0 / f.speed.0 - 1.0) * 100.0
    );
    println!(
        "  vless/tls       {:>8.1} MB/s   {:>5.2} s/GB   ({:+.1}% vs vless/tcp — the TLS layer)",
        t.speed.0,
        t.cpu_total_per_gb.unwrap_or(0.0),
        (t.speed.0 / p.speed.0 - 1.0) * 100.0
    );
    println!(
        "  vless/reality   {:>8.1} MB/s   {:>5.2} s/GB   ({:+.1}% vs vless/tls — REALITY)",
        r.speed.0,
        r.cpu_total_per_gb.unwrap_or(0.0),
        (r.speed.0 / t.speed.0 - 1.0) * 100.0
    );
    println!(
        "  TLS layer vs plain TCP (same framing): {:+8.1} MB/s throughput, {:+.2} CPU s/GB",
        t.speed.0 - p.speed.0,
        t.cpu_total_per_gb.unwrap_or(0.0) - p.cpu_total_per_gb.unwrap_or(0.0)
    );
    println!(
        "  end-to-end encryption overhead (tls vs direct): {:+.1}% throughput, {:+.2} CPU s/GB",
        (t.speed.0 / d.speed.0 - 1.0) * 100.0,
        t.cpu_total_per_gb.unwrap_or(0.0)
    );
    println!(
        "  client/server CPU split (s/GB): flux direct {:.2}; vless/tcp {:.2}/{:.2}; \
         vless/tls {:.2}/{:.2}; vless/reality {:.2}/{:.2}",
        f.cpu_total_per_gb.unwrap_or(0.0),
        p.cpu_client_per_gb.unwrap_or(0.0),
        p.cpu_total_per_gb.unwrap_or(0.0) - p.cpu_client_per_gb.unwrap_or(0.0),
        t.cpu_client_per_gb.unwrap_or(0.0),
        t.cpu_total_per_gb.unwrap_or(0.0) - t.cpu_client_per_gb.unwrap_or(0.0),
        r.cpu_client_per_gb.unwrap_or(0.0),
        r.cpu_total_per_gb.unwrap_or(0.0) - r.cpu_client_per_gb.unwrap_or(0.0),
    );
    println!(
        "\nper-connection setup (TCP connect → first echoed byte, warm process, {} probes/round):",
        12
    );
    for r in &rows {
        println!(
            "  {:<14} p50 {:>7.2} ms   p99 {:>7.2} ms",
            r.name, r.setup_ms.0, r.setup_ms.1
        );
    }
    println!("{}", "-".repeat(104));

    // Machine-readable lines for scripts/bench_all.sh.
    for r in &rows {
        result("tls", "1", r.name, "mbs", &format!("{:.1}", r.speed.0));
        result("tls", "1", r.name, "mbs_min", &format!("{:.1}", r.speed.1));
        result("tls", "1", r.name, "mbs_max", &format!("{:.1}", r.speed.2));
        if let Some(c) = r.cpu_total_per_gb {
            result("tls", "1", r.name, "cpu_s_per_gb", &format!("{c:.2}"));
        }
        if let Some(rss) = r.rss_mib {
            result("tls", "1", r.name, "rss_mib", &format!("{rss:.1}"));
        }
        result(
            "tls",
            "1",
            r.name,
            "integrity",
            if r.first_corrupt.is_some() {
                "corrupt"
            } else {
                "ok"
            },
        );
        result(
            "tls",
            "1",
            r.name,
            "corrupt_rounds",
            &format!("{}/{}", r.corrupt_rounds, args.rounds),
        );
        result(
            "tls",
            "1",
            r.name,
            "setup_p50_ms",
            &format!("{:.2}", r.setup_ms.0),
        );
        result(
            "tls",
            "1",
            r.name,
            "setup_p99_ms",
            &format!("{:.2}", r.setup_ms.1),
        );
    }

    drop((
        direct_flux,
        plain_edge,
        plain_node,
        tls_edge,
        tls_node,
        reality_edge,
        reality_node,
    ));
    println!("{}", "=".repeat(104));
    Ok(())
}

fn result(profile: &str, level: &str, target: &str, metric: &str, value: &str) {
    println!("@@RESULT|{profile}|{level}|{target}|{metric}|{value}");
}
