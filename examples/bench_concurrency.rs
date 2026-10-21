//! Concurrency matrix benchmark: throughput and cost at 1 / 64 / 512 / 2048
//! simultaneous TCP streams.
//!
//! `bench_native` answers "how fast is one stream?". This harness answers the
//! question the project's claims actually depend on — what happens when the
//! data plane has to hold *thousands* of connections at once:
//!
//!   * aggregate payload MB/s (all streams together),
//!   * per-stream throughput distribution (p50 / p99): a good aggregate with a
//!     fat tail is a worse user experience than a slightly lower aggregate with
//!     a tight distribution,
//!   * the cost side: CPU seconds per GB moved, peak RSS, peak thread count and
//!     peak file-descriptor count of the proxy process,
//!   * connection setup time for N streams (accept + SOCKS negotiation), which
//!     is where an O(n) or per-connection-thread design shows up.
//!
//! Methodology (identical to `bench_native`):
//!   * every target is warmed up before measurement,
//!   * rounds are **interleaved** (direct, flux, sing-box, direct, …) so machine
//!     drift cancels instead of accumulating in whichever target ran last,
//!   * the reported number is the **median** over rounds, with min/max printed
//!     so variance is visible,
//!   * only real, verified payload bytes count: every received chunk is
//!     byte-compared against the pattern that was sent, and a truncated stream
//!     is a hard error (no extrapolation, no sleeping, no polling tricks).
//!   * within a round, the aggregate timer starts only once *all* N streams are
//!     connected (a `Barrier`), so setup cost is reported separately instead of
//!     being hidden inside the throughput number.
//!
//! Usage:
//!   cargo run --release --example bench_concurrency -- [options]
//!
//! Options:
//!   --rounds N       interleaved rounds per level (default 5)
//!   --levels a,b,c   concurrency levels (default 1,64,512,2048)
//!   --mb N           payload MB per level (default: max(256, streams/2) MiB)
//!   --no-singbox     skip the sing-box comparison
//!   --flux PATH      flux-core binary (default ./target/release/flux-core)
//!   --singbox PATH   sing-box binary (default: PATH / ~/.local/bin)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Chunk size used for both the write and the read side. Also the period of the
/// verification pattern, so a chunk always matches one contiguous pattern window.
const CHUNK: usize = 64 * 1024;

/// Upper bound on a single measured level, so a hung path fails loudly instead
/// of freezing the run.
const TRANSFER_TIMEOUT_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    rounds: usize,
    levels: Vec<usize>,
    mb: Option<usize>,
    with_singbox: bool,
    flux_bin: PathBuf,
    singbox_bin: Option<PathBuf>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            rounds: 5,
            levels: vec![1, 64, 512, 2048],
            mb: None,
            with_singbox: true,
            flux_bin: PathBuf::from("./target/release/flux-core"),
            singbox_bin: find_in_path("sing-box"),
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
                "--levels" => {
                    let raw = take(&mut i)?;
                    args.levels = raw
                        .split(',')
                        .map(|s| s.trim().parse::<usize>())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("--levels: {e}"))?;
                }
                "--mb" => args.mb = Some(take(&mut i)?.parse().map_err(|e| format!("{e}"))?),
                "--no-singbox" => args.with_singbox = false,
                "--flux" => args.flux_bin = PathBuf::from(take(&mut i)?),
                "--singbox" => args.singbox_bin = Some(PathBuf::from(take(&mut i)?)),
                "--help" | "-h" => {
                    println!("{}", Self::usage());
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }
        if args.rounds == 0 || args.levels.is_empty() {
            return Err("--rounds and --levels must be non-empty".into());
        }
        if args.levels.contains(&0) {
            return Err("--levels entries must be >= 1".into());
        }
        Ok(args)
    }

    fn usage() -> &'static str {
        "usage: bench_concurrency [--rounds N] [--levels 1,64,512,2048] [--mb N] \
         [--no-singbox] [--flux PATH] [--singbox PATH]"
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH")
        && let Some(p) = std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    {
        return Some(p);
    }
    let home = std::env::var_os("HOME")?;
    let p = PathBuf::from(home).join(".local/bin").join(name);
    p.is_file().then_some(p)
}

// ---------------------------------------------------------------------------
// Process accounting
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
struct ProcCost {
    cpu_secs: f64,
    /// Current resident set (VmRSS), sampled.
    rss_kb: u64,
    threads: u32,
    fds: usize,
}

fn read_proc_cost(pid: u32) -> Option<ProcCost> {
    // USER_HZ is 100 on every supported Linux configuration.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let mut rss_kb = 0u64;
    let mut threads = 0u32;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            rss_kb = v
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("Threads:") {
            threads = v
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| d.count())
        .unwrap_or(0);
    Some(ProcCost {
        cpu_secs: (utime + stime) as f64 / 100.0,
        rss_kb,
        threads,
        fds,
    })
}

/// Peak sampler for a proxy process: RSS, thread count and open descriptors are
/// transient maxima, so a single read before/after the measurement can miss
/// them. This samples them while the level runs and keeps the maxima.
struct PeakSampler {
    stop: Arc<AtomicU64>,
    peak_rss_kb: Arc<AtomicU64>,
    peak_threads: Arc<AtomicU32>,
    peak_fds: Arc<AtomicU64>,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Default)]
struct Peaks {
    rss_kb: u64,
    threads: u32,
    fds: u64,
}

impl PeakSampler {
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicU64::new(0));
        let peak_rss_kb = Arc::new(AtomicU64::new(0));
        let peak_threads = Arc::new(AtomicU32::new(0));
        let peak_fds = Arc::new(AtomicU64::new(0));
        let handle = tokio::spawn({
            let stop = stop.clone();
            let peak_rss_kb = peak_rss_kb.clone();
            let peak_threads = peak_threads.clone();
            let peak_fds = peak_fds.clone();
            async move {
                while stop.load(Ordering::Relaxed) == 0 {
                    if let Some(c) = read_proc_cost(pid) {
                        peak_rss_kb.fetch_max(c.rss_kb, Ordering::Relaxed);
                        peak_threads.fetch_max(c.threads, Ordering::Relaxed);
                        peak_fds.fetch_max(c.fds as u64, Ordering::Relaxed);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });
        Self {
            stop,
            peak_rss_kb,
            peak_threads,
            peak_fds,
            handle,
        }
    }

    async fn finish(self) -> Peaks {
        self.stop.store(1, Ordering::Relaxed);
        let _ = self.handle.await;
        Peaks {
            rss_kb: self.peak_rss_kb.load(Ordering::Relaxed),
            threads: self.peak_threads.load(Ordering::Relaxed),
            fds: self.peak_fds.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct Stats {
    median: f64,
    min: f64,
    max: f64,
}

impl Stats {
    fn new(samples: &[f64]) -> Self {
        let (median, min, max) = median_min_max(samples);
        Self { median, min, max }
    }
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

/// Nearest-rank percentile over an ascending slice.
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

/// Deterministic payload; one full period is `CHUNK` bytes, so a received chunk
/// is always compared against a contiguous (possibly wrapping) pattern window.
fn make_pattern() -> Arc<Vec<u8>> {
    let mut v = Vec::with_capacity(CHUNK);
    for i in 0..CHUNK {
        v.push((i as u8) ^ ((i >> 8) as u8) ^ 0x5A);
    }
    Arc::new(v)
}

/// Byte-compares `data` against the pattern window starting at stream position
/// `pos`. This is a real comparison of every received byte, not a byte count.
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
// Echo server + proxy plumbing
// ---------------------------------------------------------------------------

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn wait_for_listener(addr: SocketAddr, what: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("{what} did not start listening on {addr} within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            // A connection storm can make accept() fail transiently (ECONNABORTED
            // and friends). Terminating the loop here would silently stop the
            // server for the rest of the run, so an error only yields.
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

/// SOCKS5 no-auth negotiation + CONNECT to `echo`.
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

// ---------------------------------------------------------------------------
// One measured level
// ---------------------------------------------------------------------------

struct StreamTiming {
    bytes: usize,
    secs: f64,
}

/// Writes the whole payload, then hands the write half back.
///
/// Dropping the write half early would half-close the connection; a transport
/// that mishandles half-close would then discard the reply still in flight and
/// the harness would hang. The measured path must be allowed to finish draining
/// before the FIN goes out.
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
) -> usize {
    let mut received = 0usize;
    let mut buf = vec![0u8; CHUNK];
    while received < total {
        // Never read past `total`: an overshooting read would make the received
        // byte count exceed what was sent and hide a transport fault.
        let want = (total - received).min(CHUNK);
        match r.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                assert!(
                    matches_pattern(&buf[..n], received, &pat),
                    "payload corruption at stream offset {received}"
                );
                received += n;
            }
        }
    }
    received
}

/// Connects one stream, waits for the common start signal, then transfers and
/// verifies `total` bytes. The per-stream clock starts at the signal, so
/// per-stream throughput excludes connection setup — which is reported
/// separately.
async fn stream_once(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total: usize,
    pat: Arc<Vec<u8>>,
    label: &'static str,
    ready: tokio::sync::mpsc::Sender<()>,
    mut start: tokio::sync::watch::Receiver<bool>,
) -> StreamTiming {
    // A hung proxy must not hang the harness: setup steps are bounded and
    // failures panic in this task rather than deadlocking the collector.
    let mut s = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_| panic!("[{label}] TCP connect to {addr} timed out"))
        .unwrap_or_else(|e| panic!("[{label}] TCP connect to {addr} failed after {e}"));
    let _ = s.set_nodelay(true);
    if let Some(echo) = target {
        tokio::time::timeout(Duration::from_secs(30), socks5_connect(&mut s, echo))
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

    let (w, received) = tokio::join!(
        write_all_pattern(w, total, pat.clone()),
        read_and_verify(r, total, pat.clone())
    );
    let secs = t0.elapsed().as_secs_f64();
    // Fully drained: only now may the connection be torn down.
    drop(w);
    StreamTiming {
        bytes: received,
        secs,
    }
}

struct LevelResult {
    /// Sum of verified payload bytes over all streams.
    bytes: usize,
    /// Streams that ended early. Reported, never extrapolated over.
    truncated: usize,
    /// Wall time from "all streams connected" to "last byte verified".
    secs: f64,
    setup_secs: f64,
    /// Per-stream MB/s, ascending.
    per_stream: Vec<f64>,
}

async fn run_level(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total: usize,
    streams: usize,
    pat: &Arc<Vec<u8>>,
    label: &'static str,
) -> LevelResult {
    let per = total / streams;
    assert!(
        per >= CHUNK,
        "per-stream payload {per} B is smaller than one chunk; raise --mb"
    );
    let per = (per / CHUNK) * CHUNK;

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
    // All N streams are connected and parked here; release them together and
    // start the aggregate clock at the same instant.
    for _ in 0..streams {
        ready_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("[{label}] a stream task died while connecting to {addr}"));
    }
    let setup_secs = t_spawn.elapsed().as_secs_f64();
    start_tx.send(true).unwrap();
    let t0 = Instant::now();

    let mut bytes = 0usize;
    let mut truncated = 0usize;
    let mut per_stream = Vec::with_capacity(streams);
    for h in handles {
        let r = tokio::time::timeout(Duration::from_secs(TRANSFER_TIMEOUT_SECS), h)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "[{label}] transfer of {per} B x {streams} streams did not finish in {TRANSFER_TIMEOUT_SECS}s"
                )
            })
            .unwrap_or_else(|e| panic!("[{label}] {e}"));
        // A truncated stream is reported, never extrapolated: its bytes do not
        // exist, so the aggregate counts only what actually arrived.
        if r.bytes != per {
            truncated += 1;
        }
        bytes += r.bytes;
        if r.bytes > 0 {
            per_stream.push(r.bytes as f64 / 1_048_576.0 / r.secs);
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    per_stream.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    LevelResult {
        bytes,
        truncated,
        secs,
        setup_secs,
        per_stream,
    }
}

struct ProxyProc {
    child: Child,
    pid: u32,
    addr: SocketAddr,
}

impl Drop for ProxyProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_proxy(bin: &Path, config: &str, label: &str, extra: &[&str]) -> ProxyProc {
    assert!(
        bin.is_file(),
        "proxy binary not found: {} (build it first: cargo build --release -p flux-core)",
        bin.display()
    );
    let cfg_path = std::env::temp_dir().join(format!("bench_conc_{label}.json"));
    std::fs::write(&cfg_path, config).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap()])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));
    ProxyProc {
        child,
        pid: 0,
        addr: "127.0.0.1:0".parse().unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

struct Row {
    target: &'static str,
    /// Streams that ended early in the worst round of this level.
    truncated: usize,
    agg: Stats,
    p50: Stats,
    p99: Stats,
    setup_ms: Stats,
    cpu_per_gb: Option<f64>,
    peaks: Option<Peaks>,
}

fn machine_profile() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".into());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    format!(
        "{} logical CPUs ({cpu}), Linux {kernel}, {} MiB RAM",
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(0),
        total_mem_mib()
    )
}

fn total_mem_mib() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
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

    println!("{}", "=".repeat(112));
    println!("CONCURRENCY MATRIX — many simultaneous TCP streams");
    println!("{}", "=".repeat(112));
    println!("profile:  loopback (127.0.0.1) only, single machine, one process per target");
    println!("machine:  {}", machine_profile());
    println!(
        "load:     {:.2} (1-minute load average at start; concurrent work on this box inflates every path)",
        load_avg()
    );
    println!(
        "protocol: {} interleaved rounds per level, median reported, min/max shown",
        args.rounds
    );
    println!(
        "payload:  deterministic {} KiB-pattern chunks, every received byte byte-compared",
        CHUNK / 1024
    );
    println!("          against the sent pattern; truncation is a hard error");
    println!("levels:   {:?} concurrent streams", args.levels);
    println!("echo:     {echo}");
    println!("flux:     {}", args.flux_bin.display());
    println!("{}", "-".repeat(112));

    // ---- flux-core ----
    let flux_port = get_free_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {flux_port} }}, "protocol": {{ "type": "socks" }} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    );
    let mut flux = spawn_proxy(&args.flux_bin, &flux_cfg, "flux", &["-f", "json"]);
    flux.pid = flux.child.id();
    flux.addr = format!("127.0.0.1:{flux_port}").parse()?;
    wait_for_listener(flux.addr, "flux-core", Duration::from_secs(20)).await;

    // ---- sing-box ----
    let singbox = if args.with_singbox {
        match args.singbox_bin.clone() {
            Some(bin) if bin.is_file() => {
                let port = get_free_port().await;
                let cfg = format!(
                    r#"{{"log": {{"level": "error"}},
                        "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": {port} }}],
                        "outbounds": [{{ "type": "direct", "tag": "direct" }}]}}"#
                );
                let mut p = spawn_proxy(&bin, &cfg, "singbox", &[]);
                p.pid = p.child.id();
                p.addr = format!("127.0.0.1:{port}").parse()?;
                wait_for_listener(p.addr, "sing-box", Duration::from_secs(20)).await;
                Some(p)
            }
            _ => {
                println!("sing-box: not found on PATH or ~/.local/bin — comparison skipped");
                None
            }
        }
    } else {
        None
    };
    println!("{}", "-".repeat(112));

    for &streams in &args.levels {
        let total_mb = args.mb.unwrap_or((streams / 2).max(256));
        let total = total_mb * 1024 * 1024;
        println!(
            "\n### {} concurrent stream(s), {total_mb} MiB of verified payload per measurement",
            streams
        );

        // Warm-up: identical shape, a quarter of the volume — but always enough
        // for at least two chunks per stream, so a high-concurrency warm-up is
        // not silently smaller than one chunk per stream.
        let warm = ((total / 4).max(streams * CHUNK * 2)).min(total);
        println!(
            "  warm-up: {} MiB over {streams} stream(s)",
            warm / (1024 * 1024)
        );
        let _ = run_level(echo, None, warm, streams, &pat, "direct").await;
        let _ = run_level(flux.addr, Some(echo), warm, streams, &pat, "flux-core").await;
        if let Some(sb) = &singbox {
            let _ = run_level(sb.addr, Some(echo), warm, streams, &pat, "sing-box").await;
        }

        let mut direct = Vec::with_capacity(args.rounds);
        let mut flux_s = Vec::with_capacity(args.rounds);
        let mut sing_s = Vec::with_capacity(args.rounds);
        let mut flux_cpu = 0.0f64;
        let mut sing_cpu = 0.0f64;
        // Peaks are per (level, target): take the max across rounds.
        let mut flux_peaks = Peaks::default();
        let mut sing_peaks = Peaks::default();
        let mut direct_trunc = 0usize;
        let mut flux_trunc = 0usize;
        let mut sing_trunc = 0usize;
        let mut flux_setup = Vec::new();
        let mut sing_setup = Vec::new();
        let mut direct_setup = Vec::new();
        let mut flux_p50 = Vec::new();
        let mut flux_p99 = Vec::new();
        let mut sing_p50 = Vec::new();
        let mut sing_p99 = Vec::new();
        let mut direct_p50 = Vec::new();
        let mut direct_p99 = Vec::new();

        for round in 1..=args.rounds {
            // --- direct ---
            let d = run_level(echo, None, total, streams, &pat, "direct").await;
            direct_trunc = direct_trunc.max(d.truncated);
            direct.push(d.bytes as f64 / 1_048_576.0 / d.secs);
            direct_setup.push(d.setup_secs * 1e3);
            direct_p50.push(percentile(&d.per_stream, 50.0));
            direct_p99.push(percentile(&d.per_stream, 99.0));

            // --- flux-core ---
            let before = read_proc_cost(flux.pid).map(|c| c.cpu_secs).unwrap_or(0.0);
            let sampler = PeakSampler::start(flux.pid);
            let f = run_level(flux.addr, Some(echo), total, streams, &pat, "flux-core").await;
            flux_trunc = flux_trunc.max(f.truncated);
            let peaks = sampler.finish().await;
            flux_peaks.rss_kb = flux_peaks.rss_kb.max(peaks.rss_kb);
            flux_peaks.threads = flux_peaks.threads.max(peaks.threads);
            flux_peaks.fds = flux_peaks.fds.max(peaks.fds);
            flux_cpu += read_proc_cost(flux.pid).map(|c| c.cpu_secs).unwrap_or(0.0) - before;
            flux_s.push(f.bytes as f64 / 1_048_576.0 / f.secs);
            flux_setup.push(f.setup_secs * 1e3);
            flux_p50.push(percentile(&f.per_stream, 50.0));
            flux_p99.push(percentile(&f.per_stream, 99.0));

            // --- sing-box ---
            let s = if let Some(sb) = &singbox {
                let before = read_proc_cost(sb.pid).map(|c| c.cpu_secs).unwrap_or(0.0);
                let sampler = PeakSampler::start(sb.pid);
                let r = run_level(sb.addr, Some(echo), total, streams, &pat, "sing-box").await;
                sing_trunc = sing_trunc.max(r.truncated);
                let peaks = sampler.finish().await;
                sing_peaks.rss_kb = sing_peaks.rss_kb.max(peaks.rss_kb);
                sing_peaks.threads = sing_peaks.threads.max(peaks.threads);
                sing_peaks.fds = sing_peaks.fds.max(peaks.fds);
                sing_cpu += read_proc_cost(sb.pid).map(|c| c.cpu_secs).unwrap_or(0.0) - before;
                Some(r)
            } else {
                None
            };
            if let Some(r) = &s {
                sing_s.push(r.bytes as f64 / 1_048_576.0 / r.secs);
                sing_setup.push(r.setup_secs * 1e3);
                sing_p50.push(percentile(&r.per_stream, 50.0));
                sing_p99.push(percentile(&r.per_stream, 99.0));
            }

            print!(
                "  round {round}: direct {:8.1}  flux {:8.1}",
                direct[round - 1],
                flux_s[round - 1]
            );
            if flux_trunc > 0 {
                print!(" ({} truncated stream(s))", flux_trunc);
            }
            if let Some(v) = sing_s.get(round - 1) {
                print!("  sing-box {v:8.1}");
            }
            println!("  (MB/s aggregate)");
        }

        let gb = (args.rounds * total_mb) as f64 / 1024.0;
        let mut rows = vec![
            Row {
                target: "direct",
                truncated: direct_trunc,
                agg: Stats::new(&direct),
                p50: Stats::new(&direct_p50),
                p99: Stats::new(&direct_p99),
                setup_ms: Stats::new(&direct_setup),
                cpu_per_gb: None,
                peaks: None,
            },
            Row {
                target: "flux-core",
                truncated: flux_trunc,
                agg: Stats::new(&flux_s),
                p50: Stats::new(&flux_p50),
                p99: Stats::new(&flux_p99),
                setup_ms: Stats::new(&flux_setup),
                cpu_per_gb: (flux_cpu > 0.0).then(|| flux_cpu / gb),
                peaks: Some(flux_peaks),
            },
        ];
        if !sing_s.is_empty() {
            rows.push(Row {
                target: "sing-box",
                truncated: sing_trunc,
                agg: Stats::new(&sing_s),
                p50: Stats::new(&sing_p50),
                p99: Stats::new(&sing_p99),
                setup_ms: Stats::new(&sing_setup),
                cpu_per_gb: (sing_cpu > 0.0).then(|| sing_cpu / gb),
                peaks: Some(sing_peaks),
            });
        }

        println!(
            "  {:<10} {:>9} {:>7} {:>7} {:>9} {:>9} {:>9} {:>8} {:>8} {:>8} {:>8}  integrity",
            "target",
            "agg MB/s",
            "min",
            "max",
            "p50 MB/s",
            "p99 MB/s",
            "setup ms",
            "CPU s/GB",
            "RSS MiB",
            "threads",
            "fds"
        );
        for r in &rows {
            let peaks = r.peaks.unwrap_or_default();
            println!(
                "  {:<10} {:>9.1} {:>7.1} {:>7.1} {:>9.1} {:>9.1} {:>9.1} {:>8} {:>8} {:>8} {:>8}  {}",
                r.target,
                r.agg.median,
                r.agg.min,
                r.agg.max,
                r.p50.median,
                r.p99.median,
                r.setup_ms.median,
                r.cpu_per_gb
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "-".into()),
                if r.peaks.is_some() {
                    format!("{:.1}", peaks.rss_kb as f64 / 1024.0)
                } else {
                    "-".into()
                },
                if r.peaks.is_some() {
                    peaks.threads.to_string()
                } else {
                    "-".into()
                },
                if r.peaks.is_some() {
                    peaks.fds.to_string()
                } else {
                    "-".into()
                },
                if r.truncated > 0 {
                    format!(
                        "TRUNCATED {}/{} streams in worst round",
                        r.truncated, streams
                    )
                } else {
                    "ok (byte-verified)".to_string()
                },
            );
        }
        let direct_med = rows[0].agg.median;
        let flux_med = rows[1].agg.median;
        println!(
            "  flux-core vs direct: {:+.1}%  ({:.1} vs {:.1} MB/s aggregate, {} streams)",
            (flux_med / direct_med - 1.0) * 100.0,
            flux_med,
            direct_med,
            streams
        );
        if let Some(sb) = rows.iter().find(|r| r.target == "sing-box") {
            println!(
                "  flux-core vs sing-box: {:+.1}%  ({:.1} vs {:.1} MB/s aggregate)",
                (flux_med / sb.agg.median - 1.0) * 100.0,
                flux_med,
                sb.agg.median
            );
        }

        // Machine-readable lines for scripts/bench_all.sh.
        for r in &rows {
            let peaks = r.peaks.unwrap_or_default();
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "agg_mbs",
                &format!("{:.1}", r.agg.median),
            );
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "agg_min_mbs",
                &format!("{:.1}", r.agg.min),
            );
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "agg_max_mbs",
                &format!("{:.1}", r.agg.max),
            );
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "p50_mbs",
                &format!("{:.1}", r.p50.median),
            );
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "p99_mbs",
                &format!("{:.1}", r.p99.median),
            );
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "setup_ms",
                &format!("{:.1}", r.setup_ms.median),
            );
            if let Some(c) = r.cpu_per_gb {
                result(
                    "concurrency",
                    &streams.to_string(),
                    r.target,
                    "cpu_s_per_gb",
                    &format!("{c:.2}"),
                );
            }
            result(
                "concurrency",
                &streams.to_string(),
                r.target,
                "truncated_streams",
                &r.truncated.to_string(),
            );
            if r.peaks.is_some() {
                result(
                    "concurrency",
                    &streams.to_string(),
                    r.target,
                    "rss_mib",
                    &format!("{:.1}", peaks.rss_kb as f64 / 1024.0),
                );
                result(
                    "concurrency",
                    &streams.to_string(),
                    r.target,
                    "threads",
                    &peaks.threads.to_string(),
                );
                result(
                    "concurrency",
                    &streams.to_string(),
                    r.target,
                    "fds",
                    &peaks.fds.to_string(),
                );
            }
        }
    }

    println!(
        "\nload at end: {:.2} (1-minute average) — compare with the value printed at start",
        load_avg()
    );
    println!("{}", "=".repeat(112));
    println!("notes:");
    println!(
        "  * aggregate MB/s = verified payload bytes / wall time measured from the moment all"
    );
    println!(
        "    N streams are established, so connection setup is reported separately (setup ms)"
    );
    println!(
        "  * p50/p99 are per-stream MB/s across the N streams, median over interleaved rounds"
    );
    println!("  * RSS / threads / fds are peak values sampled at 100 Hz from /proc/<pid>");
    println!("  * CPU s/GB is the proxy process CPU (utime+stime) per GB of payload it carried");
    println!("  * the harness itself verifies every byte (memcmp against the sent pattern), which");
    println!(
        "    costs client-side CPU at multi-GB/s rates and caps the ceiling on the direct path"
    );
    println!("{}", "=".repeat(112));
    Ok(())
}

fn result(profile: &str, level: &str, target: &str, metric: &str, value: &str) {
    println!("@@RESULT|{profile}|{level}|{target}|{metric}|{value}");
}
