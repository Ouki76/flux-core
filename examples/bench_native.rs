//! Native throughput / CPU-cost benchmark.
//!
//! Measures a pipelined TCP echo transfer through:
//!   1. a direct loopback connection (baseline),
//!   2. `flux-core` (SOCKS5 inbound → direct outbound),
//!   3. `sing-box` (SOCKS inbound → direct outbound), when installed.
//!
//! Unlike a single-shot timing run, measurements are **interleaved across
//! rounds** and summarised by median (plus min/max). Loopback throughput on a
//! busy machine drifts by >10% between runs, so a one-shot number is not a
//! basis for comparing implementations — a median over interleaved rounds is.
//!
//! For every proxy the harness also reports the cost side: CPU seconds burned
//! per GB moved (from `/proc/<pid>/stat`) and peak RSS (from `/proc/<pid>/status`).
//!
//! Usage:
//!   cargo run --release --example bench_native -- [options]
//!
//! Options:
//!   --rounds N     interleaved measurement rounds (default 5)
//!   --mb N         megabytes per measurement (default 300)
//!   --streams N    concurrent connections per measurement (default 1)
//!   --no-singbox   skip the sing-box comparison
//!   --flux PATH    flux-core binary (default ./target/release/flux-core)
//!   --singbox PATH sing-box binary (default from PATH / ~/.local/bin)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    rounds: usize,
    mb: usize,
    streams: usize,
    with_singbox: bool,
    flux_bin: PathBuf,
    singbox_bin: Option<PathBuf>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            rounds: 5,
            mb: 300,
            streams: 1,
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
                "--mb" => args.mb = take(&mut i)?.parse().map_err(|e| format!("{e}"))?,
                "--streams" => args.streams = take(&mut i)?.parse().map_err(|e| format!("{e}"))?,
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
        if args.rounds == 0 || args.streams == 0 || args.mb == 0 {
            return Err("--rounds, --streams and --mb must be >= 1".into());
        }
        Ok(args)
    }

    fn usage() -> &'static str {
        "usage: bench_native [--rounds N] [--mb N] [--streams N] [--no-singbox] \
         [--flux PATH] [--singbox PATH]"
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|p| p.join(name))
        .find(|p| p.is_file())
        .or_else(|| {
            let home = std::env::var_os("HOME")?;
            let p = PathBuf::from(home).join(".local/bin").join(name);
            p.is_file().then_some(p)
        })
}

// ---------------------------------------------------------------------------
// Process accounting
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
struct ProcCost {
    cpu_secs: f64,
    peak_rss_kb: u64,
}

fn clock_ticks_per_sec() -> f64 {
    // USER_HZ is 100 on all supported Linux configurations.
    100.0
}

fn read_proc_cost(pid: u32) -> Option<ProcCost> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 14/15 are utime/stime, but comm may contain spaces/parens: split after ')'
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
        cpu_secs: (utime + stime) as f64 / clock_ticks_per_sec(),
        peak_rss_kb,
    })
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Stats {
    median: f64,
    min: f64,
    max: f64,
    cpu_secs: Option<f64>,
    peak_rss_kb: Option<u64>,
}

impl Stats {
    fn from_samples(mut v: Vec<f64>) -> (f64, f64, f64) {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = v.len();
        let median = if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        };
        (median, v[0], v[n - 1])
    }
}

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Waits until `addr` accepts TCP connections (or times out), so benchmarks do
/// not silently measure a proxy that has not finished starting.
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

/// Start a real async echo server and return its address.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = socket.into_split();
                let mut buf = vec![0u8; 128 * 1024];
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

/// One pipelined transfer of `total_bytes` over a single connection.
async fn transfer_once(addr: SocketAddr, target: Option<SocketAddr>, total_bytes: usize) -> usize {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let _ = s.set_nodelay(true);

    if let Some(echo) = target {
        // SOCKS5 no-auth CONNECT
        s.write_all(b"\x05\x01\x00").await.unwrap();
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

    let (mut r, mut w) = s.into_split();
    let payload = vec![0xAAu8; 128 * 1024];
    let chunk = payload.len();
    let chunks = total_bytes.div_ceil(chunk);

    let writer = tokio::spawn(async move {
        for _ in 0..chunks {
            if w.write_all(&payload).await.is_err() {
                return;
            }
        }
    });
    let mut received = 0usize;
    let mut buf = vec![0u8; chunk];
    while received < total_bytes {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => received += n,
        }
    }
    let _ = writer.await;
    received
}

/// `streams` concurrent transfers; returns aggregate MB/s.
async fn measure(
    addr: SocketAddr,
    target: Option<SocketAddr>,
    total_bytes: usize,
    streams: usize,
) -> f64 {
    let t0 = Instant::now();
    let per = total_bytes / streams;
    let mut handles = Vec::with_capacity(streams);
    for _ in 0..streams {
        handles.push(tokio::spawn(transfer_once(addr, target, per)));
    }
    let mut received = 0usize;
    for h in handles {
        received += h.await.unwrap();
    }
    let elapsed = t0.elapsed().as_secs_f64();
    assert_eq!(
        received,
        per * streams,
        "transfer was truncated: proxy dropped the connection"
    );
    (received as f64 / 1_048_576.0) / elapsed
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

fn spawn_proxy(bin: &PathBuf, config: &str, label: &'static str, extra_args: &[&str]) -> ProxyProc {
    assert!(
        bin.is_file(),
        "proxy binary not found: {} (build it first, e.g. `cargo build --release -p flux-core`)",
        bin.display()
    );
    let cfg_path = std::env::temp_dir().join(format!("bench_{label}.json"));
    std::fs::write(&cfg_path, config).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c", cfg_path.to_str().unwrap()])
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));
    let pid = child.id();
    ProxyProc {
        child,
        pid,
        addr: "127.0.0.1:0".parse().unwrap(),
    }
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
    println!("echo server:            {echo}");
    println!(
        "payload:                {} MB per measurement, {} concurrent stream(s), {} interleaved rounds",
        args.mb, args.streams, args.rounds
    );

    // ---- flux-core ----
    let flux_port = get_free_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{ "tag": "in", "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {flux_port} }}, "protocol": {{ "type": "socks" }} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    );
    let mut flux = spawn_proxy(&args.flux_bin, &flux_cfg, "flux", &["-f", "json"]);
    flux.addr = format!("127.0.0.1:{flux_port}").parse()?;
    wait_for_listener(flux.addr, "flux-core", Duration::from_secs(15)).await;

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
                p.addr = format!("127.0.0.1:{port}").parse()?;
                wait_for_listener(p.addr, "sing-box", Duration::from_secs(15)).await;
                Some(p)
            }
            _ => {
                println!("sing-box:               not found, comparison skipped");
                None
            }
        }
    } else {
        None
    };

    let total_bytes = args.mb * 1024 * 1024;
    let streams = args.streams;

    // Warm-up (page cache, connection pools, JIT-less but still: task warm-up).
    let _ = measure(echo, None, 16 * 1024 * 1024, streams).await;
    let _ = measure(flux.addr, Some(echo), 16 * 1024 * 1024, streams).await;
    if let Some(sb) = &singbox {
        let _ = measure(sb.addr, Some(echo), 16 * 1024 * 1024, streams).await;
    }

    let mut direct_samples = Vec::with_capacity(args.rounds);
    let mut flux_samples = Vec::with_capacity(args.rounds);
    let mut singbox_samples = Vec::with_capacity(args.rounds);
    let mut flux_cpu = 0.0f64;
    let mut singbox_cpu = 0.0f64;

    let flux_cost_before = read_proc_cost(flux.pid);
    let singbox_cost_before = singbox.as_ref().and_then(|p| read_proc_cost(p.pid));

    for round in 1..=args.rounds {
        let d = measure(echo, None, total_bytes, streams).await;
        let f = measure(flux.addr, Some(echo), total_bytes, streams).await;
        flux_cpu += read_proc_cost(flux.pid).map(|c| c.cpu_secs).unwrap_or(0.0)
            - flux_cost_before.map(|c| c.cpu_secs).unwrap_or(0.0);
        let s = if let Some(sb) = &singbox {
            Some(measure(sb.addr, Some(echo), total_bytes, streams).await)
        } else {
            None
        };
        if let (Some(c), Some(sb)) = (singbox_cost_before, &singbox) {
            singbox_cpu += read_proc_cost(sb.pid).map(|x| x.cpu_secs).unwrap_or(0.0) - c.cpu_secs;
        }
        print!("  round {round}: direct {d:7.1}  flux {f:7.1}");
        if let Some(s) = s {
            print!("  sing-box {s:7.1}");
        }
        println!("  (MB/s)");
        direct_samples.push(d);
        flux_samples.push(f);
        if let Some(s) = s {
            singbox_samples.push(s);
        }
    }

    let (d_med, d_min, d_max) = Stats::from_samples(direct_samples);
    let (f_med, f_min, f_max) = Stats::from_samples(flux_samples);
    let flux_peak_rss = read_proc_cost(flux.pid).map(|c| c.peak_rss_kb);

    let mut rows: Vec<(String, Stats)> = vec![
        (
            "Direct TCP loopback (baseline)".into(),
            Stats {
                median: d_med,
                min: d_min,
                max: d_max,
                cpu_secs: None,
                peak_rss_kb: None,
            },
        ),
        (
            "flux-core".into(),
            Stats {
                median: f_med,
                min: f_min,
                max: f_max,
                cpu_secs: Some(flux_cpu),
                peak_rss_kb: flux_peak_rss,
            },
        ),
    ];

    if !singbox_samples.is_empty() {
        let (s_med, s_min, s_max) = Stats::from_samples(singbox_samples);
        let rss = singbox
            .as_ref()
            .and_then(|p| read_proc_cost(p.pid))
            .map(|c| c.peak_rss_kb);
        rows.push((
            "sing-box".into(),
            Stats {
                median: s_med,
                min: s_min,
                max: s_max,
                cpu_secs: Some(singbox_cpu),
                peak_rss_kb: rss,
            },
        ));
    }

    println!("\n{}", "=".repeat(96));
    println!(
        "THROUGHPUT — median of {} interleaved rounds, {} MB / {} stream(s)",
        args.rounds, args.mb, args.streams
    );
    println!("{}", "=".repeat(96));
    println!(
        "{:<32} {:>10} {:>10} {:>10} {:>12} {:>10}",
        "Target", "median", "min", "max", "MB moved", "CPU s/GB"
    );
    println!("{}", "-".repeat(96));
    let gb = (args.rounds * args.mb) as f64 / 1024.0;
    for (label, s) in &rows {
        let cpu_per_gb = s
            .cpu_secs
            .map(|c| format!("{:.2}", c / gb))
            .unwrap_or_else(|| "-".into());
        println!(
            "{:<32} {:>10.1} {:>10.1} {:>10.1} {:>12} {:>10}",
            label,
            s.median,
            s.min,
            s.max,
            format!("{:.0} MB", args.rounds as f64 * args.mb as f64),
            cpu_per_gb
        );
    }
    println!("{}", "-".repeat(96));

    let flux_pct = (f_med / d_med - 1.0) * 100.0;
    println!(
        "flux-core vs direct baseline: {:+.1}%  ({:.1} MB/s of {:.1} MB/s)",
        flux_pct, f_med, d_med
    );
    if let Some(sb) = rows.iter().find(|(l, _)| l == "sing-box") {
        let vs = (f_med / sb.1.median - 1.0) * 100.0;
        println!(
            "flux-core vs sing-box:        {:+.1}%  ({:.1} vs {:.1} MB/s)",
            vs, f_med, sb.1.median
        );
        if let (Some(fc), Some(sc)) = (rows[1].1.cpu_secs, sb.1.cpu_secs)
            && fc > 0.0
            && sc > 0.0
        {
            println!(
                "CPU cost per GB (lower is better): flux-core {:.2}s, sing-box {:.2}s ({:+.1}%)",
                fc / gb,
                sc / gb,
                (fc / sc - 1.0) * 100.0
            );
        }
        if let (Some(fr), Some(sr)) = (rows[1].1.peak_rss_kb, sb.1.peak_rss_kb) {
            println!(
                "Peak RSS:                      flux-core {} MiB, sing-box {} MiB",
                fr / 1024,
                sr / 1024
            );
        }
    }
    println!("{}", "=".repeat(96));
    Ok(())
}
