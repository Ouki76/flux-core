//! TUN datapath benchmark: how fast is flux-core's userspace (smoltcp) TUN stack?
//!
//! Measures the full loop
//!
//! ```text
//! client socket -> kernel -> TUN device -> smoltcp stack -> dispatcher (echo)
//!               -> smoltcp stack -> TUN device -> kernel -> client socket
//! ```
//!
//! and, for comparison, a plain kernel loopback TCP echo with the exact same
//! client/echo code path (minus the TUN device and the userspace stack). The
//! difference is the price of doing TCP in userspace.
//!
//! Running it needs `CAP_NET_ADMIN` (a TUN device + routes). Passwordless sudo
//! is not required: like the integration test suite, the binary re-executes
//! itself inside `unshare --user --map-root-user --net` when it is not root, so
//! the whole measurement happens in a throwaway network namespace.
//!
//! ```text
//! cargo build --release -p flux-core --example bench_tun
//! ./target/release/examples/bench_tun            # 5 rounds, median reported
//! ./target/release/examples/bench_tun --bytes 1073741824   # bigger transfer
//! ```
//!
//! Reported metrics:
//!
//! * `MiB/s` — end-to-end goodput of the echoed stream (both directions are
//!   carried, but the byte count is payload sent = payload received).
//! * `CPU s/GB` — process CPU time (all threads, from `/proc/self/stat`) spent
//!   per gigabyte of payload, i.e. how expensive the datapath is per byte.
//! * `overhead` — TUN vs. kernel-loopback baseline, in percent.

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flux_app::{Config, Instance};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};
use tokio::time::timeout;

/// Set on the re-executed child so it does not recurse into `unshare`.
const NS_CHILD_ENV: &str = "FLUX_BENCH_TUN_NS_CHILD";

const TUN: &str = "fluxtunbench";
const TUN_LOCAL: &str = "10.77.0.1";
const CLIENT: &str = "10.77.0.2";
const TARGET: &str = "10.77.66.2";
const PORT: u16 = 19_900;

struct Args {
    rounds: usize,
    bytes_per_round: u64,
    chunk: usize,
    /// TUN device MTU. A TUN carries exactly one IP packet per read()/write(),
    /// so this sets how many bytes each syscall can move.
    mtu: usize,
    /// Skip the kernel-loopback comparison rounds. Iterating on a datapath
    /// change wants the TUN rounds and their CPU split only; the baseline costs
    /// wall time and adds unrelated syscall noise to the same process.
    baseline: bool,
}

impl Args {
    fn parse() -> Self {
        let mut args = Self {
            rounds: 5,
            bytes_per_round: 256 * 1024 * 1024,
            chunk: 64 * 1024,
            mtu: 1500,
            baseline: true,
        };
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            let mut take = |name: &str| -> Option<u64> {
                if a == name {
                    it.next().and_then(|v| v.parse().ok())
                } else {
                    None
                }
            };
            if let Some(v) = take("--rounds") {
                args.rounds = v.max(1) as usize;
            } else if let Some(v) = take("--bytes") {
                args.bytes_per_round = v.max(1);
            } else if let Some(v) = take("--mtu") {
                args.mtu = (v as usize).clamp(576, 65535);
            } else if let Some(v) = take("--chunk") {
                args.chunk = (v as usize).clamp(1024, 1024 * 1024);
            } else if a == "--no-baseline" {
                args.baseline = false;
            } else if a == "--help" || a == "-h" {
                println!(
                    "usage: bench_tun [--rounds N] [--bytes BYTES_PER_ROUND] [--chunk BYTES] \
                     [--mtu BYTES] [--no-baseline]"
                );
                std::process::exit(0);
            }
        }
        args
    }
}

fn main() {
    let args = Args::parse();

    // SAFETY: `geteuid` takes no arguments and touches no memory.
    if std::env::var_os(NS_CHILD_ENV).is_none() && unsafe { libc::geteuid() } != 0 {
        // Re-run ourselves as root inside a private user+network namespace.
        let exe = std::env::current_exe().expect("current_exe");
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--"])
            .arg(&exe)
            .args(std::env::args().skip(1))
            .env(NS_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => std::process::exit(0),
            Ok(s) => {
                eprintln!("bench_tun: child inside the namespace failed ({s})");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!(
                    "bench_tun: cannot re-execute inside `unshare --user --map-root-user --net` \
                     ({e}). A TUN device needs CAP_NET_ADMIN; run as root or enable \
                     unprivileged user namespaces."
                );
                std::process::exit(1);
            }
        }
    }

    // SAFETY: no arguments or a plain `rusage` out-parameter owned by this frame.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("bench_tun: still not root after re-exec — aborting");
        std::process::exit(1);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(run(args));
}

fn sh(cmd: &str) -> Result<String, String> {
    let out = Command::new("sh")
        .args(["-c", cmd])
        .output()
        .map_err(|e| format!("spawn `sh -c {cmd}`: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("{cmd}: {} — {}", out.status, text.trim()))
    }
}

fn sh_ok(cmd: &str) -> String {
    match sh(cmd) {
        Ok(o) => o,
        Err(e) => panic!("[bench setup] {e}"),
    }
}

/// Process CPU time (user + system, all threads) in seconds.
///
/// `getrusage(RUSAGE_SELF)` reports microseconds, which matters because a
/// whole round of this benchmark runs in well under a second. (`/proc/self/stat`
/// only has 10 ms `USER_HZ` ticks and reads as 0.00 for the faster runs.)
fn proc_cpu_seconds() -> f64 {
    let (u, s) = proc_cpu_split();
    u + s
}

/// Process CPU time split into `(user, system)` seconds, all threads.
fn proc_cpu_split() -> (f64, f64) {
    #[repr(C)]
    struct Timeval {
        tv_sec: libc::c_long,
        tv_usec: libc::c_long,
    }
    #[repr(C)]
    struct Rusage {
        ru_utime: Timeval,
        ru_stime: Timeval,
        // The remainder is unused here; over-allocate so the kernel's larger
        // struct is never written past the end of ours.
        rest: [libc::c_long; 32],
    }
    // SAFETY: no arguments or a plain `rusage` out-parameter owned by this frame.
    let mut ru: Rusage = unsafe { std::mem::zeroed() };
    // 0 == RUSAGE_SELF
    // SAFETY: no arguments or a plain `rusage` out-parameter owned by this frame.
    let rc = unsafe { libc::getrusage(0, &mut ru as *mut Rusage as *mut libc::rusage) };
    if rc != 0 {
        return (0.0, 0.0);
    }
    let user = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6;
    let sys = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6;
    (user, sys)
}

/// Per-thread CPU seconds, to show which stage of the datapath burns the CPU.
fn thread_cpu() -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
        return out;
    };
    for e in dir.flatten() {
        let Ok(s) = std::fs::read_to_string(e.path().join("stat")) else {
            continue;
        };
        // "pid (comm) state ppid ..." — utime/stime are fields 14 and 15.
        let Some(close) = s.rfind(')') else { continue };
        let rest: Vec<&str> = s[close + 1..].split_whitespace().collect();
        if rest.len() < 15 {
            continue;
        }
        let ut: u64 = rest[11].parse().unwrap_or(0);
        let st: u64 = rest[12].parse().unwrap_or(0);
        let comm = s[s.find('(').map(|i| i + 1).unwrap_or(0)..close].to_string();
        out.push((ut + st, comm));
    }
    out.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
    out
}

struct Echo {
    addr: SocketAddr,
    served: Arc<AtomicU64>,
}

/// Kernel-level TCP echo server (the "remote" end).
async fn start_tcp_echo(addr: SocketAddr) -> Echo {
    let listener = TcpListener::bind(addr).await.expect("echo bind");
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicU64::new(0));
    let s = served.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            let s = s.clone();
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(socket);
                let mut buf = vec![0u8; 256 * 1024];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            s.fetch_add(n as u64, Ordering::Relaxed);
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Echo { addr, served }
}

/// Pushes `bytes` through a fresh connection to `dst` and reads the echo back.
/// Returns when everything has been echoed; panics on stall.
async fn measure_once(src: SocketAddr, dst: SocketAddr, bytes: u64, chunk: usize) -> Duration {
    let start = Instant::now();
    let sock = TcpSocket::new_v4().expect("socket");
    sock.bind(src).expect("bind client source");
    sock.set_nodelay(true).expect("nodelay");
    let stream = timeout(Duration::from_secs(20), sock.connect(dst))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let (mut r, mut w) = tokio::io::split(stream);

    let sent = Arc::new(AtomicU64::new(0));
    let read = Arc::new(AtomicU64::new(0));
    let payload = vec![0xA5u8; chunk];
    let sent_counter = sent.clone();
    let writer = tokio::spawn(async move {
        let mut sent = 0u64;
        while sent < bytes {
            let n = std::cmp::min(chunk as u64, bytes - sent) as usize;
            w.write_all(&payload[..n]).await.expect("write");
            sent += n as u64;
            sent_counter.store(sent, Ordering::Relaxed);
        }
        w.shutdown().await.ok();
    });

    {
        // Progress reporter: a stalled transfer must be diagnosable, not just a
        // timeout. Prints once per second while the round is in flight.
        let (sent, read) = (sent.clone(), read.clone());
        tokio::spawn(async move {
            let mut last = (0u64, 0u64);
            let mut idle = 0u32;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = (sent.load(Ordering::Relaxed), read.load(Ordering::Relaxed));
                if now == last {
                    idle += 1;
                    // Only report a genuine stall (>= 4 s without progress);
                    // the reporter itself must not spam a healthy run.
                    if idle == 2 {
                        eprintln!(
                            "    !! no progress: wrote {} MiB, read back {} MiB",
                            now.0 / (1024 * 1024),
                            now.1 / (1024 * 1024)
                        );
                    }
                } else {
                    idle = 0;
                }
                last = now;
            }
        });
    }

    let mut got = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    while got < bytes {
        let n = match timeout(Duration::from_secs(30), r.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read failed after {got}/{bytes} bytes: {e}"),
            Err(_) => {
                eprintln!(
                    "!! stalled after {got}/{bytes} bytes ({} missing) — socket state:",
                    bytes - got
                );
                if let Ok(out) = sh("ss -tin state established") {
                    eprintln!("{out}");
                }
                if let Ok(out) = sh(&format!("ip -s link show {TUN}")) {
                    eprintln!("{out}");
                }
                if let Ok(out) = sh(
                    "nstat -az 2>/dev/null | grep -Ei 'Tcp(Retrans|Ext|InErrs|OutSegs|InSegs)|IpInDiscards'",
                ) {
                    eprintln!("{out}");
                }
                panic!("read stalled after {got} of {bytes} bytes");
            }
        };
        if n == 0 {
            break;
        }
        got += n as u64;
        read.store(got, Ordering::Relaxed);
    }
    writer.await.expect("writer task");
    assert_eq!(got, bytes, "echoed {} of {} bytes", got, bytes);

    // The half-close must be propagated: after all payload is back, the peer's
    // FIN should follow promptly. A timeout here means the tunnel keeps the
    // connection open forever (leaked socket).
    match timeout(Duration::from_secs(5), r.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => eprintln!("!! unexpected {n} trailing bytes after the payload"),
        Ok(Err(e)) => eprintln!("!! read error while waiting for FIN: {e}"),
        Err(_) => eprintln!(
            "!! no FIN after the payload: the tunnel leaked the connection \
             (client stays in FIN-WAIT-2)"
        ),
    }
    start.elapsed()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = v.len() / 2;
    if v.len().is_multiple_of(2) {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    }
}

struct Report {
    label: &'static str,
    mib_s: f64,
    cpu_s_per_gb: f64,
    rounds: Vec<f64>,
}

impl Report {
    fn print(&self) {
        let spread = format!(
            "{:.1}..{:.1} MiB/s",
            self.rounds.first().copied().unwrap_or(0.0),
            self.rounds.last().copied().unwrap_or(0.0)
        );
        println!(
            "{:<28} {:>10.1} MiB/s  {:>8.2} CPU s/GB   rounds: {spread}",
            self.label, self.mib_s, self.cpu_s_per_gb
        );
    }
}

async fn run(args: Args) {
    // --- fresh namespace plumbing -------------------------------------------
    sh_ok("ip link set lo up");
    // The client's source address is local; the target is routed into the TUN.
    sh_ok(&format!("ip addr add {CLIENT}/32 dev lo"));

    let echo = start_tcp_echo(SocketAddr::from(([127, 0, 0, 1], PORT))).await;

    // --- TUN stack ----------------------------------------------------------
    let cfg = Config::from_json_str(&format!(
        r#"{{ "inbounds": [ {{ "type": "tun", "tag": "tun-in", "interface_name": "{TUN}", "mtu": {} }} ],
             "outbounds": [ {{ "type": "direct", "tag": "direct" }} ] }}"#,
        args.mtu
    ))
    .expect("config");
    let instance = Instance::new(cfg).expect("instance");
    instance.start().await.expect("tun inbound start");

    for _ in 0..300 {
        if sh(&format!("ip link show {TUN}")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    sh_ok(&format!("ip link set {TUN} up"));
    sh_ok(&format!("ip addr add {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {TUN}"));

    // The proxy's own dial to the recovered destination goes to the echo
    // server; the client's payload is the only thing that can reach the TUN.
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));

    let client_src: SocketAddr = format!("{CLIENT}:0").parse().unwrap();
    let tun_dst: SocketAddr = format!("{TARGET}:{PORT}").parse().unwrap();
    let kernel_dst = echo.addr;

    println!(
        "bench_tun: {} rounds/{} MiB payload, {} KiB write chunk\n\
         TUN device '{}': client {} -> {} -> flux smoltcp -> direct -> 127.0.0.1:{}",
        args.rounds,
        args.bytes_per_round / (1024 * 1024),
        args.chunk / 1024,
        TUN,
        CLIENT,
        TARGET,
        PORT
    );

    // --- warm-up (page faults, ARP, TCP slow start) -------------------------
    let warm = std::cmp::min(args.bytes_per_round, 16 * 1024 * 1024);
    measure_once(client_src, tun_dst, warm, args.chunk).await;
    if args.baseline {
        measure_once(client_src, kernel_dst, warm, args.chunk).await;
    }

    // --- TUN rounds ---------------------------------------------------------
    let mut tun_rounds = Vec::new();
    let mut tun_cpu = Vec::new();
    let mut tun_user = Vec::new();
    let mut tun_sys = Vec::new();
    for i in 0..args.rounds {
        let (u0, s0) = proc_cpu_split();
        let t0 = Instant::now();
        measure_once(client_src, tun_dst, args.bytes_per_round, args.chunk).await;
        let elapsed = t0.elapsed();
        let (u1, s1) = proc_cpu_split();
        let (cpu, cpu_user, cpu_sys) = (u1 - u0 + s1 - s0, u1 - u0, s1 - s0);
        let mib_s = args.bytes_per_round as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        let gb = args.bytes_per_round as f64 / 1e9;
        tun_rounds.push(mib_s);
        tun_cpu.push(cpu / gb);
        tun_user.push(cpu_user / gb);
        tun_sys.push(cpu_sys / gb);
        println!(
            "  tun    round {}/{}: {:8.2} s  {:9.1} MiB/s  {:.2} CPU s/GB \
             (user {:.2}, sys {:.2})",
            i + 1,
            args.rounds,
            elapsed.as_secs_f64(),
            mib_s,
            cpu / gb,
            cpu_user / gb,
            cpu_sys / gb
        );
    }

    // --- kernel loopback baseline ------------------------------------------
    let mut base_rounds = Vec::new();
    let mut base_cpu = Vec::new();
    if args.baseline {
        for i in 0..args.rounds {
            let cpu0 = proc_cpu_seconds();
            let t0 = Instant::now();
            measure_once(client_src, kernel_dst, args.bytes_per_round, args.chunk).await;
            let elapsed = t0.elapsed();
            let cpu = proc_cpu_seconds() - cpu0;
            let mib_s = args.bytes_per_round as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
            let gb = args.bytes_per_round as f64 / 1e9;
            base_rounds.push(mib_s);
            base_cpu.push(cpu / gb);
            println!(
                "  kernel round {}/{}: {:8.2} s  {:9.1} MiB/s  {:.2} CPU s/GB",
                i + 1,
                args.rounds,
                elapsed.as_secs_f64(),
                mib_s,
                cpu / gb
            );
        }
    }

    let tun = Report {
        label: "TUN (smoltcp userspace)",
        mib_s: median(tun_rounds.clone()),
        cpu_s_per_gb: median(tun_cpu),
        rounds: sorted(tun_rounds),
    };

    println!("\n=== results (median of {}) ===", args.rounds);
    tun.print();
    println!(
        "  cpu split: user {:.2} s/GB, sys {:.2} s/GB",
        median(tun_user),
        median(tun_sys)
    );
    if args.baseline {
        let base = Report {
            label: "kernel loopback (baseline)",
            mib_s: median(base_rounds.clone()),
            cpu_s_per_gb: median(base_cpu),
            rounds: sorted(base_rounds),
        };
        base.print();
        let throughput_ratio = base.mib_s / tun.mib_s;
        let cpu_ratio = tun.cpu_s_per_gb / base.cpu_s_per_gb.max(f64::MIN_POSITIVE);
        println!(
            "TUN overhead vs kernel baseline: {:.1}% of the kernel loopback throughput \
             ({:.2}x slower), {:.2}x the CPU per byte",
            tun.mib_s / base.mib_s * 100.0,
            throughput_ratio,
            cpu_ratio
        );
    }
    println!(
        "served by echo server: {} MiB",
        echo.served.load(Ordering::Relaxed) / (1024 * 1024)
    );
    // Device-level counters. A datapath change that makes the userspace pump
    // keep up but lets the kernel-side TUN queue overflow would look like a
    // throughput *win* in `MiB/s` while actually dropping segments (and paying
    // for it in retransmissions), so the drops/errors are part of the result.
    println!("{}", tun_link_counters(TUN));
    if std::env::var_os("FLUX_BENCH_THREADS").is_some() {
        println!("per-thread CPU (ticks of 10 ms):");
        for (ticks, comm) in thread_cpu() {
            if ticks > 0 {
                println!("  {:>6.2} s  {}", ticks as f64 / 100.0, comm);
            }
        }
    }

    let _ = instance.stop().await;
}

fn sorted(v: Vec<f64>) -> Vec<f64> {
    let mut v = v;
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}

/// `RX`/`TX` bytes, packets, errors and drops of the TUN device.
///
/// Parsed out of `ip -s link show` rather than `/sys/class/net/...`: sysfs is
/// not per network namespace, so inside the throwaway namespace it would read
/// the host device (or nothing), while `ip` asks netlink.
fn tun_link_counters(dev: &str) -> String {
    let Ok(out) = sh(&format!("ip -s link show {dev}")) else {
        return "device counters: unavailable".to_string();
    };
    // "RX:  bytes packets errors dropped missed mcast" followed by the numbers
    // on the next line; same for TX.
    let mut lines = out.lines().map(str::trim);
    let mut grabbed = Vec::new();
    while let Some(line) = lines.next() {
        if line.starts_with("RX:") || line.starts_with("TX:") {
            let dir = if line.starts_with("RX:") { "rx" } else { "tx" };
            if let Some(nums) = lines.next() {
                let n: Vec<&str> = nums.split_whitespace().collect();
                if n.len() >= 4 {
                    grabbed.push(format!(
                        "{dir} {:>10} B {:>8} pkt {:>4} err {:>4} drop",
                        n[0], n[1], n[2], n[3]
                    ));
                }
            }
        }
    }
    if grabbed.is_empty() {
        "device counters: unparsed".to_string()
    } else {
        format!("device counters: {}", grabbed.join("  |  "))
    }
}
