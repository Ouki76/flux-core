//! Head-to-head **tunnel** throughput matrix: `flux-core` vs `sing-box`.
//!
//! Every other benchmark in this repository measures one stack against itself,
//! or against a direct loopback socket. That establishes a ceiling but says
//! nothing about competitiveness: a number is only meaningful next to a rival
//! implementation doing the same work on the same box.
//!
//! This harness runs, for each protocol/transport pair, two *self-contained*
//! tunnels — `flux-core` client → `flux-core` server, and `sing-box` client →
//! `sing-box` server — over the identical shape:
//!
//! ```text
//!   harness ──SOCKS5──> client proxy ══tunnel══> server proxy ──> echo server
//!                                                     (and back)
//! ```
//!
//! Each round moves one pipelined request/response stream of `--mb` MiB through
//! a freshly dialled tunnel connection and records
//!
//!   * MB/s (MiB/s, 1 MiB = 1048576 B) of payload — both end-to-end and with the
//!     connection-setup phase excluded ("bulk"), because a protocol whose
//!     handshake costs seconds would otherwise be misread as slow crypto, and
//!   * CPU-seconds burned by the **two tunnel processes** per GiB of payload,
//!     summed over every thread's `/proc/<pid>/task/*/schedstat` (nanosecond
//!     resolution; the per-process `/proc/<pid>/stat` ticks are only a fallback,
//!     since a proxy does its work on worker threads and the thread-group leader
//!     alone reports ~0).
//!
//! The harness process owns the client endpoint *and* the echo server, so its
//! own CPU is never charged to either stack.
//!
//! One subtlety is load-bearing: the transfer task must keep the socket's write
//! half **open** until the echo has come back in full. Dropping it sends a FIN,
//! and a proxy that tears the whole connection down when one direction hits EOF
//! (sing-box does) then truncates the download at a random offset.
//!
//! Rounds alternate which stack goes first (odd rounds flux, even rounds
//! sing-box) so a thermal/scheduler drift inside a scenario cannot
//! systematically favour one side; scenarios themselves run sequentially.
//!
//! Usage:
//!   cargo run --release --example bench_matrix -- [options]
//!
//! Options:
//!   --rounds N      interleaved measurement rounds per pair (default 3)
//!   --mb N          MiB of payload per round (default 200)
//!   --only SUBSTR   only run protocols whose name contains SUBSTR (case-insensitive)
//!   --timeout SECS  per-transfer deadline; expiring is recorded as a result (default 120)
//!   --no-singbox    skip the sing-box column (it degrades to "not installed" anyway)
//!   --no-xray       skip the xray column (same, and rows without an xray
//!                   equivalent say so)
//!   --flux PATH     flux-core binary (default ./target/release/flux-core)
//!   --singbox PATH  sing-box binary (default from PATH, then ~/.local/bin)
//!
//! Typical run:
//!   cargo build --release -p flux-core --bin flux-core --example bench_matrix
//!   ./target/release/examples/bench_matrix --rounds 3 --mb 200

// The xray configs were validated against the real binary in
// `tests/test_xray_matrix_configs.rs`; reusing them here means the benchmark cannot
// drift from a configuration anybody has actually proven works.
#[path = "../tests/xray_matrix_configs.rs"]
mod xray_matrix_configs;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Fixed test material
// ---------------------------------------------------------------------------

const UUID: &str = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";
const TROJAN_PASSWORD: &str = "bench-trojan-secret-0123";
const SS_AEAD_PASSWORD: &str = "bench-ss-aead-secret-4567";
/// "0123456789abcdef" — the 16-byte key `2022-blake3-aes-128-gcm` requires.
const SS2022_KEY_B64: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
const TLS_SNI: &str = "example.com";
const REALITY_SNI: &str = "www.microsoft.com";
const REALITY_SHORT_ID: &str = "01020304";
const WS_PATH: &str = "/bench-ws";
const GRPC_SERVICE: &str = "bench-grpc";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Args {
    rounds: usize,
    mb: usize,
    only: Option<String>,
    timeout: Duration,
    with_singbox: bool,
    with_xray: bool,
    flux_bin: PathBuf,
    singbox_bin: Option<PathBuf>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            rounds: 3,
            mb: 200,
            only: None,
            timeout: Duration::from_secs(120),
            with_singbox: true,
            with_xray: true,
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
                "--only" => args.only = Some(take(&mut i)?.to_ascii_lowercase()),
                "--timeout" => {
                    args.timeout =
                        Duration::from_secs(take(&mut i)?.parse().map_err(|e| format!("{e}"))?)
                }
                "--no-singbox" => args.with_singbox = false,
                "--no-xray" => args.with_xray = false,
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
        if args.rounds == 0 || args.mb == 0 || args.timeout.is_zero() {
            return Err("--rounds, --mb and --timeout must be >= 1".into());
        }
        Ok(args)
    }

    fn usage() -> &'static str {
        "usage: bench_matrix [--rounds N] [--mb N] [--only SUBSTR] [--timeout SECS] \
         [--no-singbox] [--flux PATH] [--singbox PATH]"
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

/// On-CPU nanoseconds of a process, from `/proc/<pid>/schedstat` when the
/// kernel provides it (nanosecond resolution), else `/proc/<pid>/stat` ticks
/// (10 ms resolution, too coarse for sub-second transfers).
fn read_cpu_secs(pid: u32) -> Option<f64> {
    // `/proc/<pid>/schedstat` is **per task**, not per process: for a proxy that
    // does its work on worker threads the leader thread alone would report ~0.
    // Summing every thread's `schedstat` gives nanosecond resolution for the
    // whole process. Threads that exit mid-round lose their accumulation, which
    // is why the tick-based total below is kept as a cross-check fallback.
    let mut total_ns: u64 = 0;
    let mut any = false;
    if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path().join("schedstat"))
                && let Some(ns) = text
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
            {
                total_ns += ns;
                any = true;
            }
        }
    }
    if any {
        return Some(total_ns as f64 / 1e9);
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields 14/15 are utime/stime; `comm` may contain spaces and parens, so
    // split after the closing ')' of field 2.
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    // USER_HZ is 100 on every Linux configuration we support.
    Some((utime + stime) as f64 / 100.0)
}

/// Kernel-visible state of a possibly-stuck process: overall state, what each
/// thread is waiting in, and how much CPU it has burned.
fn process_snapshot(pid: u32) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let state = status
        .lines()
        .find(|l| l.starts_with("State:"))
        .unwrap_or("State: ?")
        .trim()
        .to_string();
    let threads: usize = status
        .lines()
        .find(|l| l.starts_with("Threads:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cpu = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            let fields: Vec<&str> = s.rsplit(')').next()?.split_whitespace().collect();
            // utime/stime are fields 14/15 of the full line; after the comm split
            // they are 11/12 of the remainder.
            let utime: u64 = fields.get(11)?.parse().ok()?;
            let stime: u64 = fields.get(12)?.parse().ok()?;
            Some(utime + stime)
        })
        .unwrap_or(0);
    let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut waits: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for entry in rd.flatten().take(6) {
            let tid = entry.file_name();
            let s =
                std::fs::read_to_string(format!("/proc/{pid}/task/{}/stat", tid.to_string_lossy()))
                    .ok()
                    .and_then(|line| line.rsplit(')').next().map(|r| r.trim().chars().next()))
                    .flatten();
            if let Some(s) = s {
                waits.push(format!("{}({s})", tid.to_string_lossy()));
            }
        }
    }
    Some(format!(
        "{state}; threads={threads}; cpu_ticks={cpu}; wchan={}; task states: {}",
        if wchan.is_empty() { "-" } else { &wchan },
        waits.join(" ")
    ))
}

struct ProxyProc {
    child: Child,
    pid: u32,
    log_path: PathBuf,
}

impl ProxyProc {
    fn spawn(bin: &Path, log_path: &Path, argv: &[&str]) -> Result<Self, String> {
        let mut cmd = Command::new(bin);
        // Both streams into the same file: the daemons log to stdout, and capturing
        // only stderr made every "see the log" diagnostic print "(empty)" — which cost
        // a whole hunt for the stall below.
        let log = std::fs::File::create(log_path).map_err(|e| format!("log file: {e}"))?;
        let log_err = log.try_clone().map_err(|e| format!("log file: {e}"))?;
        cmd.args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        let child = cmd.spawn().map_err(|e| {
            format!(
                "failed to spawn {}: {e} (build it first, e.g. `cargo build --release -p flux-core`)",
                bin.display()
            )
        })?;
        let pid = child.id();
        Ok(Self {
            child,
            pid,
            log_path: log_path.to_path_buf(),
        })
    }

    fn cpu_secs(&self) -> Option<f64> {
        read_cpu_secs(self.pid)
    }

    /// Last few lines of the daemon's stderr, for failure reasons.
    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let start = lines.len().saturating_sub(2);
        let tail = lines[start..].join(" | ");
        // Strip ANSI colour codes emitted by sing-box.
        let mut clean = String::with_capacity(tail.len());
        let mut chars = tail.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                clean.push(c);
            }
        }
        clean
    }
}

impl Drop for ProxyProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if keep_logs() {
            eprintln!("kept log: {}", self.log_path.display());
        } else {
            let _ = std::fs::remove_file(&self.log_path);
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy stacks
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Stack {
    Flux,
    Singbox,
    Xray,
}

impl Stack {
    fn label(self) -> &'static str {
        match self {
            Stack::Flux => "flux-core",
            Stack::Singbox => "sing-box",
            Stack::Xray => "xray",
        }
    }

    fn argv(self, cfg: &Path) -> Vec<String> {
        match self {
            // flux-core needs the format hint because examples write `.json`.
            Stack::Flux => vec![
                "run".into(),
                "-c".into(),
                cfg.display().to_string(),
                "-f".into(),
                "json".into(),
            ],
            Stack::Singbox | Stack::Xray => {
                vec!["run".into(), "-c".into(), cfg.display().to_string()]
            }
        }
    }
}

/// One running tunnel: the server proxy, the client proxy and the client's
/// SOCKS5 entry point. Both processes are what the CPU column charges.
struct Tunnel {
    server: ProxyProc,
    client: ProxyProc,
    socks: SocketAddr,
}

impl Tunnel {
    fn cpu_secs(&self) -> Option<f64> {
        Some(self.server.cpu_secs()? + self.client.cpu_secs()?)
    }

    /// The two tunnels' stderr, which is where a parked relay says so.
    fn log_tail(&self) -> String {
        let mut out = String::new();
        for (name, proc) in [("server", &self.server), ("client", &self.client)] {
            let tail = proc.log_tail();
            if !tail.is_empty() {
                out.push_str(&format!("  -- {name} --\n{tail}\n"));
            }
        }
        out
    }

    fn why(&self, ctx: &str) -> String {
        // A hang is the one failure whose cause cannot be read from a log: the
        // process is still alive, just not moving. Dump what the kernel knows about
        // it (state, wait channel, per-thread state) so the next occurrence is
        // attributable instead of being called a flake.
        let mut stalls = String::new();
        for (label, proc) in [("server", &self.server), ("client", &self.client)] {
            if let Some(snap) = process_snapshot(proc.pid) {
                stalls.push_str(&format!("\n  {label} pid={}: {snap}", proc.pid));
            }
        }
        let s = self.server.log_tail();
        let c = self.client.log_tail();
        let mut detail = String::new();
        if !s.is_empty() {
            detail.push_str(&format!("server: {s}"));
        }
        if !c.is_empty() {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&format!("client: {c}"));
        }
        if !stalls.is_empty() {
            detail.push_str(&stalls);
        }
        if detail.is_empty() {
            format!("{ctx}: no diagnostic output")
        } else {
            format!("{ctx}: {detail}")
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario material
// ---------------------------------------------------------------------------

/// Files and secrets every scenario shares, created once per run.
struct Setup {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    reality_private: String,
    reality_public: String,
    /// TLS 1.3 echo target REALITY servers fetch their certificate from.
    decoy: Option<SocketAddr>,
    /// SHA-256 of the leaf certificate, which an Xray 26 client must pin: the
    /// `allowInsecure` option was removed and a config that uses it is refused.
    cert_sha256_hex: String,
    /// Shadowsocks-2022 pre-shared key (16 bytes, base64).
    ss_password: String,
}

impl Setup {
    fn new() -> anyhow::Result<Self> {
        let dir = std::env::temp_dir().join(format!("bench_matrix_{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string(), TLS_SNI.to_string()])?;
        std::fs::write(&cert, generated.cert.pem())?;
        std::fs::write(&key, generated.key_pair.serialize_pem())?;

        // REALITY needs an X25519 keypair, base64url without padding.
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        let cert_sha256_hex = xray_matrix_configs::cert_sha256_hex(&cert);
        Ok(Self {
            cert,
            key,
            reality_private: b64(secret.to_bytes().as_slice()),
            reality_public: b64(public.as_bytes().as_slice()),
            decoy: None,
            cert_sha256_hex,
            ss_password: xray_matrix_configs::ss2022_password(),
            dir,
        })
    }

    fn cert_str(&self) -> &str {
        self.cert.to_str().unwrap()
    }

    fn key_str(&self) -> &str {
        self.key.to_str().unwrap()
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        if keep_logs() {
            eprintln!("kept configs and logs in {}", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    VlessTcp,
    /// gRPC without TLS, to separate the framing cost from the cipher's.
    VlessGrpcPlain,
    /// VLESS over XHTTP in stream-one mode.
    VlessXhttp,
    VlessWsTls,
    VlessGrpcTls,
    VlessReality,
    VlessRealityVision,
    VmessWsTls,
    TrojanTls,
    Ss2022,
    SsAead,
}

struct Scenario {
    name: &'static str,
    kind: Kind,
    needs_cert: bool,
    needs_decoy: bool,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "VLESS / TCP",
        kind: Kind::VlessTcp,
        needs_cert: false,
        needs_decoy: false,
    },
    Scenario {
        name: "VLESS / XHTTP",
        kind: Kind::VlessXhttp,
        needs_cert: false,
        needs_decoy: false,
    },
    Scenario {
        name: "VLESS / WS + TLS",
        kind: Kind::VlessWsTls,
        needs_cert: true,
        needs_decoy: false,
    },
    Scenario {
        name: "VLESS / gRPC (no TLS)",
        kind: Kind::VlessGrpcPlain,
        needs_cert: false,
        needs_decoy: false,
    },
    Scenario {
        name: "VLESS / gRPC + TLS",
        kind: Kind::VlessGrpcTls,
        needs_cert: true,
        needs_decoy: false,
    },
    Scenario {
        name: "VLESS / REALITY",
        kind: Kind::VlessReality,
        needs_cert: false,
        needs_decoy: true,
    },
    Scenario {
        name: "VLESS / REALITY + Vision",
        kind: Kind::VlessRealityVision,
        needs_cert: false,
        needs_decoy: true,
    },
    Scenario {
        name: "VMess / WS + TLS",
        kind: Kind::VmessWsTls,
        needs_cert: true,
        needs_decoy: false,
    },
    Scenario {
        name: "Trojan / TLS",
        kind: Kind::TrojanTls,
        needs_cert: true,
        needs_decoy: false,
    },
    Scenario {
        name: "Shadowsocks-2022 / blake3-aes-128-gcm",
        kind: Kind::Ss2022,
        needs_cert: false,
        needs_decoy: false,
    },
    Scenario {
        name: "Shadowsocks-AEAD / aes-256-gcm",
        kind: Kind::SsAead,
        needs_cert: false,
        needs_decoy: false,
    },
];

/// Daemon log level for the generated configs (`BENCH_MATRIX_LOG`, default
/// `error`). Raise it to `debug`/`trace` when a pair fails and the reason is
/// not obvious from the one-line diagnostics.
fn log_level() -> String {
    std::env::var("BENCH_MATRIX_LOG").unwrap_or_else(|_| "error".into())
}

/// Keep per-daemon stderr logs after the run (`BENCH_MATRIX_KEEP_LOGS=1`).
fn keep_logs() -> bool {
    std::env::var_os("BENCH_MATRIX_KEEP_LOGS").is_some()
}

// --- flux-core layer snippets ---------------------------------------------

fn flux_tls_server(s: &Setup) -> String {
    format!(
        r#""security":{{"type":"tls","certificate_path":"{}","key_path":"{}"}}"#,
        s.cert_str(),
        s.key_str()
    )
}

fn flux_tls_client(alpn_h2: bool) -> String {
    if alpn_h2 {
        format!(r#""security":{{"type":"tls","insecure":true,"sni":"{TLS_SNI}","alpn":["h2"]}}"#)
    } else {
        format!(r#""security":{{"type":"tls","insecure":true,"sni":"{TLS_SNI}"}}"#)
    }
}

/// XHTTP framing on the server side.
fn flux_xhttp_server() -> String {
    r#""framing":{"type":"xhttp","path":"/tunnel"}"#.to_string()
}

/// XHTTP framing on the client side.
fn flux_xhttp_client() -> String {
    r#""framing":{"type":"xhttp","path":"/tunnel"}"#.to_string()
}

fn flux_ws_server() -> String {
    format!(r#""framing":{{"type":"websocket","path":"{WS_PATH}"}}"#)
}

fn flux_ws_client() -> String {
    format!(
        r#""framing":{{"type":"websocket","path":"{WS_PATH}","headers":{{"Host":"{TLS_SNI}"}}}}"#
    )
}

/// The *client* framing carries the gRPC service path; the inbound does not.
fn flux_grpc_client() -> String {
    format!(r#""framing":{{"type":"grpc","service_name":"{GRPC_SERVICE}"}}"#)
}

fn flux_grpc_server() -> String {
    // An inbound gRPC framing has no `service_name`: it accepts whatever `:path`
    // the client sends. The server-side value here used to be silently ignored.
    r#""framing":{"type":"grpc"}"#.to_string()
}

fn flux_vless(vision: bool) -> String {
    if vision {
        format!(r#""protocol":{{"type":"vless","uuid":"{UUID}","flow":"xtls-rprx-vision"}}"#)
    } else {
        format!(r#""protocol":{{"type":"vless","uuid":"{UUID}"}}"#)
    }
}

fn flux_reality_server(s: &Setup) -> String {
    let decoy = s.decoy.expect("decoy started for REALITY scenarios");
    format!(
        r#""security":{{"type":"reality","server_names":["{REALITY_SNI}"],"private_key":"{}","short_ids":["{REALITY_SHORT_ID}"],"fallback":"{decoy}"}}"#,
        s.reality_private
    )
}

fn flux_reality_client(s: &Setup) -> String {
    format!(
        r#""security":{{"type":"reality","sni":"{REALITY_SNI}","public_key":"{}","short_id":"{REALITY_SHORT_ID}"}}"#,
        s.reality_public
    )
}

/// Builds a flux-core inbound node: carrier + optional security/framing + protocol.
fn flux_in(port: u16, layers: &[String], protocol: &str) -> String {
    let mut node = format!(
        r#"{{"tag":"in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{port}}}"#
    );
    for layer in layers {
        node.push(',');
        node.push_str(layer);
    }
    node.push(',');
    node.push_str(protocol);
    node.push('}');
    format!(
        r#"{{"log":{{"level":"{level}"}},"inbounds":[{node}],"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#,
        level = log_level()
    )
}

/// Builds a flux-core client: SOCKS inbound + one standard outbound node, with
/// the route final pinned to that node.
fn flux_out(socks: u16, server: u16, layers: &[String], protocol: &str) -> String {
    let mut node =
        format!(r#"{{"tag":"node","carrier":{{"type":"tcp","address":"127.0.0.1:{server}"}}"#);
    for layer in layers {
        node.push(',');
        node.push_str(layer);
    }
    node.push(',');
    node.push_str(protocol);
    node.push('}');
    format!(
        r#"{{"log":{{"level":"{level}"}},"inbounds":[{{"tag":"socks-in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{socks}}},"protocol":{{"type":"socks"}}}}],"outbounds":[{node}],"route":{{"final":"node"}}}}"#,
        level = log_level()
    )
}

// --- sing-box snippet helpers ---------------------------------------------

fn sbox_tls_server(s: &Setup) -> String {
    format!(
        r#""tls":{{"enabled":true,"certificate_path":"{}","key_path":"{}"}}"#,
        s.cert_str(),
        s.key_str()
    )
}

fn sbox_tls_client() -> String {
    format!(r#""tls":{{"enabled":true,"insecure":true,"server_name":"{TLS_SNI}"}}"#)
}

fn sbox_ws_server() -> String {
    format!(r#""transport":{{"type":"ws","path":"{WS_PATH}"}}"#)
}

fn sbox_ws_client() -> String {
    format!(r#""transport":{{"type":"ws","path":"{WS_PATH}"}}"#)
}

fn sbox_grpc_server() -> String {
    format!(r#""transport":{{"type":"grpc","service_name":"{GRPC_SERVICE}"}}"#)
}

fn sbox_reality_server(s: &Setup) -> String {
    let decoy = s.decoy.expect("decoy started for REALITY scenarios");
    format!(
        r#""tls":{{"enabled":true,"server_name":"{REALITY_SNI}","reality":{{"enabled":true,"handshake":{{"server":"127.0.0.1","server_port":{}}},"private_key":"{}","short_id":["{REALITY_SHORT_ID}"]}}}}"#,
        decoy.port(),
        s.reality_private
    )
}

fn sbox_reality_client(s: &Setup) -> String {
    format!(
        r#""tls":{{"enabled":true,"server_name":"{REALITY_SNI}","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"{}","short_id":"{REALITY_SHORT_ID}"}}}}"#,
        s.reality_public
    )
}

impl Scenario {
    fn flux_server(&self, s: &Setup, port: u16) -> String {
        match self.kind {
            Kind::VlessTcp => flux_in(port, &[], &flux_vless(false)),
            Kind::VlessXhttp => flux_in(port, &[flux_xhttp_server()], &flux_vless(false)),
            Kind::VlessGrpcPlain => flux_in(port, &[flux_grpc_server()], &flux_vless(false)),
            Kind::VlessWsTls => flux_in(
                port,
                &[flux_tls_server(s), flux_ws_server()],
                &flux_vless(false),
            ),
            Kind::VlessGrpcTls => flux_in(
                port,
                &[flux_tls_server(s), flux_grpc_server()],
                &flux_vless(false),
            ),
            Kind::VlessReality => flux_in(port, &[flux_reality_server(s)], &flux_vless(false)),
            Kind::VlessRealityVision => flux_in(port, &[flux_reality_server(s)], &flux_vless(true)),
            Kind::VmessWsTls => flux_in(
                port,
                &[flux_tls_server(s), flux_ws_server()],
                &format!(r#""protocol":{{"type":"vmess","uuid":"{UUID}"}}"#),
            ),
            Kind::TrojanTls => flux_in(
                port,
                &[flux_tls_server(s)],
                &format!(r#""protocol":{{"type":"trojan","password":"{TROJAN_PASSWORD}"}}"#),
            ),
            Kind::Ss2022 => flux_in(
                port,
                &[],
                &format!(
                    r#""protocol":{{"type":"shadowsocks","password":"{SS2022_KEY_B64}","method":"2022-blake3-aes-128-gcm"}}"#
                ),
            ),
            Kind::SsAead => flux_in(
                port,
                &[],
                &format!(
                    r#""protocol":{{"type":"shadowsocks","password":"{SS_AEAD_PASSWORD}","method":"aes-256-gcm"}}"#
                ),
            ),
        }
    }

    fn flux_client(&self, s: &Setup, socks: u16, port: u16) -> String {
        match self.kind {
            Kind::VlessTcp => flux_out(socks, port, &[], &flux_vless(false)),
            Kind::VlessXhttp => flux_out(socks, port, &[flux_xhttp_client()], &flux_vless(false)),
            Kind::VlessGrpcPlain => {
                flux_out(socks, port, &[flux_grpc_client()], &flux_vless(false))
            }
            Kind::VlessWsTls => flux_out(
                socks,
                port,
                &[flux_tls_client(false), flux_ws_client()],
                &flux_vless(false),
            ),
            Kind::VlessGrpcTls => flux_out(
                socks,
                port,
                &[flux_tls_client(true), flux_grpc_client()],
                &flux_vless(false),
            ),
            Kind::VlessReality => {
                flux_out(socks, port, &[flux_reality_client(s)], &flux_vless(false))
            }
            Kind::VlessRealityVision => {
                flux_out(socks, port, &[flux_reality_client(s)], &flux_vless(true))
            }
            Kind::VmessWsTls => flux_out(
                socks,
                port,
                &[flux_tls_client(false), flux_ws_client()],
                &format!(r#""protocol":{{"type":"vmess","uuid":"{UUID}"}}"#),
            ),
            Kind::TrojanTls => flux_out(
                socks,
                port,
                &[flux_tls_client(false)],
                &format!(r#""protocol":{{"type":"trojan","password":"{TROJAN_PASSWORD}"}}"#),
            ),
            Kind::Ss2022 => flux_out(
                socks,
                port,
                &[],
                &format!(
                    r#""protocol":{{"type":"shadowsocks","password":"{SS2022_KEY_B64}","method":"2022-blake3-aes-128-gcm"}}"#
                ),
            ),
            Kind::SsAead => flux_out(
                socks,
                port,
                &[],
                &format!(
                    r#""protocol":{{"type":"shadowsocks","password":"{SS_AEAD_PASSWORD}","method":"aes-256-gcm"}}"#
                ),
            ),
        }
    }

    fn sbox_server(&self, s: &Setup, port: u16) -> String {
        let inbound = match self.kind {
            Kind::VlessXhttp | Kind::VlessGrpcPlain => {
                unreachable!("sing-box cannot run this scenario; the column is skipped")
            }
            Kind::VlessTcp => format!(
                r#"{{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}"}}]}}"#
            ),
            Kind::VlessWsTls => format!(
                r#"{{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}"}}],{},{}}}"#,
                sbox_tls_server(s),
                sbox_ws_server()
            ),
            Kind::VlessGrpcTls => format!(
                r#"{{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}"}}],{},{}}}"#,
                sbox_tls_server(s),
                sbox_grpc_server()
            ),
            Kind::VlessReality => format!(
                r#"{{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}"}}],{}}}"#,
                sbox_reality_server(s)
            ),
            Kind::VlessRealityVision => format!(
                r#"{{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}","flow":"xtls-rprx-vision"}}],{}}}"#,
                sbox_reality_server(s)
            ),
            Kind::VmessWsTls => format!(
                r#"{{"type":"vmess","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}"}}],{},{}}}"#,
                sbox_tls_server(s),
                sbox_ws_server()
            ),
            Kind::TrojanTls => format!(
                r#"{{"type":"trojan","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"password":"{TROJAN_PASSWORD}"}}],{}}}"#,
                sbox_tls_server(s)
            ),
            Kind::Ss2022 => format!(
                r#"{{"type":"shadowsocks","tag":"in","listen":"127.0.0.1","listen_port":{port},"method":"2022-blake3-aes-128-gcm","password":"{SS2022_KEY_B64}"}}"#
            ),
            Kind::SsAead => format!(
                r#"{{"type":"shadowsocks","tag":"in","listen":"127.0.0.1","listen_port":{port},"method":"aes-256-gcm","password":"{SS_AEAD_PASSWORD}"}}"#
            ),
        };
        format!(
            r#"{{"log":{{"level":"{level}"}},"inbounds":[{inbound}],"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#,
            level = log_level()
        )
    }

    fn sbox_client(&self, s: &Setup, socks: u16, port: u16) -> String {
        let outbound = match self.kind {
            Kind::VlessXhttp | Kind::VlessGrpcPlain => {
                unreachable!("sing-box cannot run this scenario; the column is skipped")
            }
            Kind::VlessTcp => format!(
                r#"{{"type":"vless","tag":"node","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}"}}"#
            ),
            Kind::VlessWsTls => format!(
                r#"{{"type":"vless","tag":"node","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}",{},{}}}"#,
                sbox_tls_client(),
                sbox_ws_client()
            ),
            Kind::VlessGrpcTls => format!(
                r#"{{"type":"vless","tag":"node","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}",{},{}}}"#,
                sbox_tls_client(),
                sbox_grpc_server()
            ),
            Kind::VlessReality => format!(
                r#"{{"type":"vless","tag":"node","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}",{}}}"#,
                sbox_reality_client(s)
            ),
            Kind::VlessRealityVision => format!(
                r#"{{"type":"vless","tag":"node","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}","flow":"xtls-rprx-vision",{}}}"#,
                sbox_reality_client(s)
            ),
            Kind::VmessWsTls => format!(
                r#"{{"type":"vmess","tag":"node","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}","security":"aes-128-gcm",{},{}}}"#,
                sbox_tls_client(),
                sbox_ws_client()
            ),
            Kind::TrojanTls => format!(
                r#"{{"type":"trojan","tag":"node","server":"127.0.0.1","server_port":{port},"password":"{TROJAN_PASSWORD}",{}}}"#,
                sbox_tls_client()
            ),
            Kind::Ss2022 => format!(
                r#"{{"type":"shadowsocks","tag":"node","server":"127.0.0.1","server_port":{port},"method":"2022-blake3-aes-128-gcm","password":"{SS2022_KEY_B64}"}}"#
            ),
            Kind::SsAead => format!(
                r#"{{"type":"shadowsocks","tag":"node","server":"127.0.0.1","server_port":{port},"method":"aes-256-gcm","password":"{SS_AEAD_PASSWORD}"}}"#
            ),
        };
        format!(
            r#"{{"log":{{"level":"{level}"}},"inbounds":[{{"type":"socks","tag":"client-in","listen":"127.0.0.1","listen_port":{socks}}}],"outbounds":[{outbound}]}}"#,
            level = log_level()
        )
    }

    /// The scenario as the xray builders name it, or `None` where xray has no
    /// equivalent (REALITY + Vision is an xray-only flow, and it is present).
    /// Whether sing-box can run this scenario at all.
    fn sbox_capable(&self) -> bool {
        // sing-box has no XHTTP transport.
        matches!(
            self.kind,
            Kind::VlessTcp
                | Kind::VlessWsTls
                | Kind::VlessGrpcTls
                | Kind::VlessReality
                | Kind::VlessRealityVision
                | Kind::VmessWsTls
                | Kind::Ss2022
                | Kind::SsAead
                | Kind::TrojanTls
        )
    }

    fn xray_protocol(&self) -> Option<xray_matrix_configs::Protocol> {
        use xray_matrix_configs::Protocol as P;
        Some(match self.kind {
            Kind::VlessTcp => P::VlessTcp,
            Kind::VlessWsTls => P::VlessWs,
            Kind::VlessGrpcTls => P::VlessGrpc,
            Kind::VlessXhttp => P::VlessXhttp,
            Kind::VlessGrpcPlain => P::VlessGrpc,
            Kind::VlessReality => P::Reality,
            Kind::VlessRealityVision => P::RealityVision,
            Kind::VmessWsTls => P::VmessWs,
            Kind::TrojanTls => P::TrojanTls,
            Kind::Ss2022 => P::Shadowsocks2022,
            Kind::SsAead => return None,
        })
    }

    fn xray_params<'a>(
        &self,
        s: &'a Setup,
        socks: u16,
        port: u16,
    ) -> xray_matrix_configs::Params<'a> {
        xray_matrix_configs::Params {
            server_port: port,
            socks_port: socks,
            uuid: UUID,
            cert_path: &s.cert,
            key_path: &s.key,
            cert_sha256_hex: &s.cert_sha256_hex,
            reality_private: &s.reality_private,
            reality_public: &s.reality_public,
            decoy_port: s.decoy.map(|d| d.port()).unwrap_or(0),
            ss_password: &s.ss_password,
        }
    }

    fn configs(&self, stack: Stack, s: &Setup, socks: u16, port: u16) -> (String, String) {
        match stack {
            Stack::Flux => (self.flux_server(s, port), self.flux_client(s, socks, port)),
            Stack::Singbox => (self.sbox_server(s, port), self.sbox_client(s, socks, port)),
            Stack::Xray => match self.xray_protocol() {
                Some(p) => {
                    let params = self.xray_params(s, socks, port);
                    (p.server_config(&params), p.client_config(&params))
                }
                None => unreachable!("xray scenarios are filtered before this point"),
            },
        }
    }

    fn needs(&self) -> (bool, bool) {
        (self.needs_cert, self.needs_decoy)
    }
}

// ---------------------------------------------------------------------------
// Harness endpoints
// ---------------------------------------------------------------------------

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn addr_of(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Waits until `addr` accepts connections. Returns `false` on timeout instead of
/// panicking, so a broken daemon becomes a table entry rather than a crash.
async fn wait_for_listener(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

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

/// A real TLS 1.3 echo server. REALITY servers fetch the served certificate
/// chain from their `handshake`/`fallback` target, so it must speak TLS — a
/// plain TCP socket there makes the REALITY handshake fail outright.
async fn start_tls_echo_server(cert: &Path, key: &Path) -> anyhow::Result<SocketAddr> {
    let (certs, key) = flux_transport::tls::TlsTransport::load_certs_and_key(
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
    )?;
    let acceptor = flux_transport::tls::TlsTransport::create_server_acceptor(certs, key, vec![])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

const CHUNK: usize = 128 * 1024;

/// Reads a SOCKS5 reply of any address type (the fixed 10-byte read used by
/// `bench_native` silently mis-frames when a reply carries a domain name).
async fn read_socks_reply(s: &mut TcpStream) -> Result<u8, String> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .map_err(|e| format!("SOCKS5 reply header: {e}"))?;
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)
                .await
                .map_err(|e| format!("SOCKS5 reply domain length: {e}"))?;
            len[0] as usize + 2
        }
        other => return Err(format!("SOCKS5 reply with unknown ATYP 0x{other:02x}")),
    };
    let mut tail = vec![0u8; rest];
    s.read_exact(&mut tail)
        .await
        .map_err(|e| format!("SOCKS5 reply body: {e}"))?;
    Ok(head[1])
}

/// Stage tracing for one transfer (`BENCH_MATRIX_TRACE=1`), used to tell a slow
/// handshake apart from slow bulk data when a protocol misbehaves.
fn trace() -> bool {
    std::env::var_os("BENCH_MATRIX_TRACE").is_some()
}

macro_rules! tr {
    ($($arg:tt)*) => {
        if trace() {
            eprintln!("[trace] {}", format!($($arg)*));
        }
    };
}

/// One pipelined transfer of `total_bytes` payload through the tunnel at
/// `entry` (a SOCKS5 port), echoing off `echo`. Returns the bytes echoed back.
async fn transfer(
    entry: SocketAddr,
    echo: SocketAddr,
    total_bytes: usize,
) -> Result<Transfer, String> {
    let t0 = Instant::now();
    let mut s = TcpStream::connect(entry)
        .await
        .map_err(|e| format!("connect {entry}: {e}"))?;
    let _ = s.set_nodelay(true);

    s.write_all(b"\x05\x01\x00")
        .await
        .map_err(|e| format!("SOCKS5 greeting: {e}"))?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method)
        .await
        .map_err(|e| format!("SOCKS5 method reply: {e}"))?;
    if method != [0x05, 0x00] {
        return Err(format!(
            "SOCKS5 method negotiation rejected ({:02x}{:02x})",
            method[0], method[1]
        ));
    }

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match echo.ip() {
        std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => return Err("echo server must be IPv4".into()),
    }
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req)
        .await
        .map_err(|e| format!("SOCKS5 CONNECT: {e}"))?;
    let rep = read_socks_reply(&mut s).await?;
    let setup_secs = t0.elapsed().as_secs_f64();
    tr!("socks CONNECT ok after {setup_secs:.3}s");
    if rep != 0x00 {
        return Err(format!("SOCKS5 CONNECT refused (REP=0x{rep:02x})"));
    }

    let (mut r, mut w) = s.into_split();
    let payload = vec![0xA5u8; CHUNK];
    let chunks = total_bytes.div_ceil(CHUNK);
    // The write half must stay open until the echo has come back in full.
    // Dropping it sends a FIN, and a proxy that tears the whole connection down
    // when one direction hits EOF (sing-box does) then truncates the download —
    // measured as a mysteriously short transfer at a variable offset.
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel::<()>();
    let writer = tokio::spawn(async move {
        for _ in 0..chunks {
            if w.write_all(&payload).await.is_err() {
                break;
            }
        }
        let _ = finished_rx.await;
        // `w` is dropped here, after the reader is done with the payload.
    });

    let mut received = 0usize;
    let mut buf = vec![0u8; CHUNK];
    let mut failure: Option<String> = None;
    let mut reads = 0usize;
    while received < total_bytes {
        reads += 1;
        if reads == 1 {
            tr!("first read done at {:.3}s", t0.elapsed().as_secs_f64());
        }
        match r.read(&mut buf).await {
            Ok(0) => {
                failure = Some(format!(
                    "tunnel closed the connection after {received} of {total_bytes} bytes"
                ));
                break;
            }
            Err(e) => {
                failure = Some(format!(
                    "reading the tunnel failed after {received} of {total_bytes} bytes: {e}"
                ));
                break;
            }
            Ok(n) => received += n,
        }
    }
    tr!(
        "read loop ended at {:.3}s ({received} bytes in {reads} reads)",
        t0.elapsed().as_secs_f64()
    );
    let _ = finished_tx.send(());
    let _ = writer.await;
    if let Some(failure) = failure {
        return Err(failure);
    }
    Ok(Transfer {
        bytes: received,
        setup_secs,
        total_secs: t0.elapsed().as_secs_f64(),
    })
}

/// One round's measurement. `mbps` is end-to-end for a **fresh** tunnel
/// connection (setup included); `bulk_mbps` excludes the tunnel setup so a
/// protocol with an expensive handshake is not misread as a slow cipher.
struct Transfer {
    bytes: usize,
    setup_secs: f64,
    total_secs: f64,
}

struct Sample {
    mbps: f64,
    bulk_mbps: f64,
    setup_ms: f64,
    cpu_secs_per_gib: f64,
}

/// One measured round: throughput plus the CPU the *tunnel* burned for it.
async fn measure_round(
    tunnel: &Tunnel,
    echo: SocketAddr,
    total_bytes: usize,
    timeout: Duration,
) -> Result<Sample, String> {
    let cpu_before = tunnel.cpu_secs();
    let started = Instant::now();
    let outcome = tokio::time::timeout(timeout, transfer(tunnel.socks, echo, total_bytes)).await;
    let elapsed = started.elapsed().as_secs_f64();
    let cpu_after = tunnel.cpu_secs();

    let done = match outcome {
        Err(_) => {
            // How much CPU the tunnel burned while "doing nothing" separates a parked
            // tunnel from a spinning one, which is the whole question about this stall.
            let burned = match (cpu_before, cpu_after) {
                (Some(b), Some(a)) => format!("{:.3} s CPU", (a - b).max(0.0)),
                _ => "CPU unknown".to_string(),
            };
            // The tunnel's own stderr names what it thinks happened: the copier's
            // backstop logs every time it has to re-poll a parked relay.
            let notes = tunnel.log_tail();
            return Err(format!(
                "timeout: no completion within {}s ({} MiB attempted); the tunnel used {} \
                 during the attempt. Tunnel log:\n{}",
                timeout.as_secs(),
                total_bytes / (1024 * 1024),
                burned,
                if notes.is_empty() {
                    "  (empty)".to_string()
                } else {
                    notes
                }
            ));
        }
        Ok(Err(e)) => return Err(e),
        Ok(Ok(done)) => done,
    };
    let _ = elapsed;

    let mib = done.bytes as f64 / 1_048_576.0;
    let bulk_secs = (done.total_secs - done.setup_secs).max(1e-6);
    let gib = done.bytes as f64 / 1_073_741_824.0;
    let cpu = match (cpu_before, cpu_after) {
        (Some(b), Some(a)) => (a - b).max(0.0),
        _ => 0.0,
    };
    Ok(Sample {
        mbps: mib / done.total_secs.max(1e-6),
        bulk_mbps: mib / bulk_secs,
        setup_ms: done.setup_secs * 1000.0,
        cpu_secs_per_gib: if gib > 0.0 { cpu / gib } else { 0.0 },
    })
}

// ---------------------------------------------------------------------------
// One scenario, both stacks, interleaved
// ---------------------------------------------------------------------------

enum Outcome {
    Measured(Vec<Sample>),
    Skipped(String),
}

/// Spawns the pair of processes for one stack and proves the tunnel carries
/// traffic before any round is measured.
async fn prepare_tunnel(
    stack: Stack,
    scenario: &Scenario,
    setup: &Setup,
    bin: &Path,
    label: &str,
) -> Result<Tunnel, String> {
    let server_port = get_free_port().await;
    let socks_port = get_free_port().await;
    let (server_cfg, client_cfg) = scenario.configs(stack, setup, socks_port, server_port);

    let dir = &setup.dir;
    let server_cfg_path = dir.join(format!("{label}-{}-server.json", pid_suffix()));
    let client_cfg_path = dir.join(format!("{label}-{}-client.json", pid_suffix()));
    std::fs::write(&server_cfg_path, server_cfg)
        .map_err(|e| format!("write server config: {e}"))?;
    std::fs::write(&client_cfg_path, client_cfg)
        .map_err(|e| format!("write client config: {e}"))?;

    let stamp = pid_suffix();
    let server_log = dir.join(format!("{label}-{stamp}-server.log"));
    let client_log = dir.join(format!("{label}-{stamp}-client.log"));
    let server_argv: Vec<String> = stack.argv(&server_cfg_path);
    let server_argv: Vec<&str> = server_argv.iter().map(String::as_str).collect();
    let server = ProxyProc::spawn(bin, &server_log, &server_argv)?;

    if !wait_for_listener(addr_of(server_port), Duration::from_secs(20)).await {
        let why = server.log_tail();
        return Err(format!(
            "server never listened on 127.0.0.1:{server_port}{}",
            if why.is_empty() {
                String::new()
            } else {
                format!(" ({why})")
            }
        ));
    }

    let client_argv: Vec<String> = stack.argv(&client_cfg_path);
    let client_argv: Vec<&str> = client_argv.iter().map(String::as_str).collect();
    let client = ProxyProc::spawn(bin, &client_log, &client_argv)?;

    let socks = addr_of(socks_port);
    if !wait_for_listener(socks, Duration::from_secs(20)).await {
        let why = client.log_tail();
        return Err(format!(
            "client never listened on {socks}{}",
            if why.is_empty() {
                String::new()
            } else {
                format!(" ({why})")
            }
        ));
    }

    let tunnel = Tunnel {
        server,
        client,
        socks,
    };
    Ok(tunnel)
}

fn pid_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

async fn run_scenario(
    scenario: &Scenario,
    setup: &Setup,
    args: &Args,
    echo: SocketAddr,
    flux_bin: &Path,
    sbox_bin: Option<&Path>,
    xray_bin: Option<&Path>,
) -> Vec<(Stack, Outcome)> {
    let total_bytes = args.mb * 1024 * 1024;
    let mut results: Vec<(Stack, Outcome)> = Vec::new();

    // ---- spawn both tunnels first, then alternate rounds between them ------
    let flux = match prepare_tunnel(Stack::Flux, scenario, setup, flux_bin, "flux").await {
        Ok(t) => Some(t),
        Err(e) => {
            results.push((Stack::Flux, Outcome::Skipped(e)));
            None
        }
    };

    let mut sbox = None;
    if args.with_singbox && !scenario.sbox_capable() {
        results.push((
            Stack::Singbox,
            Outcome::Skipped("sing-box has no such transport".into()),
        ));
    } else if args.with_singbox {
        match sbox_bin {
            None => results.push((
                Stack::Singbox,
                Outcome::Skipped("not installed (no sing-box binary found)".into()),
            )),
            Some(bin) => match prepare_tunnel(Stack::Singbox, scenario, setup, bin, "sbox").await {
                Ok(t) => sbox = Some(t),
                Err(e) => results.push((Stack::Singbox, Outcome::Skipped(e))),
            },
        }
    }

    let mut xray = None;
    if args.with_xray {
        match (xray_bin, scenario.xray_protocol()) {
            (None, _) => results.push((
                Stack::Xray,
                Outcome::Skipped("not installed (no xray binary found)".into()),
            )),
            (Some(_), None) => results.push((
                Stack::Xray,
                Outcome::Skipped("no xray equivalent for this transport".into()),
            )),
            (Some(bin), Some(_)) => {
                match prepare_tunnel(Stack::Xray, scenario, setup, bin, "xray").await {
                    Ok(t) => xray = Some(t),
                    Err(e) => results.push((Stack::Xray, Outcome::Skipped(e))),
                }
            }
        }
    }

    let mut samples: std::collections::HashMap<Stack, Option<Vec<Sample>>> =
        std::collections::HashMap::new();
    let mut errors: std::collections::HashMap<Stack, Option<String>> =
        std::collections::HashMap::new();
    samples.insert(Stack::Flux, flux.as_ref().map(|_| Vec::new()));
    errors.insert(Stack::Flux, None);
    if sbox.is_some() {
        samples.insert(Stack::Singbox, Some(Vec::new()));
        errors.insert(Stack::Singbox, None);
    }
    if xray.is_some() {
        samples.insert(Stack::Xray, Some(Vec::new()));
        errors.insert(Stack::Xray, None);
    }

    // A tunnel that cannot carry one warm-up transfer is not a throughput
    // result; fail it before measuring so the reason is quoted, not averaged.
    const WARMUP: usize = 4 * 1024 * 1024;
    for (stack, tunnel) in [
        (Stack::Flux, &flux),
        (Stack::Singbox, &sbox),
        (Stack::Xray, &xray),
    ] {
        if let Some(t) = tunnel
            && let Err(e) = measure_round(t, echo, WARMUP, args.timeout).await
        {
            errors.insert(stack, Some(t.why(&format!("warm-up failed: {e}"))));
            samples.insert(stack, None);
        }
    }

    // Rounds are interleaved and the stack order alternates, so a machine that
    // drifts during the run charges every stack equally.
    let mut order = vec![Stack::Flux];
    if sbox.is_some() {
        order.push(Stack::Singbox);
    }
    if xray.is_some() {
        order.push(Stack::Xray);
    }
    for round in 1..=args.rounds {
        let mut this_round = order.clone();
        if round % 2 == 0 {
            this_round.reverse();
        }
        for stack in this_round {
            let tunnel = match stack {
                Stack::Flux => &flux,
                Stack::Singbox => &sbox,
                Stack::Xray => &xray,
            };
            let (Some(t), Some(acc)) = (tunnel, samples.get_mut(&stack)) else {
                continue;
            };
            if errors.get(&stack).is_some_and(|e| e.is_some()) {
                continue;
            }
            match measure_round(t, echo, total_bytes, args.timeout).await {
                Ok(sample) => {
                    print_progress(round, stack, &sample);
                    if let Some(v) = acc {
                        v.push(sample);
                    }
                }
                Err(e) => {
                    errors.insert(stack, Some(t.why(&format!("round {round}: {e}"))));
                    samples.insert(stack, None);
                }
            }
        }
    }

    for stack in [Stack::Flux, Stack::Singbox, Stack::Xray] {
        if !samples.contains_key(&stack) && !errors.contains_key(&stack) {
            continue;
        }
        let s = samples.remove(&stack).flatten();
        let e = errors.remove(&stack).flatten();
        if let Some(v) = s {
            results.push((stack, Outcome::Measured(v)));
        } else if let Some(e) = e {
            results.push((stack, Outcome::Skipped(e)));
        }
    }
    results
}

fn print_progress(round: usize, stack: Stack, sample: &Sample) {
    println!(
        "    round {round} {:<10} {:9.1} MB/s  (bulk {:9.1}, setup {:7.1} ms)  {:6.3} CPU s/GiB",
        stack.label(),
        sample.mbps,
        sample.bulk_mbps,
        sample.setup_ms,
        sample.cpu_secs_per_gib
    );
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn median(v: &[f64]) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

fn binary_version(bin: &Path) -> String {
    for args in [["--version".to_string()], ["version".to_string()]] {
        if let Ok(out) = Command::new(bin).args(&args).output()
            && let Some(line) = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
        {
            return line.to_string();
        }
    }
    "unknown".into()
}

/// One measured (or failed) cell of the matrix.
type Row = (String, Stack, Option<Vec<Sample>>, Option<String>);

/// Prints one table. Stack rows for the same protocol are grouped, with the
/// protocol name on the first row only.
fn print_table(rows: &[Row], args: &Args) {
    const W: usize = 136;
    println!();
    println!("{}", "=".repeat(W));
    println!(
        "TUNNEL THROUGHPUT MATRIX — loopback, {} MiB payload per round, {} interleaved round(s), 1 stream",
        args.mb, args.rounds
    );
    println!(
        "MB/s = MiB/s of payload for a FRESH tunnel connection (setup included); \
         bulk excludes the tunnel setup"
    );
    println!("{}", "=".repeat(W));
    println!(
        "{:<36} {:<10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>3}  status",
        "Protocol / transport",
        "Stack",
        "MB/s e2e",
        "min",
        "max",
        "MB/s bulk",
        "setup ms",
        "CPU s/GiB",
        "n"
    );
    println!("{}", "-".repeat(W));

    for (i, (protocol, stack, samples, err)) in rows.iter().enumerate() {
        let name = if i == 0 || rows[i - 1].0 != *protocol {
            protocol.as_str()
        } else {
            ""
        };
        match (samples, err) {
            (Some(samples), _) if !samples.is_empty() => {
                let mbps: Vec<f64> = samples.iter().map(|s| s.mbps).collect();
                let bulk: Vec<f64> = samples.iter().map(|s| s.bulk_mbps).collect();
                let setup: Vec<f64> = samples.iter().map(|s| s.setup_ms).collect();
                let cpu: Vec<f64> = samples.iter().map(|s| s.cpu_secs_per_gib).collect();
                println!(
                    "{:<36} {:<10} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.3} {:>3}  ok",
                    name,
                    stack.label(),
                    median(&mbps),
                    mbps.iter().cloned().fold(f64::INFINITY, f64::min),
                    mbps.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                    median(&bulk),
                    median(&setup),
                    median(&cpu),
                    mbps.len()
                );
            }
            (_, Some(reason)) => {
                let status = format!("n/a ({})", truncate(reason, 55));
                println!(
                    "{:<36} {:<10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>3}  {status}",
                    name,
                    stack.label(),
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    0
                );
            }
            _ => {}
        }
    }
    println!("{}", "-".repeat(W));
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

    if !args.flux_bin.is_file() {
        anyhow::bail!(
            "flux-core binary not found at {} — build it with \
             `cargo build --release -p flux-core --bin flux-core` or pass --flux PATH",
            args.flux_bin.display()
        );
    }

    let mut scenarios: Vec<&Scenario> = SCENARIOS
        .iter()
        .filter(|s| match &args.only {
            Some(needle) => s.name.to_ascii_lowercase().contains(needle),
            None => true,
        })
        .collect();
    if scenarios.is_empty() {
        anyhow::bail!(
            "--only matched no protocol; known protocols: {}",
            SCENARIOS
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // Keep declaration order (priority order) even after filtering.
    scenarios.sort_by_key(|s| {
        SCENARIOS
            .iter()
            .position(|c| std::ptr::eq(c, *s))
            .unwrap_or(usize::MAX)
    });

    let mut setup = Setup::new()?;
    let echo = start_echo_server().await;

    let needs_decoy = scenarios.iter().any(|s| s.needs().1);
    if needs_decoy {
        setup.decoy = Some(start_tls_echo_server(&setup.cert, &setup.key).await?);
    }

    let sbox_bin = if args.with_singbox {
        args.singbox_bin.clone().filter(|p| p.is_file())
    } else {
        None
    };
    let xray_bin = if args.with_xray {
        find_in_path("xray")
    } else {
        None
    };

    // ---- header -----------------------------------------------------------
    println!(
        "flux-core  : {}  ({})",
        binary_version(&args.flux_bin),
        args.flux_bin.display()
    );
    match &xray_bin {
        Some(bin) => println!("xray       : {}  ({})", binary_version(bin), bin.display()),
        None if args.with_xray => println!("xray       : not installed — column skipped"),
        None => {}
    }
    match (&sbox_bin, args.with_singbox) {
        (Some(bin), _) => println!("sing-box   : {}  ({})", binary_version(bin), bin.display()),
        (None, true) => println!("sing-box   : not installed — sing-box rows will report n/a"),
        (None, false) => println!("sing-box   : skipped (--no-singbox)"),
    }
    println!("echo server: {echo} (in this process; not charged to either stack)");
    if let Some(decoy) = setup.decoy {
        println!("TLS decoy  : {decoy} (REALITY certificate source)");
    }
    println!(
        "workload   : {} MiB payload per round, {} round(s), fresh tunnel connection per round",
        args.mb, args.rounds
    );

    let mut rows: Vec<Row> = Vec::new();
    for scenario in &scenarios {
        println!("\n--- {} ---", scenario.name);
        let started = Instant::now();
        let results = run_scenario(
            scenario,
            &setup,
            &args,
            echo,
            &args.flux_bin,
            sbox_bin.as_deref(),
            xray_bin.as_deref(),
        )
        .await;
        let mut results = results;
        // Stable presentation order: flux-core, then sing-box, then xray.
        results.sort_by_key(|(stack, _)| match stack {
            Stack::Flux => 0,
            Stack::Singbox => 1,
            Stack::Xray => 2,
        });
        for (stack, outcome) in results {
            match outcome {
                Outcome::Measured(samples) => {
                    rows.push((scenario.name.to_string(), stack, Some(samples), None))
                }
                Outcome::Skipped(reason) => {
                    println!("    {:<10} n/a: {}", stack.label(), truncate(&reason, 160));
                    rows.push((scenario.name.to_string(), stack, None, Some(reason)))
                }
            }
        }
        println!("    ({:.1}s)", started.elapsed().as_secs_f64());
    }

    print_table(&rows, &args);

    // ---- notes: full failure reasons, not truncated ----------------------
    let failures: Vec<&Row> = rows.iter().filter(|r| r.3.is_some()).collect();
    if !failures.is_empty() {
        println!("\nFAILURES / SKIPS (full reason)");
        for (protocol, stack, _, reason) in failures {
            println!(
                "  * {protocol} / {}: {}",
                stack.label(),
                reason.as_deref().unwrap_or("")
            );
        }
    }

    // ---- summary ---------------------------------------------------------
    println!("\nPAIRWISE SUMMARY (medians; flux-core against each competitor)");
    println!("{}", "-".repeat(126));
    println!(
        "{:<38} {:>10} {:>10} {:>10} {:>11} {:>11} {:>11} {:>11}",
        "Protocol / transport",
        "flux bulk",
        "sbox bulk",
        "xray bulk",
        "vs sbox",
        "vs xray",
        "CPU vs sbox",
        "CPU vs xray"
    );
    println!("{}", "-".repeat(126));
    let mut protocols: Vec<String> = Vec::new();
    for row in &rows {
        if !protocols.contains(&row.0) {
            protocols.push(row.0.clone());
        }
    }
    for protocol in protocols {
        let cell = |stack: Stack, pick: fn(&Sample) -> f64| -> Option<f64> {
            rows.iter()
                .find(|r| r.0 == protocol && r.1 == stack)
                .and_then(|r| r.2.as_ref())
                .map(|samples| median(&samples.iter().map(pick).collect::<Vec<_>>()))
        };
        let f_bulk = cell(Stack::Flux, |s| s.bulk_mbps);
        let s_bulk = cell(Stack::Singbox, |s| s.bulk_mbps);
        let f_cpu = cell(Stack::Flux, |s| s.cpu_secs_per_gib);
        let s_cpu = cell(Stack::Singbox, |s| s.cpu_secs_per_gib);
        let f_setup = cell(Stack::Flux, |s| s.setup_ms);
        let s_setup = cell(Stack::Singbox, |s| s.setup_ms);
        let x_bulk = cell(Stack::Xray, |s| s.bulk_mbps);
        let x_cpu = cell(Stack::Xray, |s| s.cpu_secs_per_gib);
        let _ = (f_setup, s_setup);
        let pct = match (f_bulk, s_bulk) {
            (Some(f), Some(s)) if s > 0.0 => format!("{:+.1}%", (f / s - 1.0) * 100.0),
            _ => "-".to_string(),
        };
        let pct_x = match (f_bulk, x_bulk) {
            (Some(f), Some(x)) if x > 0.0 => format!("{:+.1}%", (f / x - 1.0) * 100.0),
            _ => "-".to_string(),
        };
        let cpu_pct = match (f_cpu, s_cpu) {
            (Some(f), Some(s)) if s > 0.0 => format!("{:+.1}%", (f / s - 1.0) * 100.0),
            _ => "-".to_string(),
        };
        let cpu_pct_x = match (f_cpu, x_cpu) {
            (Some(f), Some(x)) if x > 0.0 => format!("{:+.1}%", (f / x - 1.0) * 100.0),
            _ => "-".to_string(),
        };
        let fmt = |v: Option<f64>| match v {
            Some(v) => format!("{v:.1}"),
            None => "-".to_string(),
        };
        println!(
            "{:<38} {:>10} {:>10} {:>10} {:>11} {:>11} {:>11} {:>11}",
            protocol,
            fmt(f_bulk),
            fmt(s_bulk),
            fmt(x_bulk),
            pct,
            pct_x,
            cpu_pct,
            cpu_pct_x
        );
    }
    println!("{}", "-".repeat(126));
    println!(
        "MB/s = MiB/s (1048576 B) of payload. CPU s/GiB = CPU of both tunnel processes per GiB of\n\
         payload, lower is better. `throughput` and `CPU ratio` compare bulk rates, so a protocol\n\
         with an expensive handshake is judged on its data path rather than its setup; `setup`\n\
         shows the median time from SOCKS connect to tunnel-ready, where a large flux number is\n\
         a real regression, not noise.\n\
         \n\
         Reproduce: cargo run --release --example bench_matrix -- --rounds {} --mb {}",
        args.rounds, args.mb
    );
    Ok(())
}
