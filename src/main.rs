//! flux-core: the proxy binary.

#[cfg(feature = "alloc-stats")]
mod alloc_stats {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Counts allocations so the data path's per-connection cost can be measured from the binary
    /// that serves traffic. Enabled only by the `alloc-stats` feature.
    pub struct Counting;

    pub static ALLOCS: AtomicU64 = AtomicU64::new(0);
    pub static BYTES: AtomicU64 = AtomicU64::new(0);

    // SAFETY: every method delegates to `System` with the same arguments, so the allocator
    // contract is preserved; the counters are separate from the allocation itself.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(
                new_size.saturating_sub(layout.size()) as u64,
                Ordering::Relaxed,
            );
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    pub static GLOBAL: Counting = Counting;

    /// Reports the totals, once, on a SIGTERM or at normal exit.
    pub fn spawn_reporter(allocations_start: u64) {
        // A plain thread: this runs before the tokio runtime exists, and a reporter has no
        // business depending on the reactor it is measuring.
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let n = ALLOCS.load(Ordering::Relaxed);
                let b = BYTES.load(Ordering::Relaxed);
                eprintln!(
                    "[alloc-stats] total={n} since_start={} bytes={b}",
                    n - allocations_start
                );
            }
        });
    }
}

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use flux_app::{Config, ConfigFormat, Instance, load_any_config};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::level_filters::LevelFilter;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "flux-core",
    author = "flux team",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance asynchronous proxy core in Rust",
    long_about = None
)]
struct Cli {
    /// A subcommand is required: a supervisor whose ExecStart lost its arguments
    /// used to get exit code 0 and no listeners at all, because a missing
    /// subcommand silently fell back to printing the version banner.
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy core with the specified configuration file
    Run {
        /// Path to configuration file (.json, .jsonc, .yaml, .yml)
        #[arg(short, long)]
        config: PathBuf,
        /// Config format: auto, json, yaml
        #[arg(short, long, default_value = "auto")]
        format: String,
        /// Number of worker threads (default: all CPU cores)
        #[arg(short, long, value_parser = parse_worker_count)]
        workers: Option<usize>,
    },
    /// Validate configuration file without starting listeners
    Check {
        /// Path to configuration file (.json, .jsonc, .yaml, .yml)
        #[arg(short, long)]
        config: PathBuf,
        /// Config format: auto, json, yaml
        #[arg(short, long, default_value = "auto")]
        format: String,
    },
    /// Trace how a target destination will be routed through the rules
    Trace {
        /// Path to configuration file (.json, .jsonc, .yaml, .yml)
        #[arg(short, long)]
        config: PathBuf,
        /// Destination address to simulate (e.g. "google.com:443" or "1.1.1.1:53")
        #[arg(short, long)]
        destination: String,
        /// Network protocol: tcp or udp (default: tcp)
        #[arg(short, long, default_value = "tcp")]
        network: String,
        /// Inbound tag (default: "default")
        #[arg(short, long, default_value = "default")]
        inbound: String,
        /// Config format: auto, json, yaml
        #[arg(short, long, default_value = "auto")]
        format: String,
    },
    /// Print detailed version information
    Version,
}

/// Exit code for a shutdown that was forced by a second signal: the listeners
/// were not necessarily released, so this is not a clean stop.
const EXIT_FORCED_SHUTDOWN: i32 = 1;

fn main() -> std::process::ExitCode {
    #[cfg(feature = "alloc-stats")]
    let alloc_start = alloc_stats::ALLOCS.load(std::sync::atomic::Ordering::Relaxed);

    #[cfg(target_os = "linux")]
    // SAFETY: `mallopt` only adjusts an allocator tunable; it holds no pointers and is
    // called once before any thread exists.
    unsafe {
        // Restrict glibc heap arenas to eliminate multi-megabyte arena fragmentation
        libc::mallopt(libc::M_ARENA_MAX, 2);
    }

    #[cfg(feature = "alloc-stats")]
    alloc_stats::spawn_reporter(alloc_start);

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        // One line, with the error chain flattened: supervisors capture stderr,
        // and `anyhow`'s Debug formatting spreads a three-level chain over seven
        // lines for no added information.
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let workers = match &cli.command {
        Commands::Run { workers, .. } => *workers,
        _ => None,
    };
    let workers = match workers {
        Some(w) => Some(w),
        None => workers_from_env()?,
    };

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(w) = workers {
        builder.worker_threads(w);
    }
    builder.thread_stack_size(512 * 1024);

    let rt = builder
        .enable_all()
        .build()
        .context("failed to start the tokio runtime")?;

    rt.block_on(async_main(cli))
}

/// `--workers` parser: rejects 0 at parse time (exit code 2, usage message).
///
/// `Builder::worker_threads(0)` panics inside tokio with exit code 101, which is
/// neither a usage error nor a configuration error and tells an operator nothing.
fn parse_worker_count(raw: &str) -> Result<usize, String> {
    match raw.trim().parse::<usize>() {
        Ok(0) => Err(
            "worker count must be at least 1 (omit --workers to use every CPU core)".to_string(),
        ),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("'{raw}' is not a positive integer")),
    }
}

/// `FLUX_WORKERS` fallback, used when `--workers` is absent.
///
/// An unparsable value used to be dropped on the floor (`parse().ok()`), so a
/// typo in a systemd unit silently ran with a different thread count than the
/// operator asked for. A value of 0 was worse: it reached tokio and panicked.
fn workers_from_env() -> Result<Option<usize>> {
    let raw = match std::env::var("FLUX_WORKERS") {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match trimmed.parse::<usize>() {
        Ok(0) => {
            bail!("FLUX_WORKERS=0 is not a valid worker count; unset it or set it to at least 1")
        }
        Ok(n) => Ok(Some(n)),
        Err(_) => bail!(
            "FLUX_WORKERS={raw:?} is not a positive integer; unset it or set it to the number of \
             worker threads"
        ),
    }
}

/// Parses one level name. `off` is included because it is the obvious way to
/// silence a process and `RUST_LOG=off` is what operators reach for; warning
/// about it and logging at info instead was the worst possible answer.
fn parse_log_level(s: &str) -> Option<LevelFilter> {
    match s.to_ascii_lowercase().as_str() {
        "trace" => Some(LevelFilter::TRACE),
        "debug" => Some(LevelFilter::DEBUG),
        "info" => Some(LevelFilter::INFO),
        "warn" | "warning" => Some(LevelFilter::WARN),
        "error" => Some(LevelFilter::ERROR),
        "off" | "none" => Some(LevelFilter::OFF),
        _ => None,
    }
}

fn init_tracing(level: LevelFilter) {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Resolves the effective log level: `RUST_LOG` wins, then config `log.level`,
/// then INFO.
///
/// Both inputs are operator-supplied strings, so neither may panic, and neither
/// may be discarded silently: a level that is ignored is reported on stderr
/// because the subscriber does not exist yet (a `warn!` here would go nowhere).
fn resolve_log_level(config_level: Option<&str>) -> LevelFilter {
    let from_env = match std::env::var("RUST_LOG") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                match parse_log_level(trimmed) {
                    Some(level) => Some(level),
                    None => {
                        eprintln!(
                            "flux-core: warning: ignoring RUST_LOG={raw:?}: this build accepts a \
                             single level (trace, debug, info, warn, error, off), not filter \
                             directives"
                        );
                        None
                    }
                }
            }
        }
        Err(_) => None,
    };

    let from_config = match config_level {
        Some(raw) if !raw.trim().is_empty() => match parse_log_level(raw.trim()) {
            Some(level) => Some(level),
            None => {
                eprintln!(
                    "flux-core: warning: ignoring log.level={raw:?} from the configuration \
                     (expected trace, debug, info, warn, error or off); using info"
                );
                None
            }
        },
        _ => None,
    };

    from_env.or(from_config).unwrap_or(LevelFilter::INFO)
}

/// Reads and parses a configuration file, turning every file-level problem into a
/// message that names the path.
///
/// The pre-flight checks exist because the loader alone gets three of them wrong:
///
/// * an **empty** file makes the JSON parser fail and the YAML fallback succeed
///   with `Config::default()`, so the process reported "Configuration is valid!"
///   (or started with no listener at all);
/// * a **whitespace-only** file produced "EOF while parsing a value at line 3
///   column 0" without naming the file;
/// * a **directory** and a missing path were reported through `canonicalize`,
///   which is an implementation detail of the include machinery.
fn load_config_file(path: &Path, format: ConfigFormat) -> Result<Config> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot read config file '{}'", path.display()))?;
    if meta.is_dir() {
        bail!(
            "config path '{}' is a directory, not a configuration file",
            path.display()
        );
    }

    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read config file '{}'", path.display()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        bail!(
            "config file '{}' contains no configuration ({} byte(s), all empty or whitespace)",
            path.display(),
            bytes.len()
        );
    }
    if let Err(e) = std::str::from_utf8(&bytes) {
        bail!(
            "config file '{}' is not valid UTF-8 (first invalid byte at offset {}): {}",
            path.display(),
            e.valid_up_to(),
            e
        );
    }

    match load_any_config(path, Some(format)) {
        Ok(config) => Ok(config),
        Err(e) => {
            let message = e.to_string();
            let mut full = format!("invalid configuration in '{}': {}", path.display(), message);
            if let Some(hint) = parse_error_hint(&message) {
                full.push_str("\n  hint: ");
                full.push_str(hint);
            }
            Err(anyhow!(full))
        }
    }
}

/// serde's untagged enums report only "data did not match any variant of untagged
/// enum InboundConfig": the operator learns neither which `type` field is wrong
/// nor what is accepted. Add the part serde leaves out.
fn parse_error_hint(message: &str) -> Option<&'static str> {
    if message.contains("untagged enum") {
        Some(
            "a `type` field inside an inbound/outbound `protocol` or `carrier` block is not a \
             supported value (run `flux-core version` for the supported list)",
        )
    } else {
        None
    }
}

/// One-line inventory of what the instance was asked to open, used to make a
/// listener failure name its inbounds instead of reporting a bare errno.
fn inbound_inventory(instance: &Instance) -> String {
    if instance.inbounds.is_empty() {
        return "none".to_string();
    }
    instance
        .inbounds
        .iter()
        .map(|inbound| match inbound.listen_addr() {
            Some(addr) => format!("{} ({}) on {}", inbound.tag(), inbound.protocol(), addr),
            None => format!("{} ({})", inbound.tag(), inbound.protocol()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// A start failure from `Instance::start()` is a bare `I/O error: Address already
/// in use`: with more than one inbound there is no way to tell which listener is
/// involved. Name the configured inbounds and the usual cause.
async fn start_instance(instance: &Instance, config_path: &Path) -> Result<()> {
    match instance.start().await {
        Ok(()) => Ok(()),
        // Flattened on purpose: `anyhow`'s source chain would print the io error
        // twice ("I/O error: Address already in use: Address already in use").
        Err(e) => Err(anyhow!(
            "failed to open a listener for '{}' (inbounds: {}); a port already held by another \
             process is the usual cause: {}",
            config_path.display(),
            inbound_inventory(instance),
            e
        )),
    }
}

fn instance_from_config(config: Config, config_path: &Path) -> Result<Instance> {
    Instance::new(config).map_err(|e| {
        anyhow!(
            "the configuration in '{}' is parsed but cannot be turned into a running proxy: {}",
            config_path.display(),
            e
        )
    })
}

/// Events the supervision loop reacts to.
enum SignalEvent {
    Reload,
    Shutdown(&'static str),
}

#[cfg(unix)]
struct Signals {
    hangup: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    /// Installed before the configuration is read, on purpose: SIGHUP's default
    /// action is *terminate*, so a reload sent by a supervisor while the process
    /// is still starting (or reading a config from a slow mount) used to kill it.
    /// `SIGTERM` had no handler at all.
    fn install() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            hangup: signal(SignalKind::hangup()).context("failed to install the SIGHUP handler")?,
            interrupt: signal(SignalKind::interrupt())
                .context("failed to install the SIGINT handler")?,
            terminate: signal(SignalKind::terminate())
                .context("failed to install the SIGTERM handler")?,
        })
    }

    /// Returns the first signal that arrives. Tokio counts every delivery of a
    /// registered signal, so a SIGHUP that lands while a reload is running is
    /// delivered by the next call instead of being lost.
    async fn next(&mut self) -> SignalEvent {
        tokio::select! {
            // Shutdown wins over reload when both are pending.
            biased;
            _ = self.terminate.recv() => SignalEvent::Shutdown("SIGTERM"),
            _ = self.interrupt.recv() => SignalEvent::Shutdown("SIGINT"),
            _ = self.hangup.recv() => SignalEvent::Reload,
        }
    }
}

#[cfg(not(unix))]
struct Signals;

#[cfg(not(unix))]
impl Signals {
    fn install() -> Result<Self> {
        Ok(Self)
    }

    async fn next(&mut self) -> SignalEvent {
        let _ = tokio::signal::ctrl_c().await;
        SignalEvent::Shutdown("Ctrl-C")
    }
}

/// Inbounds that own a resource only one instance can hold at a time: the TUN
/// device fd, and WireGuard's exclusive UDP bind (no SO_REUSEPORT).
fn is_exclusive(protocol: &str) -> bool {
    matches!(protocol, "tun" | "wireguard")
}

async fn run_proxy(config_path: &Path, format: &str) -> Result<()> {
    let fmt: ConfigFormat = format.parse().map_err(|e| anyhow!("--format: {}", e))?;

    let mut signals = Signals::install()?;

    let config = load_config_file(config_path, fmt)?;
    // Initialize logging AFTER config load so `log.level` from the config applies.
    init_tracing(resolve_log_level(
        config.log.as_ref().and_then(|l| l.level.as_deref()),
    ));
    info!(
        "Starting flux-core with config: {:?} (format: {:?})",
        config_path, fmt
    );

    let mut current = Arc::new(instance_from_config(config, config_path)?);
    start_instance(&current, config_path).await?;

    info!(
        "flux-core started successfully. Press Ctrl+C to terminate, or send SIGHUP to hot-reload."
    );

    loop {
        match signals.next().await {
            SignalEvent::Reload => reload(&mut current, config_path, fmt).await,
            SignalEvent::Shutdown(signal) => {
                info!("Received {}; shutting down flux-core...", signal);
                break;
            }
        }
    }

    info!("Shutting down flux-core...");
    shutdown(&current, &mut signals).await?;
    info!("Shutdown complete.");
    Ok(())
}

/// Hot reload: the new instance is built and started *before* the old one is
/// released, so every failure path leaves the running configuration untouched.
async fn reload(current: &mut Arc<Instance>, config_path: &Path, fmt: ConfigFormat) {
    info!(
        "Received SIGHUP! Reloading configuration from {:?}...",
        config_path
    );

    let config = match load_config_file(config_path, fmt) {
        Ok(config) => config,
        Err(e) => {
            error!("hot reload REJECTED, keeping the running configuration: {e:#}");
            return;
        }
    };
    let new_instance = match Instance::new(config) {
        Ok(instance) => instance,
        Err(e) => {
            error!("hot reload REJECTED, keeping the running configuration: {e:#}");
            return;
        }
    };

    // TUN (device FD) and WireGuard (exclusive UDP bind, no SO_REUSEPORT) cannot
    // coexist across old/new instances: the old instance must release the
    // resource first.
    let exclusive = new_instance
        .inbounds
        .iter()
        .any(|i| is_exclusive(i.protocol()))
        || current.inbounds.iter().any(|i| is_exclusive(i.protocol()));

    if exclusive {
        if let Err(e) = current.stop().await {
            error!("failed to release the running instance before the reload: {e:#}");
        }
        if let Err(e) = new_instance.start().await {
            error!("hot reload FAILED to start the new listeners: {e:#}");
            stop_rejected_instance(new_instance).await;
            match current.start().await {
                Ok(()) => warn!("the previous configuration is serving again"),
                Err(e) => error!(
                    "could not restore the previous instance ({e:#}); nothing is listening — fix \
                     the configuration and send SIGHUP again, or restart flux-core"
                ),
            }
            return;
        }
    } else if let Err(e) = new_instance.start().await {
        error!(
            "hot reload FAILED to start the new listeners, keeping the running configuration: {e:#}"
        );
        stop_rejected_instance(new_instance).await;
        return;
    }

    let old = std::mem::replace(current, Arc::new(new_instance));
    if !exclusive {
        // `stop()` joins the accept loops, so it is not awaited on the signal
        // loop: the next reload must not queue behind the previous teardown.
        tokio::spawn(async move {
            let _ = old.stop().await;
        });
    }
    info!("Configuration hot-reloaded successfully!");
}

/// `Instance::new()` starts background work (outbound-group probes, the traffic
/// sampler) that survives dropping the instance: a rejected reload must quiesce
/// it or every failed SIGHUP leaks a set of tasks.
async fn stop_rejected_instance(instance: Instance) {
    if let Err(e) = instance.stop().await {
        warn!("failed to quiesce the rejected instance: {e:#}");
    }
}

/// Graceful shutdown with an escape hatch.
///
/// A second SIGTERM/SIGINT exits immediately instead of waiting for a listener
/// that refuses to stop — `docker stop` and a terminal have no other way out.
/// A SIGHUP during shutdown is acknowledged and ignored: there is nothing left to
/// swap listeners into.
async fn shutdown(instance: &Instance, signals: &mut Signals) -> Result<()> {
    let stop = instance.stop();
    tokio::pin!(stop);

    loop {
        tokio::select! {
            biased;
            event = signals.next() => match event {
                SignalEvent::Shutdown(signal) => {
                    warn!(
                        "received a second {}; exiting without waiting for every listener to close",
                        signal
                    );
                    std::process::exit(EXIT_FORCED_SHUTDOWN);
                }
                SignalEvent::Reload => {
                    warn!("ignoring SIGHUP: a shutdown is already in progress");
                }
            },
            result = &mut stop => return result.context("failed to stop every listener"),
        }
    }
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Run {
            config,
            format,
            workers: _,
        } => run_proxy(&config, &format).await,
        Commands::Check { config, format } => check_config(&config, &format),
        Commands::Trace {
            config,
            destination,
            network,
            inbound,
            format,
        } => trace_route(&config, &format, &destination, &network, &inbound),
        Commands::Version => {
            print_version();
            Ok(())
        }
    }
}

fn check_config(config_path: &Path, format: &str) -> Result<()> {
    let fmt: ConfigFormat = format.parse().map_err(|e| anyhow!("--format: {}", e))?;
    let config = load_config_file(config_path, fmt);
    init_tracing(resolve_log_level(
        config
            .as_ref()
            .ok()
            .and_then(|c| c.log.as_ref())
            .and_then(|l| l.level.as_deref()),
    ));
    info!("Validating config: {:?} (format: {:?})", config_path, fmt);
    let config = config.context("configuration check failed")?;
    instance_from_config(config, config_path).context("configuration check failed")?;
    println!("Configuration is valid!");
    Ok(())
}

fn trace_route(
    config_path: &Path,
    format: &str,
    destination: &str,
    network: &str,
    inbound: &str,
) -> Result<()> {
    let fmt: ConfigFormat = format.parse().map_err(|e| anyhow!("--format: {}", e))?;
    let config = load_config_file(config_path, fmt)?;
    init_tracing(resolve_log_level(
        config.log.as_ref().and_then(|l| l.level.as_deref()),
    ));
    let instance = instance_from_config(config, config_path)?;

    // An unrecognised `--network` used to be silently treated as TCP, which makes
    // a UDP routing question come back with the TCP answer.
    let net = match network.to_ascii_lowercase().as_str() {
        "tcp" => flux_types::NetworkType::Tcp,
        "udp" => flux_types::NetworkType::Udp,
        other => bail!("--network must be 'tcp' or 'udp', got {other:?}"),
    };
    let dst: flux_types::TargetAddress = destination
        .parse()
        .unwrap_or_else(|_| flux_types::TargetAddress::domain(destination, 80));
    let dummy_src = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let meta = flux_types::SessionMeta::new(dummy_src, dst.clone(), inbound, net);

    let (matched_outbound, active_node) = instance.trace_route(&meta);
    println!("=== flux-core Route Simulation ===");
    println!("Destination: {}", dst);
    println!("Network:     {}", net);
    println!("Inbound:     {}", inbound);
    println!("----------------------------------");
    println!("Matched Rule Outbound: [{}]", matched_outbound);
    println!("Active Exit Node:      [{}]", active_node);
    println!("==================================");
    Ok(())
}

fn print_version() {
    println!("flux-core v{}", env!("CARGO_PKG_VERSION"));
    println!(
        "Target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!(
        "Configuration: Native Flux format (.json, .jsonc, .yaml, .yml) with modular $include"
    );
    println!(
        "Protocols: SOCKS5, HTTP CONNECT, MIXED, VLESS (REALITY & Vision), TROJAN, SHADOWSOCKS (AEAD & 2022), VMESS (AEAD), TUIC v5, Hysteria 2, WireGuard/AmneziaWG, TUN, REDIRECT, TPROXY"
    );
    println!(
        "Carriers: TCP, UDP, QUIC, TLS, WebSocket, gRPC, H2, HTTPUpgrade, ShadowTLS v3, REALITY"
    );
    println!("Groups: Selector, UrlTest, Fallback, LoadBalance");
    println!("API: Flux Core Native API (/api/v1/*, Unix Socket, Route Tracer)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_count_rejects_zero_instead_of_panicking() {
        let err = parse_worker_count("0").expect_err("0 must be rejected");
        assert!(err.contains("at least 1"), "{err}");
        assert_eq!(parse_worker_count("4").unwrap(), 4);
        assert_eq!(parse_worker_count(" 4 ").unwrap(), 4);
        assert!(parse_worker_count("-1").is_err());
        assert!(parse_worker_count("abc").is_err());
        assert!(parse_worker_count("").is_err());
    }

    #[test]
    fn log_level_accepts_every_documented_spelling() {
        assert_eq!(parse_log_level("TRACE"), Some(LevelFilter::TRACE));
        assert_eq!(parse_log_level("Debug"), Some(LevelFilter::DEBUG));
        assert_eq!(parse_log_level("info"), Some(LevelFilter::INFO));
        assert_eq!(parse_log_level("warn"), Some(LevelFilter::WARN));
        assert_eq!(parse_log_level("WARNING"), Some(LevelFilter::WARN));
        assert_eq!(parse_log_level("error"), Some(LevelFilter::ERROR));
        // `off` silences the process; it must not fall back to info.
        assert_eq!(parse_log_level("off"), Some(LevelFilter::OFF));
        assert_eq!(parse_log_level("OFF"), Some(LevelFilter::OFF));
        // Not a level: callers must fall back rather than panic.
        assert_eq!(parse_log_level(""), None);
        assert_eq!(parse_log_level("flux_core=debug"), None);
        assert_eq!(parse_log_level("1"), None);
    }

    #[test]
    fn empty_and_whitespace_files_are_rejected_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.json");
        std::fs::write(&empty, "").unwrap();
        let err = load_config_file(&empty, ConfigFormat::Auto)
            .expect_err("an empty config must not parse as a valid empty config")
            .to_string();
        assert!(err.contains("contains no configuration"), "{err}");
        assert!(err.contains("empty.json"), "{err}");

        let blank = dir.path().join("blank.json");
        std::fs::write(&blank, "   \n\t\n").unwrap();
        let err = load_config_file(&blank, ConfigFormat::Auto)
            .expect_err("a whitespace-only config must be rejected")
            .to_string();
        assert!(err.contains("contains no configuration"), "{err}");

        // A directory is a path problem, not a parse problem.
        let err = load_config_file(dir.path(), ConfigFormat::Auto)
            .expect_err("a directory must be rejected")
            .to_string();
        assert!(err.contains("is a directory"), "{err}");
    }

    #[test]
    fn invalid_utf8_is_reported_as_a_file_problem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.json");
        std::fs::write(&path, [0xff, 0xfe, b'{', b'}']).unwrap();
        let err = load_config_file(&path, ConfigFormat::Auto)
            .expect_err("invalid UTF-8 must be rejected")
            .to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
        assert!(err.contains("offset 0"), "{err}");
    }

    #[test]
    fn missing_config_path_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");
        let err = load_config_file(&path, ConfigFormat::Auto)
            .expect_err("a missing file must be rejected")
            .to_string();
        assert!(err.contains("cannot read config file"), "{err}");
        assert!(err.contains("absent.json"), "{err}");
    }

    #[test]
    fn untagged_enum_parse_failures_get_a_field_hint() {
        let hint = parse_error_hint(
            "failed to parse json config: data did not match any variant of untagged enum \
             InboundConfig at line 1 column 116",
        )
        .expect("untagged enum errors must carry a hint");
        assert!(hint.contains("protocol"), "{hint}");
        assert!(hint.contains("carrier"), "{hint}");
        assert!(parse_error_hint("route.rules[0]: references non-existent outbound").is_none());
    }

    #[test]
    fn exclusive_protocols_are_the_two_that_need_the_old_instance_to_stop_first() {
        for protocol in ["tun", "wireguard"] {
            assert!(is_exclusive(protocol), "{protocol}");
        }
        for protocol in ["socks", "mixed", "vless", "tuic", "hysteria2", "tproxy", ""] {
            assert!(!is_exclusive(protocol), "{protocol}");
        }
    }

    #[tokio::test]
    async fn inbound_inventory_names_tag_protocol_and_address() {
        let config = flux_app::Config {
            inbounds: vec![flux_app::InboundConfig::Node(Box::new(
                flux_app::LayeredInboundNode {
                    tag: "front".to_string(),
                    carrier: flux_app::InboundCarrierConfig::Tcp {
                        listen: Some("127.0.0.1".to_string()),
                        listen_port: Some(1080),
                        address: None,
                    },
                    protocol: flux_app::ProtocolConfig::Socks {
                        username: None,
                        password: None,
                    },
                    security: None,
                    framing: None,
                    rate_limit: None,
                    multiplex: None,
                },
            ))],
            ..Default::default()
        };
        let instance = Instance::new(config).expect("instance");
        let inventory = inbound_inventory(&instance);
        assert!(inventory.contains("front"), "{inventory}");
        assert!(inventory.contains("socks"), "{inventory}");
        assert!(inventory.contains("127.0.0.1:1080"), "{inventory}");
    }
}
