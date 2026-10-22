//! Process-level tests for the `flux-core` binary.
//!
//! Everything here drives the real executable, because that is all a supervisor,
//! a systemd unit or an operator ever sees: a command line, an exit code, and
//! stderr. The binary is located through `CARGO_BIN_EXE_flux-core`, which is
//! defined for integration tests of the package that declares the bin — if the
//! binary is not built, these tests fail instead of skipping.
//!
//! Exit-code contract asserted here:
//!
//! * `2` — the invocation itself is wrong (unknown flag, missing `--config`,
//!   `--workers 0`); clap's convention, and the same code `--help` does *not* use.
//! * `1` — the invocation is fine but the configuration cannot be read, parsed,
//!   validated or started.
//! * `0` — success: `--help`, `--version`, `version`, a valid `check`, and a
//!   *graceful* shutdown after SIGTERM/SIGINT. A signal-terminated process is not
//!   a failure once the listeners have been closed and `stop()` succeeded.

mod common;

use common::get_free_tcp_port;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_flux-core");

/// A config with one SOCKS inbound, written in the native JSON format.
fn config_with_inbound(port: u16, tag: &str) -> String {
    format!(
        r#"{{
            "log": {{ "level": "info" }},
            "inbounds": [{{
                "tag": "{tag}",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {port} }},
                "protocol": {{ "type": "socks" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    )
}

fn write_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write test config");
}

/// Runs the binary to completion with a clean environment.
fn cli(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("FLUX_WORKERS")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run flux-core")
}

fn cli_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("FLUX_WORKERS")
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().expect("failed to run flux-core")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// `Error: ...` on stderr plus exit code 1, and *no* panic anywhere.
fn assert_failed_with(out: &Output, needle: &str) {
    let err = stderr(out);
    let msg = format!(
        "expected exit 1 and a message containing {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout(out),
        err
    );
    assert_eq!(out.status.code(), Some(1), "{msg}");
    assert!(
        !err.contains("panicked"),
        "the binary panicked instead of reporting an error: {msg}"
    );
    assert!(err.contains(needle), "{msg}");
}

fn assert_usage_error(out: &Output, needle: &str) {
    let err = stderr(out);
    let msg = format!(
        "expected exit 2 and a usage message containing {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout(out),
        err
    );
    assert_eq!(out.status.code(), Some(2), "{msg}");
    assert!(!err.contains("panicked"), "the binary panicked: {msg}");
    assert!(err.contains(needle), "{msg}");
}

fn port_open(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// SOCKS5 greeting: proves the listener is not merely bound but serving.
fn socks5_greeting(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).is_ok() && response == [0x05, 0x00]
}

async fn wait_until(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

/// Child process that is killed and reaped when the test ends (including on
/// panic), so a failing assertion cannot leak a proxy onto a test port.
struct Proxy {
    child: Child,
    log_path: PathBuf,
}

impl Proxy {
    fn spawn(config: &Path, extra_args: &[&str]) -> Self {
        let log_path = config.with_extension("log");
        let log = std::fs::File::create(&log_path).expect("create log file");
        let log_err = log.try_clone().expect("clone log file");
        let child = Command::new(BIN)
            .args(["run", "-c", config.to_str().unwrap()])
            .args(extra_args)
            .env_remove("RUST_LOG")
            .env_remove("FLUX_WORKERS")
            .stdin(Stdio::null())
            // The binary logs on stdout (documented in docs/deployment.md);
            // capturing both keeps every assertion honest.
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("failed to spawn flux-core");
        Self { child, log_path }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn signal(&self, signal: i32) {
        let ret = unsafe { libc::kill(self.pid(), signal) };
        assert_eq!(ret, 0, "failed to send signal {signal}");
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().expect("try_wait").is_none()
    }

    fn wait_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                let log = self.log();
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("flux-core did not exit within {timeout:?}; log:\n{log}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

#[test]
fn no_subcommand_is_a_usage_error_instead_of_a_silent_success() {
    // A supervisor unit whose ExecStart lost its arguments used to get exit 0
    // and no listener at all (bare `flux-core` printed the version banner).
    let out = cli(&[]);
    assert_usage_error(&out, "Usage:");
    assert!(stdout(&out).is_empty(), "usage errors belong on stderr");
}

#[test]
fn help_and_version_exit_zero() {
    let out = cli(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("Usage:"));
    assert!(stdout(&out).contains("run"), "{}", stdout(&out));

    let out = cli(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("flux-core"));

    // The verbose `version` subcommand stays available for operators.
    let out = cli(&["version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("Protocols:"));
}

#[tokio::test]
async fn missing_and_unknown_arguments_are_usage_errors() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));

    assert_usage_error(&cli(&["run"]), "--config");
    assert_usage_error(
        &cli(&["run", "-c", config.to_str().unwrap(), "--no-such-flag"]),
        "--no-such-flag",
    );
    assert_usage_error(&cli(&["no-such-subcommand"]), "no-such-subcommand");
    // An invalid `--format` is a plain error (exit 1), not a panic and not a
    // usage error: the invocation is well-formed, the value is not.
    assert_failed_with(
        &cli(&["check", "-c", config.to_str().unwrap(), "-f", "toml"]),
        "unknown config format",
    );
}

#[tokio::test]
async fn workers_zero_is_a_usage_error_not_a_panic() {
    // `-w 0` used to reach `Builder::worker_threads(0)` and panic with exit 101.
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));

    let out = cli(&["run", "-c", config.to_str().unwrap(), "-w", "0"]);
    assert_usage_error(&out, "at least 1");
    assert!(
        !stderr(&out).contains("Worker threads cannot be set to 0"),
        "the panic message is back"
    );
}

#[tokio::test]
async fn flux_workers_is_validated_instead_of_ignored() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));
    let path = config.to_str().unwrap();

    // 0 panicked inside tokio; junk was silently discarded and the process ran
    // with an unknown thread count.
    assert_failed_with(
        &cli_env(&["check", "-c", path], &[("FLUX_WORKERS", "0")]),
        "FLUX_WORKERS",
    );
    assert_failed_with(
        &cli_env(&["check", "-c", path], &[("FLUX_WORKERS", "lots")]),
        "FLUX_WORKERS",
    );
    // A valid value still works.
    assert_eq!(
        cli_env(&["check", "-c", path], &[("FLUX_WORKERS", "2")])
            .status
            .code(),
        Some(0)
    );
}

// ---------------------------------------------------------------------------
// Configuration paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_file_problems_name_the_path_and_exit_non_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.json");
    assert_failed_with(
        &cli(&["check", "-c", missing.to_str().unwrap()]),
        "missing.json",
    );

    // A directory: the loader's `canonicalize` used to be the messenger.
    assert_failed_with(
        &cli(&["check", "-c", dir.path().to_str().unwrap()]),
        "is a directory",
    );

    // An empty file: the YAML fallback accepted "" as `Config::default()`, so
    // `check` printed "Configuration is valid!" for a config with no listeners.
    let empty = dir.path().join("empty.json");
    write_file(&empty, "");
    let out = cli(&["check", "-c", empty.to_str().unwrap()]);
    assert_failed_with(&out, "contains no configuration");
    assert!(!stdout(&out).contains("Configuration is valid!"));

    // Whitespace only is the same defect with a less obvious trigger.
    let blank = dir.path().join("blank.json");
    write_file(&blank, " \n\t\n");
    assert_failed_with(
        &cli(&["check", "-c", blank.to_str().unwrap()]),
        "contains no configuration",
    );

    // Invalid UTF-8 is a property of the file; say which byte.
    let binary = dir.path().join("binary.json");
    std::fs::write(&binary, [0xff, 0xfe, b'{', b'}']).expect("write binary config");
    let out = cli(&["check", "-c", binary.to_str().unwrap()]);
    assert_failed_with(&out, "not valid UTF-8");
    assert!(stderr(&out).contains("offset 0"), "{}", stderr(&out));
}

#[test]
fn unreadable_config_file_is_reported() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root can read a 0o000 file, so the failure cannot be produced");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secret.json");
    write_file(&path, &config_with_inbound(1080, "in"));
    let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&path, perms).expect("chmod");

    let out = cli(&["check", "-c", path.to_str().unwrap()]);
    assert_failed_with(&out, "Permission denied");
    assert!(stderr(&out).contains("secret.json"), "{}", stderr(&out));
}

#[tokio::test]
async fn a_broken_config_reads_nothing_into_the_log_before_it_fails() {
    // Logging is initialised *after* the config is read (that is what makes
    // `log.level` apply), so a failed startup must not emit half a log line.
    let dir = tempfile::tempdir().expect("tempdir");
    let broken = dir.path().join("broken.json");
    write_file(&broken, "{ this is not json");
    let out = cli(&["run", "-c", broken.to_str().unwrap()]);
    assert_failed_with(&out, "broken.json");
    assert!(
        stdout(&out).is_empty(),
        "a trace line was emitted before the config was read: {}",
        stdout(&out)
    );
}

// ---------------------------------------------------------------------------
// Startup failures: each one has to name the offending field
// ---------------------------------------------------------------------------

#[tokio::test]
async fn startup_failure_names_the_offending_field() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Unparseable field (typo).
    let unknown = dir.path().join("unknown.json");
    write_file(&unknown, r#"{ "log": { "level": "info" }, "nope": 1 }"#);
    let out = cli(&["check", "-c", unknown.to_str().unwrap()]);
    assert_failed_with(&out, "unknown field `nope`");

    // Unsupported protocol: serde's untagged enum says only that nothing
    // matched, so the CLI adds the field and where to look.
    let bad_protocol = dir.path().join("bad-proto.json");
    write_file(
        &bad_protocol,
        r#"{ "inbounds": [{ "tag": "front",
             "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": 0 },
             "protocol": { "type": "carrier-pigeon" } }],
           "outbounds": [{ "type": "direct", "tag": "direct" }] }"#,
    );
    let out = cli(&["check", "-c", bad_protocol.to_str().unwrap()]);
    assert_failed_with(&out, "hint:");
    assert!(stderr(&out).contains("protocol"), "{}", stderr(&out));
    assert!(stderr(&out).contains("InboundConfig"), "{}", stderr(&out));
    // `run` must report the same field, not a bare "failed to start".
    let out = cli(&["run", "-c", bad_protocol.to_str().unwrap()]);
    assert_failed_with(&out, "hint:");
    assert!(stderr(&out).contains("protocol"), "{}", stderr(&out));

    // Invalid rule set: the reference is named, not a bare "failed to start".
    let bad_rule = dir.path().join("bad-rule.json");
    write_file(
        &bad_rule,
        r#"{ "route": { "rules": [{ "outbound": "ghost" }] }, "outbounds": [] }"#,
    );
    let out = cli(&["check", "-c", bad_rule.to_str().unwrap()]);
    assert_failed_with(&out, "route.rules[0]");
    assert!(stderr(&out).contains("ghost"), "{}", stderr(&out));
}

#[test]
fn startup_failure_on_a_port_in_use_names_the_inbound() {
    // Hold the port for the whole test, so the child cannot win a race.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind busy port");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("busy.json");
    write_file(&config, &config_with_inbound(port, "front"));

    let out = cli(&["run", "-c", config.to_str().unwrap()]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(
        err.contains("Address already in use"),
        "bind error lost: {err}"
    );
    // The bare errno is not enough: the message must let the operator pick the
    // offending inbound out of the configuration.
    assert!(err.contains("front"), "inbound tag missing: {err}");
    assert!(err.contains(&format!("127.0.0.1:{port}")), "{err}");
    drop(listener);
}

// ---------------------------------------------------------------------------
// Log setup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn log_level_sources_are_resolved_without_panicking() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    let path = config.to_str().unwrap().to_string();
    write_file(&config, &config_with_inbound(port, "in"));

    // An unusable RUST_LOG used to be dropped silently; it must not panic and it
    // must not swallow the fact.
    let out = cli_env(
        &["check", "-c", path.as_str()],
        &[("RUST_LOG", "verbose-ish")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("ignoring RUST_LOG"),
        "{}",
        stderr(&out)
    );
    // ... while the default (no RUST_LOG, no config log.level) is info.
    let out = cli(&["check", "-c", &path]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout(&out).contains("Validating config"),
        "{}",
        stdout(&out)
    );

    // An unusable config log.level is reported too, and the default is used.
    let bad_level = dir.path().join("bad-level.json");
    write_file(
        &bad_level,
        r#"{ "log": { "level": "screaming" }, "inbounds": [], "outbounds": [] }"#,
    );
    let out = cli(&["check", "-c", bad_level.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("log.level"), "{}", stderr(&out));

    // RUST_LOG wins over the config: `error` silences the INFO line.
    let quiet = dir.path().join("quiet.json");
    write_file(&quiet, &config_with_inbound(port, "in"));
    let out = cli_env(
        &["check", "-c", quiet.to_str().unwrap()],
        &[("RUST_LOG", "error")],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(
        !stdout(&out).contains("Validating config"),
        "RUST_LOG=error did not win: {}",
        stdout(&out)
    );

    // `off` is a legitimate way to silence a process: it must be accepted (no
    // warning) and must suppress the log lines without suppressing the result.
    let out = cli_env(&["check", "-c", quiet.to_str().unwrap()], &[("RUST_LOG", "off")]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Configuration is valid!"),
        "the command result must survive RUST_LOG=off: {}",
        stdout(&out)
    );
    assert!(
        !stdout(&out).contains("Validating config"),
        "RUST_LOG=off still logged: {}",
        stdout(&out)
    );
    assert!(
        !stderr(&out).contains("warning"),
        "RUST_LOG=off is not a warning: {}",
        stderr(&out)
    );

    // ... and the config's own log.level does the same when RUST_LOG is unset.
    let config_level = dir.path().join("config-level.json");
    write_file(
        &config_level,
        &config_with_inbound(port, "in").replace(r#""level": "info""#, r#""level": "error""#),
    );
    let out = cli(&["check", "-c", config_level.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        !stdout(&out).contains("Validating config"),
        "log.level=error did not apply: {}",
        stdout(&out)
    );
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sigterm_shuts_down_cleanly_and_closes_every_listener() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));

    let mut proxy = Proxy::spawn(&config, &[]);
    wait_until("the listener to come up", Duration::from_secs(10), || {
        socks5_greeting(port)
    })
    .await;

    proxy.signal(libc::SIGTERM);
    let status = proxy.wait_exit(Duration::from_secs(10));

    // Clean shutdown is a success, not a signal death: `stop()` joined every
    // accept loop, so nothing was left for the OS to clean up.
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM was not handled cleanly; log:\n{}",
        proxy.log()
    );
    assert!(
        !port_open(port),
        "the listener was still open after a clean shutdown"
    );
    let log = proxy.log();
    assert!(log.contains("Received SIGTERM"), "log:\n{log}");
    assert!(log.contains("Shutdown complete"), "log:\n{log}");
}

#[tokio::test]
async fn sigint_shuts_down_cleanly() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));

    let mut proxy = Proxy::spawn(&config, &[]);
    wait_until("the listener to come up", Duration::from_secs(10), || {
        socks5_greeting(port)
    })
    .await;

    proxy.signal(libc::SIGINT);
    let status = proxy.wait_exit(Duration::from_secs(10));
    assert_eq!(status.code(), Some(0), "log:\n{}", proxy.log());
    assert!(!port_open(port), "listener still open after SIGINT");
    assert!(proxy.log().contains("Received SIGINT"), "{}", proxy.log());
}

#[tokio::test]
async fn a_second_signal_during_shutdown_does_not_hang() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));

    let mut proxy = Proxy::spawn(&config, &[]);
    wait_until("the listener to come up", Duration::from_secs(10), || {
        socks5_greeting(port)
    })
    .await;

    // Two signals back to back: either the shutdown finishes first (exit 0) or
    // the escalation path exits immediately (exit 1). Neither may hang.
    proxy.signal(libc::SIGTERM);
    proxy.signal(libc::SIGTERM);
    let status = proxy.wait_exit(Duration::from_secs(10));
    assert!(
        matches!(status.code(), Some(0) | Some(1)),
        "unexpected exit for a double signal: {status:?}; log:\n{}",
        proxy.log()
    );
}

#[tokio::test]
async fn sighup_swaps_listeners_and_keeps_serving() {
    let old_port = get_free_tcp_port().await;
    let new_port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(old_port, "in-a"));

    let mut proxy = Proxy::spawn(&config, &[]);
    wait_until("the first listener", Duration::from_secs(10), || {
        socks5_greeting(old_port)
    })
    .await;

    write_file(&config, &config_with_inbound(new_port, "in-b"));
    proxy.signal(libc::SIGHUP);

    wait_until("the reloaded listener", Duration::from_secs(10), || {
        socks5_greeting(new_port)
    })
    .await;
    assert!(proxy.is_running(), "process died on reload");
    wait_until("the old listener to close", Duration::from_secs(10), || {
        !port_open(old_port)
    })
    .await;
    proxy.signal(libc::SIGTERM);
    assert_eq!(proxy.wait_exit(Duration::from_secs(10)).code(), Some(0));
}

#[tokio::test]
async fn sighup_with_a_broken_config_keeps_the_old_instance() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(&config, &config_with_inbound(port, "in"));

    let mut proxy = Proxy::spawn(&config, &[]);
    wait_until("the listener", Duration::from_secs(10), || {
        socks5_greeting(port)
    })
    .await;

    write_file(&config, "{ not json at all");
    proxy.signal(libc::SIGHUP);
    wait_until("the reload to be rejected", Duration::from_secs(10), || {
        proxy.log().contains("hot reload REJECTED")
    })
    .await;

    assert!(proxy.is_running(), "process died on a rejected reload");
    assert!(socks5_greeting(port), "the running config stopped serving");
    // The rejection names the file and the reason.
    let log = proxy.log();
    assert!(log.contains("config.json"), "log:\n{log}");

    proxy.signal(libc::SIGTERM);
    assert_eq!(proxy.wait_exit(Duration::from_secs(10)).code(), Some(0));
}

// ---------------------------------------------------------------------------
// Signals racing startup and reload
//
// These use a FIFO as the config file: `open()` on a FIFO for reading blocks
// until a writer appears, which turns "the process is reading its config right
// now" into a state the test can observe and hold. That is the only way to hit
// the windows deterministically; a regular file is read in microseconds.
// ---------------------------------------------------------------------------

struct FifoFeeder {
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    payload: Arc<Mutex<String>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FifoFeeder {
    fn start(path: PathBuf, payload: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(payload));
        let (stop_thread, paused_thread, payload_thread) =
            (stop.clone(), paused.clone(), shared.clone());
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                if paused_thread.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                // `O_NONBLOCK` makes the open fail with ENXIO when no reader is
                // waiting instead of blocking forever; when it succeeds a reader
                // *is* waiting, so the write is paired with it.
                let opened = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&path);
                match opened {
                    Ok(mut file) => {
                        let text = payload_thread.lock().unwrap().clone();
                        let _ = file.write_all(text.as_bytes());
                        // Close, then keep quiet long enough for the reader to
                        // hit EOF. A writer that reappears while the reader is
                        // still between its two `read()` calls would make it
                        // read two configs back to back ("trailing characters",
                        // i.e. the JSON parser's version of a double paste).
                        drop(file);
                        std::thread::sleep(Duration::from_millis(150));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            stop,
            paused,
            payload: shared,
            handle: Some(handle),
        }
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume_with(&self, payload: &str) {
        *self.payload.lock().unwrap() = payload.to_string();
        self.paused.store(false, Ordering::Relaxed);
    }
}

impl Drop for FifoFeeder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn make_fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path");
    let ret = unsafe { libc::mkfifo(raw.as_ptr(), 0o600) };
    assert_eq!(ret, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
}

/// A SIGHUP that arrives while the process is still reading its configuration
/// must be *queued*, not fatal: SIGHUP's default action is to terminate, so
/// before the handler was installed early this killed a starting proxy.
#[tokio::test]
async fn sighup_during_config_load_is_queued_not_fatal() {
    let port = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("config.fifo");
    make_fifo(&fifo);

    let mut proxy = Proxy::spawn(&fifo, &[]);

    // The process is blocked opening/reading the FIFO. Give it time to install
    // its signal handlers (which happens before the config is read) and to reach
    // the blocking read.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        proxy.is_running(),
        "the process exited while reading the config"
    );

    proxy.signal(libc::SIGHUP);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        proxy.is_running(),
        "SIGHUP killed the process while it was reading its configuration; log:\n{}",
        proxy.log()
    );

    // Now let the read complete. The queued SIGHUP must be delivered afterwards
    // and produce a real reload instead of being lost.
    let feeder = FifoFeeder::start(fifo.clone(), config_with_inbound(port, "in"));

    wait_until("the listener", Duration::from_secs(10), || {
        socks5_greeting(port)
    })
    .await;
    wait_until(
        "the queued SIGHUP to be handled",
        Duration::from_secs(10),
        || proxy.log().contains("Received SIGHUP"),
    )
    .await;
    wait_until("the reload to complete", Duration::from_secs(10), || {
        proxy
            .log()
            .contains("Configuration hot-reloaded successfully")
    })
    .await;

    proxy.signal(libc::SIGTERM);
    assert_eq!(
        proxy.wait_exit(Duration::from_secs(10)).code(),
        Some(0),
        "log:\n{}",
        proxy.log()
    );
    drop(feeder);
}

/// A SIGHUP that lands while a reload is already in flight must be delivered
/// once the reload finishes. Tokio guarantees this ("once `poll` has been
/// called, a further signal is guaranteed to be yielded"), and the reload is
/// awaited on the signal loop rather than detached, so the next poll really
/// happens after the reload completes.
#[tokio::test]
async fn sighup_during_an_in_flight_reload_is_delivered() {
    let port_a = get_free_tcp_port().await;
    let port_b = get_free_tcp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("config.fifo");
    make_fifo(&fifo);

    let feeder = FifoFeeder::start(fifo.clone(), config_with_inbound(port_a, "in-a"));
    let mut proxy = Proxy::spawn(&fifo, &[]);
    wait_until("the first listener", Duration::from_secs(10), || {
        socks5_greeting(port_a)
    })
    .await;

    // Hold the reload open by starving it of config text, so the second signal
    // provably arrives while reload #1 is in flight.
    feeder.pause();
    proxy.signal(libc::SIGHUP);
    wait_until(
        "reload #1 to start and block on the config file",
        Duration::from_secs(10),
        || proxy.log().contains("Received SIGHUP"),
    )
    .await;

    proxy.signal(libc::SIGHUP);
    feeder.resume_with(&config_with_inbound(port_b, "in-b"));

    wait_until("the reloaded listener", Duration::from_secs(10), || {
        socks5_greeting(port_b)
    })
    .await;
    // The second SIGHUP must not be swallowed: it produces a second reload after
    // the first one returns.
    wait_until(
        "the queued second SIGHUP to be handled",
        Duration::from_secs(10),
        || proxy.log().matches("Received SIGHUP").count() >= 2,
    )
    .await;
    assert!(proxy.is_running(), "process died; log:\n{}", proxy.log());

    proxy.signal(libc::SIGTERM);
    assert_eq!(
        proxy.wait_exit(Duration::from_secs(10)).code(),
        Some(0),
        "log:\n{}",
        proxy.log()
    );
    drop(feeder);
}

/// A `trace` invocation with an unknown `--network` used to answer with the TCP
/// route, which makes a UDP routing question look answered.
#[test]
fn trace_rejects_an_unknown_network_instead_of_guessing_tcp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.json");
    write_file(
        &config,
        r#"{ "outbounds": [{ "type": "direct", "tag": "direct" }] }"#,
    );
    let out = cli(&[
        "trace",
        "-c",
        config.to_str().unwrap(),
        "-d",
        "example.com:443",
        "-n",
        "icmp",
    ]);
    assert_failed_with(&out, "--network");
    assert!(stderr(&out).contains("tcp"), "{}", stderr(&out));

    // The valid form still prints exactly the route report on stdout.
    let out = cli(&[
        "trace",
        "-c",
        config.to_str().unwrap(),
        "-d",
        "example.com:443",
        "-n",
        "udp",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Active Exit Node"),
        "{}",
        stdout(&out)
    );
}
