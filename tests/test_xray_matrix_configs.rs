//! Matrix smoke test: **every** Xray config pair in
//! [`xray_matrix_configs`] is started for real and made to carry a megabyte.
//!
//! The point is not performance — the numbers printed here are a coarse
//! liveness signal (roughly "does this protocol cost 2 ms or 200 ms per MiB"),
//! not a benchmark. The point is that a benchmark harness can only compare
//! flux-core against Xray on protocols where Xray's own two halves agree, and
//! nobody has ever checked that for this repository: the only Xray coverage so
//! far is REALITY, against flux.
//!
//! Each case therefore runs a genuine pair:
//!
//! ```text
//!   test ──SOCKS5──▶ xray client ──<protocol>──▶ xray server ──▶ TCP echo
//!        ◀────────────────── 1 MiB, byte-for-byte ─────────────────┘
//! ```
//!
//! All nine protocol pairs push exactly [`PAYLOAD_LEN`] bytes of
//! deterministic, incompressible data and compare every byte of the echo, so a
//! transport that silently truncates, re-frames or corrupts records fails here
//! rather than inside a benchmark run.
//!
//! Every pair runs to completion even when an earlier one fails; the failure
//! report names each broken pair with the daemon logs, instead of stopping at
//! the first. A missing `xray` binary is **not** skipped: the test fails with
//! the instruction needed to fix it, because "the matrix was never exercised"
//! must not look like a pass.
//!
//! The two supporting tests below check the other half of "works": that Xray
//! accepts each document at load time (`xray run -test`, which binds nothing)
//! and that the recorded support table matches the pairs actually exercised.

mod common;
mod xray_matrix_configs;

use common::{get_free_tcp_port, start_tcp_echo_server, start_tls_echo_server};
use serde_json::Value;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xray_matrix_configs as xc;

/// Bytes pushed through every pair. The matrix requires at least 1 MiB; using
/// exactly 1 MiB keeps the run short enough for CI and still spans many
/// protocol records: Vision switches its padding state after the first records,
/// gRPC frames in 16 KiB steps, and a TLS 1.3 record caps at 16 KiB, so 64 such
/// records have to survive the round trip intact.
const PAYLOAD_LEN: usize = 1024 * 1024;

/// Size of the lockstep round trip performed before the bulk push.
///
/// This is not a tuning knob, it is a workaround for a measurable defect in
/// Xray 26.3.27's Trojan outbound: its first write carries the request header
/// plus whatever the SOCKS5 inbound happened to read, and anything ≥ 8 KiB
/// there aborts the tunnel (`proxy/trojan: failed to write A request payload >
/// common/buf: buffer is full`). Sending smaller chunks from the test is *not*
/// enough — the inbound coalesces queued bytes, so a bulk sender loses the race
/// no matter its own write size. One lockstep round trip below the limit moves
/// the outbound past the header write; every later write is an unbuffered
/// stream copy. Harmless for the other eight protocols, and it also proves they
/// carry a small message before the flood.
const PRIME_LEN: usize = 1024;

/// Write granularity for the bulk push: one maximum-size TLS record, which is
/// also where gRPC and WebSocket framing start to split.
const WRITE_CHUNK: usize = 16 * 1024;

/// Time allowed for one handshake+echo exchange, and separately for a daemon to
/// start listening. Both are generous: this is a smoke test, and a slow CI box
/// should report a protocol failure, not a timeout at 1 s.
const CASE_TIMEOUT: Duration = Duration::from_secs(60);
const LISTEN_TIMEOUT: Duration = Duration::from_secs(20);

/// Attempts per pair. Interop suites spawn two external processes per case;
/// one retry absorbs the occasional slow start without hiding a broken config
/// (which fails both times and is then reported with its logs).
const ATTEMPTS: usize = 2;

// ---------------------------------------------------------------------------
// Xray binary discovery
// ---------------------------------------------------------------------------

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|full| full.is_file())
}

/// Locates the Xray binary (`XRAY_BIN`, then `xray` on `PATH`).
///
/// Unlike the older interop suites this **panics** when the binary is missing:
/// the whole purpose of this test is the matrix, so a skip would report success
/// for work that never happened.
fn xray_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("XRAY_BIN") {
        let path = PathBuf::from(p);
        assert!(
            path.is_file(),
            "XRAY_BIN is set to {}, which is not a file",
            path.display()
        );
        return path;
    }
    which("xray").unwrap_or_else(|| {
        panic!(
            "the `xray` binary is required by this test but was not found.\n\
             Install Xray {} (or any 26.x) and put it on PATH, or point XRAY_BIN at it:\n\
             \n  \
             bash -c \"$(curl -L https://github.com/XTLS/Xray-core/releases/latest/download/install-release.sh)\" install\n\
             \n  \
             XRAY_BIN=/path/to/xray cargo test --test test_xray_matrix_configs\n",
            xc::XRAY_VERSION_TESTED
        )
    })
}

/// `Xray 26.3.27 (Xray, Penetrates Everything.) …` — the first line of
/// `xray version`, used to attribute every verdict to a release.
fn xray_version(bin: &Path) -> String {
    let out = Command::new(bin)
        .arg("version")
        .output()
        .unwrap_or_else(|e| panic!("failed to run {} version: {e}", bin.display()));
    assert!(
        out.status.success(),
        "{} version failed with {}",
        bin.display(),
        out.status
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("<no version line>")
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// Daemon handling
// ---------------------------------------------------------------------------

/// A running Xray process; killed and reaped on drop so a failing assertion
/// never leaves a daemon behind holding a port.
struct XrayProcess {
    child: Child,
    _dir: TempDir,
    log_path: PathBuf,
    label: String,
}

impl XrayProcess {
    /// Writes `config` into a private temp dir and starts `xray run -c` on it.
    ///
    /// Returns `Err` only when the daemon could not be spawned — a config Xray
    /// rejects shows up as an early exit from [`wait_for_listen`], with the log.
    fn start(config: &str, label: &str) -> Result<Self, String> {
        // Validate that it is JSON here rather than in Xray: a builder bug would
        // otherwise be reported as a daemon startup failure.
        serde_json::from_str::<Value>(config)
            .map_err(|e| format!("{label}: generated config is not valid JSON: {e}"))?;

        let bin = xray_bin();
        let dir = TempDir::new().map_err(|e| format!("{label}: tempdir: {e}"))?;
        let cfg_path = dir.path().join("config.json");
        fs::write(&cfg_path, config).map_err(|e| format!("{label}: write config: {e}"))?;
        let log_path = dir.path().join("xray.log");
        let log = fs::File::create(&log_path).map_err(|e| format!("{label}: log file: {e}"))?;
        let log2 = log
            .try_clone()
            .map_err(|e| format!("{label}: clone log handle: {e}"))?;
        let child = Command::new(&bin)
            .args(["run", "-c", cfg_path.to_str().unwrap()])
            // Xray looks up geoip/geosite assets next to this path; the matrix
            // uses no rules that need them, but setting it keeps a stray lookup
            // from reaching into the user's home directory.
            .env("XRAY_LOCATION_ASSET", dir.path())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| format!("{label}: failed to spawn xray: {e}"))?;
        Ok(Self {
            child,
            _dir: dir,
            log_path,
            label: label.to_string(),
        })
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_else(|_| "<no log>".to_string())
    }

    /// Waits (time-bounded) until `port` accepts a TCP connection, reporting the
    /// daemon's own log when it dies instead of a bare timeout.
    async fn wait_for_listen(&mut self, port: u16) -> Result<(), String> {
        let deadline = Instant::now() + LISTEN_TIMEOUT;
        loop {
            if TcpStream::connect((xc::LOOPBACK, port)).await.is_ok() {
                return Ok(());
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!(
                    "{} exited with {status} before listening on 127.0.0.1:{port} \
                     (a config Xray refuses fails here)\n--- xray log ---\n{}",
                    self.label,
                    self.log()
                ));
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "{} did not listen on 127.0.0.1:{port} within {}s\n--- xray log ---\n{}",
                    self.label,
                    LISTEN_TIMEOUT.as_secs(),
                    self.log()
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Everything a pair needs that is expensive to build: certificates, keys and
/// the two long-lived peers (the echo target and the REALITY decoy).
struct Fixture {
    _dir: TempDir,
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_sha256_hex: String,
    uuid: String,
    ss_password: String,
    reality_private: String,
    reality_public: String,
    /// TCP echo the tunnel is asked to reach.
    echo: SocketAddr,
    /// Real TLS 1.3 listener that REALITY steals its certificate from.
    decoy: SocketAddr,
    payload: Vec<u8>,
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new().expect("tempdir for certificates");
        let (cert_path, key_path) =
            xc::write_self_signed_cert(dir.path(), &[xc::TLS_SNI]).expect("issue certificate");
        let cert_sha256_hex = xc::cert_sha256_hex(&cert_path);
        let (reality_private, reality_public) = xc::reality_keypair();
        Self {
            _dir: dir,
            cert_path,
            key_path,
            cert_sha256_hex,
            uuid: uuid::Uuid::new_v4().to_string(),
            ss_password: xc::ss2022_password(),
            reality_private,
            reality_public,
            echo: start_tcp_echo_server().await,
            decoy: start_tls_echo_server().await,
            payload: payload(PAYLOAD_LEN),
        }
    }
}

/// Deterministic, incompressible payload: a marker, then xorshift64* output.
///
/// A run of zeros would pass through every layer (and through any accidental
/// compression) unchanged, so it would prove much less than this does.
fn payload(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(b"<<flux-core/xray-matrix>>");
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    assert_eq!(out.len(), len);
    out
}

// ---------------------------------------------------------------------------
// The matrix of pairs
// ---------------------------------------------------------------------------

/// Builds the [`xc::Params`] every config builder reads from the fixture.
///
/// Ports are passed in rather than stored, so a retry gets freshly allocated
/// ones and the load-time acceptance test can use throwaway values.
fn params<'a>(fx: &'a Fixture, server_port: u16, socks_port: u16) -> xc::Params<'a> {
    xc::Params {
        server_port,
        socks_port,
        uuid: &fx.uuid,
        cert_path: &fx.cert_path,
        key_path: &fx.key_path,
        cert_sha256_hex: &fx.cert_sha256_hex,
        reality_private: &fx.reality_private,
        reality_public: &fx.reality_public,
        decoy_port: fx.decoy.port(),
        ss_password: &fx.ss_password,
    }
}

// ---------------------------------------------------------------------------
// Traffic
// ---------------------------------------------------------------------------

/// SOCKS5 no-auth CONNECT through `proxy_port` to `target`.
async fn socks5_connect(
    proxy_port: u16,
    target: SocketAddr,
    ctx: &str,
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect((xc::LOOPBACK, proxy_port))
        .await
        .map_err(|e| format!("{ctx}: connect to socks proxy failed: {e}"))?;

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("{ctx}: socks greeting: {e}"))?;
    let mut sel = [0u8; 2];
    stream
        .read_exact(&mut sel)
        .await
        .map_err(|e| format!("{ctx}: socks method reply: {e}"))?;
    if sel != [0x05, 0x00] {
        return Err(format!("{ctx}: socks method selection was {sel:?}"));
    }

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => return Err(format!("{ctx}: echo target must be IPv4")),
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&req)
        .await
        .map_err(|e| format!("{ctx}: socks CONNECT: {e}"))?;

    let mut resp = [0u8; 10];
    tokio::time::timeout(CASE_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .map_err(|_| format!("{ctx}: socks CONNECT reply timed out"))?
        .map_err(|e| format!("{ctx}: socks CONNECT reply: {e}"))?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(format!(
            "{ctx}: socks CONNECT refused: reply {:#04x?}",
            &resp[..2]
        ));
    }
    Ok(stream)
}

/// One lockstep round trip of [`PRIME_LEN`] bytes.
///
/// This is what moves Xray's Trojan outbound past its buffered header write
/// (see [`PRIME_LEN`]); for every other protocol it is simply the first proof
/// that the tunnel carries data. Waiting for the echo — rather than firing the
/// prime and the bulk push together — is the whole point: the outbound must see
/// *only* the small write while it is still setting up.
async fn prime_roundtrip(stream: &mut TcpStream, ctx: &str) -> Result<(), String> {
    let mut block = Vec::with_capacity(PRIME_LEN);
    block.extend_from_slice(b"<<flux-core/xray-matrix:prime>>");
    block.resize(PRIME_LEN, 0xa5);

    stream
        .write_all(&block)
        .await
        .map_err(|e| format!("{ctx}: prime write failed: {e}"))?;
    let mut got = vec![0u8; block.len()];
    tokio::time::timeout(CASE_TIMEOUT, stream.read_exact(&mut got))
        .await
        .map_err(|_| format!("{ctx}: prime echo timed out"))?
        .map_err(|e| format!("{ctx}: prime echo failed: {e}"))?;
    if got != block {
        return Err(format!("{ctx}: prime echo was corrupted"));
    }
    Ok(())
}

/// Pushes `payload` through `stream` and reads it back, both concurrently (a
/// megabyte does not fit in the socket buffers, so a sequential write would
/// deadlock), returning the elapsed time once every byte matched.
///
/// The write half is handed back instead of being dropped after the last byte:
/// dropping it would half-close the tunnel while the reply is still in flight,
/// which some transports tear down instead of draining.
async fn push_and_verify(stream: TcpStream, payload: &[u8]) -> Result<Duration, String> {
    let (mut reader, mut writer) = stream.into_split();
    let expected_len = payload.len();

    let writer_task = async move {
        let mut written = 0usize;
        for chunk in payload.chunks(WRITE_CHUNK) {
            writer.write_all(chunk).await.map_err(|e| {
                format!(
                    "write failed after {written} of {} bytes: {e}",
                    payload.len()
                )
            })?;
            written += chunk.len();
        }
        writer
            .flush()
            .await
            .map_err(|e| format!("flush failed: {e}"))?;
        Ok::<_, String>(writer)
    };

    let reader_task = async move {
        let mut got = vec![0u8; expected_len];
        reader.read_exact(&mut got).await.map_err(|e| {
            format!("read failed while waiting for {expected_len} echoed bytes: {e}")
        })?;
        Ok::<_, String>(got)
    };

    let started = Instant::now();
    let (written, read) = tokio::join!(writer_task, reader_task);
    let elapsed = started.elapsed();
    let _writer = written?;
    let got = read?;

    if got != payload {
        let first_mismatch = got
            .iter()
            .zip(payload.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(payload.len()));
        return Err(format!(
            "echo mismatch at byte {first_mismatch} (got {} bytes, sent {})",
            got.len(),
            payload.len()
        ));
    }
    Ok(elapsed)
}

/// One measured row of the matrix.
struct Row {
    name: &'static str,
    bytes: usize,
    elapsed: Duration,
}

impl Row {
    fn mib_per_second(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return f64::INFINITY;
        }
        (self.bytes as f64 / (1024.0 * 1024.0)) / secs
    }
}

/// Runs one pair end to end: start server, wait, start client, wait, CONNECT,
/// push, verify, tear down.
async fn run_case(protocol: xc::Protocol, fx: &Fixture) -> Result<Row, String> {
    let name = protocol.name();
    let server_port = get_free_tcp_port().await;
    let socks_port = get_free_tcp_port().await;
    let params = params(fx, server_port, socks_port);
    let server_cfg = protocol.server_config(&params);
    let client_cfg = protocol.client_config(&params);

    let mut server = XrayProcess::start(&server_cfg, &format!("{name}: xray server"))?;
    let client = match server.wait_for_listen(server_port).await {
        Ok(()) => {
            let mut client = XrayProcess::start(&client_cfg, &format!("{name}: xray client"))?;
            match client.wait_for_listen(socks_port).await {
                Ok(()) => client,
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };

    let outcome = async {
        let mut stream = socks5_connect(socks_port, fx.echo, name).await?;
        prime_roundtrip(&mut stream, name).await?;
        push_and_verify(stream, &fx.payload).await
    }
    .await;

    match outcome {
        Ok(elapsed) => {
            let row = Row {
                name,
                bytes: fx.payload.len(),
                elapsed,
            };
            // A rejected connection would not have echoed; surface it as a
            // diagnostic rather than letting a confusing pass-through hide it.
            for (role, proc) in [("server", &server), ("client", &client)] {
                let log = proc.log();
                if log.contains("rejected") || log.contains("failed to") {
                    eprintln!("[matrix] {name}: {role} log mentions a failure:\n{log}");
                }
            }
            Ok(row)
        }
        Err(e) => Err(format!(
            "{}\n--- server log ---\n{}\n--- client log ---\n{}",
            e,
            server.log(),
            client.log()
        )),
    }
}

/// Runs one pair, retrying a transient startup hiccup.
async fn run_with_retry(protocol: xc::Protocol, fx: &Fixture) -> Result<Row, String> {
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match run_case(protocol, fx).await {
            Ok(row) => return Ok(row),
            Err(e) => {
                if attempt < ATTEMPTS {
                    eprintln!(
                        "[matrix] {}: attempt {attempt} failed, retrying…",
                        protocol.name()
                    );
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                last = e;
            }
        }
    }
    Err(last)
}

// ---------------------------------------------------------------------------
// The test that proves the matrix
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn every_matrix_pair_carries_one_mebibyte() {
    let version = xray_version(&xray_bin());
    eprintln!(
        "[matrix] xray: {version} (shapes verified against {})",
        xc::XRAY_VERSION_TESTED
    );

    let fx = Fixture::new().await;
    let mut rows = Vec::new();
    let mut failures = Vec::new();

    // Every pair runs even after a failure, so one broken row does not hide the
    // state of the other eight.
    for protocol in xc::Protocol::ALL {
        match run_with_retry(protocol, &fx).await {
            Ok(row) => {
                eprintln!(
                    "[matrix] {:<22} ok   {:>7.1} ms  {:>7.2} MiB/s",
                    row.name,
                    row.elapsed.as_secs_f64() * 1000.0,
                    row.mib_per_second()
                );
                rows.push(row);
            }
            Err(e) => {
                eprintln!("[matrix] {:<22} FAIL", protocol.name());
                failures.push((protocol.name(), e));
            }
        }
    }

    println!("xray {version} — protocol matrix, {PAYLOAD_LEN} bytes per pair");
    println!(
        "{:<24} {:>10} {:>12} {:>12}",
        "protocol", "bytes", "elapsed", "throughput"
    );
    for row in &rows {
        println!(
            "{:<24} {:>10} {:>10.1} ms {:>8.2} MiB/s",
            row.name,
            row.bytes,
            row.elapsed.as_secs_f64() * 1000.0,
            row.mib_per_second()
        );
    }

    assert!(
        failures.is_empty(),
        "{} of {} protocol pairs failed:\n\n{}",
        failures.len(),
        xc::Protocol::ALL.len(),
        failures
            .iter()
            .map(|(name, why)| format!("### {name}\n{why}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    );
    assert_eq!(
        rows.len(),
        xc::Protocol::ALL.len(),
        "every protocol pair must be measured"
    );
}

// ---------------------------------------------------------------------------
// Load-time acceptance: Xray must accept each document without binding it
// ---------------------------------------------------------------------------

/// `xray run -test -c <file>` runs the full config loader but binds nothing,
/// which isolates "the shape is wrong" (fast, precise) from "the tunnel is
/// wrong" (slow, needs traffic).
fn xray_accepts(config: &str, label: &str) -> Result<(), String> {
    let dir = TempDir::new().map_err(|e| format!("{label}: tempdir: {e}"))?;
    let path = dir.path().join("config.json");
    fs::write(&path, config).map_err(|e| format!("{label}: write config: {e}"))?;
    let out = Command::new(xray_bin())
        .args(["run", "-test", "-c", path.to_str().unwrap()])
        .env("XRAY_LOCATION_ASSET", dir.path())
        .output()
        .map_err(|e| format!("{label}: failed to run xray -test: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success()
        || !(stdout.contains("Configuration OK") || stderr.contains("Configuration OK"))
    {
        return Err(format!(
            "{label}: xray refused the config ({})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            out.status
        ));
    }
    Ok(())
}

#[tokio::test]
async fn xray_accepts_every_generated_config() {
    let fx = Fixture::new().await;
    let mut failures = Vec::new();

    for protocol in xc::Protocol::ALL {
        // `-test` never binds, but the ports still come from the shared
        // allocator: a config that hardcoded one would only be noticed here.
        let server_port = get_free_tcp_port().await;
        let socks_port = get_free_tcp_port().await;
        let params = params(&fx, server_port, socks_port);
        let server_cfg = protocol.server_config(&params);
        let client_cfg = protocol.client_config(&params);
        for (role, cfg) in [("server", &server_cfg), ("client", &client_cfg)] {
            let label = format!("{}: {role}", protocol.name());
            if let Err(e) = xray_accepts(cfg, &label) {
                failures.push(e);
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} generated config(s) were refused by xray:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

// ---------------------------------------------------------------------------
// The recorded table must match what is exercised
// ---------------------------------------------------------------------------

#[test]
fn recorded_matrix_covers_every_exercised_pair() {
    // The table is the report's source of truth, so it must not drift from the
    // cases that actually run: same names, same order, no duplicates.
    let exercised: Vec<&str> = xc::Protocol::ALL.iter().map(|p| p.name()).collect();
    let recorded: Vec<&str> = xc::MATRIX.iter().map(|row| row.protocol).collect();
    assert_eq!(
        exercised, recorded,
        "xray_matrix_configs::MATRIX must list exactly the pairs the test runs, in order"
    );

    for row in xc::MATRIX {
        assert!(
            row.xray_server.is_usable() && row.xray_client.is_usable(),
            "{}: a usable pair must not carry an unusable role",
            row.protocol
        );
        assert!(
            !row.note.is_empty(),
            "{}: every row needs a note explaining its shape",
            row.protocol
        );
    }

    // The two roles' caveats are what the report quotes; a supported-but-
    // caveated role must say why.
    for row in xc::MATRIX {
        for support in [row.xray_server, row.xray_client] {
            if let xc::Support::YesWithCaveat(reason) = support {
                assert!(
                    reason.len() > 20,
                    "{}: a caveat must explain itself, got {reason:?}",
                    row.protocol
                );
            }
        }
    }
}
