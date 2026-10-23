//! Transparent inbound end-to-end tests: TUN (smoltcp), TPROXY and REDIRECT.
//!
//! # These tests are *real* — and they prove it
//!
//! Every test here moves actual IP packets through the inbound under test and
//! asserts the payload comes back byte-for-byte. Because creating a TUN device,
//! programming iptables and binding `IP_TRANSPARENT` sockets all need
//! `CAP_NET_ADMIN`, each test first *re-executes itself* inside a fresh
//! user + network namespace:
//!
//! ```text
//! unshare --user --map-root-user --net <test-binary> --exact <test-name>
//! ```
//!
//! Inside that namespace the process is `uid 0` with full `CAP_NET_ADMIN` over a
//! brand-new network stack, so the test body runs unmodified, as root, without
//! ever needing passwordless sudo. Because the namespace is torn down when the
//! child exits, every test also gets a private, collision-free network
//! (`iptables` rules, interface names, routes, ports) even when the whole test
//! binary runs its tests in parallel.
//!
//! # No vacuous passes
//!
//! * The child prints [`E2E_MARKER`] **only after** the byte-for-byte assertions
//!   have passed. The parent process fails the test unless the child both exits
//!   successfully *and* printed the marker — a child that silently did nothing
//!   can therefore never be mistaken for a pass.
//! * If `unshare` is genuinely unavailable/permitted here, the test prints a
//!   loud `SKIP:` line and **fails** unless `FLUX_ALLOW_TRANSPARENT_SKIP=1` is
//!   set, in which case it prints a `SUMMARY:` line saying that nothing was
//!   verified. Skips are never reported as silent passes.
//! * Each test additionally cross-checks the kernel-side evidence that the
//!   packet really took the intended path (`ip -s link` counters on the TUN
//!   device, `iptables -L -v` packet counters on the TPROXY/REDIRECT rules,
//!   byte counters on the echo server). A test that "passed" because the
//!   traffic was short-circuited past the inbound under test fails instead.
//!
//! # What can and cannot be exercised in a user namespace
//!
//! All three mechanics work: `/dev/net/tun` is a device-node access (checked,
//! not namespaced), and since Linux 5.x netfilter, policy routing and
//! `IP_TRANSPARENT` are fully namespaced and available to the owner of the
//! network namespace. `ip netns add` does *not* work (it wants to create
//! `/var/run/netns`, which is not writable from an unprivileged user
//! namespace), so the TPROXY test makes its traffic traverse `PREROUTING`
//! without a second network namespace: it routes the client's packets out one
//! end of a veth pair whose other end lives in the *same* namespace, so the
//! frame re-enters the stack on the peer device and hits `PREROUTING` exactly
//! like traffic from a real upstream link. That needs `accept_local=1` and
//! `rp_filter=0` (set in [`setup_loopback_and_sysctls`]).

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use flux_app::{Config, Instance};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::time::timeout;

/// Printed by a test body *after* it verified a real end-to-end exchange.
/// The parent process requires this marker before it accepts the child's exit
/// status as a pass, so a no-op child can never produce a vacuous `ok`.
const E2E_MARKER: &str = "FLUX-E2E-PROVEN";

/// Set on the re-executed child so it does not recurse into `unshare`.
const NS_CHILD_ENV: &str = "FLUX_TRANSPARENT_NS_CHILD";

/// Escape hatch for machines that forbid unprivileged user namespaces: turns
/// the otherwise-fatal "cannot run" case into a loud, visible skip.
const ALLOW_SKIP_ENV: &str = "FLUX_ALLOW_TRANSPARENT_SKIP";

/// Upper bound on a re-executed child, so a hung test fails instead of hanging
/// `cargo test` forever.
const CHILD_TIMEOUT: Duration = Duration::from_secs(180);

// ---------------------------------------------------------------------------
// namespace bootstrap
// ---------------------------------------------------------------------------

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn is_ns_child() -> bool {
    std::env::var_os(NS_CHILD_ENV).is_some()
}

/// Returns `true` when the test body has to run in *this* process.
///
/// `false` means the body either already ran (and passed) inside a freshly
/// re-executed root namespace, or that the test was skipped loudly.
fn must_run_here(test_name: &str) -> bool {
    if is_ns_child() {
        assert!(
            is_root(),
            "{test_name}: re-executed inside a user namespace but still not uid 0 — \
             `unshare --map-root-user` did not do what we expect"
        );
        eprintln!("[ns] {test_name}: uid=0 with CAP_NET_ADMIN in a private netns");
        return true;
    }
    if is_root() {
        eprintln!("[ns] {test_name}: already root, running the privileged path in place");
        return true;
    }
    match reexec_in_userns(test_name) {
        Ok(()) => false,
        Err(ReexecError::Environment(reason)) => skip_or_fail(test_name, &reason),
        Err(ReexecError::Failed(reason)) => panic!("{reason}"),
    }
}

/// Why a re-executed run produced no result.
enum ReexecError {
    /// The machine cannot provide the privileges (no `unshare`, no user
    /// namespaces, `/dev/net/tun` missing, …) — an environment problem.
    Environment(String),
    /// The child ran and the end-to-end verification failed.
    Failed(String),
}

/// Loud skip, or a hard failure that explains itself.
///
/// A test that verifies a datapath must never report `ok` while doing nothing,
/// so skipping is a failure unless explicitly allowed by [`ALLOW_SKIP_ENV`].
fn skip_or_fail(test_name: &str, reason: &str) -> bool {
    eprintln!("SKIP: {test_name}: {reason}");
    if std::env::var_os(ALLOW_SKIP_ENV).is_some() {
        eprintln!(
            "SUMMARY: {test_name}: NOTHING WAS VERIFIED (skipped: {reason}). \
             This is not a pass — {ALLOW_SKIP_ENV} downgraded the failure to a visible skip."
        );
        return false;
    }
    panic!(
        "SKIP: {test_name} could not run ({reason}).\n\
         This test verifies a real kernel datapath and must not pass vacuously.\n\
         Fix the environment (allow unprivileged user namespaces), or — if this \
         machine genuinely cannot provide one — re-run with {ALLOW_SKIP_ENV}=1 to \
         downgrade the hard failure to an explicit, loud skip."
    );
}

/// Re-executes this test binary inside `unshare --user --map-root-user --net`
/// and verifies that the child really ran the test (marker + exit status).
fn reexec_in_userns(test_name: &str) -> Result<(), ReexecError> {
    probe_userns().map_err(ReexecError::Environment)?;

    let exe = std::env::current_exe()
        .map_err(|e| ReexecError::Environment(format!("current_exe() failed: {e}")))?;
    let log_path = std::env::temp_dir().join(format!(
        "flux-transparent-{}-{}.log",
        std::process::id(),
        test_name
    ));
    let log = std::fs::File::create(&log_path).map_err(|e| {
        ReexecError::Environment(format!(
            "cannot create child log {}: {e}",
            log_path.display()
        ))
    })?;
    let log_err = log
        .try_clone()
        .map_err(|e| ReexecError::Environment(format!("cannot clone child log handle: {e}")))?;

    // `unshare` keeps the cwd and the environment, so the child resolves the
    // same test-binary-relative paths as `cargo test` did.
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(&exe)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(NS_CHILD_ENV, "1")
        // Inside a user namespace `/run` is still the host's, so the real
        // `xtables.lock` is unreadable and every iptables call dies with
        // "can't open lock file /run/xtables.lock: Permission denied". Point the
        // lock at a private file instead: the namespace has its own iptables
        // state anyway, so the lock only needs to be private to this child.
        .env(
            "XTABLES_LOCKFILE",
            // Unique per test: the tests run in parallel, and a shared lock file
            // makes them fail with "Resource temporarily unavailable".
            std::env::temp_dir().join(format!(
                "flux-xtables-{}-{}.lock",
                std::process::id(),
                test_name
            )),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| ReexecError::Environment(format!("failed to spawn `unshare`: {e}")))?;

    let deadline = std::time::Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let out = std::fs::read_to_string(&log_path).unwrap_or_default();
                    eprintln!("{out}");
                    panic!(
                        "{test_name}: child inside the namespace timed out after {CHILD_TIMEOUT:?}"
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                return Err(ReexecError::Environment(format!(
                    "waiting for the namespace child failed: {e}"
                )));
            }
        }
    };

    let out = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = std::fs::remove_file(&log_path);
    // Surface the child's own output (including any panic message) so that
    // `cargo test -- --nocapture` shows what actually happened.
    for line in out.lines() {
        eprintln!("    | {line}");
    }

    if !status.success() {
        return Err(ReexecError::Failed(format!(
            "{test_name} FAILED inside the namespace (exit {status}) — see the child output above"
        )));
    }
    if !out.contains(E2E_MARKER) {
        return Err(ReexecError::Failed(format!(
            "{test_name}: child exited successfully but never printed `{E2E_MARKER}`: the test \
             body did not verify anything. Refusing to report a vacuous pass"
        )));
    }
    eprintln!("[ns] {test_name}: verified end-to-end inside the namespace");
    Ok(())
}

/// `unshare` may exist but be unable to create a user namespace (hardened
/// kernels, seccomp, `kernel.unprivileged_userns_clone=0`). Probe it first so
/// that an environment limitation is reported as a skip, never as a test
/// failure and never as a silent pass.
fn probe_userns() -> Result<(), String> {
    match Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--", "true"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            Err(format!(
                "`unshare --user --map-root-user --net` is not permitted here ({}): {err}",
                o.status
            ))
        }
        Err(e) => Err(format!("`unshare` is unavailable: {e}")),
    }
}

// ---------------------------------------------------------------------------
// shell / netns plumbing
// ---------------------------------------------------------------------------

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
        Err(format!(
            "command failed ({})\n  cmd: {cmd}\n  output: {}",
            out.status,
            text.trim()
        ))
    }
}

/// Like [`sh`] but panics with the command, status and output on failure.
fn sh_ok(cmd: &str) -> String {
    match sh(cmd) {
        Ok(out) => out,
        Err(e) => panic!("[netns setup] {e}"),
    }
}

/// Best-effort teardown so a run *as real root* (no namespace) does not leave
/// iptables rules and interfaces behind. Inside a namespace the whole network
/// stack is discarded on exit, so this is only belt-and-braces.
#[derive(Default)]
struct Cleanup(Vec<String>);

impl Cleanup {
    fn new() -> Self {
        Self::default()
    }

    fn on(&mut self, cmd: impl Into<String>) {
        self.0.push(cmd.into());
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for cmd in self.0.iter().rev() {
            let _ = sh(cmd);
        }
    }
}

fn write_sysctl(name: &str, value: &str) {
    let path = format!("/proc/sys/net/ipv4/conf/{name}");
    let _ = std::fs::write(&path, value);
}

/// Brings loopback up and relaxes the two knobs the TPROXY layout needs:
///
/// * `rp_filter=0` — the client's packets leave through one end of a veth pair
///   and come back in the other end of the *same* namespace, which strict
///   reverse-path filtering would otherwise classify as spoofed.
/// * `accept_local=1` — the client's source address is a local address, so the
///   re-entering frame carries a "local" source; without this the kernel drops
///   it as a martian before it can reach `PREROUTING`.
fn setup_loopback_and_sysctls() {
    sh_ok("ip link set lo up");
    for iface in ["all", "default", "lo"] {
        write_sysctl(&format!("{iface}/rp_filter"), "0");
        write_sysctl(&format!("{iface}/accept_local"), "1");
    }
}

/// Waits until the kernel reports the interface created by the TUN inbound.
fn wait_for_iface(name: &str) {
    for _ in 0..300 {
        if let Ok(out) = sh(&format!("ip link show {name}"))
            && out.contains(name)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("TUN interface `{name}` never appeared — did the inbound create it?");
}

/// Packet counters from `ip -s link show <dev>`: `(rx_packets, tx_packets)`.
///
/// For a TUN device, userspace→kernel frames are reported as `RX` and
/// kernel→userspace frames as `TX`, so both being non-zero proves traffic
/// really crossed the device in both directions.
fn parse_iface_packets(ip_s_link: &str) -> (u64, u64) {
    fn grab(lines: &[&str], tag: &str) -> u64 {
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with(tag)
                && let Some(next) = lines.get(i + 1)
            {
                let cols: Vec<&str> = next.split_whitespace().collect();
                if cols.len() >= 2 {
                    return cols[1].parse().unwrap_or(0);
                }
            }
        }
        0
    }
    let lines: Vec<&str> = ip_s_link.lines().collect();
    (grab(&lines, "RX:"), grab(&lines, "TX:"))
}

/// Packet count of the first `iptables -L -v` row whose target matches `needle`.
fn rule_packets(listing: &str, needle: &str) -> u64 {
    listing
        .lines()
        .filter(|l| l.contains(needle))
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|f| f.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

fn ether_addr(ip_link_show: &str) -> Option<String> {
    ip_link_show
        .lines()
        .find(|l| l.contains("link/ether"))
        .and_then(|l| l.split_whitespace().nth(1))
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// echo servers and clients
// ---------------------------------------------------------------------------

/// A TCP/UDP echo server plus the counters used to prove traffic reached it.
struct Echo {
    bytes: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
}

async fn start_tcp_echo(addr: SocketAddr) -> Echo {
    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("echo server cannot bind {addr}: {e}"));
    let bytes = Arc::new(AtomicU64::new(0));
    let connections = Arc::new(AtomicU64::new(0));
    let (b, c) = (bytes.clone(), connections.clone());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            c.fetch_add(1, Ordering::Relaxed);
            let _ = socket.set_nodelay(true);
            let b = b.clone();
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(socket);
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            b.fetch_add(n as u64, Ordering::Relaxed);
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Echo { bytes, connections }
}

async fn start_udp_echo(addr: SocketAddr) -> Echo {
    let socket = UdpSocket::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("udp echo server cannot bind {addr}: {e}"));
    let bytes = Arc::new(AtomicU64::new(0));
    let connections = Arc::new(AtomicU64::new(0));
    let (b, c) = (bytes.clone(), connections.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            c.fetch_add(1, Ordering::Relaxed);
            b.fetch_add(n as u64, Ordering::Relaxed);
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    Echo { bytes, connections }
}

/// Connects from an explicit source address — required so the tests can tell
/// the *client's* packets apart from the proxy's own outbound dials in the
/// iptables rules (e.g. "RETURN for the client, DNAT for everyone else").
async fn tcp_roundtrip(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let sock = TcpSocket::new_v4().expect("TcpSocket::new_v4");
    sock.bind(src)
        .unwrap_or_else(|e| panic!("cannot bind client source {src}: {e}"));
    sock.set_nodelay(true).expect("set_nodelay");
    let mut stream = sock
        .connect(dst)
        .await
        .unwrap_or_else(|e| panic!("connect {src} -> {dst} failed: {e}"));
    stream.write_all(payload).await.expect("write payload");
    let mut got = vec![0u8; payload.len()];
    stream
        .read_exact(&mut got)
        .await
        .expect("read echoed payload");
    got
}

async fn udp_roundtrip(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind(src)
        .await
        .unwrap_or_else(|e| panic!("cannot bind udp client source {src}: {e}"));
    socket
        .send_to(payload, dst)
        .await
        .unwrap_or_else(|e| panic!("send to {dst} failed: {e}"));
    let mut buf = vec![0u8; 65535];
    let (n, from) = socket
        .recv_from(&mut buf)
        .await
        .unwrap_or_else(|e| panic!("no reply from {dst}: {e}"));
    assert_eq!(
        from.port(),
        dst.port(),
        "reply must come back from the original destination port"
    );
    buf.truncate(n);
    buf
}

fn config_with_inbound(inbound_json: &str) -> Config {
    Config::from_json_str(&format!(
        r#"{{ "inbounds": [ {inbound_json} ],
              "outbounds": [ {{ "type": "direct", "tag": "direct" }} ] }}"#
    ))
    .expect("test config must parse")
}

fn tunnel_config(iface: &str) -> Config {
    config_with_inbound(&format!(
        r#"{{ "type": "tun", "tag": "tun-in", "interface_name": "{iface}" }}"#
    ))
}

// ---------------------------------------------------------------------------
// TUN
// ---------------------------------------------------------------------------

/// TUN/TCP end-to-end: a client packet routed into the flux TUN device is
/// terminated by the userspace (smoltcp) stack, dispatched to the `direct`
/// outbound, and the echoed payload travels back through the tunnel.
///
/// Nothing here is a stub: the client is a real kernel socket, the route sends
/// it into the TUN device, flux's own connection to the *recovered* destination
/// is the only thing that can reach the echo server (see the `DNAT` rule), and
/// the TUN device's own packet counters must move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tun_inbound_tcp_e2e() {
    const NAME: &str = "test_tun_inbound_tcp_e2e";
    if !must_run_here(NAME) {
        return;
    }

    const TUN: &str = "fluxtun0";
    const TUN_LOCAL: &str = "10.99.0.1";
    const CLIENT: &str = "10.99.0.2";
    const TARGET: &str = "10.99.66.2";
    const PORT: u16 = 19_000;

    let mut cleanup = Cleanup::new();
    setup_loopback_and_sysctls();

    // The client's source address lives on lo; the *destination* must not, or
    // the kernel would deliver the connection locally instead of into the TUN.
    sh_ok(&format!("ip addr add {CLIENT}/32 dev lo"));
    cleanup.on(format!("ip addr del {CLIENT}/32 dev lo"));

    // The real server sits behind the proxy on loopback.
    let echo = start_tcp_echo(SocketAddr::from(([127, 0, 0, 1], PORT))).await;

    let instance = Instance::new(tunnel_config(TUN)).expect("tun config");
    instance
        .start()
        .await
        .expect("TUN inbound failed to start (no CAP_NET_ADMIN / /dev/net/tun?)");
    wait_for_iface(TUN);

    sh_ok(&format!("ip link set {TUN} up"));
    sh_ok(&format!("ip addr add {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip route del {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip addr del {TUN_LOCAL}/24 dev {TUN}"));

    // The client's connection must NOT be shortcut to the echo server: it has to
    // go through the TUN. The proxy's *own* dial to the recovered destination
    // (10.99.66.2:19000) is the only connection that is DNATed to the echo
    // server, so a round trip proves the original destination survived.
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));

    let payload = b"tun/tcp: payload must survive kernel -> smoltcp -> direct -> kernel";
    let got = timeout(
        Duration::from_secs(20),
        tcp_roundtrip(
            format!("{CLIENT}:0").parse().unwrap(),
            format!("{TARGET}:{PORT}").parse().unwrap(),
            payload,
        ),
    )
    .await
    .expect("timed out: no echo came back through the TUN tunnel");
    assert_eq!(got, payload, "payload was mangled by the TUN datapath");

    // Cross-check 1: the packets really traversed the TUN device.
    let stats = sh_ok(&format!("ip -s link show {TUN}"));
    let (rx, tx) = parse_iface_packets(&stats);
    assert!(
        rx > 0 && tx > 0,
        "TUN device saw no traffic (rx={rx} tx={tx}) — the connection was short-circuited \
         somewhere else, this test would otherwise pass vacuously:\n{stats}"
    );

    // Cross-check 2: the proxy dialled the *original* destination (only that
    // destination is DNATed to the echo server).
    let nat = sh_ok("iptables -t nat -L OUTPUT -v -n");
    let dnat_hits = rule_packets(&nat, "DNAT");
    assert!(
        dnat_hits > 0,
        "the direct outbound never dialled {TARGET}:{PORT} (DNAT counter is 0):\n{nat}"
    );

    // Cross-check 3: the echo server really served the bytes.
    assert!(
        echo.bytes.load(Ordering::Relaxed) >= payload.len() as u64,
        "echo server received {} bytes, expected at least {}",
        echo.bytes.load(Ordering::Relaxed),
        payload.len()
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {} bytes echoed 3-way, tun rx={rx} tx={tx}, dnat_hits={dnat_hits}, \
         echo_conns={}",
        payload.len(),
        echo.connections.load(Ordering::Relaxed)
    );

    let _ = instance.stop().await;
}

/// TUN/UDP end-to-end: a datagram routed into the TUN is terminated by the
/// userspace stack, proxied by the `direct` outbound and echoed back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tun_inbound_udp_e2e() {
    const NAME: &str = "test_tun_inbound_udp_e2e";
    if !must_run_here(NAME) {
        return;
    }

    const TUN: &str = "fluxtun1";
    const TUN_LOCAL: &str = "10.98.0.1";
    const CLIENT: &str = "10.98.0.2";
    const TARGET: &str = "10.98.66.2";
    const PORT: u16 = 19_001;

    let mut cleanup = Cleanup::new();
    setup_loopback_and_sysctls();

    sh_ok(&format!("ip addr add {CLIENT}/32 dev lo"));
    cleanup.on(format!("ip addr del {CLIENT}/32 dev lo"));

    let echo = start_udp_echo(SocketAddr::from(([127, 0, 0, 1], PORT))).await;

    let instance = Instance::new(tunnel_config(TUN)).expect("tun config");
    instance.start().await.expect("TUN inbound failed to start");
    wait_for_iface(TUN);

    sh_ok(&format!("ip link set {TUN} up"));
    sh_ok(&format!("ip addr add {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip route del {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip addr del {TUN_LOCAL}/24 dev {TUN}"));

    // The `direct` UDP socket is unbound (0.0.0.0), so it is the only sender
    // that can reach the echo: the client's own datagrams are excluded.
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p udp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p udp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p udp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p udp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));

    let payload = b"tun/udp datagram through smoltcp";
    let got = timeout(
        Duration::from_secs(20),
        udp_roundtrip(
            format!("{CLIENT}:0").parse().unwrap(),
            format!("{TARGET}:{PORT}").parse().unwrap(),
            payload,
        ),
    )
    .await
    .expect("timed out: no datagram came back through the TUN tunnel");
    assert_eq!(got, payload, "datagram was mangled by the TUN datapath");

    let stats = sh_ok(&format!("ip -s link show {TUN}"));
    let (rx, tx) = parse_iface_packets(&stats);
    assert!(
        rx > 0 && tx > 0,
        "TUN device saw no traffic (rx={rx} tx={tx}):\n{stats}"
    );
    assert!(
        echo.bytes.load(Ordering::Relaxed) >= payload.len() as u64,
        "udp echo server never saw the datagram"
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {} byte datagram echoed, tun rx={rx} tx={tx}",
        payload.len()
    );

    let _ = instance.stop().await;
}

// ---------------------------------------------------------------------------
// TPROXY
// ---------------------------------------------------------------------------

/// TPROXY/TCP end-to-end, with the diverted traffic really arriving through
/// `PREROUTING` (see the module docs for the veth trick that replaces a second
/// network namespace).
///
/// The client connects to `10.99.66.3:19010`, which does not exist anywhere.
/// The mangle `TPROXY` rule hands the connection to flux with
/// `IP_TRANSPARENT`; flux must recover `10.99.66.3:19010` as the original
/// destination (that is the *only* destination the `DNAT` rule rewrites to the
/// echo server) and relay the payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tproxy_inbound_tcp_e2e() {
    const NAME: &str = "test_tproxy_inbound_tcp_e2e";
    if !must_run_here(NAME) {
        return;
    }

    const V0: &str = "veth-tproxy0";
    const V1: &str = "veth-tproxy1";
    const CLIENT: &str = "10.201.0.2";
    const PROXY_SRC: &str = "10.201.0.1";
    const TARGET: &str = "10.99.66.3";
    /// Port the client *thinks* it is talking to.
    const TARGET_PORT: u16 = 19_010;
    /// Port flux listens on with `IP_TRANSPARENT`.
    const FLUX_PORT: u16 = 19_011;
    /// Port the real echo server listens on.
    const ECHO_PORT: u16 = 19_012;

    setup_loopback_and_sysctls();
    let mut cleanup = Cleanup::new();

    // A veth pair with both ends in this namespace: the client's frame leaves
    // one end and re-enters on the other, so it traverses PREROUTING exactly
    // like traffic arriving from a real upstream device.
    sh_ok(&format!("ip link add {V0} type veth peer name {V1}"));
    cleanup.on(format!("ip link del {V0}"));
    sh_ok(&format!("ip link set {V0} up"));
    sh_ok(&format!("ip link set {V1} up"));
    sh_ok(&format!("ip addr add {PROXY_SRC}/24 dev {V0}"));
    sh_ok(&format!("ip addr add {CLIENT}/24 dev {V1}"));
    for iface in [V0, V1] {
        write_sysctl(&format!("{iface}/rp_filter"), "0");
        write_sysctl(&format!("{iface}/accept_local"), "1");
    }

    // Static neighbour entry: TARGET is on-link via V0, and the first frame
    // would otherwise be dropped while ARP is still unresolved.
    let v1_mac = ether_addr(&sh_ok(&format!("ip link show {V1}")))
        .unwrap_or_else(|| panic!("cannot read the MAC address of {V1}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {V0}"));
    sh_ok(&format!(
        "ip neigh replace {TARGET} lladdr {v1_mac} dev {V0} nud permanent"
    ));
    cleanup.on(format!("ip route del {TARGET}/32 dev {V0}"));

    // The real TPROXY plumbing: intercept in mangle/PREROUTING, mark the
    // packet, and route marked packets locally so they reach the transparent
    // socket instead of being forwarded.
    sh_ok(&format!(
        "iptables -t mangle -A PREROUTING -p tcp -d {TARGET} --dport {TARGET_PORT} \
         -j TPROXY --on-port {FLUX_PORT} --tproxy-mark 0x1/0x1"
    ));
    cleanup.on(format!(
        "iptables -t mangle -D PREROUTING -p tcp -d {TARGET} --dport {TARGET_PORT} \
         -j TPROXY --on-port {FLUX_PORT} --tproxy-mark 0x1/0x1"
    ));
    sh_ok("ip rule add fwmark 1 lookup 100");
    cleanup.on("ip rule del fwmark 1 lookup 100");
    sh_ok("ip route add local 0.0.0.0/0 dev lo table 100");
    cleanup.on("ip route del local 0.0.0.0/0 dev lo table 100");

    let echo = start_tcp_echo(SocketAddr::from(([127, 0, 0, 1], ECHO_PORT))).await;

    // flux's own dial to the recovered destination must reach the echo server;
    // the client's diverted connection must not be touched by this rule.
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {TARGET_PORT} -j RETURN"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {TARGET_PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -d {TARGET} --dport {TARGET_PORT} \
         -j DNAT --to-destination 127.0.0.1:{ECHO_PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -d {TARGET} --dport {TARGET_PORT} \
         -j DNAT --to-destination 127.0.0.1:{ECHO_PORT}"
    ));

    let instance = Instance::new(config_with_inbound(&format!(
        r#"{{ "type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": {FLUX_PORT} }}"#
    )))
    .expect("tproxy config");
    instance
        .start()
        .await
        .expect("TPROXY inbound failed to start (IP_TRANSPARENT needs CAP_NET_ADMIN)");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let payload = b"tproxy/tcp: original destination recovered via IP_TRANSPARENT";
    let got = timeout(
        Duration::from_secs(20),
        tcp_roundtrip(
            format!("{CLIENT}:0").parse().unwrap(),
            format!("{TARGET}:{TARGET_PORT}").parse().unwrap(),
            payload,
        ),
    )
    .await
    .expect("timed out: TPROXY diverted connection did not reach the echo server");
    assert_eq!(got, payload, "payload was mangled by the TPROXY datapath");

    // Proof the traffic was really diverted by the netfilter rule rather than
    // short-circuited: the rule only matches the client's destination tuple.
    let mangle = sh_ok("iptables -t mangle -L PREROUTING -v -n");
    let hits = rule_packets(&mangle, "TPROXY");
    assert!(
        hits > 0,
        "the mangle TPROXY rule never matched a packet — the connection did not arrive through \
         PREROUTING:\n{mangle}"
    );
    assert!(
        echo.connections.load(Ordering::Relaxed) > 0,
        "the echo server at the original destination was never reached"
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {} bytes echoed through TPROXY, prerouting_hits={hits}, \
         echo_conns={}",
        payload.len(),
        echo.connections.load(Ordering::Relaxed)
    );

    let _ = instance.stop().await;
}

// ---------------------------------------------------------------------------
// REDIRECT
// ---------------------------------------------------------------------------

/// REDIRECT/TCP end-to-end: an `iptables -j REDIRECT` rule (nat/OUTPUT) sends
/// the client's connection to flux, which must recover the real destination
/// with `SO_ORIGINAL_DST` and relay to it.
///
/// The echo server lives at the *original* destination (`10.99.66.4:19020`),
/// so the round trip can only succeed if `SO_ORIGINAL_DST` is correct: flux
/// dialling anything else (its own listener address, the redirect target, …)
/// cannot produce the echoed payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_redirect_inbound_tcp_e2e() {
    const NAME: &str = "test_redirect_inbound_tcp_e2e";
    if !must_run_here(NAME) {
        return;
    }

    const CLIENT: &str = "10.99.0.2";
    const TARGET: &str = "10.99.66.4";
    /// Port the client connects to (and where the echo server really listens).
    const ECHO_PORT: u16 = 19_020;
    /// Port flux listens on after REDIRECT.
    const FLUX_PORT: u16 = 19_021;

    setup_loopback_and_sysctls();
    let mut cleanup = Cleanup::new();

    // The "internet" of this test: the target address is local, so the echo
    // server can live at the real destination.
    sh_ok(&format!("ip addr add {TARGET}/32 dev lo"));
    cleanup.on(format!("ip addr del {TARGET}/32 dev lo"));
    sh_ok(&format!("ip addr add {CLIENT}/32 dev lo"));
    cleanup.on(format!("ip addr del {CLIENT}/32 dev lo"));

    let echo = start_tcp_echo(format!("{TARGET}:{ECHO_PORT}").parse().unwrap()).await;

    let instance = Instance::new(config_with_inbound(&format!(
        r#"{{ "type": "redirect", "tag": "redirect-in", "listen": "0.0.0.0", "listen_port": {FLUX_PORT} }}"#
    )))
    .expect("redirect config");
    instance
        .start()
        .await
        .expect("REDIRECT inbound failed to start");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Divert only the client's connections (the proxy's own dial to the
    // original destination must go straight to the echo server, otherwise the
    // proxy would redirect itself in a loop).
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {ECHO_PORT} \
         -j REDIRECT --to-ports {FLUX_PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {ECHO_PORT} \
         -j REDIRECT --to-ports {FLUX_PORT}"
    ));

    let payload = b"redirect/tcp: SO_ORIGINAL_DST must point at the real server";
    let got = timeout(
        Duration::from_secs(20),
        tcp_roundtrip(
            format!("{CLIENT}:0").parse().unwrap(),
            format!("{TARGET}:{ECHO_PORT}").parse().unwrap(),
            payload,
        ),
    )
    .await
    .expect("timed out: REDIRECTed connection did not reach the original destination");
    assert_eq!(got, payload, "payload was mangled by the REDIRECT datapath");

    let nat = sh_ok("iptables -t nat -L OUTPUT -v -n");
    let hits = rule_packets(&nat, "REDIRECT");
    assert!(
        hits > 0,
        "the REDIRECT rule never matched a packet — traffic did not take the diverted path:\n{nat}"
    );
    assert!(
        echo.connections.load(Ordering::Relaxed) > 0,
        "the echo server at the original destination was never reached, so SO_ORIGINAL_DST \
         cannot have been recovered correctly"
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {} bytes echoed through REDIRECT, redirect_hits={hits}, echo_conns={}",
        payload.len(),
        echo.connections.load(Ordering::Relaxed)
    );

    let _ = instance.stop().await;
}
/// TPROXY/UDP end-to-end: this exercises the `recvmsg()` control-message path
/// (`IP_RECVORIGDSTADDR`) and the transparent reply socket, which are the two
/// pieces of the UDP TPROXY implementation that cannot be covered without
/// real netfilter plumbing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tproxy_inbound_udp_e2e() {
    const NAME: &str = "test_tproxy_inbound_udp_e2e";
    if !must_run_here(NAME) {
        return;
    }

    const V0: &str = "veth-tp-udp0";
    const V1: &str = "veth-tp-udp1";
    const CLIENT: &str = "10.202.0.2";
    const PROXY_SRC: &str = "10.202.0.1";
    const TARGET: &str = "10.99.66.5";
    const TARGET_PORT: u16 = 19_015;
    const FLUX_PORT: u16 = 19_016;
    const ECHO_PORT: u16 = 19_017;

    setup_loopback_and_sysctls();
    let mut cleanup = Cleanup::new();

    sh_ok(&format!("ip link add {V0} type veth peer name {V1}"));
    cleanup.on(format!("ip link del {V0}"));
    sh_ok(&format!("ip link set {V0} up"));
    sh_ok(&format!("ip link set {V1} up"));
    sh_ok(&format!("ip addr add {PROXY_SRC}/24 dev {V0}"));
    sh_ok(&format!("ip addr add {CLIENT}/24 dev {V1}"));
    for iface in [V0, V1] {
        write_sysctl(&format!("{iface}/rp_filter"), "0");
        write_sysctl(&format!("{iface}/accept_local"), "1");
    }
    let v1_mac = ether_addr(&sh_ok(&format!("ip link show {V1}")))
        .unwrap_or_else(|| panic!("cannot read the MAC address of {V1}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {V0}"));
    sh_ok(&format!(
        "ip neigh replace {TARGET} lladdr {v1_mac} dev {V0} nud permanent"
    ));
    cleanup.on(format!("ip route del {TARGET}/32 dev {V0}"));

    sh_ok(&format!(
        "iptables -t mangle -A PREROUTING -p udp -d {TARGET} --dport {TARGET_PORT} \
         -j TPROXY --on-port {FLUX_PORT} --tproxy-mark 0x1/0x1"
    ));
    cleanup.on(format!(
        "iptables -t mangle -D PREROUTING -p udp -d {TARGET} --dport {TARGET_PORT} \
         -j TPROXY --on-port {FLUX_PORT} --tproxy-mark 0x1/0x1"
    ));
    sh_ok("ip rule add fwmark 1 lookup 100");
    cleanup.on("ip rule del fwmark 1 lookup 100");
    sh_ok("ip route add local 0.0.0.0/0 dev lo table 100");
    cleanup.on("ip route del local 0.0.0.0/0 dev lo table 100");

    let echo = start_udp_echo(SocketAddr::from(([127, 0, 0, 1], ECHO_PORT))).await;

    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p udp -s {CLIENT} -d {TARGET} --dport {TARGET_PORT} -j RETURN"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p udp -s {CLIENT} -d {TARGET} --dport {TARGET_PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p udp -d {TARGET} --dport {TARGET_PORT} \
         -j DNAT --to-destination 127.0.0.1:{ECHO_PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p udp -d {TARGET} --dport {TARGET_PORT} \
         -j DNAT --to-destination 127.0.0.1:{ECHO_PORT}"
    ));

    let instance = Instance::new(config_with_inbound(&format!(
        r#"{{ "type": "tproxy", "tag": "tproxy-udp-in", "listen": "0.0.0.0", "listen_port": {FLUX_PORT} }}"#
    )))
    .expect("tproxy udp config");
    instance
        .start()
        .await
        .expect("TPROXY (UDP) inbound failed to start");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let payload = b"tproxy/udp: RECVORIGDSTADDR + transparent reply";
    let got = timeout(
        Duration::from_secs(20),
        udp_roundtrip(
            format!("{CLIENT}:0").parse().unwrap(),
            format!("{TARGET}:{TARGET_PORT}").parse().unwrap(),
            payload,
        ),
    )
    .await
    .expect("timed out: TPROXY-diverted datagram got no reply");
    assert_eq!(
        got, payload,
        "datagram was mangled by the UDP TPROXY datapath"
    );

    let mangle = sh_ok("iptables -t mangle -L PREROUTING -v -n");
    let hits = rule_packets(&mangle, "TPROXY");
    assert!(
        hits > 0,
        "the UDP TPROXY rule never matched a packet:\n{mangle}"
    );
    assert!(
        echo.bytes.load(Ordering::Relaxed) >= payload.len() as u64,
        "udp echo server at the original destination was never reached"
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {} byte datagram echoed through TPROXY, prerouting_hits={hits}",
        payload.len()
    );

    let _ = instance.stop().await;
}

/// TUN/TCP bulk integrity + clean close.
///
/// A small payload cannot catch the failure modes that actually matter on the
/// TUN datapath: buffered-but-unsent data lost on shutdown, and the peer's
/// half-close never being propagated. This test pushes 8 MiB of a
/// position-dependent pattern through the tunnel (so any reordering,
/// duplication or truncation is detected byte-for-byte) and then requires the
/// connection to close instead of lingering in FIN-WAIT-2 forever.
///
/// Regression coverage for three bugs in `flux-inbound::tun`:
/// * a queued `StackCmd::TcpData` could be overwritten in the actor's `select!`
///   (silent truncation of the proxied stream),
/// * `TcpClose` cleared not-yet-sent data (truncated the tail of a response),
/// * the peer's FIN was never forwarded to the dispatcher, so half-closing
///   clients hung and the smoltcp socket leaked in `CloseWait`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tun_inbound_bulk_transfer_integrity() {
    const NAME: &str = "test_tun_inbound_bulk_transfer_integrity";
    if !must_run_here(NAME) {
        return;
    }

    const TUN: &str = "fluxtun2";
    const TUN_LOCAL: &str = "10.97.0.1";
    const CLIENT: &str = "10.97.0.2";
    const TARGET: &str = "10.97.66.2";
    const PORT: u16 = 19_002;
    const TOTAL: usize = 8 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;

    let mut cleanup = Cleanup::new();
    setup_loopback_and_sysctls();

    sh_ok(&format!("ip addr add {CLIENT}/32 dev lo"));
    cleanup.on(format!("ip addr del {CLIENT}/32 dev lo"));

    let echo = start_tcp_echo(SocketAddr::from(([127, 0, 0, 1], PORT))).await;

    let instance = Instance::new(tunnel_config(TUN)).expect("tun config");
    instance.start().await.expect("TUN inbound failed to start");
    wait_for_iface(TUN);

    sh_ok(&format!("ip link set {TUN} up"));
    sh_ok(&format!("ip addr add {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip route del {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip addr del {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));

    /// Position-dependent payload: byte `n` of the stream is `n as u8 ^ 0x5a`.
    fn expected(n: usize) -> u8 {
        (n as u8) ^ 0x5a
    }

    let sock = TcpSocket::new_v4().expect("socket");
    sock.bind(format!("{CLIENT}:0").parse().unwrap())
        .expect("bind client source");
    sock.set_nodelay(true).expect("nodelay");
    let stream = timeout(
        Duration::from_secs(20),
        sock.connect(format!("{TARGET}:{PORT}").parse().unwrap()),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    let (mut reader, mut writer) = tokio::io::split(stream);

    let write_task = tokio::spawn(async move {
        let mut sent = 0usize;
        let mut chunk = vec![0u8; CHUNK];
        while sent < TOTAL {
            let n = CHUNK.min(TOTAL - sent);
            for (i, b) in chunk[..n].iter_mut().enumerate() {
                *b = (sent + i) as u8 ^ 0x5a;
            }
            writer.write_all(&chunk[..n]).await.expect("write");
            sent += n;
        }
        writer.shutdown().await.expect("shutdown write half");
    });

    // Read back and verify every byte position.
    let mut seen = 0usize;
    let mut buf = vec![0u8; CHUNK];
    let read_loop = async {
        while seen < TOTAL {
            let n = reader.read(&mut buf).await.expect("read");
            assert_ne!(n, 0, "connection closed after {seen}/{TOTAL} bytes");
            for (i, b) in buf[..n].iter().enumerate() {
                assert_eq!(
                    *b,
                    expected(seen + i),
                    "stream corrupted at byte {} (the TUN datapath lost, reordered or \
                     duplicated data)",
                    seen + i
                );
            }
            seen += n;
        }
    };
    timeout(Duration::from_secs(60), read_loop)
        .await
        .expect("bulk transfer through the TUN stalled");
    assert_eq!(seen, TOTAL, "short transfer");
    write_task.await.expect("writer task");

    // Half-close must be propagated: the peer's FIN has to follow promptly.
    let eof = timeout(Duration::from_secs(10), reader.read(&mut buf))
        .await
        .expect(
            "no FIN after the payload: the tunnel kept the connection open (half-close not \
             propagated, smoltcp socket leaked in CloseWait)",
        )
        .expect("read while waiting for FIN");
    assert_eq!(eof, 0, "unexpected trailing bytes after the payload");

    let stats = sh_ok(&format!("ip -s link show {TUN}"));
    let (rx, tx) = parse_iface_packets(&stats);
    assert!(
        rx > 0 && tx > 0,
        "TUN device saw no traffic (rx={rx} tx={tx}):\n{stats}"
    );
    assert!(
        echo.bytes.load(Ordering::Relaxed) >= TOTAL as u64,
        "echo server only saw {} of {TOTAL} bytes",
        echo.bytes.load(Ordering::Relaxed)
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {TOTAL} bytes verified byte-for-byte, clean FIN received, \
         tun rx={rx} tx={tx}"
    );

    let _ = instance.stop().await;
}

/// TUN/TCP with a **jumbo MTU**: the same byte-for-byte integrity proof as
/// [`test_tun_inbound_bulk_transfer_integrity`], plus two assertions that make
/// the MTU path non-vacuous:
///
/// * the configured `mtu` is actually programmed into the TUN *device* (a TUN
///   carries exactly one IP packet per `read()`/`write()`, so the device MTU —
///   not the stack's segment cap — decides how many syscalls a megabyte costs;
///   before this was fixed the `mtu` option only sized a buffer and the device
///   stayed at the kernel default of 1500),
/// * the frames on the device are genuinely large: 8 MiB through a 64 KiB MTU
///   must need far fewer packets than the same transfer at 1500.
///
/// The transfer itself is verified byte-for-byte (position-dependent pattern)
/// and must end with a clean FIN, because jumbo segments exercise the
/// assembler, sequence arithmetic and the receive-window code at sizes a
/// 1500-byte MTU never reaches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tun_inbound_jumbo_mtu_integrity() {
    const NAME: &str = "test_tun_inbound_jumbo_mtu_integrity";
    if !must_run_here(NAME) {
        return;
    }

    const TUN: &str = "fluxtun3";
    const TUN_LOCAL: &str = "10.96.0.1";
    const CLIENT: &str = "10.96.0.2";
    const TARGET: &str = "10.96.66.2";
    const PORT: u16 = 19_003;
    const MTU: usize = 65_535;
    const TOTAL: usize = 8 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;

    let mut cleanup = Cleanup::new();
    setup_loopback_and_sysctls();

    sh_ok(&format!("ip addr add {CLIENT}/32 dev lo"));
    cleanup.on(format!("ip addr del {CLIENT}/32 dev lo"));

    let echo = start_tcp_echo(SocketAddr::from(([127, 0, 0, 1], PORT))).await;

    let instance = Instance::new(config_with_inbound(&format!(
        r#"{{ "type": "tun", "tag": "tun-in", "interface_name": "{TUN}", "mtu": {MTU} }}"#
    )))
    .expect("tun config");
    instance.start().await.expect("TUN inbound failed to start");
    wait_for_iface(TUN);

    // The device MTU must be what the config asked for: applying it is what
    // makes the kernel hand the userspace stack large packets in the first
    // place, and what lets the stack emit large segments back.
    // `/sys/class/net` is not per-netns, so ask `ip` (which is) instead.
    let link = sh_ok(&format!("ip -o link show {TUN}"));
    let dev_mtu = link
        .split_whitespace()
        .position(|w| w == "mtu")
        .and_then(|i| link.split_whitespace().nth(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    assert_eq!(
        dev_mtu, MTU,
        "the `mtu` option was not applied to the TUN device (device MTU {dev_mtu},          configured {MTU}) — every packet then costs a syscall per 1448 bytes"
    );

    sh_ok(&format!("ip link set {TUN} up"));
    sh_ok(&format!("ip addr add {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!("ip route add {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip route del {TARGET}/32 dev {TUN}"));
    cleanup.on(format!("ip addr del {TUN_LOCAL}/24 dev {TUN}"));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -s {CLIENT} -d {TARGET} --dport {PORT} -j RETURN"
    ));
    sh_ok(&format!(
        "iptables -t nat -A OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));
    cleanup.on(format!(
        "iptables -t nat -D OUTPUT -p tcp -d {TARGET} --dport {PORT} -j DNAT --to-destination 127.0.0.1:{PORT}"
    ));

    /// Byte `n` of the stream is `n as u8 ^ 0xa7`.
    fn expected(n: usize) -> u8 {
        (n as u8) ^ 0xa7
    }

    let sock = TcpSocket::new_v4().expect("socket");
    sock.bind(format!("{CLIENT}:0").parse().unwrap())
        .expect("bind client source");
    sock.set_nodelay(true).expect("nodelay");
    let stream = timeout(
        Duration::from_secs(20),
        sock.connect(format!("{TARGET}:{PORT}").parse().unwrap()),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    let (mut reader, mut writer) = tokio::io::split(stream);

    let write_task = tokio::spawn(async move {
        let mut sent = 0usize;
        let mut chunk = vec![0u8; CHUNK];
        while sent < TOTAL {
            let n = CHUNK.min(TOTAL - sent);
            for (i, b) in chunk[..n].iter_mut().enumerate() {
                *b = (sent + i) as u8 ^ 0xa7;
            }
            writer.write_all(&chunk[..n]).await.expect("write");
            sent += n;
        }
        writer.shutdown().await.expect("shutdown write half");
    });

    let mut seen = 0usize;
    let mut buf = vec![0u8; CHUNK];
    let read_loop = async {
        while seen < TOTAL {
            let n = reader.read(&mut buf).await.expect("read");
            assert_ne!(n, 0, "connection closed after {seen}/{TOTAL} bytes");
            for (i, b) in buf[..n].iter().enumerate() {
                assert_eq!(
                    *b,
                    expected(seen + i),
                    "stream corrupted at byte {} through the jumbo-MTU TUN datapath",
                    seen + i
                );
            }
            seen += n;
        }
    };
    timeout(Duration::from_secs(60), read_loop)
        .await
        .expect("jumbo-MTU bulk transfer through the TUN stalled");
    assert_eq!(seen, TOTAL, "short transfer");
    write_task.await.expect("writer task");

    let eof = timeout(Duration::from_secs(10), reader.read(&mut buf))
        .await
        .expect("no FIN after the jumbo-MTU payload: half-close not propagated")
        .expect("read while waiting for FIN");
    assert_eq!(eof, 0, "unexpected trailing bytes after the payload");

    let stats = sh_ok(&format!("ip -s link show {TUN}"));
    let (rx, tx) = parse_iface_packets(&stats);
    assert!(
        rx > 0 && tx > 0,
        "TUN device saw no traffic (rx={rx} tx={tx}):\n{stats}"
    );
    // 8 MiB at a 64 KiB MTU is at most ~140 frames per direction; at the old
    // 1500-byte MTU it was ~5800. Requiring an average frame well above the
    // 1500-byte ceiling proves the jumbo path was really exercised instead of
    // silently falling back to small packets.
    let avg_frame = TOTAL as u64 / rx.max(1);
    assert!(
        avg_frame > 4096,
        "average received frame is only {avg_frame} bytes (rx={rx} for {TOTAL} bytes): the \
         transfer did not actually use jumbo frames"
    );
    assert!(
        echo.bytes.load(Ordering::Relaxed) >= TOTAL as u64,
        "echo server only saw {} of {TOTAL} bytes",
        echo.bytes.load(Ordering::Relaxed)
    );

    eprintln!(
        "{E2E_MARKER} {NAME}: {TOTAL} bytes verified byte-for-byte at MTU {MTU} \
         (avg frame {avg_frame} B), clean FIN received, tun rx={rx} tx={tx}"
    );

    let _ = instance.stop().await;
}
