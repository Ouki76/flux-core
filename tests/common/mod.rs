use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// First port of the test range.
///
/// The whole test range deliberately stays **below** the kernel's ephemeral
/// range (`/proc/sys/net/ipv4/ip_local_port_range`, typically 32768-60999):
/// any listener the OS assigns for us via `bind(":0")` (echo servers, internal
/// detour inbounds, …) therefore can never steal a port that a test reserved
/// for an external process such as sing-box. Staying below the ephemeral range
/// is what makes the interop suite immune to ephemeral binds; it says nothing
/// about *other test processes*, which is what [`PORT_BLOCKS`] is for.
pub const TEST_PORT_BASE: u16 = 12_000;
pub const TEST_PORT_MAX: u16 = 32_000;

/// The test range is split into this many contiguous blocks, and each test
/// *process* reserves exactly one of them for its lifetime, so two suites
/// running on the same host never allocate from the same ports. 40 blocks of 500
/// ports: a single binary allocates well under a hundred, and the block is
/// shared with nobody.
pub const PORT_BLOCKS: u16 = 40;
pub const PORT_BLOCK_SIZE: u16 = (TEST_PORT_MAX - TEST_PORT_BASE) / PORT_BLOCKS;

/// True when nothing is listening on `port` and both TCP and UDP bind succeed.
///
/// A bare `bind()` probe is not enough: a *foreign* listener can hold the port
/// with `SO_REUSEPORT` (which every flux listener sets), letting our probe bind
/// succeed and handing the port out twice. The probe therefore also *connects* —
/// a free port refuses the connection, an occupied one accepts it.
#[allow(dead_code)]
pub async fn port_is_free(port: u16) -> bool {
    let addr = format!("127.0.0.1:{}", port);
    if tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
    {
        return false;
    }
    if let Ok(listener) = TcpListener::bind(&addr).await
        && let Ok(udp) = std::net::UdpSocket::bind(&addr)
    {
        drop(udp);
        drop(listener);
        return true;
    }
    false
}

/// Returns a unique, non-colliding TCP port below the ephemeral port range.
///
/// Two properties matter, and the previous version only had the first:
///
/// 1. *Within* a process, no port is handed out twice (atomic cursor, see
///    [`next_candidate_port_from`]) and the candidate must actually be free
///    ([`port_is_free`]: a bare `bind()` probe is not enough, because a foreign
///    listener holding the port with `SO_REUSEPORT` — which every flux listener
///    sets — lets our probe bind succeed anyway. The probe therefore also
///    *connects*: a free port refuses, an occupied one accepts).
///
/// 2. *Across* processes it used to be broken. Every test binary is its own
///    process and every process started this counter at [`TEST_PORT_BASE`], so
///    two suites on one host — a second checkout, a parallel `cargo test`, a
///    leftover binary — walked the *same* port sequence. Both could probe the
///    same candidate while it was still free and both then bind it; the loser
///    got `AddrInUse` from a bind it could not possibly have avoided. The probe
///    cannot close that window, because between the probe and the real bind come
///    config parsing and `Instance::new`.
///
/// So each process now claims a contiguous **block** of the range and hands out
/// ports from *its* block only (see [`reserve_port_block`]). The claim is an
/// abstract Unix socket, so its scope — the network namespace — is exactly the
/// scope in which ports collide, and it covers a second suite even when that
/// suite runs in another mount/PID namespace (a lock file would not). Two suites
/// can then run at the same time without ever mentioning the same port. The
/// block is chosen pseudo-randomly, and the cursor starts at a random offset
/// inside it, so an *unmodified* neighbour (a checkout without this code, which
/// still starts at [`TEST_PORT_BASE`]) usually does not overlap either.
///
/// Every port handed out is recorded in a process-local ledger so that a bind
/// failure can be attributed: [`diagnose_bind_failure`] reports whether the
/// failing port came from this allocator, when, and to which test thread.
#[allow(dead_code)]
/// Keeps a `SO_REUSEPORT` listener on the port we just handed out.
///
/// The allocator probes a port by binding and releasing it, which leaves a window in
/// which a sibling test thread — or its own probe — can hand the same port to someone
/// else. Retrying at the call site cannot fix that: the port is already taken.
/// Holding the socket closes the window at the root, and it does not block the
/// intended bind because every flux listener sets `SO_REUSEPORT`; the reservation is
/// simply dropped when it is bound over.
fn hold_port(port: u16) {
    use std::os::fd::AsRawFd;
    let sock = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(_) => (),
        Err(_) => return,
    };
    let _ = sock;
    // Bind the real port with SO_REUSEPORT through the same helper the allocator
    // uses for probing.
    if let Some(listener) = bind_reuseport(port) {
        HOLDERS.lock().unwrap_or_else(|e| e.into_inner()).push(listener);
    }
}

/// `SO_REUSEPORT` listener on `port`, or `None` when it cannot be bound.
fn bind_reuseport(port: u16) -> Option<std::net::TcpListener> {
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return None;
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            libc::close(fd);
            return None;
        }
        let listener = std::net::TcpListener::from_raw_fd(fd);
        let _ = listener.as_raw_fd();
        Some(listener)
    }
}

static HOLDERS: std::sync::Mutex<Vec<std::net::TcpListener>> = std::sync::Mutex::new(Vec::new());

pub async fn get_free_tcp_port() -> u16 {
    warn_once_if_ephemeral_range_overlaps();
    let base = port_block_base();
    // A block has `PORT_BLOCK_SIZE` ports; a candidate that is busy is skipped,
    // so a block can only be exhausted if something outside this process holds
    // most of it. Bounding the search turns that into a diagnosed failure
    // instead of a hung full-suite run.
    let max_attempts = usize::from(PORT_BLOCK_SIZE) * 3;
    let mut last = base;
    for _ in 0..max_attempts {
        let port = next_candidate_port();
        last = port;
        if port_is_free(port).await {
            record_allocation(port);
            hold_port(port);
            return port;
        }
        if trace_enabled() {
            eprintln!(
                "[port-trace] pid={} rejected 127.0.0.1:{}: probe says busy ({}); \
                 retrying with the next candidate",
                std::process::id(),
                port,
                probe_port_sync(port),
            );
        }
    }
    panic!(
        "port allocator: {max_attempts} candidates in this process's block \
         {}..{} (pid {}) all look busy — something outside the test suite is holding them.\n\
         Last candidate 127.0.0.1:{last}: {}",
        base,
        base + PORT_BLOCK_SIZE - 1,
        std::process::id(),
        probe_port_sync(last),
    );
}

/// Advancing the cursor must be a single atomic step.
///
/// `fetch_add` + a separate `store()` on wrap is **not** safe: two threads that
/// both observe the last in-range value can both store the base, and the second
/// store lands *after* the first thread already took the base, so the base is
/// handed out twice. The compare-exchange loop below makes the advance a single
/// atomic step, so the wrap cannot repeat a port.
#[allow(dead_code)]
fn next_candidate_port() -> u16 {
    next_candidate_port_from(&NEXT_TCP_PORT, port_block_base())
}

/// Next candidate in `base..base + PORT_BLOCK_SIZE`, wrapping inside the block.
///
/// The cursor starts at 0 ("not placed yet") and is only ever advanced by one,
/// atomically, so no value is returned twice until the block wraps. After a wrap
/// the probe still validates every candidate; no test binary comes close to
/// allocating `PORT_BLOCK_SIZE` ports.
#[allow(dead_code)]
pub fn next_candidate_port_from(counter: &AtomicU16, base: u16) -> u16 {
    let end = base + PORT_BLOCK_SIZE;
    loop {
        let current = counter.load(Ordering::Relaxed);
        let port = if (base..end).contains(&current) {
            current
        } else {
            base
        };
        let next = if port + 1 >= end { base } else { port + 1 };
        if counter
            .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return port;
        }
    }
}

// ---------------------------------------------------------------------------
// Per-process port block reservation
// ---------------------------------------------------------------------------

/// Base of the block this process reserved (chosen exactly once).
static PORT_BLOCK_BASE: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
/// Absolute cursor inside the block (0 = not placed yet).
static NEXT_TCP_PORT: AtomicU16 = AtomicU16::new(0);
/// The abstract Unix socket that claims the block, kept open for the whole
/// process lifetime. The kernel releases it when the process dies — including on
/// `SIGKILL` — so it can never leak, and there is no file to clean up.
static PORT_BLOCK_CLAIM: Mutex<Option<std::os::fd::OwnedFd>> = Mutex::new(None);

fn port_block_base() -> u16 {
    *PORT_BLOCK_BASE.get_or_init(reserve_port_block)
}

pub fn block_start(index: u16) -> u16 {
    TEST_PORT_BASE + index * PORT_BLOCK_SIZE
}

/// A pseudo-random value below `bound`.
///
/// `RandomState` is seeded from OS entropy, and a fresh instance plus the clock
/// gives a value that differs between processes and between calls. Used only to
/// spread choices out — never for correctness.
fn random_below(bound: u16) -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    (hasher.finish() % u64::from(bound.max(1))) as u16
}

/// A starting block index that differs between processes, so two suites started
/// at the same moment do not even scan in the same order.
fn block_hint() -> u16 {
    random_below(PORT_BLOCKS)
}

#[cfg(all(unix, not(target_os = "solaris")))]
pub fn current_uid() -> u32 {
    // SAFETY: getuid() takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(not(all(unix, not(target_os = "solaris"))))]
pub fn current_uid() -> u32 {
    0
}

/// Claims block `index` for this process, or reports that someone else has it.
///
/// The claim is an **abstract** Unix socket (`sun_path[0] == 0`), which is
/// scoped to the **network namespace** — exactly the scope in which TCP/UDP
/// ports collide. That matters here: a second test suite running on the same
/// host may be inside a different mount and PID namespace (so a lock *file*
/// would not be shared, and its processes are not even visible in `/proc`), yet
/// it still binds ports in this namespace. A file lock cannot see it; an
/// abstract socket can, because the kernel refuses a second bind of the same
/// abstract name in that namespace.
///
/// `Ok(Some(fd))` — the block is ours, keep the socket open.
/// `Ok(None)`      — another live process holds it.
/// `Err(e)`        — this platform cannot claim blocks at all.
#[cfg(all(unix, not(target_os = "solaris")))]
fn claim_block(index: u16) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    claim_abstract_socket(&format!("flux-core-test-ports-{}-{index}", current_uid()))
}

/// The abstract-namespace bind primitive, on an explicit name.
///
/// Split out so it can be tested deterministically on a private name instead of
/// racing other test processes for a real block.
#[cfg(all(unix, not(target_os = "solaris")))]
pub fn claim_abstract_socket(name: &str) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let bytes = name.as_bytes();
    // SAFETY: a fresh socket is created and immediately owned by `fd`, so every
    // error path closes it. `sockaddr_un` is zero-initialised, its length is
    // computed from the name, and the name length is checked against the field.
    unsafe {
        let raw = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(raw);

        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // sun_path[0] stays 0: that is what makes the name abstract.
        let capacity = addr.sun_path.len().saturating_sub(1);
        if bytes.len() > capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "abstract socket name is too long",
            ));
        }
        for (slot, byte) in addr.sun_path.iter_mut().skip(1).zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len();
        let rc = libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            len as libc::socklen_t,
        );
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(code) if code == libc::EADDRINUSE => Ok(None),
                _ => Err(err),
            };
        }
        Ok(Some(fd))
    }
}

#[cfg(not(all(unix, not(target_os = "solaris"))))]
fn claim_block(_index: u16) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "abstract Unix sockets are not available on this platform",
    ))
}

/// Reserves one block for this process for its whole lifetime.
///
/// Exclusion is kernel-managed and dies with the process, so a crashed or killed
/// suite cannot leave a block reserved. If no claim can be made at all, a block
/// is still chosen and the fallback is announced: a test run should degrade with
/// a loud note, not abort.
fn reserve_port_block() -> u16 {
    let hint = block_hint();
    let mut claim_error = None;
    let mut busy_blocks: Vec<u16> = Vec::new();
    for step in 0..PORT_BLOCKS {
        let index = (hint + step) % PORT_BLOCKS;
        match claim_block(index) {
            Ok(Some(claim)) => {
                // The claim excludes cooperating processes; this check covers the
                // ones that ignore it. A block already carrying listeners belongs
                // to someone else's allocator, which is walking through the very
                // ports we would take — so let go of the claim and look elsewhere.
                if !block_is_quiet(index) {
                    busy_blocks.push(index);
                    drop(claim);
                    continue;
                }
                *PORT_BLOCK_CLAIM
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(claim);
                seed_cursor(index);
                if trace_enabled() {
                    eprintln!(
                        "[port-trace] pid={} reserved test port block {index} ({}..{}){}",
                        std::process::id(),
                        block_start(index),
                        block_start(index) + PORT_BLOCK_SIZE - 1,
                        if busy_blocks.is_empty() {
                            String::new()
                        } else {
                            format!(", skipped already-used blocks {busy_blocks:?}")
                        }
                    );
                }
                return block_start(index);
            }
            Ok(None) => {}
            Err(e) => {
                // A platform-level failure: scanning more blocks cannot help.
                claim_error = Some(e.to_string());
                break;
            }
        }
    }
    let index = hint;
    eprintln!(
        "[port-forensics] pid={} could not claim an exclusive test port block ({}); \
         falling back to block {index} ({}..{}), which another test process in this \
         network namespace may also use. A bind failure from here on is not this \
         suite's bug — see the diagnosis printed with it.",
        std::process::id(),
        claim_error.unwrap_or_else(|| format!(
            "all {PORT_BLOCKS} blocks are claimed by other live test processes"
        )),
        block_start(index),
        block_start(index) + PORT_BLOCK_SIZE - 1,
    );
    seed_cursor(index);
    block_start(index)
}

/// Starts this process's cursor at a random offset inside the block.
///
/// Belt and braces for the fallback path above: even if two processes somehow
/// end up in the same block, they start allocating from different offsets
/// instead of colliding on the first port.
fn seed_cursor(index: u16) {
    NEXT_TCP_PORT.store(
        block_start(index) + random_below(PORT_BLOCK_SIZE),
        Ordering::Relaxed,
    );
}

fn trace_enabled() -> bool {
    std::env::var_os("FLUX_PORT_TRACE").is_some()
}

/// One port handed out by [`get_free_tcp_port`] in this process.
#[derive(Clone)]
struct Allocation {
    port: u16,
    seq: u64,
    thread: String,
    at: std::time::Instant,
}

static ALLOCATION_SEQ: AtomicU64 = AtomicU64::new(1);
static ALLOCATIONS: Mutex<Vec<Allocation>> = Mutex::new(Vec::new());
/// How many allocations the ledger remembers. A full suite allocates a few
/// hundred ports per binary; 128 is enough to cover the window around a failure
/// without growing without bound.
const LEDGER_LIMIT: usize = 128;

fn ledger_guard() -> std::sync::MutexGuard<'static, Vec<Allocation>> {
    // A panicking test can poison this lock; the ledger is plain diagnostic
    // data, so recovering the inner vector is always correct here.
    ALLOCATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn record_allocation(port: u16) {
    let seq = ALLOCATION_SEQ.fetch_add(1, Ordering::Relaxed);
    let thread = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_string();
    {
        let mut ledger = ledger_guard();
        ledger.push(Allocation {
            port,
            seq,
            thread: thread.clone(),
            at: std::time::Instant::now(),
        });
        if ledger.len() > LEDGER_LIMIT {
            ledger.remove(0);
        }
    }
    if trace_enabled() {
        eprintln!(
            "[port-trace] pid={} thread='{}' handed out 127.0.0.1:{} (allocation #{})",
            std::process::id(),
            thread,
            port,
            seq,
        );
    }
}

/// Starts an asynchronous TCP echo server on an ephemeral OS-assigned port and returns its SocketAddr.
#[allow(dead_code)]
pub async fn start_tcp_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(socket);
                let mut buf = vec![0u8; 32768];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    addr
}

#[allow(dead_code)]
pub async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..len], peer).await;
            }
        }
    });

    addr
}

#[allow(dead_code)]
pub fn get_rss_kb() -> usize {
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(v) = parts[1].parse::<usize>()
                {
                    return v;
                }
            }
        }
    }
    0
}

#[allow(dead_code)]
pub fn get_rss_mb() -> f64 {
    get_rss_kb() as f64 / 1024.0
}

/// Starts a real TLS 1.3 echo server (usable as a REALITY handshake target/decoy).
#[allow(dead_code)] // used by interop tests only
pub async fn start_tls_echo_server() -> SocketAddr {
    let dir = TempDir::new().expect("tempdir");
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "example.com".to_string(),
    ])
    .expect("cert generation");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let (certs, key) = flux_transport::tls::TlsTransport::load_certs_and_key(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
    )
    .unwrap();
    let acceptor =
        flux_transport::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    std::mem::forget(dir); // keep cert files alive for the test duration
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if tls.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Retries a flaky-prone interop test body up to `attempts` times.
/// Interop tests spawn external processes (sing-box) and are timing-sensitive
/// under heavy CI load; transient failures are retried with a short backoff,
/// persistent failures still fail the test with the original panic.
#[allow(dead_code)]
pub async fn retry_on_flake<F, Fut>(label: &str, attempts: usize, f: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use futures_util::FutureExt;
    for attempt in 1..=attempts {
        let result = std::panic::AssertUnwindSafe(f()).catch_unwind().await;
        match result {
            Ok(()) => return,
            Err(payload) if attempt < attempts => {
                eprintln!(
                    "[{}] attempt {}/{} failed under load, retrying...",
                    label, attempt, attempts
                );
                drop(payload);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}

// ---------------------------------------------------------------------------
// Port forensics
//
// The suite reserves ports in `TEST_PORT_BASE..TEST_PORT_MAX` and hands them to
// flux and to sing-box. When a bind fails with `AddrInUse` the OS gives no clue
// beyond the errno, which is why this class of failure used to be unattributable.
// Everything below exists to answer, at the moment of the failure:
//
//   * which configured listener failed to bind,
//   * whether this process's allocator handed that port out (and to whom),
//   * what the kernel says is holding the port (socket state, uid, inode, pid),
//   * what *else* is sitting in the test range,
//   * whether the test range overlaps the kernel's ephemeral range.
//
// Every helper degrades gracefully: a missing `ss`, an unreadable `/proc`
// entry or a permission-denied netlink socket becomes a note in the report, and
// nothing in this section can panic while a test is already panicking.
// ---------------------------------------------------------------------------

/// The kernel's ephemeral (auto-assigned) port range, from
/// `/proc/sys/net/ipv4/ip_local_port_range`.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct EphemeralRange {
    pub first: u16,
    pub last: u16,
}

#[allow(dead_code)]
pub fn ephemeral_port_range() -> Option<EphemeralRange> {
    let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let mut fields = text.split_whitespace();
    let first = fields.next()?.parse::<u16>().ok()?;
    let last = fields.next()?.parse::<u16>().ok()?;
    (first <= last).then_some(EphemeralRange { first, last })
}

pub fn ephemeral_range_does_not_overlap_test_range() -> bool {
    match ephemeral_port_range() {
        Some(range) => !(TEST_PORT_BASE <= range.last && range.first < TEST_PORT_MAX),
        // Unreadable sysctl: assume the documented default, which does not
        // overlap. The diagnosis repeats the raw value either way.
        None => true,
    }
}

fn ephemeral_overlap_note() -> String {
    match ephemeral_port_range() {
        Some(range) => {
            let overlaps = !ephemeral_range_does_not_overlap_test_range();
            format!(
                "ip_local_port_range={}..{} vs test range {}..{}: {}",
                range.first,
                range.last,
                TEST_PORT_BASE,
                TEST_PORT_MAX - 1,
                if overlaps {
                    "OVERLAP — the OS may assign a test port to a bind(\":0\") listener or to an \
                     outgoing connection's source port"
                } else {
                    "no overlap"
                }
            )
        }
        None => "ip_local_port_range unavailable (cannot rule out an overlap)".to_string(),
    }
}

static EPHEMERAL_RANGE_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Prints one loud line when the kernel's ephemeral range covers the test range.
///
/// That overlap is the one environmental condition that makes the range-based
/// allocator unsound: any `bind(":0")` in the process, or any outgoing
/// connection's source port, can then land on a port a test just reserved, and
/// the next bind fails with `AddrInUse` with nothing to point at.
fn warn_once_if_ephemeral_range_overlaps() {
    if ephemeral_range_does_not_overlap_test_range() {
        return;
    }
    if EPHEMERAL_RANGE_WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    eprintln!(
        "[port-forensics] WARNING: {} Budget a wider separation before trusting \
         port-based tests here.",
        ephemeral_overlap_note()
    );
}

/// Classifies a port right now, synchronously (safe to call from a panic path).
///
/// Same three probes as [`port_is_free`], but it explains itself: the result is
/// either `FREE: …` or `OCCUPIED: …` followed by what each probe saw.
#[allow(dead_code)]
pub fn probe_port_sync(port: u16) -> String {
    let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(addr) => addr,
        Err(e) => return format!("UNKNOWN: cannot parse address: {e}"),
    };
    let mut free = true;
    let mut parts: Vec<String> = Vec::new();

    match std::net::TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            parts.push("tcp bind ok".to_string());
        }
        Err(e) => {
            free = false;
            parts.push(format!("tcp bind FAILED: {e}"));
        }
    }
    match std::net::UdpSocket::bind(addr) {
        Ok(socket) => {
            drop(socket);
            parts.push("udp bind ok".to_string());
        }
        Err(e) => {
            free = false;
            parts.push(format!("udp bind FAILED: {e}"));
        }
    }
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100)) {
        Ok(stream) => {
            drop(stream);
            free = false;
            parts.push("tcp connect ACCEPTED (a listener answers)".to_string());
        }
        Err(e) => parts.push(format!("tcp connect refused ({:?})", e.kind())),
    }

    format!(
        "{}: {}",
        if free { "FREE" } else { "OCCUPIED" },
        parts.join("; ")
    )
}

pub fn decode_hex_ip(text: &str) -> String {
    // IPv4: four bytes, little-endian, as one 8-character hex word.
    if text.len() == 8 {
        let mut bytes = [0u8; 4];
        let mut ok = true;
        for (i, byte) in bytes.iter_mut().enumerate() {
            match u8::from_str_radix(&text[i * 2..i * 2 + 2], 16) {
                Ok(value) => *byte = value,
                Err(_) => ok = false,
            }
        }
        if ok {
            return format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
        }
    }
    // IPv6: four little-endian 32-bit words.
    if text.len() == 32 {
        let mut groups: Vec<String> = Vec::with_capacity(8);
        for word in 0..4 {
            let word = &text[word * 8..word * 8 + 8];
            let mut bytes = [0u8; 4];
            let mut ok = true;
            for (i, byte) in bytes.iter_mut().enumerate() {
                match u8::from_str_radix(&word[i * 2..i * 2 + 2], 16) {
                    Ok(value) => *byte = value,
                    Err(_) => ok = false,
                }
            }
            if !ok {
                return text.to_string();
            }
            groups.push(format!(
                "{:02x}{:02x}:{:02x}{:02x}",
                bytes[3], bytes[2], bytes[1], bytes[0]
            ));
        }
        return groups.join(":");
    }
    text.to_string()
}

fn split_endpoint(text: &str) -> Option<(&str, u16)> {
    let (ip, port) = text.split_once(':')?;
    Some((ip, u16::from_str_radix(port, 16).ok()?))
}

fn state_name(proto: &str, code: &str) -> &'static str {
    if proto.starts_with("udp") {
        return match code {
            "01" => "ESTABLISHED",
            "07" | "0A" => "UNCONN",
            _ => "?",
        };
    }
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "?",
    }
}

/// One socket from `/proc/net/{tcp,udp}{,6}`.
#[derive(Clone)]
pub struct SocketRow {
    pub proto: &'static str,
    pub local_ip: String,
    pub local_port: u16,
    pub remote: String,
    pub state: &'static str,
    pub uid: u32,
    pub inode: u64,
}

pub fn parse_net_table(proto: &'static str, text: &str) -> Vec<SocketRow> {
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local remote st tx:rx tr:when retrnsmt uid timeout inode …
        if fields.len() < 10 {
            continue;
        }
        let Some((local_ip, local_port)) = split_endpoint(fields[1]) else {
            continue;
        };
        let (Ok(uid), Ok(inode)) = (fields[7].parse::<u32>(), fields[9].parse::<u64>()) else {
            continue;
        };
        rows.push(SocketRow {
            proto,
            local_ip: decode_hex_ip(local_ip),
            local_port,
            remote: fields[2].to_string(),
            state: state_name(proto, fields[3]),
            uid,
            inode,
        });
    }
    rows
}

/// Every socket in `/proc/net/*` whose local port is `port`, plus any notes
/// about tables that could not be read.
fn sockets_on_port(port: u16) -> (Vec<SocketRow>, Vec<String>) {
    let mut rows = Vec::new();
    let mut notes = Vec::new();
    for (proto, path) in [
        ("tcp", "/proc/net/tcp"),
        ("tcp6", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"),
        ("udp6", "/proc/net/udp6"),
    ] {
        match std::fs::read_to_string(path) {
            Ok(text) => rows.extend(
                parse_net_table(proto, &text)
                    .into_iter()
                    .filter(|row| row.local_port == port),
            ),
            Err(e) => notes.push(format!("{path}: unreadable ({e})")),
        }
    }
    (rows, notes)
}

/// Every socket in the whole test range, for spotting squatters and strays.
fn sockets_in_test_range() -> (Vec<SocketRow>, Vec<String>) {
    sockets_in_range(TEST_PORT_BASE, TEST_PORT_MAX - TEST_PORT_BASE)
}

/// Every socket whose local port is in `[base, base + size)`.
fn sockets_in_range(base: u16, size: u16) -> (Vec<SocketRow>, Vec<String>) {
    let end = base.saturating_add(size);
    let mut rows = Vec::new();
    let mut notes = Vec::new();
    for (proto, path) in [
        ("tcp", "/proc/net/tcp"),
        ("tcp6", "/proc/net/tcp6"),
        ("udp", "/proc/net/udp"),
        ("udp6", "/proc/net/udp6"),
    ] {
        match std::fs::read_to_string(path) {
            Ok(text) => rows.extend(
                parse_net_table(proto, &text)
                    .into_iter()
                    .filter(|row| (base..end).contains(&row.local_port)),
            ),
            Err(e) => notes.push(format!("{path}: unreadable ({e})")),
        }
    }
    (rows, notes)
}

/// True when nothing in the block is bound in a way that would refuse our bind.
///
/// Used *before* claiming a block: a block that already has listeners belongs to
/// someone who is not honouring the claim — an older binary, another checkout, a
/// foreign server — and its allocator is usually walking forward through exactly
/// the ports we are about to use. `TIME_WAIT`/`CLOSE` do not count: they do not
/// refuse a `SO_REUSEADDR` bind, and an exited test leaves plenty of them.
fn block_is_quiet(index: u16) -> bool {
    let (rows, notes) = sockets_in_range(block_start(index), PORT_BLOCK_SIZE);
    if !notes.is_empty() {
        // Cannot tell: treat a block we cannot inspect as usable, the per-port
        // probe still decides. Never turn an unreadable /proc into a failure.
        return true;
    }
    !rows
        .iter()
        .any(|row| !matches!(row.state, "TIME_WAIT" | "CLOSE"))
}

/// Pids holding a socket inode. An inode can be shared (forked children), so
/// this returns a list; unreadable processes are simply not listed.
fn socket_owner_pids(inode: u64) -> Result<Vec<u32>, String> {
    let needle = format!("socket:[{inode}]");
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("cannot list /proc: {e}"))?;
    let mut owners = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue; // other users' processes: permission denied is normal
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .ok()
                .and_then(|target| target.to_str().map(str::to_string))
                .as_deref()
                == Some(needle.as_str())
            {
                owners.push(pid);
                break;
            }
        }
    }
    Ok(owners)
}

fn describe_process(pid: u32) -> String {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string());
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split('\0')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let mut cmdline = cmdline;
    if cmdline.chars().count() > 180 {
        cmdline = cmdline.chars().take(180).collect::<String>() + "…";
    }
    if cmdline.is_empty() {
        format!("pid {pid} ({comm}, exe={exe})")
    } else {
        format!("pid {pid} ({comm}, exe={exe}) cmd: {cmdline}")
    }
}

/// `ss` output filtered to one port. `ss` is optional: a missing binary, a
/// permission-denied netlink socket or a hung process all become notes.
fn ss_rows(port: u16) -> Result<Vec<String>, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("ss")
        .args(["-tanup", &format!("sport = :{port}")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ss not runnable: {e}"))?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2_000);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("ss did not finish within 2s".to_string());
            }
            Err(e) => return Err(format!("ss wait failed: {e}")),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("ss output unavailable: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "ss exited {}: {}",
            output.status,
            stderr.lines().next().unwrap_or("<no stderr>")
        ));
    }
    let rows: Vec<String> = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            // Drop the table header of whichever address family ss printed.
            !line.is_empty() && !line.starts_with("State") && !line.starts_with("Netid")
        })
        .map(|line| line.trim().to_string())
        .collect();
    if rows.is_empty() {
        if stderr.trim().is_empty() {
            return Ok(vec!["<no socket reported by ss for this port>".to_string()]);
        }
        return Err(format!(
            "ss printed no rows; stderr: {}",
            stderr.lines().next().unwrap_or("<empty>")
        ));
    }
    Ok(rows)
}

/// A listener a flux config asks for, extracted from the config JSON.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ConfiguredBound {
    pub kind: &'static str,
    pub tag: String,
    pub protocol: String,
    pub port: u16,
}

/// Local ports a flux config will bind, in the order `Instance::start` binds
/// them (API first, then inbounds) — which is also the order in which a failure
/// is reachable.
#[allow(dead_code)]
pub fn configured_bounds(config_json: &str) -> Vec<ConfiguredBound> {
    let mut out = Vec::new();
    let Ok(json) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return out;
    };
    for (kind, path) in [
        ("api", &["api", "listen"][..]),
        ("dns", &["dns", "listen"][..]),
    ] {
        if let Some(port) = json
            .get(path[0])
            .and_then(|section| section.get(path[1]))
            .and_then(|listen| listen.as_str())
            .and_then(|listen| listen.rsplit_once(':'))
            .and_then(|(_, port)| port.parse::<u16>().ok())
        {
            out.push(ConfiguredBound {
                kind,
                tag: kind.to_string(),
                protocol: kind.to_string(),
                port,
            });
        }
    }
    if let Some(inbounds) = json.get("inbounds").and_then(|v| v.as_array()) {
        for inbound in inbounds {
            let tag = inbound
                .get("tag")
                .and_then(|t| t.as_str())
                .unwrap_or("<untagged>")
                .to_string();
            let protocol = inbound
                .get("protocol")
                .and_then(|p| p.get("type"))
                .and_then(|t| t.as_str())
                .or_else(|| inbound.get("type").and_then(|t| t.as_str()))
                .unwrap_or("?")
                .to_string();
            let port = inbound
                .get("listen_port")
                .and_then(|p| p.as_u64())
                .or_else(|| {
                    inbound
                        .get("carrier")
                        .and_then(|c| c.get("listen_port"))
                        .and_then(|p| p.as_u64())
                });
            if let Some(port) = port {
                out.push(ConfiguredBound {
                    kind: "inbound",
                    tag,
                    protocol,
                    port: port as u16,
                });
            }
        }
    }
    out
}

/// Writes the kernel's view of `port`: the `/proc/net/*` rows captured by
/// [`sockets_on_port`] *plus* a live `ss` query.
///
/// The caller passes rows it snapshotted **before** any probing, because a
/// squatter that is short-lived can disappear during the 100 ms probes and then
/// look like nothing ever held the port.
fn write_holders(out: &mut String, port: u16, rows: Vec<SocketRow>, notes: Vec<String>) {
    if rows.is_empty() {
        let _ = writeln!(
            out,
            "    /proc/net/*: no socket currently has local port {port}"
        );
    }
    for row in rows {
        let owner = match socket_owner_pids(row.inode) {
            Ok(pids) if pids.is_empty() => {
                "owner pid unknown (not this uid, or already gone)".to_string()
            }
            Ok(pids) => {
                let described: Vec<String> = pids.iter().map(|p| describe_process(*p)).collect();
                let this_process = pids.iter().any(|p| *p == std::process::id());
                format!(
                    "{}{}",
                    if this_process {
                        "THIS PROCESS — "
                    } else {
                        ""
                    },
                    described.join(" | ")
                )
            }
            Err(e) => format!("owner pid unavailable ({e})"),
        };
        let _ = writeln!(
            out,
            "    {} {} {} -> {} uid={} inode={} [{}]",
            row.proto, row.state, row.local_ip, row.remote, row.uid, row.inode, owner
        );
    }
    for note in notes {
        let _ = writeln!(out, "    {note}");
    }
    match ss_rows(port) {
        Ok(lines) => {
            for line in lines {
                let _ = writeln!(out, "    ss: {line}");
            }
        }
        Err(e) => {
            let _ = writeln!(out, "    ss: unavailable ({e})");
        }
    }
}

/// Describes what this process's allocator did with `port`.
fn write_allocation_history(out: &mut String, port: u16) {
    let ledger = ledger_guard();
    let hits: Vec<&Allocation> = ledger.iter().filter(|a| a.port == port).collect();
    if hits.is_empty() {
        let _ = writeln!(
            out,
            "    NOT handed out by this process's allocator ({} allocation(s) on record, none \
             for port {port}) — the port was chosen outside get_free_tcp_port: a fixed literal, \
             a bind(\":0\") the OS assigned, another test binary's allocator, or another test \
             that reused a config",
            ledger.len()
        );
        return;
    }
    let _ = writeln!(
        out,
        "    handed out {} time(s) by this process's allocator:",
        hits.len()
    );
    for hit in &hits {
        let _ = writeln!(
            out,
            "      #{} -> thread '{}' {:.3}s before this report",
            hit.seq,
            hit.thread,
            hit.at.elapsed().as_secs_f64()
        );
    }
    if hits.len() > 1 {
        let _ = writeln!(
            out,
            "    DUPLICATE ALLOCATION: the same port left the allocator twice — that is an \
             allocator defect, not a foreign squatter"
        );
    }
    let _ = writeln!(
        out,
        "    (the ledger is per process and only covers ports this allocator issued; a port \
         held by a *different* process — a second suite, a leftover child, a foreign server — \
         is not in it unless that process also allocated it)"
    );
    let _ = writeln!(
        out,
        "    recent allocations: {}",
        ledger
            .iter()
            .rev()
            .take(6)
            .map(|a| format!("{}@{}", a.port, a.thread))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Builds the report printed when `Instance::start` fails with a bind error.
///
/// Synchronous on purpose: it runs on the panicking thread and must not await
/// anything. It never panics, so the original failure is always the thing the
/// log shows first.
#[allow(dead_code)]
pub fn diagnose_bind_failure(config_json: &str, hint_port: u16, error: &str) -> String {
    let mut out = String::new();
    let bounds = configured_bounds(config_json);
    let _ = writeln!(out, "---- flux instance start failed: port diagnosis ----");
    let _ = writeln!(out, "error: {error}");
    let _ = writeln!(
        out,
        "process: pid={} thread='{}' exe={}",
        std::process::id(),
        std::thread::current().name().unwrap_or("<unnamed>"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_else(|| "?".to_string())
    );
    let _ = writeln!(out, "environment: {}", ephemeral_overlap_note());
    let block_base = PORT_BLOCK_BASE.get().copied();
    match block_base {
        Some(base) => {
            let _ = writeln!(
                out,
                "allocator block: {}..{} (claimed exclusively for this process; a holder \
                 *inside* this block is therefore a foreign listener that appeared after \
                 the probe, and a holder outside it means the allocator itself leaked a \
                 port)",
                base,
                base + PORT_BLOCK_SIZE - 1
            );
        }
        None => {
            let _ = writeln!(
                out,
                "allocator block: none claimed yet (no port was allocated through \
                 get_free_tcp_port before this failure)"
            );
        }
    }

    if bounds.is_empty() {
        let _ = writeln!(out, "configured listeners: none found in the config JSON");
    }
    let mut occupied: Vec<usize> = Vec::new();
    for (index, bound) in bounds.iter().enumerate() {
        // Snapshot first, probe second: a short-lived holder must be caught
        // before the probes (which take up to 100 ms each) give it time to die.
        let snapshot = sockets_on_port(bound.port);
        let probe = probe_port_sync(bound.port);
        if probe.starts_with("OCCUPIED") {
            occupied.push(index);
        }
        let _ = writeln!(
            out,
            "configured[{index}] kind={} tag='{}' protocol={} on 127.0.0.1:{} -> {probe}",
            bound.kind, bound.tag, bound.protocol, bound.port
        );
        write_holders(&mut out, bound.port, snapshot.0, snapshot.1);
        let _ = writeln!(out, "  allocator history for port {}:", bound.port);
        write_allocation_history(&mut out, bound.port);
    }

    let _ = writeln!(
        out,
        "allocator history for the caller-supplied port {hint_port}:"
    );
    write_allocation_history(&mut out, hint_port);

    match occupied.as_slice() {
        [only] => {
            let bound = &bounds[*only];
            let _ = writeln!(
                out,
                "=> the inbound that failed is configured[{only}] tag='{}' ({} on 127.0.0.1:{}) — \
                 its port is still held by the socket(s) listed above",
                bound.tag, bound.protocol, bound.port
            );
        }
        [] if bounds.len() == 1 => {
            let bound = &bounds[0];
            let _ = writeln!(
                out,
                "=> tag='{}' ({} on 127.0.0.1:{}) was the only listener the config asks for, but \
                 nothing holds that port now: the conflict disappeared between the failed bind \
                 and this report (short-lived holder), or the bind failed for another reason — \
                 compare the `ss`/`/proc/net` rows above with the allocator history",
                bound.tag, bound.protocol, bound.port
            );
        }
        [] => {
            let _ = writeln!(
                out,
                "=> cannot attribute from the kernel: none of the {} configured listener(s) is \
                 occupied now. The holder either vanished or was never visible to this process \
                 (different user, or a bind race inside this process)",
                bounds.len()
            );
        }
        many => {
            let _ = writeln!(
                out,
                "=> {many:?} configured listeners are occupied now; the failed bind is the first \
                 of them in start order"
            );
        }
    }

    let (range_rows, range_notes) = sockets_in_test_range();
    let _ = writeln!(
        out,
        "sockets anywhere in the test range {}..{} ({}):",
        TEST_PORT_BASE,
        TEST_PORT_MAX - 1,
        range_rows.len()
    );
    for row in range_rows.iter().take(24) {
        let owners = match socket_owner_pids(row.inode) {
            Ok(pids) if pids.is_empty() => "owner unknown".to_string(),
            Ok(pids) => pids
                .iter()
                .map(|p| {
                    if *p == std::process::id() {
                        format!("pid {p} (THIS PROCESS)")
                    } else {
                        format!("pid {p}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
            Err(e) => format!("owner unavailable ({e})"),
        };
        let _ = writeln!(
            out,
            "    {} {} 127.0.0.1:{} [{}]",
            row.proto, row.state, row.local_port, owners
        );
    }
    for note in range_notes {
        let _ = writeln!(out, "    {note}");
    }
    let _ = writeln!(out, "---- end port diagnosis ----");
    out
}
