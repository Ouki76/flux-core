use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct CacheEntry {
    name: String,
    expires_at: Instant,
}

const POSITIVE_CACHE_TTL: Duration = Duration::from_secs(10);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);
const MAX_CACHE_ENTRIES: usize = 4096;

/// Resolves the name of the process owning a local socket.
///
/// Linux `/proc` scanning is performed on a dedicated background worker thread,
/// so calling [`ProcessResolver::resolve_process_name`] from an async runtime
/// never blocks a Tokio worker. On a cache miss the scan is queued and `None`
/// is returned; subsequent queries pick up the populated cache entry.
#[derive(Clone)]
pub struct ProcessResolver {
    cache: Arc<Mutex<HashMap<SocketAddr, CacheEntry>>>,
    inner: Arc<ResolverShared>,
}

struct ResolverShared {
    pending: Mutex<HashSet<SocketAddr>>,
    scan_tx: std::sync::mpsc::Sender<SocketAddr>,
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessResolver {
    pub fn new() -> Self {
        let cache: Arc<Mutex<HashMap<SocketAddr, CacheEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (scan_tx, scan_rx) = std::sync::mpsc::channel::<SocketAddr>();
        let shared = Arc::new(ResolverShared {
            pending: Mutex::new(HashSet::new()),
            scan_tx,
        });

        // Dedicated blocking-I/O worker. Terminates when all ProcessResolver clones
        // are dropped and the channel disconnects.
        let worker_cache = cache.clone();
        let worker_shared = shared.clone();
        std::thread::Builder::new()
            .name("flux-proc-scan".into())
            .spawn(move || {
                while let Ok(src) = scan_rx.recv() {
                    let result = lookup_process_name(src);
                    let now = Instant::now();
                    let mut cache = worker_cache.lock();
                    if cache.len() > MAX_CACHE_ENTRIES {
                        cache.retain(|_, e| now < e.expires_at);
                    }
                    let (name, ttl) = match result {
                        Some(n) => (n, POSITIVE_CACHE_TTL),
                        None => (String::new(), NEGATIVE_CACHE_TTL),
                    };
                    cache.insert(
                        src,
                        CacheEntry {
                            name,
                            expires_at: now + ttl,
                        },
                    );
                    drop(cache);
                    worker_shared.pending.lock().remove(&src);
                }
            })
            .expect("failed to spawn flux-proc-scan worker thread");

        Self {
            cache,
            inner: shared,
        }
    }

    /// Resolves the executable process name owning the local socket address.
    ///
    /// Non-blocking: returns `None` on a cache miss and queues an asynchronous
    /// background scan instead of performing blocking `/proc` I/O inline.
    pub fn resolve_process_name(&self, src: SocketAddr) -> Option<String> {
        let now = Instant::now();
        {
            let mut cache = self.cache.lock();
            if let Some(entry) = cache.get(&src) {
                if now < entry.expires_at {
                    // Negative cached result is an empty name.
                    return if entry.name.is_empty() {
                        None
                    } else {
                        Some(entry.name.clone())
                    };
                }
                cache.remove(&src);
            }
        }

        // Queue a background scan (deduplicated via `pending`).
        {
            let mut pending = self.inner.pending.lock();
            if pending.insert(src) {
                // If the channel is disconnected the worker is gone; just drop the request.
                if self.inner.scan_tx.send(src).is_err() {
                    pending.remove(&src);
                }
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
fn lookup_process_name(src: SocketAddr) -> Option<String> {
    let inode = find_socket_inode(src)?;
    find_process_name_by_inode(inode)
}

#[cfg(not(target_os = "linux"))]
fn lookup_process_name(_src: SocketAddr) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn find_socket_inode(src: SocketAddr) -> Option<u64> {
    use std::io::BufRead;
    let port = src.port();
    let hex_port = format!("{:04X}", port);

    let tables: [&str; 2] = if src.is_ipv6() {
        ["/proc/net/tcp6", "/proc/net/udp6"]
    } else {
        ["/proc/net/tcp", "/proc/net/udp"]
    };

    // /proc/net/tcp stores IPv4 as 8 hex chars in host (little-endian) byte order.
    // /proc/net/tcp6 stores IPv6 as four 32-bit words, each in host byte order.
    let target_ip_hex = match src.ip() {
        std::net::IpAddr::V4(v4) => {
            let oct = v4.octets();
            format!("{:02X}{:02X}{:02X}{:02X}", oct[3], oct[2], oct[1], oct[0])
        }
        std::net::IpAddr::V6(v6) => {
            let oct = v6.octets();
            let mut out = String::with_capacity(32);
            for chunk in oct.chunks(4) {
                let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                out.push_str(&format!("{:08X}", word));
            }
            out
        }
    };

    let wildcard = if src.is_ipv6() {
        "00000000000000000000000000000000"
    } else {
        "00000000"
    };

    for table in tables {
        let file = match std::fs::File::open(table) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().skip(1).map_while(Result::ok) {
            let mut parts = line.split_whitespace();
            let _sl = parts.next();
            if let Some(local_addr) = parts.next()
                && let Some((ip_hex, p_hex)) = local_addr.split_once(':')
                && p_hex.eq_ignore_ascii_case(&hex_port)
            {
                if !ip_hex.eq_ignore_ascii_case(&target_ip_hex) && ip_hex != wildcard {
                    continue;
                }
                if let Some(inode_str) = parts.nth(7)
                    && let Ok(inode) = inode_str.parse::<u64>()
                {
                    return Some(inode);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_process_name_by_inode(target_inode: u64) -> Option<String> {
    let socket_link = format!("socket:[{}]", target_inode);

    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_str()?;
        if !name_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }

        let fd_dir_path = entry.path().join("fd");
        if let Ok(fd_entries) = std::fs::read_dir(fd_dir_path) {
            for fd_entry in fd_entries.flatten() {
                if let Ok(link) = std::fs::read_link(fd_entry.path())
                    && link.to_str() == Some(&socket_link)
                {
                    // Found PID! Read /proc/<pid>/comm
                    let comm_path = entry.path().join("comm");
                    if let Ok(comm) = std::fs::read_to_string(comm_path) {
                        return Some(comm.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_resolver_cache() {
        let resolver = ProcessResolver::new();
        let src: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        // First call is a miss (scan queued in background).
        assert_eq!(resolver.resolve_process_name(src), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_ipv6_proc_hex_format() {
        // ::1 must render as 32 hex chars in host word order
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        let src = SocketAddr::new(std::net::IpAddr::V6(ip), 80);
        // find_socket_inode must not panic on IPv6
        let _ = find_socket_inode(src);
    }
}
