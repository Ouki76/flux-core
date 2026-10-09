use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct CacheEntry {
    name: String,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct ProcessResolver {
    cache: Arc<Mutex<std::collections::HashMap<SocketAddr, CacheEntry>>>,
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Resolves the executable process name owning the local socket address.
    pub fn resolve_process_name(&self, src: SocketAddr) -> Option<String> {
        let now = Instant::now();
        // 1. Check in-memory cache (supports both positive and negative cache)
        {
            let mut cache = self.cache.lock();
            if let Some(entry) = cache.get(&src) {
                if now < entry.expires_at {
                    if entry.name.is_empty() {
                        return None; // Negative cached result
                    }
                    return Some(entry.name.clone());
                } else {
                    cache.remove(&src);
                }
            }
        }

        // 2. Perform Linux /proc inspection
        #[cfg(target_os = "linux")]
        {
            let result = find_process_by_socket(src);
            let mut cache = self.cache.lock();
            if cache.len() > 4096 {
                cache.retain(|_, e| now < e.expires_at);
            }

            if let Some(ref name) = result {
                cache.insert(
                    src,
                    CacheEntry {
                        name: name.clone(),
                        expires_at: now + Duration::from_secs(10),
                    },
                );
            } else {
                // Negative caching: prevent scanning /proc on every incoming packet
                cache.insert(
                    src,
                    CacheEntry {
                        name: String::new(),
                        expires_at: now + Duration::from_secs(5),
                    },
                );
            }
            result
        }

        #[cfg(not(target_os = "linux"))]
        None
    }
}

#[cfg(target_os = "linux")]
fn find_process_by_socket(src: SocketAddr) -> Option<String> {
    let inode = find_socket_inode(src)?;
    find_process_name_by_inode(inode)
}

#[cfg(target_os = "linux")]
fn find_socket_inode(src: SocketAddr) -> Option<u64> {
    use std::io::BufRead;
    let port = src.port();
    let hex_port = format!("{:04X}", port);

    let tables = if src.is_ipv6() {
        ["/proc/net/tcp6", "/proc/net/udp6"]
    } else {
        ["/proc/net/tcp", "/proc/net/udp"]
    };

    let target_ip_hex = match src.ip() {
        std::net::IpAddr::V4(v4) => {
            let oct = v4.octets();
            Some(format!(
                "{:02X}{:02X}{:02X}{:02X}",
                oct[3], oct[2], oct[1], oct[0]
            ))
        }
        std::net::IpAddr::V6(_) => None,
    };

    for table in tables {
        let file = match std::fs::File::open(table) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().skip(1).flatten() {
            let mut parts = line.split_whitespace();
            let _sl = parts.next();
            if let Some(local_addr) = parts.next()
                && let Some((ip_hex, p_hex)) = local_addr.split_once(':')
                && p_hex.eq_ignore_ascii_case(&hex_port)
            {
                if let Some(ref tip) = target_ip_hex
                    && !ip_hex.eq_ignore_ascii_case(tip)
                    && ip_hex != "00000000"
                {
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
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
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
        assert_eq!(resolver.resolve_process_name(src), None);
    }
}
