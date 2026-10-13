//! Soak / leak-detection harness: drives sustained SOCKS5 traffic through a
//! live flux-core instance while sampling RSS, FD count, and thread count.
//!
//! Usage: cargo run --release --example soak_load -- [duration_secs]
//! Default duration: 300s (5 min). For a full soak run 86400 (24h).
//!
//! Leak detection: compares the median RSS of the first 10% of samples with
//! the last 10%; growth beyond +25% (and beyond +64 MB absolute) = FAILURE.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use flux_app::{Config, Instance};

fn rss_kb() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0)
}

fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// One SOCKS5 proxied request: handshake + CONNECT + 4 KiB roundtrip + close.
async fn one_request(proxy: SocketAddr, target: SocketAddr) -> std::io::Result<u64> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).await?;

    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return Err(std::io::Error::other("v4 only in soak")),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut resp = [0u8; 10];
    s.read_exact(&mut resp).await?;
    if resp[1] != 0 {
        return Err(std::io::Error::other("socks connect refused"));
    }

    let payload = vec![0xABu8; 4096];
    s.write_all(&payload).await?;
    let mut echo = vec![0u8; 4096];
    s.read_exact(&mut echo).await?;
    if echo != payload {
        return Err(std::io::Error::other("echo mismatch"));
    }
    Ok(8192)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let duration_secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    let echo_addr = start_echo().await;

    let proxy_port = {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        l.local_addr()?.port()
    };

    let raw = format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "socks" }},
                    "rate_limit": {{ "max_conn_per_ip_per_sec": 100000, "burst": 100000 }}
                }}
            ],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        proxy_port
    );
    let cfg = Config::from_json_str(&raw)?;
    let instance = Instance::new(cfg)?;
    instance.start().await?;

    let proxy: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse()?;
    let stop = Arc::new(AtomicBool::new(false));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let total_reqs = Arc::new(AtomicU64::new(0));
    let total_errs = Arc::new(AtomicU64::new(0));

    // 64 concurrent short-lived-connection workers + 8 long-lived streams.
    for _ in 0..64 {
        let stop = stop.clone();
        let bytes = total_bytes.clone();
        let reqs = total_reqs.clone();
        let errs = total_errs.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                match one_request(proxy, echo_addr).await {
                    Ok(n) => {
                        bytes.fetch_add(n, Ordering::Relaxed);
                        reqs.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errs.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        });
    }
    for _ in 0..8 {
        let stop = stop.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                // Long-lived stream: CONNECT then idle-chatter.
                if let Ok(mut s) = TcpStream::connect(proxy).await {
                    if s.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
                        continue;
                    }
                    let mut b = [0u8; 2];
                    if s.read_exact(&mut b).await.is_err() {
                        continue;
                    }
                    let ip = match echo_addr.ip() {
                        std::net::IpAddr::V4(v4) => v4.octets(),
                        _ => continue,
                    };
                    let mut req = vec![0x05, 0x01, 0x00, 0x01];
                    req.extend_from_slice(&ip);
                    req.extend_from_slice(&echo_addr.port().to_be_bytes());
                    if s.write_all(&req).await.is_err() {
                        continue;
                    }
                    let mut resp = [0u8; 10];
                    if s.read_exact(&mut resp).await.is_err() {
                        continue;
                    }
                    // Chatter 1 KiB every 100ms for the connection's lifetime.
                    let chunk = vec![0xCDu8; 1024];
                    let mut rb = vec![0u8; 1024];
                    while !stop.load(Ordering::Relaxed) {
                        if s.write_all(&chunk).await.is_err() {
                            break;
                        }
                        if s.read_exact(&mut rb).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    println!(
        "soak: {}s duration, 64 short-conn workers + 8 long-lived streams",
        duration_secs
    );
    println!(
        "{:>6} {:>10} {:>8} {:>8} {:>12} {:>10}",
        "t(s)", "RSS(MB)", "FDs", "Threads", "reqs", "errors"
    );

    let start = Instant::now();
    let mut rss_samples: Vec<usize> = Vec::new();
    let mut last_report = Instant::now();
    while start.elapsed().as_secs() < duration_secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let rss = rss_kb();
        rss_samples.push(rss);
        if last_report.elapsed() >= Duration::from_secs(15) {
            last_report = Instant::now();
            println!(
                "{:>6} {:>10.1} {:>8} {:>8} {:>12} {:>10}",
                start.elapsed().as_secs(),
                rss as f64 / 1024.0,
                fd_count(),
                thread_count(),
                total_reqs.load(Ordering::Relaxed),
                total_errs.load(Ordering::Relaxed)
            );
        }
    }

    stop.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(2)).await;
    instance.stop().await?;

    // Leak analysis (time-ordered): median RSS of the first decile vs the last.
    let n = rss_samples.len();
    let decile = (n / 10).max(1);
    let median = |xs: &[usize]| {
        let mut v = xs.to_vec();
        v.sort_unstable();
        v.get(v.len() / 2).copied().unwrap_or(0)
    };
    let head_med = median(&rss_samples[..decile]);
    let tail_med = median(&rss_samples[n - decile..]);
    let min_rss = rss_samples.iter().min().copied().unwrap_or(0);
    let max_rss = rss_samples.iter().max().copied().unwrap_or(0);

    println!("\n=== SOAK SUMMARY ===");
    println!(
        "requests: {}, errors: {}, bytes proxied: {:.1} MB",
        total_reqs.load(Ordering::Relaxed),
        total_errs.load(Ordering::Relaxed),
        total_bytes.load(Ordering::Relaxed) as f64 / 1048576.0
    );
    println!(
        "RSS min/max: {:.1} / {:.1} MB | head-median: {:.1} MB | tail-median: {:.1} MB | final FDs: {} | final threads: {}",
        min_rss as f64 / 1024.0,
        max_rss as f64 / 1024.0,
        head_med as f64 / 1024.0,
        tail_med as f64 / 1024.0,
        fd_count(),
        thread_count()
    );

    // Failure criteria: tail median exceeds head median by >25% AND >16 MB absolute.
    let growth_abs = tail_med.saturating_sub(head_med) as f64 / 1024.0;
    let growth_rel = if head_med > 0 {
        tail_med as f64 / head_med as f64
    } else {
        1.0
    };
    if growth_abs > 16.0 && growth_rel > 1.25 {
        println!(
            "FAILURE: RSS tail-median grew {:.1} MB ({:.0}%) over head-median — likely leak!",
            growth_abs,
            (growth_rel - 1.0) * 100.0
        );
        std::process::exit(1);
    }
    println!(
        "OK: bounded memory (tail/head median delta {:.1} MB, {:.0}%)",
        growth_abs,
        (growth_rel - 1.0) * 100.0
    );
    Ok(())
}
