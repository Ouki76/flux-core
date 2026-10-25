//! Requests per second: many short connections, each one a request and a reply.
//!
//! `bench_matrix` measures bulk throughput — one connection moving 200 MiB. That is the
//! wrong shape for what a proxy actually serves in front of a browser or an app: dozens of
//! short-lived connections, each carrying a request and a response. This measures that
//! shape, and it measures it against the same two competitors on the same protocol row.
//!
//! What it reports is **completed exchanges per second** across `--conns` concurrent
//! connections, plus the per-exchange latency at the median and the 99th percentile. A
//! stack that is fast at bulk and slow at setup shows up here and nowhere else.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PAYLOAD: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stack {
    Flux,
    Singbox,
    Xray,
}

impl Stack {
    fn name(self) -> &'static str {
        match self {
            Self::Flux => "flux-core",
            Self::Singbox => "sing-box",
            Self::Xray => "xray",
        }
    }
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(bin: &Path, args: &[&str], log: &Path) -> Result<Proc> {
    let out = std::fs::File::create(log)?;
    let err = out.try_clone()?;
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    Ok(Proc(child))
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn wait_listen(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Server config for the chosen framing; `grpc` exercises the h2 layer end to end.
fn flux_server_framed(port: u16, framing: &str) -> String {
    // An inbound gRPC framing takes no `service_name`: it accepts whatever `:path` the
    // client sends, and a server-side value is rejected rather than ignored.
    let f = match framing {
        "grpc" => r#","framing":{"type":"grpc"}"#,
        _ => "",
    };
    format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"tag":"in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{port}}}{f},"protocol":{{"type":"vless","uuid":"{UUID}"}}}}],"outbounds":[{{"type":"direct","tag":"direct"}}],"route":{{"final":"direct"}}}}"#
    )
}

fn flux_client_framed(socks: u16, port: u16, framing: &str) -> String {
    let f = match framing {
        "grpc" => r#","framing":{"type":"grpc","service_name":"svc"}"#,
        _ => "",
    };
    format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"tag":"in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{socks}}},"protocol":{{"type":"socks"}}}}],"outbounds":[{{"tag":"node","carrier":{{"type":"tcp","address":"127.0.0.1:{port}"}}{f},"protocol":{{"type":"vless","uuid":"{UUID}"}}}}],"route":{{"final":"node"}}}}"#
    )
}

fn sbox_server(port: u16) -> String {
    format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":{port},"users":[{{"uuid":"{UUID}"}}]}}],"outbounds":[{{"type":"direct","tag":"d"}}]}}"#
    )
}

fn sbox_client(socks: u16, port: u16) -> String {
    format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":{socks}}}],"outbounds":[{{"type":"vless","tag":"n","server":"127.0.0.1","server_port":{port},"uuid":"{UUID}"}}]}}"#
    )
}

fn xray_server(port: u16) -> String {
    format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"port":{port},"listen":"127.0.0.1","protocol":"vless","settings":{{"clients":[{{"id":"{UUID}"}}],"decryption":"none"}}}}],"outbounds":[{{"protocol":"freedom"}}]}}"#
    )
}

fn xray_client(socks: u16, port: u16) -> String {
    format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"port":{socks},"listen":"127.0.0.1","protocol":"socks","settings":{{"auth":"noauth","udp":false}}}}],"outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"127.0.0.1","port":{port},"users":[{{"id":"{UUID}","encryption":"none"}}]}}]}}}}]}}"#
    )
}

/// One exchange: connect through SOCKS, send `PAYLOAD`, read it back, close.
fn exchange(socks: SocketAddr, echo: SocketAddr) -> Result<Duration> {
    let start = Instant::now();
    let mut s = TcpStream::connect(socks)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    s.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    let mut req = vec![5, 1, 0, 1];
    match echo.ip() {
        std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => anyhow::bail!("echo must be IPv4"),
    }
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 10];
    s.read_exact(&mut head)?;
    anyhow::ensure!(head[1] == 0, "SOCKS refused: {:?}", head);
    let blob = vec![0x5au8; PAYLOAD];
    s.write_all(&blob)?;
    let mut got = vec![0u8; PAYLOAD];
    s.read_exact(&mut got)?;
    anyhow::ensure!(got == blob, "payload corrupted");
    Ok(start.elapsed())
}

/// Resident set size of a process, in bytes, from `/proc`.
fn rss_bytes(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Opens `n` connections through the proxy and holds them open, returning the resident
/// memory of both tunnel processes before and after.
///
/// Capacity planning is about this number, not about throughput: a proxy that moves
/// 700 MiB/s and costs 512 KiB per connection cannot serve a phone.
fn measure_footprint(
    socks: SocketAddr,
    echo: SocketAddr,
    n: usize,
    server_pid: u32,
    client_pid: u32,
) -> Result<(u64, u64)> {
    let before = rss_bytes(server_pid).unwrap_or(0) + rss_bytes(client_pid).unwrap_or(0);
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        let mut s = TcpStream::connect(socks)?;
        s.set_nodelay(true)?;
        s.write_all(&[5, 1, 0])?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply)?;
        let mut req = vec![5, 1, 0, 1];
        match echo.ip() {
            std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
            std::net::IpAddr::V6(_) => anyhow::bail!("echo must be IPv4"),
        }
        req.extend_from_slice(&echo.port().to_be_bytes());
        s.write_all(&req)?;
        let mut head = [0u8; 10];
        s.read_exact(&mut head)?;
        held.push(s);
    }
    // Let the stacks settle: accept queues and buffers are allocated lazily, so a reading
    // taken immediately measures an optimistic state.
    std::thread::sleep(Duration::from_millis(1500));
    let after = rss_bytes(server_pid).unwrap_or(0) + rss_bytes(client_pid).unwrap_or(0);
    drop(held);
    Ok((before, after))
}

fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = sock;
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
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

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut exchanges: u64 = 4000;
    let mut conns: usize = 32;
    let mut idle: usize = 0;
    let mut framing = String::from("none");
    while let Some(a) = args.next() {
        match a.as_str() {
            "--exchanges" => exchanges = args.next().unwrap_or_default().parse()?,
            "--conns" => conns = args.next().unwrap_or_default().parse()?,
            "--idle" => idle = args.next().unwrap_or_default().parse()?,
            "--framing" => framing = args.next().unwrap_or_else(|| "none".into()),
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    // The example lives in target/release/examples/, so the binary is one level up.
    let flux = std::env::var("FLUX_BIN").unwrap_or_else(|_| {
        std::env::current_exe()
            .ok()
            .and_then(|p| {
                p.parent()?
                    .parent()
                    .map(|d| d.join("flux-core").to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "target/release/flux-core".into())
    });
    let sbox = PathBuf::from(format!("{home}/.local/bin/sing-box"));
    let xray = PathBuf::from(format!("{home}/.local/bin/xray"));
    let dir = std::env::temp_dir().join(format!("flux-rps-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let echo = start_echo();

    if idle == 0 {
        println!("requests per second — {exchanges} exchanges over {conns} concurrent connections");
        println!("{}", "-".repeat(78));
        println!(
            "{:<12} {:>13} {:>12} {:>12}",
            "stack", "exchanges/s", "median", "p99"
        );
    } else {
        println!("memory per idle connection — {idle} connections held open through the tunnel");
        println!("{}", "-".repeat(78));
        println!(
            "{:<12} {:>14} {:>14} {:>14}",
            "stack", "RSS idle", "RSS loaded", "per connection"
        );
    }

    for stack in [Stack::Flux, Stack::Singbox, Stack::Xray] {
        let bin = match stack {
            Stack::Flux => PathBuf::from(&flux),
            Stack::Singbox if sbox.is_file() => sbox.clone(),
            Stack::Xray if xray.is_file() => xray.clone(),
            _ => {
                println!("{:<12} {:>13}", stack.name(), "not installed");
                continue;
            }
        };
        let sport = free_port();
        let socks = free_port();
        let (srv, cli) = match stack {
            Stack::Flux => (
                flux_server_framed(sport, &framing),
                flux_client_framed(socks, sport, &framing),
            ),
            Stack::Singbox => (sbox_server(sport), sbox_client(socks, sport)),
            Stack::Xray => (xray_server(sport), xray_client(socks, sport)),
        };
        let sp = dir.join(format!("{}-srv.json", stack.name()));
        let cp = dir.join(format!("{}-cli.json", stack.name()));
        std::fs::write(&sp, srv)?;
        std::fs::write(&cp, cli)?;

        let server = match stack {
            Stack::Flux => spawn(
                &bin,
                &["run", "-c", sp.to_str().unwrap(), "-f", "json"],
                &dir.join("srv.log"),
            )?,
            _ => spawn(
                &bin,
                &["run", "-c", sp.to_str().unwrap()],
                &dir.join("srv.log"),
            )?,
        };
        if !wait_listen(
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), sport),
            Duration::from_secs(15),
        ) {
            println!("{:<12} {:>13}", stack.name(), "server never listened");
            continue;
        }
        let client = match stack {
            Stack::Flux => spawn(
                &bin,
                &["run", "-c", cp.to_str().unwrap(), "-f", "json"],
                &dir.join("cli.log"),
            )?,
            _ => spawn(
                &bin,
                &["run", "-c", cp.to_str().unwrap()],
                &dir.join("cli.log"),
            )?,
        };
        let socks_addr =
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), socks);
        if !wait_listen(socks_addr, Duration::from_secs(15)) {
            println!("{:<12} {:>13}", stack.name(), "client never listened");
            drop((server, client));
            continue;
        }

        if idle > 0 {
            let srv_pid = server.0.id();
            let cli_pid = client.0.id();
            match measure_footprint(socks_addr, echo, idle, srv_pid, cli_pid) {
                Ok((before, after)) => {
                    let per = after.saturating_sub(before) / idle as u64;
                    println!(
                        "{:<12} {:>13} K {:>13} K {:>13} K",
                        stack.name(),
                        before / 1024,
                        after / 1024,
                        per / 1024
                    );
                }
                Err(e) => println!("{:<12} {:>14}", stack.name(), format!("failed: {e}")),
            }
            drop((server, client));
            std::thread::sleep(Duration::from_millis(300));
            continue;
        }

        // Warm-up, so the first exchange's connection setup is not an outlier.
        for _ in 0..16 {
            let _ = exchange(socks_addr, echo);
        }

        let done = Arc::new(AtomicU64::new(0));
        let lat = Arc::new(std::sync::Mutex::new(Vec::<u64>::with_capacity(
            exchanges as usize,
        )));
        let per = exchanges / conns as u64;
        let started = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..conns {
            let lat = lat.clone();
            let done = done.clone();
            handles.push(std::thread::spawn(move || {
                let mut local = Vec::new();
                for _ in 0..per {
                    if let Ok(d) = exchange(socks_addr, echo) {
                        local.push(d.as_micros() as u64);
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                }
                lat.lock().unwrap().extend_from_slice(&local);
            }));
        }
        for h in handles {
            h.join().ok();
        }
        let elapsed = started.elapsed().as_secs_f64();
        let completed = done.load(Ordering::Relaxed);
        let mut lats = lat.lock().unwrap().clone();
        lats.sort_unstable();
        let median = lats.get(lats.len() / 2).copied().unwrap_or(0);
        let p99 = lats
            .get((lats.len() * 99 / 100).min(lats.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0);
        println!(
            "{:<12} {:>13.0} {:>9} µs {:>9} µs",
            stack.name(),
            completed as f64 / elapsed,
            median,
            p99
        );
        drop((server, client));
        std::thread::sleep(Duration::from_millis(300));
    }

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
