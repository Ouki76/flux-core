use std::net::SocketAddr;
use std::process::Command;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Start Fast Echo Server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((socket, _)) = echo_listener.accept().await {
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = socket.into_split();
                let mut buf = vec![0u8; 128 * 1024];
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

    println!("Target Echo Server listening on {}", echo_addr);

    // 2. Measure Direct Baseline (No proxy)
    let direct_speed = measure_transfer("Direct TCP Loopback (No Proxy)", echo_addr, None).await?;

    // 3. Start flux-core
    let flux_port = get_free_port().await;
    let flux_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        flux_port
    );
    std::fs::write("/tmp/bench_flux.json", flux_cfg)?;
    let mut flux_proc = Command::new("./target/release/flux-core")
        .args(["run", "-c", "/tmp/bench_flux.json", "-f", "json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let flux_addr: SocketAddr = format!("127.0.0.1:{}", flux_port).parse()?;
    let flux_speed = measure_transfer("flux-core (Rust 2024)", echo_addr, Some(flux_addr)).await?;
    let _ = flux_proc.kill();

    // 4. Start sing-box
    let sing_port = get_free_port().await;
    let sing_cfg = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        sing_port
    );
    std::fs::write("/tmp/bench_singbox.json", sing_cfg)?;
    let mut sing_proc = Command::new("/home/ouki/.local/bin/sing-box")
        .args(["run", "-c", "/tmp/bench_singbox.json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let sing_addr: SocketAddr = format!("127.0.0.1:{}", sing_port).parse()?;
    let sing_speed = measure_transfer("sing-box (Go 1.24)", echo_addr, Some(sing_addr)).await?;
    let _ = sing_proc.kill();

    println!("\n================================================================================");
    println!("NATIVE THROUGHPUT BENCHMARK (Pure Compiled Speed, No Python GIL)");
    println!("================================================================================");
    println!(
        "{:<32} | {:<18} | {:<16}",
        "Target", "Speed (MB/s)", "Bandwidth (Gbps)"
    );
    println!("--------------------------------------------------------------------------------");
    println!(
        "{:<32} | {:<18.1} | {:<16.2}",
        "Direct TCP Loopback (Baseline)",
        direct_speed,
        direct_speed * 8.0 / 1000.0
    );
    println!(
        "{:<32} | {:<18.1} | {:<16.2}",
        "flux-core (Rust 2024)",
        flux_speed,
        flux_speed * 8.0 / 1000.0
    );
    println!(
        "{:<32} | {:<18.1} | {:<16.2}",
        "sing-box (Go 1.24)",
        sing_speed,
        sing_speed * 8.0 / 1000.0
    );
    println!("================================================================================");
    if flux_speed > sing_speed {
        println!(
            "\x1b[1;32m✔ flux-core is {:.1}% faster than sing-box!\x1b[0m\n",
            (flux_speed / sing_speed - 1.0) * 100.0
        );
    } else {
        println!(
            "flux-core is at {:.1}% of sing-box speed.\n",
            flux_speed / sing_speed * 100.0
        );
    }

    Ok(())
}

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn measure_transfer(
    label: &str,
    echo_addr: SocketAddr,
    proxy: Option<SocketAddr>,
) -> anyhow::Result<f64> {
    let total_bytes: usize = 300 * 1024 * 1024; // 300 MB
    let chunk_size = 128 * 1024; // 128 KB chunks
    let total_chunks = total_bytes / chunk_size;

    let stream = if let Some(proxy_addr) = proxy {
        let mut s = TcpStream::connect(proxy_addr).await?;
        let _ = s.set_nodelay(true);
        // SOCKS5 handshake
        s.write_all(b"\x05\x01\x00").await?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        assert_eq!(&resp, b"\x05\x00");

        // CONNECT
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        if let SocketAddr::V4(v4) = echo_addr {
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        s.write_all(&req).await?;
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await?;
        assert_eq!(reply[1], 0x00);
        s
    } else {
        let s = TcpStream::connect(echo_addr).await?;
        let _ = s.set_nodelay(true);
        s
    };

    let (mut r, mut w) = stream.into_split();
    let payload = std::sync::Arc::new(vec![0xAAu8; chunk_size]);
    let payload_writer = payload.clone();

    let t0 = Instant::now();
    let write_task = tokio::spawn(async move {
        for _ in 0..total_chunks {
            w.write_all(&payload_writer).await.unwrap();
        }
    });

    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; chunk_size];
        let mut received = 0;
        while received < total_bytes {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received += n;
        }
        received
    });

    let (_, rec) = tokio::join!(write_task, read_task);
    let elapsed = t0.elapsed();
    let received = rec.unwrap();
    assert_eq!(received, total_bytes);

    let speed_mb_s = (total_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
    println!(
        "  [{}] transferred 300 MB in {:?} -> {:.1} MB/s",
        label, elapsed, speed_mb_s
    );
    Ok(speed_mb_s)
}
