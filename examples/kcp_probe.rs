//! Drives one mKCP conversation so it can be pointed at a real Xray node.
//!
//! `cargo run --release --example kcp_probe -- --peer 127.0.0.1:PORT --bytes 4096`
//!
//! It connects, writes a deterministic pattern, and checks the echo byte-for-byte.
//! This exists because "our mKCP is self-consistent" proves nothing: the only
//! question that matters is whether an implementation we did not write reads it.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut peer: Option<SocketAddr> = None;
    let mut bytes = 4096usize;
    let mut obfs = "srtp".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--peer" => peer = Some(args.next().ok_or("--peer needs a value")?.parse()?),
            "--bytes" => bytes = args.next().ok_or("--bytes needs a value")?.parse()?,
            "--obfs" => obfs = args.next().ok_or("--obfs needs a value")?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let peer = peer.ok_or("--peer is required")?;
    let obfs = match obfs.as_str() {
        "none" => flux_transport::KcpObfs::None,
        "srtp" => flux_transport::KcpObfs::Srtp,
        "utp" => flux_transport::KcpObfs::Utp,
        "wechat-video" | "wechat" => flux_transport::KcpObfs::WechatVideo,
        "dtls" => flux_transport::KcpObfs::Dtls,
        "wireguard" | "wg" => flux_transport::KcpObfs::Wireguard,
        other => return Err(format!("unknown obfs {other}").into()),
    };
    let cfg = flux_transport::KcpConfig {
        obfs,
        ..Default::default()
    };

    let started = std::time::Instant::now();
    let mut stream = flux_transport::connect(peer, cfg).await?;
    let setup = started.elapsed();

    let payload: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let started = std::time::Instant::now();
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let mut got = vec![0u8; bytes];
    tokio::time::timeout(std::time::Duration::from_secs(20), stream.read_exact(&mut got)).await??;
    let elapsed = started.elapsed();

    if got != payload {
        let at = got.iter().zip(&payload).position(|(a, b)| a != b).unwrap_or(0);
        return Err(format!("echo mismatch at byte {at}: got {:?}", &got[at..(at + 8).min(got.len())]).into());
    }
    println!(
        "OK conv={} setup={:?} echoed {bytes} bytes byte-exact in {:?} ({:.1} MiB/s)",
        stream.conv(),
        setup,
        elapsed,
        (bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1e-9)
    );
    Ok(())
}
