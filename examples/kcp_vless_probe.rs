//! Drives a VLESS request over mKCP against a real Xray node.
//!
//! `cargo run --release --example kcp_vless_probe -- --peer 127.0.0.1:PORT \
//!      --uuid <uuid> --target 127.0.0.1:19000 --bytes 4096`
//!
//! This is the only test that answers the question that matters: can an Xray
//! server's `"network": "kcp"` inbound carry our traffic? `freedom` + a
//! `dokodemo-door` inbound cannot be used for it — `freedom` with a kcp transport
//! dials the *requested destination* over KCP, not the server.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut peer: Option<SocketAddr> = None;
    let mut uuid: Option<uuid::Uuid> = None;
    let mut target = "127.0.0.1:19000".to_string();
    let mut bytes = 4096usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--peer" => peer = Some(args.next().ok_or("--peer")?.parse()?),
            "--uuid" => uuid = Some(args.next().ok_or("--uuid")?.parse()?),
            "--target" => target = args.next().ok_or("--target")?,
            "--bytes" => bytes = args.next().ok_or("--bytes")?.parse()?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let peer = peer.ok_or("--peer is required")?;
    let uuid = uuid.ok_or("--uuid is required")?;

    let kcp = flux_transport::KcpConfig {
        obfs: flux_transport::KcpObfs::Srtp,
        ..Default::default()
    };
    let mut stream = flux_transport::connect(peer, kcp).await?;
    let dest: flux_types::TargetAddress = target.parse()?;
    flux_protocol::vless::VlessProtocol::write_request_header(
        &mut stream,
        &uuid,
        flux_types::NetworkType::Tcp,
        &dest,
        None,
    )
    .await?;
    let mut stream = flux_protocol::vless::VlessClientStream::new(stream);

    let payload: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let started = std::time::Instant::now();
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let mut got = vec![0u8; bytes];
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stream.read_exact(&mut got),
    )
    .await??;
    let elapsed = started.elapsed();
    if got != payload {
        let at = got
            .iter()
            .zip(&payload)
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(format!("mismatch at byte {at}").into());
    }
    println!(
        "OK vless over mKCP: {bytes} bytes byte-exact in {:?} ({:.2} MiB/s)",
        elapsed,
        (bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64().max(1e-9)
    );
    Ok(())
}
