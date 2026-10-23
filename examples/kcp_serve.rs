//! Accepts one mKCP conversation and echoes it, so a real Xray client can be
//! pointed at our `accept()` and the result observed rather than guessed.
//!
//! `cargo run --release --example kcp_serve -- --listen 127.0.0.1:19105`

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1:19105".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--listen" {
            listen = args.next().ok_or("--listen needs a value")?;
        }
    }
    let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind(&listen).await?);
    println!("listening on {}", socket.local_addr()?);
    let cfg = flux_transport::KcpConfig {
        obfs: flux_transport::KcpObfs::Srtp,
        ..Default::default()
    };
    let mut stream = flux_transport::accept(socket, cfg).await?;
    println!("accepted conv={} from {:?}", stream.conv(), stream.peer_addr());
    let mut total = 0usize;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                println!("EOF after {total} bytes");
                break;
            }
            Ok(Ok(n)) => {
                total += n;
                println!("read {n} bytes (total {total})");
                stream.write_all(&buf[..n]).await?;
                stream.flush().await?;
            }
            Ok(Err(e)) => {
                println!("read error after {total} bytes: {e}");
                break;
            }
            Err(_) => {
                println!("no data for 10s (total {total})");
                break;
            }
        }
    }
    Ok(())
}
