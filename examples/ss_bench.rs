//! In-process throughput of the Shadowsocks-2022 stream wrapper.
//!
//! Exists because the proxy-level benchmark cannot say whether a gap is the cipher,
//! the framing or the socket plumbing. This removes the sockets: two streams talk to
//! each other over an in-memory pipe, so the only work left is ours.
//!
//! `cargo run --release --example ss_bench -- --mb 256`
//!
//! Under callgrind, which needs no kernel privileges:
//! `valgrind --tool=callgrind --callgrind-out-file=/tmp/cg.out ./target/release/examples/ss_bench --mb 8`
//! then `callgrind_annotate /tmp/cg.out | head -40`.

use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn arg(name: &str, default: &str) -> String {
    let mut args = std::env::args().skip(1);
    let mut out = default.to_string();
    while let Some(a) = args.next() {
        if a == format!("--{name}") {
            out = args.next().unwrap_or_default();
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use flux_protocol::shadowsocks2022::{ReplayFilter, Ss2022CipherMethod, Ss2022Protocol};

    let mib: usize = arg("mb", "256").parse()?;
    let total = mib * 1024 * 1024;

    // A deep pipe keeps both sides busy instead of ping-ponging on capacity.
    let (client_io, server_io) = tokio::io::duplex(2 * 1024 * 1024);

    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let expect = payload.len();

    let sink = tokio::spawn(async move {
        let psk = b"0123456789abcdef";
        let replay = ReplayFilter::new(10_000);
        let (mut s, _target, _extra) = Ss2022Protocol::server_handshake(
            server_io,
            Ss2022CipherMethod::Blake3Aes128Gcm,
            psk,
            &replay,
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut got = 0usize;
        while got < expect {
            let n = s.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            got += n;
        }
        Ok::<usize, String>(got)
    });

    let started = Instant::now();
    {
        let psk = b"0123456789abcdef";
        let target: flux_types::TargetAddress = "127.0.0.1:9".parse()?;
        let mut s = Ss2022Protocol::client_handshake(
            client_io,
            Ss2022CipherMethod::Blake3Aes128Gcm,
            psk,
            &target,
        )
        .await
        .map_err(|e| e.to_string())?;
        // 64 KiB slices, the unit the relay hands to the protocol.
        for chunk in payload.chunks(64 * 1024) {
            s.write_all(chunk).await.map_err(|e| e.to_string())?;
        }
        s.flush().await.map_err(|e| e.to_string())?;
    }

    let got = sink.await.map_err(|e| e.to_string())??;
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "{got} bytes in {elapsed:.3}s = {:.1} MiB/s (in-process, sockets excluded)",
        got as f64 / 1_048_576.0 / elapsed
    );
    Ok(())
}
