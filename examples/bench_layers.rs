//! Throughput of the framing and security layers, one at a time.
//!
//! There was no way to measure these: `bench_tls` covers the security stack on a
//! raw carrier and `bench_native` covers the plain relay, so a per-frame cost
//! added by the framing layer (WebSocket validates every frame, gRPC every
//! message) was invisible. This runs the client pipeline against a server
//! pipeline over loopback for each framing layer and prints MB/s.
//!
//! Usage: `cargo run --release --example bench_layers -- --rounds 5 --mb 32 --chunk 65536`
//!
//! Caveat: this measures an **echo** loop, so the client writes and reads
//! concurrently over one connection. That is representative of a proxy tunnel but
//! it couples the two directions through the layer's flow control, which is why
//! the numbers are lower than a one-way stream and can be noisy — run several
//! rounds and compare medians, never a single round.

use flux_transport::pipeline::{
    FramingLayer, LayeredTransportPipeline, ServerFramingLayer, ServerSecurityLayer,
    ServerTransportPipeline,
};
use flux_types::{StreamDialer, TargetAddress};
use std::collections::HashMap;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn framing(name: &str, path: &str) -> (FramingLayer, ServerFramingLayer) {
    match name {
        "raw" => (FramingLayer::Raw, ServerFramingLayer::Raw),
        "ws" => (
            FramingLayer::WebSocket {
                path: path.to_string(),
                headers: HashMap::new(),
            },
            ServerFramingLayer::WebSocket {
                path: Some(path.to_string()),
            },
        ),
        "upgrade" => (
            FramingLayer::HttpUpgrade {
                path: path.to_string(),
                headers: HashMap::new(),
            },
            ServerFramingLayer::HttpUpgrade {
                path: Some(path.to_string()),
            },
        ),
        "h2" => (
            FramingLayer::Http2 {
                path: path.to_string(),
                headers: HashMap::new(),
            },
            ServerFramingLayer::Http2,
        ),
        "grpc" => (
            FramingLayer::Grpc {
                service_name: "Tun".to_string(),
                headers: HashMap::new(),
            },
            ServerFramingLayer::Grpc,
        ),
        other => panic!("unknown layer {other}"),
    }
}

async fn measure(name: &str, mb: usize, chunk: usize) -> f64 {
    let (client_framing, server_framing) = framing(name, "/bench");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream =
            ServerTransportPipeline::new(vec![ServerSecurityLayer::None], vec![server_framing])
                .unwrap(socket)
                .await
                .expect("server handshake");
        // Echo loop back so the client has a reader.
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = stream.flush().await;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let client = LayeredTransportPipeline::new(TargetAddress::domain("bench.local", 443), addr)
        .with_framing(client_framing);
    let mut stream = client.dial().await.expect("client handshake");

    let payload = vec![0x41u8; chunk];
    let total = mb * 1024 * 1024;

    // Write and read concurrently: writing everything first deadlocks as soon as
    // the pipe buffers fill, because the echo has nowhere to go.
    let (mut rd, mut wr) = tokio::io::split(stream);
    let t = Instant::now();
    let writer = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < total {
            if wr.write_all(&payload).await.is_err() {
                break;
            }
            if wr.flush().await.is_err() {
                break;
            }
            sent += payload.len();
        }
        sent
    });
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0usize;
    while got < total {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    let _ = writer.await;
    let elapsed = t.elapsed().as_secs_f64();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    (mb as f64) / elapsed
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds = args
        .iter()
        .position(|a| a == "--rounds")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let mb = args
        .iter()
        .position(|a| a == "--mb")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);

    let chunk = args
        .iter()
        .position(|a| a == "--chunk")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(64 * 1024);
    println!("chunk = {chunk} bytes");
    println!("layer            round 1        round 2        round 3        median MB/s");
    for name in ["raw", "ws", "upgrade", "h2", "grpc"] {
        let mut vals = Vec::new();
        for _ in 0..rounds {
            vals.push(measure(name, mb, chunk).await);
        }
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
        // Median over all rounds (run at least 5 for a stable number).
        let median = if vals.len() % 2 == 1 {
            vals[vals.len() / 2]
        } else {
            (vals[vals.len() / 2 - 1] + vals[vals.len() / 2]) / 2.0
        };
        let cells: Vec<String> = vals.iter().map(|v| format!("{v:>12.1}")).collect();
        println!("{name:<14} {} {:>12.1}", cells.join(" "), median);
        println!("@@RESULT|layers|1|{name}|mbs|{median:.1}");
    }
}
