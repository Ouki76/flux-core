mod common;

use common::{get_free_tcp_port, get_rss_mb, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_protocol::socks5::{CMD_CONNECT, Socks5Handshake};
use flux_router::{DomainMatch, Router, Rule};
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_perf_memory_concurrency_and_leak() {
    let echo_addr = start_tcp_echo_server().await;
    let socks_port = get_free_tcp_port().await;

    let config_json = format!(
        r#"{{
            "inbounds": [
                {{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {} }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        socks_port
    );

    let cfg = Config::from_json_str(&config_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let initial_rss = get_rss_mb();
    println!("Initial RSS: {:.2} MB", initial_rss);

    // Concurrency: 100 simultaneous SOCKS5 connections
    let mut conns = Vec::new();
    for _ in 0..100 {
        let mut conn = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();
        Socks5Handshake::client_handshake(&mut conn, CMD_CONNECT, &TargetAddress::Ip(echo_addr))
            .await
            .unwrap();
        conns.push(conn);
    }

    let under_load_rss = get_rss_mb();
    println!("RSS under 100 connections: {:.2} MB", under_load_rss);

    // Verify all 100 connections are active and can send/recv
    let ping = b"flux_perf_test_ping";
    let mut resp = vec![0u8; ping.len()];
    for conn in &mut conns {
        conn.write_all(ping).await.unwrap();
        conn.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, ping);
    }

    // Drop all connections
    drop(conns);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let post_rss = get_rss_mb();
    println!("Post-teardown RSS: {:.2} MB", post_rss);

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_perf_throughput_speed() {
    let echo_addr = start_tcp_echo_server().await;
    let socks_port = get_free_tcp_port().await;

    let config_json = format!(
        r#"{{
            "inbounds": [
                {{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {} }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        socks_port
    );

    let cfg = Config::from_json_str(&config_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();
    let _ = conn.set_nodelay(true);
    Socks5Handshake::client_handshake(&mut conn, CMD_CONNECT, &TargetAddress::Ip(echo_addr))
        .await
        .unwrap();

    let (mut reader, mut writer) = conn.into_split();
    let chunk_size = 64 * 1024;
    let chunks = 160; // 10 MB total
    let total_bytes = chunk_size * chunks;
    let payload = Arc::new(vec![0x77u8; chunk_size]);

    let payload_writer = payload.clone();
    let t0 = Instant::now();

    let write_task = tokio::spawn(async move {
        for _ in 0..chunks {
            writer.write_all(&payload_writer).await.unwrap();
        }
    });

    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; chunk_size];
        let mut rec = 0;
        while rec < total_bytes {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            rec += n;
        }
        rec
    });

    let (_, rec) = tokio::join!(write_task, read_task);
    let elapsed = t0.elapsed();
    let received = rec.unwrap();
    assert_eq!(received, total_bytes);

    let mb_s = (total_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
    println!(
        "Throughput (10 MB transfer): {:.1} MB/s in {:?}",
        mb_s, elapsed
    );

    assert!(
        mb_s > 50.0,
        "Throughput should be at least 50 MB/s even in debug build"
    );

    instance.stop().await.unwrap();
}

#[test]
fn test_perf_router_1000_rules_latency() {
    let mut rules = Vec::with_capacity(1000);
    for i in 0..1000 {
        rules.push(Rule {
            domains: vec![DomainMatch::suffix(format!("domain-{}.com", i))],
            outbound: format!("node-{}", i),
            ..Default::default()
        });
    }

    let router = Router::new(rules, "direct");
    let meta = SessionMeta::new(
        "127.0.0.1:10000".parse().unwrap(),
        "sub.domain-500.com:443".parse().unwrap(),
        "in",
        NetworkType::Tcp,
    );

    let t0 = Instant::now();
    let iters = 10_000;
    for _ in 0..iters {
        let res = router.route(&meta);
        assert_eq!(res, "node-500");
    }
    let elapsed = t0.elapsed();
    let ns_per_lookup = elapsed.as_nanos() as f64 / iters as f64;
    println!("Router 1000 rules lookup: {:.1} ns/lookup", ns_per_lookup);

    assert!(
        ns_per_lookup < 500_000.0,
        "Lookup must be reasonably fast even in unoptimized debug"
    );
}
