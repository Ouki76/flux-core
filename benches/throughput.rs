use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use flux_app::{Config, Instance};
use flux_protocol::socks5::{CMD_CONNECT, Socks5Handshake};
use flux_router::Router;
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn bench_router(c: &mut Criterion) {
    let mut rules = Vec::new();
    for i in 0..100 {
        rules.push(flux_router::Rule {
            domains: vec![flux_router::DomainMatch::Suffix(format!("domain{}.com", i))],
            outbound: format!("outbound_{}", i),
            ..Default::default()
        });
    }

    let router = Router::new(rules, "direct");
    let meta_hit = SessionMeta::new(
        "127.0.0.1:10000".parse().unwrap(),
        "sub.domain50.com:443".parse().unwrap(),
        "socks-in",
        NetworkType::Tcp,
    );
    let meta_miss = SessionMeta::new(
        "127.0.0.1:10000".parse().unwrap(),
        "google.com:443".parse().unwrap(),
        "socks-in",
        NetworkType::Tcp,
    );

    c.bench_function("router_hit_100_rules", |b| {
        b.iter(|| {
            router.route(&meta_hit);
        })
    });

    c.bench_function("router_miss_100_rules", |b| {
        b.iter(|| {
            router.route(&meta_miss);
        })
    });
}

fn bench_proxy_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Start echo server
    let echo_addr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32768];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
        addr
    });

    // Start flux-core SOCKS5 inbound instance
    let socks_port = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    });

    let config_json = format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "socks" }}
                }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        socks_port
    );

    let instance = rt.block_on(async {
        let cfg = Config::from_json_str(&config_json).unwrap();
        let inst = Instance::new(cfg).unwrap();
        inst.start().await.unwrap();
        inst
    });

    let chunk_size = 64 * 1024; // 64 KB per chunk
    let total_chunks = 16; // 1 MB total per run
    let payload = vec![0x42u8; chunk_size];

    let mut group = c.benchmark_group("socks5_proxy_throughput");
    group.throughput(Throughput::Bytes((chunk_size * total_chunks) as u64));

    group.bench_function("transfer_1MB", |b| {
        b.to_async(&rt).iter(|| async {
            let mut conn = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
                .await
                .unwrap();
            Socks5Handshake::client_handshake(
                &mut conn,
                CMD_CONNECT,
                &TargetAddress::Ip(echo_addr),
            )
            .await
            .unwrap();

            let mut recv_buf = vec![0u8; chunk_size];
            for _ in 0..total_chunks {
                conn.write_all(&payload).await.unwrap();
                conn.read_exact(&mut recv_buf).await.unwrap();
            }
        });
    });

    group.finish();
    rt.block_on(async {
        let _ = instance.stop().await;
    });
}

criterion_group!(benches, bench_router, bench_proxy_throughput);
criterion_main!(benches);
