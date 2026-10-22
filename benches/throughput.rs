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

/// Cost of the pooled-buffer lifecycle on the datagram hot path.
///
/// The pool used to scrub every released buffer (`Vec::fill(0)`), i.e. a full
/// `memset` of the buffer — for the 64 KiB packet pool that is one memset *per
/// UDP datagram*. This measures the current lifecycle against that old
/// behaviour so the saving is a concrete, reproducible number rather than a
/// claim.
fn bench_buffer_pool(c: &mut Criterion) {
    use flux_common::BufferPool;

    let mut group = c.benchmark_group("buffer_pool_64k");
    group.throughput(Throughput::Bytes(65_536));

    group.bench_function("acquire_release", |b| {
        let pool = BufferPool::packet_pool();
        b.iter(|| {
            let buf = pool.acquire();
            pool.release(buf);
        })
    });

    group.bench_function("acquire_release_with_scrub_legacy", |b| {
        // Baseline for the removed behaviour: scrub before returning.
        let pool = BufferPool::packet_pool();
        b.iter(|| {
            let mut buf = pool.acquire();
            buf.fill(0);
            pool.release(buf);
        })
    });

    group.finish();
}

/// Cost of building a TLS client connector, cached vs. cold.
///
/// The connector embeds a `CryptoProvider` (cipher-suite / key-exchange tables)
/// and a ~150-entry root certificate store; both used to be rebuilt on every
/// dial. A cache miss is emulated with a unique ALPN list.
fn bench_tls_connector(c: &mut Criterion) {
    use flux_transport::tls::{TlsClientConfig, TlsTransport};

    let mut group = c.benchmark_group("tls_client_connector");

    let warm = TlsClientConfig::new("example.com");
    let _ = TlsTransport::create_client_connector(&warm).unwrap();
    group.bench_function("cached_hit", |b| {
        b.iter(|| TlsTransport::create_client_connector(&warm).unwrap())
    });

    let mut counter = 0u32;
    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            counter = counter.wrapping_add(1);
            let mut cfg = TlsClientConfig::new("example.com");
            cfg.alpn = vec![format!("proto-{counter}").into_bytes()];
            TlsTransport::create_client_connector(&cfg).unwrap()
        })
    });

    group.finish();
}

/// Cost of the relay copy itself: 1 MiB pushed through a pair of duplex streams.
///
/// The pooled-split variant was removed from the product: `tokio::io::split` wraps
/// the stream in a mutex that both directions contend for, and the dispatcher's
/// A/B measured +13.5 % throughput and −9.5 % CPU without it. The "pooled_buffers"
/// benchmark therefore now measures the *datagram* pool lifecycle (see
/// `bench_pool_lifecycle`); this group measures the copy path alone.
///
/// This is the floor under every TCP-path number the project reports: the proxy
/// burns this much CPU per byte before it does any protocol work. It is also why
/// the "flux direct" row in `bench_tls` costs ~0.3 CPU s/GB at multi-GB/s rates —
/// the copy path, not the socket, is the cost.
fn bench_copy_paths(c: &mut Criterion) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const BYTES: usize = 1 << 20;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("relay_copy_1mib");
    group.throughput(Throughput::Bytes(BYTES as u64));

    // Runs one relay pass: `server` writes BYTES, the copy shuttles it, and
    // `client` reads BYTES back. Both directions are exercised.
    async fn one_pass() {
        let (mut client, proxy_in) = tokio::io::duplex(64 * 1024);
        let (proxy_out, mut server) = tokio::io::duplex(64 * 1024);
        let payload = vec![0x5Au8; BYTES];

        let writer = tokio::spawn(async move {
            server.write_all(&payload).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; BYTES];
            client.read_exact(&mut buf).await.unwrap();
            buf.len()
        });

        let _ = flux_common::copy::copy_bidirectional(proxy_in, proxy_out)
            .await
            .unwrap();
        assert_eq!(writer.await.unwrap(), ());
        assert_eq!(reader.await.unwrap(), BYTES);
    }

    group.bench_function("bidirectional", |b| b.to_async(&rt).iter(one_pass));
    group.finish();
}

/// Per-connection setup cost of a SOCKS5 inbound: TCP connect + method
/// negotiation + CONNECT, no payload.
///
/// The concurrency matrix reports this as "setup ms"; at 2048 concurrent streams
/// it decides whether a burst of new connections costs milliseconds or seconds.
fn bench_socks_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let echo_addr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32 * 1024];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    });

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

    let mut group = c.benchmark_group("socks5_inbound");
    group.bench_function("handshake_connect_only", |b| {
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
            drop(conn);
        })
    });
    group.finish();

    rt.block_on(async {
        let _ = instance.stop().await;
    });
}

criterion_group!(
    benches,
    bench_router,
    bench_buffer_pool,
    bench_tls_connector,
    bench_proxy_throughput,
    bench_copy_paths,
    bench_socks_handshake
);
criterion_main!(benches);
