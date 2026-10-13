use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

static NEXT_TCP_PORT: AtomicU16 = AtomicU16::new(21000);

/// Returns a unique, non-colliding TCP port.
#[allow(dead_code)]
pub async fn get_free_tcp_port() -> u16 {
    loop {
        let port = NEXT_TCP_PORT.fetch_add(1, Ordering::Relaxed);
        if !(21000..=64000).contains(&port) {
            NEXT_TCP_PORT.store(21000, Ordering::Relaxed);
            continue;
        }
        if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", port)).await
            && let Ok(udp) = std::net::UdpSocket::bind(format!("127.0.0.1:{}", port))
        {
            drop(udp);
            drop(listener);
            return port;
        }
    }
}

/// Starts an asynchronous TCP echo server on an ephemeral OS-assigned port and returns its SocketAddr.
#[allow(dead_code)]
pub async fn start_tcp_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(socket);
                let mut buf = vec![0u8; 32768];
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

    addr
}

#[allow(dead_code)]
pub async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..len], peer).await;
            }
        }
    });

    addr
}

#[allow(dead_code)]
pub fn get_rss_kb() -> usize {
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(v) = parts[1].parse::<usize>()
                {
                    return v;
                }
            }
        }
    }
    0
}

#[allow(dead_code)]
pub fn get_rss_mb() -> f64 {
    get_rss_kb() as f64 / 1024.0
}

/// Starts a real TLS 1.3 echo server (usable as a REALITY handshake target/decoy).
#[allow(dead_code)] // used by interop tests only
pub async fn start_tls_echo_server() -> SocketAddr {
    let dir = TempDir::new().expect("tempdir");
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "example.com".to_string(),
    ])
    .expect("cert generation");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let (certs, key) = flux_transport::tls::TlsTransport::load_certs_and_key(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
    )
    .unwrap();
    let acceptor =
        flux_transport::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    std::mem::forget(dir); // keep cert files alive for the test duration
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if tls.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Retries a flaky-prone interop test body up to `attempts` times.
/// Interop tests spawn external processes (sing-box) and are timing-sensitive
/// under heavy CI load; transient failures are retried with a short backoff,
/// persistent failures still fail the test with the original panic.
#[allow(dead_code)]
pub async fn retry_on_flake<F, Fut>(label: &str, attempts: usize, f: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use futures_util::FutureExt;
    for attempt in 1..=attempts {
        let result = std::panic::AssertUnwindSafe(f()).catch_unwind().await;
        match result {
            Ok(()) => return,
            Err(payload) if attempt < attempts => {
                eprintln!(
                    "[{}] attempt {}/{} failed under load, retrying...",
                    label, attempt, attempts
                );
                drop(payload);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}
