use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Returns a unique, non-colliding TCP port assigned by the OS.
#[allow(dead_code)]
pub async fn get_free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
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
    let port = get_free_tcp_port().await;
    let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
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
