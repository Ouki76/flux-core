use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

static NEXT_PORT: AtomicU16 = AtomicU16::new(35000);

/// Returns a unique, non-colliding TCP port.
pub async fn get_free_tcp_port() -> u16 {
    NEXT_PORT.fetch_add(2, Ordering::SeqCst)
}

/// Starts an asynchronous TCP echo server on a unique port and returns its SocketAddr.
pub async fn start_tcp_echo_server() -> SocketAddr {
    let port = get_free_tcp_port().await;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
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
}

#[allow(dead_code)]
pub async fn start_udp_echo_server() -> SocketAddr {
    let port = get_free_tcp_port().await;
    let socket = UdpSocket::bind(format!("127.0.0.1:{}", port)).await.unwrap();
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
