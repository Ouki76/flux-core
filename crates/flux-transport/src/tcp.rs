use flux_types::{FluxError, FluxResult};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The TCP carrier.
pub struct TcpTransport;

impl TcpTransport {
    /// Connects with the socket options the relay expects already applied.
    pub async fn connect(addr: SocketAddr, connect_timeout: Duration) -> FluxResult<TcpStream> {
        let stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(FluxError::Io(e)),
            Err(_) => {
                return Err(FluxError::Timeout(format!(
                    "connecting to {} timed out",
                    addr
                )));
            }
        };

        let _ = stream.set_nodelay(true);
        let sock_ref = socket2::SockRef::from(&stream);
        let _ = sock_ref.set_keepalive(true);

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            drop(conn);
        });

        let cli = TcpTransport::connect(local_addr, Duration::from_secs(1))
            .await
            .unwrap();
        drop(cli);
        srv.await.unwrap();
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// **IPv6 end to end.** The transport takes a `SocketAddr`, so v6 works only if the address
    /// reaches it intact — a resolver or parser that only understands dotted quads would fail
    /// here and nowhere else.
    #[tokio::test]
    async fn a_connection_over_ipv6_carries_data() {
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => {
                eprintln!("IPv6 loopback is unavailable on this host; skipping");
                return;
            }
        };
        let addr = listener.local_addr().expect("local addr");
        assert!(addr.is_ipv6(), "the listener must be a v6 address: {addr}");
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 4];
                if s.read_exact(&mut b).await.is_ok() {
                    let _ = s.write_all(&b).await;
                }
            }
        });

        let mut stream = TcpTransport::connect(addr, std::time::Duration::from_secs(5))
            .await
            .expect("a v6 connection must be possible");
        stream.write_all(b"v6!!").await.expect("write");
        stream.flush().await.expect("flush");
        let mut got = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut got),
        )
        .await
        .expect("v6 read timed out")
        .expect("read");
        assert_eq!(&got, b"v6!!");
    }
}
