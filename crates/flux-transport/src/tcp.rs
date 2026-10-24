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
