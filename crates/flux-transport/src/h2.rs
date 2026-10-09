use bytes::Bytes;
use flux_types::{AsyncStream, FluxError, FluxResult};
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional byte stream operating over an HTTP/2 stream.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    read_buf: Bytes,
    read_pos: usize,
}

impl H2Stream {
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            read_pos: 0,
        }
    }

    pub fn send_grpc_trailers(&mut self) {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        let _ = self.send.send_trailers(trailers);
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
                this.read_pos += to_copy;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf = Bytes::new();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match this.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = this.recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                    this.read_pos = 0;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = &mut *self;
        let current_cap = this.send.capacity();
        if current_cap < buf.len() {
            this.send.reserve_capacity(buf.len() - current_cap);
        }

        match this.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                if capacity == 0 {
                    return Poll::Pending;
                }
                let to_write = buf.len().min(capacity);
                let chunk = Bytes::copy_from_slice(&buf[..to_write]);
                if let Err(e) = this.send.send_data(chunk, false) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                Poll::Ready(Ok(to_write))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let _ = this.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

pub struct H2Transport;

impl H2Transport {
    /// Client-side HTTP/2 handshake (over TLS or cleartext h2c) establishing an active stream.
    pub async fn client_handshake<S>(
        stream: S,
        host: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> FluxResult<H2Stream>
    where
        S: AsyncStream + 'static,
    {
        let (mut client, h2_conn) =
            h2::client::handshake(stream)
                .await
                .map_err(|e| FluxError::Protocol {
                    protocol: "http2",
                    message: format!("H2 handshake failed: {}", e),
                })?;

        // Spawn connection driver in background
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        Self::create_client_stream(&mut client, host, path, headers).await
    }

    pub async fn create_client_stream(
        client: &mut SendRequest<Bytes>,
        host: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> FluxResult<H2Stream> {
        let clean_path = if path.is_empty() { "/" } else { path };

        let mut req_builder = Request::builder()
            .method("POST")
            .uri(format!("https://{}{}", host, clean_path))
            .header("Host", host)
            .header("User-Agent", "flux-core/h2");

        for (k, v) in headers {
            req_builder = req_builder.header(k.as_str(), v.as_str());
        }

        let request = req_builder.body(()).map_err(|e| FluxError::Protocol {
            protocol: "http2",
            message: format!("failed to build H2 request: {}", e),
        })?;

        let (response_fut, send_stream) =
            client
                .send_request(request, false)
                .map_err(|e| FluxError::Protocol {
                    protocol: "http2",
                    message: format!("failed to send H2 request: {}", e),
                })?;

        let response = response_fut.await.map_err(|e| FluxError::Protocol {
            protocol: "http2",
            message: format!("H2 response error: {}", e),
        })?;

        let recv_stream = response.into_body();
        Ok(H2Stream::new(send_stream, recv_stream))
    }

    /// Server-side HTTP/2 handshake establishing an active stream.
    pub async fn server_handshake<S>(stream: S) -> FluxResult<H2Stream>
    where
        S: AsyncStream + 'static,
    {
        let mut server_builder = h2::server::Builder::new();
        server_builder.initial_window_size(1024 * 1024);
        server_builder.initial_connection_window_size(2 * 1024 * 1024);

        let mut server_conn =
            server_builder
                .handshake(stream)
                .await
                .map_err(|e| FluxError::Protocol {
                    protocol: "http2",
                    message: format!("server H2 handshake failed: {}", e),
                })?;

        let (request, mut respond) = server_conn
            .accept()
            .await
            .ok_or_else(|| FluxError::Protocol {
                protocol: "http2",
                message: "H2 client closed connection before sending request".into(),
            })?
            .map_err(|e| FluxError::Protocol {
                protocol: "http2",
                message: format!("error receiving H2 request: {}", e),
            })?;

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(())
            .unwrap();

        let send_stream =
            respond
                .send_response(response, false)
                .map_err(|e| FluxError::Protocol {
                    protocol: "http2",
                    message: format!("failed to send H2 response: {}", e),
                })?;

        let recv_stream = request.into_body();

        // Spawn server connection driver in background that keeps processing H2 connection frames
        tokio::spawn(async move {
            let mut conn = server_conn;
            while let Some(res) = conn.accept().await {
                if res.is_err() {
                    break;
                }
            }
        });

        Ok(H2Stream::new(send_stream, recv_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_h2_bidirectional_streaming() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let srv = tokio::spawn(async move {
            let mut srv_stream = H2Transport::server_handshake(server_io).await.unwrap();
            let mut buf = [0u8; 11];
            srv_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping h2_req");
            srv_stream.write_all(b"pong h2_res").await.unwrap();
            srv_stream.flush().await.unwrap();
            let _ = done_rx.await;
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = H2Transport::client_handshake(
                client_io,
                "example.com",
                "/proxy-h2",
                &HashMap::new(),
            )
            .await
            .unwrap();

            cli_stream.write_all(b"ping h2_req").await.unwrap();
            cli_stream.flush().await.unwrap();

            let mut buf = [0u8; 11];
            cli_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong h2_res");
            let _ = done_tx.send(());
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}
