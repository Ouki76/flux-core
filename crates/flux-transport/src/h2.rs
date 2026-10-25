use bytes::Bytes;
use flux_types::{AsyncStream, FluxError, FluxResult};
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum H2RecvState {
    Pending(h2::client::ResponseFuture),
    Ready(RecvStream),
}

/// A bidirectional byte stream operating over an HTTP/2 stream.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: H2RecvState,
    read_buf: Bytes,
    read_pos: usize,
}

impl H2Stream {
    /// Wraps one h2 stream pair as a byte stream.
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv: H2RecvState::Ready(recv),
            read_buf: Bytes::new(),
            read_pos: 0,
        }
    }

    /// Builds a client stream whose request completes later.
    pub fn new_client_pending(
        send: SendStream<Bytes>,
        response_fut: h2::client::ResponseFuture,
    ) -> Self {
        Self {
            send,
            recv: H2RecvState::Pending(response_fut),
            read_buf: Bytes::new(),
            read_pos: 0,
        }
    }

    /// Ends the stream with a gRPC status trailer.
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

            match &mut this.recv {
                H2RecvState::Pending(fut) => match Pin::new(fut).poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        // A tunnel is only established on success: a 404,
                        // captive-portal 200-less error page or 407 proxy
                        // challenge would otherwise be spliced into the stream
                        // body as if it were proxy data (silent corruption).
                        let status = response.status();
                        if !status.is_success() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("H2 tunnel rejected by peer with HTTP status {status}"),
                            )));
                        }
                        let recv_stream = response.into_body();
                        this.recv = H2RecvState::Ready(recv_stream);
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("H2 response error: {}", e),
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                H2RecvState::Ready(recv) => match recv.poll_data(cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        let _ = recv.flow_control().release_capacity(bytes.len());
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
                },
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
                    // After `reserve_capacity`, `poll_capacity` returns `Pending`
                    // until at least one byte of capacity is granted, so a
                    // `Ready(0)` here means the peer will never accept more data
                    // (stream closed/reset). Returning `Pending` lost the wake-up
                    // and could stall the tunnel indefinitely; returning `Ok(0)`
                    // would surface as a confusing `WriteZero`. Report the real
                    // condition instead.
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 stream can no longer accept data",
                    )));
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

/// Raw HTTP/2 framing.
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
        let mut client = shared::client_handshake(stream, "http2").await?;
        Self::create_client_stream(&mut client, host, path, headers).await
    }

    /// Opens an h2 stream to the server named in the pipeline.
    pub async fn create_client_stream(
        client: &mut SendRequest<Bytes>,
        host: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> FluxResult<H2Stream> {
        let clean_path = if path.is_empty() { "/" } else { path };

        let mut req_builder = Request::builder()
            .method("POST")
            .uri(clean_path)
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

        Ok(H2Stream::new_client_pending(send_stream, response_fut))
    }

    /// Server-side HTTP/2 handshake establishing an active stream.
    pub async fn server_handshake<S>(stream: S) -> FluxResult<H2Stream>
    where
        S: AsyncStream + 'static,
    {
        let mut server_conn = shared::server_handshake(stream, "http2").await?;

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
            .map_err(|e| FluxError::Protocol {
                protocol: "http2",
                message: format!("failed to build H2 response: {}", e),
            })?;

        let send_stream =
            respond
                .send_response(response, false)
                .map_err(|e| FluxError::Protocol {
                    protocol: "http2",
                    message: format!("failed to send H2 response: {}", e),
                })?;

        let recv_stream = request.into_body();

        shared::spawn_connection_driver(server_conn, None);

        Ok(H2Stream::new(send_stream, recv_stream))
    }
}

/// Connection-level plumbing shared by the raw HTTP/2 tunnel ([`H2Stream`]) and
/// the gRPC tunnel in [`crate::grpc`].
///
/// The two layers must differ *inside* a stream: a gRPC tunnel has to read the
/// response HEADERS and the terminal trailers, a raw h2 tunnel must not. That is
/// why there are two stream types. Everything that establishes the connection
/// and keeps it polled afterwards is identical, and lives here exactly once.
pub(crate) mod shared {
    use super::{AsyncRead, AsyncWrite, Bytes, FluxError, FluxResult, SendRequest};
    use flux_types::AsyncStream;

    /// `SETTINGS_INITIAL_WINDOW_SIZE` advertised to the peer, in bytes.
    pub(crate) const STREAM_WINDOW: u32 = flux_common::copy::RELAY_BUFFER_BYTES as u32;
    #[allow(dead_code)]
    const INITIAL_STREAM_WINDOW: u32 = STREAM_WINDOW;
    /// Largest DATA frame either side will send, negotiated in SETTINGS.
    ///
    /// The relay moves 64 KiB at a time, so a 64 KiB frame is the size that stops one
    /// buffer becoming four frames and four `writev` calls. Anything above the peer's
    /// advertised limit is its own business: SETTINGS is symmetric and h2 respects it.
    const MAX_FRAME_SIZE: u32 = 64 * 1024;
    /// Connection-level window advertised to the peer, in bytes.
    pub(crate) const CONNECTION_WINDOW: u32 = 2 * flux_common::copy::RELAY_BUFFER_BYTES as u32;
    #[allow(dead_code)]
    const INITIAL_CONNECTION_WINDOW: u32 = CONNECTION_WINDOW;
    /// Consecutive non-I/O `accept()` failures tolerated before the driver gives
    /// up on a connection that is otherwise still open.
    const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 8;

    /// Runs the client half of the HTTP/2 handshake and keeps the client
    /// connection polled in the background for the lifetime of the tunnel.
    pub(crate) async fn client_handshake<S>(
        stream: S,
        protocol: &'static str,
    ) -> FluxResult<SendRequest<Bytes>>
    where
        S: AsyncStream + 'static,
    {
        let mut builder = h2::client::Builder::new();
        // The client is the *receiver* of a download, so its advertised window is what
        // limits the server's send rate. Leaving it at h2's 64 KiB default caps a stream at
        // 64 KiB per round trip, which is far below what the link can carry — the server
        // half of this module had these windows from the start and the client half did not.
        builder.initial_window_size(INITIAL_STREAM_WINDOW);
        builder.initial_connection_window_size(INITIAL_CONNECTION_WINDOW);
        builder.max_frame_size(MAX_FRAME_SIZE);
        let (client, connection) =
            builder
                .handshake(stream)
                .await
                .map_err(|e| FluxError::Protocol {
                    protocol,
                    message: format!("H2 handshake failed: {e}"),
                })?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// Runs the server half of the HTTP/2 handshake with this crate's window
    /// configuration and hands the connection back, so the caller can accept and
    /// answer the tunnel's request before the driver takes it over.
    pub(crate) async fn server_handshake<S>(
        stream: S,
        protocol: &'static str,
    ) -> FluxResult<h2::server::Connection<S, Bytes>>
    where
        S: AsyncStream + 'static,
    {
        let mut builder = h2::server::Builder::new();
        // A tunnel carries bulk data in both directions: give it room to run
        // ahead of a WINDOW_UPDATE round trip, but keep the advertised window
        // small enough that an idle peer cannot pin unbounded memory.
        builder.initial_window_size(INITIAL_STREAM_WINDOW);
        builder.initial_connection_window_size(INITIAL_CONNECTION_WINDOW);
        // h2's default DATA frame is 16 KiB, so a 64 KiB relay write left as four
        // frames — four `writev`s for one buffer. The setting is negotiated in SETTINGS,
        // so both ends agree and a peer that does not support it simply keeps its own.
        builder.max_frame_size(MAX_FRAME_SIZE);
        builder
            .handshake(stream)
            .await
            .map_err(|e| FluxError::Protocol {
                protocol,
                message: format!("server H2 handshake failed: {e}"),
            })
    }

    /// Keeps an HTTP/2 server connection polled for the lifetime of the tunnel,
    /// so the library can flush what the stream writes. Extra streams are
    /// refused one by one (an endpoint carries exactly one tunnel stream)
    /// rather than by killing the socket.
    ///
    /// Only I/O-level failures are fatal. A stream-level or protocol-level error
    /// concerns the offending stream, not the connection: tearing the whole
    /// connection down there reset the underlying TCP socket, so a peer saw
    /// `ECONNRESET` instead of `RST_STREAM`/`GOAWAY` (h2spec 3.4/1, 5.1/9, 7/2).
    ///
    /// `linger` bounds how long a *rejected* request keeps the connection open
    /// so its refusal actually reaches the peer; `None` drives it until the peer
    /// goes away.
    pub(crate) fn spawn_connection_driver<T>(
        mut connection: h2::server::Connection<T, Bytes>,
        linger: Option<std::time::Duration>,
    ) where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            // A non-IO error is per-stream, but a *persistent* one would spin
            // this loop forever (accept() returning instantly with the same
            // error), so give up after a short run of consecutive failures.
            let mut consecutive_errors = 0u32;
            let run = async {
                while let Some(result) = connection.accept().await {
                    match result {
                        Ok((_request, mut respond)) => {
                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                        }
                        Err(e) if e.is_io() => break,
                        Err(_) => {
                            consecutive_errors += 1;
                            if consecutive_errors > MAX_CONSECUTIVE_ACCEPT_ERRORS {
                                break;
                            }
                        }
                    }
                }
            };
            match linger {
                Some(linger) => {
                    let _ = tokio::time::timeout(linger, run).await;
                }
                None => run.await,
            }
        });
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

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Builds a client/server H2 tunnel pair over an in-memory duplex.
    async fn pair() -> (H2Stream, H2Stream) {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move { H2Transport::server_handshake(server_io).await });
        let client = H2Transport::client_handshake(
            client_io,
            "example.com",
            "/tunnel",
            &std::collections::HashMap::new(),
        )
        .await
        .expect("client handshake");
        let server = server.await.expect("join").expect("server handshake");
        (client, server)
    }

    /// The tunnel must survive payloads spanning many HTTP/2 DATA frames,
    /// byte-for-byte, in both directions. A frame-boundary copy bug would corrupt
    /// exactly here and nowhere in a small test.
    #[tokio::test]
    async fn multi_frame_payload_is_byte_exact_both_ways() {
        let (mut client, mut server) = pair().await;

        let up: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();
        let expected = up.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&up).await.expect("client write");
            client.flush().await.expect("client flush");
            client
        });

        let mut got = Vec::new();
        let mut buf = vec![0u8; 8192];
        while got.len() < expected.len() {
            let n = server.read(&mut buf).await.expect("server read");
            assert_ne!(n, 0, "server saw EOF after {} bytes", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, expected, "uplink corrupted at frame boundaries");

        let mut client = writer.await.expect("join");
        let down: Vec<u8> = (0..200 * 1024).map(|i| (i % 239) as u8).collect();
        let expected = down.clone();
        tokio::spawn(async move {
            server.write_all(&down).await.expect("server write");
            let _ = server.flush().await;
            // Hold the stream briefly: dropping an H2 response stream sends
            // RST_STREAM, which can overtake the tail of the data and make the
            // peer see CANCEL instead of the payload.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });

        let mut got = Vec::new();
        while got.len() < expected.len() {
            let n = client.read(&mut buf).await.expect("client read");
            assert_ne!(n, 0, "client saw EOF after {} bytes", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, expected, "downlink corrupted at frame boundaries");
    }

    /// Whatever a peer sends, the handshake must fail with an error, in bounded
    /// time — never hang and never panic.
    #[tokio::test]
    async fn garbage_before_the_preface_fails_cleanly() {
        let cases: Vec<Vec<u8>> = vec![
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            vec![0x00; 64],
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\xff\xff\xff\xff\x00\x00\x00\x00\x00".to_vec(),
        ];
        for payload in cases {
            let label = payload.clone();
            let (client_io, mut peer) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let _ = peer.write_all(&payload).await;
                let _ = peer.shutdown().await;
            });
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                H2Transport::server_handshake(client_io),
            )
            .await
            .expect("handshake must not hang on garbage input");
            assert!(res.is_err(), "server accepted a garbage preface: {label:?}");
        }
    }

    /// A client that vanishes right after the preface must produce an error, not
    /// a stream the caller can wait on forever.
    #[tokio::test]
    async fn a_peer_that_vanishes_after_the_preface_fails_cleanly() {
        let (client_io, mut peer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
            let _ = peer.shutdown().await;
        });
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            H2Transport::server_handshake(client_io),
        )
        .await
        .expect("handshake must not hang");
        assert!(
            res.is_err(),
            "server accepted a stream from a vanished peer"
        );
    }
}
