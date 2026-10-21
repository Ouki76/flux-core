use crate::h2::{H2Stream, H2Transport};
use bytes::BytesMut;
use flux_types::{AsyncStream, FluxResult};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const GRPC_HEADER_LEN: usize = 5;

/// Maximum accepted length for a single length-prefixed gRPC message.
///
/// The length is four raw wire bytes, so a peer may legally claim up to
/// `u32::MAX`; without a cap a single 5-byte header makes the proxy buffer
/// 4 GiB before it can emit anything (unauthenticated remote memory DoS).
/// 16 MiB is far above any legitimate proxy frame (the tunnel streams in
/// `read_buf`-sized chunks) and keeps the worst case bounded.
pub const MAX_GRPC_MESSAGE: usize = 16 * 1024 * 1024;

/// gRPC stream wrapper applying RFC standard gRPC frame encapsulation:
/// [Compressed-Flag (1 byte: 0x00) + Message-Length (4 bytes BE) + Message-Data]
pub struct GrpcStream {
    inner: H2Stream,
    read_buf: BytesMut,
    unread_payload: bytes::Bytes,
    unread_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    pending_chunk_len: usize,
}

impl GrpcStream {
    pub fn new(inner: H2Stream) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(16384),
            unread_payload: bytes::Bytes::new(),
            unread_pos: 0,
            write_buf: Vec::with_capacity(16384 + GRPC_HEADER_LEN),
            write_pos: 0,
            pending_chunk_len: 0,
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            // Drain any pending unread payload from previous frame without heap reallocation
            if this.unread_pos < this.unread_payload.len() {
                let avail = this.unread_payload.len() - this.unread_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.unread_payload[this.unread_pos..this.unread_pos + to_copy]);
                this.unread_pos += to_copy;
                if this.unread_pos == this.unread_payload.len() {
                    this.unread_payload = bytes::Bytes::new();
                    this.unread_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Check if we have a full gRPC message framed in read_buf
            if this.read_buf.len() >= GRPC_HEADER_LEN {
                let msg_len = u32::from_be_bytes([
                    this.read_buf[1],
                    this.read_buf[2],
                    this.read_buf[3],
                    this.read_buf[4],
                ]) as usize;

                if msg_len > MAX_GRPC_MESSAGE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "gRPC message length {msg_len} exceeds the {MAX_GRPC_MESSAGE}-byte limit"
                        ),
                    )));
                }

                let total_frame_len = GRPC_HEADER_LEN + msg_len;
                if this.read_buf.len() >= total_frame_len {
                    // Extract payload
                    let _hdr = this.read_buf.split_to(GRPC_HEADER_LEN);
                    let mut body = this.read_buf.split_to(msg_len);

                    // Check for Gun Protobuf field 1 tag (0x0A)
                    let payload = if !body.is_empty() && body[0] == 0x0A {
                        let _tag = body.split_to(1);
                        let mut val = 0u64;
                        let mut shift = 0;
                        let mut consumed = 0;
                        let mut overflow = false;
                        let mut terminated = false;
                        for &b in body.as_ref() {
                            consumed += 1;
                            if shift >= 64 {
                                overflow = true;
                                break;
                            }
                            val |= ((b & 0x7f) as u64) << shift;
                            if b & 0x80 == 0 {
                                terminated = true;
                                break;
                            }
                            shift += 7;
                        }
                        if overflow || !terminated || consumed > 10 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "malformed or unterminated protobuf varint length",
                            )));
                        }
                        let _varint = body.split_to(consumed);
                        if val as usize > body.len() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "gRPC protobuf length {} exceeds message body {}",
                                    val,
                                    body.len()
                                ),
                            )));
                        }
                        body.split_to(val as usize).freeze()
                    } else {
                        body.freeze()
                    };

                    if payload.is_empty() {
                        // An empty gRPC message carries no tunnel bytes. Returning
                        // `Ready(Ok(()))` with an empty `ReadBuf` would be read as
                        // end-of-stream by every caller, tearing the tunnel down,
                        // so keep consuming frames instead.
                        continue;
                    }

                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);

                    if to_copy < payload.len() {
                        this.unread_payload = payload;
                        this.unread_pos = to_copy;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            // Read more data from inner H2 stream
            let mut tmp = [0u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        if !this.read_buf.is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF in gRPC frame",
                            )));
                        }
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.read_buf.extend_from_slice(&tmp[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // 1. Flush any pending buffered frame in progress
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write buffered gRPC frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let chunk_len = this.pending_chunk_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                return Poll::Ready(Ok(chunk_len));
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 2. Prepare next Gun/gRPC frame with Protobuf Hunk encoding
        let chunk_size = buf.len().min(16384);
        let mut varint = [0u8; 10];
        let mut vn = 0;
        let mut val = chunk_size as u64;
        while val >= 0x80 {
            varint[vn] = (val as u8 & 0x7f) | 0x80;
            val >>= 7;
            vn += 1;
        }
        varint[vn] = val as u8;
        vn += 1;
        let varint_bytes = &varint[..vn];

        let proto_len = 1 + varint_bytes.len() + chunk_size;
        // Reuse the pre-reserved allocation instead of replacing it: assigning a
        // fresh `Vec` threw away the 16 KiB capacity reserved at construction and
        // reallocated on every write.
        this.write_buf.clear();
        this.write_buf.reserve(GRPC_HEADER_LEN + proto_len);
        this.write_buf.push(0x00); // Uncompressed
        this.write_buf
            .extend_from_slice(&(proto_len as u32).to_be_bytes());
        this.write_buf.push(0x0A); // Protobuf field 1 length-delimited
        this.write_buf.extend_from_slice(varint_bytes);
        this.write_buf.extend_from_slice(&buf[..chunk_size]);
        this.write_pos = 0;
        this.pending_chunk_len = chunk_size;

        // 3. Write out as much as possible
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write gRPC frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let chunk_len = this.pending_chunk_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                return Poll::Ready(Ok(chunk_len));
            }
        }

        Poll::Pending
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to flush buffered gRPC frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_chunk_len = 0;
                break;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.send_grpc_trailers();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct GrpcTransport;

impl GrpcTransport {
    /// Client-side gRPC handshake (Gun / Multi-mode).
    pub async fn client_handshake<S>(
        stream: S,
        host: &str,
        service_name: &str,
        headers: &HashMap<String, String>,
    ) -> FluxResult<GrpcStream>
    where
        S: AsyncStream + 'static,
    {
        let mut custom_headers = headers.clone();
        custom_headers.insert("Content-Type".into(), "application/grpc".into());
        custom_headers.insert("TE".into(), "trailers".into());

        let path = format!("/{}/Tun", service_name.trim_matches('/'));
        let h2_stream = H2Transport::client_handshake(stream, host, &path, &custom_headers).await?;
        Ok(GrpcStream::new(h2_stream))
    }

    /// Server-side gRPC handshake.
    pub async fn server_handshake<S>(stream: S) -> FluxResult<GrpcStream>
    where
        S: AsyncStream + 'static,
    {
        let h2_stream = H2Transport::server_handshake(stream).await?;
        Ok(GrpcStream::new(h2_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_grpc_stream_encapsulation() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let srv = tokio::spawn(async move {
            let mut srv_stream = GrpcTransport::server_handshake(server_io).await.unwrap();
            let mut buf = [0u8; 13];
            srv_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"grpc request!");
            srv_stream.write_all(b"grpc reply!!").await.unwrap();
            srv_stream.flush().await.unwrap();
            let _ = done_rx.await;
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            cli_stream.write_all(b"grpc request!").await.unwrap();
            cli_stream.flush().await.unwrap();

            let mut buf = [0u8; 12];
            cli_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"grpc reply!!");
            let _ = done_tx.send(());
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_grpc_stream_unexpected_eof() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let srv = tokio::spawn(async move {
            let mut srv_h2 = crate::h2::H2Transport::server_handshake(server_io)
                .await
                .unwrap();
            // Send partial gRPC frame: 5-byte header indicating 20 bytes of payload, but only send 4 bytes
            let mut partial_frame = vec![0x00, 0x00, 0x00, 0x00, 20];
            partial_frame.extend_from_slice(b"abcd");
            srv_h2.write_all(&partial_frame).await.unwrap();
            srv_h2.flush().await.unwrap();
            // Drop srv_h2 so inner H2 stream hits EOF
            srv_h2.shutdown().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            let mut buf = vec![0u8; 64];
            let err = cli_stream.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_grpc_stream_backpressure_and_partial_writes() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let data_len = 1_500_000; // 1.5 MB, larger than H2 initial window (1MB)
        let original_data: Vec<u8> = (0..data_len).map(|i| (i % 251) as u8).collect();
        let expected_data = original_data.clone();

        let srv = tokio::spawn(async move {
            let mut srv_stream = GrpcTransport::server_handshake(server_io).await.unwrap();
            let mut received = Vec::with_capacity(data_len);
            let mut buf = vec![0u8; 8192];
            while received.len() < data_len {
                let n = srv_stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(received.len(), expected_data.len());
            assert_eq!(received, expected_data);
            let _ = done_tx.send(());
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            cli_stream.write_all(&original_data).await.unwrap();
            cli_stream.flush().await.unwrap();
            let _ = done_rx.await;
        });

        cli.await.unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_grpc_unterminated_protobuf_varint_rejected() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let srv = tokio::spawn(async move {
            let mut srv_h2 = crate::h2::H2Transport::server_handshake(server_io)
                .await
                .unwrap();
            // Send gRPC frame: 5-byte header indicating 3 bytes of payload
            // Payload is 0x0A (field 1 tag) followed by unterminated varint [0x80, 0x80]
            let frame = vec![0x00, 0x00, 0x00, 0x00, 3, 0x0A, 0x80, 0x80];
            srv_h2.write_all(&frame).await.unwrap();
            srv_h2.flush().await.unwrap();
            srv_h2.shutdown().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = GrpcTransport::client_handshake(
                client_io,
                "grpc.example.com",
                "MyService",
                &HashMap::new(),
            )
            .await
            .unwrap();

            let mut buf = vec![0u8; 64];
            let err = cli_stream.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}
