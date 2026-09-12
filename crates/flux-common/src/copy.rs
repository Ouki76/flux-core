use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const DEFAULT_COPY_BUFFER_SIZE: usize = 256 * 1024; // 256 KB saturated buffer

/// Bidirectional copy between two streams using lock-free Tokio copy with 256KB buffers.
pub async fn copy_bidirectional<A, B>(mut a: A, mut b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, DEFAULT_COPY_BUFFER_SIZE, DEFAULT_COPY_BUFFER_SIZE).await
}

/// A stream that prepends a prefix byte buffer before delegating to the inner stream.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let available = self.prefix.len() - self.prefix_pos;
            let to_write = available.min(buf.remaining());
            buf.put_slice(&self.prefix[self.prefix_pos..self.prefix_pos + to_write]);
            self.prefix_pos += to_write;
            if self.prefix_pos == self.prefix.len() {
                self.prefix.clear();
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_copy_bidirectional() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (proxy_in, mut proxy_out) = tokio::io::duplex(1024);

        let t1 = tokio::spawn(async move {
            client.write_all(b"hello from client").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut client, &mut buf).await.unwrap();
            assert_eq!(buf, b"reply from server");
        });

        let t2 = tokio::spawn(async move {
            let mut buf = vec![0u8; 17];
            tokio::io::AsyncReadExt::read_exact(&mut proxy_out, &mut buf).await.unwrap();
            assert_eq!(&buf, b"hello from client");
            proxy_out.write_all(b"reply from server").await.unwrap();
            proxy_out.shutdown().await.unwrap();
        });

        let (up, down) = copy_bidirectional(server, proxy_in).await.unwrap();
        assert_eq!(up, 17);
        assert_eq!(down, 17);

        t1.await.unwrap();
        t2.await.unwrap();
    }
}
