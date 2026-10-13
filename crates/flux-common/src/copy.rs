use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An AsyncRead + AsyncWrite stream wrapper that updates atomic counters in real time.
pub struct MeteredStream<S> {
    inner: S,
    read_bytes: Arc<AtomicU64>,
    written_bytes: Arc<AtomicU64>,
    global_read: Option<Arc<AtomicU64>>,
    global_written: Option<Arc<AtomicU64>>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, read_bytes: Arc<AtomicU64>, written_bytes: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            read_bytes,
            written_bytes,
            global_read: None,
            global_written: None,
        }
    }

    pub fn with_global(
        mut self,
        global_read: Arc<AtomicU64>,
        global_written: Arc<AtomicU64>,
    ) -> Self {
        self.global_read = Some(global_read);
        self.global_written = Some(global_written);
        self
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len().saturating_sub(before);
            if n > 0 {
                self.read_bytes.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(ref g) = self.global_read {
                    g.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res
            && *n > 0
        {
            self.written_bytes.fetch_add(*n as u64, Ordering::Relaxed);
            if let Some(ref g) = self.global_written {
                g.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bidirectional copy between two streams leveraging non-deadlocking simultaneous read/write polling.
pub async fn copy_bidirectional<A, B>(mut a: A, mut b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// One-way copy reading into a pooled 16KB buffer (reused across connections).
/// On EOF or error the write half is shut down to propagate half-close semantics.
async fn copy_one_way_pooled<R, W>(
    r: &mut R,
    w: &mut W,
    pool: &'static crate::buffer::BufferPool,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut guard = pool.acquire_guard();
    let mut total = 0u64;
    loop {
        let n = r.read(&mut guard[..]).await?;
        if n == 0 {
            break;
        }
        w.write_all(&guard[..n]).await?;
        total += n as u64;
    }
    let _ = w.shutdown().await;
    Ok(total)
}

/// Bidirectional stream copy between two mutable stream references without mutual
/// deadlock, using pooled buffers instead of per-connection heap allocations.
pub async fn copy_bidirectional_pooled<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let pool = crate::buffer::BufferPool::default_pool();
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let f1 = copy_one_way_pooled(&mut ar, &mut bw, pool);
    let f2 = copy_one_way_pooled(&mut br, &mut aw, pool);
    tokio::try_join!(f1, f2)
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
    async fn test_copy_bidirectional_pooled() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let (mut proxy_in, mut proxy_out) = tokio::io::duplex(1024);

        let t1 = tokio::spawn(async move {
            client.write_all(b"hello pooled").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut client, &mut buf)
                .await
                .unwrap();
            assert_eq!(buf, b"pooled reply");
        });

        let t2 = tokio::spawn(async move {
            let mut buf = vec![0u8; 12];
            tokio::io::AsyncReadExt::read_exact(&mut proxy_out, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf, b"hello pooled");
            proxy_out.write_all(b"pooled reply").await.unwrap();
            proxy_out.shutdown().await.unwrap();
        });

        let (up, down) = copy_bidirectional_pooled(&mut server, &mut proxy_in)
            .await
            .unwrap();
        assert_eq!(up, 12);
        assert_eq!(down, 12);

        t1.await.unwrap();
        t2.await.unwrap();
    }

    #[tokio::test]
    async fn test_copy_bidirectional() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (proxy_in, mut proxy_out) = tokio::io::duplex(1024);

        let t1 = tokio::spawn(async move {
            client.write_all(b"hello from client").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut client, &mut buf)
                .await
                .unwrap();
            assert_eq!(buf, b"reply from server");
        });

        let t2 = tokio::spawn(async move {
            let mut buf = vec![0u8; 17];
            tokio::io::AsyncReadExt::read_exact(&mut proxy_out, &mut buf)
                .await
                .unwrap();
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
