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
    async fn test_copy_bidirectional_round_trip() {
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

        let (up, down) = copy_bidirectional(&mut server, &mut proxy_in)
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

/// Bidirectional copy with large buffers and **no `tokio::io::split`**.
///
/// The generic path used to be `tokio::io::copy_bidirectional`, whose internal
/// buffers are 8 KiB per direction. Every protocol tunnel (VLESS, Trojan,
/// Shadowsocks, VMess, TLS, WebSocket, …) wraps the socket, so the in-kernel
/// `splice` path never applies to them and they all paid the 8 KiB syscall size —
/// measured as roughly half of sing-box's throughput on the same protocol.
///
/// This drives both directions from one task with 64 KiB buffers: no split (which
/// in tokio is a mutex around the whole stream taken on every poll), no per-chunk
/// allocation, and a quarter of the syscalls.
pub async fn copy_bidirectional_buffered<A, B>(
    a: &mut A,
    b: &mut B,
    buf_size: usize,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::io::ReadBuf;

    // Direction 1: a -> b. Direction 2: b -> a. Each keeps its own buffer and a
    // pending range when the peer accepted only part of a write.
    let mut buf_ab = vec![0u8; buf_size];
    let mut buf_ba = vec![0u8; buf_size];
    let mut pend_ab: Option<(usize, usize)> = None; // (start, end) in buf_ab
    let mut pend_ba: Option<(usize, usize)> = None;
    let mut up = 0u64;
    let mut down = 0u64;
    let mut eof_ab = false;
    let mut eof_ba = false;

    let total = std::future::poll_fn(|cx| {
        let mut progressed = false;

        // 1. Flush a pending a->b write.
        if let Some((start, end)) = pend_ab {
            match Pin::new(&mut *b).poll_write(cx, &buf_ab[start..end]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(zero_write())),
                Poll::Ready(Ok(n)) => {
                    up += n as u64;
                    progressed = true;
                    if start + n >= end {
                        pend_ab = None;
                    } else {
                        pend_ab = Some((start + n, end));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // 2. Flush a pending b->a write.
        if let Some((start, end)) = pend_ba {
            match Pin::new(&mut *a).poll_write(cx, &buf_ba[start..end]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(zero_write())),
                Poll::Ready(Ok(n)) => {
                    down += n as u64;
                    progressed = true;
                    if start + n >= end {
                        pend_ba = None;
                    } else {
                        pend_ba = Some((start + n, end));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // 3. Read more from a (only when nothing is outstanding for a->b).
        if pend_ab.is_none() && !eof_ab {
            let mut rb = ReadBuf::new(&mut buf_ab);
            match Pin::new(&mut *a).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        eof_ab = true;
                        // Propagate the half-close.
                        match Pin::new(&mut *b).poll_shutdown(cx) {
                            Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {}
                            Poll::Pending => {}
                        }
                    } else {
                        pend_ab = Some((0, n));
                        progressed = true;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // 4. Read more from b.
        if pend_ba.is_none() && !eof_ba {
            let mut rb = ReadBuf::new(&mut buf_ba);
            match Pin::new(&mut *b).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        eof_ba = true;
                        match Pin::new(&mut *a).poll_shutdown(cx) {
                            Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {}
                            Poll::Pending => {}
                        }
                    } else {
                        pend_ba = Some((0, n));
                        progressed = true;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        if eof_ab && eof_ba && pend_ab.is_none() && pend_ba.is_none() {
            return Poll::Ready(Ok((up, down)));
        }
        if progressed {
            // Data moved: poll again immediately rather than waiting for a wakeup.
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await?;

    Ok(total)
}

fn zero_write() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WriteZero,
        "the destination accepted zero bytes",
    )
}

#[cfg(test)]
mod buffered_copy_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Byte-exact in both directions, across many buffers worth of data.
    #[tokio::test]
    async fn copies_both_directions_exactly() {
        let (mut a_client, mut a_proxy) = tokio::io::duplex(64 * 1024);
        let (mut b_proxy, mut b_server) = tokio::io::duplex(64 * 1024);

        let payload_up: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let payload_down: Vec<u8> = (0..200_000u32).map(|i| (i % 239) as u8).collect();
        let up_expected = payload_up.clone();
        let down_expected = payload_down.clone();

        let writer = tokio::spawn(async move {
            a_client.write_all(&payload_up).await.unwrap();
            a_client.shutdown().await.unwrap();
            let mut got = Vec::new();
            a_client.read_to_end(&mut got).await.unwrap();
            got
        });
        let server = tokio::spawn(async move {
            let mut got = Vec::new();
            // Read to EOF, then answer — the half-close must have reached us.
            b_server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, up_expected, "uplink corrupted");
            b_server.write_all(&payload_down).await.unwrap();
            b_server.shutdown().await.unwrap();
        });

        let (up, down) = copy_bidirectional_buffered(&mut a_proxy, &mut b_proxy, 64 * 1024)
            .await
            .expect("copy");
        assert_eq!(up, 300_000);
        assert_eq!(down, 200_000);

        let back = writer.await.unwrap();
        assert_eq!(back, down_expected, "downlink corrupted");
        server.await.unwrap();
    }

    /// A peer that closes immediately must end the copy, not spin.
    #[tokio::test]
    async fn an_immediate_close_finishes() {
        let (a, mut a_proxy) = tokio::io::duplex(4096);
        let (mut b_proxy, b) = tokio::io::duplex(4096);
        drop(a);
        drop(b);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            copy_bidirectional_buffered(&mut a_proxy, &mut b_proxy, 4096),
        )
        .await
        .expect("must not hang");
        assert!(res.is_ok());
    }
}
