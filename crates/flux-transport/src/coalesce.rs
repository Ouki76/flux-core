//! Fill the caller's buffer from a stream that hands out one unit per call.
//!
//! `rustls` returns at most one TLS record's plaintext per `poll_read` — 16 KiB — and the
//! relay reads with a 64 KiB buffer, so every buffer cost four read/write cycles. That is
//! the same "one framing unit per call" defect found in the WebSocket, Shadowsocks,
//! REALITY and VMess transports, except this one lives inside a dependency we do not
//! control.
//!
//! This adapter is the fix at the boundary instead: keep polling the inner stream while
//! the caller's buffer still has room, and return as soon as the inner stream is Pending
//! *and* something was already delivered.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a stream so that a large read is served from as many inner reads as are
/// immediately available.
#[derive(Debug)]
pub struct CoalesceReader<S> {
    inner: S,
}

impl<S> CoalesceReader<S> {
    /// Wraps `inner`.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Returns the wrapped stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CoalesceReader<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut put = 0usize;
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let before = buf.filled().len();
            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len() - before;
                    if n == 0 {
                        // Inner EOF: hand back whatever we already delivered.
                        return Poll::Ready(Ok(()));
                    }
                    put += n;
                    // Inner stream made progress; try for another unit.
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    return if put > 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(e))
                    };
                }
                // Nothing more right now: bytes already delivered are a successful read.
                Poll::Pending => {
                    return if put > 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CoalesceReader<S> {
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
    use std::io;
    use tokio::io::AsyncReadExt;

    /// Hands out at most `unit` bytes per `poll_read`, like a TLS record.
    struct UnitStream {
        data: Vec<u8>,
        pos: usize,
        unit: usize,
    }

    impl AsyncRead for UnitStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let left = self.data.len() - self.pos;
            if left == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = left.min(self.unit).min(buf.remaining());
            let start = self.pos;
            let chunk = self.data[start..start + n].to_vec();
            buf.put_slice(&chunk);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_large_read_is_served_from_several_inner_reads() {
        let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let inner = UnitStream {
            data: data.clone(),
            pos: 0,
            unit: 16 * 1024,
        };
        let mut stream = CoalesceReader::new(inner);

        let mut got = vec![0u8; 64 * 1024];
        let n = stream.read(&mut got).await.expect("read");
        assert_eq!(
            n,
            64 * 1024,
            "one read must return the whole buffer, not a single 16 KiB unit"
        );
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn a_short_inner_stream_still_ends_cleanly() {
        let data = vec![7u8; 100];
        let inner = UnitStream {
            data: data.clone(),
            pos: 0,
            unit: 16 * 1024,
        };
        let mut stream = CoalesceReader::new(inner);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read to end");
        assert_eq!(out, data);
    }
}
