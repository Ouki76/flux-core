use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentationConfig {
    pub enabled: bool,
    #[serde(default = "default_length_min")]
    pub length_min: usize,
    #[serde(default = "default_length_max")]
    pub length_max: usize,
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
}

fn default_length_min() -> usize {
    1
}
fn default_length_max() -> usize {
    3
}
fn default_interval_ms() -> u64 {
    10
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            length_min: 1,
            length_max: 3,
            interval_ms: 10,
        }
    }
}

pub struct FragmentedStream<S> {
    inner: S,
    config: FragmentationConfig,
    header_checked: bool,
    direct_mode: bool,
    // Asynchronous fragment queue
    pending_chunks: Vec<Vec<u8>>,
    current_chunk_idx: usize,
    chunk_write_pos: usize,
    sleep_fut: Option<Pin<Box<tokio::time::Sleep>>>,
    plain_len: usize,
}

impl<S> FragmentedStream<S> {
    pub fn new(inner: S, config: FragmentationConfig) -> Self {
        let direct_mode = !config.enabled;
        Self {
            inner,
            config,
            header_checked: false,
            direct_mode,
            pending_chunks: Vec::new(),
            current_chunk_idx: 0,
            chunk_write_pos: 0,
            sleep_fut: None,
            plain_len: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Direct mode pass-through
        if this.direct_mode || buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        loop {
            // 1. Flush any pending fragments
            while this.current_chunk_idx < this.pending_chunks.len() {
                // Check micro-delay timer between fragments
                if let Some(ref mut sleep) = this.sleep_fut {
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            this.sleep_fut = None;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let idx = this.current_chunk_idx;
                let chunk_len = this.pending_chunks[idx].len();
                while this.chunk_write_pos < chunk_len {
                    let pos = this.chunk_write_pos;
                    let n = match Pin::new(&mut this.inner)
                        .poll_write(cx, &this.pending_chunks[idx][pos..])
                    {
                        Poll::Ready(Ok(n)) => n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write TLS fragmented packet",
                        )));
                    }
                    this.chunk_write_pos += n;
                }

                // Flush after each fragment
                match Pin::new(&mut this.inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }

                this.current_chunk_idx += 1;
                this.chunk_write_pos = 0;

                if this.current_chunk_idx < this.pending_chunks.len() && this.config.interval_ms > 0
                {
                    let mut sleep = Box::pin(tokio::time::sleep(Duration::from_millis(
                        this.config.interval_ms,
                    )));
                    // Poll once to register the waker with Tokio timer driver
                    let _ = sleep.as_mut().poll(cx);
                    this.sleep_fut = Some(sleep);
                    return Poll::Pending;
                }
            }

            // If all fragments written, return success for the full packet
            if !this.pending_chunks.is_empty() {
                let n = this.plain_len;
                this.pending_chunks.clear();
                this.current_chunk_idx = 0;
                this.chunk_write_pos = 0;
                this.plain_len = 0;
                this.direct_mode = true;
                return Poll::Ready(Ok(n));
            }

            // 2. Check initial packet for TLS ClientHello (0x16, 0x03)
            if !this.header_checked {
                this.header_checked = true;
                if buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
                    // Fragment TLS ClientHello
                    let min_len = this.config.length_min.max(1);
                    let max_len = this.config.length_max.max(min_len);
                    let split_pos = (min_len + (rand::random::<usize>() % (max_len - min_len + 1)))
                        .min(buf.len() - 1);

                    let frag1 = buf[..split_pos].to_vec();
                    let frag2 = buf[split_pos..].to_vec();

                    this.pending_chunks = vec![frag1, frag2];
                    this.current_chunk_idx = 0;
                    this.chunk_write_pos = 0;
                    this.plain_len = buf.len();

                    // Loop immediately to flush the first fragment without stalling
                    continue;
                } else {
                    this.direct_mode = true;
                }
            }

            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tls_fragmentation_stream() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let config = FragmentationConfig {
            enabled: true,
            length_min: 2,
            length_max: 2,
            interval_ms: 5,
        };

        let mut stream = FragmentedStream::new(client_io, config);

        // Simulated TLS ClientHello: 0x16, 0x03, 0x01, 0x00, 0x10, ...
        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];

        tokio::spawn(async move {
            stream.write_all(&client_hello).await.unwrap();
            stream.flush().await.unwrap();
            stream
                .write_all(b"subsequent direct payload")
                .await
                .unwrap();
        });

        // Read first fragment (length 2)
        let mut f1 = [0u8; 2];
        server_io.read_exact(&mut f1).await.unwrap();
        assert_eq!(&f1, &[0x16, 0x03]);

        // Read remaining fragment
        let mut f2 = [0u8; 8];
        server_io.read_exact(&mut f2).await.unwrap();
        assert_eq!(&f2, &[0x01, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);

        // Read direct subsequent payload
        let mut rest = [0u8; 25];
        server_io.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"subsequent direct payload");
    }
}
