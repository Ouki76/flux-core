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
    /// Leading bytes of the first write when it was too short to classify as a
    /// TLS record header. Held so the decision is not latched prematurely.
    probe: Vec<u8>,
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
            probe: Vec::new(),
            plain_len: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> FragmentedStream<S> {
    /// Splits `hello` into two fragments according to the configured size range
    /// and queues them for writing.
    ///
    /// `consumed` is how many bytes of the *caller's* buffer this write
    /// accounts for; it differs from `hello.len()` when a stashed probe prefix
    /// is being flushed alongside this buffer. `poll_write` must never report
    /// more bytes consumed than the caller passed.
    fn queue_fragments(&mut self, hello: &[u8], consumed: usize) {
        let min_len = self.config.length_min.max(1);
        let max_len = self.config.length_max.max(min_len);
        let split_pos =
            (min_len + (rand::random::<usize>() % (max_len - min_len + 1))).min(hello.len() - 1);

        self.pending_chunks = vec![hello[..split_pos].to_vec(), hello[split_pos..].to_vec()];
        self.current_chunk_idx = 0;
        self.chunk_write_pos = 0;
        self.plain_len = consumed;
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

            // 2. Check the initial packet for a TLS ClientHello (0x16, 0x03).
            //
            // The classification must not latch on an incomplete write: a caller
            // that emits the 5-byte record header separately (or writes a very
            // short first chunk) would otherwise disable fragmentation for the
            // whole connection. In that case the leading bytes are stashed and
            // the decision is deferred until the header is complete.
            if !this.header_checked {
                if buf.len() >= 5 {
                    this.header_checked = true;
                    if buf[0] == 0x16 && buf[1] == 0x03 {
                        this.queue_fragments(buf, buf.len());
                        continue;
                    }
                    if this.probe.is_empty() {
                        this.direct_mode = true;
                        return Pin::new(&mut this.inner).poll_write(cx, buf);
                    }
                } else if buf[0] == 0x16 {
                    // Looks like the start of a TLS record but is too short to
                    // tell. Consume it and wait for the remainder.
                    this.probe.extend_from_slice(buf);
                    return Poll::Ready(Ok(buf.len()));
                } else {
                    this.header_checked = true;
                    this.direct_mode = true;
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                }
            }

            if !this.probe.is_empty() && this.header_checked {
                // We had stashed bytes and now know the verdict: emit the probe
                // followed by this buffer through the normal write path.
                let mut all = std::mem::take(&mut this.probe);
                all.extend_from_slice(buf);
                if all.len() >= 2 && all[0] == 0x16 && all[1] == 0x03 {
                    this.queue_fragments(&all, buf.len());
                    continue;
                }
                // Not TLS after all: hand the stashed prefix to the fragment
                // queue as a single pass-through chunk so no bytes are lost.
                this.pending_chunks = vec![all];
                this.current_chunk_idx = 0;
                this.chunk_write_pos = 0;
                this.plain_len = buf.len();
                continue;
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

#[cfg(test)]
mod fragmentation_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn cfg() -> FragmentationConfig {
        FragmentationConfig {
            enabled: true,
            length_min: 4,
            length_max: 8,
            interval_ms: 0,
        }
    }

    async fn run(chunks: &[&[u8]]) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(8192);
        let mut frag = FragmentedStream::new(server, cfg());
        for c in chunks {
            frag.write_all(c).await.unwrap();
        }
        frag.flush().await.unwrap();
        drop(frag);
        let mut out = Vec::new();
        use tokio::io::AsyncReadExt;
        client.read_to_end(&mut out).await.unwrap();
        out
    }

    /// A ClientHello split across two writes must still be fragmented, and every
    /// byte must arrive intact.
    #[tokio::test]
    async fn split_client_hello_is_still_fragmented() {
        // 0x16 0x03 0x01 <len16> then the body, written in two calls.
        let mut hello = vec![0x16u8, 0x03, 0x01, 0x00, 0x20];
        hello.extend((0..0x20).map(|i| i as u8));
        let (a, b) = hello.split_at(3);
        let got = run(&[a, b]).await;
        assert_eq!(
            got, hello,
            "split ClientHello must be forwarded byte-exactly"
        );
    }

    /// A short first write that is not TLS must not switch off fragmentation for
    /// later writes, and must still be forwarded exactly.
    #[tokio::test]
    async fn short_non_tls_prefix_is_forwarded_exactly() {
        let got = run(&[b"ab", b"cdefghij"]).await;
        assert_eq!(got, b"abcdefghij");
    }

    /// Non-TLS traffic passes straight through.
    #[tokio::test]
    async fn plain_text_passes_through() {
        let got = run(&[b"GET / HTTP/1.1\r\n\r\n"]).await;
        assert_eq!(got, b"GET / HTTP/1.1\r\n\r\n");
    }

    /// A full ClientHello in one write is fragmented and preserved.
    #[tokio::test]
    async fn whole_client_hello_is_fragmented() {
        let mut hello = vec![0x16u8, 0x03, 0x01, 0x00, 0x40];
        hello.extend((0..0x40).map(|i| i as u8));
        let got = run(&[&hello]).await;
        assert_eq!(got, hello);
    }
}
