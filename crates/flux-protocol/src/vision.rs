use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const VISION_FLOW: &str = "xtls-rprx-vision";

pub fn encode_vision_addons() -> Vec<u8> {
    let flow_bytes = VISION_FLOW.as_bytes();
    let mut buf = Vec::with_capacity(2 + flow_bytes.len());
    buf.push(0x0a); // protobuf tag: field 1, wire type 2
    buf.push(flow_bytes.len() as u8);
    buf.extend_from_slice(flow_bytes);
    buf
}

/// Vision client stream:
/// Reads 16-byte server session seed, then parses Vision frames:
/// [command: 2 bytes] + [data_len: 2 bytes LE] + [pad_len: 1 byte] + [data] + [padding].
pub struct VisionStream<S> {
    inner: S,
    seed_read: bool,
    seed_buf: [u8; 16],
    seed_pos: usize,
    direct_read_mode: bool,
    header_buf: [u8; 5],
    header_pos: usize,
    data_rem: usize,
    pad_rem: usize,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            seed_read: false,
            seed_buf: [0u8; 16],
            seed_pos: 0,
            direct_read_mode: false,
            header_buf: [0u8; 5],
            header_pos: 0,
            data_rem: 0,
            pad_rem: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Step 1: Read 16-byte server seed
        while !self.seed_read {
            let pos = self.seed_pos;
            let mut tmp = [0u8; 16];
            let mut tmp_buf = ReadBuf::new(&mut tmp[..16 - pos]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading Vision server seed",
                        )));
                    }
                    self.seed_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                    self.seed_pos += n;
                    if self.seed_pos == 16 {
                        self.seed_read = true;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.direct_read_mode {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        loop {
            // Read payload data
            if self.data_rem > 0 {
                let mut tmp = [0u8; 4096];
                let to_read = self.data_rem.min(tmp.len()).min(buf.remaining());
                if to_read == 0 {
                    return Poll::Ready(Ok(()));
                }

                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while reading Vision payload",
                            )));
                        }
                        buf.put_slice(&tmp[..n]);
                        self.data_rem -= n;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Drain padding
            if self.pad_rem > 0 {
                let mut drain = [0u8; 256];
                let to_drain = self.pad_rem.min(drain.len());
                let mut drain_buf = ReadBuf::new(&mut drain[..to_drain]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut drain_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = drain_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while draining Vision padding",
                            )));
                        }
                        self.pad_rem -= n;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Read 5-byte header: [command: 2] + [data_len: 2 LE] + [pad_len: 1]
            let hpos = self.header_pos;
            if hpos < 5 {
                let mut htmp = [0u8; 5];
                let mut htmp_buf = ReadBuf::new(&mut htmp[..5 - hpos]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut htmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = htmp_buf.filled().len();
                        if n == 0 {
                            if hpos == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF in Vision frame header",
                            )));
                        }
                        self.header_buf[hpos..hpos + n].copy_from_slice(&htmp[..n]);
                        self.header_pos += n;

                        if self.header_pos == 5 {
                            let cmd = u16::from_be_bytes([self.header_buf[0], self.header_buf[1]]);
                            if cmd == 1 {
                                // Direct mode switch
                                self.direct_read_mode = true;
                                self.header_pos = 0;
                                break;
                            }

                            let data_len = u16::from_le_bytes([self.header_buf[2], self.header_buf[3]]) as usize;
                            let pad_len = self.header_buf[4] as usize;

                            self.data_rem = data_len;
                            self.pad_rem = pad_len;
                            self.header_pos = 0;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        if self.direct_read_mode {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
