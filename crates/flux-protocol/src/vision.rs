use rand::{Rng, RngCore};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const VISION_FLOW: &str = "xtls-rprx-vision";

pub const VISION_CMD_PADDING: u8 = 0x01;
pub const VISION_CMD_DIRECT: u8 = 0x02;

/// Encodes the protobuf flow addon for VLESS XTLS Vision flow.
/// Wire format: tag 1, wire type 2 (0x0a), length-delimited string.
pub fn encode_vision_addons() -> Vec<u8> {
    let flow_bytes = VISION_FLOW.as_bytes();
    let mut buf = Vec::with_capacity(2 + flow_bytes.len());
    buf.push(0x0a); // protobuf tag: field 1, wire type 2
    buf.push(flow_bytes.len() as u8);
    buf.extend_from_slice(flow_bytes);
    buf
}

/// Vision client stream:
/// Applies DPI camouflage padding to the initial TLS ClientHello packet,
/// then seamlessly switches to zero-copy direct pass-through mode.
pub struct VisionClientStream<S> {
    inner: S,
    direct_mode: bool,
    header_written: bool,
    pending_write_frame: Vec<u8>,
    pending_write_pos: usize,
    pending_plain_len: usize,
    read_direct_mode: bool,
    raw_in_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> VisionClientStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            direct_mode: false,
            header_written: false,
            pending_write_frame: Vec::new(),
            pending_write_pos: 0,
            pending_plain_len: 0,
            read_direct_mode: false,
            raw_in_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. Flush any pending padding frame first
        while this.pending_write_pos < this.pending_write_frame.len() {
            let n = match Pin::new(&mut this.inner)
                .poll_write(cx, &this.pending_write_frame[this.pending_write_pos..])
            {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.pending_write_pos += n;
            if this.pending_write_pos == this.pending_write_frame.len() {
                let plain_n = this.pending_plain_len;
                this.pending_write_frame.clear();
                this.pending_write_pos = 0;
                this.pending_plain_len = 0;
                this.direct_mode = true;
                return Poll::Ready(Ok(plain_n));
            }
        }

        if this.direct_mode || buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // Check if first packet is TLS ClientHello (0x16, 0x03)
        if !this.header_written {
            this.header_written = true;
            if buf.len() >= 3 && buf[0] == 0x16 && buf[1] == 0x03 {
                // Pad to ~900-1100 bytes to camouflage ClientHello fingerprint against GFW/DPI
                let target_size = rand::thread_rng().gen_range(900..1100);
                let pad_len = if target_size > buf.len() {
                    (target_size - buf.len()).min(255) as u8
                } else {
                    0
                };

                let mut frame = Vec::with_capacity(4 + buf.len() + pad_len as usize);
                frame.push(VISION_CMD_PADDING);
                frame.extend_from_slice(&((buf.len() as u16) + (pad_len as u16)).to_be_bytes());
                frame.push(pad_len);
                frame.extend_from_slice(buf);
                if pad_len > 0 {
                    let mut pad = vec![0u8; pad_len as usize];
                    rand::thread_rng().fill_bytes(&mut pad);
                    frame.extend_from_slice(&pad);
                }

                this.pending_write_frame = frame;
                this.pending_write_pos = 0;
                this.pending_plain_len = buf.len();

                // Attempt to write frame now
                while this.pending_write_pos < this.pending_write_frame.len() {
                    let n = match Pin::new(&mut this.inner)
                        .poll_write(cx, &this.pending_write_frame[this.pending_write_pos..])
                    {
                        Poll::Ready(Ok(n)) => n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    this.pending_write_pos += n;
                    if this.pending_write_pos == this.pending_write_frame.len() {
                        let plain_n = this.pending_plain_len;
                        this.pending_write_frame.clear();
                        this.pending_write_pos = 0;
                        this.pending_plain_len = 0;
                        this.direct_mode = true;
                        return Poll::Ready(Ok(plain_n));
                    }
                }
                return Poll::Pending;
            } else {
                this.direct_mode = true;
            }
        }

        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.pending_write_pos < this.pending_write_frame.len() {
            let n = match Pin::new(&mut this.inner)
                .poll_write(cx, &this.pending_write_frame[this.pending_write_pos..])
            {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.pending_write_pos += n;
            if this.pending_write_pos == this.pending_write_frame.len() {
                this.pending_write_frame.clear();
                this.pending_write_pos = 0;
                this.pending_plain_len = 0;
                this.direct_mode = true;
                break;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain any unpadded data in read_buf first
        if this.read_pos < this.read_buf.len() {
            let available = this.read_buf.len() - this.read_pos;
            let to_read = available.min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_read]);
            this.read_pos += to_read;
            if this.read_pos == this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 2. If already switched to direct mode, drain remaining buffered bytes before reading inner
        if this.read_direct_mode {
            if !this.raw_in_buf.is_empty() {
                let to_copy = this.raw_in_buf.len().min(buf.remaining());
                buf.put_slice(&this.raw_in_buf[..to_copy]);
                this.raw_in_buf.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        loop {
            // Check if raw_in_buf already has enough to parse a frame
            if !this.raw_in_buf.is_empty() {
                if this.raw_in_buf[0] == VISION_CMD_PADDING {
                    if this.raw_in_buf.len() >= 4 {
                        let total_len =
                            u16::from_be_bytes([this.raw_in_buf[1], this.raw_in_buf[2]]) as usize;
                        if this.raw_in_buf.len() >= 4 + total_len {
                            let pad_len = this.raw_in_buf[3] as usize;
                            let payload_len = total_len.saturating_sub(pad_len);
                            let payload = this.raw_in_buf[4..4 + payload_len].to_vec();
                            this.raw_in_buf.drain(..4 + total_len);
                            this.read_buf = payload;
                            this.read_pos = 0;
                            this.read_direct_mode = true; // Switch to direct mode immediately after initial padding frame

                            let available = this.read_buf.len();
                            let to_read = available.min(buf.remaining());
                            buf.put_slice(&this.read_buf[..to_read]);
                            this.read_pos = to_read;
                            if this.read_pos == this.read_buf.len() {
                                this.read_buf.clear();
                                this.read_pos = 0;
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                } else if this.raw_in_buf[0] == VISION_CMD_DIRECT {
                    this.raw_in_buf.drain(..1);
                    this.read_direct_mode = true;
                    if !this.raw_in_buf.is_empty() {
                        let to_copy = this.raw_in_buf.len().min(buf.remaining());
                        buf.put_slice(&this.raw_in_buf[..to_copy]);
                        this.raw_in_buf.drain(..to_copy);
                    }
                    return Poll::Ready(Ok(()));
                } else {
                    this.read_direct_mode = true;
                    let to_copy = this.raw_in_buf.len().min(buf.remaining());
                    buf.put_slice(&this.raw_in_buf[..to_copy]);
                    this.raw_in_buf.drain(..to_copy);
                    return Poll::Ready(Ok(()));
                }
            }

            // Read more data into raw_in_buf
            let mut tmp = [0u8; 4096];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        if !this.raw_in_buf.is_empty() {
                            let to_copy = this.raw_in_buf.len().min(buf.remaining());
                            buf.put_slice(&this.raw_in_buf[..to_copy]);
                            this.raw_in_buf.drain(..to_copy);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    this.raw_in_buf.extend_from_slice(&tmp[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub struct VisionServerStream<S> {
    inner: S,
    read_direct_mode: bool,
    raw_in_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> VisionServerStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_direct_mode: false,
            raw_in_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionServerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain any unpadded data in read_buf first
        if this.read_pos < this.read_buf.len() {
            let available = this.read_buf.len() - this.read_pos;
            let to_read = available.min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_read]);
            this.read_pos += to_read;
            if this.read_pos == this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 2. If already switched to direct mode, drain remaining buffered bytes before reading inner
        if this.read_direct_mode {
            if !this.raw_in_buf.is_empty() {
                let to_copy = this.raw_in_buf.len().min(buf.remaining());
                buf.put_slice(&this.raw_in_buf[..to_copy]);
                this.raw_in_buf.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        loop {
            if !this.raw_in_buf.is_empty() {
                if this.raw_in_buf[0] == VISION_CMD_PADDING {
                    if this.raw_in_buf.len() >= 4 {
                        let total_len =
                            u16::from_be_bytes([this.raw_in_buf[1], this.raw_in_buf[2]]) as usize;
                        if this.raw_in_buf.len() >= 4 + total_len {
                            let pad_len = this.raw_in_buf[3] as usize;
                            let payload_len = total_len.saturating_sub(pad_len);
                            let payload = this.raw_in_buf[4..4 + payload_len].to_vec();
                            this.raw_in_buf.drain(..4 + total_len);
                            this.read_buf = payload;
                            this.read_pos = 0;
                            this.read_direct_mode = true; // Switch to direct mode immediately after initial padding frame

                            let available = this.read_buf.len();
                            let to_read = available.min(buf.remaining());
                            buf.put_slice(&this.read_buf[..to_read]);
                            this.read_pos = to_read;
                            if this.read_pos == this.read_buf.len() {
                                this.read_buf.clear();
                                this.read_pos = 0;
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                } else if this.raw_in_buf[0] == VISION_CMD_DIRECT {
                    this.raw_in_buf.drain(..1);
                    this.read_direct_mode = true;
                    if !this.raw_in_buf.is_empty() {
                        let to_copy = this.raw_in_buf.len().min(buf.remaining());
                        buf.put_slice(&this.raw_in_buf[..to_copy]);
                        this.raw_in_buf.drain(..to_copy);
                    }
                    return Poll::Ready(Ok(()));
                } else {
                    this.read_direct_mode = true;
                    let to_copy = this.raw_in_buf.len().min(buf.remaining());
                    buf.put_slice(&this.raw_in_buf[..to_copy]);
                    this.raw_in_buf.drain(..to_copy);
                    return Poll::Ready(Ok(()));
                }
            }

            let mut tmp = [0u8; 4096];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        if !this.raw_in_buf.is_empty() {
                            let to_copy = this.raw_in_buf.len().min(buf.remaining());
                            buf.put_slice(&this.raw_in_buf[..to_copy]);
                            this.raw_in_buf.drain(..to_copy);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    this.raw_in_buf.extend_from_slice(&tmp[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_encode_vision_addons() {
        let addons = encode_vision_addons();
        assert_eq!(addons[0], 0x0a);
        assert_eq!(addons[1], VISION_FLOW.len() as u8);
        assert_eq!(&addons[2..], VISION_FLOW.as_bytes());
    }

    #[tokio::test]
    async fn test_vision_client_stream_padding() {
        let (client_io, mut server_io) = tokio::io::duplex(2048);
        let mut vision = VisionClientStream::new(client_io);

        // Client sends simulated TLS ClientHello
        let fake_client_hello = vec![0x16, 0x03, 0x03, 0x01, 0x00, 0xAA];
        vision.write_all(&fake_client_hello).await.unwrap();

        // Server reads frame
        let mut frame_buf = vec![0u8; 2048];
        let n = server_io.read(&mut frame_buf).await.unwrap();
        assert!(n >= 4 + fake_client_hello.len());
        // Verify vision padding header
        assert_eq!(frame_buf[0], VISION_CMD_PADDING);
        let pad_len = frame_buf[3] as usize;
        // Verify payload data inside padding frame
        assert_eq!(
            &frame_buf[4..4 + fake_client_hello.len()],
            &fake_client_hello
        );
        assert_eq!(n, 4 + fake_client_hello.len() + pad_len);
    }

    #[tokio::test]
    async fn test_vision_read_partial_and_pipelined_direct_mode() {
        let (mut client_io, server_io) = tokio::io::duplex(2048);
        let mut vision = VisionServerStream::new(server_io);

        // Client sends a vision padding frame with 10 bytes payload: b"0123456789"
        // followed immediately by 10 bytes of pipelined direct TLS data: b"ABCDEFGHIJ"
        let payload = b"0123456789";
        let mut frame = Vec::new();
        frame.push(VISION_CMD_PADDING);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.push(0); // 0 padding
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"ABCDEFGHIJ");

        client_io.write_all(&frame).await.unwrap();

        // 1. Read first 5 bytes into a small 5-byte buffer (partial read of padding payload)
        let mut buf1 = [0u8; 5];
        vision.read_exact(&mut buf1).await.unwrap();
        assert_eq!(&buf1, b"01234");

        // 2. Read next 5 bytes (remainder of padding payload)
        let mut buf2 = [0u8; 5];
        vision.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"56789");

        // 3. Read next 10 bytes (pipelined direct data that arrived with padding frame)
        let mut buf3 = [0u8; 10];
        vision.read_exact(&mut buf3).await.unwrap();
        assert_eq!(&buf3, b"ABCDEFGHIJ");

        // 4. Send additional direct data across established stream
        client_io.write_all(b"STREAM_DIRECT_DATA").await.unwrap();
        let mut buf4 = [0u8; 18];
        vision.read_exact(&mut buf4).await.unwrap();
        assert_eq!(&buf4, b"STREAM_DIRECT_DATA");
    }
}
