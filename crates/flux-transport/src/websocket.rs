use base64::Engine;
use flux_types::{AsyncStream, FluxError, FluxResult};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Performs client-side RFC 6455 WebSocket handshake over an underlying stream.
pub async fn client_handshake<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> FluxResult<WebSocketStream<S>>
where
    S: AsyncStream + 'static,
{
    let nonce: [u8; 16] = rand::random();
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);

    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
        if path.is_empty() { "/" } else { path },
        host,
        key
    );

    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("upgrade")
            && !k.eq_ignore_ascii_case("connection")
            && !k.eq_ignore_ascii_case("sec-websocket-key")
            && !k.eq_ignore_ascii_case("sec-websocket-version")
        {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // Read response headers until \r\n\r\n
    let mut resp_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while resp_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: "EOF while reading websocket handshake response".into(),
            });
        }
        resp_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "websocket",
        message: "response header too large or missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&resp_buf[..h_end]);
    let first_line = header_str.lines().next().unwrap_or("");
    if !first_line.contains("101") {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("server rejected websocket upgrade: {}", first_line),
        });
    }

    // Verify Sec-WebSocket-Accept
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID);
    let expected_accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    let mut accept_ok = false;
    for line in header_str.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("sec-websocket-accept")
            && v.trim() == expected_accept
        {
            accept_ok = true;
            break;
        }
    }

    if !accept_ok {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: "invalid Sec-WebSocket-Accept header from server".into(),
        });
    }

    let excess_data = resp_buf[h_end..].to_vec();

    Ok(WebSocketStream::new(stream, excess_data, true))
}

/// Performs server-side RFC 6455 WebSocket handshake.
pub async fn server_handshake<S>(
    mut stream: S,
    expected_path: Option<&str>,
) -> FluxResult<WebSocketStream<S>>
where
    S: AsyncStream + 'static,
{
    let mut req_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while req_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: "EOF while reading client websocket handshake".into(),
            });
        }
        req_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "websocket",
        message: "request header too large or missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&req_buf[..h_end]);
    let mut lines = header_str.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if method != "GET" {
        return Err(FluxError::Protocol {
            protocol: "websocket",
            message: format!("invalid websocket method: {}", method),
        });
    }

    if let Some(exp) = expected_path {
        let actual_path = path.split('?').next().unwrap_or(path);
        if actual_path != exp {
            return Err(FluxError::Protocol {
                protocol: "websocket",
                message: format!(
                    "websocket path mismatch: expected '{}', got '{}'",
                    exp, actual_path
                ),
            });
        }
    }

    let mut client_key = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("sec-websocket-key")
        {
            client_key = Some(v.trim().to_string());
            break;
        }
    }

    let key = client_key.ok_or_else(|| FluxError::Protocol {
        protocol: "websocket",
        message: "missing Sec-WebSocket-Key in client request".into(),
    })?;

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID);
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept
    );

    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    let excess_data = req_buf[h_end..].to_vec();
    Ok(WebSocketStream::new(stream, excess_data, false))
}

enum ReadState {
    Header,
    Payload,
}

pub struct WebSocketStream<S> {
    inner: S,
    is_client: bool,
    read_state: ReadState,
    header_buf: [u8; 14],
    header_pos: usize,
    header_len: usize,
    current_opcode: u8,
    payload_rem: usize,
    mask_key: Option<[u8; 4]>,
    mask_idx: usize,
    buffered_excess: Vec<u8>,
    buffered_pos: usize,
    // Ping/Pong control frame handling
    ping_payload: Vec<u8>,
    pending_pong: Vec<u8>,
    pending_pong_pos: usize,
    // Robust writer state machine
    write_buf: Vec<u8>,
    write_pos: usize,
    pending_chunk_len: usize,
}

fn build_pong_frame(payload: &[u8], is_client: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.push(0x8A); // FIN=1, Opcode=0x0A (Pong)
    let len = payload.len().min(125) as u8;
    if is_client {
        frame.push(0x80 | len);
        let mask: [u8; 4] = rand::random();
        frame.extend_from_slice(&mask);
        for (i, &b) in payload[..len as usize].iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
    } else {
        frame.push(len);
        frame.extend_from_slice(&payload[..len as usize]);
    }
    frame
}

impl<S> WebSocketStream<S> {
    pub fn new(inner: S, excess: Vec<u8>, is_client: bool) -> Self {
        Self {
            inner,
            is_client,
            read_state: ReadState::Header,
            header_buf: [0u8; 14],
            header_pos: 0,
            header_len: 2,
            current_opcode: 0x02, // Binary
            payload_rem: 0,
            mask_key: None,
            mask_idx: 0,
            buffered_excess: excess,
            buffered_pos: 0,
            ping_payload: Vec::new(),
            pending_pong: Vec::new(),
            pending_pong_pos: 0,
            write_buf: Vec::with_capacity(4096),
            write_pos: 0,
            pending_chunk_len: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            // Flush any pending Pong response before reading
            while this.pending_pong_pos < this.pending_pong.len() {
                match Pin::new(&mut this.inner)
                    .poll_write(cx, &this.pending_pong[this.pending_pong_pos..])
                {
                    Poll::Ready(Ok(n)) if n > 0 => {
                        this.pending_pong_pos += n;
                        if this.pending_pong_pos == this.pending_pong.len() {
                            this.pending_pong.clear();
                            this.pending_pong_pos = 0;
                            let _ = Pin::new(&mut this.inner).poll_flush(cx);
                            break;
                        }
                    }
                    _ => break,
                }
            }

            match this.read_state {
                ReadState::Header => {
                    // Read initial header bytes
                    while this.header_pos < this.header_len {
                        let needed = this.header_len - this.header_pos;
                        if this.buffered_pos < this.buffered_excess.len() {
                            let avail = this.buffered_excess.len() - this.buffered_pos;
                            let n = avail.min(needed);
                            this.header_buf[this.header_pos..this.header_pos + n].copy_from_slice(
                                &this.buffered_excess[this.buffered_pos..this.buffered_pos + n],
                            );
                            this.buffered_pos += n;
                            this.header_pos += n;
                        } else {
                            let mut tmp = [0u8; 14];
                            let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = tmp_buf.filled().len();
                                    if n == 0 {
                                        return Poll::Ready(Ok(())); // Clean EOF
                                    }
                                    let pos = this.header_pos;
                                    this.header_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                                    this.header_pos += n;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    }

                    if this.header_len == 2 {
                        let b1 = this.header_buf[1];
                        let masked = (b1 & 0x80) != 0;
                        let basic_len = (b1 & 0x7F) as usize;

                        let mut extra = 0;
                        if basic_len == 126 {
                            extra += 2;
                        } else if basic_len == 127 {
                            extra += 8;
                        }
                        if masked {
                            extra += 4;
                        }

                        this.header_len = 2 + extra;
                        if this.header_len > 2 {
                            continue;
                        }
                    }

                    // Full header read complete
                    let b0 = this.header_buf[0];
                    let opcode = b0 & 0x0F;
                    this.current_opcode = opcode;

                    // Handle Close frame (0x08)
                    if opcode == 0x08 {
                        return Poll::Ready(Ok(())); // Graceful EOF
                    }

                    let b1 = this.header_buf[1];
                    let masked = (b1 & 0x80) != 0;
                    let basic_len = (b1 & 0x7F) as usize;
                    let mut offset = 2;

                    let payload_len = if basic_len == 126 {
                        let l =
                            u16::from_be_bytes([this.header_buf[2], this.header_buf[3]]) as usize;
                        offset += 2;
                        l
                    } else if basic_len == 127 {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&this.header_buf[2..10]);
                        offset += 8;
                        u64::from_be_bytes(b) as usize
                    } else {
                        basic_len
                    };

                    this.mask_key = if masked {
                        let mut m = [0u8; 4];
                        m.copy_from_slice(&this.header_buf[offset..offset + 4]);
                        Some(m)
                    } else {
                        None
                    };

                    this.payload_rem = payload_len;
                    this.mask_idx = 0;
                    this.header_pos = 0;
                    this.header_len = 2;
                    this.read_state = ReadState::Payload;
                }

                ReadState::Payload => {
                    if this.payload_rem == 0 {
                        this.read_state = ReadState::Header;
                        continue;
                    }

                    // For Ping (0x09) and Pong (0x0A) control frames, drain payload without delivering to user buf
                    let is_control = this.current_opcode == 0x09 || this.current_opcode == 0x0A;

                    if !is_control && buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    let max_to_read = if is_control {
                        this.payload_rem.min(256)
                    } else {
                        this.payload_rem.min(buf.remaining()).min(64 * 1024)
                    };

                    let n_read = if this.buffered_pos < this.buffered_excess.len() {
                        let avail = this.buffered_excess.len() - this.buffered_pos;
                        let n = avail.min(max_to_read);
                        let slice = &this.buffered_excess[this.buffered_pos..this.buffered_pos + n];

                        if !is_control {
                            if let Some(mask) = this.mask_key {
                                let mut unmasked = [0u8; 16 * 1024];
                                let to_unmask = n.min(unmasked.len());
                                for (i, &b) in slice[..to_unmask].iter().enumerate() {
                                    unmasked[i] = b ^ mask[(this.mask_idx + i) % 4];
                                }
                                buf.put_slice(&unmasked[..to_unmask]);
                            } else {
                                buf.put_slice(slice);
                            }
                        } else if this.current_opcode == 0x09 && this.ping_payload.len() < 125 {
                            if let Some(mask) = this.mask_key {
                                for (i, &b) in slice.iter().enumerate() {
                                    this.ping_payload.push(b ^ mask[(this.mask_idx + i) % 4]);
                                }
                            } else {
                                this.ping_payload.extend_from_slice(slice);
                            }
                        }

                        this.buffered_pos += n;
                        this.mask_idx = (this.mask_idx + n) % 4;
                        n
                    } else if this.mask_key.is_none() && !is_control {
                        // Fast path: unmasked payload bounded strictly by current frame remaining payload
                        let chunk_to_read = max_to_read.min(16 * 1024);
                        let mut tmp = [0u8; 16 * 1024];
                        let mut tmp_buf = ReadBuf::new(&mut tmp[..chunk_to_read]);

                        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF in websocket payload",
                                    )));
                                }
                                buf.put_slice(tmp_buf.filled());
                                n
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        let mut tmp = [0u8; 16 * 1024];
                        let chunk_to_read = max_to_read.min(tmp.len());
                        let mut tmp_buf = ReadBuf::new(&mut tmp[..chunk_to_read]);

                        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF in websocket payload",
                                    )));
                                }

                                if !is_control {
                                    if let Some(mask) = this.mask_key {
                                        let mut unmasked = [0u8; 16 * 1024];
                                        let filled = tmp_buf.filled();
                                        for (i, &b) in filled.iter().enumerate() {
                                            unmasked[i] = b ^ mask[(this.mask_idx + i) % 4];
                                        }
                                        buf.put_slice(&unmasked[..filled.len()]);
                                    } else {
                                        buf.put_slice(tmp_buf.filled());
                                    }
                                } else if this.current_opcode == 0x09
                                    && this.ping_payload.len() < 125
                                {
                                    let filled = tmp_buf.filled();
                                    if let Some(mask) = this.mask_key {
                                        for (i, &b) in filled.iter().enumerate() {
                                            this.ping_payload
                                                .push(b ^ mask[(this.mask_idx + i) % 4]);
                                        }
                                    } else {
                                        this.ping_payload.extend_from_slice(filled);
                                    }
                                }

                                this.mask_idx = (this.mask_idx + n) % 4;
                                n
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    };

                    this.payload_rem -= n_read;
                    if this.payload_rem == 0 {
                        if this.current_opcode == 0x09 {
                            this.pending_pong =
                                build_pong_frame(&this.ping_payload, this.is_client);
                            this.pending_pong_pos = 0;
                            this.ping_payload.clear();
                        }
                        this.read_state = ReadState::Header;
                    }

                    if !is_control {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Step 0: Flush any pending Pong frame first
        while this.pending_pong_pos < this.pending_pong.len() {
            let n = match Pin::new(&mut this.inner)
                .poll_write(cx, &this.pending_pong[this.pending_pong_pos..])
            {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.pending_pong_pos += n;
            if this.pending_pong_pos == this.pending_pong.len() {
                this.pending_pong.clear();
                this.pending_pong_pos = 0;
                break;
            }
        }

        // Step 1: If a previously framed chunk is in progress, finish flushing it first
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
                    "failed to write buffered websocket frame",
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

        // Step 2: Frame a new payload chunk
        let chunk_len = buf.len().min(16384);
        let payload = &buf[..chunk_len];

        this.write_buf.clear();
        this.write_buf.push(0x82); // FIN = 1, Opcode = 2 (Binary)

        let is_client = this.is_client;

        if is_client {
            let mask: [u8; 4] = rand::random();
            if chunk_len <= 125 {
                this.write_buf.push(0x80 | (chunk_len as u8));
            } else if chunk_len <= 65535 {
                this.write_buf.push(0x80 | 126);
                this.write_buf
                    .extend_from_slice(&(chunk_len as u16).to_be_bytes());
            } else {
                this.write_buf.push(0x80 | 127);
                this.write_buf
                    .extend_from_slice(&(chunk_len as u64).to_be_bytes());
            }

            this.write_buf.extend_from_slice(&mask);
            for (i, &b) in payload.iter().enumerate() {
                this.write_buf.push(b ^ mask[i % 4]);
            }
        } else {
            // Server to client (unmasked)
            if chunk_len <= 125 {
                this.write_buf.push(chunk_len as u8);
            } else if chunk_len <= 65535 {
                this.write_buf.push(126);
                this.write_buf
                    .extend_from_slice(&(chunk_len as u16).to_be_bytes());
            } else {
                this.write_buf.push(127);
                this.write_buf
                    .extend_from_slice(&(chunk_len as u64).to_be_bytes());
            }
            this.write_buf.extend_from_slice(payload);
        }

        this.write_pos = 0;
        this.pending_chunk_len = chunk_len;

        // Step 3: Write out as much as possible
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
                    "failed to write buffered websocket frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
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
                    "failed to flush buffered websocket frame",
                )));
            }
            this.write_pos += n;
        }
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_chunk_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_websocket_handshake_and_bidirectional_data() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, Some("/chat")).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = ws_server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Hello from client over WS!");
            ws_server
                .write_all(b"Hello from server over WS!")
                .await
                .unwrap();
            ws_server.flush().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut headers = HashMap::new();
            headers.insert("User-Agent".into(), "flux-test".into());
            let mut ws_client = client_handshake(client_io, "example.com", "/chat", &headers)
                .await
                .unwrap();
            ws_client
                .write_all(b"Hello from client over WS!")
                .await
                .unwrap();
            ws_client.flush().await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = ws_client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Hello from server over WS!");
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_large_pipelined_payload() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);

        let large_msg = vec![0x42u8; 32 * 1024]; // 32 KB payload
        let large_msg_clone = large_msg.clone();

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, None).await.unwrap();
            let mut buf = vec![0u8; large_msg_clone.len()];
            ws_server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, large_msg_clone);
        });

        let client_task = tokio::spawn(async move {
            let mut ws_client = client_handshake(client_io, "test.local", "/", &HashMap::new())
                .await
                .unwrap();
            ws_client.write_all(&large_msg).await.unwrap();
            ws_client.flush().await.unwrap();
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_close_frame_eof() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut ws_server = server_handshake(server_io, None).await.unwrap();
            // Send Close frame: 0x88, length 0
            ws_server.inner.write_all(&[0x88, 0x00]).await.unwrap();
            ws_server.inner.flush().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut ws_client = client_handshake(client_io, "test.local", "/", &HashMap::new())
                .await
                .unwrap();
            let mut buf = [0u8; 32];
            let n = ws_client.read(&mut buf).await.unwrap();
            assert_eq!(n, 0); // Clean EOF!
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }
}
