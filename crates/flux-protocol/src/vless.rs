use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;
use flux_types::{FluxError, FluxResult, NetworkType, TargetAddress};

pub const VLESS_VERSION: u8 = 0x00;

pub const VLESS_CMD_TCP: u8 = 0x01;
pub const VLESS_CMD_UDP: u8 = 0x02;
pub const VLESS_CMD_MUX: u8 = 0x03;

pub const VLESS_ATYP_IPV4: u8 = 0x01;
pub const VLESS_ATYP_DOMAIN: u8 = 0x02;
pub const VLESS_ATYP_IPV6: u8 = 0x03;

#[derive(Clone, Debug)]
pub struct VlessRequest {
    pub uuid: Uuid,
    pub command: u8,
    pub address: TargetAddress,
}

/// Stream wrapper for VLESS client that lazily strips the VLESS response header
/// on the first read without blocking client writes.
pub struct VlessClientStream<S> {
    inner: S,
    header_read: bool,
    header_buf: [u8; 2],
    header_pos: usize,
    addon_rem: usize,
}

impl<S> VlessClientStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header_read: false,
            header_buf: [0u8; 2],
            header_pos: 0,
            addon_rem: 0,
        }
    }
}

// AsyncStream is automatically implemented by blanket impl in flux_types
// for any type that implements AsyncRead + AsyncWrite + Send + Sync + Unpin.

impl<S: AsyncRead + Unpin> AsyncRead for VlessClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while !self.header_read {
            // Step 1: Read the 2-byte header: [version, addon_len]
            if self.header_pos < 2 {
                let mut tmp = [0u8; 2];
                let mut tmp_buf = ReadBuf::new(&mut tmp[..2 - self.header_pos]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while reading VLESS response header",
                            )));
                        }
                        let pos = self.header_pos;
                        self.header_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        self.header_pos += n;
                        if self.header_pos == 2 {
                            if self.header_buf[0] != VLESS_VERSION {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("unexpected vless version: {}", self.header_buf[0]),
                                )));
                            }
                            self.addon_rem = self.header_buf[1] as usize;
                            if self.addon_rem == 0 {
                                self.header_read = true;
                                break;
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else if self.addon_rem > 0 {
                // Step 2: Drain any addon bytes
                let mut drain = [0u8; 64];
                let to_read = self.addon_rem.min(drain.len());
                let mut drain_buf = ReadBuf::new(&mut drain[..to_read]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut drain_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = drain_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while reading VLESS response addons",
                            )));
                        }
                        self.addon_rem -= n;
                        if self.addon_rem == 0 {
                            self.header_read = true;
                            break;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        // Once header is read, read application data directly into buf
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessClientStream<S> {
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

pub struct VlessProtocol;

impl VlessProtocol {
    /// Client-side: encode and write VLESS request header.
    pub async fn write_request_header<S: AsyncWrite + Unpin>(
        stream: &mut S,
        uuid: &Uuid,
        network: NetworkType,
        destination: &TargetAddress,
        flow: Option<&str>,
    ) -> FluxResult<()> {
        let mut buf = Vec::with_capacity(64);
        // Version
        buf.push(VLESS_VERSION);
        // UUID (16 bytes)
        buf.extend_from_slice(uuid.as_bytes());

        // Addons
        if flow == Some(crate::vision::VISION_FLOW) {
            let addons = crate::vision::encode_vision_addons();
            buf.push(addons.len() as u8);
            buf.extend_from_slice(&addons);
        } else {
            buf.push(0x00);
        }

        // Command
        let cmd = match network {
            NetworkType::Tcp => VLESS_CMD_TCP,
            NetworkType::Udp => VLESS_CMD_UDP,
        };
        buf.push(cmd);
        // Port (2 bytes BE)
        buf.extend_from_slice(&destination.port().to_be_bytes());

        // Address
        match destination {
            TargetAddress::Ip(SocketAddr::V4(v4)) => {
                buf.push(VLESS_ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
            }
            TargetAddress::Ip(SocketAddr::V6(v6)) => {
                buf.push(VLESS_ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
            }
            TargetAddress::Domain(domain, _) => {
                buf.push(VLESS_ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(FluxError::InvalidAddress("domain too long for VLESS".into()));
                }
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
        }

        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Server-side: read and validate client request header.
    pub async fn read_request_header<S: AsyncRead + Unpin>(
        stream: &mut S,
        valid_uuids: &[Uuid],
    ) -> FluxResult<VlessRequest> {
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "vless",
                message: format!("failed to read vless version: {}", e),
            }
        })?;

        if ver[0] != VLESS_VERSION {
            return Err(FluxError::Protocol {
                protocol: "vless",
                message: format!("invalid vless version: {}", ver[0]),
            });
        }

        let mut uuid_bytes = [0u8; 16];
        stream.read_exact(&mut uuid_bytes).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "vless",
                message: format!("failed to read vless uuid: {}", e),
            }
        })?;

        let client_uuid = Uuid::from_bytes(uuid_bytes);
        if !valid_uuids.is_empty() && !valid_uuids.contains(&client_uuid) {
            return Err(FluxError::AuthFailed(format!("unauthorized vless uuid: {}", client_uuid)));
        }

        let mut addon_len_buf = [0u8; 1];
        stream.read_exact(&mut addon_len_buf).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "vless",
                message: format!("failed to read vless addon length: {}", e),
            }
        })?;

        let addon_len = addon_len_buf[0] as usize;
        if addon_len > 0 {
            let mut addon_buf = vec![0u8; addon_len];
            stream.read_exact(&mut addon_buf).await.map_err(|e| {
                FluxError::Protocol {
                    protocol: "vless",
                    message: format!("failed to read vless addons: {}", e),
                }
            })?;
        }

        let mut cmd_and_port = [0u8; 3];
        stream.read_exact(&mut cmd_and_port).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "vless",
                message: format!("failed to read vless command and port: {}", e),
            }
        })?;

        let command = cmd_and_port[0];
        let port = u16::from_be_bytes([cmd_and_port[1], cmd_and_port[2]]);

        let mut atyp_buf = [0u8; 1];
        stream.read_exact(&mut atyp_buf).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "vless",
                message: format!("failed to read vless address type: {}", e),
            }
        })?;

        let address = match atyp_buf[0] {
            VLESS_ATYP_IPV4 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "vless",
                        message: format!("failed to read ipv4: {}", e),
                    }
                })?;
                let ip = Ipv4Addr::from(ip_bytes);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            VLESS_ATYP_DOMAIN => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "vless",
                        message: format!("failed to read domain length: {}", e),
                    }
                })?;
                let len = dlen[0] as usize;
                let mut domain_buf = vec![0u8; len];
                stream.read_exact(&mut domain_buf).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "vless",
                        message: format!("failed to read domain string: {}", e),
                    }
                })?;
                let domain = String::from_utf8(domain_buf).map_err(|e| {
                    FluxError::Protocol {
                        protocol: "vless",
                        message: format!("invalid utf-8 domain: {}", e),
                    }
                })?;
                TargetAddress::Domain(domain, port)
            }
            VLESS_ATYP_IPV6 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "vless",
                        message: format!("failed to read ipv6: {}", e),
                    }
                })?;
                let ip = Ipv6Addr::from(ip_bytes);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            other => {
                return Err(FluxError::Protocol {
                    protocol: "vless",
                    message: format!("unknown vless address type: {}", other),
                });
            }
        };

        Ok(VlessRequest {
            uuid: client_uuid,
            command,
            address,
        })
    }

    /// Server-side: write VLESS response header (version 0, addons length 0).
    pub async fn write_response_header<S: AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<()> {
        stream.write_all(&[VLESS_VERSION, 0x00]).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vless_client_stream_lazy_header() {
        let (client_raw, mut server_raw) = tokio::io::duplex(1024);
        let mut vless_client = VlessClientStream::new(client_raw);

        let srv = tokio::spawn(async move {
            // Server sends response header followed by payload
            VlessProtocol::write_response_header(&mut server_raw).await.unwrap();
            server_raw.write_all(b"response-data").await.unwrap();
        });

        // Client writes payload first without reading response header
        vless_client.write_all(b"client-payload").await.unwrap();

        // Client reads response; VlessClientStream strips [0, 0] header transparently!
        let mut buf = vec![0u8; 13];
        vless_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"response-data");

        srv.await.unwrap();
    }
}
