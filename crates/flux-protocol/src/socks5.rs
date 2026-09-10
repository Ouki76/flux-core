use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use flux_types::{FluxError, FluxResult, TargetAddress};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Socks5Command {
    Connect,
    UdpAssociate,
    Bind,
}

#[derive(Clone, Debug)]
pub struct Socks5Request {
    pub command: Socks5Command,
    pub address: TargetAddress,
}

/// SOCKS5 protocol handler
pub struct Socks5Handshake;

impl Socks5Handshake {
    /// Server-side: read client handshake and negotiate authentication.
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<()> {
        let mut ver_nmethods = [0u8; 2];
        stream.read_exact(&mut ver_nmethods).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "socks5",
                message: format!("failed to read version & nmethods: {}", e),
            }
        })?;

        if ver_nmethods[0] != SOCKS5_VERSION {
            return Err(FluxError::Protocol {
                protocol: "socks5",
                message: format!("unsupported socks version: {}", ver_nmethods[0]),
            });
        }

        let nmethods = ver_nmethods[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "socks5",
                message: format!("failed to read auth methods: {}", e),
            }
        })?;

        if methods.contains(&METHOD_NO_AUTH) {
            stream.write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH]).await.map_err(|e| {
                FluxError::Protocol {
                    protocol: "socks5",
                    message: format!("failed to write method selection: {}", e),
                }
            })?;
            stream.flush().await?;
            Ok(())
        } else {
            stream.write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]).await?;
            stream.flush().await?;
            Err(FluxError::AuthFailed("no acceptable auth method".into()))
        }
    }

    /// Server-side: read the SOCKS5 request (CONNECT / UDP ASSOCIATE / BIND).
    pub async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<Socks5Request> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.map_err(|e| {
            FluxError::Protocol {
                protocol: "socks5",
                message: format!("failed to read request header: {}", e),
            }
        })?;

        if header[0] != SOCKS5_VERSION {
            return Err(FluxError::Protocol {
                protocol: "socks5",
                message: format!("invalid socks version in request: {}", header[0]),
            });
        }

        let command = match header[1] {
            CMD_CONNECT => Socks5Command::Connect,
            CMD_UDP_ASSOCIATE => Socks5Command::UdpAssociate,
            CMD_BIND => Socks5Command::Bind,
            cmd => {
                Self::send_reply(stream, REP_COMMAND_NOT_SUPPORTED, None).await?;
                return Err(FluxError::Protocol {
                    protocol: "socks5",
                    message: format!("unsupported socks command: {}", cmd),
                });
            }
        };

        let atyp = header[3];
        let address = Self::read_address(stream, atyp).await?;

        Ok(Socks5Request { command, address })
    }

    /// Read address based on ATYP
    pub async fn read_address<S: AsyncRead + Unpin>(
        stream: &mut S,
        atyp: u8,
    ) -> FluxResult<TargetAddress> {
        match atyp {
            ATYP_IPV4 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read ipv4: {}", e),
                    }
                })?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read port: {}", e),
                    }
                })?;
                let ip = Ipv4Addr::from(ip_bytes);
                let port = u16::from_be_bytes(port_bytes);
                Ok(TargetAddress::Ip(SocketAddr::new(ip.into(), port)))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read domain len: {}", e),
                    }
                })?;
                let domain_len = len[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read domain string: {}", e),
                    }
                })?;
                let domain = String::from_utf8(domain_buf).map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("invalid utf-8 domain: {}", e),
                    }
                })?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read port: {}", e),
                    }
                })?;
                let port = u16::from_be_bytes(port_bytes);
                Ok(TargetAddress::Domain(domain, port))
            }
            ATYP_IPV6 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read ipv6: {}", e),
                    }
                })?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await.map_err(|e| {
                    FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read port: {}", e),
                    }
                })?;
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes(port_bytes);
                Ok(TargetAddress::Ip(SocketAddr::new(ip.into(), port)))
            }
            _ => Err(FluxError::Protocol {
                protocol: "socks5",
                message: format!("unsupported atyp: {}", atyp),
            }),
        }
    }

    /// Server-side: send SOCKS5 reply
    pub async fn send_reply<S: AsyncWrite + Unpin>(
        stream: &mut S,
        rep: u8,
        bind_addr: Option<SocketAddr>,
    ) -> FluxResult<()> {
        let mut buf = Vec::with_capacity(10);
        buf.push(SOCKS5_VERSION);
        buf.push(rep);
        buf.push(0x00); // RSV

        match bind_addr {
            Some(SocketAddr::V4(v4)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            Some(SocketAddr::V6(v6)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            None => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&[0, 0, 0, 0]);
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Client-side: initiate SOCKS5 connection to a remote server.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        command: u8,
        target: &TargetAddress,
    ) -> FluxResult<Option<SocketAddr>> {
        // Send client greeting (No Auth)
        stream.write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH]).await?;
        stream.flush().await?;

        // Read server response
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION || resp[1] != METHOD_NO_AUTH {
            return Err(FluxError::AuthFailed(format!(
                "socks5 handshake rejected: ver={}, method={}",
                resp[0], resp[1]
            )));
        }

        // Send request
        let mut req = Vec::with_capacity(32);
        req.push(SOCKS5_VERSION);
        req.push(command);
        req.push(0x00); // RSV

        match target {
            TargetAddress::Ip(SocketAddr::V4(v4)) => {
                req.push(ATYP_IPV4);
                req.extend_from_slice(&v4.ip().octets());
                req.extend_from_slice(&v4.port().to_be_bytes());
            }
            TargetAddress::Ip(SocketAddr::V6(v6)) => {
                req.push(ATYP_IPV6);
                req.extend_from_slice(&v6.ip().octets());
                req.extend_from_slice(&v6.port().to_be_bytes());
            }
            TargetAddress::Domain(domain, port) => {
                req.push(ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(FluxError::InvalidAddress("domain too long".into()));
                }
                req.push(bytes.len() as u8);
                req.extend_from_slice(bytes);
                req.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&req).await?;
        stream.flush().await?;

        // Read server reply
        let mut reply_header = [0u8; 4];
        stream.read_exact(&mut reply_header).await?;
        if reply_header[0] != SOCKS5_VERSION {
            return Err(FluxError::Protocol {
                protocol: "socks5",
                message: format!("invalid socks5 reply version: {}", reply_header[0]),
            });
        }
        if reply_header[1] != REP_SUCCESS {
            return Err(FluxError::Blocked(format!(
                "socks5 request failed with code: 0x{:02x}",
                reply_header[1]
            )));
        }

        let bound_addr = Self::read_address(stream, reply_header[3]).await?;
        match bound_addr {
            TargetAddress::Ip(addr) => Ok(Some(addr)),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_handshake_and_connect() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let srv_task = tokio::spawn(async move {
            Socks5Handshake::server_handshake(&mut server).await.unwrap();
            let req = Socks5Handshake::read_request(&mut server).await.unwrap();
            assert_eq!(req.command, Socks5Command::Connect);
            assert_eq!(req.address.host(), "example.com");
            assert_eq!(req.address.port(), 443);
            Socks5Handshake::send_reply(&mut server, REP_SUCCESS, None).await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let target = TargetAddress::domain("example.com", 443);
            Socks5Handshake::client_handshake(&mut client, CMD_CONNECT, &target).await.unwrap();
        });

        srv_task.await.unwrap();
        client_task.await.unwrap();
    }
}
