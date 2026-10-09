use flux_types::{FluxError, FluxResult, TargetAddress};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_PASSWORD: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
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

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SOCKS5 protocol handler supporting RFC 1928 and RFC 1929 authentication.
pub struct Socks5Handshake;

impl Socks5Handshake {
    /// Server-side: read client handshake and negotiate authentication (No Auth).
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<()> {
        Self::server_handshake_with_auth(stream, None)
            .await
            .map(|_| ())
    }

    /// Server-side: negotiate auth with optional RFC 1929 username/password list.
    pub async fn server_handshake_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        users: Option<&[(String, String)]>,
    ) -> FluxResult<Option<String>> {
        let mut ver_nmethods = [0u8; 2];
        stream
            .read_exact(&mut ver_nmethods)
            .await
            .map_err(|e| FluxError::Protocol {
                protocol: "socks5",
                message: format!("failed to read version & nmethods: {}", e),
            })?;

        if ver_nmethods[0] != SOCKS5_VERSION {
            return Err(FluxError::Protocol {
                protocol: "socks5",
                message: format!("unsupported socks version: {}", ver_nmethods[0]),
            });
        }

        let nmethods = ver_nmethods[1] as usize;
        let mut methods = [0u8; 256];
        stream
            .read_exact(&mut methods[..nmethods])
            .await
            .map_err(|e| FluxError::Protocol {
                protocol: "socks5",
                message: format!("failed to read auth methods: {}", e),
            })?;

        if let Some(user_list) = users
            && !user_list.is_empty()
        {
            // Server requires username/password
            if !methods[..nmethods].contains(&METHOD_PASSWORD) {
                stream
                    .write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
                    .await?;
                stream.flush().await?;
                return Err(FluxError::AuthFailed(
                    "client does not support password auth".into(),
                ));
            }

            stream.write_all(&[SOCKS5_VERSION, METHOD_PASSWORD]).await?;
            stream.flush().await?;

            // Read RFC 1929 Auth negotiation
            let mut sub_ver = [0u8; 1];
            stream.read_exact(&mut sub_ver).await?;
            if sub_ver[0] != 0x01 {
                return Err(FluxError::Protocol {
                    protocol: "socks5",
                    message: format!("unsupported auth subnegotiation version: {}", sub_ver[0]),
                });
            }

            let mut ulen = [0u8; 1];
            stream.read_exact(&mut ulen).await?;
            let mut u_buf = vec![0u8; ulen[0] as usize];
            stream.read_exact(&mut u_buf).await?;
            let username = String::from_utf8_lossy(&u_buf).to_string();

            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut p_buf = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut p_buf).await?;
            let password = String::from_utf8_lossy(&p_buf).to_string();

            let matched = user_list.iter().any(|(u, p)| {
                constant_time_eq_str(u, &username) && constant_time_eq_str(p, &password)
            });
            if matched {
                // Success: 0x01 0x00
                stream.write_all(&[0x01, 0x00]).await?;
                stream.flush().await?;
                Ok(Some(username))
            } else {
                // Fail: 0x01 0x01
                stream.write_all(&[0x01, 0x01]).await?;
                stream.flush().await?;
                Err(FluxError::AuthFailed(format!(
                    "invalid credentials for user '{}'",
                    username
                )))
            }
        } else {
            // No auth required
            if methods.contains(&METHOD_NO_AUTH) {
                stream.write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH]).await?;
                stream.flush().await?;
                Ok(None)
            } else {
                stream
                    .write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
                    .await?;
                stream.flush().await?;
                Err(FluxError::AuthFailed("no acceptable auth method".into()))
            }
        }
    }

    /// Server-side: read the SOCKS5 request (CONNECT / UDP ASSOCIATE / BIND).
    pub async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<Socks5Request> {
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| FluxError::Protocol {
                protocol: "socks5",
                message: format!("failed to read request header: {}", e),
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
                let mut buf = [0u8; 6];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read ipv4 and port: {}", e),
                    })?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(TargetAddress::Ip(SocketAddr::new(ip.into(), port)))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(|e| FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read domain len: {}", e),
                    })?;
                let domain_len = len[0] as usize;
                if domain_len == 0 {
                    return Err(FluxError::Protocol {
                        protocol: "socks5",
                        message: "empty domain length in socks5 request".into(),
                    });
                }
                let mut buf = [0u8; 257]; // Max RFC 1928 domain (255) + port (2)
                let to_read = domain_len + 2;
                stream
                    .read_exact(&mut buf[..to_read])
                    .await
                    .map_err(|e| FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read domain string and port: {}", e),
                    })?;
                let domain = std::str::from_utf8(&buf[..domain_len])
                    .map_err(|e| FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("invalid utf-8 domain: {}", e),
                    })?
                    .to_string();
                let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);
                Ok(TargetAddress::Domain(domain, port))
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| FluxError::Protocol {
                        protocol: "socks5",
                        message: format!("failed to read ipv6 and port: {}", e),
                    })?;
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[..16]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
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

    /// Client-side: initiate SOCKS5 connection to a remote server with optional credentials.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        command: u8,
        target: &TargetAddress,
    ) -> FluxResult<Option<SocketAddr>> {
        Self::client_handshake_with_auth(stream, command, target, None).await
    }

    /// Client-side: initiate SOCKS5 connection with optional username/password auth.
    pub async fn client_handshake_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        command: u8,
        target: &TargetAddress,
        auth: Option<(&str, &str)>,
    ) -> FluxResult<Option<SocketAddr>> {
        if let Some((user, pass)) = auth {
            // Client supports Password Auth
            stream
                .write_all(&[SOCKS5_VERSION, 1, METHOD_PASSWORD])
                .await?;
            stream.flush().await?;

            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != SOCKS5_VERSION || resp[1] != METHOD_PASSWORD {
                return Err(FluxError::AuthFailed(
                    "server rejected password auth method".into(),
                ));
            }

            // Send RFC 1929 Auth Request
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01); // Version 1
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;
            stream.flush().await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(FluxError::AuthFailed("invalid username or password".into()));
            }
        } else {
            // Client greeting (No Auth)
            stream
                .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
                .await?;
            stream.flush().await?;

            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != SOCKS5_VERSION || resp[1] != METHOD_NO_AUTH {
                return Err(FluxError::AuthFailed(format!(
                    "socks5 handshake rejected: ver={}, method={}",
                    resp[0], resp[1]
                )));
            }
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
            Socks5Handshake::server_handshake(&mut server)
                .await
                .unwrap();
            let req = Socks5Handshake::read_request(&mut server).await.unwrap();
            assert_eq!(req.command, Socks5Command::Connect);
            assert_eq!(req.address.host(), "example.com");
            assert_eq!(req.address.port(), 443);
            Socks5Handshake::send_reply(&mut server, REP_SUCCESS, None)
                .await
                .unwrap();
        });

        let client_task = tokio::spawn(async move {
            let target = TargetAddress::domain("example.com", 443);
            Socks5Handshake::client_handshake(&mut client, CMD_CONNECT, &target)
                .await
                .unwrap();
        });

        srv_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_user_pass_auth() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let allowed = vec![("admin".to_string(), "pass123".to_string())];

        let srv_task = tokio::spawn(async move {
            let user = Socks5Handshake::server_handshake_with_auth(&mut server, Some(&allowed))
                .await
                .unwrap();
            assert_eq!(user, Some("admin".to_string()));
            let req = Socks5Handshake::read_request(&mut server).await.unwrap();
            assert_eq!(req.command, Socks5Command::Connect);
            Socks5Handshake::send_reply(&mut server, REP_SUCCESS, None)
                .await
                .unwrap();
        });

        let client_task = tokio::spawn(async move {
            let target = TargetAddress::domain("example.com", 443);
            Socks5Handshake::client_handshake_with_auth(
                &mut client,
                CMD_CONNECT,
                &target,
                Some(("admin", "pass123")),
            )
            .await
            .unwrap();
        });

        srv_task.await.unwrap();
        client_task.await.unwrap();
    }
}
