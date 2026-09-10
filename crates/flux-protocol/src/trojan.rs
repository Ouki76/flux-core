use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use flux_types::{FluxError, FluxResult, NetworkType, TargetAddress};
use crate::socks5::{Socks5Handshake, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

pub const TROJAN_CMD_CONNECT: u8 = 0x01;
pub const TROJAN_CMD_UDP: u8 = 0x03;

pub fn hash_trojan_password(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub struct TrojanProtocol;

impl TrojanProtocol {
    /// Client-side: encode and write Trojan request header into stream.
    pub async fn write_request_header<S: AsyncWrite + Unpin>(
        stream: &mut S,
        password: &str,
        network: NetworkType,
        destination: &TargetAddress,
    ) -> FluxResult<()> {
        let hex_hash = hash_trojan_password(password);
        let mut buf = Vec::with_capacity(128);

        // 56-byte hex hash + CRLF
        buf.extend_from_slice(hex_hash.as_bytes());
        buf.extend_from_slice(b"\r\n");

        // Command: 0x01 = TCP, 0x03 = UDP
        let cmd = match network {
            NetworkType::Tcp => TROJAN_CMD_CONNECT,
            NetworkType::Udp => TROJAN_CMD_UDP,
        };
        buf.push(cmd);

        // SOCKS5-style Address
        match destination {
            TargetAddress::Ip(std::net::SocketAddr::V4(v4)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            TargetAddress::Ip(std::net::SocketAddr::V6(v6)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            TargetAddress::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        // CRLF terminating header
        buf.extend_from_slice(b"\r\n");

        stream.write_all(&buf).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    /// Server-side: read and validate Trojan request.
    pub async fn read_request_header<S: AsyncRead + Unpin>(
        stream: &mut S,
        valid_hashes: &[String],
    ) -> FluxResult<(u8, TargetAddress)> {
        let mut hex_buf = [0u8; 56];
        stream.read_exact(&mut hex_buf).await.map_err(FluxError::Io)?;
        let hex_str = String::from_utf8_lossy(&hex_buf);

        if !valid_hashes.is_empty() && !valid_hashes.iter().any(|h| h.eq_ignore_ascii_case(&hex_str)) {
            return Err(FluxError::AuthFailed("invalid trojan password hash".into()));
        }

        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.map_err(FluxError::Io)?;
        if &crlf != b"\r\n" {
            return Err(FluxError::Protocol {
                protocol: "trojan",
                message: "missing CRLF after password hash".into(),
            });
        }

        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await.map_err(FluxError::Io)?;

        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await.map_err(FluxError::Io)?;

        let target = Socks5Handshake::read_address(stream, atyp[0]).await?;

        let mut end_crlf = [0u8; 2];
        stream.read_exact(&mut end_crlf).await.map_err(FluxError::Io)?;
        if &end_crlf != b"\r\n" {
            return Err(FluxError::Protocol {
                protocol: "trojan",
                message: "missing terminating CRLF in trojan header".into(),
            });
        }

        Ok((cmd[0], target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trojan_request_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let password = "my-secret-trojan-password";
        let target = TargetAddress::domain("example.com", 443);
        let expected_hash = hash_trojan_password(password);

        let srv = tokio::spawn(async move {
            let (cmd, addr) = TrojanProtocol::read_request_header(&mut server, &[expected_hash])
                .await
                .unwrap();
            assert_eq!(cmd, TROJAN_CMD_CONNECT);
            assert_eq!(addr.host(), "example.com");
            assert_eq!(addr.port(), 443);
        });

        let cli = tokio::spawn(async move {
            TrojanProtocol::write_request_header(
                &mut client,
                password,
                NetworkType::Tcp,
                &target,
            )
            .await
            .unwrap();
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}
