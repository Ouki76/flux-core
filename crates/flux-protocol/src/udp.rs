use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flux_types::{FluxError, FluxResult, TargetAddress, UdpPacket};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Encodes a UdpPacket into a SOCKS5 UDP datagram.
pub fn encode_socks5_udp(packet: &UdpPacket) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + packet.payload.len());
    buf.put_u16(0x0000); // RSV
    buf.put_u8(0x00); // FRAG

    match &packet.destination {
        TargetAddress::Ip(SocketAddr::V4(v4)) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        TargetAddress::Ip(SocketAddr::V6(v6)) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
        TargetAddress::Domain(domain, port) => {
            buf.put_u8(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            let dlen = bytes.len().min(255);
            buf.put_u8(dlen as u8);
            buf.put_slice(&bytes[..dlen]);
            buf.put_u16(*port);
        }
    }

    buf.put_slice(&packet.payload);
    buf.freeze()
}

/// Decodes a SOCKS5 UDP datagram into a UdpPacket.
pub fn decode_socks5_udp(src_addr: TargetAddress, mut data: Bytes) -> FluxResult<UdpPacket> {
    if data.len() < 4 {
        return Err(FluxError::Protocol {
            protocol: "socks5-udp",
            message: "datagram too short".into(),
        });
    }

    let _rsv = data.get_u16();
    let frag = data.get_u8();
    if frag != 0 {
        return Err(FluxError::Protocol {
            protocol: "socks5-udp",
            message: "fragmentation not supported".into(),
        });
    }

    let atyp = data.get_u8();
    let destination = match atyp {
        ATYP_IPV4 => {
            if data.len() < 4 + 2 {
                return Err(FluxError::Protocol {
                    protocol: "socks5-udp",
                    message: "truncated ipv4 address".into(),
                });
            }
            let mut ip_bytes = [0u8; 4];
            data.copy_to_slice(&mut ip_bytes);
            let port = data.get_u16();
            TargetAddress::Ip(SocketAddr::new(Ipv4Addr::from(ip_bytes).into(), port))
        }
        ATYP_DOMAIN => {
            if data.is_empty() {
                return Err(FluxError::Protocol {
                    protocol: "socks5-udp",
                    message: "missing domain length".into(),
                });
            }
            let len = data.get_u8() as usize;
            if data.len() < len + 2 {
                return Err(FluxError::Protocol {
                    protocol: "socks5-udp",
                    message: "truncated domain address".into(),
                });
            }
            let domain_bytes = data.split_to(len);
            let port = data.get_u16();
            let domain = std::str::from_utf8(&domain_bytes).map_err(|e| FluxError::Protocol {
                protocol: "socks5-udp",
                message: format!("invalid utf-8 domain: {}", e),
            })?;
            TargetAddress::domain(domain, port)
        }
        ATYP_IPV6 => {
            if data.len() < 16 + 2 {
                return Err(FluxError::Protocol {
                    protocol: "socks5-udp",
                    message: "truncated ipv6 address".into(),
                });
            }
            let mut ip_bytes = [0u8; 16];
            data.copy_to_slice(&mut ip_bytes);
            let port = data.get_u16();
            TargetAddress::Ip(SocketAddr::new(Ipv6Addr::from(ip_bytes).into(), port))
        }
        _ => {
            return Err(FluxError::Protocol {
                protocol: "socks5-udp",
                message: format!("unsupported atyp: {}", atyp),
            });
        }
    };

    Ok(UdpPacket::new(data, src_addr, destination))
}

/// Encodes a Trojan UDP packet: `[ATYP + Addr + Port] + [Length (2 bytes BE)] + [\r\n] + [Payload]`.
pub fn encode_trojan_udp(packet: &UdpPacket) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + packet.payload.len());
    match &packet.destination {
        TargetAddress::Ip(SocketAddr::V4(v4)) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        TargetAddress::Ip(SocketAddr::V6(v6)) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
        TargetAddress::Domain(domain, port) => {
            buf.put_u8(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            let dlen = bytes.len().min(255);
            buf.put_u8(dlen as u8);
            buf.put_slice(&bytes[..dlen]);
            buf.put_u16(*port);
        }
    }
    let p_len = packet.payload.len().min(65535);
    buf.put_u16(p_len as u16);
    buf.put_slice(b"\r\n");
    buf.put_slice(&packet.payload[..p_len]);
    buf.freeze()
}

/// Encodes a VLESS UDP packet: `[Length (2 bytes BE)] + [Payload]`.
pub fn encode_vless_udp(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
    buf.freeze()
}

/// Encodes a standard VLESS UDP packet: `[Address] + [Length (2 bytes BE)] + [Payload]`.
pub fn encode_vless_udp_packet(packet: &UdpPacket) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + packet.payload.len());
    match &packet.destination {
        TargetAddress::Ip(SocketAddr::V4(v4)) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        TargetAddress::Ip(SocketAddr::V6(v6)) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
        TargetAddress::Domain(domain, port) => {
            buf.put_u8(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            let dlen = bytes.len().min(255);
            buf.put_u8(dlen as u8);
            buf.put_slice(&bytes[..dlen]);
            buf.put_u16(*port);
        }
    }
    let p_len = packet.payload.len().min(65535);
    buf.put_u16(p_len as u16);
    buf.put_slice(&packet.payload[..p_len]);
    buf.freeze()
}

/// Decodes a standard VLESS UDP packet from an asynchronous stream.
pub async fn decode_vless_udp_packet<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    default_dst: &TargetAddress,
) -> FluxResult<UdpPacket> {
    use tokio::io::AsyncReadExt;
    let mut atyp_buf = [0u8; 1];
    reader
        .read_exact(&mut atyp_buf)
        .await
        .map_err(FluxError::Io)?;
    let target = crate::socks5::Socks5Handshake::read_address(reader, atyp_buf[0])
        .await
        .unwrap_or_else(|_| default_dst.clone());

    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(FluxError::Io)?;
    let payload_len = u16::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(FluxError::Io)?;

    Ok(UdpPacket::new(payload.into(), target.clone(), target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_udp_encoding_decoding() {
        let packet = UdpPacket::new(
            Bytes::from_static(b"ping"),
            "127.0.0.1:12345".parse().unwrap(),
            TargetAddress::domain("dns.google", 53),
        );

        let encoded = encode_socks5_udp(&packet);
        let decoded = decode_socks5_udp(packet.source.clone(), encoded).unwrap();

        assert_eq!(decoded.payload, Bytes::from_static(b"ping"));
        assert_eq!(decoded.destination, TargetAddress::domain("dns.google", 53));
    }

    #[test]
    fn test_trojan_udp_encoding() {
        let packet = UdpPacket::new(
            Bytes::from_static(b"trojan-payload"),
            "127.0.0.1:12345".parse().unwrap(),
            TargetAddress::domain("dns.google", 53),
        );
        let encoded = encode_trojan_udp(&packet);
        assert!(encoded.len() > 14);
    }
}
