use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flux_types::{FluxError, FluxResult, TargetAddress, UdpPacket};
use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

/// Encodes a UdpPacket into a SOCKS5 UDP datagram.
pub fn encode_socks5_udp(packet: &UdpPacket) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + packet.payload.len());
    buf.put_u16(0x0000); // RSV
    buf.put_u8(0x00);   // FRAG

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
            buf.put_u8(bytes.len() as u8);
            buf.put_slice(bytes);
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
            let domain = String::from_utf8(domain_bytes.to_vec()).map_err(|e| {
                FluxError::Protocol {
                    protocol: "socks5-udp",
                    message: format!("invalid utf-8 domain: {}", e),
                }
            })?;
            TargetAddress::Domain(domain, port)
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
}
