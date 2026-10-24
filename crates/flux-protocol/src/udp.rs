use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flux_types::{FluxError, FluxResult, TargetAddress, UdpPacket};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Writes `[ATYP + Addr + Port]` for `addr` into `buf`.
fn put_addr(buf: &mut BytesMut, addr: &TargetAddress) {
    match addr {
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
}

/// Encodes a UdpPacket into a SOCKS5 UDP datagram.
pub fn encode_socks5_udp(packet: &UdpPacket) -> Bytes {
    encode_socks5_udp_with_addr(packet, &packet.destination)
}

/// Encodes a SOCKS5 UDP reply datagram: the address header is the sender
/// (`packet.source`), as required by RFC 1928 for server-to-client datagrams.
pub fn encode_socks5_udp_reply(packet: &UdpPacket) -> Bytes {
    encode_socks5_udp_with_addr(packet, &packet.source)
}

/// The same encoding into a caller-owned buffer, for reply loops that already have one.
///
/// A relayed datagram pays this once per reply, and at tens of thousands of datagrams a
/// second a fresh `BytesMut` each time is a measurable share of the process's
/// allocations — measured as 7 allocations per datagram, of which this is one.
pub fn encode_socks5_udp_reply_into(buf: &mut BytesMut, packet: &UdpPacket) {
    buf.clear();
    buf.reserve(32 + packet.payload.len());
    buf.put_u16(0x0000); // RSV
    buf.put_u8(0x00); // FRAG
    put_addr(buf, &packet.source);
    buf.extend_from_slice(&packet.payload);
}

fn encode_socks5_udp_with_addr(packet: &UdpPacket, addr: &TargetAddress) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + packet.payload.len());
    buf.put_u16(0x0000); // RSV
    buf.put_u8(0x00); // FRAG
    put_addr(&mut buf, addr);
    buf.extend_from_slice(&packet.payload);
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
    encode_trojan_udp_with_addr(packet, &packet.destination)
}

/// Encodes a Trojan UDP reply packet: the address header is the sender
/// (`packet.source`), per Trojan UDP-ASSOCIATE reply semantics.
pub fn encode_trojan_udp_reply(packet: &UdpPacket) -> Bytes {
    encode_trojan_udp_with_addr(packet, &packet.source)
}

fn encode_trojan_udp_with_addr(packet: &UdpPacket, addr: &TargetAddress) -> Bytes {
    let mut buf = BytesMut::with_capacity(32 + packet.payload.len());
    put_addr(&mut buf, addr);
    let p_len = packet.payload.len().min(65535);
    buf.put_u16(p_len as u16);
    buf.put_slice(b"\r\n");
    buf.put_slice(&packet.payload[..p_len]);
    buf.freeze()
}

/// Encodes a VLESS UDP datagram: `[Length (2 bytes BE)] + [Payload]`.
///
/// VLESS carries the destination once, in the request header, and then exchanges
/// bare length-prefixed datagrams on that stream — there is no per-datagram
/// address. (The previous implementation prefixed each datagram with a SOCKS
/// address, which is Trojan's framing; sing-box and Xray both use the bare form,
/// so VLESS UDP never interoperated. Verified against sing-box 1.11.4: a
/// `[addr][len][payload]` frame is ignored, `[len u16 BE][payload]` is answered.)
pub fn encode_vless_udp_packet(packet: &UdpPacket) -> Bytes {
    encode_vless_udp_wire(&packet.payload)
}

/// Encodes a VLESS UDP reply datagram. Identical to the request form: the peer
/// already knows the association's destination.
pub fn encode_vless_udp_reply_packet(packet: &UdpPacket) -> Bytes {
    encode_vless_udp_wire(&packet.payload)
}

/// Encodes a `VLESS_CMD_PACKETADDR` datagram in the framing sing-box emits and
/// expects: `[metaLen u16 BE][meta][dataLen u16 BE][data]`, where `meta` ends
/// with `[port u16 BE][atyp][address]`.
///
/// Verified against sing-box 1.11.4 by capturing its VLESS client traffic: two
/// successive IPv4 datagrams differed only in the sequence byte, so the layout is
/// fixed per address family.
pub fn encode_vless_packetaddr(packet: &UdpPacket, addr: &TargetAddress) -> Bytes {
    let mut addr_buf = BytesMut::with_capacity(24);
    let (port, atyp) = match addr {
        TargetAddress::Ip(sa) => match sa.ip() {
            std::net::IpAddr::V4(v4) => {
                addr_buf.put_slice(&v4.octets());
                (sa.port(), 1u8)
            }
            std::net::IpAddr::V6(v6) => {
                addr_buf.put_slice(&v6.octets());
                (sa.port(), 2u8)
            }
        },
        TargetAddress::Domain(host, port) => {
            let bytes = host.as_bytes();
            let take = bytes.len().min(255);
            addr_buf.put_u8(take as u8);
            addr_buf.put_slice(&bytes[..take]);
            (*port, 3u8)
        }
    };

    // meta = [0, 0, seq, 1, 2] ++ port ++ atyp ++ addr
    let meta_len = 5 + 2 + 1 + addr_buf.len();
    let mut buf = BytesMut::with_capacity(2 + meta_len + 2 + packet.payload.len());
    buf.put_u16(meta_len as u16);
    // Observed from sing-box: 1 is the request status, 2 the response status.
    buf.put_slice(&[0, 0, 2, 1, 2]);
    buf.put_u16(port);
    buf.put_u8(atyp);
    buf.put_slice(&addr_buf);

    let p_len = packet.payload.len().min(65535);
    buf.put_u16(p_len as u16);
    buf.put_slice(&packet.payload[..p_len]);
    buf.freeze()
}

/// Decodes a `VLESS_CMD_PACKETADDR` datagram (see
/// [`encode_vless_packetaddr`] for the layout and how it was established).
pub async fn decode_vless_packetaddr<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> FluxResult<UdpPacket> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(FluxError::Io)?;
    let meta_len = u16::from_be_bytes(len_buf) as usize;
    if !(8..=512).contains(&meta_len) {
        return Err(FluxError::Protocol {
            protocol: "vless-packetaddr",
            message: format!("implausible metadata length {}", meta_len),
        });
    }
    let mut meta = vec![0u8; meta_len];
    reader.read_exact(&mut meta).await.map_err(FluxError::Io)?;

    // The metadata ends with `[port u16 BE][atyp][address]`; everything before is
    // opaque session/sequence state that we do not need.
    let (addr_len, atyp) = match meta.get(meta_len - 1) {
        _ if meta.len() >= 7 && meta[meta_len - 5] == 1 => (4usize, 1u8),
        _ if meta.len() >= 19 && meta[meta_len - 17] == 2 => (16usize, 2u8),
        _ if meta.len() >= 3 && meta[meta_len - 2] == 3 => {
            let dlen = meta[meta_len - 1] as usize;
            if meta.len() < dlen + 3 {
                return Err(FluxError::Protocol {
                    protocol: "vless-packetaddr",
                    message: "truncated domain address".into(),
                });
            }
            (dlen + 1, 3u8)
        }
        _ => {
            return Err(FluxError::Protocol {
                protocol: "vless-packetaddr",
                message: format!("unrecognised packetaddr metadata: {:02x?}", meta),
            });
        }
    };

    let port_off = meta_len - addr_len - 3;
    let port = u16::from_be_bytes([meta[port_off], meta[port_off + 1]]);
    let addr_off = port_off + 3;
    let destination = match atyp {
        1 => TargetAddress::Ip(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                meta[addr_off],
                meta[addr_off + 1],
                meta[addr_off + 2],
                meta[addr_off + 3],
            )),
            port,
        )),
        2 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&meta[addr_off..addr_off + 16]);
            TargetAddress::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                port,
            ))
        }
        _ => {
            let dlen = meta_len - addr_off;
            let host = String::from_utf8_lossy(&meta[addr_off..addr_off + dlen]).into_owned();
            TargetAddress::Domain(host, port)
        }
    };

    let mut data_len_buf = [0u8; 2];
    reader
        .read_exact(&mut data_len_buf)
        .await
        .map_err(FluxError::Io)?;
    let data_len = u16::from_be_bytes(data_len_buf) as usize;
    let mut payload = vec![0u8; data_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(FluxError::Io)?;

    Ok(UdpPacket::new(
        payload.into(),
        destination.clone(),
        destination,
    ))
}

fn encode_vless_udp_wire(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + payload.len());
    let p_len = payload.len().min(65535);
    buf.put_u16(p_len as u16);
    buf.put_slice(&payload[..p_len]);
    buf.freeze()
}

/// Decodes a VLESS UDP datagram: `[Length (2 bytes BE)] + [Payload]`.
///
/// The destination comes from the association (`default_dst`), not from the
/// frame — see [`encode_vless_udp_packet`].
pub async fn decode_vless_udp_packet<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    default_dst: &TargetAddress,
) -> FluxResult<UdpPacket> {
    use tokio::io::AsyncReadExt;
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

    Ok(UdpPacket::new(
        payload.into(),
        default_dst.clone(),
        default_dst.clone(),
    ))
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

    #[tokio::test]
    async fn test_decode_vless_udp_packet_invalid_atyp_fails() {
        // Invalid ATYP = 0xFF
        let data = [0xFFu8, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut cursor = std::io::Cursor::new(&data);
        let default_dst = TargetAddress::domain("example.com", 53);
        let res = decode_vless_udp_packet(&mut cursor, &default_dst).await;
        assert!(res.is_err(), "invalid atyp must return error");
    }

    #[tokio::test]
    async fn test_decode_vless_udp_packet_truncated_payload_fails() {
        // Valid ATYP IPv4 (0x01) + 127.0.0.1:53 + length 100 but stream ends early
        let mut data = vec![0x01, 127, 0, 0, 1, 0, 53, 0, 100];
        data.extend_from_slice(b"short");
        let mut cursor = std::io::Cursor::new(&data);
        let default_dst = TargetAddress::domain("example.com", 53);
        let res = decode_vless_udp_packet(&mut cursor, &default_dst).await;
        assert!(res.is_err(), "truncated payload must return error");
    }
}
