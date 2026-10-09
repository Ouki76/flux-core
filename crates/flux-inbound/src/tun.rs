use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use flux_types::{
    Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub network: NetworkType,
    pub payload: Bytes,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_flags: u8,
}

/// Parses raw IP packets (IPv4 and IPv6) into structured session and payload metadata.
pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => None,
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 20 {
        return None;
    }

    let ihl = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ihl {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let actual_len = packet.len().min(total_len);
    if actual_len < ihl {
        return None;
    }

    let proto = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    match proto {
        17 => {
            // UDP
            if actual_len < ihl + 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
            if udp_len < 8 || actual_len < ihl + udp_len {
                return None;
            }

            let payload = Bytes::copy_from_slice(&packet[ihl + 8..ihl + udp_len]);
            Some(ParsedPacket {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                network: NetworkType::Udp,
                payload,
                tcp_seq: 0,
                tcp_ack: 0,
                tcp_flags: 0,
            })
        }
        6 => {
            // TCP
            if actual_len < ihl + 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let seq = u32::from_be_bytes([
                packet[ihl + 4],
                packet[ihl + 5],
                packet[ihl + 6],
                packet[ihl + 7],
            ]);
            let ack = u32::from_be_bytes([
                packet[ihl + 8],
                packet[ihl + 9],
                packet[ihl + 10],
                packet[ihl + 11],
            ]);
            let data_offset = (((packet[ihl + 12] >> 4) * 4) as usize).max(20);
            let flags = packet[ihl + 13];

            if actual_len < ihl + data_offset {
                return None;
            }

            let payload = Bytes::copy_from_slice(&packet[ihl + data_offset..actual_len]);
            Some(ParsedPacket {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                network: NetworkType::Tcp,
                payload,
                tcp_seq: seq,
                tcp_ack: ack,
                tcp_flags: flags,
            })
        }
        _ => None,
    }
}

fn parse_ipv6_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 40 {
        return None;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let mut next_header = packet[6];

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&packet[8..24]);
    dst_bytes.copy_from_slice(&packet[24..40]);
    let src_ip = Ipv6Addr::from(src_bytes);
    let dst_ip = Ipv6Addr::from(dst_bytes);

    let actual_len = packet.len().min(40 + payload_len);
    let mut offset = 40;

    // Traverse IPv6 Extension Headers (RFC 8200) to find the L4 protocol
    while offset < actual_len {
        match next_header {
            0 /* Hop-by-Hop Options */ | 43 /* Routing */ | 60 /* Destination Options */ => {
                if offset + 2 > actual_len {
                    return None;
                }
                let ext_next = packet[offset];
                let ext_len = (packet[offset + 1] as usize + 1) * 8;
                if offset + ext_len > actual_len {
                    return None;
                }
                offset += ext_len;
                next_header = ext_next;
            }
            44 /* Fragment */ => {
                if offset + 8 > actual_len {
                    return None;
                }
                let ext_next = packet[offset];
                offset += 8;
                next_header = ext_next;
            }
            _ => break,
        }
    }

    match next_header {
        17 => {
            // UDP
            if actual_len < offset + 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
            let udp_len = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]) as usize;
            if udp_len < 8 || actual_len < offset + udp_len {
                return None;
            }

            let payload = Bytes::copy_from_slice(&packet[offset + 8..offset + udp_len]);
            Some(ParsedPacket {
                src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                network: NetworkType::Udp,
                payload,
                tcp_seq: 0,
                tcp_ack: 0,
                tcp_flags: 0,
            })
        }
        6 => {
            // TCP
            if actual_len < offset + 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
            let seq = u32::from_be_bytes([
                packet[offset + 4],
                packet[offset + 5],
                packet[offset + 6],
                packet[offset + 7],
            ]);
            let ack = u32::from_be_bytes([
                packet[offset + 8],
                packet[offset + 9],
                packet[offset + 10],
                packet[offset + 11],
            ]);
            let data_offset = (((packet[offset + 12] >> 4) * 4) as usize).max(20);
            let flags = packet[offset + 13];

            if actual_len < offset + data_offset {
                return None;
            }

            let payload = Bytes::copy_from_slice(&packet[offset + data_offset..actual_len]);
            Some(ParsedPacket {
                src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                network: NetworkType::Tcp,
                payload,
                tcp_seq: seq,
                tcp_ack: ack,
                tcp_flags: flags,
            })
        }
        _ => None,
    }
}

/// Builds an IPv4 or IPv6 UDP packet with IP checksum.
pub fn build_ip_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => build_ipv4_udp_packet(src, dst, payload),
        (SocketAddr::V6(_), SocketAddr::V6(_)) => build_ipv6_udp_packet(src, dst, payload),
        _ => None,
    }
}

/// Builds an IPv4 UDP packet with IP checksum.
pub fn build_ipv4_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => return None,
    };

    let total_len = 20 + 8 + payload.len();
    if total_len > 65535 {
        return None;
    }

    let mut buf = vec![0u8; total_len];
    // IPv4 Header (20 bytes)
    buf[0] = 0x45; // Version 4, IHL 5
    buf[1] = 0x00; // DSCP / ECN
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identification
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
    buf[8] = 64; // TTL
    buf[9] = 17; // Protocol: UDP
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    // Calculate IPv4 Header Checksum
    let ip_checksum = calc_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // UDP Header (8 bytes)
    buf[20..22].copy_from_slice(&src.port().to_be_bytes());
    buf[22..24].copy_from_slice(&dst.port().to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
    buf[26..28].copy_from_slice(&0u16.to_be_bytes()); // Checksum optional for IPv4 UDP

    // Payload
    buf[28..].copy_from_slice(payload);

    Some(buf)
}

/// Builds an IPv6 UDP packet.
pub fn build_ipv6_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => return None,
    };

    let udp_len = 8 + payload.len();
    let total_len = 40 + udp_len;
    if total_len > 65535 {
        return None;
    }

    let mut buf = vec![0u8; total_len];
    buf[0] = 0x60;
    buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[6] = 17; // Next Header: UDP
    buf[7] = 64; // Hop Limit

    buf[8..24].copy_from_slice(&src_ip.octets());
    buf[24..40].copy_from_slice(&dst_ip.octets());

    buf[40..42].copy_from_slice(&src.port().to_be_bytes());
    buf[42..44].copy_from_slice(&dst.port().to_be_bytes());
    buf[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[46..48].copy_from_slice(&0u16.to_be_bytes());

    buf[48..].copy_from_slice(payload);

    // RFC 8200 §8.1: IPv6 UDP checksum is mandatory
    calc_udp_checksum_ipv6(src_ip, dst_ip, &mut buf[40..]);
    Some(buf)
}

fn calc_udp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, udp_segment: &mut [u8]) {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += (udp_segment.len() as u32) >> 16;
    sum += (udp_segment.len() as u32) & 0xFFFF;
    sum += 17u32; // Next Header: UDP

    udp_segment[6] = 0;
    udp_segment[7] = 0;
    for chunk in udp_segment.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let final_csum = if csum == 0 { 0xFFFF } else { csum };
    udp_segment[6..8].copy_from_slice(&final_csum.to_be_bytes());
}

/// Builds an IPv4 or IPv6 TCP packet with correct IP and TCP checksums.
pub fn build_ip_tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => {
            build_ipv4_tcp_packet(src, dst, seq, ack, flags, payload)
        }
        (SocketAddr::V6(_), SocketAddr::V6(_)) => {
            build_ipv6_tcp_packet(src, dst, seq, ack, flags, payload)
        }
        _ => None,
    }
}

pub fn build_ipv4_tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => return None,
    };

    let total_len = 20 + 20 + payload.len();
    if total_len > 65535 {
        return None;
    }

    let mut buf = vec![0u8; total_len];
    // IPv4 Header
    buf[0] = 0x45;
    buf[1] = 0x00;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    buf[8] = 64; // TTL
    buf[9] = 6; // Protocol: TCP
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let ip_csum = calc_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP Header
    buf[20..22].copy_from_slice(&src.port().to_be_bytes());
    buf[22..24].copy_from_slice(&dst.port().to_be_bytes());
    buf[24..28].copy_from_slice(&seq.to_be_bytes());
    buf[28..32].copy_from_slice(&ack.to_be_bytes());
    buf[32] = 0x50; // 5 x 4 = 20 bytes data offset
    buf[33] = flags;
    buf[34..36].copy_from_slice(&64240u16.to_be_bytes()); // Window Size

    if !payload.is_empty() {
        buf[40..].copy_from_slice(payload);
    }

    calc_tcp_checksum_ipv4(src_ip, dst_ip, &mut buf[20..]);
    Some(buf)
}

pub fn build_ipv6_tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
        (IpAddr::V6(s), IpAddr::V6(d)) => (s, d),
        _ => return None,
    };

    let tcp_len = 20 + payload.len();
    let total_len = 40 + tcp_len;
    if total_len > 65535 {
        return None;
    }

    let mut buf = vec![0u8; total_len];
    buf[0] = 0x60;
    buf[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    buf[6] = 6; // Next Header: TCP
    buf[7] = 64; // Hop Limit

    buf[8..24].copy_from_slice(&src_ip.octets());
    buf[24..40].copy_from_slice(&dst_ip.octets());

    // TCP Header
    buf[40..42].copy_from_slice(&src.port().to_be_bytes());
    buf[42..44].copy_from_slice(&dst.port().to_be_bytes());
    buf[44..48].copy_from_slice(&seq.to_be_bytes());
    buf[48..52].copy_from_slice(&ack.to_be_bytes());
    buf[52] = 0x50;
    buf[53] = flags;
    buf[54..56].copy_from_slice(&64240u16.to_be_bytes());

    if !payload.is_empty() {
        buf[60..].copy_from_slice(payload);
    }

    calc_tcp_checksum_ipv6(src_ip, dst_ip, &mut buf[40..]);
    Some(buf)
}

fn calc_tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &mut [u8]) {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 6u32; // Protocol TCP
    sum += tcp_segment.len() as u32;

    tcp_segment[16] = 0;
    tcp_segment[17] = 0;
    for chunk in tcp_segment.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let final_csum = if csum == 0 { 0xFFFF } else { csum };
    tcp_segment[16..18].copy_from_slice(&final_csum.to_be_bytes());
}

fn calc_tcp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, tcp_segment: &mut [u8]) {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += (tcp_segment.len() as u32) >> 16;
    sum += (tcp_segment.len() as u32) & 0xFFFF;
    sum += 6u32;

    tcp_segment[16] = 0;
    tcp_segment[17] = 0;
    for chunk in tcp_segment.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let final_csum = if csum == 0 { 0xFFFF } else { csum };
    tcp_segment[16..18].copy_from_slice(&final_csum.to_be_bytes());
}

fn calc_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Handles ICMP Echo Requests (ping) and generates matching Echo Replies.
pub fn handle_icmp_packet(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => handle_ipv4_icmp(packet),
        6 => handle_ipv6_icmp(packet),
        _ => None,
    }
}

fn handle_ipv4_icmp(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 28 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ihl + 8 || packet[9] != 1 {
        return None;
    }
    // Type 8 is Echo Request
    if packet[ihl] != 8 || packet[ihl + 1] != 0 {
        return None;
    }

    let mut reply = packet.to_vec();
    // Swap IPv4 src and dst
    let src = [packet[12], packet[13], packet[14], packet[15]];
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    reply[8] = 64; // TTL

    // Recalculate IPv4 header checksum
    reply[10] = 0;
    reply[11] = 0;
    let ip_csum = calc_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMP Echo Reply: Type 0, Code 0
    reply[ihl] = 0;
    reply[ihl + 1] = 0;
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_csum = calc_checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(reply)
}

fn handle_ipv6_icmp(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 48 || packet[6] != 58 {
        return None;
    }
    // Type 128 is Echo Request
    if packet[40] != 128 || packet[41] != 0 {
        return None;
    }

    let mut reply = packet.to_vec();
    // Swap IPv6 src and dst
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    dst.copy_from_slice(&packet[24..40]);
    reply[8..24].copy_from_slice(&dst);
    reply[24..40].copy_from_slice(&src);
    reply[7] = 64; // Hop limit

    // ICMPv6 Echo Reply: Type 129, Code 0
    reply[40] = 129;
    reply[41] = 0;

    let src_ip = Ipv6Addr::from(dst);
    let dst_ip = Ipv6Addr::from(src);

    calc_icmpv6_checksum(src_ip, dst_ip, &mut reply[40..]);
    Some(reply)
}

fn calc_icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, data: &mut [u8]) {
    data[2] = 0;
    data[3] = 0;
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = data.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += 58; // Next Header: ICMPv6

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += u16::from_be_bytes([chunk[0], 0]) as u32;
        }
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    data[2..4].copy_from_slice(&csum.to_be_bytes());
}

#[cfg(target_os = "linux")]
fn open_tun_device(name: &str) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let dev_path = std::ffi::CString::new("/dev/net/tun")?;
    let fd = unsafe {
        libc::open(
            dev_path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    #[repr(C)]
    struct ifreq {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
    }

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

    let bytes = name.as_bytes();
    let len = bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    let mut ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if ret < 0 {
        // Fallback without IFF_MULTI_QUEUE if unsupported by host kernel
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

struct TunTcpSession {
    client_seq: AtomicU32,
    server_seq: AtomicU32,
    payload_tx: tokio::sync::mpsc::Sender<Bytes>,
    last_activity: parking_lot::Mutex<std::time::Instant>,
    ooo_buffer: parking_lot::Mutex<std::collections::BTreeMap<u32, Bytes>>,
}

#[cfg(target_os = "linux")]
fn send_packet_guaranteed(tx: &tokio::sync::mpsc::Sender<Vec<u8>>, pkt: Vec<u8>) {
    match tx.try_send(pkt) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(val)) => {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let _ = tx_clone.send(val).await;
            });
        }
        Err(_) => {}
    }
}

pub struct TunInbound {
    tag: String,
    interface_name: String,
    mtu: usize,
    sessions: Arc<DashMap<(SocketAddr, SocketAddr), Arc<TunTcpSession>>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl TunInbound {
    pub fn new(
        tag: impl Into<String>,
        interface_name: impl Into<String>,
        mtu: Option<usize>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            interface_name: interface_name.into(),
            mtu: mtu.unwrap_or(1500),
            sessions: Arc::new(DashMap::new()),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }
}

#[async_trait]
impl Inbound for TunInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "tun"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.interface_name.clone())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        self.running.store(true, Ordering::SeqCst);
        let tag = self.tag.clone();
        let mtu = self.mtu;
        let ifname = self.interface_name.clone();
        let running = self.running.clone();
        let sessions = self.sessions.clone();

        #[cfg(target_os = "linux")]
        {
            match open_tun_device(&ifname) {
                Ok(owned_fd) => {
                    info!(
                        "[{}] TUN interface '{}' opened successfully (MTU: {})",
                        tag, ifname, mtu
                    );
                    let async_fd = match tokio::io::unix::AsyncFd::new(owned_fd) {
                        Ok(afd) => Arc::new(afd),
                        Err(e) => {
                            tracing::error!("[{}] failed to register TUN AsyncFd: {}", tag, e);
                            return Ok(());
                        }
                    };

                    // Dedicated single writer task to serialize all raw TUN FD writes without race conditions or dropped frames
                    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2048);
                    let afd_writer = async_fd.clone();
                    let running_writer = running.clone();
                    let mut shutdown_rx_writer = self.shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        while running_writer.load(Ordering::Relaxed) {
                            let pkt = tokio::select! {
                                _ = shutdown_rx_writer.recv() => break,
                                res = tun_rx.recv() => match res {
                                    Some(p) => p,
                                    None => break,
                                },
                            };
                            loop {
                                let mut guard = match afd_writer.writable().await {
                                    Ok(g) => g,
                                    Err(_) => break,
                                };
                                match guard.try_io(|inner| {
                                    use std::os::fd::AsRawFd;
                                    let res = unsafe {
                                        libc::write(
                                            inner.as_raw_fd(),
                                            pkt.as_ptr() as *const libc::c_void,
                                            pkt.len(),
                                        )
                                    };
                                    if res < 0 {
                                        Err(std::io::Error::last_os_error())
                                    } else {
                                        Ok(res as usize)
                                    }
                                }) {
                                    Ok(_) => break,
                                    Err(_would_block) => continue,
                                }
                            }
                        }
                    });

                    // Background TCP session reaper to prevent memory leaks from abandoned half-open connections
                    let sessions_reaper = sessions.clone();
                    let running_reaper = running.clone();
                    let mut shutdown_rx_reaper = self.shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        let mut interval =
                            tokio::time::interval(std::time::Duration::from_secs(30));
                        while running_reaper.load(Ordering::Relaxed) {
                            tokio::select! {
                                _ = shutdown_rx_reaper.recv() => break,
                                _ = interval.tick() => {}
                            }
                            let now = std::time::Instant::now();
                            sessions_reaper.retain(|_, s| {
                                now.duration_since(*s.last_activity.lock())
                                    < std::time::Duration::from_secs(120)
                            });
                        }
                    });

                    let tag_clone: Arc<str> = Arc::from(tag.as_str());
                    let udp_sessions: Arc<
                        DashMap<(SocketAddr, SocketAddr), tokio::sync::mpsc::Sender<UdpPacket>>,
                    > = Arc::new(DashMap::new());
                    let mut shutdown_rx_reader = self.shutdown_tx.subscribe();

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; mtu + 64];

                        while running.load(Ordering::Relaxed) {
                            let mut guard = tokio::select! {
                                _ = shutdown_rx_reader.recv() => break,
                                res = async_fd.readable() => match res {
                                    Ok(g) => g,
                                    Err(_) => break,
                                },
                            };

                            let n = match guard.try_io(|inner| {
                                use std::os::fd::AsRawFd;
                                let res = unsafe {
                                    libc::read(
                                        inner.as_raw_fd(),
                                        buf.as_mut_ptr() as *mut libc::c_void,
                                        buf.len(),
                                    )
                                };
                                if res < 0 {
                                    Err(std::io::Error::last_os_error())
                                } else {
                                    Ok(res as usize)
                                }
                            }) {
                                Ok(Ok(n)) => n,
                                Ok(Err(_)) => continue,
                                Err(_would_block) => continue,
                            };

                            if let Some(icmp_reply) = handle_icmp_packet(&buf[..n]) {
                                let _ = tun_tx.try_send(icmp_reply);
                                continue;
                            }

                            let Some(parsed) = parse_ip_packet(&buf[..n]) else {
                                continue;
                            };

                            if parsed.network == NetworkType::Udp {
                                let pkt = UdpPacket::new(
                                    parsed.payload,
                                    TargetAddress::Ip(parsed.src),
                                    TargetAddress::Ip(parsed.dst),
                                );

                                let udp_key = (parsed.src, parsed.dst);
                                if let Some(tx) = udp_sessions.get(&udp_key) {
                                    let _ = tx.try_send(pkt);
                                } else {
                                    let (pkt_tx, pkt_rx) =
                                        tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let (out_tx, mut out_rx) =
                                        tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let disp = dispatcher.clone();
                                    let meta = SessionMeta::new(
                                        parsed.src,
                                        TargetAddress::Ip(parsed.dst),
                                        tag_clone.clone(),
                                        NetworkType::Udp,
                                    );

                                    tokio::spawn(async move {
                                        disp.dispatch_packet(meta, pkt_rx, out_tx).await;
                                    });

                                    let _ = pkt_tx.try_send(pkt);
                                    udp_sessions.insert(udp_key, pkt_tx.clone());

                                    let tun_tx_udp = tun_tx.clone();
                                    let udp_sessions_clean = udp_sessions.clone();
                                    let orig_src = parsed.dst;
                                    let orig_dst = parsed.src;

                                    tokio::spawn(async move {
                                        loop {
                                            match tokio::time::timeout(
                                                std::time::Duration::from_secs(30),
                                                out_rx.recv(),
                                            )
                                            .await
                                            {
                                                Ok(Some(reply)) => {
                                                    if let Some(ip_pkt) = build_ip_udp_packet(
                                                        orig_src,
                                                        orig_dst,
                                                        &reply.payload,
                                                    ) {
                                                        let _ = tun_tx_udp.send(ip_pkt).await;
                                                    }
                                                }
                                                _ => {
                                                    udp_sessions_clean.remove(&udp_key);
                                                    break;
                                                }
                                            }
                                        }
                                    });
                                }
                            } else if parsed.network == NetworkType::Tcp {
                                let key = (parsed.src, parsed.dst);

                                // Check for SYN (new connection request)
                                if (parsed.tcp_flags & TCP_SYN != 0)
                                    && (parsed.tcp_flags & TCP_ACK == 0)
                                {
                                    if let Some(existing) = sessions.get(&key) {
                                        // Duplicate SYN: retransmit SYN-ACK without spawning duplicate sessions
                                        let s_seq = existing
                                            .server_seq
                                            .load(Ordering::Relaxed)
                                            .wrapping_sub(1);
                                        let c_ack = existing.client_seq.load(Ordering::Relaxed);
                                        if let Some(syn_ack) = build_ip_tcp_packet(
                                            parsed.dst,
                                            parsed.src,
                                            s_seq,
                                            c_ack,
                                            TCP_SYN | TCP_ACK,
                                            &[],
                                        ) {
                                            send_packet_guaranteed(&tun_tx, syn_ack);
                                        }
                                        continue;
                                    }

                                    let isn_s = rand::random::<u32>();
                                    let isn_c = parsed.tcp_seq;
                                    let (tx_payload, mut rx_payload) =
                                        tokio::sync::mpsc::channel::<Bytes>(128);

                                    let session = Arc::new(TunTcpSession {
                                        client_seq: AtomicU32::new(isn_c.wrapping_add(1)),
                                        server_seq: AtomicU32::new(isn_s.wrapping_add(1)),
                                        payload_tx: tx_payload,
                                        last_activity: parking_lot::Mutex::new(
                                            std::time::Instant::now(),
                                        ),
                                        ooo_buffer: parking_lot::Mutex::new(
                                            std::collections::BTreeMap::new(),
                                        ),
                                    });
                                    sessions.insert(key, session.clone());

                                    // Reply with SYN-ACK through serialized writer channel
                                    if let Some(syn_ack) = build_ip_tcp_packet(
                                        parsed.dst,
                                        parsed.src,
                                        isn_s,
                                        isn_c.wrapping_add(1),
                                        TCP_SYN | TCP_ACK,
                                        &[],
                                    ) {
                                        send_packet_guaranteed(&tun_tx, syn_ack);
                                    }

                                    // Create duplex bridge to Dispatcher
                                    let (client_io, proxy_io) = tokio::io::duplex(64 * 1024);
                                    let (mut client_read, mut client_write) =
                                        tokio::io::split(client_io);
                                    let meta = SessionMeta::new(
                                        parsed.src,
                                        TargetAddress::Ip(parsed.dst),
                                        tag_clone.clone(),
                                        NetworkType::Tcp,
                                    );
                                    let disp = dispatcher.clone();
                                    tokio::spawn(async move {
                                        disp.dispatch_stream(meta, Box::new(proxy_io)).await;
                                    });

                                    // Forward incoming payload from client to proxy_io
                                    tokio::spawn(async move {
                                        while let Some(chunk) = rx_payload.recv().await {
                                            if client_write.write_all(&chunk).await.is_err() {
                                                break;
                                            }
                                        }
                                    });

                                    // Read reply from proxy_io, segment by MSS, and write via tun_tx
                                    let tun_tx_tcp = tun_tx.clone();
                                    let s_clone = session.clone();
                                    let orig_src = parsed.dst;
                                    let orig_dst = parsed.src;
                                    let sessions_cleanup = sessions.clone();
                                    tokio::spawn(async move {
                                        let mss = if orig_dst.is_ipv6() {
                                            mtu.saturating_sub(60).max(512)
                                        } else {
                                            mtu.saturating_sub(40).max(512)
                                        };
                                        let mut r_guard =
                                            flux_common::BufferPool::default_pool().acquire_guard();
                                        let r_buf = &mut *r_guard;
                                        loop {
                                            match client_read.read(r_buf).await {
                                                Ok(0) => {
                                                    // Send FIN-ACK
                                                    let s_seq =
                                                        s_clone.server_seq.load(Ordering::Relaxed);
                                                    let c_ack =
                                                        s_clone.client_seq.load(Ordering::Relaxed);
                                                    if let Some(fin_pkt) = build_ip_tcp_packet(
                                                        orig_src,
                                                        orig_dst,
                                                        s_seq,
                                                        c_ack,
                                                        TCP_FIN | TCP_ACK,
                                                        &[],
                                                    ) {
                                                        let _ = tun_tx_tcp.send(fin_pkt).await;
                                                    }
                                                    // Retain session briefly (5s TIME_WAIT) to absorb final client ACK/RST
                                                    tokio::spawn(async move {
                                                        tokio::time::sleep(
                                                            std::time::Duration::from_secs(5),
                                                        )
                                                        .await;
                                                        sessions_cleanup.remove(&key);
                                                    });
                                                    break;
                                                }
                                                Ok(n) => {
                                                    // Segment by MTU / MSS to prevent EMSGSIZE errors on TUN device
                                                    for chunk in r_buf[..n].chunks(mss) {
                                                        let s_seq = s_clone.server_seq.fetch_add(
                                                            chunk.len() as u32,
                                                            Ordering::SeqCst,
                                                        );
                                                        let c_ack = s_clone
                                                            .client_seq
                                                            .load(Ordering::Relaxed);
                                                        if let Some(tcp_pkt) = build_ip_tcp_packet(
                                                            orig_src,
                                                            orig_dst,
                                                            s_seq,
                                                            c_ack,
                                                            TCP_ACK | TCP_PSH,
                                                            chunk,
                                                        ) {
                                                            let _ = tun_tx_tcp.send(tcp_pkt).await;
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    sessions_cleanup.remove(&key);
                                                    break;
                                                }
                                            }
                                        }
                                    });
                                } else if let Some(session) = sessions.get(&key) {
                                    // Established session
                                    if parsed.tcp_flags & TCP_FIN != 0 {
                                        let s_seq = session.server_seq.load(Ordering::Relaxed);
                                        let c_ack = parsed.tcp_seq.wrapping_add(1);
                                        if let Some(fin_ack) = build_ip_tcp_packet(
                                            parsed.dst,
                                            parsed.src,
                                            s_seq,
                                            c_ack,
                                            TCP_FIN | TCP_ACK,
                                            &[],
                                        ) {
                                            send_packet_guaranteed(&tun_tx, fin_ack);
                                        }
                                        sessions.remove(&key);
                                    } else if parsed.tcp_flags & TCP_RST != 0 {
                                        sessions.remove(&key);
                                    } else if !parsed.payload.is_empty() {
                                        *session.last_activity.lock() = std::time::Instant::now();
                                        let mut expected_seq =
                                            session.client_seq.load(Ordering::Relaxed);
                                        let payload_len = parsed.payload.len() as u32;
                                        let s_seq = session.server_seq.load(Ordering::Relaxed);

                                        if parsed.tcp_seq == expected_seq {
                                            match session.payload_tx.try_send(parsed.payload) {
                                                Ok(()) => {
                                                    expected_seq =
                                                        expected_seq.wrapping_add(payload_len);
                                                }
                                                Err(
                                                    tokio::sync::mpsc::error::TrySendError::Full(_),
                                                ) => {
                                                    tracing::debug!(
                                                        "TUN TCP session buffer full for {:?}",
                                                        key
                                                    );
                                                }
                                                Err(_) => {}
                                            }

                                            // Drain contiguous out-of-order segments
                                            let mut ooo = session.ooo_buffer.lock();
                                            while let Some(entry) = ooo.first_entry() {
                                                if *entry.key() == expected_seq {
                                                    // Peek before removing to prevent silent drop if channel is full
                                                    if session.payload_tx.capacity() == 0 {
                                                        break;
                                                    }
                                                    let next_chunk = entry.remove();
                                                    let next_len = next_chunk.len() as u32;
                                                    let _ = session.payload_tx.try_send(next_chunk);
                                                    expected_seq =
                                                        expected_seq.wrapping_add(next_len);
                                                } else {
                                                    break;
                                                }
                                            }
                                            session
                                                .client_seq
                                                .store(expected_seq, Ordering::SeqCst);
                                        } else if (parsed.tcp_seq.wrapping_sub(expected_seq) as i32)
                                            > 0
                                        {
                                            // Buffer out-of-order packet (up to 32 segments) using RFC 793 serial number arithmetic
                                            let mut ooo = session.ooo_buffer.lock();
                                            if ooo.len() < 32 {
                                                ooo.insert(parsed.tcp_seq, parsed.payload);
                                            }
                                        }

                                        // Send ACK to client via non-blocking serialized writer channel
                                        if let Some(ack_pkt) = build_ip_tcp_packet(
                                            parsed.dst,
                                            parsed.src,
                                            s_seq,
                                            expected_seq,
                                            TCP_ACK,
                                            &[],
                                        ) {
                                            send_packet_guaranteed(&tun_tx, ack_pkt);
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "[{}] TUN device '{}' could not be opened (CAP_NET_ADMIN / root required: {}). TUN mode will remain passive.",
                        tag,
                        ifname,
                        e
                    );
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::info!(
                "[{}] TUN interface configured on non-Linux OS: {}",
                tag,
                ifname
            );
        }

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        self.sessions.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_build_ipv4_udp() {
        let src: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let payload = b"ping dns";

        let raw = build_ipv4_udp_packet(src, dst, payload).unwrap();
        assert_eq!(raw.len(), 20 + 8 + payload.len());

        let parsed = parse_ip_packet(&raw).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.network, NetworkType::Udp);
        assert_eq!(&parsed.payload[..], payload);
    }

    #[test]
    fn test_parse_and_build_ipv6_udp() {
        let src: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let dst: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        let payload = b"ping ipv6 dns";

        let raw = build_ipv6_udp_packet(src, dst, payload).unwrap();
        assert_eq!(raw.len(), 40 + 8 + payload.len());

        let parsed = parse_ip_packet(&raw).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.network, NetworkType::Udp);
        assert_eq!(&parsed.payload[..], payload);
    }

    #[test]
    fn test_parse_and_build_ipv4_tcp() {
        let src: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let payload = b"GET / HTTP/1.1\r\n\r\n";

        let raw = build_ipv4_tcp_packet(src, dst, 1000, 2000, TCP_ACK | TCP_PSH, payload).unwrap();
        assert_eq!(raw.len(), 20 + 20 + payload.len());

        let parsed = parse_ip_packet(&raw).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.network, NetworkType::Tcp);
        assert_eq!(parsed.tcp_seq, 1000);
        assert_eq!(parsed.tcp_ack, 2000);
        assert_eq!(parsed.tcp_flags, TCP_ACK | TCP_PSH);
        assert_eq!(&parsed.payload[..], payload);
    }

    #[test]
    fn test_parse_and_build_ipv6_tcp() {
        let src: SocketAddr = "[2001:db8::1]:54321".parse().unwrap();
        let dst: SocketAddr = "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap();
        let payload = b"ClientHello TLS";

        let raw = build_ipv6_tcp_packet(src, dst, 5000, 6000, TCP_SYN, payload).unwrap();
        assert_eq!(raw.len(), 40 + 20 + payload.len());

        let parsed = parse_ip_packet(&raw).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.network, NetworkType::Tcp);
        assert_eq!(parsed.tcp_seq, 5000);
        assert_eq!(parsed.tcp_ack, 6000);
        assert_eq!(parsed.tcp_flags, TCP_SYN);
        assert_eq!(&parsed.payload[..], payload);
    }

    #[test]
    fn test_icmpv4_echo_reply() {
        // Construct IPv4 ICMP Echo Request (Type 8)
        let mut req = vec![
            0x45, 0x00, 0x00, 0x1c, // IPv4 header: len 28
            0x00, 0x00, 0x40, 0x00, 64, 1, 0x00, 0x00, // TTL 64, Proto 1 (ICMP), csum
            192, 168, 1, 100, // src: 192.168.1.100
            8, 8, 8, 8, // dst: 8.8.8.8
            8, 0, 0x00, 0x00, // ICMP Type 8 (Echo), Code 0, csum
            0x12, 0x34, 0x00, 0x01, // ID, Seq
        ];
        let ip_csum = calc_checksum(&req[..20]);
        req[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        let icmp_csum = calc_checksum(&req[20..]);
        req[22..24].copy_from_slice(&icmp_csum.to_be_bytes());

        let reply = handle_icmp_packet(&req).expect("should handle ICMP echo");
        // Verify reply is IPv4, length 28
        assert_eq!(reply.len(), 28);
        // Verify src and dst are swapped
        assert_eq!(&reply[12..16], &[8, 8, 8, 8]);
        assert_eq!(&reply[16..20], &[192, 168, 1, 100]);
        // Verify ICMP Type 0 (Echo Reply), Code 0
        assert_eq!(reply[20], 0);
        assert_eq!(reply[21], 0);
        // Verify ID and Seq preserved
        assert_eq!(&reply[24..28], &[0x12, 0x34, 0x00, 0x01]);
    }

    #[test]
    fn test_icmpv6_echo_reply() {
        // Construct IPv6 ICMPv6 Echo Request (Type 128)
        let mut req = vec![0u8; 48];
        req[0] = 0x60; // IPv6
        req[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload len 8
        req[6] = 58; // Next Header: ICMPv6
        req[7] = 64; // Hop limit
        req[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        req[24..40].copy_from_slice(&[
            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ]); // dst
        req[40] = 128; // Type 128 Echo Request
        req[41] = 0; // Code 0
        req[44..48].copy_from_slice(&[0xaa, 0xbb, 0x00, 0x01]); // ID, Seq

        let reply = handle_icmp_packet(&req).expect("should handle ICMPv6 echo");
        assert_eq!(reply.len(), 48);
        assert_eq!(&reply[8..24], &req[24..40]); // src is old dst
        assert_eq!(&reply[24..40], &req[8..24]); // dst is old src
        assert_eq!(reply[40], 129); // Type 129 Echo Reply
        assert_eq!(reply[41], 0);
        assert_eq!(&reply[44..48], &[0xaa, 0xbb, 0x00, 0x01]);
    }

    #[test]
    fn test_tun_tcp_out_of_order_reassembly_and_wrap() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let session = TunTcpSession {
            client_seq: AtomicU32::new(100),
            server_seq: AtomicU32::new(500),
            payload_tx: tx,
            last_activity: parking_lot::Mutex::new(std::time::Instant::now()),
            ooo_buffer: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
        };

        // Scenario: Packet with seq 110 (len 10) arrives BEFORE packet with seq 100 (len 10)
        let chunk_ooo = Bytes::from_static(b"WORLD_1234");
        let chunk_in_order = Bytes::from_static(b"HELLO_1234");

        // 1. Process out-of-order segment 110
        let expected_seq = session.client_seq.load(Ordering::Relaxed);
        assert_eq!(expected_seq, 100);
        let seq_110 = 110u32;
        if (seq_110.wrapping_sub(expected_seq) as i32) > 0 {
            session.ooo_buffer.lock().insert(seq_110, chunk_ooo);
        }

        // Verify buffer has 1 entry and rx hasn't received anything
        assert_eq!(session.ooo_buffer.lock().len(), 1);
        assert!(rx.try_recv().is_err());

        // 2. Process in-order segment 100
        let seq_100 = 100u32;
        let mut curr_expected = session.client_seq.load(Ordering::Relaxed);
        assert_eq!(seq_100, curr_expected);

        session.payload_tx.try_send(chunk_in_order).unwrap();
        curr_expected = curr_expected.wrapping_add(10);

        // Drain contiguous segments
        let mut ooo = session.ooo_buffer.lock();
        while let Some(entry) = ooo.first_entry() {
            if *entry.key() == curr_expected {
                let next_chunk = entry.remove();
                let next_len = next_chunk.len() as u32;
                session.payload_tx.try_send(next_chunk).unwrap();
                curr_expected = curr_expected.wrapping_add(next_len);
            } else {
                break;
            }
        }
        drop(ooo);
        session.client_seq.store(curr_expected, Ordering::SeqCst);

        // Verify client_seq advanced to 120 (100 + 10 + 10)
        assert_eq!(session.client_seq.load(Ordering::Relaxed), 120);

        // Verify rx received both segments in strictly correct order: "HELLO_1234" then "WORLD_1234"
        let p1 = rx.try_recv().unwrap();
        assert_eq!(&p1[..], b"HELLO_1234");
        let p2 = rx.try_recv().unwrap();
        assert_eq!(&p2[..], b"WORLD_1234");
    }
}
