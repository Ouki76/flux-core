use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use bytes::Bytes;
use async_trait::async_trait;
use tracing::info;
use flux_types::{
    Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub network: NetworkType,
    pub payload: Bytes,
}

/// Parses raw IP packets into structured session and payload metadata.
pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    if version == 4 {
        parse_ipv4_packet(packet)
    } else {
        None
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
            })
        }
        6 => {
            // TCP
            if actual_len < ihl + 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let data_offset = (((packet[ihl + 12] >> 4) * 4) as usize).max(20);
            if actual_len < ihl + data_offset {
                return None;
            }

            let payload = Bytes::copy_from_slice(&packet[ihl + data_offset..actual_len]);
            Some(ParsedPacket {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                network: NetworkType::Tcp,
                payload,
            })
        }
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
    buf[8] = 64;   // TTL
    buf[9] = 17;   // Protocol: UDP
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

#[cfg(target_os = "linux")]
fn open_tun_device(name: &str) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let dev_path = std::ffi::CString::new("/dev/net/tun")?;
    let fd = unsafe { libc::open(dev_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
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
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    let bytes = name.as_bytes();
    let len = bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

pub struct TunInbound {
    tag: String,
    interface_name: String,
    mtu: usize,
    running: Arc<AtomicBool>,
}

impl TunInbound {
    pub fn new(tag: impl Into<String>, interface_name: impl Into<String>, mtu: Option<usize>) -> Self {
        Self {
            tag: tag.into(),
            interface_name: interface_name.into(),
            mtu: mtu.unwrap_or(1500),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for TunInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        self.running.store(true, Ordering::SeqCst);
        let tag = self.tag.clone();
        let mtu = self.mtu;
        let ifname = self.interface_name.clone();
        let running = self.running.clone();

        #[cfg(target_os = "linux")]
        {
            match open_tun_device(&ifname) {
                Ok(owned_fd) => {
                    info!("[{}] TUN interface '{}' opened successfully (MTU: {})", tag, ifname, mtu);
                    let async_fd = match tokio::io::unix::AsyncFd::new(owned_fd) {
                        Ok(afd) => Arc::new(afd),
                        Err(e) => {
                            tracing::error!("[{}] failed to register TUN AsyncFd: {}", tag, e);
                            return Ok(());
                        }
                    };

                    let tag_clone: Arc<str> = Arc::from(tag.as_str());
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; mtu + 64];
                        while running.load(Ordering::Relaxed) {
                            let mut guard = match async_fd.readable().await {
                                Ok(g) => g,
                                Err(_) => break,
                            };

                            let n = match guard.try_io(|inner| {
                                use std::os::fd::AsRawFd;
                                let res = unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
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

                            if let Some(parsed) = parse_ip_packet(&buf[..n])
                                && parsed.network == NetworkType::Udp
                            {
                                let meta = SessionMeta::new(
                                    parsed.src,
                                    TargetAddress::Ip(parsed.dst),
                                    tag_clone.clone(),
                                    NetworkType::Udp,
                                );

                                    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let disp = dispatcher.clone();
                                    tokio::spawn(async move {
                                        disp.dispatch_packet(meta, pkt_rx, out_tx).await;
                                    });

                                    let _ = pkt_tx.send(UdpPacket::new(
                                        parsed.payload,
                                        TargetAddress::Ip(parsed.src),
                                        TargetAddress::Ip(parsed.dst),
                                    )).await;

                                    let afd_clone = async_fd.clone();
                                    let orig_src = parsed.dst;
                                    let orig_dst = parsed.src;
                                    tokio::spawn(async move {
                                        while let Some(reply) = out_rx.recv().await {
                                            if let Some(ip_pkt) = build_ipv4_udp_packet(orig_src, orig_dst, &reply.payload) {
                                                let _ = afd_clone.writable().await.map(|mut g| {
                                                    g.try_io(|inner| {
                                                        use std::os::fd::AsRawFd;
                                                        let res = unsafe {
                                                            libc::write(inner.as_raw_fd(), ip_pkt.as_ptr() as *const libc::c_void, ip_pkt.len())
                                                        };
                                                        if res < 0 {
                                                            Err(std::io::Error::last_os_error())
                                                        } else {
                                                            Ok(res as usize)
                                                        }
                                                    })
                                                });
                                            }
                                        }
                                    });
                                }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "[{}] TUN device '{}' could not be opened (CAP_NET_ADMIN / root required: {}). TUN mode will remain passive.",
                        tag, ifname, e
                    );
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::info!("[{}] TUN interface configured on non-Linux OS: {}", tag, ifname);
        }

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
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
}
