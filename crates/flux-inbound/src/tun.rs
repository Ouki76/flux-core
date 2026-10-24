use async_trait::async_trait;
use bytes::Bytes;
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound, NetworkType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Everything [`parse_ip_packet`] extracts, *except* the payload: the payload
/// stays where it is and is described by `payload` as a byte range.
///
/// The datapath only ever needs to classify an inbound frame (is it the SYN
/// that opens a new port? which UDP port?) before handing the frame to the
/// stack, and the stack parses the frame again itself. Building a
/// [`ParsedPacket`] for that would allocate and copy the whole payload once per
/// inbound packet — at MTU 1500 that is one `malloc` + ~1.4 KiB `memcpy` for
/// every 1448 bytes carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub network: NetworkType,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_flags: u8,
    /// Byte range of the L4 payload within the packet that was peeked at.
    pub payload: std::ops::Range<usize>,
}

/// Parses raw IP packets (IPv4 and IPv6) into structured session and payload metadata.
pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacket> {
    let header = peek_ip_packet(packet)?;
    Some(ParsedPacket {
        src: header.src,
        dst: header.dst,
        network: header.network,
        payload: Bytes::copy_from_slice(&packet[header.payload]),
        tcp_seq: header.tcp_seq,
        tcp_ack: header.tcp_ack,
        tcp_flags: header.tcp_flags,
    })
}

/// Header-only variant of [`parse_ip_packet`]: no allocation, no payload copy.
///
/// Validates exactly the same fields as [`parse_ip_packet`] (they share this
/// implementation), so a frame accepted here is accepted there too.
pub fn peek_ip_packet(packet: &[u8]) -> Option<PacketHeader> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => peek_ipv4_packet(packet),
        6 => peek_ipv6_packet(packet),
        _ => None,
    }
}

fn peek_ipv4_packet(packet: &[u8]) -> Option<PacketHeader> {
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

            Some(PacketHeader {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                network: NetworkType::Udp,
                tcp_seq: 0,
                tcp_ack: 0,
                tcp_flags: 0,
                payload: ihl + 8..ihl + udp_len,
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

            Some(PacketHeader {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                network: NetworkType::Tcp,
                tcp_seq: seq,
                tcp_ack: ack,
                tcp_flags: flags,
                payload: ihl + data_offset..actual_len,
            })
        }
        _ => None,
    }
}

fn peek_ipv6_packet(packet: &[u8]) -> Option<PacketHeader> {
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

            Some(PacketHeader {
                src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                network: NetworkType::Udp,
                tcp_seq: 0,
                tcp_ack: 0,
                tcp_flags: 0,
                payload: offset + 8..offset + udp_len,
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

            Some(PacketHeader {
                src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                network: NetworkType::Tcp,
                tcp_seq: seq,
                tcp_ack: ack,
                tcp_flags: flags,
                payload: offset + data_offset..actual_len,
            })
        }
        _ => None,
    }
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

/// Applies `mtu` to an existing interface with `SIOCSIFMTU`.
///
/// The TUN device's MTU is *not* the same thing as the userspace stack's MTU
/// cap, and both have to agree. The kernel segments everything it hands to the
/// device by the *device* MTU, and it delivers at most MTU-sized IP packets
/// back into the local stack, so a device left at its 1500-byte default caps
/// the datapath at one `read()`/`write()` syscall pair per 1448 payload bytes
/// no matter what the stack believes. Conversely, a stack that emits segments
/// larger than the device MTU produces oversized packets on the wire. The
/// configured MTU is therefore programmed into the device here instead of only
/// being used as a buffer size.
#[cfg(target_os = "linux")]
fn set_interface_mtu(name: &str, mtu: usize) -> std::io::Result<()> {
    // `struct ifreq` with `ifr_mtu`: `int` at offset IFNAMSIZ (16). The
    // padding keeps the struct at the size the kernel copies from user space.
    #[repr(C)]
    struct ifreq_mtu {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_mtu: libc::c_int,
        _pad: [u8; 64 - libc::IFNAMSIZ - std::mem::size_of::<libc::c_int>()],
    }

    const SIOCSIFMTU: libc::c_ulong = 0x8922;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut ifr: ifreq_mtu = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    let len = bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in bytes[..len].iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr.ifr_mtu = mtu as libc::c_int;
    let ret = unsafe { libc::ioctl(sock, SIOCSIFMTU, &ifr) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if ret < 0 { Err(err) } else { Ok(()) }
}

// ---------------------------------------------------------------------------
// smoltcp-based userspace TCP/IP stack
//
// All TCP state machines (retransmission, congestion control, out-of-order
// reassembly, window management) are delegated to smoltcp. This module only
// shuttles frames between the kernel TUN device and the stack, and bridges
// accepted connections/UDP flows to the dispatcher.
// ---------------------------------------------------------------------------

// Portable smoltcp userspace stack: the channel-driven core (`run_stack_channels`)
// works on every platform; only the TUN fd pump (`run_stack`) is Unix-gated.
mod smol_stack {
    use super::{TCP_SYN, peek_ip_packet};
    use bytes::Bytes;
    use flux_types::{BoxedStream, Dispatcher, NetworkType, SessionMeta, TargetAddress, UdpPacket};
    use futures_util::{Sink, SinkExt, Stream, StreamExt};
    use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::{tcp, udp};
    use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
    use smoltcp::wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
    };
    use std::collections::{HashMap, VecDeque};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use tracing::{debug, info};

    /// Per-connection smoltcp buffer floor, per direction.
    ///
    /// A smoltcp socket buffer *is* the advertised TCP window, and on this
    /// datapath the window — not the CPU — was the binding constraint up to
    /// about 256 KiB. Measured with `examples/bench_tun.rs` (256 MiB payload
    /// per round, pooled median over >= 20 rounds, one binary with only this
    /// constant varied):
    ///
    /// ```text
    /// window     MTU 1500      MTU 9000
    ///  64 KiB    376 MiB/s     831 MiB/s
    /// 128 KiB    424 MiB/s    1112 MiB/s
    /// 256 KiB    459 MiB/s    1196 MiB/s
    /// 384 KiB    473 MiB/s    1194 MiB/s
    /// 512 KiB    511 MiB/s     918 MiB/s  (bimodal: rounds split between
    ///                          ~1450 and ~650 MiB/s)
    /// ```
    ///
    /// The knee at MTU 1500 is the bandwidth-delay product of the userspace
    /// pipeline (~0.5 ms round trip for a 256 KiB window); below it the
    /// connection is stop-and-wait, not CPU-bound.
    ///
    /// 256 KiB sits in the knee of both curves for 4x the memory of the old
    /// 64 KiB floor (512 KiB instead of 128 KiB per connection, counting both
    /// directions). 512 KiB buys another ~11 % at MTU 1500 but doubles that
    /// memory and destabilises the jumbo path, so it is not the default.
    const TCP_SOCKET_BUF_MIN: usize = 256 * 1024;
    /// Upper bound on a per-connection smoltcp buffer (2 MiB per connection
    /// counting both directions).
    const TCP_SOCKET_BUF_MAX: usize = 1024 * 1024;

    /// Per-connection smoltcp buffer size for a given interface MTU.
    ///
    /// The `mtu * 4` term keeps a window that spans several *jumbo* segments:
    /// at MTU 65535 a single 64 KiB buffer holds one segment, which measured
    /// 58 MiB/s with the stack actor idle 3.4 s out of 3.5 s. The floor is what
    /// covers the bandwidth-delay product of the userspace pipeline at small
    /// MTUs (see [`TCP_SOCKET_BUF_MIN`]). Window scaling (smoltcp derives the
    /// shift from the receive capacity) keeps the advertised window honest
    /// above 64 KiB.
    fn tcp_buffer_size(mtu: usize) -> usize {
        mtu.saturating_mul(4)
            .clamp(TCP_SOCKET_BUF_MIN, TCP_SOCKET_BUF_MAX)
    }

    const UDP_SOCKET_BUF: usize = 256 * 1024;
    const UDP_SOCKET_MAX_PACKETS: usize = 64;
    const CONN_CHANNEL_CAP: usize = 128;
    /// Largest chunk handed to a connection task per `to_proxy` slot.
    ///
    /// This is the copy granularity of the socket→proxy direction: bigger
    /// chunks mean fewer channel sends, fewer `Bytes` allocations and fewer
    /// task wakeups per byte, while the channel still bounds a connection to
    /// `CONN_CHANNEL_CAP` of them.
    const TO_PROXY_CHUNK: usize = 64 * 1024;
    const CMD_CHANNEL_CAP: usize = 4096;

    /// Maximum bytes buffered per connection for proxy→socket data.
    ///
    /// Without a bound, a fast local client feeding a stalled remote would let
    /// `pending_from_proxy` grow until the process dies: the command channel's
    /// own capacity does not help because every command is drained into this
    /// queue unconditionally.
    const MAX_PENDING_FROM_PROXY: usize = 256 * 1024;

    /// Idle UDP "listener" sockets are reclaimed after this long.
    ///
    /// Each entry costs `2 × UDP_SOCKET_BUF` (512 KiB) of smoltcp buffers, so a
    /// destination-port sweep would otherwise allocate them forever.
    const UDP_LISTENER_IDLE: Duration = Duration::from_secs(60);

    /// Hard cap on simultaneous UDP listener sockets (~128 MiB worst case).
    const UDP_LISTENER_MAX: usize = 256;
    const TUN_OUT_CAP: usize = 2048;
    /// Bytes of egress allowed to sit in the writer channel between two stack
    /// iterations. Capping by *bytes* rather than frames matters once the MTU
    /// is large: 2048 jumbo frames would be 128 MiB of queued buffers, while
    /// 2048 small frames are 3 MiB.
    const TUN_OUT_BYTES: usize = 4 * 1024 * 1024;
    const UDP_SESSION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    /// Commands from connection tasks to the stack actor.
    enum StackCmd {
        TcpData {
            handle: SocketHandle,
            data: Bytes,
        },
        TcpClose {
            handle: SocketHandle,
        },
        UdpReply {
            remote: SocketAddr,
            client: SocketAddr,
            payload: Bytes,
        },
        UdpSessionClose {
            key: (SocketAddr, SocketAddr),
        },
    }

    /// Frame-queue device bridging smoltcp with the async TUN reader/writer tasks.
    #[derive(Default)]
    pub struct TunDevice {
        pub rxq: VecDeque<Vec<u8>>,
        pub txq: VecDeque<Vec<u8>>,
        pub mtu: usize,
        /// Buffers whose frame the stack already consumed, kept for reuse by the
        /// reader. Without this every inbound frame costs one allocation plus a
        /// full-buffer memset on the actor's critical path.
        pub rx_pool: Vec<Vec<u8>>,
    }

    /// Recycled buffers kept for reuse; bounded so a burst cannot pin memory.
    const RX_POOL_MAX: usize = 64;

    pub struct TunRxToken<'a> {
        buf: Vec<u8>,
        pool: &'a mut Vec<Vec<u8>>,
    }

    pub struct TunTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

    impl RxToken for TunRxToken<'_> {
        fn consume<R, F: FnOnce(&[u8]) -> R>(mut self, f: F) -> R {
            let r = f(&self.buf);
            if self.pool.len() < RX_POOL_MAX {
                self.pool.push(std::mem::take(&mut self.buf));
            }
            r
        }
    }

    impl TxToken for TunTxToken<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut buf = vec![0u8; len];
            let r = f(&mut buf);
            self.0.push_back(buf);
            r
        }
    }

    impl Device for TunDevice {
        type RxToken<'a> = TunRxToken<'a>;
        type TxToken<'a> = TunTxToken<'a>;

        fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.rxq.pop_front()?;
            let pool = &mut self.rx_pool;
            Some((TunRxToken { buf: frame, pool }, TunTxToken(&mut self.txq)))
        }

        fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(TunTxToken(&mut self.txq))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = self.mtu;
            caps
        }
    }

    /// AsyncRead/AsyncWrite bridge between a proxy pipeline and a smoltcp TCP socket.
    struct SmolTcpStream {
        handle: SocketHandle,
        cmd_tx: futures_channel::mpsc::Sender<StackCmd>,
        rx: futures_channel::mpsc::Receiver<Bytes>,
        leftover: Option<Bytes>,
        closed: bool,
    }

    impl tokio::io::AsyncRead for SmolTcpStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(left) = &mut self.leftover {
                let n = left.len().min(buf.remaining());
                buf.put_slice(&left[..n]);
                if n == left.len() {
                    self.leftover = None;
                } else {
                    *left = left.split_off(n);
                }
                return std::task::Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut self.rx).poll_next(cx) {
                std::task::Poll::Ready(Some(bytes)) => {
                    let n = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.leftover = Some(bytes.slice(n..));
                    }
                    std::task::Poll::Ready(Ok(()))
                }
                // Channel closed by the stack actor: connection is done → EOF.
                std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    impl tokio::io::AsyncWrite for SmolTcpStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.closed {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "smoltcp connection closed",
                )));
            }
            if buf.is_empty() {
                return std::task::Poll::Ready(Ok(0));
            }
            let this = &mut *self;
            match std::pin::Pin::new(&mut this.cmd_tx).poll_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {
                    let item = StackCmd::TcpData {
                        handle: this.handle,
                        data: Bytes::copy_from_slice(buf),
                    };
                    match std::pin::Pin::new(&mut this.cmd_tx).start_send(item) {
                        Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
                        Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            format!("stack actor gone: {}", e),
                        ))),
                    }
                }
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("stack actor gone: {}", e),
                ))),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            std::pin::Pin::new(&mut this.cmd_tx)
                .poll_flush(cx)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if !self.closed {
                self.closed = true;
                let handle = self.handle;
                let _ =
                    std::pin::Pin::new(&mut self.cmd_tx).start_send(StackCmd::TcpClose { handle });
            }
            let this = self.get_mut();
            std::pin::Pin::new(&mut this.cmd_tx)
                .poll_flush(cx)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))
        }
    }

    impl Drop for SmolTcpStream {
        fn drop(&mut self) {
            if !self.closed {
                let _ = self.cmd_tx.try_send(StackCmd::TcpClose {
                    handle: self.handle,
                });
            }
        }
    }

    /// Per-connection state owned by the stack actor.
    struct TcpConn {
        /// `None` once the proxy side has been told about EOF (peer FIN or
        /// teardown); dropping the sender is what delivers EOF to the proxy.
        to_proxy: Option<futures_channel::mpsc::Sender<Bytes>>,
        /// Chunk read from the socket that did not fit into the channel yet.
        pending_to_proxy: Option<Bytes>,
        /// Data received from the proxy but not yet accepted by the socket.
        pending_from_proxy: VecDeque<Bytes>,
        /// The peer's FIN (or the socket otherwise stopped receiving) has
        /// already been forwarded to the proxy as EOF.
        read_eof: bool,
        /// The proxy asked to close; the FIN is sent once everything the proxy
        /// wrote has been handed to the socket.
        closing: bool,
    }

    impl TcpConn {
        /// Bytes still waiting to be handed to the smoltcp socket.
        fn pending_from_proxy_bytes(&self) -> usize {
            self.pending_from_proxy.iter().map(|b| b.len()).sum()
        }
    }

    /// Monotonic "now" used only for UDP-listener bookkeeping.
    fn now_instant() -> Instant {
        Instant::now()
    }

    /// Drops UDP listener sockets that have been idle for [`UDP_LISTENER_IDLE`],
    /// evicting the least recently used entries first when above
    /// [`UDP_LISTENER_MAX`]. Each live entry holds 512 KiB of smoltcp buffers,
    /// so this is what keeps a UDP destination-port sweep from exhausting RAM.
    fn reap_idle_udp_listeners(
        listeners: &mut HashMap<u16, (SocketHandle, Instant)>,
        sockets: &mut SocketSet<'static>,
        now: Instant,
    ) {
        if !listeners.is_empty() {
            listeners.retain(|_, (handle, last_used)| {
                let idle = now.saturating_duration_since(*last_used) > UDP_LISTENER_IDLE;
                if idle {
                    sockets.remove(*handle);
                }
                !idle
            });
        }
        while listeners.len() >= UDP_LISTENER_MAX {
            let Some(victim) = listeners
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(port, _)| *port)
            else {
                break;
            };
            if let Some((handle, _)) = listeners.remove(&victim) {
                sockets.remove(handle);
            }
        }
    }

    /// Creates a bound UDP socket for a destination port, with both smoltcp
    /// buffers sized from the shared constants.
    fn new_udp_socket(port: u16) -> Option<udp::Socket<'static>> {
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_MAX_PACKETS],
                vec![0u8; UDP_SOCKET_BUF],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_MAX_PACKETS],
                vec![0u8; UDP_SOCKET_BUF],
            ),
        );
        sock.bind(IpListenEndpoint { addr: None, port }).ok()?;
        Some(sock)
    }

    fn ip_ep_to_std(ep: IpEndpoint) -> Option<SocketAddr> {
        // smoltcp with `std` uses core::net address types directly.
        let ip: IpAddr = ep.addr.into();
        Some(SocketAddr::new(ip, ep.port))
    }

    fn std_to_ip_addr(addr: IpAddr) -> IpAddress {
        addr.into()
    }

    /// Where the stack actor gets its inbound frames from.
    ///
    /// The TUN datapath reads the device itself (see [`FdFrames`]); the
    /// WireGuard inbound still feeds decrypted frames through a channel. Both
    /// share the whole actor loop, so the classification, command handling,
    /// backpressure and half-close state machine has exactly one implementation.
    enum FrameSource {
        Channel(tokio::sync::mpsc::Receiver<Vec<u8>>),
        #[cfg(unix)]
        Fd(FdFrames),
    }

    impl FrameSource {
        /// Next frame that is available *right now*, without waiting.
        fn try_next(&mut self, pool: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
            match self {
                FrameSource::Channel(rx) => rx.try_recv().ok(),
                #[cfg(unix)]
                FrameSource::Fd(fd) => fd.try_read(pool),
            }
        }

        /// Waits for the next frame. `None` means no frame can ever arrive
        /// again (the carrier is gone).
        async fn next(&mut self, pool: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
            match self {
                FrameSource::Channel(rx) => rx.recv().await,
                #[cfg(unix)]
                FrameSource::Fd(fd) => fd.read(pool).await,
            }
        }
    }

    /// Inbound TUN frames read directly by the stack actor.
    ///
    /// This used to be a separate task that read the device and forwarded each
    /// frame over a `tokio::sync::mpsc` channel. That cost, per inbound packet,
    /// one allocation + copy (`buf[..n].to_vec()`), one channel send, one
    /// receiver wakeup and one context switch between two tasks — for a packet
    /// the actor was going to touch immediately anyway.
    ///
    /// Measured on `bench_tun`, at the old 64 KiB socket buffer the merge was a
    /// wash: the connection was window-limited, so the hop was never on the
    /// critical path. With the buffer floor at 256 KiB it is worth **+19.5 %**
    /// at MTU 1500 (376 -> 449 MiB/s) and −6 % at MTU 9000, where the
    /// per-frame kernel copy into a fresh buffer costs more than the hop saves;
    /// the receive pool below is what turns that −6 % into +1 %.
    ///
    /// Edge-triggered readiness (mio registers `EPOLLET`) is handled the
    /// canonical way: every read loop runs until the kernel reports
    /// `EAGAIN`, and only that `EAGAIN` clears the cached readiness flag, so a
    /// later arrival always produces a fresh edge. A readiness guard that is
    /// dropped without a read does not clear anything, which is why the
    /// non-blocking path uses `try_io` (which does not touch the flag when it
    /// has no readiness to spend).
    #[cfg(unix)]
    struct FdFrames {
        afd: Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
        /// Read buffer size: one IP packet plus slack for a larger-than-MTU
        /// frame (the kernel never hands out more than the device MTU).
        cap: usize,
    }

    #[cfg(unix)]
    impl FdFrames {
        fn new(afd: Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>, mtu: usize) -> Self {
            Self { afd, cap: mtu + 64 }
        }

        /// One non-blocking `read()` of the device, if it is ready.
        fn try_read(&mut self, pool: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
            use std::os::fd::AsRawFd;
            let cap = self.cap;
            let mut buf = recycle(pool, cap);
            // `AsyncFd::try_io` returns `WouldBlock` *without* spending the
            // cached readiness when the device is not ready, so this neither
            // blocks nor loses an edge.
            let r = self.afd.try_io(tokio::io::Interest::READABLE, |inner| {
                read_frame(inner.as_raw_fd(), &mut buf, cap)
            });
            match r {
                Ok(n) => {
                    buf.truncate(n);
                    Some(buf)
                }
                _ => {
                    if pool.len() < RX_POOL_MAX {
                        pool.push(buf);
                    }
                    None
                }
            }
        }

        /// Waits for the device to become readable and returns one frame.
        async fn read(&mut self, pool: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
            use std::os::fd::AsRawFd;
            loop {
                let mut guard = match self.afd.readable().await {
                    Ok(g) => g,
                    Err(_) => return None,
                };
                let cap = self.cap;
                let mut buf = recycle(pool, cap);
                match guard.try_io(|inner| read_frame(inner.as_raw_fd(), &mut buf, cap)) {
                    Ok(Ok(n)) => {
                        buf.truncate(n);
                        return Some(buf);
                    }
                    // Interrupted: retry the same read.
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                        if pool.len() < RX_POOL_MAX {
                            pool.push(buf);
                        }
                        continue;
                    }
                    // Real device error: no frame can ever arrive again.
                    Ok(Err(_)) => return None,
                    // Not readable after all (`try_io` spent the readiness):
                    // wait for the next edge instead of spinning.
                    Err(_) => {
                        if pool.len() < RX_POOL_MAX {
                            pool.push(buf);
                        }
                        continue;
                    }
                }
            }
        }
    }

    /// A writable `cap`-byte frame buffer, reusing a recycled one when possible.
    ///
    /// This is what keeps the per-frame allocation and the full-buffer memset
    /// off the actor's critical path: at MTU 9000 that is 9 KiB of
    /// allocation+zeroing per frame, measured at +7.4 % throughput
    /// (1247 -> 1339 MiB/s) on the jumbo path.
    #[cfg(unix)]
    fn recycle(pool: &mut Vec<Vec<u8>>, cap: usize) -> Vec<u8> {
        match pool.pop() {
            Some(mut buf) if buf.capacity() >= cap => {
                // Restore the length a read needs. Only the bytes the kernel did
                // not write last time are re-zeroed, so this is usually the
                // 64-byte slack and not a whole frame.
                if buf.len() != cap {
                    buf.resize(cap, 0);
                }
                buf
            }
            _ => vec![0u8; cap],
        }
    }

    /// Reads one IP packet into `frame` (which must be `cap` bytes long).
    #[cfg(unix)]
    fn read_frame(fd: std::os::fd::RawFd, frame: &mut [u8], cap: usize) -> std::io::Result<usize> {
        let n = unsafe { libc::read(fd, frame.as_mut_ptr() as *mut libc::c_void, cap) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let n = n as usize;
        if n == 0 {
            // A TUN never reports EOF; treat it as "no frame" so the caller
            // keeps polling instead of tearing the stack down.
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        Ok(n)
    }

    /// Runs the smoltcp stack actor over the TUN file descriptor.
    ///
    /// The actor reads the device itself; only the egress writer is a separate
    /// task (it has to be able to wait for writability without stalling the
    /// stack).
    #[cfg(unix)]
    pub(super) async fn run_stack(
        afd: Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
        mtu: usize,
        tag: Arc<str>,
        dispatcher: Arc<dyn Dispatcher>,
        running: Arc<AtomicBool>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let (tun_out_tx, tun_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TUN_OUT_CAP);

        // Actor → TUN writer task.
        {
            let afd = afd.clone();
            let running = running.clone();
            tokio::spawn(async move {
                let mut tun_out_rx = tun_out_rx;
                while running.load(Ordering::Relaxed) {
                    let Some(pkt) = tun_out_rx.recv().await else {
                        break;
                    };
                    // Retry until the frame is on the device. The previous
                    // version called `try_io` once and ignored its result, so
                    // the frame was *silently dropped* whenever the device
                    // momentarily refused the write (`WouldBlock` inside
                    // `try_io`, which is exactly the case the readiness guard
                    // exists for). Dropped segments turn into retransmission
                    // timeouts, and a dropped pure ACK / window update can
                    // stall the peer's window until it probes — observed as a
                    // rare multi-second tail stall on bulk transfers.
                    loop {
                        let mut guard = match afd.writable().await {
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
                            // Written.
                            Ok(Ok(_)) => break,
                            // Interrupted: retry the same frame.
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            // Real device error: the connection it belongs to
                            // will time out; do not spin on it.
                            Ok(Err(_)) => break,
                            // Not writable after all: readiness was consumed by
                            // `try_io`, so wait for it again instead of
                            // dropping the frame.
                            Err(_) => continue,
                        }
                    }
                }
            });
        }

        run_stack_core(
            mtu,
            tag,
            dispatcher,
            shutdown_rx,
            FrameSource::Fd(FdFrames::new(afd, mtu)),
            tun_out_tx,
        )
        .await;
    }

    /// Channel-fed smoltcp stack actor core, for transports that decrypt or
    /// otherwise produce frames in another task (the WireGuard inbound).
    pub(crate) async fn run_stack_channels(
        mtu: usize,
        tag: Arc<str>,
        dispatcher: Arc<dyn Dispatcher>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        frame_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        stack_out_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        run_stack_core(
            mtu,
            tag,
            dispatcher,
            shutdown_rx,
            FrameSource::Channel(frame_rx),
            stack_out_tx,
        )
        .await;
    }

    /// Smoltcp stack actor core. Owns the Interface and SocketSet;
    /// all socket manipulation happens on this single task (no locking required).
    ///
    /// Transport-agnostic over [`FrameSource`]: the TUN datapath hands the
    /// device fd over, the WireGuard inbound a channel of decrypted packets.
    async fn run_stack_core(
        mtu: usize,
        tag: Arc<str>,
        dispatcher: Arc<dyn Dispatcher>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut frame_src: FrameSource,
        stack_out_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        let start = Instant::now();
        let mut device = TunDevice {
            rxq: VecDeque::with_capacity(64),
            txq: VecDeque::with_capacity(64),
            mtu,
            rx_pool: Vec::new(),
        };
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
        // AnyIP: treat every destination address as local (transparent capture).
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(Ipv4Address::new(198, 18, 0, 1).into(), 32));
            let _ = addrs.push(IpCidr::new(
                Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into(),
                128,
            ));
        });

        let mut sockets = SocketSet::new(vec![]);

        let (cmd_tx, mut cmd_rx) = futures_channel::mpsc::channel::<StackCmd>(CMD_CHANNEL_CAP);

        // port → listening socket
        let mut tcp_listeners: HashMap<u16, SocketHandle> = HashMap::new();
        // port → (handle, last activity). Entries are reclaimed when idle so a
        // destination-port sweep cannot pin 512 KiB of smoltcp buffers per port.
        let mut udp_listeners: HashMap<u16, (SocketHandle, Instant)> = HashMap::new();
        // active connections/flows
        let mut tcp_conns: HashMap<SocketHandle, TcpConn> = HashMap::new();
        let mut udp_sessions: HashMap<
            (SocketAddr, SocketAddr),
            tokio::sync::mpsc::Sender<UdpPacket>,
        > = HashMap::new();

        let tcp_buf = tcp_buffer_size(mtu);
        fn new_tcp_socket(tcp_buf: usize) -> tcp::Socket<'static> {
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; tcp_buf]),
                tcp::SocketBuffer::new(vec![0u8; tcp_buf]),
            );
            // This is a transparent proxy, not a general purpose host stack:
            // every millisecond an ACK is held back is a millisecond the local
            // client's window stays closed, and there is no AQM or radio link
            // whose batching would profit from delayed ACKs. smoltcp's 10 ms
            // default was measurable here: with jumbo segments it turned the
            // datapath into a stop-and-wait loop (58 MiB/s at MTU 65535).
            sock.set_ack_delay(None);
            // Same reasoning for Nagle. The proxy hands the socket everything
            // it has on every poll, so there is nothing to coalesce; waiting
            // for more data would only add latency to interactive streams.
            sock.set_nagle_enabled(false);
            sock
        }

        // Frame/command captured by the idle select arms; must be fed into the
        // stack on the next iteration instead of being silently dropped.
        let mut pending_frame: Option<Vec<u8>> = None;
        let mut pending_cmd: Option<StackCmd> = None;
        // A closed sender makes `recv()`/`next()` resolve immediately on every
        // poll; selecting on it unconditionally would spin the CPU at 100%.
        let mut cmd_rx_open = true;

        // Pre-creates the listening socket a new flow needs before the frame is
        // handed to smoltcp. Header-only: the stack parses the packet again
        // itself, so a full `parse_ip_packet` here (payload allocation + copy
        // per inbound packet) was pure overhead on the hot path.
        fn precreate_listener(
            frame: &[u8],
            tcp_buf: usize,
            sockets: &mut SocketSet<'static>,
            tcp_listeners: &mut HashMap<u16, SocketHandle>,
            udp_listeners: &mut HashMap<u16, (SocketHandle, Instant)>,
        ) {
            let Some(hdr) = peek_ip_packet(frame) else {
                return;
            };
            match hdr.network {
                NetworkType::Tcp
                    if hdr.tcp_flags & TCP_SYN != 0
                        && hdr.tcp_flags & 0x10 == 0 // pure SYN, no ACK
                        && !tcp_listeners.contains_key(&hdr.dst.port()) =>
                {
                    let mut sock = new_tcp_socket(tcp_buf);
                    if sock.listen(hdr.dst.port()).is_ok() {
                        let h = sockets.add(sock);
                        tcp_listeners.insert(hdr.dst.port(), h);
                    }
                }
                NetworkType::Udp if !udp_listeners.contains_key(&hdr.dst.port()) => {
                    reap_idle_udp_listeners(udp_listeners, sockets, now_instant());
                    if let Some(sock) = new_udp_socket(hdr.dst.port()) {
                        let h = sockets.add(sock);
                        udp_listeners.insert(hdr.dst.port(), (h, Instant::now()));
                    }
                }
                _ => {}
            }
        }

        loop {
            // ---- 1. Feed pending inbound frames into the device queue, pre-creating
            //         listener sockets for new flows.
            let mut drained = 0;
            if let Some(frame) = pending_frame.take() {
                drained += 1;
                precreate_listener(
                    &frame,
                    tcp_buf,
                    &mut sockets,
                    &mut tcp_listeners,
                    &mut udp_listeners,
                );
                device.rxq.push_back(frame);
            }
            while drained < 512 {
                let frame = match frame_src.try_next(&mut device.rx_pool) {
                    Some(f) => f,
                    None => break,
                };
                drained += 1;
                precreate_listener(
                    &frame,
                    tcp_buf,
                    &mut sockets,
                    &mut tcp_listeners,
                    &mut udp_listeners,
                );
                device.rxq.push_back(frame);
            }

            // ---- 2. Apply pending commands from connection tasks.
            let mut cmds_processed = 0;
            loop {
                let cmd = match pending_cmd.take() {
                    Some(c) => Some(c),
                    None if cmds_processed < 512 => cmd_rx.try_recv().ok(),
                    None => None,
                };
                let Some(cmd) = cmd else { break };

                // Backpressure: if accepting this chunk would push a connection
                // past its buffer budget, leave the command (and everything
                // behind it) in the bounded channel. That blocks the proxy task
                // in `send().await` instead of growing an unbounded queue here.
                if let StackCmd::TcpData { handle, data } = &cmd
                    && let Some(conn) = tcp_conns.get(handle)
                    && conn.pending_from_proxy_bytes() + data.len() > MAX_PENDING_FROM_PROXY
                {
                    pending_cmd = Some(cmd);
                    break;
                }

                cmds_processed += 1;
                match cmd {
                    StackCmd::TcpData { handle, data } => {
                        if let Some(conn) = tcp_conns.get_mut(&handle) {
                            conn.pending_from_proxy.push_back(data);
                        }
                    }
                    StackCmd::TcpClose { handle } => {
                        if let Some(conn) = tcp_conns.get_mut(&handle) {
                            // Do not discard data that the proxy already wrote
                            // but the socket has not accepted yet: close once
                            // the queue has been flushed (see step 2b). Clearing
                            // it here truncated the last up-to-256 KiB of a
                            // proxied response on every graceful shutdown.
                            conn.closing = true;
                        }
                    }
                    StackCmd::UdpSessionClose { key } => {
                        udp_sessions.remove(&key);
                    }
                    StackCmd::UdpReply {
                        remote,
                        client,
                        payload,
                    } => {
                        if let Some(&(handle, _)) = udp_listeners.get(&remote.port()) {
                            let sock = sockets.get_mut::<udp::Socket>(handle);
                            let meta = udp::UdpMetadata {
                                endpoint: IpEndpoint {
                                    addr: std_to_ip_addr(client.ip()),
                                    port: client.port(),
                                },
                                local_address: Some(std_to_ip_addr(remote.ip())),
                                meta: smoltcp::phy::PacketMeta::default(),
                            };
                            if let Err(e) = sock.send_slice(&payload, meta) {
                                debug!("[{}] smoltcp udp send failed: {}", tag, e);
                            }
                        }
                    }
                }
            }

            // ---- 2b. Flush proxy→socket pending data into socket buffers.
            for (handle, conn) in tcp_conns.iter_mut() {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                while sock.can_send() {
                    let Some(chunk) = conn.pending_from_proxy.front_mut() else {
                        break;
                    };
                    match sock.send_slice(chunk) {
                        Ok(n) if n == chunk.len() => {
                            conn.pending_from_proxy.pop_front();
                        }
                        Ok(n) => {
                            bytes::Buf::advance(chunk, n); // keep remainder
                            break;
                        }
                        _ => break,
                    }
                }
                // Deferred close: only send the FIN once every byte the proxy
                // wrote has been accepted by the socket.
                if conn.closing && conn.pending_from_proxy.is_empty() {
                    conn.closing = false;
                    sock.close();
                }
            }

            // ---- 3. Poll the stack (ingress + egress + timers/retransmits).
            let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);

            // ---- 4. Emit frames to the transport writer.
            //
            // On a full channel the frame must be put back: `try_send` consumes
            // it, so the previous `if ... .is_err() { break }` silently *dropped*
            // the segment every time the writer task fell behind by
            // `TUN_OUT_CAP` frames. Dropped data segments turn into retransmit
            // timeouts (throughput collapse) and dropped pure ACKs/window
            // updates can wedge the connection.
            let mut queued = 0usize;
            // Set when the byte budget leaves frames in `txq`. The actor must
            // then iterate again instead of parking on the channel: nothing
            // else would ever wake it for frames it is already holding.
            let mut egress_pending = false;
            while let Some(frame) = device.txq.pop_front() {
                if queued + frame.len() > TUN_OUT_BYTES && queued > 0 {
                    // Leave the rest to the next iteration: the writer is not
                    // keeping up and an unbounded jumbo-frame queue would cost
                    // hundreds of megabytes.
                    device.txq.push_front(frame);
                    egress_pending = true;
                    break;
                }
                queued += frame.len();
                match stack_out_tx.try_send(frame) {
                    Ok(()) => {}
                    Err(e) => {
                        // The writer is behind: keep the frame and poll again
                        // instead of parking. Sleeping here with egress still
                        // queued is a lost wakeup — nothing would wake the
                        // actor for data it is already holding, so the peer
                        // sees a stalled connection until unrelated traffic
                        // arrives.
                        device.txq.push_front(e.into_inner());
                        egress_pending = true;
                        break;
                    }
                }
            }

            // ---- 5. Post-poll: claim new connections, pump socket→proxy data,
            //         reap closed sockets, dispatch UDP datagrams.
            let mut to_claim: Vec<(SocketHandle, SocketAddr, SocketAddr, u16)> = vec![];
            // (handle, force_reset)
            let mut to_remove: Vec<(SocketHandle, bool)> = vec![];
            for (handle, conn) in tcp_conns.iter_mut() {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                // Flush a chunk that previously didn't fit into the channel.
                if let Some(tx) = conn.to_proxy.as_mut() {
                    if let Some(chunk) = conn.pending_to_proxy.take() {
                        match tx.try_send(chunk) {
                            Ok(()) => {}
                            Err(e) => {
                                conn.pending_to_proxy = Some(e.into_inner());
                            }
                        }
                    }
                    if conn.pending_to_proxy.is_none() {
                        while sock.can_recv() {
                            // One copy, straight out of the socket's receive
                            // ring: `recv` hands the closure the contiguous
                            // readable region, so no staging buffer is needed.
                            // The old code copied into an 8 KiB stack array
                            // (zeroed on every iteration) and then copied
                            // again into `Bytes` — two extra passes over the
                            // payload and one allocation per 8 KiB.
                            let chunk = match sock.recv(|buf| {
                                let n = buf.len().min(TO_PROXY_CHUNK);
                                (n, Bytes::copy_from_slice(&buf[..n]))
                            }) {
                                // A zero-length chunk would be delivered to the
                                // proxy as EOF and truncate the stream, so an
                                // empty contiguous region ends the drain instead.
                                Ok(chunk) if chunk.is_empty() => break,
                                Ok(chunk) => chunk,
                                Err(_) => break,
                            };
                            match tx.try_send(chunk) {
                                Ok(()) => {}
                                Err(e) => {
                                    conn.pending_to_proxy = Some(e.into_inner());
                                    break;
                                }
                            }
                        }
                    }
                }

                // The peer half-closed (FIN): hand EOF to the proxy so the
                // outbound side is shut down. Without this the proxy kept
                // waiting for data that can never arrive, the socket stayed in
                // CloseWait forever (leaking 128 KiB of smoltcp buffers per
                // connection) and clients that half-close — a very common
                // pattern — hung instead of receiving the response tail.
                if matches!(sock.state(), tcp::State::CloseWait | tcp::State::Closing)
                    && conn.pending_to_proxy.is_none()
                    && !conn.read_eof
                {
                    conn.read_eof = true;
                    conn.to_proxy = None;
                }
                let nothing_queued =
                    conn.pending_to_proxy.is_none() && conn.pending_from_proxy.is_empty();
                let dead = !sock.is_active() && nothing_queued;
                // A socket that can neither send nor receive *and* has flushed all
                // buffered data is finished: tear it down without a RST so a
                // graceful FIN/FIN-ACK exchange is not truncated into an abort.
                let finished = matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait)
                    || (!sock.may_recv() && !sock.may_send() && nothing_queued);
                if dead || finished {
                    // Only force a reset when data may still be outstanding.
                    to_remove.push((*handle, !nothing_queued));
                }
            }
            for (handle, force_reset) in to_remove {
                if let Some(conn) = tcp_conns.remove(&handle) {
                    drop(conn.to_proxy); // EOF for the proxy task
                }
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                if force_reset && !matches!(sock.state(), tcp::State::Listen | tcp::State::Closed) {
                    sock.abort();
                }
                sockets.remove(handle);
            }

            // Discover newly accepted connections (sockets that transitioned out of Listen).
            for (handle, sock_any) in sockets.iter_mut() {
                let sock: &mut tcp::Socket = match sock_any {
                    smoltcp::socket::Socket::Tcp(s) => s,
                    _ => continue,
                };
                if tcp_conns.contains_key(&handle) {
                    continue;
                }
                let (Some(local), Some(remote)) = (sock.local_endpoint(), sock.remote_endpoint())
                else {
                    continue; // still listening / not yet accepted
                };
                if !matches!(
                    sock.state(),
                    tcp::State::Established | tcp::State::SynReceived
                ) {
                    continue;
                }
                if let (Some(l), Some(r)) = (ip_ep_to_std(local), ip_ep_to_std(remote)) {
                    to_claim.push((handle, r, l, l.port()));
                }
            }

            for (handle, remote, local, port) in to_claim {
                // The accepting socket no longer listens; replace the port listener.
                tcp_listeners.remove(&port);
                let mut sock = new_tcp_socket(tcp_buf);
                if sock.listen(port).is_ok() {
                    let h = sockets.add(sock);
                    tcp_listeners.insert(port, h);
                }

                let (to_proxy_tx, to_proxy_rx) =
                    futures_channel::mpsc::channel::<Bytes>(CONN_CHANNEL_CAP);
                tcp_conns.insert(
                    handle,
                    TcpConn {
                        to_proxy: Some(to_proxy_tx),
                        pending_to_proxy: None,
                        pending_from_proxy: VecDeque::new(),
                        read_eof: false,
                        closing: false,
                    },
                );

                let meta = SessionMeta::new(
                    remote,
                    TargetAddress::Ip(local),
                    tag.clone(),
                    NetworkType::Tcp,
                );
                let stream: BoxedStream = Box::new(SmolTcpStream {
                    handle,
                    cmd_tx: cmd_tx.clone(),
                    rx: to_proxy_rx,
                    leftover: None,
                    closed: false,
                });
                let disp = dispatcher.clone();
                tokio::spawn(async move {
                    disp.dispatch_stream(meta, stream).await;
                });
            }

            // UDP datagrams → per-flow dispatcher sessions.
            let udp_handles: Vec<(u16, SocketHandle)> =
                udp_listeners.iter().map(|(p, (h, _))| (*p, *h)).collect();
            for (port, handle) in udp_handles {
                if let Some(entry) = udp_listeners.get_mut(&port) {
                    entry.1 = Instant::now();
                }
                loop {
                    let sock = sockets.get_mut::<udp::Socket>(handle);
                    let (payload, meta) = match sock.recv() {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let Some(local_ip) = meta.local_address else {
                        break;
                    };
                    let remote = match ip_ep_to_std(meta.endpoint) {
                        Some(r) => r,
                        None => break,
                    };
                    let dst = SocketAddr::new(IpAddr::from(local_ip), port);
                    let pkt = UdpPacket::new(
                        Bytes::copy_from_slice(payload),
                        TargetAddress::Ip(remote),
                        TargetAddress::Ip(dst),
                    );

                    let key = (remote, dst);
                    if let Some(tx) = udp_sessions.get(&key) {
                        let _ = tx.try_send(pkt);
                    } else {
                        let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                        let meta_sess = SessionMeta::new(
                            remote,
                            TargetAddress::Ip(dst),
                            tag.clone(),
                            NetworkType::Udp,
                        );
                        let disp = dispatcher.clone();
                        tokio::spawn(async move {
                            disp.dispatch_packet(meta_sess, pkt_rx, out_tx).await;
                        });
                        let _ = pkt_tx.try_send(pkt);
                        udp_sessions.insert(key, pkt_tx);

                        // Reply pump: dispatcher replies → stack actor.
                        let mut cmd_tx_reply = cmd_tx.clone();
                        // Reply pump: dispatcher replies → stack actor.
                        // On idle timeout the session is closed and removed from the map.
                        let mut cmd_tx_close = cmd_tx.clone();
                        tokio::spawn(async move {
                            loop {
                                let reply = match tokio::time::timeout(
                                    UDP_SESSION_IDLE_TIMEOUT,
                                    out_rx.recv(),
                                )
                                .await
                                {
                                    Ok(Some(reply)) => reply,
                                    _ => break,
                                };
                                // reply.destination = client, reply.source = remote server
                                let (client, remote_srv) = match (&reply.destination, &reply.source)
                                {
                                    (TargetAddress::Ip(c), TargetAddress::Ip(r)) => (*c, *r),
                                    _ => continue,
                                };
                                if cmd_tx_reply
                                    .send(StackCmd::UdpReply {
                                        remote: remote_srv,
                                        client,
                                        payload: reply.payload.clone(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            let _ = cmd_tx_close.send(StackCmd::UdpSessionClose { key }).await;
                        });
                    }
                }
            }

            // ---- 6. Sleep until the next stack timer or new input arrives.
            let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
            let wait = iface
                .poll_delay(now, &sockets)
                .unwrap_or(SmolDuration::from_secs(60));
            let wait_std: std::time::Duration = wait.into();

            tokio::select! {
                _ = shutdown_rx.recv() => break,
                // Frames still queued from the byte-budget cut-off: poll again
                // immediately rather than sleeping until unrelated input.
                _ = std::future::ready(()), if egress_pending => {}
                // Capture the frame so it is processed next iteration instead of dropped.
                f = frame_src.next(&mut device.rx_pool) => {
                    if f.is_none() {
                        // The carrier is gone: no packet can ever enter
                        // the stack again, so the actor has nothing left to do.
                        break;
                    }
                    pending_frame = f;
                }
                // Only take a new command when no command is already waiting:
                // the backpressure branch in step 2 deliberately leaves the
                // current command in `pending_cmd` for the next iteration, and
                // overwriting it here silently discarded the payload (a 64 KiB
                // chunk per occurrence -> truncated streams). It also avoids
                // spinning on a full command channel while backpressured.
                c = cmd_rx.next(), if cmd_rx_open && pending_cmd.is_none() => {
                    if c.is_none() {
                        cmd_rx_open = false;
                    }
                    pending_cmd = c;
                }
                _ = tokio::time::sleep(wait_std) => {}
            }
        }

        info!("[{}] smoltcp stack actor stopped", tag);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod smol_stack_tests {
    //! Drives the smoltcp stack with crafted frames — no root / real TUN device required.
    use super::smol_stack::*;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::Medium;
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant as SmolInstant;
    use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};

    fn csum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in data.chunks(2) {
            let w = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(w);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp: &mut [u8]) {
        tcp[16] = 0;
        tcp[17] = 0;
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&*tcp);
        let c = csum(&pseudo);
        tcp[16..18].copy_from_slice(&c.to_be_bytes());
    }

    /// Builds an IPv4/TCP packet; flags/seq/ack/payload configurable.
    #[allow(clippy::too_many_arguments)]
    fn tcp_pkt(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let c = csum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());

        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        tcp_checksum(src, dst, tcp);
        pkt
    }

    fn test_device() -> TunDevice {
        TunDevice {
            rxq: Default::default(),
            txq: Default::default(),
            mtu: 1500,
            rx_pool: Default::default(),
        }
    }

    fn make_iface(device: &mut TunDevice) -> Interface {
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, device, SmolInstant::ZERO);
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(Ipv4Address::new(198, 18, 0, 1).into(), 32));
        });
        iface
    }

    #[test]
    fn test_smoltcp_accept_and_echo_roundtrip() {
        use smoltcp::phy::Device as _;
        let mut device = test_device();
        assert_eq!(device.capabilities().medium, Medium::Ip);
        let mut iface = make_iface(&mut device);
        let mut sockets = SocketSet::new(vec![]);

        let client = [192, 168, 1, 100];
        let server = [93, 184, 216, 34]; // arbitrary "remote" captured transparently

        // Listener on port 443, like the stack actor installs on SYN.
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        );
        sock.listen(443).unwrap();
        let handle = sockets.add(sock);

        // 1. SYN
        device
            .rxq
            .push_back(tcp_pkt(client, 50000, server, 443, 1000, 0, 0x02, &[]));
        let now = SmolInstant::from_millis(1);
        let res = iface.poll(now, &mut device, &mut sockets);
        assert_ne!(res, smoltcp::iface::PollResult::None);

        // Expect SYN-ACK emitted
        let out = device.txq.pop_front().expect("stack must emit SYN-ACK");
        assert_eq!(out[9], 6);
        assert_eq!(out[20 + 13] & 0x12, 0x12, "expected SYN|ACK flags");

        let sock = sockets.get_mut::<tcp::Socket>(handle);
        assert!(matches!(sock.state(), tcp::State::SynReceived));
        // Original dst must be preserved in the socket tuple (transparent proxy key)
        let local = sock.local_endpoint().unwrap();
        assert_eq!(local.addr.to_string(), "93.184.216.34");
        assert_eq!(local.port, 443);

        // 2. ACK completes handshake; then data segment
        let server_isn = u32::from_be_bytes([out[24], out[25], out[26], out[27]]);
        device.rxq.push_back(tcp_pkt(
            client,
            50000,
            server,
            443,
            1001,
            server_isn.wrapping_add(1),
            0x10,
            &[],
        ));
        iface.poll(SmolInstant::from_millis(2), &mut device, &mut sockets);
        assert!(matches!(
            sockets.get_mut::<tcp::Socket>(handle).state(),
            tcp::State::Established
        ));

        let payload = b"GET / HTTP/1.0\r\n\r\n";
        device.rxq.push_back(tcp_pkt(
            client,
            50000,
            server,
            443,
            1001,
            server_isn.wrapping_add(1),
            0x18,
            payload,
        ));
        iface.poll(SmolInstant::from_millis(3), &mut device, &mut sockets);

        let sock = sockets.get_mut::<tcp::Socket>(handle);
        assert!(sock.can_recv());
        let mut buf = [0u8; 64];
        let n = sock.recv_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);

        // 3. Stack → client: send reply, frame must appear in txq
        let sock = sockets.get_mut::<tcp::Socket>(handle);
        sock.send_slice(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        iface.poll(SmolInstant::from_millis(4), &mut device, &mut sockets);
        assert!(device.txq.iter().any(|f| f.len() > 40));
    }

    #[test]
    fn test_udp_datagram_dispatch() {
        use smoltcp::socket::udp;
        let mut device = test_device();
        let mut iface = make_iface(&mut device);
        let mut sockets = SocketSet::new(vec![]);

        let mut usock = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16384]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16384]),
        );
        usock
            .bind(smoltcp::wire::IpListenEndpoint {
                addr: None,
                port: 53,
            })
            .unwrap();
        let h = sockets.add(usock);

        let client = [10, 8, 0, 5];
        let dns = [8, 8, 8, 8];
        // IPv4 UDP packet
        let udp_len = 8 + 4;
        let total = 20 + udp_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&client);
        pkt[16..20].copy_from_slice(&dns);
        let c = csum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        pkt[20..22].copy_from_slice(&5353u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[28..32].copy_from_slice(b"dns!");

        device.rxq.push_back(pkt);
        iface.poll(SmolInstant::from_millis(1), &mut device, &mut sockets);

        let sock = sockets.get_mut::<udp::Socket>(h);
        let (data, meta) = sock.recv().expect("udp socket must receive datagram");
        assert_eq!(data, b"dns!");
        assert_eq!(meta.endpoint.port, 5353);
        // Original destination preserved for transparent routing
        assert_eq!(meta.local_address.unwrap().to_string(), "8.8.8.8");
    }
}

#[cfg(target_os = "linux")]
use smol_stack::run_stack;

// Re-export the channel-driven stack core for the WireGuard inbound.
pub(crate) use smol_stack::run_stack_channels;

/// Default interface MTU. Kept at the Ethernet value so existing configs keep
/// their current behaviour; a larger MTU (see [`MAX_MTU`]) is the single most
/// effective throughput knob on this datapath, because a TUN device carries
/// exactly one IP packet per `read()`/`write()` syscall and no read/write
/// batching (`readv`, `writev`, …) is possible on it.
/// Default TUN MTU.
///
/// 9000 (jumbo) because the datapath is syscall-bound: a TUN supports no read or
/// write batching, so bytes-per-syscall is the only lever. Measured on loopback:
/// MTU 1500 -> 324 MiB/s at 6.7 CPU s/GB, MTU 9000 -> 745 MiB/s at 3.4 s/GB.
///
/// This is safe for forwarding: the proxy terminates TCP, so the segment size on
/// the wire is negotiated with the remote peer and never exceeds its path MTU —
/// only same-host applications see larger packets. Set `mtu: 1500` explicitly if
/// the device MTU has to match a 1500-byte path (e.g. bridging a real LAN).
pub const DEFAULT_MTU: usize = 9000;
/// Smallest MTU the userspace stack is willing to run with.
pub const MIN_MTU: usize = 576;
/// Largest IP packet a TUN device can carry.
pub const MAX_MTU: usize = 65535;

pub struct TunInbound {
    tag: String,
    interface_name: String,
    mtu: usize,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
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
            // 576 is the IPv4 minimum every stack must accept; 65535 is the
            // largest IP packet a TUN device can carry. Anything outside that
            // range would make the stack emit segments the kernel refuses.
            mtu: mtu.unwrap_or(DEFAULT_MTU).clamp(MIN_MTU, MAX_MTU),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            tasks: crate::InboundTasks::new(),
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

        #[cfg(target_os = "linux")]
        {
            match open_tun_device(&self.interface_name) {
                Ok(owned_fd) => {
                    info!(
                        "[{}] TUN interface '{}' opened successfully (MTU: {})",
                        self.tag, self.interface_name, self.mtu
                    );
                    // Program the MTU into the device itself: the kernel
                    // segments by the device MTU, so leaving it at 1500 while
                    // the stack is willing to emit more only wastes a syscall
                    // pair per 1448 bytes.
                    match set_interface_mtu(&self.interface_name, self.mtu) {
                        Ok(()) => info!(
                            "[{}] TUN interface '{}' MTU set to {}",
                            self.tag, self.interface_name, self.mtu
                        ),
                        Err(e) => tracing::warn!(
                            "[{}] could not set MTU {} on '{}': {} (the device keeps its \
                             current MTU, which caps the datapath at that packet size)",
                            self.tag,
                            self.mtu,
                            self.interface_name,
                            e
                        ),
                    }
                    // SAFETY: `owned_fd` is an `OwnedFd` moved into the `AsyncFd`, so the
                    // descriptor stays open for exactly as long as the reactor holds it
                    // and no other owner can close or reuse it.
                    let async_fd = unsafe { tokio::io::unix::AsyncFd::register(owned_fd) }.map_err(|e| {
                        self.running.store(false, Ordering::SeqCst);
                        let cause: std::io::Error = e.into();
                        FluxError::Io(std::io::Error::new(
                            cause.kind(),
                            format!(
                                "tun inbound '{}': failed to register device with the reactor: {}",
                                self.tag, cause
                            ),
                        ))
                    })?;
                    let async_fd = Arc::new(async_fd);
                    let tag: Arc<str> = Arc::from(self.tag.as_str());
                    self.tasks.spawn(run_stack(
                        async_fd,
                        self.mtu,
                        tag,
                        dispatcher,
                        self.running.clone(),
                        self.shutdown_tx.subscribe(),
                    ));
                }
                Err(e) => {
                    // Report the failure instead of reporting a successful start:
                    // a `tun` inbound that silently does nothing makes the whole
                    // configuration look healthy while no traffic is captured.
                    self.running.store(false, Ordering::SeqCst);
                    return Err(FluxError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "tun inbound '{}': failed to open device '{}': {}.                              Root or CAP_NET_ADMIN is required.",
                            self.tag, self.interface_name, e
                        ),
                    )));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = dispatcher;
            self.running.store(false, Ordering::SeqCst);
            return Err(FluxError::Config(format!(
                "tun inbound '{}': TUN is only supported on Linux",
                self.tag
            )));
        }

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning while it is still running leaves the
        // port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}
