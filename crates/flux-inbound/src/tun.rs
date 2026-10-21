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
    use super::{TCP_SYN, parse_ip_packet};
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

    const TCP_SOCKET_BUF: usize = 64 * 1024;
    const UDP_SOCKET_BUF: usize = 256 * 1024;
    const UDP_SOCKET_MAX_PACKETS: usize = 64;
    const CONN_CHANNEL_CAP: usize = 128;
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
    }

    pub struct TunRxToken(Vec<u8>);
    pub struct TunTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

    impl RxToken for TunRxToken {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
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
        type RxToken<'a> = TunRxToken;
        type TxToken<'a> = TunTxToken<'a>;

        fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            self.rxq
                .pop_front()
                .map(|frame| (TunRxToken(frame), TunTxToken(&mut self.txq)))
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
        to_proxy: futures_channel::mpsc::Sender<Bytes>,
        /// Chunk read from the socket that did not fit into the channel yet.
        pending_to_proxy: Option<Bytes>,
        /// Data received from the proxy but not yet accepted by the socket.
        pending_from_proxy: VecDeque<Bytes>,
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

    /// Runs the smoltcp stack actor over the TUN file descriptor.
    /// Spawns fd reader/writer pump tasks and delegates to the channel-driven core.
    #[cfg(unix)]
    pub(super) async fn run_stack(
        afd: Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
        mtu: usize,
        tag: Arc<str>,
        dispatcher: Arc<dyn Dispatcher>,
        running: Arc<AtomicBool>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TUN_OUT_CAP);
        let (tun_out_tx, tun_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TUN_OUT_CAP);

        // TUN reader task → frames into the actor.
        {
            let afd = afd.clone();
            let running = running.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; mtu + 64];
                while running.load(Ordering::Relaxed) {
                    let mut guard = match afd.readable().await {
                        Ok(g) => g,
                        Err(_) => break,
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
                        Err(_) => continue, // WouldBlock: spurious readiness
                    };
                    if n == 0 || frame_tx.send(buf[..n].to_vec()).await.is_err() {
                        if n == 0 {
                            continue;
                        }
                        break;
                    }
                }
            });
        }

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
                    let mut guard = match afd.writable().await {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    let _ = guard.try_io(|inner| {
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
                    });
                }
            });
        }

        run_stack_channels(mtu, tag, dispatcher, shutdown_rx, frame_rx, tun_out_tx).await;
    }

    /// Channel-driven smoltcp stack actor core. Owns the Interface and SocketSet;
    /// all socket manipulation happens on this single task (no locking required).
    ///
    /// Transport-agnostic: consumed both by the TUN inbound (via fd pump tasks) and
    /// by the WireGuard inbound (via encrypted tunnel packets).
    pub(crate) async fn run_stack_channels(
        mtu: usize,
        tag: Arc<str>,
        dispatcher: Arc<dyn Dispatcher>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut frame_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        stack_out_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        let start = Instant::now();
        let mut device = TunDevice {
            rxq: VecDeque::with_capacity(64),
            txq: VecDeque::with_capacity(64),
            mtu,
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

        fn new_tcp_socket() -> tcp::Socket<'static> {
            tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]),
                tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]),
            )
        }

        // Frame/command captured by the idle select arms; must be fed into the
        // stack on the next iteration instead of being silently dropped.
        let mut pending_frame: Option<Vec<u8>> = None;
        let mut pending_cmd: Option<StackCmd> = None;
        // A closed sender makes `recv()`/`next()` resolve immediately on every
        // poll; selecting on it unconditionally would spin the CPU at 100%.
        let mut cmd_rx_open = true;

        loop {
            // ---- 1. Feed pending inbound frames into the device queue, pre-creating
            //         listener sockets for new flows.
            let mut drained = 0;
            if let Some(frame) = pending_frame.take() {
                drained += 1;
                if let Some(parsed) = parse_ip_packet(&frame) {
                    match parsed.network {
                        NetworkType::Tcp
                            if parsed.tcp_flags & TCP_SYN != 0
                                && parsed.tcp_flags & 0x10 == 0 // pure SYN, no ACK
                                && !tcp_listeners.contains_key(&parsed.dst.port()) =>
                        {
                            let mut sock = new_tcp_socket();
                            if sock.listen(parsed.dst.port()).is_ok() {
                                let h = sockets.add(sock);
                                tcp_listeners.insert(parsed.dst.port(), h);
                            }
                        }
                        NetworkType::Udp if !udp_listeners.contains_key(&parsed.dst.port()) => {
                            reap_idle_udp_listeners(
                                &mut udp_listeners,
                                &mut sockets,
                                now_instant(),
                            );
                            if let Some(sock) = new_udp_socket(parsed.dst.port()) {
                                let h = sockets.add(sock);
                                udp_listeners.insert(parsed.dst.port(), (h, Instant::now()));
                            }
                        }
                        _ => {}
                    }
                }
                device.rxq.push_back(frame);
            }
            while drained < 512 {
                let frame = match frame_rx.try_recv() {
                    Ok(f) => f,
                    Err(_) => break,
                };
                drained += 1;
                if let Some(parsed) = parse_ip_packet(&frame) {
                    match parsed.network {
                        NetworkType::Tcp
                            if parsed.tcp_flags & TCP_SYN != 0
                                && parsed.tcp_flags & 0x10 == 0 // pure SYN, no ACK
                                && !tcp_listeners.contains_key(&parsed.dst.port()) =>
                        {
                            let mut sock = new_tcp_socket();
                            if sock.listen(parsed.dst.port()).is_ok() {
                                let h = sockets.add(sock);
                                tcp_listeners.insert(parsed.dst.port(), h);
                            }
                        }
                        NetworkType::Udp if !udp_listeners.contains_key(&parsed.dst.port()) => {
                            reap_idle_udp_listeners(
                                &mut udp_listeners,
                                &mut sockets,
                                now_instant(),
                            );
                            if let Some(sock) = new_udp_socket(parsed.dst.port()) {
                                let h = sockets.add(sock);
                                udp_listeners.insert(parsed.dst.port(), (h, Instant::now()));
                            }
                        }
                        _ => {}
                    }
                }
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
                            conn.pending_from_proxy.clear();
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            sock.close();
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
            }

            // ---- 3. Poll the stack (ingress + egress + timers/retransmits).
            let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);

            // ---- 4. Emit frames to the transport writer.
            while let Some(frame) = device.txq.pop_front() {
                if stack_out_tx.try_send(frame).is_err() {
                    break; // writer channel full; try again next iteration
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
                if let Some(chunk) = conn.pending_to_proxy.take() {
                    match conn.to_proxy.try_send(chunk) {
                        Ok(()) => {}
                        Err(e) => {
                            conn.pending_to_proxy = Some(e.into_inner());
                        }
                    }
                }
                if conn.pending_to_proxy.is_none() {
                    let mut tmp = [0u8; 8192];
                    while sock.can_recv() {
                        match sock.recv_slice(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => {
                                match conn.to_proxy.try_send(Bytes::copy_from_slice(&tmp[..n])) {
                                    Ok(()) => {}
                                    Err(e) => {
                                        conn.pending_to_proxy = Some(e.into_inner());
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
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
                let mut sock = new_tcp_socket();
                if sock.listen(port).is_ok() {
                    let h = sockets.add(sock);
                    tcp_listeners.insert(port, h);
                }

                let (to_proxy_tx, to_proxy_rx) =
                    futures_channel::mpsc::channel::<Bytes>(CONN_CHANNEL_CAP);
                tcp_conns.insert(
                    handle,
                    TcpConn {
                        to_proxy: to_proxy_tx,
                        pending_to_proxy: None,
                        pending_from_proxy: VecDeque::new(),
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
                // Capture the frame so it is processed next iteration instead of dropped.
                f = frame_rx.recv() => {
                    if f.is_none() {
                        // The carrier reader is gone: no packet can ever enter
                        // the stack again, so the actor has nothing left to do.
                        break;
                    }
                    pending_frame = f;
                }
                c = cmd_rx.next(), if cmd_rx_open => { // keep the command for step 2
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

pub struct TunInbound {
    tag: String,
    interface_name: String,
    mtu: usize,
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

        #[cfg(target_os = "linux")]
        {
            match open_tun_device(&self.interface_name) {
                Ok(owned_fd) => {
                    info!(
                        "[{}] TUN interface '{}' opened successfully (MTU: {})",
                        self.tag, self.interface_name, self.mtu
                    );
                    let async_fd = tokio::io::unix::AsyncFd::new(owned_fd).map_err(|e| {
                        self.running.store(false, Ordering::SeqCst);
                        FluxError::Io(std::io::Error::new(
                            e.kind(),
                            format!(
                                "tun inbound '{}': failed to register device with the reactor: {}",
                                self.tag, e
                            ),
                        ))
                    })?;
                    let async_fd = Arc::new(async_fd);
                    let tag: Arc<str> = Arc::from(self.tag.as_str());
                    tokio::spawn(run_stack(
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
        Ok(())
    }
}
