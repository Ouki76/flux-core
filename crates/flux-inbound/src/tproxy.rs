use async_trait::async_trait;
use dashmap::DashMap;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tracing::{info, warn};

const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

#[cfg(target_os = "linux")]
pub fn enable_tproxy_socket(socket: &Socket, is_v6: bool) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    unsafe {
        let enable: libc::c_int = 1;
        let level = if is_v6 { libc::SOL_IPV6 } else { libc::SOL_IP };
        let ret = libc::setsockopt(
            fd,
            level,
            IP_TRANSPARENT,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let orig_dst_opt = if is_v6 {
            IPV6_RECVORIGDSTADDR
        } else {
            IP_RECVORIGDSTADDR
        };
        let _ = libc::setsockopt(
            fd,
            level,
            orig_dst_opt,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_tproxy_socket(_socket: &Socket, _is_v6: bool) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn recv_tproxy_udp(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    unsafe {
        let mut src_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut ctrl_buf = [0u8; 512];
        let mut msg = libc::msghdr {
            msg_name: &mut src_addr as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ctrl_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: ctrl_buf.len(),
            msg_flags: 0,
        };

        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let bytes_read = ret as usize;

        let src = match src_addr.ss_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(&src_addr as *const _ as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            libc::AF_INET6 => {
                let sin6 = &*(&src_addr as *const _ as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported address family in TPROXY recvmsg",
                ));
            }
        };

        let mut orig_dst = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ctype = (*cmsg).cmsg_type;

            if level == libc::SOL_IP && ctype == IP_RECVORIGDSTADDR {
                let sin = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                orig_dst = Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                break;
            } else if level == libc::SOL_IPV6 && ctype == IPV6_RECVORIGDSTADDR {
                let sin6 = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                orig_dst = Some(SocketAddr::new(std::net::IpAddr::V6(ip), port));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        Ok((bytes_read, src, orig_dst))
    }
}

fn create_transparent_reply_socket(dst: SocketAddr) -> std::io::Result<UdpSocket> {
    let is_v6 = dst.is_ipv6();
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);
    #[cfg(all(unix, not(target_os = "solaris")))]
    let _ = sock.set_reuse_port(true);
    enable_tproxy_socket(&sock, is_v6)?;
    sock.bind(&dst.into())?;
    let std_udp: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_udp)
}

pub struct TproxyInbound {
    tag: String,
    listen_addr: SocketAddr,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl TproxyInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }
}

#[async_trait]
impl Inbound for TproxyInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "tproxy"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let is_v6 = self.listen_addr.is_ipv6();
        let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };

        // 1. Setup TCP TProxy listener
        let tcp_sock =
            Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(FluxError::Io)?;
        let _ = tcp_sock.set_nonblocking(true);
        let _ = tcp_sock.set_reuse_address(true);
        #[cfg(all(unix, not(target_os = "solaris")))]
        let _ = tcp_sock.set_reuse_port(true);
        let _ = enable_tproxy_socket(&tcp_sock, is_v6);
        tcp_sock
            .bind(&self.listen_addr.into())
            .map_err(FluxError::Io)?;
        tcp_sock.listen(1024).map_err(FluxError::Io)?;
        let std_listener: std::net::TcpListener = tcp_sock.into();
        let tcp_listener =
            tokio::net::TcpListener::from_std(std_listener).map_err(FluxError::Io)?;

        // 2. Setup UDP TProxy listener
        let udp_sock =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(FluxError::Io)?;
        let _ = udp_sock.set_nonblocking(true);
        let _ = udp_sock.set_reuse_address(true);
        #[cfg(all(unix, not(target_os = "solaris")))]
        let _ = udp_sock.set_reuse_port(true);
        let _ = enable_tproxy_socket(&udp_sock, is_v6);
        udp_sock
            .bind(&self.listen_addr.into())
            .map_err(FluxError::Io)?;
        let std_udp: std::net::UdpSocket = udp_sock.into();
        let udp_listener = Arc::new(UdpSocket::from_std(std_udp).map_err(FluxError::Io)?);

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());

        info!(
            "[{}] Linux TPROXY listening on {} (TCP & UDP)",
            tag, self.listen_addr
        );

        let mut shutdown_rx_tcp = self.shutdown_tx.subscribe();
        let disp_tcp = dispatcher.clone();
        let tag_tcp = tag.clone();
        let running_tcp = running.clone();

        // TCP Worker
        tokio::spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
                    res = tcp_listener.accept() => match res {
                        Ok(res) => res,
                        Err(e) => {
                            if running_tcp.load(Ordering::Relaxed) {
                                warn!("[{}] tproxy tcp accept error: {}", tag_tcp, e);
                            }
                            break;
                        }
                    },
                    _ = shutdown_rx_tcp.recv() => break,
                };

                flux_common::optimize_tcp_socket(&socket);
                let orig_dst = socket.local_addr().unwrap_or(client_addr);

                let meta = SessionMeta::new(
                    client_addr,
                    TargetAddress::Ip(orig_dst),
                    tag_tcp.clone(),
                    NetworkType::Tcp,
                );

                let disp = disp_tcp.clone();
                tokio::spawn(async move {
                    disp.dispatch_stream(meta, Box::new(socket)).await;
                });
            }
        });

        // UDP Worker
        let mut shutdown_rx_udp = self.shutdown_tx.subscribe();
        let disp_udp = dispatcher.clone();
        let tag_udp = tag.clone();
        let udp_socket = udp_listener.clone();

        tokio::spawn(async move {
            let sessions: Arc<
                DashMap<(SocketAddr, SocketAddr), tokio::sync::mpsc::Sender<UdpPacket>>,
            > = Arc::new(DashMap::new());
            let mut buf = vec![0u8; 65535];

            loop {
                #[cfg(target_os = "linux")]
                let (n, src, orig_dst_opt) = {
                    use std::os::fd::AsRawFd;
                    let raw_fd = udp_socket.as_raw_fd();
                    tokio::select! {
                        res = udp_socket.async_io(tokio::io::Interest::READABLE, || {
                            recv_tproxy_udp(raw_fd, &mut buf)
                        }) => match res {
                            Ok(r) => r,
                            Err(_) => break,
                        },
                        _ = shutdown_rx_udp.recv() => break,
                    }
                };

                #[cfg(not(target_os = "linux"))]
                let (n, src, orig_dst_opt) = tokio::select! {
                    res = udp_socket.recv_from(&mut buf) => match res {
                        Ok((n, s)) => (n, s, None),
                        Err(_) => break,
                    },
                    _ = shutdown_rx_udp.recv() => break,
                };

                let dst = orig_dst_opt.unwrap_or_else(|| udp_socket.local_addr().unwrap_or(src));
                let key = (src, dst);
                let payload = bytes::Bytes::copy_from_slice(&buf[..n]);

                let pkt = UdpPacket::new(payload, TargetAddress::Ip(src), TargetAddress::Ip(dst));

                if let Some(tx) = sessions.get(&key) {
                    let _ = tx.send(pkt).await;
                } else {
                    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);

                    let meta = SessionMeta::new(
                        src,
                        TargetAddress::Ip(dst),
                        tag_udp.clone(),
                        NetworkType::Udp,
                    );

                    let disp = disp_udp.clone();
                    tokio::spawn(async move {
                        disp.dispatch_packet(meta, pkt_rx, out_tx).await;
                    });

                    let _ = pkt_tx.send(pkt).await;
                    sessions.insert(key, pkt_tx.clone());

                    let reply_sock = match create_transparent_reply_socket(dst) {
                        Ok(s) => Arc::new(s),
                        Err(_) => udp_socket.clone(),
                    };
                    let sessions_clean = sessions.clone();

                    tokio::spawn(async move {
                        loop {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(30),
                                out_rx.recv(),
                            )
                            .await
                            {
                                Ok(Some(reply)) => {
                                    let _ = reply_sock.send_to(&reply.payload, src).await;
                                }
                                _ => {
                                    sessions_clean.remove(&key);
                                    break;
                                }
                            }
                        }
                    });
                }
            }
        });

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        Ok(())
    }
}
