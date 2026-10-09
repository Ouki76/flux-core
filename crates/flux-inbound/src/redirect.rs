use async_trait::async_trait;
use flux_types::{Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
pub fn get_original_destination(socket: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();

    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        const SO_ORIGINAL_DST: libc::c_int = 80;

        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret == 0 {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
        }

        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let ret6 = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            SO_ORIGINAL_DST,
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        );
        if ret6 == 0 {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            return Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port));
        }

        socket.local_addr()
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_original_destination(socket: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
    socket.local_addr()
}

pub struct RedirectInbound {
    tag: String,
    listen_addr: SocketAddr,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl RedirectInbound {
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
impl Inbound for RedirectInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "redirect"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = flux_common::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!(
            "[{}] Linux REDIRECT inbound listening on {}",
            tag, self.listen_addr
        );

        tokio::spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
                    res = listener.accept() => match res {
                        Ok(res) => res,
                        Err(e) => {
                            if running.load(Ordering::Relaxed) {
                                warn!("[{}] redirect accept error: {}", tag, e);
                            }
                            break;
                        }
                    },
                    _ = shutdown_rx.recv() => {
                        debug!("[{}] redirect listener shutting down cleanly", tag);
                        break;
                    }
                };

                flux_common::optimize_tcp_socket(&socket);

                let orig_dst = match get_original_destination(&socket) {
                    Ok(dst) => dst,
                    Err(e) => {
                        warn!(
                            "[{}] failed to get SO_ORIGINAL_DST from {}: {}",
                            tag, client_addr, e
                        );
                        continue;
                    }
                };

                // Prevent infinite self-connection loops if directly connecting to the REDIRECT port
                if let Ok(local) = socket.local_addr()
                    && orig_dst == local
                {
                    warn!(
                        "[{}] direct connection from {} to redirect port {} rejected to prevent forwarding loop",
                        tag, client_addr, local
                    );
                    continue;
                }

                let meta = SessionMeta::new(
                    client_addr,
                    TargetAddress::Ip(orig_dst),
                    tag.clone(),
                    NetworkType::Tcp,
                );

                let disp = dispatcher.clone();
                tokio::spawn(async move {
                    disp.dispatch_stream(meta, Box::new(socket)).await;
                });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_redirect_original_dst_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let orig = get_original_destination(&sock).unwrap();
            assert_eq!(orig.port(), l_addr.port());
        });

        let _cli = tokio::net::TcpStream::connect(l_addr).await.unwrap();
    }
}
