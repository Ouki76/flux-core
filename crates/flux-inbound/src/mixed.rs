use async_trait::async_trait;
use flux_protocol::http::HttpHandshake;
use flux_protocol::socks5::{
    REP_COMMAND_NOT_SUPPORTED, REP_SUCCESS, Socks5Command, Socks5Handshake,
};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp_reply};
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

/// /// One port that speaks SOCKS5 and HTTP, decided by the first byte.
pub struct MixedInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<(String, String)>,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
}

impl MixedInbound {
    /// A listener named `tag` on `listen_addr`.
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users: vec![],
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            tasks: crate::InboundTasks::new(),
        }
    }

    /// Requires credentials for both protocols.
    pub fn with_users(mut self, users: Vec<(String, String)>) -> Self {
        self.users = users;
        self
    }

    /// Rejects connections above the limiter before any per-connection work.
    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }
}

#[async_trait]
impl Inbound for MixedInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "mixed"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = crate::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let users = Arc::new(self.users.clone());
        let listen_ip = self.listen_addr.ip();
        let rate_limiter = self.rate_limiter.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!(
            "[{}] Mixed (SOCKS5/HTTP) inbound listening on {}",
            tag, self.listen_addr
        );

        self.tasks.spawn(async move {
            loop {
                let (mut socket, client_addr) = tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok(res) => res,
                            Err(e) => {
                                if running.load(Ordering::Relaxed) {
                                    warn!("[{}] accept error: {}", tag, e);
                                }
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("[{}] Mixed listener shutting down cleanly", tag);
                        break;
                    }
                };
                // Rate limiting: reject before any per-connection work.
                let conn_guard = match &rate_limiter {
                    Some(rl) => match rl.try_acquire(client_addr.ip()) {
                        Some(g) => Some(g),
                        None => {
                            debug!(
                                "[{}] connection from {} rejected by rate limiter",
                                tag, client_addr
                            );
                            continue;
                        }
                    },
                    None => None,
                };
                crate::optimize_tcp_socket(&socket);

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    // Peek the first byte to detect protocol with bounded timeout
                    let mut peek_buf = [0u8; 1];
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        socket.peek(&mut peek_buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] client {} peek failed: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            debug!("[{}] client {} peek timed out", inbound_tag, client_addr);
                            return;
                        }
                    };
                    if n == 0 {
                        return;
                    }

                    if peek_buf[0] == 0x05 {
                        // SOCKS5 with optional auth
                        let handshake_fut = async {
                            let auth_user = Socks5Handshake::server_handshake_with_auth(
                                &mut socket,
                                Some(&user_list),
                            )
                            .await?;
                            let req = Socks5Handshake::read_request(&mut socket).await?;
                            Ok::<_, FluxError>((auth_user, req))
                        };

                        let (auth_user, req) = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            handshake_fut,
                        )
                        .await
                        {
                            Ok(Ok(res)) => res,
                            Ok(Err(e)) => {
                                warn!("[{}] SOCKS5 handshake failed: {}", inbound_tag, e);
                                return;
                            }
                            Err(_) => {
                                debug!("[{}] SOCKS5 handshake timed out", inbound_tag);
                                return;
                            }
                        };

                        match req.command {
                            Socks5Command::Connect => {
                                let mut meta = SessionMeta::new(
                                    client_addr,
                                    req.address,
                                    inbound_tag.clone(),
                                    NetworkType::Tcp,
                                );
                                if let Some(u) = auth_user {
                                    meta = meta.with_user(u);
                                }

                                let outbound_stream = match disp.dial_outbound(&meta).await {
                                    Ok(s) => s,
                                    Err(FluxError::Blocked(msg)) => {
                                        warn!(
                                            "[{}] connection to {} blocked: {}",
                                            inbound_tag, meta.destination, msg
                                        );
                                        let _ =
                                            Socks5Handshake::send_reply(&mut socket, 0x02, None)
                                                .await;
                                        return;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "[{}] connection to {} failed: {}",
                                            inbound_tag, meta.destination, e
                                        );
                                        let _ =
                                            Socks5Handshake::send_reply(&mut socket, 0x05, None)
                                                .await;
                                        return;
                                    }
                                };

                                if let Err(e) =
                                    Socks5Handshake::send_reply(&mut socket, REP_SUCCESS, None)
                                        .await
                                {
                                    warn!("[{}] SOCKS5 send reply failed: {}", inbound_tag, e);
                                    return;
                                }

                                disp.bridge_streams(meta, Box::new(socket), outbound_stream)
                                    .await;
                            }
                            Socks5Command::UdpAssociate => {
                                // Bind local UDP socket for relaying on the matching inbound interface
                                let udp_socket =
                                    match UdpSocket::bind(SocketAddr::new(listen_ip, 0)).await {
                                        Ok(s) => Arc::new(s),
                                        Err(e) => {
                                            error!(
                                                "[{}] failed to bind UDP relay socket on {}: {}",
                                                inbound_tag, listen_ip, e
                                            );
                                            let _ = Socks5Handshake::send_reply(
                                                &mut socket,
                                                0x01,
                                                None,
                                            )
                                            .await;
                                            return;
                                        }
                                    };

                                let local_udp_addr = match udp_socket.local_addr() {
                                    Ok(a) => a,
                                    Err(e) => {
                                        error!("[{}] local_addr failed: {}", inbound_tag, e);
                                        return;
                                    }
                                };

                                let reply_addr = if listen_ip.is_unspecified() {
                                    socket
                                        .local_addr()
                                        .map(|a| SocketAddr::new(a.ip(), local_udp_addr.port()))
                                        .unwrap_or(local_udp_addr)
                                } else {
                                    local_udp_addr
                                };

                                if let Err(e) = Socks5Handshake::send_reply(
                                    &mut socket,
                                    REP_SUCCESS,
                                    Some(reply_addr),
                                )
                                .await
                                {
                                    warn!(
                                        "[{}] failed to send UDP associate reply: {}",
                                        inbound_tag, e
                                    );
                                    return;
                                }

                                // Keep TCP connection open to maintain UDP association lifecycle
                                let (pkt_tx, pkt_rx) = mpsc::channel::<UdpPacket>(128);
                                let (out_tx, mut out_rx) = mpsc::channel::<UdpPacket>(128);

                                let mut meta = SessionMeta::new(
                                    client_addr,
                                    req.address.clone(),
                                    inbound_tag.clone(),
                                    NetworkType::Udp,
                                );
                                if let Some(u) = auth_user {
                                    meta = meta.with_user(u);
                                }

                                let disp_clone = disp.clone();
                                tokio::spawn(async move {
                                    disp_clone.dispatch_packet(meta, pkt_rx, out_tx).await;
                                });

                                let client_udp_peer: Arc<Mutex<Option<SocketAddr>>> =
                                    Arc::new(Mutex::new(None));
                                let client_peer_clone = client_udp_peer.clone();
                                let allowed_client_ip = match &req.address {
                                    TargetAddress::Ip(sa) if !sa.ip().is_unspecified() => sa.ip(),
                                    _ => client_addr.ip(),
                                };
                                let tag_for_recv = inbound_tag.clone();

                                // Task to receive packets from UDP socket and forward to dispatcher
                                let udp_recv = udp_socket.clone();
                                let recv_task = tokio::spawn(async move {
                                    let mut buf = vec![0u8; 65535];
                                    loop {
                                        let (len, src) = match udp_recv.recv_from(&mut buf).await {
                                            Ok(r) => r,
                                            Err(_) => break,
                                        };

                                        // Verify source IP matches authenticated TCP client to prevent session hijacking
                                        if src.ip() != allowed_client_ip {
                                            warn!(
                                                "[{}] dropped unauthorized UDP packet from {} (expected client IP: {})",
                                                tag_for_recv, src, allowed_client_ip
                                            );
                                            continue;
                                        }

                                        // Pin UDP session to the first packet's source port to prevent cross-port hijacking
                                        let mut peer_guard = client_peer_clone.lock().await;
                                        if let Some(pinned_peer) = *peer_guard {
                                            if src != pinned_peer {
                                                warn!(
                                                    "[{}] dropped UDP packet from unexpected source {} (session pinned to {})",
                                                    tag_for_recv, src, pinned_peer
                                                );
                                                continue;
                                            }
                                        } else {
                                            *peer_guard = Some(src);
                                        }
                                        drop(peer_guard);

                                        let payload = bytes::Bytes::copy_from_slice(&buf[..len]);
                                        if let Ok(pkt) =
                                            decode_socks5_udp(TargetAddress::Ip(src), payload)
                                            && pkt_tx.send(pkt).await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                });

                                // Task to send packets from out_rx back to client
                                let udp_send = udp_socket.clone();
                                let send_task = tokio::spawn(async move {
                                    while let Some(pkt) = out_rx.recv().await {
                                        let maybe_peer = *client_udp_peer.lock().await;
                                        if let Some(client_sock) = maybe_peer {
                                            let encoded = encode_socks5_udp_reply(&pkt);
                                            let _ = udp_send.send_to(&encoded, client_sock).await;
                                        }
                                    }
                                });

                                // Keep alive until TCP control stream closes (client disconnects)
                                let mut probe_buf = [0u8; 1];
                                use tokio::io::AsyncReadExt;
                                loop {
                                    match socket.read(&mut probe_buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(_) => continue,
                                    }
                                }

                                recv_task.abort();
                                send_task.abort();
                            }
                            Socks5Command::Bind => {
                                // RFC 1928 §6: answer unsupported commands with
                                // REP 0x07 instead of closing silently.
                                warn!(
                                    "[{}] BIND not supported in mixed mode; replying 0x07",
                                    inbound_tag
                                );
                                let _ = Socks5Handshake::send_reply(
                                    &mut socket,
                                    REP_COMMAND_NOT_SUPPORTED,
                                    None,
                                )
                                .await;
                            }
                        }
                    } else {
                        // HTTP proxy with auth support matching user_list
                        let handshake_fut = HttpHandshake::server_handshake_with_auth(
                            &mut socket,
                            Some(&user_list),
                        );
                        let (target, prefix_opt, auth_user) = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            handshake_fut,
                        )
                        .await
                        {
                            Ok(Ok(t)) => t,
                            Ok(Err(e)) => {
                                warn!(
                                    "[{}] client {} HTTP handshake failed: {}",
                                    inbound_tag, client_addr, e
                                );
                                return;
                            }
                            Err(_) => {
                                debug!(
                                    "[{}] client {} HTTP handshake timed out",
                                    inbound_tag, client_addr
                                );
                                return;
                            }
                        };

                        let mut meta =
                            SessionMeta::new(client_addr, target, inbound_tag, NetworkType::Tcp);
                        if let Some(u) = auth_user {
                            meta = meta.with_user(u);
                        }

                        let stream: flux_types::BoxedStream = if let Some(prefix) = prefix_opt {
                            Box::new(flux_common::copy::PrefixedStream::new(socket, prefix))
                        } else {
                            Box::new(socket)
                        };

                        disp.dispatch_stream(meta, stream).await;
                    }
                });
            }
        });

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

#[cfg(test)]
mod tests {
    use super::*;
    use flux_types::{BoxedStream, SessionMeta, UdpPacket};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct NullDispatcher;

    #[async_trait::async_trait]
    impl Dispatcher for NullDispatcher {
        async fn dispatch_stream(&self, _meta: SessionMeta, _stream: BoxedStream) {}
        async fn dial_outbound(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            Err(FluxError::Protocol {
                protocol: "test",
                message: "no outbound in this test".into(),
            })
        }
        async fn bridge_streams(&self, _m: SessionMeta, _a: BoxedStream, _b: BoxedStream) {}
        async fn dispatch_packet(
            &self,
            _meta: SessionMeta,
            _rx: mpsc::Receiver<UdpPacket>,
            _tx: mpsc::Sender<UdpPacket>,
        ) {
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn spawn() -> (Arc<MixedInbound>, SocketAddr) {
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let inbound = Arc::new(MixedInbound::new("mixed-test", addr));
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(NullDispatcher);
        inbound.start(dispatcher).await.unwrap();
        for _ in 0..100 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (inbound, addr)
    }

    /// The mixed listener must auto-detect SOCKS5 by the first byte and, for an
    /// unsupported command, answer RFC 1928's REP 0x07 rather than closing.
    #[tokio::test]
    async fn socks5_bind_gets_command_not_supported() {
        let (inbound, addr) = spawn().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00]);

        let mut req = vec![0x05, 0x02, 0x00, 0x01];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&0u16.to_be_bytes());
        s.write_all(&req).await.unwrap();

        let mut reply = [0u8; 10];
        tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut reply))
            .await
            .expect("mixed inbound must answer BIND instead of hanging up")
            .expect("reply read");
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], REP_COMMAND_NOT_SUPPORTED);
        inbound.stop().await.unwrap();
    }

    /// The same listener must recognise an HTTP request (first byte not 0x05) and
    /// fail the handshake instead of treating it as SOCKS5.
    #[tokio::test]
    async fn http_request_is_not_parsed_as_socks5() {
        let (inbound, addr) = spawn().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        // Unparsable as HTTP (no CRLFCRLF) — the point is only that it is not
        // misrouted into the SOCKS5 parser, which would read it as a greeting.
        s.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut buf)).await;
        // Either EOF/timeout (connection dropped) — but never a SOCKS5 greeting
        // reply (0x05 0x00) followed by data.
        if let Ok(Ok(_)) = res {
            assert_ne!(
                &buf[..2],
                &[0x05, 0x00],
                "HTTP request was answered as SOCKS5"
            );
        }
        inbound.stop().await.unwrap();
    }
}
