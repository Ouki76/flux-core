use async_trait::async_trait;
use flux_protocol::socks5::{
    REP_COMMAND_NOT_SUPPORTED, REP_SUCCESS, Socks5Command, Socks5Handshake,
};
use flux_protocol::udp::decode_socks5_udp;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

/// /// A SOCKS5 listener.
pub struct SocksInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<(String, String)>,
    pipeline: flux_transport::pipeline::ServerTransportPipeline,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
}

impl SocksInbound {
    /// A listener named `tag` on `listen_addr`.
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users: vec![],
            pipeline: flux_transport::pipeline::ServerTransportPipeline::raw(),
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            tasks: crate::InboundTasks::new(),
        }
    }

    /// Rejects connections above the limiter before any per-connection work.
    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    /// Requires username/password authentication with one of these pairs.
    pub fn with_users(mut self, users: Vec<(String, String)>) -> Self {
        self.users = users;
        self
    }

    /// Applies a transport pipeline to accepted connections.
    pub fn with_pipeline(
        mut self,
        pipe: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        self.pipeline = pipe;
        self
    }
}

#[async_trait]
impl Inbound for SocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "socks"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = crate::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let listen_ip = self.listen_addr.ip();
        let users = Arc::new(self.users.clone());
        let pipeline = Arc::new(self.pipeline.clone());
        let rate_limiter = self.rate_limiter.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] SOCKS5 inbound listening on {}", tag, self.listen_addr);

        self.tasks.spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
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
                        debug!("[{}] SOCKS5 listener shutting down cleanly", tag);
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
                let local_sock_addr = socket.local_addr().ok();

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();
                let pipe = pipeline.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let mut stream: flux_types::BoxedStream = match pipe.unwrap(socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "[{}] client {} transport handshake failed: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                    };

                    // 1. SOCKS5 Auth Handshake (No Auth or RFC 1929 Password) with bounded timeout
                    let handshake_fut = async {
                        let auth_user = Socks5Handshake::server_handshake_with_auth(
                            &mut stream,
                            Some(&user_list),
                        )
                        .await?;
                        let req = Socks5Handshake::read_request(&mut stream).await?;
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
                            warn!(
                                "[{}] client {} handshake failed: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "[{}] client {} handshake timed out",
                                inbound_tag, client_addr
                            );
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
                                        Socks5Handshake::send_reply(&mut stream, 0x02, None).await; // 0x02 = connection not allowed by ruleset
                                    return;
                                }
                                Err(e) => {
                                    warn!(
                                        "[{}] connection to {} failed: {}",
                                        inbound_tag, meta.destination, e
                                    );
                                    let _ =
                                        Socks5Handshake::send_reply(&mut stream, 0x05, None).await; // 0x05 = connection refused
                                    return;
                                }
                            };

                            if let Err(e) =
                                Socks5Handshake::send_reply(&mut stream, REP_SUCCESS, None).await
                            {
                                warn!("[{}] failed to send reply: {}", inbound_tag, e);
                                return;
                            }

                            disp.bridge_streams(meta, stream, outbound_stream).await;
                        }
                        Socks5Command::UdpAssociate => {
                            // Bind local UDP socket for relaying on the matching inbound interface
                            let udp_socket = match UdpSocket::bind(SocketAddr::new(listen_ip, 0))
                                .await
                            {
                                Ok(s) => Arc::new(s),
                                Err(e) => {
                                    error!(
                                        "[{}] failed to bind UDP relay socket on {}: {}",
                                        inbound_tag, listen_ip, e
                                    );
                                    let _ =
                                        Socks5Handshake::send_reply(&mut stream, 0x01, None).await;
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
                                local_sock_addr
                                    .map(|a| SocketAddr::new(a.ip(), local_udp_addr.port()))
                                    .unwrap_or(local_udp_addr)
                            } else {
                                local_udp_addr
                            };

                            if let Err(e) = Socks5Handshake::send_reply(
                                &mut stream,
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
                                // One buffer for the whole loop: encoding a reply used to
                                // allocate a fresh `BytesMut` per datagram.
                                let mut encoded = bytes::BytesMut::new();
                                while let Some(pkt) = out_rx.recv().await {
                                    let maybe_peer = *client_udp_peer.lock().await;
                                    if let Some(client_sock) = maybe_peer {
                                        flux_protocol::udp::encode_socks5_udp_reply_into(
                                            &mut encoded,
                                            &pkt,
                                        );
                                        let _ = udp_send.send_to(&encoded, client_sock).await;
                                    }
                                }
                            });

                            // Keep alive until TCP control stream closes (client disconnects)
                            let mut probe_buf = [0u8; 1];
                            use tokio::io::AsyncReadExt;
                            loop {
                                match stream.read(&mut probe_buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => continue,
                                }
                            }

                            recv_task.abort();
                            send_task.abort();
                        }
                        Socks5Command::Bind => {
                            // RFC 1928 §6: unsupported commands must be answered
                            // with REP 0x07. Closing silently left the client
                            // waiting for a reply until its own timeout.
                            warn!("[{}] BIND not supported; replying 0x07", inbound_tag);
                            let _ = Socks5Handshake::send_reply(
                                &mut stream,
                                REP_COMMAND_NOT_SUPPORTED,
                                None,
                            )
                            .await;
                        }
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

    /// Minimal dispatcher: the SOCKS tests only exercise the handshake layer, so
    /// nothing is ever dispatched.
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
        async fn bridge_streams(&self, _meta: SessionMeta, _a: BoxedStream, _b: BoxedStream) {}
        async fn dispatch_packet(
            &self,
            _meta: SessionMeta,
            _rx: mpsc::Receiver<UdpPacket>,
            _tx: mpsc::Sender<UdpPacket>,
        ) {
        }
    }

    /// Reserves a free loopback port, then releases it for the inbound to take.
    /// `listen_addr()` reports the *configured* address, so port 0 would give the
    /// tests nothing to connect to.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    async fn spawn_inbound() -> (Arc<SocksInbound>, SocketAddr) {
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let inbound = Arc::new(SocksInbound::new("socks-test", addr));
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(NullDispatcher);
        inbound.start(dispatcher).await.unwrap();

        // Wait for the listener to accept connections instead of sleeping blind.
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (inbound, addr)
    }

    /// RFC 1928 §6: an unsupported command (BIND) must be answered with REP 0x07.
    /// The server used to close silently, leaving the client to hang until its
    /// own timeout.
    #[tokio::test]
    async fn bind_command_is_answered_with_command_not_supported() {
        let (inbound, addr) = spawn_inbound().await;

        let mut s = TcpStream::connect(addr)
            .await
            .expect("connect to socks inbound");
        // Greeting: version 5, one method, "no authentication".
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, 0x00], "server must pick the no-auth method");

        // BIND to 127.0.0.1:0
        let mut req = vec![0x05, 0x02, 0x00, 0x01];
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&0u16.to_be_bytes());
        s.write_all(&req).await.unwrap();

        let mut reply = [0u8; 10];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut reply))
            .await
            .expect("server must reply to BIND instead of closing silently")
            .expect("reply read");
        assert_eq!(n, 10);
        assert_eq!(reply[0], 0x05, "reply version");
        assert_eq!(
            reply[1], REP_COMMAND_NOT_SUPPORTED,
            "unsupported command must be answered with REP 0x07, got 0x{:02x}",
            reply[1]
        );

        inbound.stop().await.unwrap();
    }

    /// An unsupported auth method must be rejected with 0xFF and the connection
    /// closed, not silently accepted.
    #[tokio::test]
    async fn unsupported_auth_method_is_rejected() {
        let (inbound, addr) = spawn_inbound().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        // Offering only GSSAPI (0x01), which this inbound does not implement.
        s.write_all(&[0x05, 0x01, 0x01]).await.unwrap();
        let mut resp = [0u8; 2];
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut resp)).await;
        assert_eq!(
            resp[1], 0xFF,
            "server must answer 0xFF when no method is acceptable"
        );
        inbound.stop().await.unwrap();
    }

    /// A greeting with the wrong protocol version must not be accepted.
    #[tokio::test]
    async fn wrong_version_is_rejected() {
        let (inbound, addr) = spawn_inbound().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut buf)).await;
        // Either the connection is closed (EOF/err) or an explicit rejection.
        if let Ok(Ok(_)) = res {
            assert_eq!(buf[1], 0xFF, "SOCKS4 greeting must be rejected");
        }
        inbound.stop().await.unwrap();
    }
}
