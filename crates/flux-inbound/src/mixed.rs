use async_trait::async_trait;
use flux_protocol::http::HttpHandshake;
use flux_protocol::socks5::{REP_SUCCESS, Socks5Command, Socks5Handshake};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

pub struct MixedInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<(String, String)>,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl MixedInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users: vec![],
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_users(mut self, users: Vec<(String, String)>) -> Self {
        self.users = users;
        self
    }

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

        tokio::spawn(async move {
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
                                            let encoded = encode_socks5_udp(&pkt);
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
                                warn!("[{}] BIND not supported in mixed mode", inbound_tag);
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
        Ok(())
    }
}
