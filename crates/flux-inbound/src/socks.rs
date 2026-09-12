use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use async_trait::async_trait;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use flux_protocol::socks5::{Socks5Command, Socks5Handshake, REP_SUCCESS};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};

pub struct SocksInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<(String, String)>,
    running: Arc<AtomicBool>,
}

impl SocksInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            users: vec![],
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_users(mut self, users: Vec<(String, String)>) -> Self {
        self.users = users;
        self
    }
}

#[async_trait]
impl Inbound for SocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let listen_ip = self.listen_addr.ip();
        let users = Arc::new(self.users.clone());

        info!("[{}] SOCKS5 inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let (mut socket, client_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(e) => {
                        if running.load(Ordering::Relaxed) {
                            warn!("[{}] accept error: {}", tag, e);
                        }
                        break;
                    }
                };
                crate::optimize_tcp_socket(&socket);

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();

                tokio::spawn(async move {
                    // 1. SOCKS5 Auth Handshake (No Auth or RFC 1929 Password)
                    let auth_user = match Socks5Handshake::server_handshake_with_auth(&mut socket, Some(&user_list)).await {
                        Ok(u) => u,
                        Err(e) => {
                            warn!("[{}] client {} handshake failed: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    // 2. Read Request
                    let req = match Socks5Handshake::read_request(&mut socket).await {
                        Ok(r) => r,
                        Err(e) => {
                            debug!("[{}] client {} read request failed: {}", inbound_tag, client_addr, e);
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
                                    warn!("[{}] connection to {} blocked: {}", inbound_tag, meta.destination, msg);
                                    let _ = Socks5Handshake::send_reply(&mut socket, 0x02, None).await; // 0x02 = connection not allowed by ruleset
                                    return;
                                }
                                Err(e) => {
                                    warn!("[{}] connection to {} failed: {}", inbound_tag, meta.destination, e);
                                    let _ = Socks5Handshake::send_reply(&mut socket, 0x05, None).await; // 0x05 = connection refused
                                    return;
                                }
                            };

                            if let Err(e) = Socks5Handshake::send_reply(&mut socket, REP_SUCCESS, None).await {
                                warn!("[{}] failed to send reply: {}", inbound_tag, e);
                                return;
                            }

                            disp.bridge_streams(meta, Box::new(socket), outbound_stream).await;
                        }
                        Socks5Command::UdpAssociate => {
                            // Bind local UDP socket for relaying on the matching inbound interface
                            let udp_socket = match UdpSocket::bind(SocketAddr::new(listen_ip, 0)).await {
                                Ok(s) => Arc::new(s),
                                Err(e) => {
                                    error!("[{}] failed to bind UDP relay socket on {}: {}", inbound_tag, listen_ip, e);
                                    let _ = Socks5Handshake::send_reply(&mut socket, 0x01, None).await;
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
                                socket.local_addr().map(|a| SocketAddr::new(a.ip(), local_udp_addr.port())).unwrap_or(local_udp_addr)
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
                                warn!("[{}] failed to send UDP associate reply: {}", inbound_tag, e);
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

                            let client_udp_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
                            let client_peer_clone = client_udp_peer.clone();

                            // Task to receive packets from UDP socket and forward to dispatcher
                            let udp_recv = udp_socket.clone();
                            let recv_task = tokio::spawn(async move {
                                let mut buf = vec![0u8; 65535];
                                loop {
                                    let (len, src) = match udp_recv.recv_from(&mut buf).await {
                                        Ok(r) => r,
                                        Err(_) => break,
                                    };

                                    *client_peer_clone.lock().await = Some(src);

                                    let payload = bytes::Bytes::copy_from_slice(&buf[..len]);
                                    if let Ok(pkt) = decode_socks5_udp(TargetAddress::Ip(src), payload)
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

                            // Wait until TCP socket closes
                            let mut dummy = [0u8; 1];
                            use tokio::io::AsyncReadExt;
                            let _ = socket.read(&mut dummy).await;

                            recv_task.abort();
                            send_task.abort();
                        }
                        Socks5Command::Bind => {
                            warn!("[{}] BIND not supported", inbound_tag);
                        }
                    }
                });
            }
        });

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}
