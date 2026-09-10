use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};
use async_trait::async_trait;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use flux_protocol::socks5::{Socks5Command, Socks5Handshake, REP_SUCCESS};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};

pub struct SocksInbound {
    tag: String,
    listen_addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl SocksInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            running: Arc::new(AtomicBool::new(false)),
        }
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
                let _ = socket.set_nodelay(true);

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();

                tokio::spawn(async move {
                    // 1. SOCKS5 Auth Handshake
                    if let Err(e) = Socks5Handshake::server_handshake(&mut socket).await {
                        warn!("[{}] client {} handshake failed: {}", inbound_tag, client_addr, e);
                        return;
                    }

                    // 2. Read Request
                    let req = match Socks5Handshake::read_request(&mut socket).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("[{}] client {} read request failed: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    match req.command {
                        Socks5Command::Connect => {
                            // Send success reply
                            if let Err(e) = Socks5Handshake::send_reply(&mut socket, REP_SUCCESS, None).await {
                                warn!("[{}] failed to send reply: {}", inbound_tag, e);
                                return;
                            }

                            let meta = SessionMeta::new(
                                client_addr,
                                req.address,
                                inbound_tag.clone(),
                                NetworkType::Tcp,
                            );

                            disp.dispatch_stream(meta, Box::new(socket)).await;
                        }
                        Socks5Command::UdpAssociate => {
                            // Bind local UDP socket for relaying
                            let udp_socket = match UdpSocket::bind("127.0.0.1:0").await {
                                Ok(s) => Arc::new(s),
                                Err(e) => {
                                    error!("[{}] failed to bind UDP relay socket: {}", inbound_tag, e);
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

                            if let Err(e) = Socks5Handshake::send_reply(
                                &mut socket,
                                REP_SUCCESS,
                                Some(local_udp_addr),
                            )
                            .await
                            {
                                warn!("[{}] failed to send UDP associate reply: {}", inbound_tag, e);
                                return;
                            }

                            // Keep TCP connection open to maintain UDP association lifecycle
                            let (pkt_tx, pkt_rx) = mpsc::channel::<UdpPacket>(128);
                            let (out_tx, mut out_rx) = mpsc::channel::<UdpPacket>(128);

                            let meta = SessionMeta::new(
                                client_addr,
                                req.address.clone(),
                                inbound_tag.clone(),
                                NetworkType::Udp,
                            );

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
                                    if let Ok(pkt) = decode_socks5_udp(TargetAddress::Ip(src), payload) {
                                        if pkt_tx.send(pkt).await.is_err() {
                                            break;
                                        }
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
