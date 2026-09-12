use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use async_trait::async_trait;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use flux_protocol::trojan::{hash_trojan_password, TrojanProtocol, TROJAN_CMD_CONNECT};

pub struct TrojanInbound {
    tag: String,
    listen_addr: SocketAddr,
    password_hashes: Vec<String>,
    tls_acceptor: TlsAcceptor,
    running: Arc<AtomicBool>,
}

impl TrojanInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        passwords: Vec<String>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        let password_hashes = passwords.into_iter().map(|p| hash_trojan_password(&p)).collect();
        Self {
            tag: tag.into(),
            listen_addr,
            password_hashes,
            tls_acceptor,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let hashes = self.password_hashes.clone();
        let acceptor = self.tls_acceptor.clone();

        info!("[{}] Trojan inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let (socket, client_addr) = match listener.accept().await {
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
                let valid_hashes = hashes.clone();
                let tls = acceptor.clone();

                tokio::spawn(async move {
                    let mut tls_stream = match tls.accept(socket).await {
                        Ok(s) => Box::new(s),
                        Err(e) => {
                            warn!("[{}] TLS handshake error from {}: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    let (cmd, target) = match TrojanProtocol::read_request_header(&mut tls_stream, &valid_hashes).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("[{}] Trojan auth/request failed from {}: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    if cmd == TROJAN_CMD_CONNECT {
                        let meta = SessionMeta::new(
                            client_addr,
                            target,
                            inbound_tag,
                            NetworkType::Tcp,
                        );

                        disp.dispatch_stream(meta, tls_stream).await;
                    } else if cmd == flux_protocol::trojan::TROJAN_CMD_UDP {
                        let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);
                        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);

                        let meta = SessionMeta::new(
                            client_addr,
                            target.clone(),
                            inbound_tag.clone(),
                            NetworkType::Udp,
                        );

                        let disp_clone = disp.clone();
                        tokio::spawn(async move {
                            disp_clone.dispatch_packet(meta, pkt_rx, out_tx).await;
                        });

                        let (mut read_half, mut write_half) = tokio::io::split(tls_stream);

                        let read_task = tokio::spawn(async move {
                            loop {
                                let mut atyp_buf = [0u8; 1];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut atyp_buf).await.is_err() {
                                    break;
                                }
                                let pkt_target = match flux_protocol::socks5::Socks5Handshake::read_address(&mut read_half, atyp_buf[0]).await {
                                    Ok(t) => t,
                                    Err(_) => break,
                                };

                                let mut len_buf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut len_buf).await.is_err() {
                                    break;
                                }
                                let payload_len = u16::from_be_bytes(len_buf) as usize;

                                let mut crlf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut crlf).await.is_err() {
                                    break;
                                }

                                let mut payload = vec![0u8; payload_len];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut payload).await.is_err() {
                                    break;
                                }

                                let packet = flux_types::UdpPacket::new(
                                    bytes::Bytes::from(payload),
                                    pkt_target.clone(),
                                    pkt_target,
                                );
                                if pkt_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        });

                        let write_task = tokio::spawn(async move {
                            while let Some(packet) = out_rx.recv().await {
                                let encoded = flux_protocol::udp::encode_trojan_udp(&packet);
                                if tokio::io::AsyncWriteExt::write_all(&mut write_half, &encoded).await.is_err() {
                                    break;
                                }
                                if tokio::io::AsyncWriteExt::flush(&mut write_half).await.is_err() {
                                    break;
                                }
                            }
                        });

                        tokio::select! {
                            _ = read_task => {},
                            _ = write_task => {},
                        }
                    } else {
                        warn!("[{}] Trojan unknown command: {}", inbound_tag, cmd);
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
