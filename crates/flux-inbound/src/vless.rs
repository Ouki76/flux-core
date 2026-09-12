use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;
use async_trait::async_trait;
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use flux_protocol::vless::{VlessProtocol, VLESS_CMD_TCP};

pub struct VlessInbound {
    tag: String,
    listen_addr: SocketAddr,
    uuids: Vec<Uuid>,
    tls_acceptor: Option<TlsAcceptor>,
    reality_config: Option<flux_transport::reality::RealityServerConfig>,
    running: Arc<AtomicBool>,
}

impl VlessInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        uuids: Vec<Uuid>,
        tls_acceptor: Option<TlsAcceptor>,
        reality_config: Option<flux_transport::reality::RealityServerConfig>,
    ) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            uuids,
            tls_acceptor,
            reality_config,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let uuids = self.uuids.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let reality_config = self.reality_config.clone();

        info!("[{}] VLESS inbound listening on {}", tag, self.listen_addr);

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
                let uuids = uuids.clone();
                let acceptor = tls_acceptor.clone();
                let reality_cfg = reality_config.clone();

                tokio::spawn(async move {
                    let mut stream: BoxedStream = if let Some(r_cfg) = reality_cfg {
                        match flux_transport::reality::RealityHandshake::server_handshake(&mut socket, &r_cfg).await {
                            Ok(_) => Box::new(socket),
                            Err(e) => {
                                warn!("[{}] Reality handshake failed from {}: {}", inbound_tag, client_addr, e);
                                return;
                            }
                        }
                    } else if let Some(tls) = acceptor {
                        match tls.accept(socket).await {
                            Ok(s) => Box::new(s),
                            Err(e) => {
                                warn!("[{}] TLS handshake error from {}: {}", inbound_tag, client_addr, e);
                                return;
                            }
                        }
                    } else {
                        Box::new(socket)
                    };

                    let req = match VlessProtocol::read_request_header(&mut stream, &uuids).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("[{}] VLESS handshake failed from {}: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    if let Err(e) = VlessProtocol::write_response_header(&mut stream).await {
                        warn!("[{}] VLESS write response header failed: {}", inbound_tag, e);
                        return;
                    }

                    if req.command == VLESS_CMD_TCP {
                        let meta = SessionMeta::new(
                            client_addr,
                            req.address,
                            inbound_tag,
                            NetworkType::Tcp,
                        );

                        disp.dispatch_stream(meta, stream).await;
                    } else if req.command == flux_protocol::vless::VLESS_CMD_UDP {
                        let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);
                        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);

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

                        let (mut read_half, mut write_half) = tokio::io::split(stream);

                        let req_addr = req.address.clone();
                        let read_task = tokio::spawn(async move {
                            loop {
                                let mut len_buf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut len_buf).await.is_err() {
                                    break;
                                }
                                let payload_len = u16::from_be_bytes(len_buf) as usize;
                                let mut payload = vec![0u8; payload_len];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut payload).await.is_err() {
                                    break;
                                }

                                let packet = flux_types::UdpPacket::new(
                                    bytes::Bytes::from(payload),
                                    req_addr.clone(),
                                    req_addr.clone(),
                                );
                                if pkt_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        });

                        let write_task = tokio::spawn(async move {
                            while let Some(packet) = out_rx.recv().await {
                                let encoded = flux_protocol::udp::encode_vless_udp(&packet.payload);
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
                        warn!("[{}] VLESS unsupported command: {}", inbound_tag, req.command);
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
