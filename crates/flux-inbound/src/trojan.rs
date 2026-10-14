use async_trait::async_trait;
use flux_protocol::trojan::{TROJAN_CMD_CONNECT, TrojanProtocol, hash_trojan_password};
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

pub struct TrojanInbound {
    tag: String,
    listen_addr: SocketAddr,
    password_hashes: Vec<String>,
    pipeline: flux_transport::pipeline::ServerTransportPipeline,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl TrojanInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        passwords: Vec<String>,
        pipeline: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        let password_hashes = passwords
            .into_iter()
            .map(|p| hash_trojan_password(&p))
            .collect();
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            password_hashes,
            pipeline,
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }
}

#[async_trait]
impl Inbound for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "trojan"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = crate::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let hashes = self.password_hashes.clone();
        let pipeline = self.pipeline.clone();
        let rate_limiter = self.rate_limiter.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] Trojan inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
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
                        debug!("[{}] Trojan listener shutting down cleanly", tag);
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
                let valid_hashes = hashes.clone();
                let pipe = pipeline.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let handshake_fut = async {
                        let mut stream = pipe.unwrap(socket).await?;
                        let (cmd, target) =
                            TrojanProtocol::read_request_header(&mut stream, &valid_hashes).await?;
                        Ok::<_, FluxError>((stream, cmd, target))
                    };

                    let (tls_stream, cmd, target) = match tokio::time::timeout(
                        std::time::Duration::from_secs(15),
                        handshake_fut,
                    )
                    .await
                    {
                        Ok(Ok(res)) => res,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] Trojan handshake/auth failed from {}: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "[{}] Trojan handshake timed out from {}",
                                inbound_tag, client_addr
                            );
                            return;
                        }
                    };

                    if cmd == TROJAN_CMD_CONNECT {
                        let meta =
                            SessionMeta::new(client_addr, target, inbound_tag, NetworkType::Tcp);

                        disp.dispatch_stream(meta, tls_stream).await;
                    } else if cmd == flux_protocol::trojan::TROJAN_CMD_UDP {
                        let (pkt_tx, pkt_rx) =
                            tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);
                        let (out_tx, mut out_rx) =
                            tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);

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

                        let read_fut = async move {
                            loop {
                                let mut atyp_buf = [0u8; 1];
                                if tokio::io::AsyncReadExt::read_exact(
                                    &mut read_half,
                                    &mut atyp_buf,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                                let pkt_target =
                                    match flux_protocol::socks5::Socks5Handshake::read_address(
                                        &mut read_half,
                                        atyp_buf[0],
                                    )
                                    .await
                                    {
                                        Ok(t) => t,
                                        Err(_) => break,
                                    };

                                let mut len_buf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut len_buf)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                let payload_len = u16::from_be_bytes(len_buf) as usize;
                                if payload_len > 65507 {
                                    break;
                                }

                                let mut crlf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut crlf)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }

                                let mut payload = vec![0u8; payload_len];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut payload)
                                    .await
                                    .is_err()
                                {
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
                        };

                        let write_fut = async move {
                            while let Some(packet) = out_rx.recv().await {
                                let encoded = flux_protocol::udp::encode_trojan_udp_reply(&packet);
                                if tokio::io::AsyncWriteExt::write_all(&mut write_half, &encoded)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                if tokio::io::AsyncWriteExt::flush(&mut write_half)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        };

                        tokio::select! {
                            _ = read_fut => {},
                            _ = write_fut => {},
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
        let _ = self.shutdown_tx.send(());
        Ok(())
    }
}
