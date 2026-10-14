use async_trait::async_trait;
use flux_protocol::vless::{VLESS_CMD_TCP, VlessProtocol};
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct VlessInbound {
    tag: String,
    listen_addr: SocketAddr,
    uuids: Vec<Uuid>,
    pipeline: flux_transport::pipeline::ServerTransportPipeline,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl VlessInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        uuids: Vec<Uuid>,
        pipeline: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            uuids,
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
impl Inbound for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "vless"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = crate::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let uuids = self.uuids.clone();
        let pipeline = self.pipeline.clone();
        let rate_limiter = self.rate_limiter.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] VLESS inbound listening on {}", tag, self.listen_addr);

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
                        debug!("[{}] VLESS listener shutting down cleanly", tag);
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
                let uuids = uuids.clone();
                let pipe = pipeline.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let handshake_fut = async {
                        let mut stream = pipe.unwrap(socket).await?;
                        let req = VlessProtocol::read_request_header(&mut stream, &uuids).await?;
                        VlessProtocol::write_response_header(&mut stream).await?;
                        Ok::<_, FluxError>((stream, req))
                    };

                    let (stream, req) = match tokio::time::timeout(
                        std::time::Duration::from_secs(15),
                        handshake_fut,
                    )
                    .await
                    {
                        Ok(Ok(res)) => res,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] VLESS handshake failed from {}: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "[{}] VLESS handshake timed out from {}",
                                inbound_tag, client_addr
                            );
                            return;
                        }
                    };

                    if req.command == VLESS_CMD_TCP {
                        let meta = SessionMeta::new(
                            client_addr,
                            req.address,
                            inbound_tag,
                            NetworkType::Tcp,
                        );

                        let final_stream: BoxedStream = if req.is_vision {
                            Box::new(flux_protocol::vision::VisionServerStream::new(stream))
                        } else {
                            stream
                        };

                        disp.dispatch_stream(meta, final_stream).await;
                    } else if req.command == flux_protocol::vless::VLESS_CMD_UDP {
                        let (pkt_tx, pkt_rx) =
                            tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);
                        let (out_tx, mut out_rx) =
                            tokio::sync::mpsc::channel::<flux_types::UdpPacket>(128);

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
                        let read_fut = async move {
                            while let Ok(packet) = flux_protocol::udp::decode_vless_udp_packet(
                                &mut read_half,
                                &req_addr,
                            )
                            .await
                            {
                                if pkt_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        };

                        let write_fut = async move {
                            while let Some(packet) = out_rx.recv().await {
                                let encoded =
                                    flux_protocol::udp::encode_vless_udp_reply_packet(&packet);
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
                        warn!(
                            "[{}] VLESS unsupported command: {}",
                            inbound_tag, req.command
                        );
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
