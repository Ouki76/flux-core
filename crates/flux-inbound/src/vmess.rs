use async_trait::async_trait;
use flux_protocol::mux::{MuxConfig, is_mux_destination};
use flux_protocol::vmess::{VMESS_CMD_UDP, VmessProtocol, VmessStream};
use flux_types::{Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, UdpPacket};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct VmessInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<Uuid>,
    pipeline: flux_transport::pipeline::ServerTransportPipeline,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    /// Accept multiplexed (smux) sessions when set.
    mux: Option<MuxConfig>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl VmessInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        users: Vec<Uuid>,
        pipeline: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users,
            pipeline,
            rate_limiter: None,
            mux: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    /// Accept multiplexed (smux) sessions on this inbound.
    pub fn with_mux(mut self, config: MuxConfig) -> Self {
        self.mux = Some(config);
        self
    }
}

#[async_trait]
impl Inbound for VmessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "vmess"
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
        let pipeline = self.pipeline.clone();
        let rate_limiter = self.rate_limiter.clone();
        let mux = self.mux.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] VMess inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
                    res = listener.accept() => match res {
                        Ok(res) => res,
                        Err(e) => {
                            if running.load(Ordering::Relaxed) {
                                warn!("[{}] VMess accept error: {}", tag, e);
                            }
                            break;
                        }
                    },
                    _ = shutdown_rx.recv() => break,
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
                let pipe = pipeline.clone();
                let mux = mux.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let mut stream = match pipe.unwrap(socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "[{}] VMess transport handshake failed from {}: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                    };

                    let req = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        VmessProtocol::read_request_header(&mut stream, &user_list),
                    )
                    .await
                    {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] VMess header failed from {}: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            warn!(
                                "[{}] VMess header timed out from {}",
                                inbound_tag, client_addr
                            );
                            return;
                        }
                    };

                    let vmess_stream = VmessStream::new_server(
                        stream,
                        req.session_key,
                        req.session_iv,
                        req.security,
                        req.resp_header,
                        req.option,
                    );

                    if let Some(mux_config) = &mux
                        && req.command != VMESS_CMD_UDP
                        && is_mux_destination(&req.address)
                    {
                        let mux_config = mux_config.clone();
                        let disp = disp.clone();
                        let session_tag = inbound_tag.clone();
                        let accept = move |accepted| {
                            flux_protocol::mux::spawn_mux_dispatcher(
                                disp.clone(),
                                session_tag.clone(),
                                client_addr,
                                accepted,
                            )
                        };
                        if let Err(e) =
                            flux_protocol::mux::serve(Box::new(vmess_stream), &mux_config, accept)
                                .await
                        {
                            debug!(
                                "[{}] mux session from {} ended: {}",
                                inbound_tag, client_addr, e
                            );
                        }
                        return;
                    }

                    if req.command == VMESS_CMD_UDP {
                        // VMess UDP-over-TCP: datagrams are `[u16 BE len][payload]` frames
                        // inside the encrypted stream, all bound to the request target.
                        let target = req.address.clone();
                        let meta = SessionMeta::new(
                            client_addr,
                            target.clone(),
                            inbound_tag.clone(),
                            NetworkType::Udp,
                        );
                        let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                        let (mut reader, mut writer) = tokio::io::split(vmess_stream);

                        let read_fut = async move {
                            loop {
                                let mut len_buf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut reader, &mut len_buf)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                let payload_len = u16::from_be_bytes(len_buf) as usize;
                                let mut payload = vec![0u8; payload_len];
                                if tokio::io::AsyncReadExt::read_exact(&mut reader, &mut payload)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                let packet = UdpPacket::new(
                                    bytes::Bytes::from(payload),
                                    target.clone(),
                                    target.clone(),
                                );
                                if pkt_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        };

                        let write_fut = async move {
                            while let Some(packet) = out_rx.recv().await {
                                let payload_len = (packet.payload.len().min(65535)) as u16;
                                let mut frame = Vec::with_capacity(2 + payload_len as usize);
                                frame.extend_from_slice(&payload_len.to_be_bytes());
                                frame.extend_from_slice(&packet.payload[..payload_len as usize]);
                                if tokio::io::AsyncWriteExt::write_all(&mut writer, &frame)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                if tokio::io::AsyncWriteExt::flush(&mut writer).await.is_err() {
                                    break;
                                }
                            }
                        };

                        tokio::select! {
                            _ = read_fut => {},
                            _ = write_fut => {},
                            res = disp.dispatch_packet(meta, pkt_rx, out_tx) => { let _ = res; },
                        }
                        return;
                    }

                    let meta = SessionMeta::new(
                        client_addr,
                        req.address.clone(),
                        inbound_tag.clone(),
                        NetworkType::Tcp,
                    );

                    disp.dispatch_stream(meta, Box::new(vmess_stream)).await;
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
