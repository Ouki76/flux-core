use async_trait::async_trait;
use flux_protocol::tuic::{TUIC_CMD_CONNECT, TUIC_CMD_PACKET, TuicV5Protocol};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct TuicInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<Uuid>,
    password: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pipeline: Option<flux_transport::pipeline::ServerTransportPipeline>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl TuicInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        users: Vec<Uuid>,
        password: impl Into<String>,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users,
            password: password.into(),
            certs,
            key,
            pipeline: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn new_with_pipeline(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        users: Vec<Uuid>,
        password: impl Into<String>,
        pipeline: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users,
            password: password.into(),
            certs: vec![],
            key: PrivateKeyDer::Pkcs8(vec![].into()),
            pipeline: Some(pipeline),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }
}

#[async_trait]
impl Inbound for TuicInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "tuic"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        if let Some(pipe) = self.pipeline.clone() {
            let listener = crate::create_reuse_port_listener(self.listen_addr)?;
            self.running.store(true, Ordering::SeqCst);
            let tag: Arc<str> = Arc::from(self.tag.as_str());
            let users = Arc::new(self.users.clone());
            let password = Arc::new(self.password.clone());
            let mut shutdown_rx = self.shutdown_tx.subscribe();

            info!(
                "[{}] TUIC v5 Stream/TCP inbound listening on {}",
                tag, self.listen_addr
            );

            tokio::spawn(async move {
                loop {
                    let (socket, client_addr) = tokio::select! {
                        res = listener.accept() => match res {
                            Ok(res) => res,
                            Err(_) => break,
                        },
                        _ = shutdown_rx.recv() => break,
                    };
                    crate::optimize_tcp_socket(&socket);
                    let disp = dispatcher.clone();
                    let inbound_tag = tag.clone();
                    let user_list = users.clone();
                    let pw = password.clone();
                    let p = pipe.clone();

                    tokio::spawn(async move {
                        let mut stream = match p.unwrap(socket).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(
                                    "[{}] TUIC transport handshake failed from {}: {}",
                                    inbound_tag, client_addr, e
                                );
                                return;
                            }
                        };

                        let mut auth_buf = [0u8; 57];
                        if stream.read_exact(&mut auth_buf).await.is_err() {
                            return;
                        }

                        let uuid =
                            match TuicV5Protocol::verify_auth_frame(&auth_buf, &pw, &user_list) {
                                Ok(u) => u,
                                Err(_) => return,
                            };

                        let mut cmd_hdr = [0u8; 4];
                        if stream.read_exact(&mut cmd_hdr).await.is_err() {
                            return;
                        }

                        let atyp = cmd_hdr[3];
                        let mut full_cmd = cmd_hdr.to_vec();

                        match atyp {
                            1 => {
                                let mut ip_bytes = [0u8; 4];
                                if stream.read_exact(&mut ip_bytes).await.is_err() {
                                    return;
                                }
                                full_cmd.extend_from_slice(&ip_bytes);
                            }
                            3 => {
                                let mut len_byte = [0u8; 1];
                                if stream.read_exact(&mut len_byte).await.is_err() {
                                    return;
                                }
                                let dlen = len_byte[0] as usize;
                                let mut domain_buf = vec![0u8; dlen];
                                if stream.read_exact(&mut domain_buf).await.is_err() {
                                    return;
                                }
                                full_cmd.push(len_byte[0]);
                                full_cmd.extend_from_slice(&domain_buf);
                            }
                            4 => {
                                let mut ip_bytes = [0u8; 16];
                                if stream.read_exact(&mut ip_bytes).await.is_err() {
                                    return;
                                }
                                full_cmd.extend_from_slice(&ip_bytes);
                            }
                            _ => return,
                        }

                        let (cmd, target_addr) =
                            match TuicV5Protocol::parse_command_frame(&full_cmd) {
                                Ok(res) => res,
                                Err(_) => return,
                            };

                        let meta = SessionMeta::new(
                            client_addr,
                            target_addr,
                            inbound_tag,
                            if cmd == TUIC_CMD_PACKET {
                                NetworkType::Udp
                            } else {
                                NetworkType::Tcp
                            },
                        )
                        .with_user(uuid.to_string());

                        disp.dispatch_stream(meta, stream).await;
                    });
                }
            });

            return Ok(());
        }

        let alpn = vec![b"tuic-v5".to_vec(), b"h3".to_vec()];
        let endpoint = QuicTransport::create_server_endpoint(
            self.listen_addr,
            self.certs.clone(),
            self.key.clone_key(),
            alpn,
        )?;

        self.running.store(true, Ordering::SeqCst);
        let _running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let users = Arc::new(self.users.clone());
        let password = Arc::new(self.password.clone());
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!(
            "[{}] TUIC v5 QUIC inbound listening on {}",
            tag, self.listen_addr
        );

        tokio::spawn(async move {
            loop {
                let incoming = tokio::select! {
                    inc = endpoint.accept() => match inc {
                        Some(inc) => inc,
                        None => break,
                    },
                    _ = shutdown_rx.recv() => break,
                };

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();
                let pw = password.clone();

                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(
                                "[{}] TUIC QUIC connection handshake error: {}",
                                inbound_tag, e
                            );
                            return;
                        }
                    };

                    let client_addr = conn.remote_address();

                    while let Ok((send, recv)) = conn.accept_bi().await {
                        let mut stream = QuicBiStream::new(send, recv);
                        let disp_stream = disp.clone();
                        let in_tag = inbound_tag.clone();
                        let users_sub = user_list.clone();
                        let pw_sub = pw.clone();

                        tokio::spawn(async move {
                            // 1. Read TUIC v5 auth frame: 57 bytes
                            let mut auth_buf = [0u8; 57];
                            if let Err(e) = stream.read_exact(&mut auth_buf).await {
                                debug!(
                                    "[{}] TUIC auth read failed from {}: {}",
                                    in_tag, client_addr, e
                                );
                                return;
                            }

                            let uuid = match TuicV5Protocol::verify_auth_frame(
                                &auth_buf, &pw_sub, &users_sub,
                            ) {
                                Ok(u) => u,
                                Err(e) => {
                                    warn!(
                                        "[{}] TUIC auth verification failed from {}: {}",
                                        in_tag, client_addr, e
                                    );
                                    return;
                                }
                            };

                            // 2. Read command frame header: [cmd (1 byte) + port (2 bytes) + atyp (1 byte)]
                            let mut cmd_hdr = [0u8; 4];
                            if let Err(e) = stream.read_exact(&mut cmd_hdr).await {
                                debug!("[{}] TUIC command header read failed: {}", in_tag, e);
                                return;
                            }

                            let atyp = cmd_hdr[3];
                            let mut full_cmd = cmd_hdr.to_vec();

                            match atyp {
                                1 => {
                                    let mut ip_bytes = [0u8; 4];
                                    if stream.read_exact(&mut ip_bytes).await.is_err() {
                                        return;
                                    }
                                    full_cmd.extend_from_slice(&ip_bytes);
                                }
                                3 => {
                                    let mut len_byte = [0u8; 1];
                                    if stream.read_exact(&mut len_byte).await.is_err() {
                                        return;
                                    }
                                    let dlen = len_byte[0] as usize;
                                    let mut domain_buf = vec![0u8; dlen];
                                    if stream.read_exact(&mut domain_buf).await.is_err() {
                                        return;
                                    }
                                    full_cmd.push(len_byte[0]);
                                    full_cmd.extend_from_slice(&domain_buf);
                                }
                                4 => {
                                    let mut ip_bytes = [0u8; 16];
                                    if stream.read_exact(&mut ip_bytes).await.is_err() {
                                        return;
                                    }
                                    full_cmd.extend_from_slice(&ip_bytes);
                                }
                                _ => return,
                            }

                            let (cmd, target_addr) =
                                match TuicV5Protocol::parse_command_frame(&full_cmd) {
                                    Ok(res) => res,
                                    Err(e) => {
                                        warn!("[{}] TUIC command parse failed: {}", in_tag, e);
                                        return;
                                    }
                                };

                            let meta = SessionMeta::new(
                                client_addr,
                                target_addr.clone(),
                                in_tag.clone(),
                                if cmd == TUIC_CMD_PACKET {
                                    NetworkType::Udp
                                } else {
                                    NetworkType::Tcp
                                },
                            )
                            .with_user(uuid.to_string());

                            if cmd == TUIC_CMD_CONNECT {
                                disp_stream.dispatch_stream(meta, Box::new(stream)).await;
                            } else if cmd == TUIC_CMD_PACKET {
                                let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                                let (out_tx, mut out_rx) =
                                    tokio::sync::mpsc::channel::<UdpPacket>(64);

                                let disp_packet = disp_stream.clone();
                                let meta_packet = meta.clone();
                                tokio::spawn(async move {
                                    disp_packet
                                        .dispatch_packet(meta_packet, pkt_rx, out_tx)
                                        .await;
                                });

                                let (mut stream_r, mut stream_w) = tokio::io::split(stream);

                                // Forward client packets to dispatcher
                                let pkt_send = pkt_tx.clone();
                                let target_src = target_addr.clone();
                                let read_task = tokio::spawn(async move {
                                    let mut len_buf = [0u8; 2];
                                    loop {
                                        if stream_r.read_exact(&mut len_buf).await.is_err() {
                                            break;
                                        }
                                        let len = u16::from_be_bytes(len_buf) as usize;
                                        let mut payload = vec![0u8; len];
                                        if stream_r.read_exact(&mut payload).await.is_err() {
                                            break;
                                        }
                                        let pkt = UdpPacket::new(
                                            payload.into(),
                                            TargetAddress::Ip(client_addr),
                                            target_src.clone(),
                                        );
                                        if pkt_send.send(pkt).await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                // Forward outbound replies back to client
                                let write_task = tokio::spawn(async move {
                                    while let Some(reply) = out_rx.recv().await {
                                        let len = reply.payload.len() as u16;
                                        if stream_w.write_all(&len.to_be_bytes()).await.is_err() {
                                            break;
                                        }
                                        if stream_w.write_all(&reply.payload).await.is_err() {
                                            break;
                                        }
                                        if stream_w.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                tokio::select! {
                                    _ = read_task => {},
                                    _ = write_task => {},
                                }
                            }
                        });
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
