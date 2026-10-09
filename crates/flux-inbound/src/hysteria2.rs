use async_trait::async_trait;
use flux_protocol::hysteria2::{HYSTERIA2_CMD_TCP, HYSTERIA2_CMD_UDP, Hysteria2Protocol};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};

pub struct Hysteria2Inbound {
    tag: String,
    listen_addr: SocketAddr,
    password: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pipeline: Option<flux_transport::pipeline::ServerTransportPipeline>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl Hysteria2Inbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        password: impl Into<String>,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
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
        password: impl Into<String>,
        pipeline: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
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
impl Inbound for Hysteria2Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "hysteria2"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        if let Some(pipe) = self.pipeline.clone() {
            let listener = crate::create_reuse_port_listener(self.listen_addr)?;
            self.running.store(true, Ordering::SeqCst);
            let tag: Arc<str> = Arc::from(self.tag.as_str());
            let password = Arc::new(self.password.clone());
            let mut shutdown_rx = self.shutdown_tx.subscribe();

            info!(
                "[{}] Hysteria 2 Stream/TCP inbound listening on {}",
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
                    let pw = password.clone();
                    let p = pipe.clone();

                    tokio::spawn(async move {
                        let mut stream = match p.unwrap(socket).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(
                                    "[{}] Hysteria 2 transport handshake failed from {}: {}",
                                    inbound_tag, client_addr, e
                                );
                                return;
                            }
                        };

                        let mut auth_hdr = [0u8; 3];
                        if stream.read_exact(&mut auth_hdr).await.is_err() {
                            return;
                        }
                        let pw_len = u16::from_be_bytes([auth_hdr[1], auth_hdr[2]]) as usize;
                        let mut full_auth = vec![0u8; 3 + pw_len];
                        full_auth[..3].copy_from_slice(&auth_hdr);
                        if stream.read_exact(&mut full_auth[3..]).await.is_err() {
                            return;
                        }
                        if Hysteria2Protocol::parse_auth_frame(&full_auth, &pw).is_err() {
                            return;
                        }

                        let mut req_hdr = [0u8; 4];
                        if stream.read_exact(&mut req_hdr).await.is_err() {
                            return;
                        }
                        let command = req_hdr[0];
                        let port = u16::from_be_bytes([req_hdr[1], req_hdr[2]]);
                        let atyp = req_hdr[3];

                        let target_addr = match atyp {
                            1 => {
                                let mut ip_bytes = [0u8; 4];
                                if stream.read_exact(&mut ip_bytes).await.is_err() {
                                    return;
                                }
                                TargetAddress::Ip(SocketAddr::new(
                                    std::net::Ipv4Addr::from(ip_bytes).into(),
                                    port,
                                ))
                            }
                            2 => {
                                let mut len_byte = [0u8; 1];
                                if stream.read_exact(&mut len_byte).await.is_err() {
                                    return;
                                }
                                let dlen = len_byte[0] as usize;
                                let mut domain_buf = vec![0u8; dlen];
                                if stream.read_exact(&mut domain_buf).await.is_err() {
                                    return;
                                }
                                TargetAddress::Domain(
                                    String::from_utf8_lossy(&domain_buf).to_string(),
                                    port,
                                )
                            }
                            3 => {
                                let mut ip_bytes = [0u8; 16];
                                if stream.read_exact(&mut ip_bytes).await.is_err() {
                                    return;
                                }
                                TargetAddress::Ip(SocketAddr::new(
                                    std::net::Ipv6Addr::from(ip_bytes).into(),
                                    port,
                                ))
                            }
                            _ => return,
                        };

                        let meta = SessionMeta::new(
                            client_addr,
                            target_addr,
                            inbound_tag,
                            if command == HYSTERIA2_CMD_UDP {
                                NetworkType::Udp
                            } else {
                                NetworkType::Tcp
                            },
                        );

                        disp.dispatch_stream(meta, stream).await;
                    });
                }
            });

            return Ok(());
        }

        let alpn = vec![b"h3".to_vec(), b"hysteria2".to_vec()];
        let endpoint = QuicTransport::create_server_endpoint(
            self.listen_addr,
            self.certs.clone(),
            self.key.clone_key(),
            alpn,
        )?;

        self.running.store(true, Ordering::SeqCst);
        let _running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let password = Arc::new(self.password.clone());
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!(
            "[{}] Hysteria 2 QUIC inbound listening on {}",
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
                let pw = password.clone();

                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(
                                "[{}] Hysteria 2 QUIC connection handshake error: {}",
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
                        let pw_sub = pw.clone();

                        tokio::spawn(async move {
                            // 1. Read Hysteria 2 auth header: [ver (1 byte: 2) + len (2 bytes BE)]
                            let mut auth_hdr = [0u8; 3];
                            if let Err(e) = stream.read_exact(&mut auth_hdr).await {
                                debug!("[{}] Hysteria 2 auth header read failed: {}", in_tag, e);
                                return;
                            }

                            let pw_len = u16::from_be_bytes([auth_hdr[1], auth_hdr[2]]) as usize;
                            let mut full_auth = vec![0u8; 3 + pw_len];
                            full_auth[..3].copy_from_slice(&auth_hdr);
                            if let Err(e) = stream.read_exact(&mut full_auth[3..]).await {
                                debug!("[{}] Hysteria 2 auth password read failed: {}", in_tag, e);
                                return;
                            }

                            if let Err(e) = Hysteria2Protocol::parse_auth_frame(&full_auth, &pw_sub)
                            {
                                warn!(
                                    "[{}] Hysteria 2 auth verification failed from {}: {}",
                                    in_tag, client_addr, e
                                );
                                return;
                            }

                            // 2. Read request header: [command (1 byte) + port (2 bytes BE) + atyp (1 byte)]
                            let mut req_hdr = [0u8; 4];
                            if let Err(e) = stream.read_exact(&mut req_hdr).await {
                                debug!("[{}] Hysteria 2 request header read failed: {}", in_tag, e);
                                return;
                            }

                            let command = req_hdr[0];
                            let port = u16::from_be_bytes([req_hdr[1], req_hdr[2]]);
                            let atyp = req_hdr[3];

                            let target_addr = match atyp {
                                1 => {
                                    let mut ip_bytes = [0u8; 4];
                                    if stream.read_exact(&mut ip_bytes).await.is_err() {
                                        return;
                                    }
                                    let ip = Ipv4Addr::from(ip_bytes);
                                    TargetAddress::Ip(SocketAddr::new(ip.into(), port))
                                }
                                2 => {
                                    let mut len_byte = [0u8; 1];
                                    if stream.read_exact(&mut len_byte).await.is_err() {
                                        return;
                                    }
                                    let dlen = len_byte[0] as usize;
                                    let mut domain_buf = vec![0u8; dlen];
                                    if stream.read_exact(&mut domain_buf).await.is_err() {
                                        return;
                                    }
                                    let domain = String::from_utf8_lossy(&domain_buf).to_string();
                                    TargetAddress::Domain(domain, port)
                                }
                                3 => {
                                    let mut ip_bytes = [0u8; 16];
                                    if stream.read_exact(&mut ip_bytes).await.is_err() {
                                        return;
                                    }
                                    let ip = Ipv6Addr::from(ip_bytes);
                                    TargetAddress::Ip(SocketAddr::new(ip.into(), port))
                                }
                                _ => return,
                            };

                            let meta = SessionMeta::new(
                                client_addr,
                                target_addr.clone(),
                                in_tag.clone(),
                                if command == HYSTERIA2_CMD_UDP {
                                    NetworkType::Udp
                                } else {
                                    NetworkType::Tcp
                                },
                            );

                            if command == HYSTERIA2_CMD_TCP {
                                disp_stream.dispatch_stream(meta, Box::new(stream)).await;
                            } else if command == HYSTERIA2_CMD_UDP {
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
