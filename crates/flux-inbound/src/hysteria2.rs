use async_trait::async_trait;
use flux_protocol::hysteria2::{HYSTERIA2_CMD_UDP, Hysteria2Protocol};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncReadExt;
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
                            debug!("[{}] Hysteria 2 QUIC handshake error: {}", inbound_tag, e);
                            return;
                        }
                    };
                    let client_addr = conn.remote_address();
                    let h3 = flux_transport::h3_lite::H3LiteServer::new(conn.clone());
                    let authenticated = Arc::new(AtomicBool::new(false));

                    // UDP datagram sessions for this connection.
                    let udp_sessions: Arc<
                        dashmap::DashMap<u32, tokio::sync::mpsc::Sender<UdpPacket>>,
                    > = Arc::new(dashmap::DashMap::new());
                    {
                        let conn_c = conn.clone();
                        let tag_c = inbound_tag.clone();
                        let disp_c = disp.clone();
                        let auth_c = authenticated.clone();
                        let sessions_c = udp_sessions.clone();
                        tokio::spawn(async move {
                            loop {
                                let dgram = match conn_c.read_datagram().await {
                                    Ok(d) => d,
                                    Err(_) => break,
                                };
                                if !auth_c.load(Ordering::SeqCst) {
                                    continue;
                                }
                                // hy2 UDP datagram: [sessionID u32][packetID u16][fragID u8][fragTotal u8][vstring dest][data]
                                if dgram.len() < 9 {
                                    continue;
                                }
                                let session_id =
                                    u32::from_be_bytes([dgram[0], dgram[1], dgram[2], dgram[3]]);
                                let frag_id = dgram[6];
                                let frag_total = dgram[7];
                                if frag_total > 1 || frag_id != 0 {
                                    continue; // fragmented UDP not supported
                                }
                                // vstring dest
                                let vlen = match dgram[8] {
                                    v if v < 0x40 => v as usize,
                                    _ => continue, // only short varints for sanity
                                };
                                if dgram.len() < 9 + vlen {
                                    continue;
                                }
                                let dest_str =
                                    String::from_utf8_lossy(&dgram[9..9 + vlen]).to_string();
                                let payload = &dgram[9 + vlen..];
                                let target: TargetAddress = match dest_str.parse() {
                                    Ok(t) => t,
                                    Err(_) => continue,
                                };

                                if let Some(tx) = sessions_c.get(&session_id) {
                                    let pkt = UdpPacket::new(
                                        payload.to_vec().into(),
                                        TargetAddress::Ip(client_addr),
                                        target,
                                    );
                                    let _ = tx.try_send(pkt);
                                } else {
                                    let (pkt_tx, pkt_rx) =
                                        tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let (out_tx, mut out_rx) =
                                        tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let meta = SessionMeta::new(
                                        client_addr,
                                        target.clone(),
                                        tag_c.clone(),
                                        NetworkType::Udp,
                                    );
                                    let disp2 = disp_c.clone();
                                    tokio::spawn(async move {
                                        disp2.dispatch_packet(meta, pkt_rx, out_tx).await;
                                    });
                                    let pkt = UdpPacket::new(
                                        payload.to_vec().into(),
                                        TargetAddress::Ip(client_addr),
                                        target,
                                    );
                                    let _ = pkt_tx.try_send(pkt);
                                    sessions_c.insert(session_id, pkt_tx);

                                    let conn2 = conn_c.clone();
                                    tokio::spawn(async move {
                                        let mut pid: u16 = 0;
                                        while let Some(reply) = out_rx.recv().await {
                                            let dest_str = reply.source.to_string();
                                            let mut frame =
                                                Vec::with_capacity(16 + reply.payload.len());
                                            frame.extend_from_slice(&session_id.to_be_bytes());
                                            frame.extend_from_slice(&pid.to_be_bytes());
                                            frame.push(0); // frag id
                                            frame.push(1); // frag total
                                            frame.push(dest_str.len() as u8);
                                            frame.extend_from_slice(dest_str.as_bytes());
                                            frame.extend_from_slice(&reply.payload);
                                            pid = pid.wrapping_add(1);
                                            if conn2.send_datagram(frame.into()).is_err() {
                                                break;
                                            }
                                        }
                                    });
                                }
                            }
                        });
                    }

                    loop {
                        let ev = match h3.accept().await {
                            Ok(e) => e,
                            Err(_) => break,
                        };
                        match ev {
                            flux_transport::h3_lite::H3Event::Request {
                                headers,
                                mut send,
                                recv: _,
                            } => {
                                let get = |name: &str| {
                                    headers
                                        .iter()
                                        .find(|(n, _)| n == name)
                                        .map(|(_, v)| v.as_str())
                                };
                                let is_auth = get(":method") == Some("POST")
                                    && get(":path") == Some("/auth")
                                    && get(":authority").map(|a| a == "hysteria").unwrap_or(true);
                                let auth_ok = is_auth
                                    && get("hysteria-auth")
                                        .map(|p| p == pw.as_str())
                                        .unwrap_or(false);
                                if auth_ok {
                                    authenticated.store(true, Ordering::SeqCst);
                                    let fields = vec![
                                        ("hysteria-udp".to_string(), "true".to_string()),
                                        ("hysteria-cc-rx".to_string(), "0".to_string()),
                                    ];
                                    if flux_transport::h3_lite::write_response_headers(
                                        &mut send, 233, &fields,
                                    )
                                    .await
                                    .is_ok()
                                    {
                                        let _ = send.finish();
                                    }
                                    debug!(
                                        "[{}] Hysteria 2 authenticated client {}",
                                        inbound_tag, client_addr
                                    );
                                } else {
                                    // Masquerade: plain 404.
                                    let _ = flux_transport::h3_lite::write_response_headers(
                                        &mut send,
                                        404,
                                        &[],
                                    )
                                    .await;
                                    let _ = send.finish();
                                }
                            }
                            flux_transport::h3_lite::H3Event::RawStream {
                                frame_type,
                                send,
                                mut recv,
                            } => {
                                if frame_type != 0x401 || !authenticated.load(Ordering::SeqCst) {
                                    continue;
                                }
                                let disp_s = disp.clone();
                                let in_tag = inbound_tag.clone();
                                tokio::spawn(async move {
                                    let target =
                                        match Hysteria2Protocol::read_tcp_request_body(&mut recv)
                                            .await
                                        {
                                            Ok(t) => t,
                                            Err(e) => {
                                                debug!(
                                                    "[{}] hy2 tcp request read failed: {}",
                                                    in_tag, e
                                                );
                                                return;
                                            }
                                        };
                                    let ok_resp =
                                        Hysteria2Protocol::encode_tcp_response(true, "OK");
                                    let mut send = send;
                                    if send.write_all(&ok_resp).await.is_err() {
                                        return;
                                    }
                                    let meta = SessionMeta::new(
                                        client_addr,
                                        target,
                                        in_tag,
                                        NetworkType::Tcp,
                                    );
                                    let stream = QuicBiStream::new(send, recv);
                                    disp_s.dispatch_stream(meta, Box::new(stream)).await;
                                });
                            }
                        }
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
