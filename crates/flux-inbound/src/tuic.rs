use async_trait::async_trait;
use dashmap::DashMap;
use flux_protocol::tuic::{TUIC_AUTH_LEN, TUIC_CMD_CONNECT, TUIC_VERSION, TuicV5Protocol};
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
use uuid::Uuid;

/// TUIC v5 inbound (QUIC-native, spec-compatible with sing-box).
pub struct TuicInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<Uuid>,
    password: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pipeline: Option<flux_transport::pipeline::ServerTransportPipeline>,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
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
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
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
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (&x, &y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
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
        // ---- Layered mode (TUIC frames over an arbitrary stream transport)
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

                        // Layered mode: AUTH frame (legacy HMAC token) then CONNECT frame.
                        let mut auth_buf = [0u8; TUIC_AUTH_LEN];
                        if stream.read_exact(&mut auth_buf).await.is_err() {
                            return;
                        }
                        let uuid = match TuicV5Protocol::parse_auth_frame(&auth_buf) {
                            Ok((u, token)) => {
                                if !user_list.is_empty() && !user_list.contains(&u) {
                                    return;
                                }
                                let expected = TuicV5Protocol::legacy_token(&u, &pw);
                                if !Self::constant_time_eq(&token, &expected) {
                                    return;
                                }
                                u
                            }
                            Err(_) => return,
                        };

                        // Read CONNECT header: [5, 0x01, addr...]
                        let mut hdr = [0u8; 2];
                        if stream.read_exact(&mut hdr).await.is_err() {
                            return;
                        }
                        if hdr[0] != TUIC_VERSION || hdr[1] != TUIC_CMD_CONNECT {
                            return;
                        }
                        // Peek the address: read ATYP byte first
                        let mut atyp = [0u8; 1];
                        if stream.read_exact(&mut atyp).await.is_err() {
                            return;
                        }
                        let mut addr_buf = atyp.to_vec();
                        let more = match atyp[0] {
                            0x00 => {
                                let mut lb = [0u8; 1];
                                if stream.read_exact(&mut lb).await.is_err() {
                                    return;
                                }
                                let mut rest = vec![0u8; lb[0] as usize + 2];
                                if stream.read_exact(&mut rest).await.is_err() {
                                    return;
                                }
                                let mut v = lb.to_vec();
                                v.extend_from_slice(&rest);
                                v
                            }
                            0x01 => {
                                let mut rest = [0u8; 4 + 2];
                                if stream.read_exact(&mut rest).await.is_err() {
                                    return;
                                }
                                rest.to_vec()
                            }
                            0x02 => {
                                let mut rest = vec![0u8; 16 + 2];
                                if stream.read_exact(&mut rest).await.is_err() {
                                    return;
                                }
                                rest.to_vec()
                            }
                            _ => return,
                        };
                        addr_buf.extend_from_slice(&more);

                        let (target_addr, _) = match TuicV5Protocol::decode_address(&addr_buf) {
                            Ok(r) => r,
                            Err(_) => return,
                        };

                        let meta = SessionMeta::new(
                            client_addr,
                            target_addr,
                            inbound_tag,
                            NetworkType::Tcp,
                        )
                        .with_user(uuid.to_string());

                        disp.dispatch_stream(meta, stream).await;
                    });
                }
            });

            return Ok(());
        }

        // ---- Native QUIC mode (spec TUIC v5)
        let alpn = vec![b"tuic".to_vec(), b"tuic-v5".to_vec(), b"h3".to_vec()];
        let endpoint = QuicTransport::create_server_endpoint(
            self.listen_addr,
            self.certs.clone(),
            self.key.clone_key(),
            alpn,
        )?;

        self.running.store(true, Ordering::SeqCst);
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let users = Arc::new(self.users.clone());
        let password = Arc::new(self.password.clone());
        let rate_limiter = self.rate_limiter.clone();
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

                // Rate limiting at the QUIC connection attempt level.
                let conn_guard = match &rate_limiter {
                    Some(rl) => match rl.try_acquire(incoming.remote_address().ip()) {
                        Some(g) => Some(g),
                        None => {
                            debug!(
                                "[{}] QUIC connection from {} rejected by rate limiter",
                                tag,
                                incoming.remote_address()
                            );
                            continue; // drop the Incoming: quinn refuses the handshake
                        }
                    },
                    None => None,
                };

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();
                let pw = password.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard; // held for the QUIC connection lifetime
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
                    let authenticated = Arc::new(AtomicBool::new(false));

                    // UDP sessions: session_id → dispatcher packet channel
                    let udp_sessions: Arc<DashMap<u16, tokio::sync::mpsc::Sender<UdpPacket>>> =
                        Arc::new(DashMap::new());

                    // Task 1: unidirectional streams (AUTHENTICATE, DISSOCIATE)
                    {
                        let conn_c = conn.clone();
                        let tag_c = inbound_tag.clone();
                        let users_c = user_list.clone();
                        let pw_c = pw.clone();
                        let auth_c = authenticated.clone();
                        let sessions_c = udp_sessions.clone();
                        tokio::spawn(async move {
                            loop {
                                let mut recv = match conn_c.accept_uni().await {
                                    Ok(r) => r,
                                    Err(_) => break,
                                };
                                let tag2 = tag_c.clone();
                                let users2 = users_c.clone();
                                let pw2 = pw_c.clone();
                                let auth2 = auth_c.clone();
                                let sessions2 = sessions_c.clone();
                                let conn2 = conn_c.clone();
                                tokio::spawn(async move {
                                    let mut hdr = [0u8; 2];
                                    if recv.read_exact(&mut hdr).await.is_err() {
                                        return;
                                    }
                                    if hdr[0] != TUIC_VERSION {
                                        return;
                                    }
                                    match hdr[1] {
                                        flux_protocol::tuic::TUIC_CMD_AUTHENTICATE => {
                                            let mut rest = [0u8; 16 + 32];
                                            if recv.read_exact(&mut rest).await.is_err() {
                                                return;
                                            }
                                            let mut frame = Vec::with_capacity(TUIC_AUTH_LEN);
                                            frame.extend_from_slice(&hdr);
                                            frame.extend_from_slice(&rest);
                                            let (uuid, token) =
                                                match TuicV5Protocol::parse_auth_frame(&frame) {
                                                    Ok(v) => v,
                                                    Err(_) => return,
                                                };
                                            if !users2.is_empty() && !users2.contains(&uuid) {
                                                warn!(
                                                    "[{}] TUIC unknown uuid from {}",
                                                    tag2,
                                                    conn2.remote_address()
                                                );
                                                return;
                                            }
                                            let mut expected = [0u8; 32];
                                            if conn2
                                                .export_keying_material(
                                                    &mut expected,
                                                    uuid.as_bytes(),
                                                    pw2.as_bytes(),
                                                )
                                                .is_err()
                                            {
                                                return;
                                            }
                                            if !TuicInbound::constant_time_eq(&token, &expected) {
                                                warn!(
                                                    "[{}] TUIC token mismatch from {}",
                                                    tag2,
                                                    conn2.remote_address()
                                                );
                                                return;
                                            }
                                            auth2.store(true, Ordering::SeqCst);
                                            debug!(
                                                "[{}] TUIC authenticated {} from {}",
                                                tag2,
                                                uuid,
                                                conn2.remote_address()
                                            );
                                        }
                                        flux_protocol::tuic::TUIC_CMD_DISSOCIATE => {
                                            let mut sid = [0u8; 2];
                                            if recv.read_exact(&mut sid).await.is_ok() {
                                                let session_id = u16::from_be_bytes(sid);
                                                sessions2.remove(&session_id);
                                            }
                                        }
                                        _ => {}
                                    }
                                });
                            }
                        });
                    }

                    // Task 2: QUIC datagrams (UDP PACKET frames)
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
                                let (session_id, _pid, addr, payload) =
                                    match TuicV5Protocol::parse_packet_frame(&dgram) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                if let Some(tx) = sessions_c.get(&session_id) {
                                    let pkt = UdpPacket::new(
                                        payload.into(),
                                        TargetAddress::Ip(client_addr),
                                        addr,
                                    );
                                    let _ = tx.try_send(pkt);
                                } else {
                                    // New UDP session over datagrams
                                    let (pkt_tx, pkt_rx) =
                                        tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let (out_tx, mut out_rx) =
                                        tokio::sync::mpsc::channel::<UdpPacket>(64);
                                    let meta = SessionMeta::new(
                                        client_addr,
                                        addr.clone(),
                                        tag_c.clone(),
                                        NetworkType::Udp,
                                    );
                                    let disp2 = disp_c.clone();
                                    tokio::spawn(async move {
                                        disp2.dispatch_packet(meta, pkt_rx, out_tx).await;
                                    });
                                    let pkt = UdpPacket::new(
                                        payload.into(),
                                        TargetAddress::Ip(client_addr),
                                        addr,
                                    );
                                    let _ = pkt_tx.try_send(pkt);
                                    sessions_c.insert(session_id, pkt_tx);

                                    // Reply pump: dispatcher replies → datagrams
                                    let conn2 = conn_c.clone();
                                    tokio::spawn(async move {
                                        let mut pid: u16 = 0;
                                        while let Some(reply) = out_rx.recv().await {
                                            let frame = TuicV5Protocol::build_packet_frame(
                                                session_id,
                                                pid,
                                                &reply.source,
                                                &reply.payload,
                                            );
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

                    // Task 3: bidirectional streams (CONNECT)
                    loop {
                        let (send, recv) = match conn.accept_bi().await {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        if !authenticated.load(Ordering::SeqCst) {
                            // Wait briefly for the auth uni-stream to arrive first.
                            let mut ok = false;
                            for _ in 0..20 {
                                if authenticated.load(Ordering::SeqCst) {
                                    ok = true;
                                    break;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            }
                            if !ok {
                                continue;
                            }
                        }
                        let disp_s = disp.clone();
                        let in_tag = inbound_tag.clone();
                        tokio::spawn(async move {
                            let mut stream = QuicBiStream::new(send, recv);
                            let mut hdr = [0u8; 2];
                            if stream.read_exact(&mut hdr).await.is_err() {
                                return;
                            }
                            if hdr[0] != TUIC_VERSION || hdr[1] != TUIC_CMD_CONNECT {
                                return;
                            }
                            let mut atyp = [0u8; 1];
                            if stream.read_exact(&mut atyp).await.is_err() {
                                return;
                            }
                            let mut addr_buf = atyp.to_vec();
                            let more = match atyp[0] {
                                0x00 => {
                                    let mut lb = [0u8; 1];
                                    if stream.read_exact(&mut lb).await.is_err() {
                                        return;
                                    }
                                    let mut rest = vec![0u8; lb[0] as usize + 2];
                                    if stream.read_exact(&mut rest).await.is_err() {
                                        return;
                                    }
                                    let mut v = lb.to_vec();
                                    v.extend_from_slice(&rest);
                                    v
                                }
                                0x01 => {
                                    let mut rest = [0u8; 4 + 2];
                                    if stream.read_exact(&mut rest).await.is_err() {
                                        return;
                                    }
                                    rest.to_vec()
                                }
                                0x02 => {
                                    let mut rest = vec![0u8; 16 + 2];
                                    if stream.read_exact(&mut rest).await.is_err() {
                                        return;
                                    }
                                    rest.to_vec()
                                }
                                _ => return,
                            };
                            addr_buf.extend_from_slice(&more);
                            let (target_addr, _) = match TuicV5Protocol::decode_address(&addr_buf) {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            let meta = SessionMeta::new(
                                client_addr,
                                target_addr,
                                in_tag,
                                NetworkType::Tcp,
                            );
                            disp_s.dispatch_stream(meta, Box::new(stream)).await;
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
