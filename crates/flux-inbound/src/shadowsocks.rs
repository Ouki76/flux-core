use async_trait::async_trait;
use dashmap::DashMap;
use flux_protocol::mux::{MuxConfig, is_mux_destination};
use flux_protocol::shadowsocks::{
    CipherKind, ShadowsocksCipher, ShadowsocksStream, TAG_LEN, derive_master_key_for_kind,
    derive_subkey, encode_ss_address,
};
use flux_protocol::socks5::Socks5Handshake;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

pub struct ShadowsocksInbound {
    tag: String,
    listen_addr: SocketAddr,
    password: String,
    master_key: Vec<u8>,
    cipher_kind: CipherKind,
    replay_filter: Arc<flux_protocol::shadowsocks2022::ReplayFilter>,
    pipeline: flux_transport::pipeline::ServerTransportPipeline,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    /// Accept multiplexed (smux) sessions when set.
    mux: Option<MuxConfig>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
}

impl ShadowsocksInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr, password: &str) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let cipher_kind = CipherKind::ChaCha20IetfPoly1305;
        let master_key = derive_master_key_for_kind(password, cipher_kind);
        Self {
            tag: tag.into(),
            listen_addr,
            password: password.to_string(),
            master_key,
            cipher_kind,
            replay_filter: Arc::new(flux_protocol::shadowsocks2022::ReplayFilter::new(10000)),
            pipeline: flux_transport::pipeline::ServerTransportPipeline::raw(),
            rate_limiter: None,
            mux: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            tasks: crate::InboundTasks::new(),
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    pub fn with_cipher_kind(mut self, kind: CipherKind) -> Self {
        self.cipher_kind = kind;
        self.master_key = derive_master_key_for_kind(&self.password, kind);
        self
    }

    pub fn with_pipeline(
        mut self,
        pipeline: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        self.pipeline = pipeline;
        self
    }

    /// Accept multiplexed (smux) sessions on this inbound.
    pub fn with_mux(mut self, config: MuxConfig) -> Self {
        self.mux = Some(config);
        self
    }
}

#[async_trait]
impl Inbound for ShadowsocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "shadowsocks"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = crate::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let master_key = self.master_key.clone();
        let cipher_kind = self.cipher_kind;
        let replay_filter = self.replay_filter.clone();
        let mux = self.mux.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!(
            "[{}] Shadowsocks AEAD inbound listening on {}",
            tag, self.listen_addr
        );

        let disp_tcp = dispatcher.clone();
        let tag_tcp = tag.clone();
        let running_tcp = running.clone();
        let replay_tcp = replay_filter.clone();
        let pipeline_tcp = Arc::new(self.pipeline.clone());
        let rate_limiter_tcp = self.rate_limiter.clone();

        self.tasks.spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok(res) => res,
                            Err(e) => {
                                if running_tcp.load(Ordering::Relaxed) {
                                    warn!("[{}] accept error: {}", tag_tcp, e);
                                }
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("[{}] Shadowsocks listener shutting down cleanly", tag_tcp);
                        break;
                    }
                };
                // Rate limiting: reject before any per-connection work.
                let conn_guard = match &rate_limiter_tcp {
                    Some(rl) => match rl.try_acquire(client_addr.ip()) {
                        Some(g) => Some(g),
                        None => {
                            debug!(
                                "[{}] connection from {} rejected by rate limiter",
                                tag_tcp, client_addr
                            );
                            continue;
                        }
                    },
                    None => None,
                };
                crate::optimize_tcp_socket(&socket);

                let disp = disp_tcp.clone();
                let inbound_tag = tag_tcp.clone();
                let replay = replay_tcp.clone();
                let pipe = pipeline_tcp.clone();
                let master_key = master_key.clone();
                let mux = mux.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let mut stream: flux_types::BoxedStream = match pipe.unwrap(socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "[{}] transport handshake error from {}: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                    };

                    if let CipherKind::Ss2022(method) = cipher_kind {
                        let key_bytes = &master_key[..method.key_len()];
                        let handshake_2022 =
                            flux_protocol::shadowsocks2022::Ss2022Protocol::server_handshake(
                                stream, method, key_bytes, &replay,
                            );
                        let (ss_stream, target, extra) = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            handshake_2022,
                        )
                        .await
                        {
                            Ok(Ok(res)) => res,
                            Ok(Err(e)) => {
                                warn!(
                                    "[{}] client {} SS-2022 handshake failed: {}",
                                    inbound_tag, client_addr, e
                                );
                                return;
                            }
                            Err(_) => {
                                debug!(
                                    "[{}] client {} SS-2022 handshake timed out",
                                    inbound_tag, client_addr
                                );
                                return;
                            }
                        };

                        let stream: flux_types::BoxedStream = if !extra.is_empty() {
                            Box::new(flux_common::copy::PrefixedStream::new(ss_stream, extra))
                        } else {
                            Box::new(ss_stream)
                        };

                        if let Some(mux_config) = &mux
                            && is_mux_destination(&target)
                        {
                            serve_mux_session(stream, mux_config, &disp, &inbound_tag, client_addr)
                                .await;
                            return;
                        }

                        let meta =
                            SessionMeta::new(client_addr, target, inbound_tag, NetworkType::Tcp);
                        disp.dispatch_stream(meta, stream).await;
                        return;
                    }
                    let handshake_fut = async {
                        // 1. Read client salt
                        let salt_len = cipher_kind.salt_len();
                        let mut salt = vec![0u8; salt_len];
                        stream.read_exact(&mut salt).await.map_err(FluxError::Io)?;

                        if !replay.check_and_insert_salt(&salt) {
                            return Err(FluxError::AuthFailed(
                                "shadowsocks client salt reused (replay attack detected)".into(),
                            ));
                        }

                        // 2. Derive subkey & cipher
                        let subkey = derive_subkey(&master_key, &salt);
                        let mut dec = ShadowsocksCipher::with_kind(cipher_kind, &subkey);

                        // 3. Read encrypted payload length (2 bytes + 16 bytes tag)
                        let mut enc_len = [0u8; 2 + TAG_LEN];
                        stream
                            .read_exact(&mut enc_len)
                            .await
                            .map_err(FluxError::Io)?;

                        let len_bytes = dec.decrypt(&enc_len)?;
                        let payload_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

                        // 4. Read encrypted payload (address)
                        let mut enc_payload = vec![0u8; payload_len + TAG_LEN];
                        stream
                            .read_exact(&mut enc_payload)
                            .await
                            .map_err(FluxError::Io)?;

                        let payload = dec.decrypt(&enc_payload)?;

                        // Parse SOCKS5 address
                        if payload.is_empty() {
                            return Err(FluxError::Protocol {
                                protocol: "shadowsocks",
                                message: "empty payload".into(),
                            });
                        }
                        let atyp = payload[0];
                        let mut cursor = std::io::Cursor::new(&payload[1..]);
                        let target = Socks5Handshake::read_address(&mut cursor, atyp).await?;
                        let consumed = 1 + cursor.position() as usize;
                        let pipelined_data = if consumed < payload.len() {
                            payload[consumed..].to_vec()
                        } else {
                            vec![]
                        };

                        Ok::<_, FluxError>((dec, target, pipelined_data))
                    };

                    let (dec, target, pipelined_data) = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        handshake_fut,
                    )
                    .await
                    {
                        Ok(Ok(res)) => res,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] client {} SS handshake failed: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "[{}] client {} SS handshake timed out",
                                inbound_tag, client_addr
                            );
                            return;
                        }
                    };

                    // Generate server salt and prepare server encoder
                    let salt_len = cipher_kind.salt_len();
                    let mut server_salt = vec![0u8; salt_len];
                    rand::rngs::OsRng.fill_bytes(&mut server_salt);
                    if stream.write_all(&server_salt).await.is_err() {
                        return;
                    }
                    let server_subkey = derive_subkey(&master_key, &server_salt);
                    let server_enc = ShadowsocksCipher::with_kind(cipher_kind, &server_subkey);

                    let ss_stream = ShadowsocksStream::new_with_initial_chunk(
                        stream,
                        server_enc,
                        Some(dec),
                        &master_key,
                        pipelined_data,
                    );

                    if let Some(mux_config) = &mux
                        && is_mux_destination(&target)
                    {
                        serve_mux_session(
                            Box::new(ss_stream),
                            mux_config,
                            &disp,
                            &inbound_tag,
                            client_addr,
                        )
                        .await;
                        return;
                    }

                    let meta = SessionMeta::new(client_addr, target, inbound_tag, NetworkType::Tcp);
                    disp.dispatch_stream(meta, Box::new(ss_stream)).await;
                });
            }
        });

        // 2. Setup Shadowsocks UDP listener
        let udp_socket = Arc::new(
            tokio::net::UdpSocket::bind(self.listen_addr)
                .await
                .map_err(FluxError::Io)?,
        );
        let udp_sock_recv = udp_socket.clone();
        let disp_udp = dispatcher.clone();
        let tag_udp = tag.clone();
        let replay_udp = replay_filter.clone();
        let mut shutdown_rx_udp = self.shutdown_tx.subscribe();
        let sessions: Arc<DashMap<SocketAddr, tokio::sync::mpsc::Sender<UdpPacket>>> =
            Arc::new(DashMap::new());
        let master_key_udp = self.master_key.clone();

        self.tasks.spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (len, client_addr) = tokio::select! {
                    res = udp_sock_recv.recv_from(&mut buf) => match res {
                        Ok(r) => r,
                        Err(_) => break,
                    },
                    _ = shutdown_rx_udp.recv() => break,
                };

                let decrypted = if let CipherKind::Ss2022(method) = cipher_kind {
                    let psk = &master_key_udp[..method.key_len()];
                    let cipher =
                        flux_protocol::shadowsocks2022::Ss2022UdpPacketCipher::new(method, psk);
                    cipher.decrypt_packet(&buf[..len]).await.ok()
                } else {
                    let salt_len = cipher_kind.salt_len();
                    if len < salt_len + TAG_LEN {
                        continue;
                    }
                    let salt = &buf[..salt_len];
                    if !replay_udp.check_and_insert_salt(salt) {
                        continue;
                    }
                    let subkey = derive_subkey(&master_key_udp, salt);
                    let mut cipher = ShadowsocksCipher::with_kind(cipher_kind, &subkey);
                    let plain = match cipher.decrypt(&buf[salt_len..len]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if plain.is_empty() {
                        continue;
                    }
                    let atyp = plain[0];
                    let mut cursor = std::io::Cursor::new(&plain[1..]);
                    let target = match Socks5Handshake::read_address(&mut cursor, atyp).await {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let pos = 1 + cursor.position() as usize;
                    let payload = bytes::Bytes::copy_from_slice(&plain[pos..]);
                    Some((target, payload))
                };

                let Some((target, payload)) = decrypted else {
                    continue;
                };

                let pkt = UdpPacket::new(payload, TargetAddress::Ip(client_addr), target.clone());

                if let Some(tx) = sessions.get(&client_addr) {
                    let _ = tx.send(pkt).await;
                } else {
                    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);

                    let meta =
                        SessionMeta::new(client_addr, target, tag_udp.clone(), NetworkType::Udp);

                    let disp = disp_udp.clone();
                    tokio::spawn(async move {
                        disp.dispatch_packet(meta, pkt_rx, out_tx).await;
                    });

                    let _ = pkt_tx.send(pkt).await;
                    sessions.insert(client_addr, pkt_tx);

                    let udp_send = udp_sock_recv.clone();
                    let sessions_clean = sessions.clone();
                    let master_key_send = master_key_udp.clone();
                    tokio::spawn(async move {
                        loop {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(30),
                                out_rx.recv(),
                            )
                            .await
                            {
                                Ok(Some(reply)) => {
                                    let encoded = if let CipherKind::Ss2022(method) = cipher_kind {
                                        let psk = &master_key_send[..method.key_len()];
                                        let cipher = flux_protocol::shadowsocks2022::Ss2022UdpPacketCipher::new(method, psk);
                                        cipher.encrypt_packet(&reply.source, &reply.payload).ok()
                                    } else {
                                        let salt_len = cipher_kind.salt_len();
                                        let mut salt = vec![0u8; salt_len];
                                        rand::rngs::OsRng.fill_bytes(&mut salt);
                                        let subkey = derive_subkey(&master_key_send, &salt);
                                        let mut cipher =
                                            ShadowsocksCipher::with_kind(cipher_kind, &subkey);
                                        let addr_bytes = encode_ss_address(&reply.source);
                                        let mut plain = Vec::with_capacity(
                                            addr_bytes.len() + reply.payload.len(),
                                        );
                                        plain.extend_from_slice(&addr_bytes);
                                        plain.extend_from_slice(&reply.payload);
                                        if let Ok(ciphertext) = cipher.encrypt(&plain) {
                                            let mut out =
                                                Vec::with_capacity(salt_len + ciphertext.len());
                                            out.extend_from_slice(&salt);
                                            out.extend_from_slice(&ciphertext);
                                            Some(out)
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(enc) = encoded {
                                        let _ = udp_send.send_to(&enc, client_addr).await;
                                    }
                                }
                                _ => {
                                    sessions_clean.remove(&client_addr);
                                    break;
                                }
                            }
                        }
                    });
                }
            }
        });

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning while it is still running leaves the
        // port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}

/// Runs a multiplexed (smux) session on an authenticated Shadowsocks stream.
async fn serve_mux_session(
    stream: flux_types::BoxedStream,
    config: &MuxConfig,
    dispatcher: &Arc<dyn Dispatcher>,
    inbound_tag: &Arc<str>,
    source: SocketAddr,
) {
    let config = config.clone();
    let disp = dispatcher.clone();
    let tag = inbound_tag.clone();
    let accept = move |accepted| {
        flux_protocol::mux::spawn_mux_dispatcher(disp.clone(), tag.clone(), source, accepted);
    };
    if let Err(e) = flux_protocol::mux::serve(stream, &config, accept).await {
        debug!("[{}] mux session from {} ended: {}", inbound_tag, source, e);
    }
}
