use async_trait::async_trait;
use flux_protocol::mux::{MuxConfig, is_mux_destination};
use flux_protocol::trojan::{TROJAN_CMD_CONNECT, TrojanProtocol, hash_trojan_password};
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

/// /// A Trojan listener: a password, then a request header, over TLS.
pub struct TrojanInbound {
    tag: String,
    listen_addr: SocketAddr,
    password_hashes: Vec<String>,
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

impl TrojanInbound {
    /// A listener named `tag` on `listen_addr` with these passwords.
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
            mux: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            tasks: crate::InboundTasks::new(),
        }
    }

    /// Rejects connections above the limiter before any per-connection work.
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

/// Rejects a command the inbound cannot serve.
///
/// The command byte selects the framing of everything after the header, so an
/// unrecognised value must end the connection deterministically instead of
/// reaching the dispatcher or being retried by a peer that never gets an answer.
fn check_command(cmd: u8) -> FluxResult<()> {
    match cmd {
        TROJAN_CMD_CONNECT | flux_protocol::trojan::TROJAN_CMD_UDP => Ok(()),
        other => Err(FluxError::Protocol {
            protocol: "trojan",
            message: format!("unsupported trojan command: {other:#04x}"),
        }),
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
        let mux = self.mux.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] Trojan inbound listening on {}", tag, self.listen_addr);

        self.tasks.spawn(async move {
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
                let mux = mux.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let handshake_fut = async {
                        let mut stream = pipe.unwrap(socket).await?;
                        let (cmd, target) =
                            TrojanProtocol::read_request_header(&mut stream, &valid_hashes).await?;
                        // The command decides how the rest of the stream is
                        // framed: refuse an unknown one here, before it can
                        // reach the router or the mux branch.
                        check_command(cmd)?;
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

                    if let Some(mux_config) = &mux
                        && cmd == TROJAN_CMD_CONNECT
                        && is_mux_destination(&target)
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
                            flux_protocol::mux::serve(tls_stream, &mux_config, accept).await
                        {
                            debug!(
                                "[{}] mux session from {} ended: {}",
                                inbound_tag, client_addr, e
                            );
                        }
                        return;
                    }

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

                                // The frame is `[address][len u16 BE][CRLF][payload]`.
                                // These two bytes are part of the wire format: they
                                // used to be read and discarded, so a peer could put
                                // anything there (including another frame's header)
                                // and still have the datagram delivered.
                                let mut crlf = [0u8; 2];
                                if tokio::io::AsyncReadExt::read_exact(&mut read_half, &mut crlf)
                                    .await
                                    .is_err()
                                    || &crlf != b"\r\n"
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
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning while it is still running leaves the
        // port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_protocol::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
    use flux_transport::pipeline::ServerTransportPipeline;
    use flux_types::{BoxedStream, TargetAddress, UdpPacket};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc;

    const PASSWORD: &str = "correct horse battery staple";

    /// Dispatcher that records what the inbound produced instead of forwarding.
    #[derive(Default)]
    struct Recorder {
        streams: std::sync::atomic::AtomicUsize,
        packets: std::sync::atomic::AtomicUsize,
        stream_meta: std::sync::Mutex<Option<(TargetAddress, NetworkType)>>,
        received: std::sync::Mutex<Vec<UdpPacket>>,
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn streams(&self) -> usize {
            self.streams.load(Ordering::SeqCst)
        }

        fn packets(&self) -> usize {
            self.packets.load(Ordering::SeqCst)
        }

        fn received(&self) -> Vec<UdpPacket> {
            self.received.lock().unwrap().clone()
        }

        fn stream_meta(&self) -> Option<(TargetAddress, NetworkType)> {
            self.stream_meta.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Dispatcher for Recorder {
        async fn dispatch_stream(&self, meta: SessionMeta, _stream: BoxedStream) {
            *self.stream_meta.lock().unwrap() = Some((meta.destination, meta.network));
            self.streams.fetch_add(1, Ordering::SeqCst);
        }

        async fn dial_outbound(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            Err(FluxError::Protocol {
                protocol: "test",
                message: "no outbound in this test".into(),
            })
        }

        async fn bridge_streams(&self, _meta: SessionMeta, _a: BoxedStream, _b: BoxedStream) {}

        async fn dispatch_packet(
            &self,
            _meta: SessionMeta,
            mut rx: mpsc::Receiver<UdpPacket>,
            _tx: mpsc::Sender<UdpPacket>,
        ) {
            while let Some(packet) = rx.recv().await {
                self.received.lock().unwrap().push(packet);
                self.packets.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    async fn spawn_inbound(recorder: Arc<Recorder>) -> (Arc<TrojanInbound>, SocketAddr) {
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let inbound = Arc::new(TrojanInbound::new(
            "trojan-test",
            addr,
            vec![PASSWORD.to_string()],
            ServerTransportPipeline::raw(),
        ));
        let dispatcher: Arc<dyn Dispatcher> = recorder;
        inbound.start(dispatcher).await.unwrap();
        for _ in 0..100 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (inbound, addr)
    }

    fn hash() -> String {
        hash_trojan_password(PASSWORD)
    }

    /// A complete request: 56-byte hex hash, CRLF, command, SOCKS5 address, CRLF.
    fn request(hash_str: &str, cmd: u8, port: u16, atyp: u8, address: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(hash_str.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.push(cmd);
        out.push(atyp);
        out.extend_from_slice(address);
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(b"\r\n");
        out
    }

    fn connect_request() -> Vec<u8> {
        request(&hash(), TROJAN_CMD_CONNECT, 443, ATYP_IPV4, &[1, 2, 3, 4])
    }

    fn udp_request() -> Vec<u8> {
        request(
            &hash(),
            flux_protocol::trojan::TROJAN_CMD_UDP,
            53,
            ATYP_IPV4,
            &[9, 9, 9, 9],
        )
    }

    /// Trojan's UDP frame: `[address][len u16 BE][CRLF][payload]`.
    fn udp_frame(
        atyp: u8,
        address: &[u8],
        port: u16,
        len: u16,
        terminator: &[u8; 2],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![atyp];
        out.extend_from_slice(address);
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(terminator);
        out.extend_from_slice(payload);
        out
    }

    async fn wait_until(cond: impl Fn() -> bool) -> bool {
        for _ in 0..400 {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    /// Collects what the server sends within `budget`, stopping at EOF or RST.
    async fn recv_for(stream: &mut TcpStream, budget: Duration) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return buf;
            }
            match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return buf,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return buf,
            }
        }
    }

    /// Runs the server-side header parser on a fixed byte string.
    async fn parse(input: &[u8], hashes: &[String]) -> FluxResult<(u8, TargetAddress)> {
        let mut cursor = std::io::Cursor::new(input.to_vec());
        tokio::time::timeout(
            Duration::from_secs(2),
            TrojanProtocol::read_request_header(&mut cursor, hashes),
        )
        .await
        .expect("Trojan parser blocked instead of returning")
    }

    // -------------------------------------------------------------------
    // Baseline
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn valid_connect_request_is_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&connect_request()).await.unwrap();
        stream.write_all(b"payload").await.unwrap();

        assert!(wait_until(|| recorder.streams() == 1).await);
        assert_eq!(
            recorder.stream_meta(),
            Some((TargetAddress::ipv4(1, 2, 3, 4, 443), NetworkType::Tcp))
        );
        inbound.stop().await.unwrap();
    }

    // -------------------------------------------------------------------
    // 1. The password field: exactly 56 bytes, CRLF required, auth first
    // -------------------------------------------------------------------

    /// Authentication must fail before the command or the address is parsed: a
    /// wrong hash with nothing behind it is an auth failure, not an EOF.
    #[tokio::test]
    async fn wrong_password_is_auth_failed_before_the_address_is_parsed() {
        let wrong = hash_trojan_password("wrong password");
        let mut header = Vec::new();
        header.extend_from_slice(wrong.as_bytes());
        header.extend_from_slice(b"\r\n");
        let err = parse(&header, &[hash()]).await.unwrap_err();
        assert!(
            matches!(err, FluxError::AuthFailed(_)),
            "expected an auth failure before any address parsing, got {err:?}"
        );
    }

    /// A short password field cannot be smuggled past the fixed 58-byte read:
    /// the bytes after it must still be a CRLF, and the address that follows is
    /// never reached.
    #[tokio::test]
    async fn short_password_field_is_rejected() {
        let mut header = b"0123456789abcdef".repeat(3).to_vec(); // 48 bytes
        header.extend_from_slice(b"\r\n");
        header.push(TROJAN_CMD_CONNECT);
        header.push(ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
        header.extend_from_slice(b"\r\n");
        let err = parse(&header, &[hash()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");
    }

    /// A long password field is likewise just the first 56 bytes plus a required
    /// CRLF; the extra bytes are not swallowed into the credential.
    #[tokio::test]
    async fn over_long_password_field_is_rejected() {
        let mut header = b"0123456789abcdef".repeat(4).to_vec(); // 64 bytes
        header.extend_from_slice(b"\r\n");
        header.push(TROJAN_CMD_CONNECT);
        header.push(ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
        header.extend_from_slice(b"\r\n");
        let err = parse(&header, &[hash()]).await.unwrap_err();
        assert!(
            matches!(err, FluxError::AuthFailed(_) | FluxError::Protocol { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_crlf_after_the_password_hash_is_rejected() {
        let mut header = hash().into_bytes();
        header.pop();
        header.extend_from_slice(b"XY"); // 56 bytes, but not a CRLF at 56..58
        header.push(TROJAN_CMD_CONNECT);
        header.push(ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
        header.extend_from_slice(b"\r\n");
        let err = parse(&header, &[hash()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");
    }

    /// The terminating CRLF is part of the header. Without it the request must
    /// not be accepted, and it must not be dispatched either.
    #[tokio::test]
    async fn terminating_crlf_is_required() {
        let mut header = connect_request();
        header.truncate(header.len() - 2);

        // On a stream a missing terminator is indistinguishable from a truncated
        // header, so the error is whatever the final `read_exact` produced; what
        // matters is that the request is not accepted.
        assert!(parse(&header, &[hash()]).await.is_err());

        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&header).await.unwrap();
        let received = recv_for(&mut stream, Duration::from_millis(500)).await;
        assert!(received.is_empty());
        assert_eq!(recorder.streams(), 0, "a CRLF-less header was dispatched");
        inbound.stop().await.unwrap();
    }

    /// The address that follows the command is SOCKS5-shaped; its type byte must
    /// be one of the three defined values, and a zero-length domain is invalid.
    #[tokio::test]
    async fn socks_style_address_is_validated() {
        let mut bad_atyp = Vec::new();
        bad_atyp.extend_from_slice(hash().as_bytes());
        bad_atyp.extend_from_slice(b"\r\n");
        bad_atyp.push(TROJAN_CMD_CONNECT);
        bad_atyp.push(0x05);
        bad_atyp.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
        bad_atyp.extend_from_slice(b"\r\n");
        let err = parse(&bad_atyp, &[hash()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");

        let mut empty_domain = Vec::new();
        empty_domain.extend_from_slice(hash().as_bytes());
        empty_domain.extend_from_slice(b"\r\n");
        empty_domain.push(TROJAN_CMD_CONNECT);
        empty_domain.push(ATYP_DOMAIN);
        empty_domain.push(0x00);
        empty_domain.extend_from_slice(&[0, 80]);
        empty_domain.extend_from_slice(b"\r\n");
        let err = parse(&empty_domain, &[hash()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");

        // The largest length a one-byte field can express, with three bytes
        // present: the address reader must stop at the missing bytes instead of
        // reading past the buffer.
        let mut long_domain = Vec::new();
        long_domain.extend_from_slice(hash().as_bytes());
        long_domain.extend_from_slice(b"\r\n");
        long_domain.push(TROJAN_CMD_CONNECT);
        long_domain.push(ATYP_DOMAIN);
        long_domain.push(0xff);
        long_domain.extend_from_slice(b"abc");
        assert!(parse(&long_domain, &[hash()]).await.is_err());
    }

    /// Every prefix of a valid header is an error, and a complete header parses.
    #[tokio::test]
    async fn every_truncation_prefix_is_rejected() {
        for valid in [
            connect_request(),
            request(&hash(), TROJAN_CMD_CONNECT, 443, ATYP_IPV6, &[0x20; 16]),
            request(
                &hash(),
                TROJAN_CMD_CONNECT,
                443,
                ATYP_DOMAIN,
                b"\x0bexample.com",
            ),
        ] {
            for cut in 0..valid.len() {
                let result = parse(&valid[..cut], &[hash()]).await;
                assert!(
                    result.is_err(),
                    "a {cut}-byte prefix of a {}-byte header was accepted: {result:?}",
                    valid.len()
                );
            }
            assert!(
                parse(&valid, &[hash()]).await.is_ok(),
                "the complete header must still parse"
            );
        }
    }

    #[tokio::test]
    async fn single_byte_mutations_never_panic_or_block() {
        let valid = connect_request();
        for pos in 0..valid.len() {
            for xor in [0x01u8, 0x80, 0xff] {
                let mut mutated = valid.clone();
                mutated[pos] ^= xor;
                let _ = parse(&mutated, &[hash()]).await;
            }
        }
    }

    // -------------------------------------------------------------------
    // 2. Commands
    // -------------------------------------------------------------------

    /// Only CONNECT and UDP are servable; anything else must be refused rather
    /// than logged and left to the dispatcher.
    #[test]
    fn unknown_command_is_refused_by_the_gate() {
        assert!(check_command(TROJAN_CMD_CONNECT).is_ok());
        assert!(check_command(flux_protocol::trojan::TROJAN_CMD_UDP).is_ok());
        for cmd in [0x00u8, 0x02, 0x04, 0x7f, 0xff] {
            assert!(
                check_command(cmd).is_err(),
                "command {cmd:#04x} must be refused"
            );
        }
    }

    // -------------------------------------------------------------------
    // 3. The Trojan UDP framing (a post-auth parser, still attacker-controlled)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn udp_datagram_is_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&udp_request()).await.unwrap();
        stream
            .write_all(&udp_frame(
                ATYP_IPV4,
                &[9, 9, 9, 9],
                53,
                5,
                b"\r\n",
                b"hello",
            ))
            .await
            .unwrap();

        assert!(
            wait_until(|| recorder.packets() == 1).await,
            "a valid Trojan UDP frame was not delivered"
        );
        let packets = recorder.received();
        assert_eq!(packets[0].payload.as_ref(), b"hello");
        assert_eq!(packets[0].destination.port(), 53);
        inbound.stop().await.unwrap();
    }

    /// The frame is `[address][len][CRLF][payload]`. The two terminator bytes
    /// used to be read and thrown away, so any frame — including one whose
    /// padding bytes carry another frame's header — was accepted.
    #[tokio::test]
    async fn udp_frame_without_the_crlf_terminator_is_refused() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&udp_request()).await.unwrap();
        stream
            .write_all(&udp_frame(ATYP_IPV4, &[9, 9, 9, 9], 53, 5, b"XY", b"hello"))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            recorder.packets(),
            0,
            "a frame with a bogus terminator was dispatched: {:?}",
            recorder.received()
        );
        inbound.stop().await.unwrap();
    }

    /// A declared length above the largest possible UDP payload is refused
    /// before any buffer is sized from it.
    #[tokio::test]
    async fn oversized_udp_frame_is_refused_without_allocating() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&udp_request()).await.unwrap();
        // 65508 > 65507: claim the maximum and send nothing.
        stream
            .write_all(&udp_frame(
                ATYP_IPV4,
                &[9, 9, 9, 9],
                53,
                65508,
                b"\r\n",
                b"",
            ))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            recorder.packets(),
            0,
            "an oversized frame was accepted: {:?}",
            recorder.received()
        );
        inbound.stop().await.unwrap();
    }

    /// The boundary itself is legal: 65507 bytes in one datagram still arrives.
    #[tokio::test]
    async fn maximum_sized_udp_frame_is_accepted() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let payload = vec![0xa5u8; 65507];
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&udp_request()).await.unwrap();
        stream
            .write_all(&udp_frame(
                ATYP_IPV4,
                &[9, 9, 9, 9],
                53,
                65507,
                b"\r\n",
                &payload,
            ))
            .await
            .unwrap();

        assert!(wait_until(|| recorder.packets() == 1).await);
        assert_eq!(recorder.received()[0].payload.len(), 65507);
        inbound.stop().await.unwrap();
    }

    /// A truncated frame ends the association without delivering anything and
    /// without reading past the end of the buffer.
    #[tokio::test]
    async fn truncated_udp_frame_delivers_nothing() {
        let frame = udp_frame(ATYP_IPV4, &[9, 9, 9, 9], 53, 20, b"\r\n", b"short");
        for cut in 0..frame.len() {
            let recorder = Recorder::new();
            let (inbound, addr) = spawn_inbound(recorder.clone()).await;
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&udp_request()).await.unwrap();
            stream.write_all(&frame[..cut]).await.unwrap();
            stream.shutdown().await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert_eq!(
                recorder.packets(),
                0,
                "frame prefix of {cut} bytes delivered"
            );
            inbound.stop().await.unwrap();
        }
    }
}
