use async_trait::async_trait;
use flux_protocol::mux::{MuxConfig, is_mux_destination};
use flux_protocol::vmess::{VMESS_CMD_UDP, VmessProtocol, VmessStream};
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, UdpPacket};
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
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
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
            tasks: crate::InboundTasks::new(),
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

/// Rejects a request header whose fields this inbound cannot serve.
///
/// Three header fields decide how the rest of the connection is framed, and all
/// three are attacker-controlled:
///
/// * the command byte must be TCP or UDP -- anything else has no defined
///   framing and used to be served as a TCP stream;
/// * the option bits must not ask for global padding (`0x08`) or authenticated
///   length (`0x10`), which change the chunk layout and cannot be ignored
///   without desynchronising the stream (chunk-stream `0x01`,
///   connection-reuse `0x02` and chunk-masking `0x04` are safe);
/// * the security byte must be one of the two AEADs actually implemented --
///   `VmessCipher::new` silently falls back to AES-128-GCM for anything else,
///   so an unsupported value used to be "repaired" rather than refused.
fn check_request_shape(req: &flux_protocol::vmess::VmessRequest) -> FluxResult<()> {
    if !matches!(
        req.command,
        flux_protocol::vmess::VMESS_CMD_TCP | flux_protocol::vmess::VMESS_CMD_UDP
    ) {
        return Err(FluxError::Protocol {
            protocol: "vmess",
            message: format!("unsupported vmess command: {}", req.command),
        });
    }
    if req.option & 0x18 != 0 {
        return Err(FluxError::Protocol {
            protocol: "vmess",
            message: format!("unsupported vmess option bits: {:#04x}", req.option),
        });
    }
    if !matches!(
        req.security,
        flux_protocol::vmess::VMESS_SECURITY_AES_128_GCM
            | flux_protocol::vmess::VMESS_SECURITY_CHACHA20_POLY1305
    ) {
        return Err(FluxError::Protocol {
            protocol: "vmess",
            message: format!("unsupported vmess security: {}", req.security),
        });
    }
    Ok(())
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

        self.tasks.spawn(async move {
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

                    // Refuse a header we cannot frame before building any
                    // stream state from it.
                    if let Err(e) = check_request_shape(&req) {
                        warn!(
                            "[{}] VMess request refused from {}: {}",
                            inbound_tag, client_addr, e
                        );
                        return;
                    }

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
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning while it is still running leaves the
        // port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_protocol::vmess::{
        VMESS_CMD_TCP, VMESS_SECURITY_AES_128_GCM, VMESS_SECURITY_CHACHA20_POLY1305, VmessRequest,
    };
    use flux_transport::pipeline::ServerTransportPipeline;
    use flux_types::{BoxedStream, TargetAddress, UdpPacket};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc;

    fn test_uuid() -> Uuid {
        Uuid::from_bytes([0x33; 16])
    }

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

    async fn spawn_inbound(recorder: Arc<Recorder>) -> (Arc<VmessInbound>, SocketAddr) {
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let inbound = Arc::new(VmessInbound::new(
            "vmess-test",
            addr,
            vec![test_uuid()],
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

    /// Encodes a request header the way a real client does and returns the bytes
    /// plus the session key/IV a client would need to speak afterwards.
    async fn encode_header(
        security: u8,
        network: NetworkType,
        destination: &TargetAddress,
    ) -> ([u8; 16], [u8; 16], Vec<u8>) {
        let mut buf = Vec::new();
        let (key, iv, resp) = VmessProtocol::write_request_header(
            &mut buf,
            &test_uuid(),
            network,
            destination,
            security,
        )
        .await
        .unwrap();
        let _ = resp;
        (key, iv, buf)
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

    async fn parse(input: &[u8], uuids: &[Uuid]) -> FluxResult<VmessRequest> {
        let mut cursor = std::io::Cursor::new(input.to_vec());
        tokio::time::timeout(
            Duration::from_secs(2),
            VmessProtocol::read_request_header(&mut cursor, uuids),
        )
        .await
        .expect("VMess parser blocked instead of returning")
    }

    // -------------------------------------------------------------------
    // Baseline
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn valid_tcp_header_is_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let destination = TargetAddress::domain("example.com", 8443);
        let (_, _, header) =
            encode_header(VMESS_SECURITY_AES_128_GCM, NetworkType::Tcp, &destination).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&header).await.unwrap();

        assert!(wait_until(|| recorder.streams() == 1).await);
        assert_eq!(
            recorder.stream_meta(),
            Some((destination, NetworkType::Tcp))
        );
        inbound.stop().await.unwrap();
    }

    // -------------------------------------------------------------------
    // 1. Authentication before any decryption work
    // -------------------------------------------------------------------

    /// A wrong auth ID must be refused before the encrypted body is read (and
    /// long before it is allocated for).
    #[tokio::test]
    async fn wrong_auth_id_is_auth_failed_before_the_body_is_read() {
        let mut header = [0u8; 16];
        header[0] = 0xff;
        let err = parse(&header, &[test_uuid()]).await.unwrap_err();
        assert!(
            matches!(err, FluxError::AuthFailed(_)),
            "expected an auth failure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn wrong_auth_id_is_not_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0x5au8; 16]).await.unwrap();
        let received = recv_for(&mut stream, Duration::from_millis(500)).await;
        assert!(
            received.is_empty(),
            "an unauthenticated header was answered"
        );
        assert_eq!(recorder.streams(), 0);
        assert_eq!(recorder.packets(), 0);
        inbound.stop().await.unwrap();
    }

    // -------------------------------------------------------------------
    // 2. Header fields that change the framing
    // -------------------------------------------------------------------

    /// The security byte selects the AEAD. `VmessCipher::new` falls back to
    /// AES-128-GCM for anything it does not know, so an unsupported value used
    /// to be silently "repaired" instead of refused — which then decrypts the
    /// peer's chunks with the wrong cipher.
    #[tokio::test]
    async fn unsupported_security_is_refused() {
        for security in [0u8, 1, 2, 5, 6, 15] {
            let recorder = Recorder::new();
            let (inbound, addr) = spawn_inbound(recorder.clone()).await;

            let destination = TargetAddress::ipv4(1, 2, 3, 4, 443);
            let (_, _, header) = encode_header(security, NetworkType::Tcp, &destination).await;

            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&header).await.unwrap();

            assert!(
                !wait_until(|| recorder.streams() > 0).await,
                "security {security} was accepted and dispatched"
            );
            assert_eq!(recorder.streams(), 0);
            inbound.stop().await.unwrap();
        }
    }

    #[tokio::test]
    async fn supported_security_values_are_accepted() {
        for security in [VMESS_SECURITY_AES_128_GCM, VMESS_SECURITY_CHACHA20_POLY1305] {
            let recorder = Recorder::new();
            let (inbound, addr) = spawn_inbound(recorder.clone()).await;
            let destination = TargetAddress::ipv4(1, 2, 3, 4, 443);
            let (_, _, header) = encode_header(security, NetworkType::Tcp, &destination).await;

            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&header).await.unwrap();
            assert!(
                wait_until(|| recorder.streams() == 1).await,
                "security {security} must be accepted"
            );
            inbound.stop().await.unwrap();
        }
    }

    /// The command byte and the option bits are only reachable inside the AEAD
    /// body, so this pins the gate itself: every value the inbound will serve is
    /// listed explicitly, and everything else is refused.
    #[test]
    fn request_shape_gate_enumerates_exactly_what_is_supported() {
        let base = VmessRequest {
            uuid: test_uuid(),
            command: VMESS_CMD_TCP,
            address: TargetAddress::ipv4(1, 2, 3, 4, 443),
            security: VMESS_SECURITY_AES_128_GCM,
            session_key: [0u8; 16],
            session_iv: [0u8; 16],
            resp_header: 0x55,
            option: 0x05,
        };
        assert!(check_request_shape(&base).is_ok());

        // Commands: only TCP and UDP have a defined framing.
        for command in 0u8..=255 {
            let mut req = base.clone();
            req.command = command;
            let expected = matches!(command, 1 | 2);
            assert_eq!(
                check_request_shape(&req).is_ok(),
                expected,
                "command {command} acceptance"
            );
        }

        // Option bits: 0x08 (global padding) and 0x10 (authenticated length)
        // change the chunk layout, so a peer that sets them cannot be served.
        for option in 0u8..=255 {
            let mut req = base.clone();
            req.option = option;
            let expected = option & 0x18 == 0;
            assert_eq!(
                check_request_shape(&req).is_ok(),
                expected,
                "option {option:#04x} acceptance"
            );
        }

        // Security: only the two AEADs this implementation actually has.
        for security in 0u8..16 {
            let mut req = base.clone();
            req.security = security;
            let expected = matches!(
                security,
                VMESS_SECURITY_AES_128_GCM | VMESS_SECURITY_CHACHA20_POLY1305
            );
            assert_eq!(
                check_request_shape(&req).is_ok(),
                expected,
                "security {security} acceptance"
            );
        }
    }

    // -------------------------------------------------------------------
    // 3. Bounds: truncation and mutation of the whole header
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn every_truncation_prefix_is_rejected() {
        let destination = TargetAddress::domain("example.com", 443);
        let (_, _, header) =
            encode_header(VMESS_SECURITY_AES_128_GCM, NetworkType::Tcp, &destination).await;
        for cut in 0..header.len() {
            let result = parse(&header[..cut], &[test_uuid()]).await;
            assert!(
                result.is_err(),
                "a {cut}-byte prefix of a {}-byte header was accepted: {result:?}",
                header.len()
            );
        }
        // A prefix of at least 16 bytes still carries the (valid) auth ID, and
        // verification records it in the replay filter, so the complete header
        // has to come from a fresh client header.
        let (_, _, fresh) =
            encode_header(VMESS_SECURITY_AES_128_GCM, NetworkType::Tcp, &destination).await;
        assert!(
            parse(&fresh, &[test_uuid()]).await.is_ok(),
            "the complete header must parse"
        );
    }

    #[tokio::test]
    async fn single_byte_mutations_never_panic_or_block() {
        let destination = TargetAddress::ipv4(1, 2, 3, 4, 443);
        let (_, _, header) =
            encode_header(VMESS_SECURITY_AES_128_GCM, NetworkType::Tcp, &destination).await;
        for pos in 0..header.len() {
            for xor in [0x01u8, 0x80, 0xff] {
                let mut mutated = header.clone();
                mutated[pos] ^= xor;
                let _ = parse(&mutated, &[test_uuid()]).await;
            }
        }
    }

    // -------------------------------------------------------------------
    // 4. The VMess UDP framing and the response header
    // -------------------------------------------------------------------

    /// VMess UDP over TCP is `[len u16 BE][payload]` inside the encrypted
    /// stream. A length the peer declares but never sends must not be allocated
    /// and must not deliver a packet.
    #[tokio::test]
    async fn udp_frame_is_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let destination = TargetAddress::ipv4(198, 51, 100, 7, 53);
        let (key, iv, header) =
            encode_header(VMESS_SECURITY_AES_128_GCM, NetworkType::Udp, &destination).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&header).await.unwrap();
        let mut client =
            VmessStream::new_client(stream, key, iv, VMESS_SECURITY_AES_128_GCM, 0x55, 0x05);
        client.write_all(&5u16.to_be_bytes()).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();

        assert!(
            wait_until(|| recorder.packets() == 1).await,
            "a VMess UDP frame was not delivered"
        );
        assert_eq!(recorder.received()[0].payload.as_ref(), b"hello");
        assert_eq!(recorder.received()[0].destination.port(), 53);
        inbound.stop().await.unwrap();
    }

    #[tokio::test]
    async fn truncated_udp_frame_delivers_nothing() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone()).await;

        let destination = TargetAddress::ipv4(198, 51, 100, 7, 53);
        let (key, iv, header) =
            encode_header(VMESS_SECURITY_AES_128_GCM, NetworkType::Udp, &destination).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&header).await.unwrap();
        let mut client =
            VmessStream::new_client(stream, key, iv, VMESS_SECURITY_AES_128_GCM, 0x55, 0x05);
        // Declares 60000 bytes, sends three.
        client.write_all(&60000u16.to_be_bytes()).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(recorder.packets(), 0, "a truncated frame was delivered");
        inbound.stop().await.unwrap();
    }

    /// The response header is sealed with an AEAD under a key derived from the
    /// session key/IV, so the client only accepts a header produced by the peer
    /// that finished the request handshake. A different echo value is refused.
    #[tokio::test]
    async fn client_rejects_a_mismatched_response_header() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let (client_side, server_side) = tokio::io::duplex(4096);

        let mut client =
            VmessStream::new_client(client_side, key, iv, VMESS_SECURITY_AES_128_GCM, 0x55, 0x05);
        // The server echoes 0x99; the client asked for 0x55.
        let mut server =
            VmessStream::new_server(server_side, key, iv, VMESS_SECURITY_AES_128_GCM, 0x99, 0x05);
        server.write_all(b"data").await.unwrap();
        server.flush().await.unwrap();

        let mut buf = [0u8; 4];
        let err = client.read_exact(&mut buf).await;
        assert!(
            err.is_err(),
            "a response header echoing the wrong value was accepted"
        );
    }

    #[tokio::test]
    async fn client_accepts_the_matching_response_header() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let (client_side, server_side) = tokio::io::duplex(4096);

        let mut client =
            VmessStream::new_client(client_side, key, iv, VMESS_SECURITY_AES_128_GCM, 0x55, 0x05);
        let mut server =
            VmessStream::new_server(server_side, key, iv, VMESS_SECURITY_AES_128_GCM, 0x55, 0x05);
        server.write_all(b"data").await.unwrap();
        server.flush().await.unwrap();

        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
    }
}
