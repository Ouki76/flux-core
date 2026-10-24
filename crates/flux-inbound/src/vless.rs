use async_trait::async_trait;
use flux_protocol::mux::{MuxConfig, is_mux_destination};
use flux_protocol::vless::{VLESS_CMD_TCP, VlessProtocol};
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// /// A VLESS listener.
pub struct VlessInbound {
    tag: String,
    listen_addr: SocketAddr,
    uuids: Vec<Uuid>,
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

impl VlessInbound {
    /// A listener named `tag` on `listen_addr` accepting these UUIDs.
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

/// Rejects a header the inbound cannot serve, *before* anything is answered.
///
/// The command byte decides the wire shape of everything that follows the
/// header, so an unrecognised value must be refused rather than logged and
/// dropped: an answered-but-unsupported request tells a scanner the UUID was
/// valid, and the declared command has to agree with the flow the peer asked
/// for (the Vision flow is TCP-only, as in Xray).
fn check_request(req: &flux_protocol::vless::VlessRequest) -> FluxResult<()> {
    match req.command {
        VLESS_CMD_TCP
        | flux_protocol::vless::VLESS_CMD_UDP
        | flux_protocol::vless::VLESS_CMD_PACKETADDR => {}
        other => {
            return Err(FluxError::Protocol {
                protocol: "vless",
                message: format!("unsupported vless command: {other:#04x}"),
            });
        }
    }
    if req.is_vision && req.command != VLESS_CMD_TCP {
        return Err(FluxError::Protocol {
            protocol: "vless",
            message: format!("vision flow requires the TCP command, got {}", req.command),
        });
    }
    Ok(())
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
        let mux = self.mux.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] VLESS inbound listening on {}", tag, self.listen_addr);

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
                let mux = mux.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let handshake_fut = async {
                        let mut stream = pipe.unwrap(socket).await?;
                        let req = VlessProtocol::read_request_header(&mut stream, &uuids).await?;
                        // Refuse anything we cannot serve before answering: the
                        // response header is this inbound's only "authenticated,
                        // go ahead" signal, so it must not precede validation.
                        check_request(&req)?;
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

                    // A mux session is a normal VLESS connection whose target is
                    // the reserved mux destination (sing-box convention). It is
                    // TCP-only: taking the branch for a UDP/PACKETADDR request
                    // would parse the peer's datagram framing as smux frames.
                    if let Some(mux_config) = &mux
                        && req.command == VLESS_CMD_TCP
                        && !req.is_vision
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
                        if let Err(e) = flux_protocol::mux::serve(stream, &mux_config, accept).await
                        {
                            debug!(
                                "[{}] mux session from {} ended: {}",
                                inbound_tag, client_addr, e
                            );
                        }
                        return;
                    }

                    if req.command == VLESS_CMD_TCP {
                        let meta = SessionMeta::new(
                            client_addr,
                            req.address,
                            inbound_tag,
                            NetworkType::Tcp,
                        );

                        let final_stream: BoxedStream = if req.is_vision {
                            // The UUID comes from the (already authenticated) VLESS
                            // header; the peer prefixes its first frame with it.
                            Box::new(flux_protocol::vision::VisionStream::new(
                                stream,
                                *req.uuid.as_bytes(),
                            ))
                        } else {
                            stream
                        };

                        disp.dispatch_stream(meta, final_stream).await;
                    } else if req.command == flux_protocol::vless::VLESS_CMD_PACKETADDR {
                        // sing-box (and Xray's packetaddr mode) send UDP this way:
                        // every datagram carries its own destination. The request
                        // header's address is a placeholder, so replies must echo
                        // the responder address per datagram.
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

                        let read_fut = async move {
                            while let Ok(packet) =
                                flux_protocol::udp::decode_vless_packetaddr(&mut read_half).await
                            {
                                if pkt_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        };

                        let write_fut = async move {
                            while let Some(packet) = out_rx.recv().await {
                                let encoded = flux_protocol::udp::encode_vless_packetaddr(
                                    &packet,
                                    &packet.source,
                                );
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
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning while it is still running leaves the
        // port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_protocol::mux::MUX_DESTINATION_FQDN;
    use flux_protocol::vless::{
        VLESS_ATYP_DOMAIN, VLESS_ATYP_IPV4, VLESS_ATYP_IPV6, VLESS_CMD_PACKETADDR, VLESS_CMD_UDP,
        VLESS_VERSION, VlessRequest,
    };
    use flux_transport::pipeline::ServerTransportPipeline;
    use flux_types::{BoxedStream, TargetAddress, UdpPacket};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc;

    fn test_uuid() -> Uuid {
        Uuid::from_bytes([0x11; 16])
    }

    fn other_uuid() -> Uuid {
        Uuid::from_bytes([0x22; 16])
    }

    /// Dispatcher that records what the inbound produced instead of forwarding.
    ///
    /// Every pre-authentication test asserts on "nothing was dispatched": a
    /// parser that resolves, dials or hands a target to the router before it has
    /// authenticated the peer fails these assertions.
    #[derive(Default)]
    struct Recorder {
        streams: std::sync::atomic::AtomicUsize,
        packets: std::sync::atomic::AtomicUsize,
        stream_meta: std::sync::Mutex<Option<(TargetAddress, NetworkType)>>,
        packet_meta: std::sync::Mutex<Option<(TargetAddress, NetworkType)>>,
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

        fn packet_meta(&self) -> Option<(TargetAddress, NetworkType)> {
            self.packet_meta.lock().unwrap().clone()
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
            meta: SessionMeta,
            mut rx: mpsc::Receiver<UdpPacket>,
            _tx: mpsc::Sender<UdpPacket>,
        ) {
            *self.packet_meta.lock().unwrap() = Some((meta.destination, meta.network));
            while let Some(packet) = rx.recv().await {
                self.received.lock().unwrap().push(packet);
                self.packets.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Reserves a free loopback port and releases it for the inbound to bind.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    async fn spawn_inbound(
        recorder: Arc<Recorder>,
        mux: Option<MuxConfig>,
    ) -> (Arc<VlessInbound>, SocketAddr) {
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut inbound = VlessInbound::new(
            "vless-test",
            addr,
            vec![test_uuid()],
            ServerTransportPipeline::raw(),
        );
        if let Some(config) = mux {
            inbound = inbound.with_mux(config);
        }
        let inbound = Arc::new(inbound);
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

    /// Builds an unencrypted VLESS request header with no addons.
    fn request(uuid: &Uuid, cmd: u8, port: u16, atyp: u8, address: &[u8]) -> Vec<u8> {
        let mut out = vec![VLESS_VERSION];
        out.extend_from_slice(uuid.as_bytes());
        out.push(0x00); // addons
        out.push(cmd);
        out.extend_from_slice(&port.to_be_bytes());
        out.push(atyp);
        out.extend_from_slice(address);
        out
    }

    fn domain_request(uuid: &Uuid, cmd: u8, port: u16, domain: &str) -> Vec<u8> {
        let mut out = vec![VLESS_VERSION];
        out.extend_from_slice(uuid.as_bytes());
        out.push(0x00);
        out.push(cmd);
        out.extend_from_slice(&port.to_be_bytes());
        out.push(VLESS_ATYP_DOMAIN);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain.as_bytes());
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

    /// Collects everything the server sends within `budget`, stopping early at
    /// EOF. `Ok(empty)` therefore means "the server rejected the request without
    /// saying anything", which is what every pre-authentication test expects.
    ///
    /// A read error counts as a close: rejecting a request leaves unread bytes
    /// in the socket buffer, so the kernel answers with RST once the server
    /// drops the stream, and a `read_to_end` would lose the buffered reply.
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

    /// Runs the server-side parser on a fixed byte string. A hang is a failure
    /// (the handshake is `timeout`-wrapped in production, but a parser that
    /// blocks forever on EOF would still pin a task per connection).
    async fn parse(input: &[u8], uuids: &[Uuid]) -> FluxResult<VlessRequest> {
        let mut cursor = std::io::Cursor::new(input.to_vec());
        tokio::time::timeout(
            Duration::from_secs(2),
            VlessProtocol::read_request_header(&mut cursor, uuids),
        )
        .await
        .expect("VLESS parser blocked instead of returning")
    }

    // -------------------------------------------------------------------
    // Baseline: the happy path still works (interop must not change)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn valid_tcp_request_is_answered_and_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), None).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(&request(
                &test_uuid(),
                VLESS_CMD_TCP,
                443,
                VLESS_ATYP_IPV4,
                &[1, 2, 3, 4],
            ))
            .await
            .unwrap();

        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [VLESS_VERSION, 0x00], "response header");

        assert!(wait_until(|| recorder.streams() == 1).await);
        assert_eq!(
            recorder.stream_meta(),
            Some((TargetAddress::ipv4(1, 2, 3, 4, 443), NetworkType::Tcp))
        );
        inbound.stop().await.unwrap();
    }

    // -------------------------------------------------------------------
    // 1. Authentication happens before anything else
    // -------------------------------------------------------------------

    /// The UUID is the credential. It must be checked before the addons field,
    /// the command and the target address are parsed: an invalid credential
    /// must produce `AuthFailed` even when the rest of the header is absent.
    #[tokio::test]
    async fn invalid_uuid_is_auth_failed_before_the_address_is_parsed() {
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(other_uuid().as_bytes());
        // Nothing follows: if the parser read the rest of the header first this
        // would be an EOF/protocol error instead of an authentication failure.

        let err = parse(&header, &[test_uuid()]).await.unwrap_err();
        assert!(
            matches!(err, FluxError::AuthFailed(_)),
            "expected an auth failure before any further parsing, got {err:?}"
        );
    }

    #[tokio::test]
    async fn invalid_uuid_gets_no_response_header_and_no_dispatch() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), None).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(other_uuid().as_bytes());
        header.push(0x00);
        header.push(VLESS_CMD_TCP);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(VLESS_ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4]);
        stream.write_all(&header).await.unwrap();

        let received = recv_for(&mut stream, Duration::from_millis(500)).await;
        assert!(
            received.is_empty(),
            "unauthenticated request was answered with {received:02x?}"
        );
        assert_eq!(recorder.streams(), 0, "unauthenticated request dispatched");
        assert_eq!(recorder.packets(), 0, "unauthenticated request dispatched");
        inbound.stop().await.unwrap();
    }

    // -------------------------------------------------------------------
    // 2. Bounds: truncation, mutations, address types, addons
    // -------------------------------------------------------------------

    /// Every prefix of a valid request must be an error. A parser that accepts a
    /// truncated prefix (or blocks forever) desynchronises the stream.
    #[tokio::test]
    async fn every_truncation_prefix_is_rejected() {
        for valid in [
            request(
                &test_uuid(),
                VLESS_CMD_TCP,
                443,
                VLESS_ATYP_IPV4,
                &[1, 2, 3, 4],
            ),
            request(
                &test_uuid(),
                VLESS_CMD_TCP,
                443,
                VLESS_ATYP_IPV6,
                &[0x20; 16],
            ),
            domain_request(&test_uuid(), VLESS_CMD_TCP, 443, "example.com"),
        ] {
            for cut in 0..valid.len() {
                let result = parse(&valid[..cut], &[test_uuid()]).await;
                assert!(
                    result.is_err(),
                    "a {cut}-byte prefix of a {}-byte header was accepted: {result:?}",
                    valid.len()
                );
            }
            assert!(
                parse(&valid, &[test_uuid()]).await.is_ok(),
                "the complete header must still parse"
            );
        }
    }

    /// Single-byte mutation across the whole header: no panic, no hang. Some
    /// mutations are legitimately valid (a different port, a different IP), so
    /// only "did not panic" and "did not block" are asserted.
    #[tokio::test]
    async fn single_byte_mutations_never_panic_or_block() {
        let valid = domain_request(&test_uuid(), VLESS_CMD_TCP, 443, "example.com");
        for pos in 0..valid.len() {
            for xor in [0x01u8, 0x80, 0xff] {
                let mut mutated = valid.clone();
                mutated[pos] ^= xor;
                let _ = parse(&mutated, &[test_uuid()]).await;
            }
        }
    }

    /// The version byte is checked before the UUID is even considered.
    #[tokio::test]
    async fn wrong_version_is_rejected() {
        for version in [0x01u8, 0x02, 0xff] {
            let mut header = request(
                &test_uuid(),
                VLESS_CMD_TCP,
                443,
                VLESS_ATYP_IPV4,
                &[1, 2, 3, 4],
            );
            header[0] = version;
            let err = parse(&header, &[test_uuid()]).await.unwrap_err();
            assert!(
                matches!(err, FluxError::Protocol { .. }),
                "version {version:#04x} must be a protocol error, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_address_type_is_rejected() {
        for atyp in [0x00u8, 0x04, 0x80, 0xff] {
            let err = parse(
                &request(&test_uuid(), VLESS_CMD_TCP, 80, atyp, &[1, 2, 3, 4]),
                &[test_uuid()],
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, FluxError::Protocol { .. }),
                "atyp {atyp:#04x} must be a protocol error, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn empty_domain_is_rejected() {
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(test_uuid().as_bytes());
        header.push(0x00);
        header.push(VLESS_CMD_TCP);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(VLESS_ATYP_DOMAIN);
        header.push(0x00); // zero-length domain
        let err = parse(&header, &[test_uuid()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");
    }

    /// 255 is the largest length a one-byte field can express and is legal; what
    /// matters is that the read is bounded by the declared length and that a
    /// claim larger than the buffered bytes is an error rather than a panic.
    #[tokio::test]
    async fn domain_length_is_bounded_by_the_declared_bytes() {
        let long = "a".repeat(255);
        let ok = parse(
            &domain_request(&test_uuid(), VLESS_CMD_TCP, 443, &long),
            &[test_uuid()],
        )
        .await
        .expect("a 255-byte domain is legal");
        assert_eq!(ok.address.port(), 443);
        assert_eq!(ok.address.host().len(), 255);

        // Same claim, five bytes present.
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(test_uuid().as_bytes());
        header.push(0x00);
        header.push(VLESS_CMD_TCP);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(VLESS_ATYP_DOMAIN);
        header.push(200);
        header.extend_from_slice(b"short");
        let err = parse(&header, &[test_uuid()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");
    }

    /// The addons field is length-prefixed. Its length must not be trusted into
    /// a heap allocation, and a truncated addons block must be an error.
    #[tokio::test]
    async fn addon_length_is_bounded() {
        // 255 addons bytes, all present: accepted, and is_vision stays false.
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(test_uuid().as_bytes());
        header.push(255);
        header.extend_from_slice(&[b'x'; 255]);
        header.push(VLESS_CMD_TCP);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(VLESS_ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4]);
        let request = parse(&header, &[test_uuid()]).await.expect("255 addons");
        assert!(!request.is_vision);

        // 255 claimed, 10 present: error, not a panic and not an unbounded read.
        let mut truncated = vec![VLESS_VERSION];
        truncated.extend_from_slice(test_uuid().as_bytes());
        truncated.push(255);
        truncated.extend_from_slice(&[b'x'; 10]);
        let err = parse(&truncated, &[test_uuid()]).await.unwrap_err();
        assert!(matches!(err, FluxError::Protocol { .. }), "got {err:?}");

        // The addons block is exactly as long as declared: the command that
        // follows must be read from the byte after it (no off-by-one drain).
        let mut exact = vec![VLESS_VERSION];
        exact.extend_from_slice(test_uuid().as_bytes());
        exact.push(3);
        exact.extend_from_slice(b"abc");
        exact.push(VLESS_CMD_TCP);
        exact.extend_from_slice(&8080u16.to_be_bytes());
        exact.push(VLESS_ATYP_IPV4);
        exact.extend_from_slice(&[9, 9, 9, 9]);
        let request = parse(&exact, &[test_uuid()]).await.expect("exact addons");
        assert_eq!(request.command, VLESS_CMD_TCP);
        assert_eq!(request.address.port(), 8080);
    }

    // -------------------------------------------------------------------
    // 3. Commands: unknown ones are refused, PACKETADDR keeps its own shape
    // -------------------------------------------------------------------

    /// An unknown command byte must be refused *before* the server answers:
    /// writing the response header first tells a scanner "authenticated, go on"
    /// and leaks that the UUID was valid.
    #[tokio::test]
    async fn unknown_command_gets_no_response_header_and_no_dispatch() {
        for cmd in [0x00u8, 0x04, 0x05, 0x7f, 0xff] {
            let recorder = Recorder::new();
            let (inbound, addr) = spawn_inbound(recorder.clone(), None).await;

            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(&request(
                    &test_uuid(),
                    cmd,
                    443,
                    VLESS_ATYP_IPV4,
                    &[1, 2, 3, 4],
                ))
                .await
                .unwrap();

            let received = recv_for(&mut stream, Duration::from_millis(500)).await;
            assert!(
                received.is_empty(),
                "command {cmd:#04x} was answered with {received:02x?}"
            );
            assert_eq!(recorder.streams(), 0, "command {cmd:#04x} dispatched");
            assert_eq!(recorder.packets(), 0, "command {cmd:#04x} dispatched");
            inbound.stop().await.unwrap();
        }
    }

    /// `PACKETADDR` has no port and no address in the header: each datagram
    /// carries its own destination. Mixing the shapes must not desynchronise.
    #[tokio::test]
    async fn packetaddr_dispatches_udp_and_decodes_datagrams() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), None).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        // No port, no address after the command.
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(test_uuid().as_bytes());
        header.push(0x00);
        header.push(VLESS_CMD_PACKETADDR);
        stream.write_all(&header).await.unwrap();

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VLESS_VERSION, 0x00]);

        let destination = TargetAddress::ipv4(203, 0, 113, 5, 9999);
        let datagram = flux_protocol::udp::encode_vless_packetaddr(
            &UdpPacket::new(
                bytes::Bytes::from_static(b"abc"),
                destination.clone(),
                destination,
            ),
            &TargetAddress::ipv4(203, 0, 113, 5, 9999),
        );
        stream.write_all(&datagram).await.unwrap();

        assert!(
            wait_until(|| recorder.packets() == 1).await,
            "PACKETADDR datagram was not delivered"
        );
        let packets = recorder.received();
        assert_eq!(packets[0].payload.as_ref(), b"abc");
        assert_eq!(packets[0].destination.port(), 9999);
        assert_eq!(
            recorder.packet_meta(),
            Some((TargetAddress::ipv4(0, 0, 0, 0, 0), NetworkType::Udp))
        );
        inbound.stop().await.unwrap();
    }

    /// A `UDP` command aimed at the smux pseudo destination must stay UDP: the
    /// mux branch used to be taken for *any* command, so the declared command
    /// was silently dropped and the datagram stream was parsed as smux frames.
    #[tokio::test]
    async fn udp_command_to_the_mux_destination_stays_udp() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), Some(MuxConfig::default())).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(&domain_request(
                &test_uuid(),
                VLESS_CMD_UDP,
                444,
                MUX_DESTINATION_FQDN,
            ))
            .await
            .unwrap();

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VLESS_VERSION, 0x00]);

        stream.write_all(&5u16.to_be_bytes()).await.unwrap();
        stream.write_all(b"hello").await.unwrap();

        assert!(
            wait_until(|| recorder.packets() == 1).await,
            "a UDP command was swallowed by the mux branch"
        );
        assert_eq!(recorder.received()[0].payload.as_ref(), b"hello");
        assert_eq!(recorder.streams(), 0);
        inbound.stop().await.unwrap();
    }

    /// The Vision flow (`addons` field) is defined for TCP only. A `UDP` command
    /// that claims it asks the parser to read the same bytes two ways.
    #[tokio::test]
    async fn vision_flow_with_a_udp_command_is_rejected() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), None).await;

        let addons = b"xtls-rprx-vision";
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(test_uuid().as_bytes());
        header.push(addons.len() as u8);
        header.extend_from_slice(addons);
        header.push(VLESS_CMD_UDP);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(VLESS_ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4]);

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&header).await.unwrap();
        let received = recv_for(&mut stream, Duration::from_millis(500)).await;
        assert!(
            received.is_empty(),
            "vision + UDP was answered with {received:02x?}"
        );
        assert_eq!(recorder.packets(), 0);
        assert_eq!(recorder.streams(), 0);
        inbound.stop().await.unwrap();
    }

    /// Control: the same addons with the TCP command are still accepted and
    /// reach the router as a TCP session (Vision interop must not regress).
    #[tokio::test]
    async fn vision_flow_with_a_tcp_command_is_dispatched() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), None).await;

        let addons = b"xtls-rprx-vision";
        let mut header = vec![VLESS_VERSION];
        header.extend_from_slice(test_uuid().as_bytes());
        header.push(addons.len() as u8);
        header.extend_from_slice(addons);
        header.push(VLESS_CMD_TCP);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(VLESS_ATYP_IPV4);
        header.extend_from_slice(&[1, 2, 3, 4]);

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&header).await.unwrap();

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VLESS_VERSION, 0x00]);
        assert!(wait_until(|| recorder.streams() == 1).await);
        inbound.stop().await.unwrap();
    }

    /// Control: a *TCP* request to the mux destination still enters smux (the
    /// compatibility property that must survive the fix above).
    #[tokio::test]
    async fn tcp_request_to_the_mux_destination_enters_smux() {
        let recorder = Recorder::new();
        let (inbound, addr) = spawn_inbound(recorder.clone(), Some(MuxConfig::default())).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(&domain_request(
                &test_uuid(),
                VLESS_CMD_TCP,
                444,
                MUX_DESTINATION_FQDN,
            ))
            .await
            .unwrap();

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VLESS_VERSION, 0x00]);

        // The session is handed to smux, which waits for a preface: no stream is
        // dispatched and the connection stays open.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(recorder.streams(), 0, "mux destination went to the router");
        assert_eq!(recorder.packets(), 0);

        let mut probe = [0u8; 1];
        let still_open = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut probe))
            .await
            .is_err();
        assert!(still_open, "the mux session was closed instead of served");
        inbound.stop().await.unwrap();
    }
}
