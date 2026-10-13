use async_trait::async_trait;
use flux_protocol::wireguard::{
    WG_DEFAULT_KEEPALIVE_SECS, WG_REKEY_AFTER_TIME_SECS, WireGuardConfig, WireGuardHandshake,
    WireGuardSession,
};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use futures_util::{Sink, Stream};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Inner IP MTU for the tunnel (1500 - 80 bytes of WG/UDP/IP overhead).
const WG_MTU: usize = 1420;
/// TCP connect timeout inside the tunnel.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared mutable WireGuard tunnel state (socket + current session).
#[derive(Default)]
struct WgState {
    socket: Option<Arc<UdpSocket>>,
    peer: Option<SocketAddr>,
    session: Option<Arc<Mutex<WireGuardSession>>>,
    established: Option<Instant>,
    last_sent: Option<Instant>,
    handshake_in_progress: bool,
}

/// A pending TCP connect request handled by the tunnel stack actor.
struct ConnectRequest {
    dst: SocketAddr,
    respond: oneshot::Sender<FluxResult<WgTcpStream>>,
}

/// Lazily-started embedded userspace TCP/IP stack (smoltcp, client mode).
struct StackState {
    frame_tx: mpsc::Sender<Vec<u8>>,
    connect_tx: mpsc::Sender<ConnectRequest>,
}

/// Shared tunnel core used by both stream and packet dialing.
///
/// Architecture: a single demultiplexing task owns all reads from the UDP socket.
/// Handshake responses are forwarded to the in-flight handshake waiter, UDP inner
/// packets to the owning packet endpoint (keyed by local tunnel address), and TCP
/// inner packets to the embedded smoltcp stack actor.
struct WgTunnel {
    config: WireGuardConfig,
    resolver: Arc<flux_dns::DnsResolver>,
    state: Mutex<WgState>,
    keepalive_started: AtomicBool,
    demux_started: AtomicBool,
    cancel: tokio_util::sync::CancellationToken,
    handshake_waiter: parking_lot::Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// Reply routing: local tunnel address (ip:port) → owning endpoint channel.
    udp_routes: dashmap::DashMap<SocketAddr, mpsc::Sender<UdpPacket>>,
    stack: Mutex<Option<StackState>>,
}

impl WgTunnel {
    fn new(config: WireGuardConfig, resolver: Arc<flux_dns::DnsResolver>) -> Self {
        Self {
            config,
            resolver,
            state: Mutex::new(WgState::default()),
            keepalive_started: AtomicBool::new(false),
            demux_started: AtomicBool::new(false),
            cancel: tokio_util::sync::CancellationToken::new(),
            handshake_waiter: parking_lot::Mutex::new(None),
            udp_routes: dashmap::DashMap::new(),
            stack: Mutex::new(None),
        }
    }

    fn stop(&self) {
        self.cancel.cancel();
    }

    fn local_v4(&self) -> Ipv4Addr {
        match self.config.local_address {
            Some(IpAddr::V4(v4)) => v4,
            _ => Ipv4Addr::new(10, 0, 0, 2),
        }
    }

    fn local_v6(&self) -> Ipv6Addr {
        match self.config.local_address {
            Some(IpAddr::V6(v6)) => v6,
            _ => Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        }
    }

    fn local_ip_for(&self, dst: IpAddr) -> IpAddr {
        match dst {
            IpAddr::V4(_) => IpAddr::V4(self.local_v4()),
            IpAddr::V6(_) => IpAddr::V6(self.local_v6()),
        }
    }

    /// Returns `(socket, peer, session)` when a fresh session exists.
    async fn current_session(
        &self,
    ) -> Option<(Arc<UdpSocket>, SocketAddr, Arc<Mutex<WireGuardSession>>)> {
        let g = self.state.lock().await;
        match (&g.socket, g.peer, &g.session, g.established) {
            (Some(s), Some(p), Some(sess), Some(est))
                if est.elapsed() < Duration::from_secs(WG_REKEY_AFTER_TIME_SECS) =>
            {
                Some((s.clone(), p, sess.clone()))
            }
            _ => None,
        }
    }

    /// Ensures the demultiplexing socket-reader task is running.
    /// Must be started before any handshake so responses are routed to the waiter.
    async fn ensure_demux(self: &Arc<Self>) -> FluxResult<()> {
        if self.demux_started.load(AtomicOrdering::Relaxed) {
            return Ok(());
        }
        // Resolve the peer early: the socket address family depends on it.
        let peer = self.resolver.resolve(&self.config.server_address).await?;

        {
            let mut guard = self.state.lock().await;
            if self.demux_started.load(AtomicOrdering::Relaxed) {
                return Ok(());
            }
            // Create/bind the UDP socket if missing or of the wrong family.
            let needs_socket = match &guard.socket {
                Some(s) => s
                    .local_addr()
                    .map(|a| a.is_ipv6() != peer.is_ipv6())
                    .unwrap_or(true),
                None => true,
            };
            if needs_socket {
                let bind_addr = if peer.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let s = match UdpSocket::bind(bind_addr).await {
                    Ok(s) => s,
                    Err(_) if peer.is_ipv6() => {
                        UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?
                    }
                    Err(e) => return Err(FluxError::Io(e)),
                };
                guard.socket = Some(Arc::new(s));
            }
            guard.peer = Some(peer);
        }

        self.demux_started.store(true, AtomicOrdering::Relaxed);
        let tunnel = self.clone();
        tokio::spawn(async move { tunnel.demux_loop().await });
        Ok(())
    }

    /// Single reader task for the tunnel UDP socket.
    async fn demux_loop(self: Arc<Self>) {
        let socket = match self.state.lock().await.socket.clone() {
            Some(s) => s,
            None => return,
        };
        let awg_h2 = self.config.awg.clone().unwrap_or_default().h2;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = tokio::select! {
                _ = self.cancel.cancelled() => break,
                res = socket.recv_from(&mut buf) => match res {
                    Ok((n, _)) => n,
                    Err(_) => break,
                },
            };
            let pkt = &buf[..n];
            if pkt.len() < 4 {
                continue;
            }
            let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);

            if msg_type == awg_h2 {
                // Handshake response: forward to the in-flight handshake, if any.
                let waiter = self.handshake_waiter.lock().clone();
                if let Some(tx) = waiter {
                    let _ = tx.try_send(pkt.to_vec());
                }
                continue;
            }

            // Data packet: decrypt with the current session.
            let session = match self.state.lock().await.session.clone() {
                Some(s) => s,
                None => continue,
            };
            let plain = {
                let mut sess = session.lock().await;
                match sess.decrypt_data_packet(pkt) {
                    Ok(p) => p,
                    Err(_) => continue, // corrupted / stale-session packet
                }
            };
            if plain.is_empty() {
                continue; // keepalive
            }
            let Some(parsed) = parse_ip_packet_meta(&plain) else {
                continue;
            };
            match parsed.proto {
                IpProto::Udp => {
                    // Replies are addressed to the local tunnel address.
                    if let Some(tx) = self.udp_routes.get(&parsed.dst) {
                        let _ = tx.try_send(UdpPacket::new(
                            parsed.payload,
                            TargetAddress::Ip(parsed.src),
                            TargetAddress::Ip(parsed.dst),
                        ));
                    }
                }
                IpProto::Tcp => {
                    let stack = self.stack.lock().await;
                    if let Some(st) = stack.as_ref() {
                        let _ = st.frame_tx.try_send(plain);
                    }
                }
            }
        }
    }

    /// Ensures a fresh session exists, performing a handshake if needed.
    /// Concurrent callers are serialized: only one handshake runs at a time.
    async fn ensure_session(
        self: &Arc<Self>,
    ) -> FluxResult<(Arc<UdpSocket>, SocketAddr, Arc<Mutex<WireGuardSession>>)> {
        self.ensure_demux().await?;

        if let Some(v) = self.current_session().await {
            return Ok(v);
        }

        {
            let mut guard = self.state.lock().await;
            if guard.handshake_in_progress {
                drop(guard);
                // Another task is handshaking; wait for it to finish.
                for _ in 0..200 {
                    if self.cancel.is_cancelled() {
                        return Err(FluxError::Network("wireguard tunnel stopped".into()));
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    if !self.state.lock().await.handshake_in_progress {
                        break;
                    }
                }
                return self.current_session().await.ok_or_else(|| {
                    FluxError::Timeout("wireguard concurrent handshake wait failed".into())
                });
            }
            guard.handshake_in_progress = true;
        }

        let result = self.perform_handshake().await;

        let mut guard = self.state.lock().await;
        guard.handshake_in_progress = false;
        match result {
            Ok(sess) => {
                guard.session = Some(sess.clone());
                guard.established = Some(Instant::now());
                let sock = guard.socket.clone().expect("demux guarantees socket");
                let peer = guard.peer.expect("demux guarantees peer");
                Ok((sock, peer, sess))
            }
            Err(e) => {
                // Drop the stale session so the next attempt starts clean.
                guard.session = None;
                guard.established = None;
                Err(e)
            }
        }
    }

    async fn perform_handshake(self: &Arc<Self>) -> FluxResult<Arc<Mutex<WireGuardSession>>> {
        let (socket, peer) = {
            let mut g = self.state.lock().await;
            match (g.socket.clone(), g.peer) {
                (Some(s), Some(p)) => {
                    // Re-resolve the peer on every (re)handshake to follow DNS changes;
                    // ignore the update when the address family no longer matches the socket.
                    if let Ok(fresh) = self.resolver.resolve(&self.config.server_address).await
                        && fresh.is_ipv6() == p.is_ipv6()
                        && fresh != p
                    {
                        g.peer = Some(fresh);
                        (s, fresh)
                    } else {
                        (s, p)
                    }
                }
                _ => {
                    return Err(FluxError::Network(
                        "wireguard socket not initialized".into(),
                    ));
                }
            }
        };

        let awg = self.config.awg.clone().unwrap_or_default();

        if awg.jc > 0 {
            let junk_packets = WireGuardHandshake::generate_junk_packets(&awg);
            for junk in junk_packets {
                let _ = socket.send_to(&junk, peer).await;
            }
        }

        let local_static = StaticSecret::from(self.config.private_key);
        let peer_pub = X25519PublicKey::from(self.config.peer_public_key);
        let sender_index = rand::random::<u32>();

        let (init_pkt, state) = WireGuardHandshake::create_initiation(
            &local_static,
            &peer_pub,
            sender_index,
            &awg,
            self.config.preshared_key,
        );

        // Register the response waiter BEFORE sending the initiation so the
        // demux task can route the response to us.
        let (htx, mut hrx) = mpsc::channel::<Vec<u8>>(4);
        {
            *self.handshake_waiter.lock() = Some(htx);
        }
        let waiter_guard = scopeguard(self);

        socket
            .send_to(&init_pkt, peer)
            .await
            .map_err(FluxError::Io)?;

        let resp_pkt = tokio::time::timeout(HANDSHAKE_TIMEOUT, hrx.recv())
            .await
            .map_err(|_| FluxError::Timeout("WireGuard handshake response timed out".into()))?
            .ok_or_else(|| FluxError::Network("wireguard handshake waiter closed".into()))?;
        drop(waiter_guard);

        let session = WireGuardHandshake::consume_response(state, &resp_pkt)?;
        Ok(Arc::new(Mutex::new(session)))
    }

    fn start_keepalive_task(self: &Arc<Self>) {
        if self.keepalive_started.swap(true, AtomicOrdering::Relaxed) {
            return;
        }
        let interval_secs = self
            .config
            .keepalive_secs
            .unwrap_or(WG_DEFAULT_KEEPALIVE_SECS);
        if interval_secs == 0 {
            return;
        }
        let interval = Duration::from_secs(interval_secs);
        let tunnel = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tunnel.cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
                let (sock, peer, sess, needs) = {
                    let g = tunnel.state.lock().await;
                    let needs = g.session.is_some()
                        && match g.last_sent {
                            Some(t) => t.elapsed() >= interval,
                            None => false,
                        };
                    (g.socket.clone(), g.peer, g.session.clone(), needs)
                };
                if !needs {
                    continue;
                }
                if let (Some(sock), Some(peer), Some(sess)) = (sock, peer, sess) {
                    // WireGuard keepalive: data packet with empty plaintext payload.
                    let pkt = {
                        let mut s = sess.lock().await;
                        match s.encrypt_data_packet(&[]) {
                            Ok(p) => p,
                            Err(_) => continue,
                        }
                    };
                    if sock.send_to(&pkt, peer).await.is_ok() {
                        tunnel.state.lock().await.last_sent = Some(Instant::now());
                    }
                }
            }
        });
    }

    /// Ensures the embedded smoltcp client stack actor is running.
    async fn ensure_stack(self: &Arc<Self>) -> FluxResult<()> {
        let mut guard = self.stack.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let (frame_tx, frame_rx) = mpsc::channel::<Vec<u8>>(2048);
        let (connect_tx, connect_rx) = mpsc::channel::<ConnectRequest>(64);
        *guard = Some(StackState {
            frame_tx,
            connect_tx,
        });
        let tunnel = self.clone();
        tokio::spawn(async move { tunnel.stack_actor(frame_rx, connect_rx).await });
        Ok(())
    }

    /// Opens a TCP connection through the tunnel via the embedded stack.
    async fn connect_tcp(self: &Arc<Self>, dst: SocketAddr) -> FluxResult<WgTcpStream> {
        self.ensure_stack().await?;
        let (tx, rx) = oneshot::channel();
        let req = ConnectRequest { dst, respond: tx };
        let connect_tx = {
            let guard = self.stack.lock().await;
            guard
                .as_ref()
                .expect("stack just started")
                .connect_tx
                .clone()
        };
        connect_tx
            .send(req)
            .await
            .map_err(|_| FluxError::Network("wireguard stack actor gone".into()))?;
        let mut stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, rx)
            .await
            .map_err(|_| FluxError::Timeout("wireguard stack connect timed out".into()))?
            .map_err(|_| FluxError::Network("wireguard stack actor dropped connect".into()))??;

        // Wait for the TCP handshake inside the tunnel to complete.
        let established = stream
            .established_rx
            .take()
            .expect("established_rx present on fresh stream");
        match tokio::time::timeout(TCP_CONNECT_TIMEOUT, established).await {
            Ok(Ok(Ok(()))) => Ok(stream),
            Ok(Ok(Err(e))) => Err(FluxError::Network(format!(
                "wireguard TCP connect to {} failed: {}",
                dst, e
            ))),
            Ok(Err(_)) => Err(FluxError::Network("wireguard stack actor gone".into())),
            Err(_) => Err(FluxError::Timeout(format!(
                "wireguard TCP connect to {} timed out",
                dst
            ))),
        }
    }

    /// The embedded userspace TCP stack actor (smoltcp, client mode).
    async fn stack_actor(
        self: Arc<Self>,
        mut frame_rx: mpsc::Receiver<Vec<u8>>,
        mut connect_rx: mpsc::Receiver<ConnectRequest>,
    ) {
        use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
        use smoltcp::socket::tcp;
        use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
        use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};

        let start = Instant::now();
        let mut device = QueueDevice {
            rxq: VecDeque::with_capacity(64),
            txq: VecDeque::with_capacity(64),
            mtu: WG_MTU,
        };
        let config = IfaceConfig::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(self.local_v4().into(), 32));
            let _ = addrs.push(IpCidr::new(self.local_v6().into(), 128));
        });
        // Point-to-point tunnel: default route via the tunnel peer.
        let gw4 = Ipv4Address::new(10, 0, 0, 1);
        let gw6 = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let _ = iface.routes_mut().add_default_ipv4_route(gw4);
        let _ = iface.routes_mut().add_default_ipv6_route(gw6);

        let mut sockets = SocketSet::new(vec![]);

        struct Conn {
            to_proxy: futures_channel::mpsc::Sender<bytes::Bytes>,
            pending_to_proxy: Option<bytes::Bytes>,
            pending_from_proxy: VecDeque<bytes::Bytes>,
            established_tx: Option<oneshot::Sender<Result<(), String>>>,
            dst: SocketAddr,
        }

        let (cmd_tx, mut cmd_rx) = futures_channel::mpsc::channel::<StackCmd>(4096);
        let mut conns: HashMap<SocketHandle, Conn> = HashMap::new();
        let mut next_ephemeral_port: u16 = 49152;

        // Items captured by the idle select arms below; `select!` consumes them,
        // so they must be stashed and processed on the next iteration.
        let mut pending_frame: Option<Vec<u8>> = None;
        let mut pending_connect: Option<ConnectRequest> = None;
        let mut pending_cmd: Option<StackCmd> = None;

        loop {
            // ---- 1. Inbound IP frames from the tunnel.
            let mut drained = 0;
            if let Some(f) = pending_frame.take() {
                device.rxq.push_back(f);
                drained += 1;
            }
            while drained < 512 {
                match frame_rx.try_recv() {
                    Ok(f) => {
                        device.rxq.push_back(f);
                        drained += 1;
                    }
                    Err(_) => break,
                }
            }

            // ---- 2. New connect requests.
            fn process_connect(
                req: ConnectRequest,
                iface: &mut Interface,
                sockets: &mut SocketSet,
                conns: &mut HashMap<SocketHandle, Conn>,
                next_ephemeral_port: &mut u16,
                cmd_tx: &futures_channel::mpsc::Sender<StackCmd>,
            ) {
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                    tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                );
                let local_port = *next_ephemeral_port;
                *next_ephemeral_port = next_ephemeral_port.wrapping_add(1).max(49152);
                let remote: IpEndpoint = IpEndpoint {
                    addr: req.dst.ip().into(),
                    port: req.dst.port(),
                };
                if let Err(e) = sock.connect(iface.context(), remote, local_port) {
                    let _ = req.respond.send(Err(FluxError::Network(format!(
                        "smoltcp connect failed: {}",
                        e
                    ))));
                    return;
                }
                let handle = sockets.add(sock);
                let (to_proxy_tx, to_proxy_rx) = futures_channel::mpsc::channel(128);
                let (est_tx, est_rx) = oneshot::channel();
                conns.insert(
                    handle,
                    Conn {
                        to_proxy: to_proxy_tx,
                        pending_to_proxy: None,
                        pending_from_proxy: VecDeque::new(),
                        established_tx: Some(est_tx),
                        dst: req.dst,
                    },
                );
                let stream = WgTcpStream {
                    handle,
                    cmd_tx: cmd_tx.clone(),
                    rx: to_proxy_rx,
                    leftover: None,
                    closed: false,
                    established_rx: Some(est_rx),
                };
                let _ = req.respond.send(Ok(stream));
            }

            if let Some(req) = pending_connect.take() {
                process_connect(
                    req,
                    &mut iface,
                    &mut sockets,
                    &mut conns,
                    &mut next_ephemeral_port,
                    &cmd_tx,
                );
            }
            while let Ok(req) = connect_rx.try_recv() {
                process_connect(
                    req,
                    &mut iface,
                    &mut sockets,
                    &mut conns,
                    &mut next_ephemeral_port,
                    &cmd_tx,
                );
            }

            // ---- 3. Proxy → socket commands.
            let mut cmds_done = 0;
            let mut next_cmd = pending_cmd.take();
            loop {
                let cmd = match next_cmd.take() {
                    Some(c) => Some(c),
                    None if cmds_done < 512 => cmd_rx.try_recv().ok(),
                    None => None,
                };
                let Some(cmd) = cmd else { break };
                cmds_done += 1;
                match cmd {
                    StackCmd::TcpData { handle, data } => {
                        if let Some(c) = conns.get_mut(&handle) {
                            c.pending_from_proxy.push_back(data);
                        }
                    }
                    StackCmd::TcpClose { handle } => {
                        if let Some(c) = conns.get_mut(&handle) {
                            c.pending_from_proxy.clear();
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            sock.close();
                        }
                    }
                }
            }

            // ---- 4. Flush proxy data into socket buffers.
            for (handle, conn) in conns.iter_mut() {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                while sock.can_send() {
                    let Some(chunk) = conn.pending_from_proxy.front_mut() else {
                        break;
                    };
                    match sock.send_slice(chunk) {
                        Ok(n) if n == chunk.len() => {
                            conn.pending_from_proxy.pop_front();
                        }
                        Ok(n) => {
                            bytes::Buf::advance(chunk, n);
                            break;
                        }
                        _ => break,
                    }
                }
            }

            // ---- 5. Poll the stack.
            let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(now, &mut device, &mut sockets);

            // ---- 6. Egress IP frames → encrypt → tunnel.
            while let Some(frame) = device.txq.pop_front() {
                let sess = match self.state.lock().await.session.clone() {
                    Some(s) => s,
                    None => continue,
                };
                let encrypted = {
                    let mut s = sess.lock().await;
                    match s.encrypt_data_packet(&frame) {
                        Ok(p) => p,
                        Err(_) => continue,
                    }
                };
                let (sock, peer) = {
                    let g = self.state.lock().await;
                    (g.socket.clone(), g.peer)
                };
                if let (Some(sock), Some(peer)) = (sock, peer)
                    && sock.send_to(&encrypted, peer).await.is_ok()
                {
                    self.state.lock().await.last_sent = Some(Instant::now());
                }
            }

            // ---- 7. Pump socket → proxy data; reap closed connections.
            let mut to_remove = Vec::new();
            for (handle, conn) in conns.iter_mut() {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);

                if let Some(est_tx) = conn.established_tx.take() {
                    match sock.state() {
                        tcp::State::Established => {
                            let _ = est_tx.send(Ok(()));
                        }
                        tcp::State::Closed => {
                            let _ = est_tx
                                .send(Err(format!("connection to {} refused/reset", conn.dst)));
                        }
                        _ => {
                            conn.established_tx = Some(est_tx);
                        }
                    }
                }

                if let Some(chunk) = conn.pending_to_proxy.take() {
                    match conn.to_proxy.try_send(chunk) {
                        Ok(()) => {}
                        Err(e) => conn.pending_to_proxy = Some(e.into_inner()),
                    }
                }
                if conn.pending_to_proxy.is_none() {
                    let mut tmp = [0u8; 8192];
                    while sock.can_recv() {
                        match sock.recv_slice(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => {
                                match conn
                                    .to_proxy
                                    .try_send(bytes::Bytes::copy_from_slice(&tmp[..n]))
                                {
                                    Ok(()) => {}
                                    Err(e) => {
                                        conn.pending_to_proxy = Some(e.into_inner());
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }

                // Reap only truly finished sockets. A client-side socket in SynSent
                // has may_recv/may_send == false — it must NOT be treated as dead.
                let finished = matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait)
                    && conn.pending_to_proxy.is_none()
                    && conn.pending_from_proxy.is_empty();
                if finished {
                    to_remove.push(*handle);
                }
            }
            for handle in to_remove {
                if let Some(conn) = conns.remove(&handle) {
                    if let Some(est_tx) = conn.established_tx {
                        let _ = est_tx.send(Err("connection closed before establishment".into()));
                    }
                    drop(conn.to_proxy); // EOF for the proxy task
                }
                sockets.remove(handle);
            }

            // ---- 8. Sleep until the next stack timer or new input arrives.
            let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
            let wait = iface
                .poll_delay(now, &sockets)
                .unwrap_or(SmolDuration::from_secs(60));
            let wait_std: std::time::Duration = wait.into();

            tokio::select! {
                _ = self.cancel.cancelled() => break,
                // select! consumes the item: stash it for the next iteration.
                f = frame_rx.recv() => { pending_frame = f; }
                c = connect_rx.recv() => { pending_connect = c; }
                c = futures_util::StreamExt::next(&mut cmd_rx) => { pending_cmd = c; }
                _ = tokio::time::sleep(wait_std) => {}
            }
        }
    }
}

/// RAII guard clearing the handshake waiter on early exit.
fn scopeguard(tunnel: &Arc<WgTunnel>) -> impl Drop {
    struct Guard(Arc<WgTunnel>);
    impl Drop for Guard {
        fn drop(&mut self) {
            *self.0.handshake_waiter.lock() = None;
        }
    }
    Guard(tunnel.clone())
}

/// Commands from stream tasks to the stack actor.
enum StackCmd {
    TcpData {
        handle: smoltcp::iface::SocketHandle,
        data: bytes::Bytes,
    },
    TcpClose {
        handle: smoltcp::iface::SocketHandle,
    },
}

/// Frame-queue device bridging smoltcp with the async tunnel tasks.
#[derive(Default)]
struct QueueDevice {
    rxq: VecDeque<Vec<u8>>,
    txq: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct QueueRxToken(Vec<u8>);
struct QueueTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::RxToken for QueueRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for QueueTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl smoltcp::phy::Device for QueueDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken<'a>;

    fn receive(
        &mut self,
        _ts: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rxq
            .pop_front()
            .map(|frame| (QueueRxToken(frame), QueueTxToken(&mut self.txq)))
    }

    fn transmit(&mut self, _ts: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken(&mut self.txq))
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// AsyncRead/AsyncWrite bridge between the proxy pipeline and a smoltcp TCP socket
/// inside the WireGuard tunnel.
pub struct WgTcpStream {
    handle: smoltcp::iface::SocketHandle,
    cmd_tx: futures_channel::mpsc::Sender<StackCmd>,
    rx: futures_channel::mpsc::Receiver<bytes::Bytes>,
    leftover: Option<bytes::Bytes>,
    closed: bool,
    established_rx: Option<oneshot::Receiver<Result<(), String>>>,
}

impl tokio::io::AsyncRead for WgTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(left) = &mut self.leftover {
            let n = left.len().min(buf.remaining());
            buf.put_slice(&left[..n]);
            if n == left.len() {
                self.leftover = None;
            } else {
                *left = left.split_off(n);
            }
            return std::task::Poll::Ready(Ok(()));
        }
        match std::pin::Pin::new(&mut self.rx).poll_next(cx) {
            std::task::Poll::Ready(Some(bytes)) => {
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..n]);
                if n < bytes.len() {
                    self.leftover = Some(bytes.slice(n..));
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())), // EOF
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for WgTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.closed {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wireguard tunnel connection closed",
            )));
        }
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        match std::pin::Pin::new(&mut this.cmd_tx).poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => {
                let item = StackCmd::TcpData {
                    handle: this.handle,
                    data: bytes::Bytes::copy_from_slice(buf),
                };
                match std::pin::Pin::new(&mut this.cmd_tx).start_send(item) {
                    Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
                    Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("stack actor gone: {}", e),
                    ))),
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("stack actor gone: {}", e),
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.cmd_tx)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.closed {
            self.closed = true;
            let handle = self.handle;
            let _ = std::pin::Pin::new(&mut self.cmd_tx).start_send(StackCmd::TcpClose { handle });
        }
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.cmd_tx)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.cmd_tx.try_send(StackCmd::TcpClose {
                handle: self.handle,
            });
        }
    }
}

pub struct WireGuardOutbound {
    tag: String,
    tunnel: Arc<WgTunnel>,
}

impl WireGuardOutbound {
    pub fn new(
        tag: impl Into<String>,
        config: WireGuardConfig,
        resolver: Arc<flux_dns::DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            tunnel: Arc::new(WgTunnel::new(config, resolver)),
        }
    }
}

#[async_trait]
impl Outbound for WireGuardOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "wireguard"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        self.tunnel.start_keepalive_task();
        self.tunnel.ensure_session().await?;
        // A domain destination must be resolved here: WireGuard transports L3 IP
        // packets, and the inner IP header needs a concrete address.
        let dst = self.tunnel.resolver.resolve(&meta.destination).await?;
        let stream = self.tunnel.connect_tcp(dst).await?;
        Ok(Box::new(stream))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        self.tunnel.start_keepalive_task();
        self.tunnel.ensure_session().await?;

        // Resolve once for the local address family; per-packet destinations are
        // resolved individually in send_packet.
        let dst_addr = self.tunnel.resolver.resolve(&meta.destination).await?;
        let src_ip = self.tunnel.local_ip_for(dst_addr.ip());
        let local_addr = SocketAddr::new(src_ip, meta.source.port());

        // Register the reply route: inner packets addressed to our local tunnel
        // address are demultiplexed into this endpoint's channel.
        let (tx, rx) = mpsc::channel::<UdpPacket>(256);
        self.tunnel.udp_routes.insert(local_addr, tx);

        Ok(Box::new(WireGuardPacketEndpoint {
            tunnel: self.tunnel.clone(),
            local: local_addr,
            rx: Mutex::new(rx),
        }))
    }

    fn stop(&self) {
        self.tunnel.stop();
    }
}

pub struct WireGuardPacketEndpoint {
    tunnel: Arc<WgTunnel>,
    /// Local tunnel address (ip:port) used as inner source.
    local: SocketAddr,
    rx: Mutex<mpsc::Receiver<UdpPacket>>,
}

impl Drop for WireGuardPacketEndpoint {
    fn drop(&mut self) {
        // Unregister the demux route so replies are not delivered to a dead endpoint.
        self.tunnel.udp_routes.remove(&self.local);
    }
}

#[async_trait]
impl PacketEndpoint for WireGuardPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        // Transparent rekey when REKEY_AFTER_TIME expired.
        let (socket, peer, session) = self.tunnel.ensure_session().await?;

        // Per-packet destination resolution: one endpoint serves every destination
        // of the owning UDP session (the dispatcher shares endpoints per outbound).
        let dst = match &packet.destination {
            TargetAddress::Ip(addr) => *addr,
            TargetAddress::Domain(..) => self.tunnel.resolver.resolve(&packet.destination).await?,
        };

        // Encapsulate the UDP payload into an inner IP packet — real WireGuard
        // peers route IP datagrams, not bare UDP payloads.
        let ip_pkt = build_ip_udp_packet(self.local.ip(), dst, self.local.port(), &packet.payload)
            .ok_or_else(|| {
                FluxError::InvalidAddress(format!(
                    "cannot encapsulate UDP packet to {} into an IP datagram",
                    dst
                ))
            })?;

        let encrypted = {
            let mut s = session.lock().await;
            s.encrypt_data_packet(&ip_pkt)?
        };
        socket
            .send_to(&encrypted, peer)
            .await
            .map_err(FluxError::Io)?;

        self.tunnel.state.lock().await.last_sent = Some(Instant::now());
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| FluxError::Network("wireguard tunnel closed for UDP endpoint".into()))
    }
}

// ---------------------------------------------------------------------------
// Inner IP datagram helpers (WireGuard tunnels L3 packets)
// ---------------------------------------------------------------------------

enum IpProto {
    Tcp,
    Udp,
}

struct ParsedIp {
    src: SocketAddr,
    dst: SocketAddr,
    proto: IpProto,
    payload: bytes::Bytes,
}

/// Minimal IP packet classification for the tunnel demux (TCP vs UDP).
fn parse_ip_packet_meta(pkt: &[u8]) -> Option<ParsedIp> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = (usize::from(pkt[0] & 0x0f)) * 4;
            if pkt.len() < ihl {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
            let actual = pkt.len().min(total_len);
            if actual < ihl {
                return None;
            }
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            match pkt[9] {
                6 => {
                    if actual < ihl + 20 {
                        return None;
                    }
                    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    Some(ParsedIp {
                        src: SocketAddr::new(IpAddr::V4(src), sport),
                        dst: SocketAddr::new(IpAddr::V4(dst), dport),
                        proto: IpProto::Tcp,
                        payload: bytes::Bytes::new(),
                    })
                }
                17 => {
                    if actual < ihl + 8 {
                        return None;
                    }
                    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    let ulen = usize::from(u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]));
                    if ulen < 8 || actual < ihl + ulen {
                        return None;
                    }
                    Some(ParsedIp {
                        src: SocketAddr::new(IpAddr::V4(src), sport),
                        dst: SocketAddr::new(IpAddr::V4(dst), dport),
                        proto: IpProto::Udp,
                        payload: bytes::Bytes::copy_from_slice(&pkt[ihl + 8..ihl + ulen]),
                    })
                }
                _ => None,
            }
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            if pkt.len() < 40 + plen {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            match pkt[6] {
                6 => {
                    if plen < 20 {
                        return None;
                    }
                    let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
                    let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
                    Some(ParsedIp {
                        src: SocketAddr::new(IpAddr::V6(src), sport),
                        dst: SocketAddr::new(IpAddr::V6(dst), dport),
                        proto: IpProto::Tcp,
                        payload: bytes::Bytes::new(),
                    })
                }
                17 => {
                    if plen < 8 {
                        return None;
                    }
                    let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
                    let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
                    let ulen = usize::from(u16::from_be_bytes([pkt[44], pkt[45]]));
                    if ulen < 8 || plen < ulen {
                        return None;
                    }
                    Some(ParsedIp {
                        src: SocketAddr::new(IpAddr::V6(src), sport),
                        dst: SocketAddr::new(IpAddr::V6(dst), dport),
                        proto: IpProto::Udp,
                        payload: bytes::Bytes::copy_from_slice(&pkt[48..40 + ulen]),
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum_pseudo(src_octets: &[u8], dst_octets: &[u8], udp: &mut [u8], zero_allowed: bool) {
    udp[6] = 0;
    udp[7] = 0;
    let mut sum: u32 = 0;
    for b in src_octets.chunks(2).chain(dst_octets.chunks(2)) {
        sum += u32::from(u16::from_be_bytes([b[0], b[1]]));
    }
    sum += 17u32; // protocol UDP
    sum += udp.len() as u32;
    for chunk in udp.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let mut c = !(sum as u16);
    if c == 0 && zero_allowed {
        c = 0xffff; // RFC 768: computed zero checksum transmitted as all-ones
    }
    udp[6..8].copy_from_slice(&c.to_be_bytes());
}

/// Builds an IPv4/IPv6 packet carrying a UDP datagram from `src_ip:src_port` to `dst`.
fn build_ip_udp_packet(
    src_ip: IpAddr,
    dst: SocketAddr,
    src_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    match (src_ip, dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total_len = 20 + 8 + payload.len();
            let mut buf = vec![0u8; total_len];
            buf[0] = 0x45;
            buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[6] = 0x40; // DF
            buf[8] = 64; // TTL
            buf[9] = 17; // UDP
            buf[12..16].copy_from_slice(&s.octets());
            buf[16..20].copy_from_slice(&d.octets());
            let csum = ip_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&csum.to_be_bytes());

            let udp = &mut buf[20..];
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
            udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            udp[8..].copy_from_slice(payload);
            udp_checksum_pseudo(&s.octets(), &d.octets(), udp, true);
            Some(buf)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let total_len = 40 + 8 + payload.len();
            let mut buf = vec![0u8; total_len];
            buf[0] = 0x60;
            buf[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            buf[6] = 17; // next header UDP
            buf[7] = 64; // hop limit
            buf[8..24].copy_from_slice(&s.octets());
            buf[24..40].copy_from_slice(&d.octets());

            let udp = &mut buf[40..];
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
            udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            udp[8..].copy_from_slice(payload);
            udp_checksum_pseudo(&s.octets(), &d.octets(), udp, true);
            Some(buf)
        }
        _ => None,
    }
}

/// Parses an inner IP packet and extracts (src, dst, UDP payload).
#[cfg(test)]
fn parse_ip_udp_packet(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    parse_ip_packet_meta(pkt).and_then(|p| match p.proto {
        IpProto::Udp => Some((p.src, p.dst, p.payload.to_vec())),
        IpProto::Tcp => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_ipv4_udp_roundtrip() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let payload = b"\x12\x34dns-query";
        let pkt = build_ip_udp_packet(src, dst, 5353, payload).unwrap();

        // Verify IPv4 header checksum
        assert_eq!(ip_checksum(&pkt[..20]), 0);

        let (psrc, pdst, ppayload) = parse_ip_udp_packet(&pkt).unwrap();
        assert_eq!(psrc, "10.0.0.2:5353".parse().unwrap());
        assert_eq!(pdst, dst);
        assert_eq!(ppayload, payload);

        // Verify UDP checksum
        let mut udp = pkt[20..].to_vec();
        let csum = u16::from_be_bytes([udp[6], udp[7]]);
        assert_ne!(csum, 0);
        // recompute over the same data must yield zero when checksum included
        let mut sum: u32 = 0;
        for b in [10, 0, 0, 2].chunks(2).chain([8, 8, 8, 8].chunks(2)) {
            sum += u32::from(u16::from_be_bytes([b[0], b[1]]));
        }
        sum += 17 + udp.len() as u32;
        for chunk in udp.chunks(2) {
            let w = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(w);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
        udp.clear();
    }

    #[test]
    fn test_build_and_parse_ipv6_udp_roundtrip() {
        let src = IpAddr::V6("fd00::2".parse().unwrap());
        let dst: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        let payload = b"hello-v6";
        let pkt = build_ip_udp_packet(src, dst, 1234, payload).unwrap();
        let (psrc, pdst, ppayload) = parse_ip_udp_packet(&pkt).unwrap();
        assert_eq!(psrc, "[fd00::2]:1234".parse().unwrap());
        assert_eq!(pdst, dst);
        assert_eq!(ppayload, payload);
    }

    #[test]
    fn test_parse_ip_packet_meta_tcp_v4() {
        // Minimal IPv4 TCP SYN packet
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&1234u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        let meta = parse_ip_packet_meta(&pkt).unwrap();
        assert!(matches!(meta.proto, IpProto::Tcp));
        assert_eq!(meta.src, "10.0.0.1:1234".parse().unwrap());
        assert_eq!(meta.dst, "10.0.0.2:80".parse().unwrap());
    }
}
