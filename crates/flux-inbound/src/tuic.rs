use async_trait::async_trait;
use dashmap::DashMap;
use flux_protocol::tuic::{
    TUIC_AUTH_LEN, TUIC_CMD_AUTHENTICATE, TUIC_CMD_CONNECT, TUIC_CMD_DISSOCIATE,
    TUIC_CMD_HEARTBEAT, TUIC_STREAM_AUTH_LEN, TUIC_VERSION, TuicV5Protocol,
};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncReadExt;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};

/// Absolute budget for the TUIC stream-mode handshake (transport unwrap + AUTH +
/// CONNECT header). Matches the 10 s used by the other TCP inbounds.
const TUIC_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TUIC address types. These are the protocol's own values (0 = domain,
/// 1 = IPv4, 2 = IPv6), *not* the SOCKS5 ones.
const TUIC_ATYP_DOMAIN: u8 = 0x00;
const TUIC_ATYP_IPV4: u8 = 0x01;
const TUIC_ATYP_IPV6: u8 = 0x02;

/// Longest possible CONNECT header: version + command + ATYP + a 255-byte
/// domain + a 2-byte port.
const TUIC_MAX_HEADER_LEN: usize = 4 + 255 + 2;

/// Largest UDP datagram we are willing to parse out of one QUIC datagram frame.
///
/// The QUIC layer will happily hand us datagrams up to the receive buffer size
/// (4 MiB in `flux_transport::quic`), which is far above any UDP payload that
/// can legitimately appear here. Everything beyond a jumbo frame is dropped
/// before it is parsed or copied.
pub(crate) const MAX_UDP_DATAGRAM: usize = 4096;

/// Hard cap on live UDP associations per QUIC connection.
///
/// Association state is keyed on a client-supplied id and holds a channel plus
/// two tasks, so an authenticated client that keeps opening associations with
/// fresh ids could otherwise grow it without bound.
const TUIC_MAX_UDP_SESSIONS: usize = 256;

/// Upper bound on remembered stream-AUTH tokens.
const TUIC_SEEN_TOKEN_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// Testable core
//
// Everything in this section is a pure function or a small self-contained
// state machine: no QUIC, no sockets, no tasks. The `Inbound::start` body is
// then a thin wire-up, which is the only way any of this can be tested without
// standing up a full QUIC peer.
// ---------------------------------------------------------------------------

/// Why a bounded read gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// The peer closed the stream (or the transport died) mid-frame.
    Eof,
    /// The handshake deadline passed with the frame still incomplete.
    Timeout,
    /// The bytes read so far can never form a valid frame.
    Invalid(&'static str),
}

/// Incremental parse result for a length-prefixed request header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderParse {
    /// A complete header; the address it carried.
    Complete(TargetAddress),
    /// Not enough bytes yet. The total number of header bytes required, which
    /// is always bounded by the caller's buffer.
    NeedMore(usize),
    /// The header can never be valid, whatever follows it.
    Invalid(&'static str),
}

/// Reads exactly `buf.len()` bytes, giving up at `deadline`.
pub(crate) async fn read_exact_until<S>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<(), ReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout_at(deadline, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Err(ReadError::Eof),
        Err(_) => Err(ReadError::Timeout),
    }
}

/// Parses a TUIC CONNECT header: `[version, command, address]`.
///
/// The address is parsed from the bytes at hand, incrementally: the caller
/// hands in whatever it has buffered and gets back either a complete address,
/// the number of bytes still needed, or a definitive rejection. A declared
/// domain length always resolves to a bounded total, so no client-controlled
/// value can drive an allocation here.
pub(crate) fn parse_connect_header(buf: &[u8]) -> HeaderParse {
    if buf.is_empty() {
        return HeaderParse::NeedMore(1);
    }
    if buf[0] != TUIC_VERSION {
        return HeaderParse::Invalid("unsupported TUIC version");
    }
    if buf.len() < 2 {
        return HeaderParse::NeedMore(2);
    }
    if buf[1] != TUIC_CMD_CONNECT {
        return HeaderParse::Invalid("expected a CONNECT command");
    }
    let atyp = match buf.get(2) {
        Some(a) => *a,
        None => return HeaderParse::NeedMore(3),
    };
    let total = match atyp {
        TUIC_ATYP_DOMAIN => {
            let dlen = match buf.get(3) {
                Some(l) => *l as usize,
                None => return HeaderParse::NeedMore(4),
            };
            if dlen == 0 {
                return HeaderParse::Invalid("empty domain");
            }
            4 + dlen + 2
        }
        TUIC_ATYP_IPV4 => 3 + 4 + 2,
        TUIC_ATYP_IPV6 => 3 + 16 + 2,
        _ => return HeaderParse::Invalid("unknown address type"),
    };
    debug_assert!(total <= TUIC_MAX_HEADER_LEN);
    if buf.len() < total {
        return HeaderParse::NeedMore(total);
    }
    match TuicV5Protocol::decode_address(&buf[2..total]) {
        Ok((addr, used)) if used == total - 2 => HeaderParse::Complete(addr),
        // `decode_address` accepted fewer bytes than the header declared: the
        // two disagree, so treat the frame as malformed rather than resyncing.
        _ => HeaderParse::Invalid("malformed address"),
    }
}

/// Reads a CONNECT header from `stream` without ever reading one byte past it
/// (the payload follows immediately on the same stream) and without allocating.
pub(crate) async fn read_connect_header<S>(
    stream: &mut S,
    deadline: tokio::time::Instant,
) -> Result<TargetAddress, ReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; TUIC_MAX_HEADER_LEN];
    let mut have = 0usize;
    loop {
        match parse_connect_header(&buf[..have]) {
            HeaderParse::Complete(addr) => return Ok(addr),
            HeaderParse::Invalid(reason) => return Err(ReadError::Invalid(reason)),
            HeaderParse::NeedMore(needed) => {
                if needed > buf.len() || needed <= have {
                    return Err(ReadError::Invalid("header length out of range"));
                }
                read_exact_until(stream, &mut buf[have..needed], deadline).await?;
                have = needed;
            }
        }
    }
}

/// Connection-level authentication state.
///
/// A TUIC connection authenticates out-of-band, on a unidirectional stream that
/// races the streams and datagrams that need it. This type holds that race:
/// nothing keyed on client input may be parsed or allocated until `is_ok()`,
/// and a connection that never authenticates gives up at `deadline` instead of
/// parking a task forever.
pub(crate) struct ConnAuth {
    ok: AtomicBool,
    /// Which user the connection authenticated as, once it has.
    identity: parking_lot::Mutex<Option<uuid::Uuid>>,
    deadline: tokio::time::Instant,
    notify: tokio::sync::Notify,
}

impl ConnAuth {
    pub(crate) fn new(deadline: tokio::time::Instant) -> Arc<Self> {
        Arc::new(Self {
            ok: AtomicBool::new(false),
            identity: parking_lot::Mutex::new(None),
            deadline,
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Records a verified AUTH frame. Idempotent: a second valid AUTH frame on
    /// another stream keeps the connection authenticated, and cannot change the
    /// identity the first one established.
    pub(crate) fn mark_ok(&self, identity: Option<uuid::Uuid>) {
        {
            let mut slot = self.identity.lock();
            if slot.is_none() {
                *slot = identity;
            }
        }
        self.ok.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// The authenticated user, if the connection had one.
    ///
    /// Several UUIDs may share this inbound's password, so the identity is the
    /// only thing that distinguishes them. It used to be discarded, which left
    /// every stream of a multi-user inbound anonymous to the dispatcher.
    pub(crate) fn user(&self) -> Option<uuid::Uuid> {
        *self.identity.lock()
    }

    pub(crate) fn is_ok(&self) -> bool {
        self.ok.load(Ordering::SeqCst)
    }

    /// Waits for authentication up to the connection deadline.
    ///
    /// Returns `true` if the connection became authenticated, `false` if the
    /// deadline passed first.
    pub(crate) async fn wait_ok(&self) -> bool {
        loop {
            if self.is_ok() {
                return true;
            }
            // Register for the notification *before* re-checking, then wait:
            // `notify_waiters` only wakes already-registered waiters, so the
            // re-check after `notified()` would otherwise race a missed wakeup.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_ok() {
                return true;
            }
            if tokio::time::timeout_at(self.deadline, notified)
                .await
                .is_err()
            {
                return self.is_ok();
            }
        }
    }
}

/// Outcome of [`UdpAssocTable::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenResult {
    /// A new association slot was taken.
    Inserted,
    /// The id was already registered; the caller's sender was not installed.
    Exists,
    /// The table is at its cap: the caller must drop the packet.
    AtCapacity,
}

/// Per-connection table of UDP associations.
///
/// Shared by the TUIC and Hysteria 2 inbounds, because both key association
/// state on a client-supplied id and both must (a) refuse to grow past a cap
/// and (b) give the slot back when the association ends. Losing (b) is the
/// leak shape this project has already hit twice: the map entry survives its
/// dispatcher, so every dead association keeps a channel and its id forever.
pub(crate) struct UdpAssocTable<K: Eq + std::hash::Hash + Copy> {
    max: usize,
    entries: DashMap<K, tokio::sync::mpsc::Sender<UdpPacket>>,
}

impl<K: Eq + std::hash::Hash + Copy> UdpAssocTable<K> {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            entries: DashMap::new(),
        })
    }

    /// Looks up an association and clones its sender.
    ///
    /// The map guard is released before returning, so callers may remove the
    /// entry (or send) without risking a deadlock against a shard lock.
    pub(crate) fn get(&self, key: &K) -> Option<tokio::sync::mpsc::Sender<UdpPacket>> {
        self.entries.get(key).map(|tx| tx.clone())
    }

    /// Claims a slot for `key`. Never grows the table past its cap.
    pub(crate) fn open(&self, key: K, tx: tokio::sync::mpsc::Sender<UdpPacket>) -> OpenResult {
        if self.entries.contains_key(&key) {
            return OpenResult::Exists;
        }
        if self.len() >= self.max {
            return OpenResult::AtCapacity;
        }
        match self.entries.insert(key, tx) {
            None => OpenResult::Inserted,
            Some(_) => OpenResult::Exists,
        }
    }

    /// Releases a slot. Returns whether anything was there.
    pub(crate) fn remove(&self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Membership test over the configured user list.
///
/// Scans the whole list instead of stopping at the match: the loop bound must
/// not depend on the position of the entry, or the time to answer tells a
/// prober which UUIDs exist here. An empty list means "any UUID is acceptable".
pub(crate) fn user_exists(users: &[uuid::Uuid], uuid: &uuid::Uuid) -> bool {
    let mut found = users.is_empty();
    for candidate in users {
        found |= candidate == uuid;
    }
    found
}

/// Verifies a timestamped stream-mode AUTH frame.
///
/// Order matters. The token is checked first, because it is bound to the UUID:
/// an unknown UUID can never produce a matching token, so checking the user
/// list first would only turn the reply order into an oracle for which UUIDs
/// exist here. The token comparison is constant-time; the replay insert happens
/// only after both checks pass, so a forged frame cannot burn a legitimate
/// `(uuid, timestamp)` slot.
pub(crate) fn authenticate_stream_frame(
    frame: &[u8],
    users: &[uuid::Uuid],
    password: &str,
    seen: &DashMap<([u8; 16], u64), ()>,
) -> Result<uuid::Uuid, &'static str> {
    let (uuid, ts, token) =
        TuicV5Protocol::parse_stream_auth_frame(frame).map_err(|_| "malformed AUTH frame")?;

    let expected = TuicV5Protocol::stream_token(&uuid, password, ts);
    if !flux_common::constant_time_eq(&token, &expected) {
        return Err("token mismatch");
    }
    if !TuicV5Protocol::stream_token_fresh(ts) {
        return Err("timestamp outside the accepted window");
    }
    if !user_exists(users, &uuid) {
        return Err("unknown user");
    }
    if seen.contains_key(&(*uuid.as_bytes(), ts)) {
        return Err("replayed AUTH frame");
    }
    seen.insert((*uuid.as_bytes(), ts), ());
    if seen.len() > TUIC_SEEN_TOKEN_CAPACITY {
        // Drop the oldest half rather than flushing everything: a scan must not
        // reopen a window for tokens already seen this second. Collect first —
        // removing while a `DashMap` iterator holds a shard lock would deadlock.
        let drop_count = seen.len() / 2;
        let keys: Vec<_> = seen.iter().take(drop_count).map(|e| *e.key()).collect();
        for k in keys {
            seen.remove(&k);
        }
    }
    Ok(uuid)
}

/// Parses a PACKET frame after refusing anything larger than a jumbo frame.
pub(crate) fn parse_udp_datagram(
    datagram: &[u8],
) -> Result<(u16, u16, TargetAddress, Vec<u8>), FluxError> {
    if datagram.len() > MAX_UDP_DATAGRAM {
        return Err(FluxError::Protocol {
            protocol: "tuic5",
            message: format!(
                "PACKET frame of {} bytes exceeds the {MAX_UDP_DATAGRAM}-byte limit",
                datagram.len()
            ),
        });
    }
    TuicV5Protocol::parse_packet_frame(datagram)
}

/// Size of the PACKET frame that would carry `payload_len` bytes of UDP to
/// `target`, mirroring `TuicV5Protocol::build_packet_frame`.
///
/// Used to drop a reply *before* framing it: the frame's length field is a
/// `u16`, so a payload over 65535 bytes would silently wrap, and a frame over
/// the connection's datagram limit is refused by the transport anyway.
pub(crate) fn packet_frame_len(target: &TargetAddress, payload_len: usize) -> usize {
    let addr_len = match target {
        TargetAddress::Ip(SocketAddr::V4(_)) => 1 + 4 + 2,
        TargetAddress::Ip(SocketAddr::V6(_)) => 1 + 16 + 2,
        TargetAddress::Domain(domain, _) => 1 + 1 + domain.len() + 2,
    };
    // version + command + session id + packet id + frag total + frag id + len
    10 + addr_len + payload_len
}

/// TUIC v5 inbound (QUIC-native, spec-compatible with sing-box).
pub struct TuicInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<uuid::Uuid>,
    password: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pipeline: Option<flux_transport::pipeline::ServerTransportPipeline>,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
}

impl TuicInbound {
    /// A listener named `tag` on `listen_addr` with these credentials.
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        users: Vec<uuid::Uuid>,
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
            tasks: crate::InboundTasks::new(),
        }
    }

    /// Rejects sessions above the limiter.
    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    /// A listener whose QUIC transport is pre-built from configuration.
    pub fn new_with_pipeline(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        users: Vec<uuid::Uuid>,
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
            tasks: crate::InboundTasks::new(),
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
        // ---- Layered mode (TUIC frames over an arbitrary stream transport)
        if let Some(pipe) = self.pipeline.clone() {
            let listener = crate::create_reuse_port_listener(self.listen_addr)?;
            self.running.store(true, Ordering::SeqCst);
            let tag: Arc<str> = Arc::from(self.tag.as_str());
            let users = Arc::new(self.users.clone());
            let password = Arc::new(self.password.clone());
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            // Timestamped AUTH frames are replayable for the whole freshness
            // window unless the server remembers which ones it has already
            // accepted. Bounded so a flood of distinct timestamps cannot grow it.
            let seen_tokens: Arc<dashmap::DashMap<([u8; 16], u64), ()>> =
                Arc::new(dashmap::DashMap::new());

            info!(
                "[{}] TUIC v5 Stream/TCP inbound listening on {}",
                tag, self.listen_addr
            );

            self.tasks.spawn(async move {
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
                    let seen = seen_tokens.clone();

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

                        // Everything below must complete inside one absolute
                        // handshake budget: without it a client that connects and
                        // then sends nothing (slow-loris) parks this task and its
                        // descriptors forever. `timeout_at` keeps the budget
                        // absolute rather than per-read.
                        let deadline = tokio::time::Instant::now() + TUIC_HANDSHAKE_TIMEOUT;

                        // Layered mode: timestamped AUTH frame then CONNECT frame.
                        let mut auth_buf = [0u8; TUIC_STREAM_AUTH_LEN];
                        if let Err(e) = read_exact_until(&mut stream, &mut auth_buf, deadline).await
                        {
                            debug!(
                                "[{}] TUIC stream auth frame from {} unreadable: {:?}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        // Authentication happens before a single byte of the
                        // target address is looked at.
                        let uuid =
                            match authenticate_stream_frame(&auth_buf, &user_list, &pw, &seen) {
                                Ok(uuid) => uuid,
                                Err(reason) => {
                                    warn!(
                                        "[{}] TUIC stream auth from {} rejected: {}",
                                        inbound_tag, client_addr, reason
                                    );
                                    return;
                                }
                            };

                        let target_addr = match read_connect_header(&mut stream, deadline).await {
                            Ok(addr) => addr,
                            Err(e) => {
                                debug!(
                                    "[{}] TUIC CONNECT from {} rejected: {:?}",
                                    inbound_tag, client_addr, e
                                );
                                return;
                            }
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

        self.tasks.spawn(async move {
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
                    let auth = ConnAuth::new(tokio::time::Instant::now() + TUIC_HANDSHAKE_TIMEOUT);

                    // UDP sessions: session_id → dispatcher packet channel
                    let udp_sessions: Arc<UdpAssocTable<u16>> =
                        UdpAssocTable::new(TUIC_MAX_UDP_SESSIONS);

                    // A connection that never authenticates must not hold a task
                    // and a live QUIC connection indefinitely. Close it when the
                    // handshake budget runs out; the client can reconnect.
                    {
                        let auth_wd = auth.clone();
                        let conn_wd = conn.clone();
                        let tag_wd = inbound_tag.clone();
                        tokio::spawn(async move {
                            if !auth_wd.wait_ok().await {
                                debug!(
                                    "[{}] TUIC connection from {} closed: no AUTH within the handshake budget",
                                    tag_wd,
                                    conn_wd.remote_address()
                                );
                                conn_wd.close(0u32.into(), b"tuic auth timeout");
                            }
                        });
                    }

                    // Task 1: unidirectional streams (AUTHENTICATE, DISSOCIATE)
                    {
                        let conn_c = conn.clone();
                        let tag_c = inbound_tag.clone();
                        let users_c = user_list.clone();
                        let pw_c = pw.clone();
                        let auth_c = auth.clone();
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
                                    // A unidirectional stream that never sends its
                                    // frame must not park this task either.
                                    let deadline =
                                        tokio::time::Instant::now() + TUIC_HANDSHAKE_TIMEOUT;
                                    let mut hdr = [0u8; 2];
                                    if read_exact_until(&mut recv, &mut hdr, deadline)
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                    if hdr[0] != TUIC_VERSION {
                                        return;
                                    }
                                    match hdr[1] {
                                        TUIC_CMD_AUTHENTICATE => {
                                            let mut rest = [0u8; 16 + 32];
                                            if read_exact_until(&mut recv, &mut rest, deadline)
                                                .await
                                                .is_err()
                                            {
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
                                            // Token first, then the user list: the
                                            // token is derived from the UUID, so an
                                            // unknown UUID can never pass, and the
                                            // order stops the reply from telling a
                                            // prober which UUIDs exist here.
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
                                            if !flux_common::constant_time_eq(&token, &expected) {
                                                warn!(
                                                    "[{}] TUIC token mismatch from {}",
                                                    tag2,
                                                    conn2.remote_address()
                                                );
                                                return;
                                            }
                                            if !user_exists(&users2, &uuid) {
                                                warn!(
                                                    "[{}] TUIC unknown uuid from {}",
                                                    tag2,
                                                    conn2.remote_address()
                                                );
                                                return;
                                            }
                                            auth2.mark_ok(Some(uuid));
                                            debug!(
                                                "[{}] TUIC authenticated {} from {}",
                                                tag2,
                                                uuid,
                                                conn2.remote_address()
                                            );
                                        }
                                        TUIC_CMD_DISSOCIATE => {
                                            // Only an authenticated connection may
                                            // tear an association down.
                                            if !auth2.is_ok() {
                                                return;
                                            }
                                            let mut sid = [0u8; 2];
                                            if read_exact_until(&mut recv, &mut sid, deadline)
                                                .await
                                                .is_ok()
                                            {
                                                let session_id = u16::from_be_bytes(sid);
                                                if sessions2.remove(&session_id) {
                                                    debug!(
                                                        "[{}] TUIC UDP session {} dissociated",
                                                        tag2, session_id
                                                    );
                                                }
                                            }
                                        }
                                        TUIC_CMD_HEARTBEAT => {}
                                        other => {
                                            debug!(
                                                "[{}] TUIC unknown unidirectional command {:#04x}",
                                                tag2, other
                                            );
                                        }
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
                        let auth_c = auth.clone();
                        let sessions_c = udp_sessions.clone();
                        tokio::spawn(async move {
                            loop {
                                let dgram = match conn_c.read_datagram().await {
                                    Ok(d) => d,
                                    Err(_) => break,
                                };
                                // Nothing keyed on this datagram is parsed or
                                // allocated before the connection authenticated.
                                if !auth_c.is_ok() {
                                    continue;
                                }
                                let (session_id, _pid, addr, payload) =
                                    match parse_udp_datagram(&dgram) {
                                        Ok(v) => v,
                                        Err(e) => {
                                            debug!("[{}] TUIC datagram rejected: {}", tag_c, e);
                                            continue;
                                        }
                                    };
                                let pkt = UdpPacket::new(
                                    payload.into(),
                                    TargetAddress::Ip(client_addr),
                                    addr.clone(),
                                );
                                if let Some(tx) = sessions_c.get(&session_id) {
                                    match tx.try_send(pkt) {
                                        Ok(()) => {}
                                        // Queue full: UDP is allowed to drop.
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                                        // The association is gone downstream:
                                        // release its slot so the id can be reused.
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                            drop(tx);
                                            sessions_c.remove(&session_id);
                                        }
                                    }
                                    continue;
                                }
                                let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
                                let (out_tx, mut out_rx) =
                                    tokio::sync::mpsc::channel::<UdpPacket>(64);
                                if sessions_c.open(session_id, pkt_tx.clone())
                                    != OpenResult::Inserted
                                {
                                    // Already registered (race) or at the cap.
                                    continue;
                                }
                                let mut meta = SessionMeta::new(
                                    client_addr,
                                    addr.clone(),
                                    tag_c.clone(),
                                    NetworkType::Udp,
                                );
                                if let Some(user) = auth_c.user() {
                                    meta = meta.with_user(user.to_string());
                                }
                                let disp2 = disp_c.clone();
                                tokio::spawn(async move {
                                    disp2.dispatch_packet(meta, pkt_rx, out_tx).await;
                                });
                                let _ = pkt_tx.try_send(pkt);

                                // Reply pump: dispatcher replies → datagrams
                                let conn2 = conn_c.clone();
                                let sessions2 = sessions_c.clone();
                                let tag2 = tag_c.clone();
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
                                        // One oversized reply must not destroy
                                        // the association (the old code broke out
                                        // of the pump here and stayed dead).
                                        let budget = conn2.max_datagram_size().unwrap_or(0);
                                        if packet_frame_len(&reply.source, reply.payload.len())
                                            > budget
                                        {
                                            debug!(
                                                "[{}] TUIC reply of {} bytes for session {} exceeds the {}-byte datagram budget",
                                                tag2,
                                                reply.payload.len(),
                                                session_id,
                                                budget
                                            );
                                            continue;
                                        }
                                        if let Err(e) = conn2.send_datagram(frame.into()) {
                                            if conn2.close_reason().is_some() {
                                                break;
                                            }
                                            debug!(
                                                "[{}] TUIC reply datagram for session {} dropped: {}",
                                                tag2, session_id, e
                                            );
                                        }
                                    }
                                    // Association teardown: hand the slot back.
                                    sessions2.remove(&session_id);
                                });
                            }
                        });
                    }

                    // Task 3: bidirectional streams (CONNECT)
                    loop {
                        let (send, recv) = match conn.accept_bi().await {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        // A CONNECT may race the AUTH stream, so wait for the
                        // connection to authenticate instead of dropping streams
                        // that arrive first. The wait is bounded by the same
                        // absolute deadline as the watchdog above.
                        if !auth.is_ok() && !auth.wait_ok().await {
                            continue;
                        }
                        let disp_s = disp.clone();
                        let in_tag = inbound_tag.clone();
                        let auth_s = auth.clone();
                        tokio::spawn(async move {
                            let mut stream = QuicBiStream::new(send, recv);
                            // No header read without a deadline: an idle stream
                            // used to park this task for the connection's life.
                            let deadline = tokio::time::Instant::now() + TUIC_HANDSHAKE_TIMEOUT;
                            let target_addr = match read_connect_header(&mut stream, deadline).await
                            {
                                Ok(addr) => addr,
                                Err(e) => {
                                    debug!(
                                        "[{}] TUIC CONNECT from {} rejected: {:?}",
                                        in_tag, client_addr, e
                                    );
                                    return;
                                }
                            };
                            let mut meta = SessionMeta::new(
                                client_addr,
                                target_addr,
                                in_tag,
                                NetworkType::Tcp,
                            );
                            if let Some(user) = auth_s.user() {
                                meta = meta.with_user(user.to_string());
                            }
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
        // Requesting the shutdown is not enough: the accept/receive loop owns
        // the listener FD, so returning while it is still running leaves the
        // port bound (`EADDRINUSE` on an immediate rebind). Join it.
        self.tasks.join().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_protocol::tuic::TUIC_CMD_PACKET;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use uuid::Uuid;

    // -- helpers ----------------------------------------------------------

    fn deadline_in(ms: u64) -> tokio::time::Instant {
        tokio::time::Instant::now() + std::time::Duration::from_millis(ms)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn v4_header() -> Vec<u8> {
        TuicV5Protocol::build_connect_frame(&"1.2.3.4:443".parse().unwrap())
    }

    fn v6_header() -> Vec<u8> {
        TuicV5Protocol::build_connect_frame(&"[2606:4700::1111]:53".parse().unwrap())
    }

    fn domain_header() -> Vec<u8> {
        TuicV5Protocol::build_connect_frame(&TargetAddress::domain("example.com", 8443))
    }

    /// An `AsyncRead` that never produces a byte: models a peer that completed
    /// the transport handshake and then went silent.
    struct Silent;

    impl tokio::io::AsyncRead for Silent {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    fn stream_auth_frame(uuid: &Uuid, password: &str, ts: u64) -> Vec<u8> {
        let mut buf = vec![TUIC_VERSION, TUIC_CMD_AUTHENTICATE];
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(uuid.as_bytes());
        buf.extend_from_slice(&TuicV5Protocol::stream_token(uuid, password, ts));
        buf
    }

    // -- end-to-end over a real (in-process) QUIC peer --------------------
    //
    // The parser tests above cannot prove *ordering*: that an invalid token is
    // rejected before a target address is looked at. These two tests stand up a
    // real server endpoint, certificate and QUIC client on loopback (the same
    // shape `flux_transport::h3_lite` uses) and watch what the dispatcher sees.

    /// Records every session the inbound hands to the router, and nothing else.
    #[derive(Default)]
    struct RecordingDispatcher {
        streams: parking_lot::Mutex<Vec<SessionMeta>>,
        packets: parking_lot::Mutex<Vec<SessionMeta>>,
    }

    #[async_trait::async_trait]
    impl Dispatcher for RecordingDispatcher {
        async fn dispatch_stream(&self, meta: SessionMeta, _stream: flux_types::BoxedStream) {
            self.streams.lock().push(meta);
        }

        async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<flux_types::BoxedStream> {
            Err(FluxError::Protocol {
                protocol: "test",
                message: format!("no outbound for {}", meta.destination),
            })
        }

        async fn bridge_streams(
            &self,
            _meta: SessionMeta,
            _inbound: flux_types::BoxedStream,
            _outbound: flux_types::BoxedStream,
        ) {
        }

        async fn dispatch_packet(
            &self,
            meta: SessionMeta,
            mut packet_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
            _packet_tx: tokio::sync::mpsc::Sender<UdpPacket>,
        ) {
            self.packets.lock().push(meta);
            while packet_rx.recv().await.is_some() {}
        }
    }

    /// A loopback port that was free a moment ago (the same probe `h3_lite`
    /// uses; the endpoint binds it inside `start`).
    fn free_udp_port() -> SocketAddr {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        addr
    }

    fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certs = vec![CertificateDer::from(cert.cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            cert.key_pair.serialize_der(),
        ));
        (certs, key)
    }

    /// Opens the TUIC AUTH unidirectional stream with whatever token the caller
    /// derives (or a forged one).
    async fn send_auth(conn: &quinn::Connection, uuid: &Uuid, token: [u8; 32]) {
        let mut uni = conn.open_uni().await.unwrap();
        uni.write_all(&TuicV5Protocol::build_auth_frame(uuid, &token))
            .await
            .unwrap();
        let _ = uni.finish();
    }

    #[tokio::test]
    async fn a_valid_token_dispatches_the_connect_target_end_to_end() {
        let addr = free_udp_port();
        let uuid = Uuid::new_v4();
        let (certs, key) = self_signed();
        let inbound = TuicInbound::new("tuic-e2e", addr, vec![uuid], "e2e-password", certs, key);
        let disp = Arc::new(RecordingDispatcher::default());
        inbound.start(disp.clone()).await.unwrap();

        let ep =
            QuicTransport::create_client_endpoint(false, vec![b"tuic".to_vec()], true).unwrap();
        let conn = QuicTransport::connect(&ep, addr, "localhost")
            .await
            .unwrap();

        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, uuid.as_bytes(), b"e2e-password")
            .unwrap();
        send_auth(&conn, &uuid, token).await;

        let target = TargetAddress::domain("dispatch.example", 8443);
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(&TuicV5Protocol::build_connect_frame(&target))
            .await
            .unwrap();

        let mut seen = None;
        for _ in 0..100 {
            if let Some(meta) = disp.streams.lock().first().cloned() {
                seen = Some(meta);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let meta = seen.expect("a valid token must lead to a dispatched stream");
        assert_eq!(meta.destination, target);
        assert_eq!(meta.user.as_deref(), Some(uuid.to_string().as_str()));
        assert_eq!(meta.network, NetworkType::Tcp);
    }

    #[tokio::test]
    async fn an_invalid_token_never_dispatches_even_with_a_complete_connect() {
        // The whole point of "authenticate before allocation": the client sends
        // a perfectly well-formed CONNECT for a routable target, but the token
        // is wrong, so the target must never reach the dispatcher.
        let addr = free_udp_port();
        let uuid = Uuid::new_v4();
        let (certs, key) = self_signed();
        let inbound = TuicInbound::new("tuic-e2e", addr, vec![uuid], "e2e-password", certs, key);
        let disp = Arc::new(RecordingDispatcher::default());
        inbound.start(disp.clone()).await.unwrap();

        let ep =
            QuicTransport::create_client_endpoint(false, vec![b"tuic".to_vec()], true).unwrap();
        let conn = QuicTransport::connect(&ep, addr, "localhost")
            .await
            .unwrap();

        // A token derived from the wrong password: the shape is right, the
        // value is not.
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, uuid.as_bytes(), b"wrong-password")
            .unwrap();
        send_auth(&conn, &uuid, token).await;

        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(&TuicV5Protocol::build_connect_frame(
            &TargetAddress::domain("forbidden.example", 443),
        ))
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        assert!(
            disp.streams.lock().is_empty(),
            "an unauthenticated CONNECT reached the dispatcher"
        );
        assert!(disp.packets.lock().is_empty());
    }

    #[tokio::test]
    async fn a_datagram_before_authentication_creates_no_association() {
        // Datagrams are ignored until the AUTH frame lands, so they cannot be
        // used to allocate association state either.
        let addr = free_udp_port();
        let uuid = Uuid::new_v4();
        let (certs, key) = self_signed();
        let inbound = TuicInbound::new("tuic-e2e", addr, vec![uuid], "e2e-password", certs, key);
        let disp = Arc::new(RecordingDispatcher::default());
        inbound.start(disp.clone()).await.unwrap();

        let ep =
            QuicTransport::create_client_endpoint(false, vec![b"tuic".to_vec()], true).unwrap();
        let conn = QuicTransport::connect(&ep, addr, "localhost")
            .await
            .unwrap();

        for sid in 0..8u16 {
            let frame = TuicV5Protocol::build_packet_frame(
                sid,
                0,
                &TargetAddress::domain("udp.example", 53),
                b"payload",
            );
            let _ = conn.send_datagram(frame.into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(
            disp.packets.lock().is_empty(),
            "a pre-auth datagram opened a UDP association"
        );
    }

    // -- CONNECT header parsing -------------------------------------------

    #[test]
    fn connect_header_accepts_every_address_family() {
        for (header, want) in [
            (v4_header(), "1.2.3.4:443".parse::<TargetAddress>().unwrap()),
            (v6_header(), "[2606:4700::1111]:53".parse().unwrap()),
            (domain_header(), TargetAddress::domain("example.com", 8443)),
        ] {
            match parse_connect_header(&header) {
                HeaderParse::Complete(got) => assert_eq!(got, want),
                other => panic!("expected a complete header, got {other:?}"),
            }
            // Trailing payload bytes must not disturb the parse.
            let mut with_payload = header.clone();
            with_payload.extend_from_slice(b"GET / HTTP/1.1\r\n");
            match parse_connect_header(&with_payload) {
                HeaderParse::Complete(got) => assert_eq!(got, want),
                other => panic!("expected a complete header, got {other:?}"),
            }
        }
    }

    #[test]
    fn connect_header_reports_the_exact_number_of_bytes_needed() {
        // Each prefix must ask for something strictly larger, bounded by the
        // maximum header size, and never ask for a client-controlled amount.
        for header in [v4_header(), v6_header(), domain_header()] {
            let mut last = 0usize;
            for n in 0..header.len() {
                match parse_connect_header(&header[..n]) {
                    HeaderParse::NeedMore(needed) => {
                        assert!(needed > n, "prefix {n} asked for {needed}");
                        assert!(needed <= TUIC_MAX_HEADER_LEN, "unbounded request {needed}");
                        assert!(needed >= last, "request went backwards");
                        last = needed;
                    }
                    other => panic!("prefix {n} of {} gave {other:?}", header.len()),
                }
            }
        }
    }

    #[test]
    fn connect_header_rejects_a_wrong_version_or_command() {
        let mut h = v4_header();
        h[0] = 4;
        assert!(matches!(
            parse_connect_header(&h),
            HeaderParse::Invalid("unsupported TUIC version")
        ));

        let mut h = v4_header();
        h[1] = 0x00; // AUTHENTICATE, not CONNECT
        assert!(matches!(
            parse_connect_header(&h),
            HeaderParse::Invalid("expected a CONNECT command")
        ));

        // The command is checked before the address is looked at, so a bad
        // command with a valid address still fails.
        let mut h = v4_header();
        h[1] = 0xff;
        assert!(matches!(parse_connect_header(&h), HeaderParse::Invalid(_)));
    }

    #[test]
    fn connect_header_rejects_an_unknown_address_type() {
        let mut h = v4_header();
        h[2] = 0x07;
        assert!(matches!(parse_connect_header(&h), HeaderParse::Invalid(_)));
    }

    #[test]
    fn connect_header_rejects_an_empty_domain() {
        // ATYP_DOMAIN with a zero-length name: previously accepted as
        // `Domain("")`, which the resolver then has to reject.
        let h = [
            TUIC_VERSION,
            TUIC_CMD_CONNECT,
            TUIC_ATYP_DOMAIN,
            0x00,
            0x01,
            0xbb,
        ];
        assert!(matches!(parse_connect_header(&h), HeaderParse::Invalid(_)));
    }

    #[test]
    fn connect_header_accepts_a_maximum_length_domain() {
        let name = "a".repeat(255);
        let header = TuicV5Protocol::build_connect_frame(&TargetAddress::Domain(name.clone(), 1));
        assert_eq!(header.len(), TUIC_MAX_HEADER_LEN);
        match parse_connect_header(&header) {
            HeaderParse::Complete(TargetAddress::Domain(got, 1)) => assert_eq!(got, name),
            other => panic!("expected the maximum-length domain, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_header_reader_rejects_every_truncation() {
        for header in [v4_header(), v6_header(), domain_header()] {
            for n in 0..header.len() {
                // Truncated, then EOF: must be an error, never a panic and
                // never a hang.
                let mut cursor = Cursor::new(header[..n].to_vec());
                let got = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read_connect_header(&mut cursor, deadline_in(1_000)),
                )
                .await
                .expect("a truncated header must not hang the reader");
                assert_eq!(got, Err(ReadError::Eof), "prefix {n}");
            }
            // The complete header parses.
            let mut cursor = Cursor::new(header.clone());
            assert!(
                read_connect_header(&mut cursor, deadline_in(1_000))
                    .await
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn connect_header_reader_times_out_on_a_silent_peer() {
        // The defect this proves: the QUIC path used to read the header with no
        // deadline at all, so this read never returned. The outer timeout is the
        // check: with the fix the inner deadline fires first and this returns.
        let mut silent = Silent;
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_connect_header(&mut silent, deadline_in(50)),
        )
        .await
        .expect("the header read must give up at its own deadline, not hang");
        assert_eq!(err, Err(ReadError::Timeout));
    }

    #[tokio::test]
    async fn connect_header_reader_reports_garbage_instead_of_waiting() {
        // A bad version must be rejected from the first byte, without waiting
        // for the rest of a header that can never be valid.
        let mut cursor = Cursor::new(vec![0x00, 0x00, 0x00, 0x00]);
        let err = read_connect_header(&mut cursor, deadline_in(1_000)).await;
        assert_eq!(err, Err(ReadError::Invalid("unsupported TUIC version")));

        let mut cursor = Cursor::new(vec![TUIC_VERSION, TUIC_CMD_CONNECT, 0x09]);
        let err = read_connect_header(&mut cursor, deadline_in(1_000)).await;
        assert_eq!(err, Err(ReadError::Invalid("unknown address type")));
    }

    // -- stream-mode authentication ---------------------------------------

    fn seen() -> DashMap<([u8; 16], u64), ()> {
        DashMap::new()
    }

    #[test]
    fn stream_auth_accepts_a_valid_frame() {
        let uuid = Uuid::new_v4();
        let frame = stream_auth_frame(&uuid, "correct horse", now_secs());
        let users = vec![uuid, Uuid::new_v4()];
        let seen = seen();
        assert_eq!(
            authenticate_stream_frame(&frame, &users, "correct horse", &seen),
            Ok(uuid)
        );
    }

    #[test]
    fn stream_auth_accepts_any_uuid_when_no_user_list_is_configured() {
        let uuid = Uuid::new_v4();
        let frame = stream_auth_frame(&uuid, "pw", now_secs());
        let seen = seen();
        assert_eq!(
            authenticate_stream_frame(&frame, &[], "pw", &seen),
            Ok(uuid)
        );
    }

    #[test]
    fn stream_auth_rejects_a_wrong_password_including_a_near_miss() {
        let uuid = Uuid::new_v4();
        let frame = stream_auth_frame(&uuid, "hunter2", now_secs());
        let users = vec![uuid];
        for wrong in ["hunter3", "hunte", "hunter22", "", "HUNTER2"] {
            let seen = seen();
            assert_eq!(
                authenticate_stream_frame(&frame, &users, wrong, &seen),
                Err("token mismatch"),
                "password {wrong:?} must not authenticate"
            );
            assert_eq!(seen.len(), 0, "a rejected frame must not burn a slot");
        }
    }

    #[test]
    fn stream_auth_token_is_bound_to_its_uuid() {
        // Multi-user: the token for user A must never authenticate user B, even
        // though both share the password, and a uuid one bit away from a real
        // user must not select that user.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let users = vec![a, b];
        let ts = now_secs();
        let mut frame = stream_auth_frame(&a, "pw", ts);
        // Swap in B's uuid, keeping A's token.
        frame[10..26].copy_from_slice(b.as_bytes());
        let seen = seen();
        assert_eq!(
            authenticate_stream_frame(&frame, &users, "pw", &seen),
            Err("token mismatch")
        );

        // A near-miss uuid (one byte flipped from a valid user) cannot be
        // selected either.
        let mut near = a.as_bytes().to_vec();
        near[15] ^= 0x01;
        let mut frame = stream_auth_frame(&a, "pw", ts);
        frame[10..26].copy_from_slice(&near);
        assert_eq!(
            authenticate_stream_frame(&frame, &users, "pw", &seen),
            Err("token mismatch")
        );
    }

    #[test]
    fn stream_auth_finds_a_user_that_is_not_first_in_the_list() {
        // Proves the membership scan is exhaustive rather than anchored on the
        // first entry or truncated by an early exit.
        let first = Uuid::new_v4();
        let last = Uuid::new_v4();
        let users = vec![first, Uuid::new_v4(), Uuid::new_v4(), last];
        let frame = stream_auth_frame(&last, "pw", now_secs());
        let seen = seen();
        assert_eq!(
            authenticate_stream_frame(&frame, &users, "pw", &seen),
            Ok(last)
        );
    }

    #[test]
    fn stream_auth_does_not_distinguish_an_unknown_user_from_a_bad_token() {
        // The reply must not tell a prober whether a uuid exists: both cases
        // report the same reason, and the user list is checked only after the
        // token, which is the expensive part anyway.
        let known = Uuid::new_v4();
        let unknown = Uuid::new_v4();
        let users = vec![known];
        let ts = now_secs();
        let seen = seen();
        let forged_known = stream_auth_frame(&known, "wrong", ts);
        let forged_unknown = stream_auth_frame(&unknown, "wrong", ts);
        assert_eq!(
            authenticate_stream_frame(&forged_known, &users, "right", &seen),
            authenticate_stream_frame(&forged_unknown, &users, "right", &seen)
        );
    }

    #[test]
    fn stream_auth_rejects_replays() {
        let uuid = Uuid::new_v4();
        let users = vec![uuid];
        let seen = seen();
        let frame = stream_auth_frame(&uuid, "pw", now_secs());
        assert_eq!(
            authenticate_stream_frame(&frame, &users, "pw", &seen),
            Ok(uuid)
        );
        assert_eq!(
            authenticate_stream_frame(&frame, &users, "pw", &seen),
            Err("replayed AUTH frame")
        );
        // A different timestamp is a different frame and must still work.
        let later = stream_auth_frame(&uuid, "pw", now_secs() + 1);
        assert_eq!(
            authenticate_stream_frame(&later, &users, "pw", &seen),
            Ok(uuid)
        );
    }

    #[test]
    fn stream_auth_rejects_timestamps_outside_the_window() {
        let uuid = Uuid::new_v4();
        let users = vec![uuid];
        let now = now_secs();
        for ts in [
            now - flux_protocol::tuic::TUIC_STREAM_TOKEN_WINDOW_SECS - 5,
            now + flux_protocol::tuic::TUIC_STREAM_TOKEN_WINDOW_SECS + 5,
        ] {
            let frame = stream_auth_frame(&uuid, "pw", ts);
            let seen = seen();
            assert_eq!(
                authenticate_stream_frame(&frame, &users, "pw", &seen),
                Err("timestamp outside the accepted window")
            );
        }
    }

    #[test]
    fn stream_auth_rejects_every_truncated_frame() {
        let uuid = Uuid::new_v4();
        let frame = stream_auth_frame(&uuid, "pw", now_secs());
        let users = vec![uuid];
        for n in 0..frame.len() {
            let seen = seen();
            assert_eq!(
                authenticate_stream_frame(&frame[..n], &users, "pw", &seen),
                Err("malformed AUTH frame"),
                "prefix {n}"
            );
        }
    }

    #[test]
    fn stream_auth_rejects_garbage() {
        let users = vec![Uuid::new_v4()];
        for frame in [
            vec![],
            vec![0u8; TUIC_STREAM_AUTH_LEN],
            vec![0xff; TUIC_STREAM_AUTH_LEN],
        ] {
            let seen = seen();
            assert!(authenticate_stream_frame(&frame, &users, "pw", &seen).is_err());
        }
    }

    // -- connection auth gate ---------------------------------------------

    #[tokio::test]
    async fn the_gate_every_datagram_and_connect_passes_through() {
        let auth = ConnAuth::new(deadline_in(5_000));
        assert!(!auth.is_ok(), "a fresh connection is unauthenticated");
        assert_eq!(auth.user(), None);
        // The datagram task's guard: nothing is parsed until this flips.
        let frame = TuicV5Protocol::build_packet_frame(1, 0, &"1.2.3.4:53".parse().unwrap(), b"x");
        assert!(!(auth.is_ok() && parse_udp_datagram(&frame).is_ok()));
        auth.mark_ok(None);
        assert!(auth.is_ok() && parse_udp_datagram(&frame).is_ok());
    }

    #[tokio::test]
    async fn the_authenticated_identity_is_remembered_and_not_relabelled() {
        // Multi-user: the dispatcher has to see which user a stream belongs to,
        // and a second AUTH frame must not re-label an established connection.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let auth = ConnAuth::new(deadline_in(5_000));
        auth.mark_ok(Some(a));
        assert_eq!(auth.user(), Some(a));
        auth.mark_ok(Some(b));
        assert_eq!(auth.user(), Some(a));
    }

    #[tokio::test]
    async fn auth_gate_wakes_a_waiting_stream() {
        let auth = ConnAuth::new(deadline_in(5_000));
        let waiter = auth.clone();
        let handle = tokio::spawn(async move { waiter.wait_ok().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        auth.mark_ok(None);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("waiter must be woken by mark_ok")
                .unwrap()
        );
        assert!(auth.is_ok());
    }

    #[tokio::test]
    async fn auth_gate_gives_up_at_the_deadline() {
        // Proves the handshake budget: without it a connection that never
        // authenticates would park its task forever.
        let auth = ConnAuth::new(deadline_in(40));
        assert!(!auth.wait_ok().await);
        assert!(!auth.is_ok());
        // A late AUTH is still recorded (the connection is being closed by the
        // watchdog, but the state machine must not lie).
        auth.mark_ok(None);
        assert!(auth.is_ok());
    }

    // -- UDP association table --------------------------------------------

    fn dummy_sender() -> tokio::sync::mpsc::Sender<UdpPacket> {
        tokio::sync::mpsc::channel(1).0
    }

    #[test]
    fn association_table_enforces_its_capacity() {
        let table: Arc<UdpAssocTable<u16>> = UdpAssocTable::new(2);
        assert_eq!(table.open(1, dummy_sender()), OpenResult::Inserted);
        assert_eq!(table.open(2, dummy_sender()), OpenResult::Inserted);
        // The cap holds: a fresh id is refused, not silently accepted.
        assert_eq!(table.open(3, dummy_sender()), OpenResult::AtCapacity);
        assert_eq!(table.len(), 2);
        // An existing id is reported as such, not counted twice.
        assert_eq!(table.open(1, dummy_sender()), OpenResult::Exists);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn association_teardown_releases_its_slot() {
        // The leak this proves: the map entry used to outlive its association,
        // so a client churning through ids exhausted the table.
        let table: Arc<UdpAssocTable<u16>> = UdpAssocTable::new(2);
        assert_eq!(table.open(1, dummy_sender()), OpenResult::Inserted);
        assert_eq!(table.open(2, dummy_sender()), OpenResult::Inserted);
        assert_eq!(table.open(3, dummy_sender()), OpenResult::AtCapacity);
        assert!(table.remove(&1));
        assert_eq!(table.open(3, dummy_sender()), OpenResult::Inserted);
        assert_eq!(table.len(), 2);
        // Removing something absent is a no-op, not a panic.
        assert!(!table.remove(&999));
    }

    #[test]
    fn association_table_hands_back_the_sender() {
        let table: Arc<UdpAssocTable<u32>> = UdpAssocTable::new(4);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpPacket>(1);
        assert_eq!(table.open(7, tx), OpenResult::Inserted);
        let got = table.get(&7).expect("registered");
        got.try_send(UdpPacket::new(
            bytes::Bytes::from_static(b"x"),
            "1.1.1.1:1".parse().unwrap(),
            "2.2.2.2:2".parse().unwrap(),
        ))
        .unwrap();
        assert!(rx.try_recv().is_ok());
        assert!(table.get(&8).is_none());
    }

    // -- UDP datagram framing ---------------------------------------------

    #[test]
    fn datagram_parses_a_well_formed_packet() {
        let target = TargetAddress::domain("example.com", 53);
        let frame = TuicV5Protocol::build_packet_frame(9, 77, &target, b"hello");
        let (sid, pid, addr, payload) = parse_udp_datagram(&frame).unwrap();
        assert_eq!((sid, pid), (9, 77));
        assert_eq!(addr, target);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn datagram_rejects_every_truncation() {
        let frame = TuicV5Protocol::build_packet_frame(1, 0, &"1.2.3.4:5".parse().unwrap(), b"abc");
        for n in 0..frame.len() {
            assert!(
                parse_udp_datagram(&frame[..n]).is_err(),
                "prefix {n} of {} was accepted",
                frame.len()
            );
        }
    }

    #[test]
    fn datagram_rejects_a_declared_length_beyond_the_datagram() {
        // Payload length says 8, only 3 bytes follow.
        let mut frame =
            TuicV5Protocol::build_packet_frame(1, 0, &"1.2.3.4:5".parse().unwrap(), b"abc");
        // Length field sits at a fixed offset 8..10 in the PACKET frame.
        frame[8..10].copy_from_slice(&8u16.to_be_bytes());
        assert!(parse_udp_datagram(&frame).is_err());
    }

    #[test]
    fn datagram_keeps_a_zero_length_payload() {
        // A zero-length payload is a legal (empty) UDP datagram, not EOF: it
        // must reach the dispatcher as an empty packet.
        let target: TargetAddress = "1.2.3.4:53".parse().unwrap();
        let frame = TuicV5Protocol::build_packet_frame(3, 0, &target, &[]);
        let (sid, _, addr, payload) = parse_udp_datagram(&frame).unwrap();
        assert_eq!(sid, 3);
        assert_eq!(addr, target);
        assert!(payload.is_empty());
    }

    #[test]
    fn datagram_rejects_fragments() {
        let target: TargetAddress = "1.2.3.4:53".parse().unwrap();
        let mut frame = TuicV5Protocol::build_packet_frame(3, 0, &target, b"xx");
        frame[6] = 2; // frag_total
        frame[7] = 1; // frag_id
        assert!(parse_udp_datagram(&frame).is_err());
    }

    #[test]
    fn datagram_rejects_an_oversized_frame() {
        // Frames larger than a jumbo datagram are refused before they are
        // parsed or copied, whatever QUIC's receive buffer allows.
        let mut frame = vec![TUIC_VERSION, TUIC_CMD_PACKET];
        frame.resize(MAX_UDP_DATAGRAM + 1, 0);
        assert!(parse_udp_datagram(&frame).is_err());
    }

    #[test]
    fn datagram_rejects_a_non_packet_frame() {
        let target: TargetAddress = "1.2.3.4:53".parse().unwrap();
        let mut frame = TuicV5Protocol::build_connect_frame(&target);
        frame.resize(32, 0);
        assert!(parse_udp_datagram(&frame).is_err());
    }

    #[test]
    fn reply_frames_are_measured_the_same_way_they_are_built() {
        // Guards the reply budget against drifting from the encoder: a reply
        // over the connection's datagram size is dropped, and the length field
        // is a u16, so the measured size must be exact.
        for target in [
            "1.2.3.4:5".parse::<TargetAddress>().unwrap(),
            "[::1]:5".parse().unwrap(),
            TargetAddress::domain("example.com", 5),
        ] {
            for payload_len in [0usize, 1, 100, 1200, 65535] {
                let payload = vec![0u8; payload_len];
                let frame = TuicV5Protocol::build_packet_frame(0, 0, &target, &payload);
                assert_eq!(frame.len(), packet_frame_len(&target, payload_len));
            }
            // Nothing that fits a datagram can overflow the u16 length field.
            assert!(packet_frame_len(&target, 60_000) > u16::MAX as usize / 2);
        }
    }
}
