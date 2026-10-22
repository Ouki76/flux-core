use async_trait::async_trait;
use flux_protocol::hysteria2::{
    HYSTERIA2_CMD_TCP, HYSTERIA2_CMD_UDP, HYSTERIA2_VERSION, Hysteria2Protocol,
};
use flux_transport::quic::{QuicBiStream, QuicTransport};
use flux_types::{
    Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};

// The framing primitives shared by both QUIC inbounds (bounded reads, the
// connection auth gate and the UDP association table) live in `tuic.rs`; they
// are protocol-agnostic and TUIC is their other user.
use crate::tuic::{
    ConnAuth, HeaderParse, MAX_UDP_DATAGRAM, OpenResult, ReadError, UdpAssocTable, read_exact_until,
};

/// Absolute budget for the layered (non-QUIC) Hysteria 2 handshake: AUTH frame
/// plus request header.
const HY2_STREAM_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Absolute budget for the HTTP/3 authentication exchange of a QUIC connection.
/// A connection that has not authenticated inside it is closed.
const HY2_QUIC_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Longest password (in bytes) accepted in a stream AUTH frame.
///
/// The length is a `u16` straight off the wire and used to size a buffer before
/// anything is verified, so it needs a bound of its own: 64 KiB of pre-auth
/// allocation per connection is otherwise free for an attacker.
const MAX_HY2_PASSWORD_LEN: usize = 1024;

/// Longest possible request header: command + port + ATYP + a 255-byte domain.
const HY2_MAX_REQUEST_HEADER_LEN: usize = 5 + 255;

/// Longest destination string accepted inside a UDP datagram frame.
const MAX_HY2_ADDR_LEN: u64 = 2048;

/// Hard cap on live UDP associations per QUIC connection.
const HY2_MAX_UDP_SESSIONS: usize = 256;

/// Upper bound on the receive rate a client may declare (`Hysteria-CC-RX`).
///
/// The value is entirely client-supplied, so it is clamped before it is echoed
/// or used: ten million of whatever unit the client is speaking is past any real
/// link and far below the point where a bits-per-second conversion or a line-rate
/// pacer's burst arithmetic could overflow. This removes the whole class of
/// absurd-rate inputs.
const MAX_HY2_CC_RX: u64 = 10_000_000;

/// Hysteria 2 `TCPRequest` frame type (the only raw-stream frame we serve).
const HY2_FRAME_TCP_REQUEST: u64 = 0x401;

// ---------------------------------------------------------------------------
// Testable core — pure framing and policy, no QUIC and no sockets.
// ---------------------------------------------------------------------------

/// Reads a QUIC variable-length integer (RFC 9000 §16) from a datagram.
///
/// Returns the value and the number of bytes it occupied, or `None` when the
/// buffer is too short for the length the prefix announces.
pub(crate) fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &buf[1..len] {
        value = (value << 8) | (*byte as u64);
    }
    Some((value, len))
}

/// Parses the layered-mode AUTH frame header `[version, password_len u16]` and
/// returns the password length after bounding it.
pub(crate) fn parse_auth_header(header: &[u8; 3]) -> Result<usize, &'static str> {
    if header[0] != HYSTERIA2_VERSION {
        return Err("unsupported Hysteria 2 version");
    }
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    if len == 0 {
        return Err("empty password in AUTH frame");
    }
    if len > MAX_HY2_PASSWORD_LEN {
        return Err("password length in AUTH frame exceeds the limit");
    }
    Ok(len)
}

/// Constant-time password check, used wherever a client-supplied secret is
/// compared against the configured one.
///
/// A plain `==` on `str` is a `memcmp` with an early exit, so its duration
/// reports the length of the matching prefix. All three comparison sites in this
/// inbound (stream AUTH, HTTP/3 `Hysteria-Auth`) go through here.
pub(crate) fn verify_password(provided: &str, expected: &str) -> bool {
    flux_common::constant_time_eq_str(provided, expected)
}

/// Parses the layered-mode request header: `[command, port u16, atyp, address]`.
///
/// Incremental like the TUIC one: the caller supplies what it has buffered and
/// learns whether the header is complete, how many bytes it needs, or that it
/// can never be valid. A domain length is bounded by its one-byte field, so the
/// total is always bounded.
pub(crate) fn parse_request_header(buf: &[u8]) -> HeaderParse {
    let command = match buf.first() {
        Some(c) => *c,
        None => return HeaderParse::NeedMore(1),
    };
    // An unknown command used to fall through to TCP; it is a reject.
    if command != HYSTERIA2_CMD_TCP && command != HYSTERIA2_CMD_UDP {
        return HeaderParse::Invalid("unknown request command");
    }
    if buf.len() < 4 {
        return HeaderParse::NeedMore(4);
    }
    let atyp = buf[3];
    let total = match atyp {
        1 => 4 + 4,
        2 => {
            let dlen = match buf.get(4) {
                Some(l) => *l as usize,
                None => return HeaderParse::NeedMore(5),
            };
            if dlen == 0 {
                return HeaderParse::Invalid("empty domain");
            }
            5 + dlen
        }
        3 => 4 + 16,
        _ => return HeaderParse::Invalid("unknown address type"),
    };
    debug_assert!(total <= HY2_MAX_REQUEST_HEADER_LEN);
    if buf.len() < total {
        return HeaderParse::NeedMore(total);
    }
    match Hysteria2Protocol::parse_request_frame(&buf[..total]) {
        Ok((parsed_command, target)) if parsed_command == command => HeaderParse::Complete(target),
        _ => HeaderParse::Invalid("malformed address"),
    }
}

/// Reads a request header from `stream` without reading past it and without
/// allocating. The payload follows immediately on the same stream.
///
/// Returns `(command, target)`; the command is already validated as one of the
/// two the protocol defines.
pub(crate) async fn read_request_header<S>(
    stream: &mut S,
    deadline: tokio::time::Instant,
) -> Result<(u8, TargetAddress), ReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; HY2_MAX_REQUEST_HEADER_LEN];
    let mut have = 0usize;
    loop {
        match parse_request_header(&buf[..have]) {
            HeaderParse::Complete(addr) => return Ok((buf[0], addr)),
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

/// A parsed Hysteria 2 UDP datagram frame:
/// `[session_id u32][packet_id u16][frag_id u8][frag_total u8][dest][payload]`
/// where `dest` is a QUIC varint length followed by the address string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hy2Udp {
    pub session_id: u32,
    pub packet_id: u16,
    pub target: TargetAddress,
    pub payload: Vec<u8>,
}

/// Parses a UDP datagram frame, refusing anything that is not exactly
/// well-formed.
///
/// Fragment reassembly is not implemented, so fragmented packets are rejected
/// rather than half-delivered; a fragment count of zero (which no sender may
/// produce, fragment counts are 1-based) is rejected too.
pub(crate) fn parse_udp_datagram(datagram: &[u8]) -> Result<Hy2Udp, &'static str> {
    if datagram.len() > MAX_UDP_DATAGRAM {
        return Err("framed datagram exceeds the maximum size");
    }
    if datagram.len() < 9 {
        return Err("datagram shorter than the 9-byte header");
    }
    let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let frag_id = datagram[6];
    let frag_total = datagram[7];
    if frag_total == 0 {
        return Err("fragment count of zero");
    }
    if frag_id >= frag_total {
        return Err("fragment index outside the fragment count");
    }
    if frag_total > 1 {
        return Err("fragmented datagrams are not supported");
    }
    let (dest_len, used) = read_varint(&datagram[8..]).ok_or("truncated destination length")?;
    if dest_len > MAX_HY2_ADDR_LEN {
        return Err("destination length exceeds the limit");
    }
    let dest_len = dest_len as usize;
    let dest_start = 8 + used;
    let dest_end = dest_start + dest_len;
    // A declared length larger than the datagram is a reject, not a short read.
    if datagram.len() < dest_end {
        return Err("declared destination length runs past the datagram");
    }
    let dest_str = std::str::from_utf8(&datagram[dest_start..dest_end])
        .map_err(|_| "destination is not valid UTF-8")?;
    let target: TargetAddress = dest_str
        .parse()
        .map_err(|_| "invalid destination address")?;
    Ok(Hy2Udp {
        session_id,
        packet_id,
        target,
        payload: datagram[dest_end..].to_vec(),
    })
}

/// Builds a UDP datagram frame in reply to a client packet.
///
/// The destination length is a QUIC varint, not a single byte: a name of 64
/// bytes or more would otherwise be written with a length the peer cannot read
/// back (the old encoder wrote `len as u8`).
pub(crate) fn build_udp_reply(
    session_id: u32,
    packet_id: u16,
    dest: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(11 + dest.len() + payload.len());
    frame.extend_from_slice(&session_id.to_be_bytes());
    frame.extend_from_slice(&packet_id.to_be_bytes());
    frame.push(0); // frag id
    frame.push(1); // frag total
    Hysteria2Protocol::put_quic_varint(dest.len() as u64, &mut frame);
    frame.extend_from_slice(dest.as_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parses the client-declared receive rate from the `Hysteria-CC-RX` header.
///
/// The value is attacker-controlled. Anything unparseable is treated as "no
/// claim" (zero); anything larger than [`MAX_HY2_CC_RX`] is clamped, so no
/// downstream arithmetic (or pacer) can be driven to an absurd rate or an
/// overflow by a client.
pub(crate) fn parse_client_cc_rx(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|v| v.min(MAX_HY2_CC_RX))
        .unwrap_or(0)
}

pub struct Hysteria2Inbound {
    tag: String,
    listen_addr: SocketAddr,
    password: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pipeline: Option<flux_transport::pipeline::ServerTransportPipeline>,
    obfs_password: Option<String>,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
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
            obfs_password: None,
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    /// Enables Salamander obfuscation with the given password (must match the client).
    pub fn with_obfs_password(mut self, password: Option<String>) -> Self {
        self.obfs_password = password;
        self
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
            obfs_password: None,
            rate_limiter: None,
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

                        // One absolute budget for the whole layered handshake:
                        // every stage below used to be an unbounded read, so a
                        // client that connected and stalled parked the task.
                        let deadline = tokio::time::Instant::now() + HY2_STREAM_HANDSHAKE_TIMEOUT;

                        let mut auth_hdr = [0u8; 3];
                        if let Err(e) = read_exact_until(&mut stream, &mut auth_hdr, deadline).await
                        {
                            debug!(
                                "[{}] Hysteria 2 AUTH header from {} unreadable: {:?}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        // Bound the length before allocating on it.
                        let pw_len = match parse_auth_header(&auth_hdr) {
                            Ok(len) => len,
                            Err(reason) => {
                                warn!(
                                    "[{}] Hysteria 2 AUTH from {} rejected: {}",
                                    inbound_tag, client_addr, reason
                                );
                                return;
                            }
                        };
                        let mut full_auth = vec![0u8; 3 + pw_len];
                        full_auth[..3].copy_from_slice(&auth_hdr);
                        if read_exact_until(&mut stream, &mut full_auth[3..], deadline)
                            .await
                            .is_err()
                        {
                            return;
                        }
                        // The password is verified before a single byte of the
                        // target address is parsed.
                        if Hysteria2Protocol::parse_auth_frame(&full_auth, &pw).is_err() {
                            warn!(
                                "[{}] Hysteria 2 password rejected from {}",
                                inbound_tag, client_addr
                            );
                            return;
                        }

                        let (command, target_addr) =
                            match read_request_header(&mut stream, deadline).await {
                                Ok(parsed) => parsed,
                                Err(e) => {
                                    debug!(
                                        "[{}] Hysteria 2 request from {} rejected: {:?}",
                                        inbound_tag, client_addr, e
                                    );
                                    return;
                                }
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
        let endpoint = if let Some(obfs_pwd) = &self.obfs_password {
            QuicTransport::create_server_endpoint_obfs(
                self.listen_addr,
                self.certs.clone(),
                self.key.clone_key(),
                alpn,
                obfs_pwd,
            )?
        } else {
            QuicTransport::create_server_endpoint(
                self.listen_addr,
                self.certs.clone(),
                self.key.clone_key(),
                alpn,
            )?
        };

        self.running.store(true, Ordering::SeqCst);
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let password = Arc::new(self.password.clone());
        let rate_limiter = self.rate_limiter.clone();
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
                let pw = password.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard; // held for the QUIC connection lifetime
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("[{}] Hysteria 2 QUIC handshake error: {}", inbound_tag, e);
                            return;
                        }
                    };
                    let client_addr = conn.remote_address();
                    let h3 = flux_transport::h3_lite::H3LiteServer::new(conn.clone());
                    let auth =
                        ConnAuth::new(tokio::time::Instant::now() + HY2_QUIC_HANDSHAKE_TIMEOUT);

                    // UDP datagram sessions for this connection. Capped, and each
                    // slot is released when its association ends: the id is
                    // client-supplied and 32 bits wide, so an unbounded table
                    // would be a memory exhaustion primitive.
                    let udp_sessions: Arc<UdpAssocTable<u32>> =
                        UdpAssocTable::new(HY2_MAX_UDP_SESSIONS);

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
                                // Nothing is parsed or allocated before the
                                // connection authenticated.
                                if !auth_c.is_ok() {
                                    continue;
                                }
                                let parsed = match parse_udp_datagram(&dgram) {
                                    Ok(p) => p,
                                    Err(reason) => {
                                        debug!(
                                            "[{}] Hysteria 2 datagram rejected: {}",
                                            tag_c, reason
                                        );
                                        continue;
                                    }
                                };
                                let session_id = parsed.session_id;
                                let pkt = UdpPacket::new(
                                    parsed.payload.into(),
                                    TargetAddress::Ip(client_addr),
                                    parsed.target.clone(),
                                );
                                if let Some(tx) = sessions_c.get(&session_id) {
                                    match tx.try_send(pkt) {
                                        Ok(()) => {}
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
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
                                    // Race, or the association cap is reached:
                                    // drop the packet, never the accounting.
                                    debug!(
                                        "[{}] Hysteria 2 UDP session {} refused (cap {})",
                                        tag_c, session_id, HY2_MAX_UDP_SESSIONS
                                    );
                                    continue;
                                }
                                let meta = SessionMeta::new(
                                    client_addr,
                                    parsed.target.clone(),
                                    tag_c.clone(),
                                    NetworkType::Udp,
                                );
                                let disp2 = disp_c.clone();
                                tokio::spawn(async move {
                                    disp2.dispatch_packet(meta, pkt_rx, out_tx).await;
                                });
                                let _ = pkt_tx.try_send(pkt);

                                let conn2 = conn_c.clone();
                                let sessions2 = sessions_c.clone();
                                let tag2 = tag_c.clone();
                                tokio::spawn(async move {
                                    let mut pid: u16 = 0;
                                    while let Some(reply) = out_rx.recv().await {
                                        let dest = reply.source.to_string();
                                        let frame =
                                            build_udp_reply(session_id, pid, &dest, &reply.payload);
                                        pid = pid.wrapping_add(1);
                                        let budget = conn2.max_datagram_size().unwrap_or(0);
                                        if frame.len() > budget {
                                            // Drop the packet, keep the
                                            // association alive.
                                            debug!(
                                                "[{}] Hysteria 2 reply of {} bytes for session {} exceeds the {}-byte datagram budget",
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
                                                "[{}] Hysteria 2 reply datagram for session {} dropped: {}",
                                                tag2, session_id, e
                                            );
                                        }
                                    }
                                    // Association teardown: release the slot.
                                    sessions2.remove(&session_id);
                                });
                            }
                        });
                    }

                    loop {
                        // Before authentication the accept is bounded: a peer
                        // that opens nothing (or a stream that never sends its
                        // header) must not hold the connection task forever.
                        let ev = if auth.is_ok() {
                            h3.accept().await
                        } else {
                            tokio::select! {
                                ev = h3.accept() => ev,
                                authed = auth.wait_ok() => {
                                    if authed {
                                        h3.accept().await
                                    } else {
                                        debug!(
                                            "[{}] Hysteria 2 connection from {} closed: no authentication within the handshake budget",
                                            inbound_tag, client_addr
                                        );
                                        break;
                                    }
                                }
                            }
                        };
                        let ev = match ev {
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
                                // Constant-time compare: a plain `==` leaks the
                                // length of the shared prefix of the password.
                                let auth_ok = is_auth
                                    && get("hysteria-auth")
                                        .map(|p| verify_password(p, pw.as_str()))
                                        .unwrap_or(false);
                                if auth_ok {
                                    auth.mark_ok(None);
                                    // A client-declared rate is bounded before it
                                    // is echoed or used anywhere.
                                    let cc_rx = parse_client_cc_rx(get("hysteria-cc-rx"));
                                    let fields = vec![
                                        ("hysteria-udp".to_string(), "true".to_string()),
                                        ("hysteria-cc-rx".to_string(), cc_rx.to_string()),
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
                                        "[{}] Hysteria 2 authenticated client {} (declares receive rate {})",
                                        inbound_tag, client_addr, cc_rx
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
                                if frame_type != HY2_FRAME_TCP_REQUEST || !auth.is_ok() {
                                    continue;
                                }
                                let disp_s = disp.clone();
                                let in_tag = inbound_tag.clone();
                                tokio::spawn(async move {
                                    // Bounded read: a raw stream that never
                                    // completes its request would otherwise park
                                    // this task for the connection's life.
                                    let target = match tokio::time::timeout(
                                        HY2_STREAM_HANDSHAKE_TIMEOUT,
                                        Hysteria2Protocol::read_tcp_request_body(&mut recv),
                                    )
                                    .await
                                    {
                                        Ok(Ok(t)) => t,
                                        Ok(Err(e)) => {
                                            debug!(
                                                "[{}] hy2 tcp request read failed: {}",
                                                in_tag, e
                                            );
                                            return;
                                        }
                                        Err(_) => {
                                            debug!("[{}] hy2 tcp request read timed out", in_tag);
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWriteExt;

    // -- helpers ----------------------------------------------------------

    fn deadline_in(ms: u64) -> tokio::time::Instant {
        tokio::time::Instant::now() + std::time::Duration::from_millis(ms)
    }

    /// An `AsyncRead` that never produces a byte.
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

    fn request_header(command: u8, target: &TargetAddress) -> Vec<u8> {
        Hysteria2Protocol::build_request_frame(command, target)
    }

    fn auth_frame(version: u8, len: u16, body: &[u8]) -> Vec<u8> {
        let mut buf = vec![version, (len >> 8) as u8, len as u8];
        buf.extend_from_slice(body);
        buf
    }

    /// A datagram in the client→server direction.
    fn udp_frame(session_id: u32, packet_id: u16, dest: &str, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&session_id.to_be_bytes());
        frame.extend_from_slice(&packet_id.to_be_bytes());
        frame.push(0); // frag id
        frame.push(1); // frag total
        Hysteria2Protocol::put_quic_varint(dest.len() as u64, &mut frame);
        frame.extend_from_slice(dest.as_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    // -- stream AUTH ------------------------------------------------------

    #[test]
    fn auth_header_bounds_the_password_length_before_allocating() {
        // The length is client-supplied and used to size a buffer pre-auth.
        assert_eq!(parse_auth_header(&[HYSTERIA2_VERSION, 0x00, 0x05]), Ok(5));
        assert_eq!(
            parse_auth_header(&[HYSTERIA2_VERSION, 0xFF, 0xFF]),
            Err("password length in AUTH frame exceeds the limit")
        );
        assert_eq!(
            parse_auth_header(&[HYSTERIA2_VERSION, 0x04, 0x01]), // 1025
            Err("password length in AUTH frame exceeds the limit")
        );
        assert_eq!(
            parse_auth_header(&[HYSTERIA2_VERSION, 0x04, 0x00]), // exactly 1024
            Ok(1024)
        );
        assert_eq!(
            parse_auth_header(&[HYSTERIA2_VERSION, 0x00, 0x00]),
            Err("empty password in AUTH frame")
        );
        assert_eq!(
            parse_auth_header(&[1, 0x00, 0x01]),
            Err("unsupported Hysteria 2 version")
        );
    }

    #[test]
    fn auth_frame_is_verified_before_anything_else_happens() {
        let frame = Hysteria2Protocol::build_auth_frame("correct-password");
        assert!(Hysteria2Protocol::parse_auth_frame(&frame, "correct-password").is_ok());
        for wrong in [
            "",
            "correct-passwor",
            "correct-password2",
            "Correct-password",
        ] {
            assert!(
                Hysteria2Protocol::parse_auth_frame(&frame, wrong).is_err(),
                "password {wrong:?} must not authenticate"
            );
        }
    }

    #[test]
    fn password_comparison_agrees_with_equality() {
        for (a, b) in [
            ("", ""),
            ("pw", "pw"),
            ("pw", "p"),
            ("pw", "pwx"),
            ("p\u{00e4}ssword", "p\u{00e4}ssword"),
            ("p\u{00e4}ssword", "password"),
        ] {
            assert_eq!(verify_password(a, b), a == b, "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn auth_frame_truncated_at_every_prefix_is_refused() {
        let frame = Hysteria2Protocol::build_auth_frame("my-password");
        for n in 0..frame.len() {
            assert!(
                Hysteria2Protocol::parse_auth_frame(&frame[..n], "my-password").is_err(),
                "prefix {n} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn auth_frame_from_the_wire_rejects_a_declared_length_past_the_frame() {
        // Declares 100 bytes of password and supplies 5: the reader must stop at
        // EOF rather than blocking on the missing bytes.
        let short = auth_frame(HYSTERIA2_VERSION, 100, b"abcde");
        let mut cursor = Cursor::new(short);
        let mut hdr = [0u8; 3];
        assert!(
            read_exact_until(&mut cursor, &mut hdr, deadline_in(1_000))
                .await
                .is_ok()
        );
        let len = parse_auth_header(&hdr).unwrap();
        assert_eq!(len, 100);
        let mut rest = vec![0u8; len];
        assert_eq!(
            read_exact_until(&mut cursor, &mut rest, deadline_in(1_000)).await,
            Err(ReadError::Eof)
        );
    }

    // -- end-to-end over a real (in-process) QUIC peer --------------------

    /// Records every session the inbound hands to the router, and nothing else.
    #[derive(Default)]
    struct RecordingDispatcher {
        streams: parking_lot::Mutex<Vec<SessionMeta>>,
    }

    #[async_trait::async_trait]
    impl Dispatcher for RecordingDispatcher {
        async fn dispatch_stream(&self, meta: SessionMeta, _stream: flux_types::BoxedStream) {
            self.streams.lock().push(meta);
        }

        async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<flux_types::BoxedStream> {
            Err(flux_types::FluxError::Protocol {
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
            let _ = meta;
            while packet_rx.recv().await.is_some() {}
        }
    }

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

    #[tokio::test]
    async fn a_valid_password_serves_a_tcp_request_end_to_end() {
        let addr = free_udp_port();
        let (certs, key) = self_signed();
        let inbound = Hysteria2Inbound::new("hy2-e2e", addr, "e2e-password", certs, key);
        let disp = Arc::new(RecordingDispatcher::default());
        inbound.start(disp.clone()).await.unwrap();

        let ep = QuicTransport::create_client_endpoint(false, vec![b"h3".to_vec()], true).unwrap();
        let conn = QuicTransport::connect(&ep, addr, "localhost")
            .await
            .unwrap();

        // The real Hysteria 2 HTTP/3 auth exchange. The returned keeper owns the
        // client's HTTP/3 driver: dropping it closes the connection, so it has to
        // stay alive for the rest of the test (exactly as the outbound does).
        let _keeper = Hysteria2Protocol::client_authenticate_h3(conn.clone(), "e2e-password")
            .await
            .expect("a valid password must authenticate");

        let target = TargetAddress::domain("dispatch.example", 8443);
        let mut stream = QuicTransport::open_bi_stream(&conn).await.unwrap();
        stream
            .write_all(&Hysteria2Protocol::encode_tcp_request(&target))
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
        let meta = seen.expect("an authenticated 0x401 stream must be dispatched");
        assert_eq!(meta.destination, target);
        assert_eq!(meta.network, NetworkType::Tcp);
    }

    /// Sends one HTTP/3 request by hand and returns the `:status` the server
    /// answered with. The `h3` crate's client tears its connection down when
    /// authentication fails, so the negative case has to drive the framing
    /// itself to keep the connection — and the server's gate — under test.
    async fn manual_h3_request(
        conn: &quinn::Connection,
        fields: Vec<(&str, &str)>,
    ) -> Option<String> {
        use flux_transport::h3_lite::{H3_FRAME_HEADERS, h3_frame, qpack_encode_field_section};
        let fields: Vec<(String, String)> = fields
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let section = qpack_encode_field_section(&fields);
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&h3_frame(H3_FRAME_HEADERS, &section))
            .await
            .unwrap();
        let _ = send.finish();

        let mut buf = vec![0u8; 4096];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), recv.read(&mut buf))
            .await
            .ok()?;
        let n = read.ok()??;
        let frame = &buf[..n];
        let (frame_type, used) = read_varint(frame)?;
        if frame_type != H3_FRAME_HEADERS {
            return None;
        }
        let (len, used2) = read_varint(&frame[used..])?;
        let body = &frame[used + used2..];
        let len = (len as usize).min(body.len());
        let body = &body[..len];
        let decoded = flux_transport::h3_lite::qpack_decode_field_section(body).ok()?;
        decoded
            .into_iter()
            .find(|(n, _)| n == ":status")
            .map(|(_, v)| v)
    }

    #[tokio::test]
    async fn a_wrong_password_is_answered_404_and_nothing_is_dispatched() {
        // The client completes the QUIC handshake and sends a well-formed
        // Hysteria 2 auth request with the wrong password, then a perfectly
        // well-formed 0x401 request: none of it may reach the router.
        let addr = free_udp_port();
        let (certs, key) = self_signed();
        let inbound = Hysteria2Inbound::new("hy2-e2e", addr, "e2e-password", certs, key);
        let disp = Arc::new(RecordingDispatcher::default());
        inbound.start(disp.clone()).await.unwrap();

        let ep = QuicTransport::create_client_endpoint(false, vec![b"h3".to_vec()], true).unwrap();
        let conn = QuicTransport::connect(&ep, addr, "localhost")
            .await
            .unwrap();

        let status = manual_h3_request(
            &conn,
            vec![
                (":method", "POST"),
                (":path", "/auth"),
                (":authority", "hysteria"),
                ("hysteria-auth", "wrong-password"),
            ],
        )
        .await;
        assert_eq!(
            status.as_deref(),
            Some("404"),
            "a wrong password must be refused"
        );

        // Now the request a client would send if it believed it was authenticated.
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(&Hysteria2Protocol::encode_tcp_request(
            &TargetAddress::domain("forbidden.example", 443),
        ))
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        assert!(
            disp.streams.lock().is_empty(),
            "an unauthenticated 0x401 stream reached the dispatcher"
        );
    }

    // -- request header ---------------------------------------------------

    #[test]
    fn request_header_accepts_both_commands_and_every_family() {
        for target in [
            "1.2.3.4:443".parse::<TargetAddress>().unwrap(),
            "[2606:4700::1111]:53".parse().unwrap(),
            TargetAddress::domain("example.com", 8443),
        ] {
            for command in [HYSTERIA2_CMD_TCP, HYSTERIA2_CMD_UDP] {
                let header = request_header(command, &target);
                assert_eq!(
                    parse_request_header(&header),
                    HeaderParse::Complete(target.clone()),
                    "command {command}"
                );
            }
        }
    }

    #[test]
    fn request_header_reports_the_exact_number_of_bytes_needed() {
        for header in [
            request_header(HYSTERIA2_CMD_TCP, &"1.2.3.4:1".parse().unwrap()),
            request_header(HYSTERIA2_CMD_UDP, &"[::1]:1".parse().unwrap()),
            request_header(HYSTERIA2_CMD_TCP, &TargetAddress::domain("example.com", 1)),
        ] {
            for n in 0..header.len() {
                match parse_request_header(&header[..n]) {
                    HeaderParse::NeedMore(needed) => {
                        assert!(needed > n && needed <= HY2_MAX_REQUEST_HEADER_LEN);
                    }
                    other => panic!("prefix {n} gave {other:?}"),
                }
            }
        }
    }

    #[test]
    fn request_header_rejects_an_unknown_command() {
        // Previously any command that was not UDP was silently treated as TCP.
        for command in [0u8, 3, 0xff] {
            let mut header = request_header(HYSTERIA2_CMD_TCP, &"1.2.3.4:1".parse().unwrap());
            header[0] = command;
            assert_eq!(
                parse_request_header(&header),
                HeaderParse::Invalid("unknown request command"),
                "command {command} must be refused"
            );
        }
    }

    #[test]
    fn request_header_rejects_an_unknown_address_type() {
        let mut header = request_header(HYSTERIA2_CMD_TCP, &"1.2.3.4:1".parse().unwrap());
        header[3] = 7;
        assert_eq!(
            parse_request_header(&header),
            HeaderParse::Invalid("unknown address type")
        );
    }

    #[test]
    fn request_header_rejects_an_empty_domain() {
        let header = [HYSTERIA2_CMD_TCP, 0x01, 0xbb, 2, 0x00];
        assert_eq!(
            parse_request_header(&header),
            HeaderParse::Invalid("empty domain")
        );
    }

    #[tokio::test]
    async fn request_header_reader_rejects_every_truncation() {
        for header in [
            request_header(HYSTERIA2_CMD_TCP, &"1.2.3.4:1".parse().unwrap()),
            request_header(HYSTERIA2_CMD_UDP, &"[::1]:1".parse().unwrap()),
            request_header(HYSTERIA2_CMD_TCP, &TargetAddress::domain("example.com", 1)),
        ] {
            for n in 0..header.len() {
                let mut cursor = Cursor::new(header[..n].to_vec());
                let got = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read_request_header(&mut cursor, deadline_in(1_000)),
                )
                .await
                .expect("a truncated request header must not hang");
                assert_eq!(got, Err(ReadError::Eof), "prefix {n}");
            }
            let mut cursor = Cursor::new(header.clone());
            assert!(
                read_request_header(&mut cursor, deadline_in(1_000))
                    .await
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn request_header_reader_times_out_on_a_silent_peer() {
        // The layered handshake used to read every field with no deadline at
        // all; this is the slow-loris that fix closed.
        // The outer timeouts are the check: with the fix the inner deadline
        // fires first and each read returns; without it they hang.
        let mut silent = Silent;
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_request_header(&mut silent, deadline_in(50)),
        )
        .await
        .expect("the request-header read must give up at its own deadline, not hang");
        assert_eq!(got, Err(ReadError::Timeout));

        let mut silent = Silent;
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_exact_until(&mut silent, &mut [0u8; 3], deadline_in(50)),
        )
        .await
        .expect("the AUTH-header read must give up at its own deadline, not hang");
        assert_eq!(got, Err(ReadError::Timeout));
    }

    // -- UDP datagram framing ---------------------------------------------

    #[test]
    fn datagram_parses_a_well_formed_frame() {
        let frame = udp_frame(7, 42, "example.com:53", b"dns-query");
        let parsed = parse_udp_datagram(&frame).unwrap();
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.packet_id, 42);
        assert_eq!(parsed.target, TargetAddress::domain("example.com", 53));
        assert_eq!(parsed.payload, b"dns-query");
    }

    #[test]
    fn datagram_rejects_every_truncation_of_the_header() {
        let dest = "1.2.3.4:53";
        let frame = udp_frame(1, 2, dest, b"abc");
        // Everything up to the end of the destination is a truncation. Beyond
        // that point a prefix is a *valid* frame with a shorter payload: the
        // payload is "the rest of the datagram", so there is nothing to check
        // there and no way to distinguish it from a short datagram.
        let dest_end = 9 + dest.len();
        for n in 0..dest_end {
            assert!(
                parse_udp_datagram(&frame[..n]).is_err(),
                "prefix {n} of {dest_end} was accepted"
            );
        }
        // From here on the frame is well-formed; the payload is just shorter.
        for n in dest_end..=frame.len() {
            let parsed = parse_udp_datagram(&frame[..n]).expect("payload tail is not framed");
            assert_eq!(parsed.payload.len(), n - dest_end);
        }
    }

    #[test]
    fn datagram_rejects_a_declared_destination_length_beyond_the_datagram() {
        // The varint says 100 bytes of destination, the datagram ends first.
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1]);
        Hysteria2Protocol::put_quic_varint(100, &mut frame);
        frame.extend_from_slice(b"short");
        assert_eq!(
            parse_udp_datagram(&frame),
            Err("declared destination length runs past the datagram")
        );
    }

    #[test]
    fn datagram_accepts_a_two_byte_destination_length() {
        // A destination of 64 bytes or more is encoded with a 2-byte varint.
        // The old parser only accepted a single raw byte under 0x40 and
        // silently dropped every such datagram.
        let dest = format!("{}.example.com:443", "a".repeat(60));
        assert!(dest.len() >= 64, "test premise");
        let frame = udp_frame(9, 1, &dest, b"x");
        let parsed = parse_udp_datagram(&frame).unwrap();
        assert_eq!(
            parsed.target,
            TargetAddress::domain(&dest[..dest.len() - 4], 443)
        );
        assert_eq!(parsed.payload, b"x");
    }

    #[test]
    fn datagram_rejects_an_unreasonable_destination_length() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1]);
        Hysteria2Protocol::put_quic_varint(MAX_HY2_ADDR_LEN + 1, &mut frame);
        frame.resize(frame.len() + (MAX_HY2_ADDR_LEN as usize + 1), b'a');
        assert_eq!(
            parse_udp_datagram(&frame),
            Err("destination length exceeds the limit")
        );
    }

    #[test]
    fn datagram_rejects_bad_fragment_counts() {
        let base = udp_frame(1, 0, "1.2.3.4:53", b"x");
        for (frag_id, frag_total, want) in [
            (0u8, 0u8, "fragment count of zero"),
            (1, 1, "fragment index outside the fragment count"),
            (3, 3, "fragment index outside the fragment count"),
            (2, 3, "fragmented datagrams are not supported"),
            (0, 2, "fragmented datagrams are not supported"),
            (1, 2, "fragmented datagrams are not supported"),
        ] {
            let mut frame = base.clone();
            frame[6] = frag_id;
            frame[7] = frag_total;
            assert_eq!(
                parse_udp_datagram(&frame),
                Err(want),
                "{frag_id}/{frag_total}"
            );
        }
    }

    #[test]
    fn datagram_keeps_a_zero_length_payload() {
        // An empty UDP payload is legal; it must not be mistaken for EOF.
        let frame = udp_frame(4, 5, "1.2.3.4:53", b"");
        let parsed = parse_udp_datagram(&frame).unwrap();
        assert!(parsed.payload.is_empty());
        assert_eq!(
            parsed.target,
            "1.2.3.4:53".parse::<TargetAddress>().unwrap()
        );
    }

    #[test]
    fn datagram_rejects_an_oversized_frame() {
        let mut frame = udp_frame(1, 0, "1.2.3.4:53", b"x");
        frame.resize(MAX_UDP_DATAGRAM + 1, 0);
        assert_eq!(
            parse_udp_datagram(&frame),
            Err("framed datagram exceeds the maximum size")
        );
    }

    #[test]
    fn datagram_rejects_a_destination_that_is_not_an_address() {
        for dest in ["", "no-port", "example.com:notaport", "::::"] {
            let frame = udp_frame(1, 0, dest, b"x");
            assert!(
                parse_udp_datagram(&frame).is_err(),
                "destination {dest:?} must be refused"
            );
        }
    }

    #[test]
    fn datagram_rejects_invalid_utf8_in_the_destination() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1]);
        frame.push(3); // 3-byte destination
        frame.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        assert_eq!(
            parse_udp_datagram(&frame),
            Err("destination is not valid UTF-8")
        );
    }

    #[test]
    fn replies_round_trip_through_the_parser() {
        // Proves the encoder and decoder agree for every destination length,
        // including the ones the old single-byte encoder truncated.
        for dest in [
            "1.2.3.4:53".to_string(),
            "[2606:4700::1111]:443".to_string(),
            format!("{}.example.com:8443", "b".repeat(120)),
        ] {
            let payload: Vec<u8> = (0..=255u8).cycle().take(100).collect();
            let frame = build_udp_reply(0xDEAD_BEEF, 9, &dest, &payload);
            let parsed = parse_udp_datagram(&frame).unwrap();
            assert_eq!(parsed.session_id, 0xDEAD_BEEF);
            assert_eq!(parsed.packet_id, 9);
            assert_eq!(parsed.target, dest.parse::<TargetAddress>().unwrap());
            assert_eq!(parsed.payload, payload);
        }
    }

    #[test]
    fn reply_destination_length_is_a_varint() {
        let dest = format!("{}.example.com", "c".repeat(120));
        let frame = build_udp_reply(1, 0, &dest, b"");
        // Bytes 8.. are the varint length; 120 needs the two-byte form.
        assert_eq!(frame[8], 0x40 | ((dest.len() >> 8) as u8), "{}", frame[8]);
        assert_eq!(frame[9], dest.len() as u8);
        assert_eq!(read_varint(&frame[8..]), Some((dest.len() as u64, 2)));
    }

    #[test]
    fn varint_reader_rejects_truncated_prefixes() {
        assert_eq!(read_varint(&[]), None);
        // 2-byte prefix with only one byte present.
        assert_eq!(read_varint(&[0x41]), None);
        // 4-byte prefix with two bytes present.
        assert_eq!(read_varint(&[0x80, 0x01]), None);
        assert_eq!(read_varint(&[0x3f]), Some((63, 1)));
        assert_eq!(read_varint(&[0x41, 0x00]), Some((256, 2)));
        assert_eq!(read_varint(&[0x80, 0x00, 0x00, 0x01]), Some((1, 4)));
    }

    // -- congestion-control knob ------------------------------------------

    #[test]
    fn client_declared_rate_is_bounded() {
        // A client must not be able to declare an absurd rate, and the parse
        // must not panic on junk.
        assert_eq!(parse_client_cc_rx(Some("0")), 0);
        assert_eq!(parse_client_cc_rx(Some("100")), 100);
        assert_eq!(parse_client_cc_rx(Some("1000000000")), MAX_HY2_CC_RX);
        assert_eq!(
            parse_client_cc_rx(Some("18446744073709551615")),
            MAX_HY2_CC_RX
        );
        assert_eq!(parse_client_cc_rx(Some("-1")), 0);
        assert_eq!(parse_client_cc_rx(Some("")), 0);
        assert_eq!(parse_client_cc_rx(Some("12.5")), 0);
        assert_eq!(parse_client_cc_rx(Some("nan")), 0);
        assert_eq!(parse_client_cc_rx(Some(" 42 ")), 42);
        assert_eq!(parse_client_cc_rx(None), 0);
        // The bound is far below the point where a unit conversion or a
        // line-rate pacer's 100 ms burst arithmetic could overflow.
        assert!(MAX_HY2_CC_RX.saturating_mul(1_000_000) < u64::MAX / 2);
    }

    // -- shared association table (hy2 keys on a 32-bit id) ---------------

    #[test]
    fn association_table_caps_a_32_bit_id_space() {
        let table: Arc<UdpAssocTable<u32>> = UdpAssocTable::new(2);
        let tx = || tokio::sync::mpsc::channel::<UdpPacket>(1).0;
        assert_eq!(table.open(0, tx()), OpenResult::Inserted);
        assert_eq!(table.open(u32::MAX, tx()), OpenResult::Inserted);
        // The id space is 4 billion wide; the cap is what protects memory.
        assert_eq!(table.open(12345, tx()), OpenResult::AtCapacity);
        assert!(table.remove(&0));
        assert_eq!(table.open(12345, tx()), OpenResult::Inserted);
    }
}
