//! Stream multiplexing: **xtaci/smux v1**, as spoken by sing-box's
//! `"multiplex": { "protocol": "smux" }`.
//!
//! The wire format below was verified byte-for-byte against sing-box 1.11.4
//! (`sagernet/sing-mux` v0.3.1 + `sagernet/smux`); see the byte captures quoted
//! in the comments and the interop suite in `tests/test_mux_interop.rs`.
//!
//! ## Session preface (client -> server, immediately after the proxy header)
//!
//! ```text
//! +---------+----------+                          (one byte each)
//! | version | protocol |
//! +---------+----------+
//! version 1 only:
//! +---------+--------+-----------------+-------------------+
//! | padding | padlen | (padlen bytes)  |                   |
//! +---------+--------+-----------------+-------------------+
//! ```
//!
//! * `version`: 0 = legacy (no padding field), 1 = padding aware.
//! * `protocol`: 0 = smux, 1 = yamux, 2 = h2mux (only smux is implemented).
//! * `padding`: 1 byte, 1 when the client padded the session, followed by a
//!   big-endian `u16` pad length and that many filler bytes.
//!
//! Captured from sing-box (`padding: false`): `00 00`.
//! Captured from sing-box (`padding: true`): `01 00 01 02 24` + 548 zero bytes.
//!
//! When padding is enabled the session connection is additionally wrapped in a
//! *chunk* layer for the first 16 writes of each direction:
//!
//! ```text
//! | data_len: u16 BE | pad_len: u16 BE | data | pad_len filler bytes |
//! ```
//!
//! Captured: `00 08 02 9d 01 00 00 00 03 00 00 00` = chunk(8 bytes of frame,
//! 669 bytes of padding), i.e. the first chunk carried `SYN(stream 3)`.
//!
//! ## Frames
//!
//! Every frame is `[version: u8][cmd: u8][length: u16][stream_id: u32][payload]`
//! with **little endian** `length` and `stream_id` (8 byte header); this is
//! `sagernet/smux`'s `rawHeader`, not the big-endian variant some smux ports
//! use. Commands: `SYN=0`, `FIN=1`, `PSH=2`, `NOP=3`, `UPD=4`.
//!
//! Captured PSH carrying 27 bytes of HTTP request:
//! `01 02 1b 00 03 00 00 00` = ver 1, cmd PSH, len 27, stream 3.
//!
//! The *client* opens odd stream ids and the reference implementation starts at
//! 3 (`smux` pre-increments its counter); the server opens even ids. Stream id 0
//! is never valid for data.
//!
//! ## Per-stream protocol
//!
//! The first bytes on a fresh stream are a request:
//!
//! ```text
//! | flags: u16 BE | address (SOCKS5 form) | ...payload... |
//! ```
//!
//! `flags` bit 0 = UDP, bit 1 = "packet address" (per-datagram address prefix).
//! Captured request for 1.1.1.1:80: `00 00 01 01 01 01 01 00 50`.
//!
//! The server answers with a single status byte (`0` = ok, `1` = error followed
//! by a varint length and a message) before the first payload byte. Datagrams on
//! a UDP stream are framed as `[len: u16 BE][payload]`.
//!
//! ## Flow control
//!
//! smux **v1 has no window management at all** (that is v2's `UPD`); `sing-box`
//! sends its smux sessions with `KeepAliveDisabled` and never emits `UPD`. We
//! therefore treat the peer window as unlimited by default, but still parse
//! `UPD` frames and honour the advertised window when a (v2-style) peer sends
//! one, and we bound what a single stream may buffer so a slow consumer cannot
//! stall the shared reader.

use bytes::{Buf, Bytes, BytesMut};
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, NetworkType, PacketEndpoint, SessionMeta,
    StreamDialer, TargetAddress, UdpPacket,
};
use parking_lot::Mutex as PlMutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, Notify, mpsc};
use tracing::{debug, trace, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reserved destination that marks a connection as a multiplexed session.
///
/// This is the same pseudo-address sing-box uses (`sing-mux.Destination`), so
/// either side can detect "this authenticated connection carries smux frames".
pub const MUX_DESTINATION_FQDN: &str = "sp.mux.sing-box.arpa";
pub const MUX_DESTINATION_PORT: u16 = 444;

/// smux protocol version spoken on the wire.
pub const SMUX_VERSION: u8 = 1;
/// Frame header size in bytes.
pub const FRAME_HEADER_LEN: usize = 8;

pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;
pub const CMD_UPD: u8 = 4;

/// Preface version 0 (legacy, no padding field).
const PREFACE_VERSION_0: u8 = 0;
/// Preface version 1 (carries the padding flag).
const PREFACE_VERSION_1: u8 = 1;
/// Preface protocol id for smux.
const PREFACE_PROTOCOL_SMUX: u8 = 0;

/// How many writes each direction is wrapped in the padding chunk layer.
const PADDING_CHUNKS: u32 = 16;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const STREAM_FLAG_UDP: u16 = 1;
const STREAM_FLAG_PACKET_ADDR: u16 = 2;

/// First stream id a client opens (mirrors the reference client, which
/// pre-increments its counter).
const FIRST_CLIENT_STREAM_ID: u32 = 3;
/// First stream id a server opens.
const FIRST_SERVER_STREAM_ID: u32 = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn smux_err(message: impl Into<String>) -> FluxError {
    FluxError::Protocol {
        protocol: "smux",
        message: message.into(),
    }
}

fn smux_io(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Multiplex protocol. Only `smux` exists today; yamux/h2mux are signalled on
/// the wire but not implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxProtocol {
    Smux,
}

impl MuxProtocol {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "smux" => Some(Self::Smux),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smux => "smux",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Smux => PREFACE_PROTOCOL_SMUX,
        }
    }
}

/// Runtime multiplex settings shared by the client and server halves.
#[derive(Clone, Debug)]
pub struct MuxConfig {
    pub protocol: MuxProtocol,
    /// Streams per session. The client treats it as a pooling target (it opens
    /// another session, then reuses the least loaded one); the server enforces
    /// it as a hard per-session cap so one peer cannot exhaust resources.
    /// `0` disables the limit.
    pub max_streams: u32,
    /// Maximum physical sessions the client keeps in its pool.
    pub max_connections: u32,
    /// Client: pad the session preface and the first writes.
    /// Server: require the peer to pad (`sing-box`'s inbound semantics).
    pub padding: bool,
    /// Largest PSH payload we emit; also bounds the reader's frame buffer.
    /// 64 KiB is the maximum a `u16` length can express.
    pub max_frame_size: usize,
    /// Bytes a single stream may buffer before it is reset.
    pub max_buffered_bytes: usize,
    /// NOP keepalive interval (`None` disables it).
    pub keepalive: Option<Duration>,
    /// Close a session that has had no streams and no frames for this long.
    pub idle_timeout: Option<Duration>,
    /// Timeout for the session preface / stream request handshake.
    pub handshake_timeout: Duration,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            protocol: MuxProtocol::Smux,
            max_streams: 128,
            max_connections: 4,
            padding: false,
            max_frame_size: 65_535,
            max_buffered_bytes: 512 * 1024,
            keepalive: Some(Duration::from_secs(30)),
            idle_timeout: Some(Duration::from_secs(300)),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl MuxConfig {
    /// Bounded per-stream frame queue depth derived from the byte budget.
    fn queue_capacity(&self) -> usize {
        (self.max_buffered_bytes / self.max_frame_size.max(1)).clamp(2, 1024)
    }

    fn frame_size(&self) -> usize {
        self.max_frame_size.clamp(1, u16::MAX as usize)
    }

    /// Validates the settings, returning a config error instead of panicking.
    pub fn validate(&self) -> FluxResult<()> {
        if self.max_frame_size == 0 {
            return Err(FluxError::Config(
                "multiplex: max_frame_size must be greater than 0".into(),
            ));
        }
        if self.max_buffered_bytes < self.frame_size() {
            return Err(FluxError::Config(
                "multiplex: max_buffered_bytes must be at least max_frame_size".into(),
            ));
        }
        Ok(())
    }
}

/// The pseudo destination that opens a multiplexed session.
pub fn mux_destination() -> TargetAddress {
    TargetAddress::domain(MUX_DESTINATION_FQDN, MUX_DESTINATION_PORT)
}

/// Whether `address` is the multiplex pseudo destination.
pub fn is_mux_destination(address: &TargetAddress) -> bool {
    match address {
        TargetAddress::Domain(host, port) => {
            host.eq_ignore_ascii_case(MUX_DESTINATION_FQDN) && *port == MUX_DESTINATION_PORT
        }
        TargetAddress::Ip(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// A decoded smux frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub cmd: u8,
    pub length: u16,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn new(cmd: u8, stream_id: u32, length: u16) -> Self {
        Self {
            version: SMUX_VERSION,
            cmd,
            length,
            stream_id,
        }
    }

    /// Serialises the header (little endian length/stream id, like smux).
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0] = self.version;
        out[1] = self.cmd;
        out[2..4].copy_from_slice(&self.length.to_le_bytes());
        out[4..8].copy_from_slice(&self.stream_id.to_le_bytes());
        out
    }

    /// Parses a header, rejecting unknown versions and commands.
    pub fn decode(bytes: &[u8; FRAME_HEADER_LEN]) -> FluxResult<Self> {
        if bytes[0] != SMUX_VERSION {
            return Err(smux_err(format!(
                "unsupported frame version {} (expected {})",
                bytes[0], SMUX_VERSION
            )));
        }
        let header = Self {
            version: bytes[0],
            cmd: bytes[1],
            length: u16::from_le_bytes([bytes[2], bytes[3]]),
            stream_id: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        };
        if header.cmd > CMD_UPD {
            return Err(smux_err(format!("unknown frame command {}", header.cmd)));
        }
        Ok(header)
    }
}

// ---------------------------------------------------------------------------
// Session internals
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// Events delivered from the session reader to one stream.
enum StreamEvent {
    Data(Bytes),
    Fin,
}

struct OutFrame {
    stream_id: u32,
    cmd: u8,
    payload: Bytes,
}

struct PendingAccept {
    stream_id: u32,
    rx: mpsc::Receiver<StreamEvent>,
}

struct Shared {
    config: MuxConfig,
    role: Role,
    out_tx: mpsc::Sender<OutFrame>,
    streams: PlMutex<HashMap<u32, mpsc::Sender<StreamEvent>>>,
    next_id: AtomicU32,
    open_streams: AtomicUsize,
    closed: AtomicBool,
    shutdown: Notify,
    last_activity_ms: AtomicU64,
    /// Send credit advertised by a `UPD`-sending (v2-style) peer. `i64::MAX`
    /// means "no window" (plain smux v1), which is what sing-box speaks.
    peer_window: AtomicI64,
    /// Wakes writers when the peer advertises more window.
    credit_ready: Notify,
    /// Wakes writers when a slot in the frame queue frees up.
    out_ready: Notify,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Shared {
    fn touch(&self) {
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self, reason: &str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        debug!("smux: closing session: {}", reason);
        // Dropping the senders makes every stream reader observe EOF.
        self.streams.lock().clear();
        self.shutdown.notify_waiters();
    }

    fn try_send_frame(&self, stream_id: u32, cmd: u8, payload: Bytes) -> bool {
        self.out_tx
            .try_send(OutFrame {
                stream_id,
                cmd,
                payload,
            })
            .is_ok()
    }

    fn allocate_id(&self) -> u32 {
        self.next_id.fetch_add(2, Ordering::SeqCst)
    }

    fn register(&self, stream_id: u32, tx: mpsc::Sender<StreamEvent>) {
        self.streams.lock().insert(stream_id, tx);
        self.open_streams.fetch_add(1, Ordering::Relaxed);
    }

    fn unregister(&self, stream_id: u32) {
        if self.streams.lock().remove(&stream_id).is_some() {
            self.open_streams.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// One multiplexed physical connection.
pub struct MuxSession {
    shared: Arc<Shared>,
    tasks: PlMutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        self.shared.close("session dropped");
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
    }
}

impl MuxSession {
    /// Whether the session can still carry new streams.
    pub fn is_alive(&self) -> bool {
        !self.shared.is_closed()
    }

    /// Whether the session is below its stream cap.
    fn has_capacity(&self) -> bool {
        let max = self.shared.config.max_streams as usize;
        max == 0 || self.shared.open_streams.load(Ordering::Relaxed) < max
    }

    /// Opens a new stream (sends `SYN`).
    pub async fn open_stream(&self) -> FluxResult<MuxStream> {
        if self.shared.is_closed() {
            return Err(smux_err("session closed"));
        }
        if !self.has_capacity() {
            return Err(smux_err("stream limit reached on this session"));
        }
        let stream_id = self.shared.allocate_id();
        let (tx, rx) = mpsc::channel(self.shared.config.queue_capacity());
        self.shared.register(stream_id, tx);
        if !self.shared.try_send_frame(stream_id, CMD_SYN, Bytes::new()) {
            self.shared.unregister(stream_id);
            return Err(smux_err("failed to queue SYN frame"));
        }
        Ok(MuxStream::new(
            stream_id,
            self.shared.clone(),
            rx,
            Role::Client,
        ))
    }

    fn from_parts(shared: Arc<Shared>, tasks: Vec<tokio::task::JoinHandle<()>>) -> Arc<Self> {
        Arc::new(Self {
            shared,
            tasks: PlMutex::new(tasks),
        })
    }

    /// Builds the client half of a session over an already authenticated
    /// transport stream, writing the session preface first.
    pub async fn connect(conn: BoxedStream, config: MuxConfig) -> FluxResult<Arc<MuxSession>> {
        config.validate()?;
        let mut conn = conn;
        let mut preface = Vec::with_capacity(8);
        if config.padding {
            preface.push(PREFACE_VERSION_1);
            preface.push(config.protocol.code());
            preface.push(1);
            let mut filler = vec![0u8; 256 + (now_ms() as usize % 512)];
            // Randomised filler like the reference implementation.
            for byte in filler.iter_mut() {
                *byte = rand::random::<u8>();
            }
            preface.extend_from_slice(&(filler.len() as u16).to_be_bytes());
            preface.extend_from_slice(&filler);
        } else {
            preface.push(PREFACE_VERSION_0);
            preface.push(config.protocol.code());
        }
        conn.write_all(&preface)
            .await
            .map_err(|e| smux_err(format!("failed to write session preface: {e}")))?;
        conn.flush()
            .await
            .map_err(|e| smux_err(format!("failed to flush session preface: {e}")))?;

        let conn: BoxedStream = if config.padding {
            Box::new(PaddingStream::new(conn))
        } else {
            conn
        };
        Ok(Self::start(conn, config, Role::Client, None))
    }

    fn start(
        conn: BoxedStream,
        config: MuxConfig,
        role: Role,
        accepts_tx: Option<mpsc::Sender<PendingAccept>>,
    ) -> Arc<MuxSession> {
        let (read_half, write_half) = tokio::io::split(conn);
        let (out_tx, out_rx) = mpsc::channel::<OutFrame>(64);
        let shared = Arc::new(Shared {
            config: config.clone(),
            role,
            out_tx,
            streams: PlMutex::new(HashMap::new()),
            next_id: AtomicU32::new(match role {
                Role::Client => FIRST_CLIENT_STREAM_ID,
                Role::Server => FIRST_SERVER_STREAM_ID,
            }),
            open_streams: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            shutdown: Notify::new(),
            last_activity_ms: AtomicU64::new(now_ms()),
            peer_window: AtomicI64::new(i64::MAX),
            credit_ready: Notify::new(),
            out_ready: Notify::new(),
        });
        let reader = tokio::spawn(reader_loop(shared.clone(), read_half, accepts_tx));
        let writer = tokio::spawn(writer_loop(shared.clone(), write_half, out_rx));
        Self::from_parts(shared, vec![reader, writer])
    }
}

// ---------------------------------------------------------------------------
// Session reader
// ---------------------------------------------------------------------------

async fn reader_loop(
    shared: Arc<Shared>,
    mut read_half: ReadHalf<BoxedStream>,
    accepts_tx: Option<mpsc::Sender<PendingAccept>>,
) {
    loop {
        if shared.is_closed() {
            return;
        }
        let mut header_bytes = [0u8; FRAME_HEADER_LEN];
        let mut filled = 0;
        while filled < FRAME_HEADER_LEN {
            let idle = shared.config.idle_timeout;
            let idle_enabled = idle.is_some() && shared.open_streams.load(Ordering::Relaxed) == 0;
            let read = read_half.read(&mut header_bytes[filled..]);
            tokio::pin!(read);
            let idle_sleep = tokio::time::sleep(idle.unwrap_or(Duration::from_secs(3600)));
            tokio::pin!(idle_sleep);
            tokio::select! {
                result = &mut read => match result {
                    Ok(0) => {
                        shared.close("peer closed the connection");
                        return;
                    }
                    Ok(n) => {
                        filled += n;
                        shared.touch();
                    }
                    Err(e) => {
                        shared.close(&format!("read error: {e}"));
                        return;
                    }
                },
                _ = shared.shutdown.notified() => return,
                _ = &mut idle_sleep, if idle_enabled => {
                    shared.close("idle session timeout");
                    return;
                }
            }
        }

        let header = match FrameHeader::decode(&header_bytes) {
            Ok(header) => header,
            Err(e) => {
                shared.close(&format!("malformed frame header: {e}"));
                return;
            }
        };
        trace!(
            "smux: rx cmd={} sid={} len={}",
            header.cmd, header.stream_id, header.length
        );

        let mut payload = BytesMut::new();
        if header.length > 0 {
            if header.cmd != CMD_PSH && header.cmd != CMD_UPD {
                shared.close(&format!(
                    "control frame {} carried {} payload bytes",
                    header.cmd, header.length
                ));
                return;
            }
            payload.resize(header.length as usize, 0);
            // A frame that never completes must not pin the connection (and its
            // buffer) forever.
            let payload_deadline = shared
                .config
                .idle_timeout
                .unwrap_or(Duration::from_secs(300));
            match tokio::time::timeout(payload_deadline, read_half.read_exact(&mut payload)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    shared.close(&format!("failed to read frame payload: {e}"));
                    return;
                }
                Err(_) => {
                    shared.close("timed out reading a frame payload");
                    return;
                }
            }
            shared.touch();
        }
        let payload = payload.freeze();

        match header.cmd {
            CMD_PSH => {
                if header.stream_id == 0 {
                    shared.close("peer sent data on stream 0");
                    return;
                }
                if payload.is_empty() {
                    continue;
                }
                let sink = shared.streams.lock().get(&header.stream_id).cloned();
                let Some(sink) = sink else {
                    // Stream already gone (client closed it): drop the data,
                    // matching smux.
                    continue;
                };
                match sink.try_send(StreamEvent::Data(payload)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // A stalled consumer must not stall every other stream:
                        // reset only this stream.
                        warn!(
                            "smux: stream {} exceeded its receive buffer, resetting it",
                            header.stream_id
                        );
                        shared.try_send_frame(header.stream_id, CMD_FIN, Bytes::new());
                        shared.unregister(header.stream_id);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        shared.unregister(header.stream_id);
                    }
                }
            }
            CMD_SYN => {
                if shared.role == Role::Server {
                    if let Some(accepts) = &accepts_tx {
                        handle_syn(&shared, &header, accepts);
                    }
                } else {
                    shared.close(&format!(
                        "peer opened stream {} but is not a server",
                        header.stream_id
                    ));
                    return;
                }
            }
            CMD_FIN => {
                let sink = shared.streams.lock().get(&header.stream_id).cloned();
                if let Some(sink) = sink
                    && let Err(mpsc::error::TrySendError::Full(_)) =
                        sink.clone().try_send(StreamEvent::Fin)
                {
                    // Deliver the EOF once the consumer drains its buffer.
                    tokio::spawn(async move {
                        let _ = sink.send(StreamEvent::Fin).await;
                    });
                }
            }
            CMD_NOP => {
                // Heartbeat: nothing to do beyond refreshing liveness.
            }
            CMD_UPD => {
                apply_window_update(&shared, &payload);
            }
            _ => unreachable!("FrameHeader::decode rejects unknown commands"),
        }
    }
}

fn handle_syn(shared: &Arc<Shared>, header: &FrameHeader, accepts: &mpsc::Sender<PendingAccept>) {
    let stream_id = header.stream_id;
    if stream_id == 0 {
        shared.close("peer opened stream 0");
        return;
    }
    if stream_id.is_multiple_of(2) {
        // Clients own odd ids; a server must never open one towards itself.
        shared.close(&format!("peer opened even stream id {}", stream_id));
        return;
    }
    let max = shared.config.max_streams as usize;
    if max > 0 && shared.open_streams.load(Ordering::Relaxed) >= max {
        warn!("smux: rejecting stream {}: stream limit reached", stream_id);
        shared.try_send_frame(stream_id, CMD_FIN, Bytes::new());
        return;
    }
    let (tx, rx) = mpsc::channel(shared.config.queue_capacity());
    {
        let mut streams = shared.streams.lock();
        if streams.contains_key(&stream_id) {
            // Duplicate SYN: ignore, like smux.
            return;
        }
        streams.insert(stream_id, tx);
        shared.open_streams.fetch_add(1, Ordering::Relaxed);
    }
    if accepts.try_send(PendingAccept { stream_id, rx }).is_err() {
        warn!("smux: accept backlog full, rejecting stream {}", stream_id);
        shared.try_send_frame(stream_id, CMD_FIN, Bytes::new());
        shared.unregister(stream_id);
    }
}

fn apply_window_update(shared: &Arc<Shared>, payload: &Bytes) {
    // smux v2: | consumed: u32 BE | window: u32 BE |
    if payload.len() != 8 {
        return;
    }
    let window = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as i64;
    // The advertised window is treated as the remaining send credit for the
    // session. smux v2 tracks this per stream; sing-box never sends UPD for
    // v1 sessions, so this only matters for v2-style peers and tests.
    shared.peer_window.store(window, Ordering::Release);
    shared.credit_ready.notify_waiters();
    trace!("smux: peer advertised window {}", window);
}

// ---------------------------------------------------------------------------
// Session writer
// ---------------------------------------------------------------------------

async fn writer_loop(
    shared: Arc<Shared>,
    mut write_half: WriteHalf<BoxedStream>,
    mut out_rx: mpsc::Receiver<OutFrame>,
) {
    let mut buffer = BytesMut::with_capacity(64 * 1024);
    let keepalive = shared.config.keepalive.filter(|d| !d.is_zero());
    let mut ticker = tokio::time::interval(keepalive.unwrap_or(Duration::from_secs(3600)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval` fires immediately; the session is alive already.
    ticker.tick().await;

    loop {
        let first = tokio::select! {
            frame = out_rx.recv() => match frame {
                Some(frame) => frame,
                None => {
                    shared.close("writer channel closed");
                    return;
                }
            },
            _ = shared.shutdown.notified() => return,
            _ = ticker.tick(), if keepalive.is_some() => {
                if shared.try_send_frame(0, CMD_NOP, Bytes::new()) {
                    continue;
                }
                continue;
            }
        };

        shared.out_ready.notify_one();
        buffer.clear();
        push_frame(&mut buffer, &first);
        // Coalesce everything already queued into a single write.
        while let Ok(frame) = out_rx.try_recv() {
            push_frame(&mut buffer, &frame);
            shared.out_ready.notify_one();
            if buffer.len() >= 32 * 1024 {
                break;
            }
        }

        if let Err(e) = write_half.write_all(&buffer).await {
            shared.close(&format!("write error: {e}"));
            return;
        }
        if let Err(e) = write_half.flush().await {
            shared.close(&format!("flush error: {e}"));
            return;
        }
        shared.touch();
    }
}

fn push_frame(buffer: &mut BytesMut, frame: &OutFrame) {
    let length = frame.payload.len().min(u16::MAX as usize);
    let header = FrameHeader::new(frame.cmd, frame.stream_id, length as u16);
    buffer.extend_from_slice(&header.encode());
    if length > 0 {
        buffer.extend_from_slice(&frame.payload[..length]);
    }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handshake {
    /// Waiting for the server status byte.
    Status,
    /// Reading the varint error length.
    Length,
    /// Reading the error message body.
    Message(usize),
    Done,
}

/// State of the client-side response handshake.
struct HandshakeState {
    state: Handshake,
    shift: u32,
    accum: u64,
    message: Vec<u8>,
}

impl HandshakeState {
    fn new(role: Role) -> Self {
        Self {
            state: if role == Role::Client {
                Handshake::Status
            } else {
                Handshake::Done
            },
            shift: 0,
            accum: 0,
            message: Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        self.state == Handshake::Done
    }
}

/// One multiplexed byte stream; implements the project's `BoxedStream` bounds.
pub struct MuxStream {
    stream_id: u32,
    shared: Arc<Shared>,
    rx: mpsc::Receiver<StreamEvent>,
    role: Role,
    handshake: HandshakeState,
    status_sent: bool,
    read_buf: Bytes,
    remote_eof: bool,
    write_closed: bool,
    fin_sent: bool,
}

impl MuxStream {
    fn new(
        stream_id: u32,
        shared: Arc<Shared>,
        rx: mpsc::Receiver<StreamEvent>,
        role: Role,
    ) -> Self {
        Self {
            stream_id,
            shared,
            rx,
            role,
            handshake: HandshakeState::new(role),
            status_sent: false,
            read_buf: Bytes::new(),
            remote_eof: false,
            write_closed: false,
            fin_sent: false,
        }
    }

    /// Stream identifier on the session.
    pub fn id(&self) -> u32 {
        self.stream_id
    }

    /// Sends the positive status byte a server must emit before payload.
    pub async fn accept_ok(&mut self) -> FluxResult<()> {
        if self.role != Role::Server || self.status_sent {
            return Ok(());
        }
        self.status_sent = true;
        self.write_all(&[0u8])
            .await
            .map_err(|e| smux_err(format!("failed to send stream status: {e}")))?;
        self.flush()
            .await
            .map_err(|e| smux_err(format!("failed to flush stream status: {e}")))
    }

    /// Sends the negative status byte (with a message) then closes the stream.
    pub async fn reject(&mut self, message: &str) -> FluxResult<()> {
        if self.role != Role::Server || self.status_sent {
            return Ok(());
        }
        self.status_sent = true;
        let mut payload = Vec::with_capacity(8 + message.len());
        payload.push(1u8);
        write_uvarint(&mut payload, message.len() as u64);
        payload.extend_from_slice(message.as_bytes());
        self.write_all(&payload)
            .await
            .map_err(|e| smux_err(format!("failed to send stream error: {e}")))?;
        let _ = self.flush().await;
        let _ = self.shutdown_stream();
        Ok(())
    }

    /// Reads the `[flags][address]` request that opens a muxed stream.
    pub async fn read_request(&mut self) -> FluxResult<StreamRequest> {
        let flags = self
            .read_u16()
            .await
            .map_err(|e| smux_err(format!("failed to read stream request flags: {e}")))?;
        let packet_addr = flags & STREAM_FLAG_PACKET_ADDR != 0;
        let destination = read_socksaddr(self).await?;
        let network = if flags & STREAM_FLAG_UDP != 0 {
            NetworkType::Udp
        } else {
            NetworkType::Tcp
        };
        Ok(StreamRequest {
            destination,
            network,
            packet_addr,
        })
    }

    fn poll_next_event(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(StreamEvent::Data(data))) => {
                self.read_buf = data;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Some(StreamEvent::Fin)) => {
                self.remote_eof = true;
                Poll::Ready(Ok(false))
            }
            Poll::Ready(None) => {
                self.remote_eof = true;
                Poll::Ready(Ok(false))
            }
        }
    }

    /// Consumes buffered bytes for the client-side response handshake.
    fn advance_handshake(&mut self) -> std::io::Result<()> {
        loop {
            match self.handshake.state {
                Handshake::Done => return Ok(()),
                Handshake::Status => {
                    if self.read_buf.is_empty() {
                        return Ok(());
                    }
                    let status = self.read_buf[0];
                    self.read_buf.advance(1);
                    if status == 0 {
                        self.handshake.state = Handshake::Done;
                        return Ok(());
                    }
                    if status != 1 {
                        return Err(smux_io(format!(
                            "unexpected mux stream status byte {status}"
                        )));
                    }
                    self.handshake.state = Handshake::Length;
                    self.handshake.shift = 0;
                    self.handshake.accum = 0;
                }
                Handshake::Length => {
                    while !self.read_buf.is_empty() {
                        let byte = self.read_buf[0];
                        self.read_buf.advance(1);
                        self.handshake.accum |= u64::from(byte & 0x7f) << self.handshake.shift;
                        if byte & 0x80 == 0 {
                            let len = self.handshake.accum as usize;
                            if len > 8192 {
                                return Err(smux_io("mux error message is too long"));
                            }
                            self.handshake.state = Handshake::Message(len);
                            break;
                        }
                        self.handshake.shift += 7;
                        if self.handshake.shift > 63 {
                            return Err(smux_io("mux error length varint overflow"));
                        }
                    }
                    if self.handshake.state == Handshake::Length {
                        return Ok(());
                    }
                }
                Handshake::Message(len) => {
                    let take = len.saturating_sub(self.handshake.message.len());
                    let take = take.min(self.read_buf.len());
                    if take > 0 {
                        let chunk = self.read_buf.split_to(take);
                        self.handshake.message.extend_from_slice(&chunk);
                    }
                    if self.handshake.message.len() < len {
                        return Ok(());
                    }
                    let message = String::from_utf8_lossy(&self.handshake.message).into_owned();
                    self.handshake.state = Handshake::Done;
                    return Err(smux_io(format!("mux stream rejected: {message}")));
                }
            }
        }
    }

    fn shutdown_stream(&mut self) -> std::io::Result<()> {
        if self.fin_sent {
            return Ok(());
        }
        self.fin_sent = true;
        self.write_closed = true;
        self.shared
            .try_send_frame(self.stream_id, CMD_FIN, Bytes::new());
        // The stream stays registered so the peer may keep sending: FIN is a
        // half close, not a teardown.
        Ok(())
    }
}

/// The request that opens a multiplexed stream.
#[derive(Clone, Debug)]
pub struct StreamRequest {
    pub destination: TargetAddress,
    pub network: NetworkType,
    /// Per-datagram addressing (sing-box's `flagAddr`): every datagram carries
    /// its own destination instead of relying on the stream's.
    pub packet_addr: bool,
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.handshake.is_done() {
                this.advance_handshake()?;
                if !this.handshake.is_done() {
                    if this.remote_eof {
                        return Poll::Ready(Err(smux_io(
                            "mux stream closed before the server status byte",
                        )));
                    }
                    match this.poll_next_event(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(true)) => continue,
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(smux_io(
                                "mux stream closed before the server status byte",
                            )));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
            }

            if !this.read_buf.is_empty() {
                let take = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..take]);
                this.read_buf.advance(take);
                return Poll::Ready(Ok(()));
            }

            if this.remote_eof {
                return Poll::Ready(Ok(()));
            }

            match this.poll_next_event(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed || this.shared.is_closed() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "mux stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(this.shared.config.frame_size());

        // 1. Reserve a slot in the session's frame queue. Doing this before
        //    consuming window credit keeps the accounting exact when a poll
        //    would block halfway through.
        let permit = loop {
            match this.shared.out_tx.try_reserve() {
                Ok(permit) => break permit,
                Err(_) => {
                    if this.shared.is_closed() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "mux session is closed",
                        )));
                    }
                    let notified = this.shared.out_ready.notified();
                    let mut notified = std::pin::pin!(notified);
                    if notified.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                }
            }
        };

        // 2. Consume peer window credit advertised by a UPD-sending peer.
        loop {
            let window = this.shared.peer_window.load(Ordering::Acquire);
            if window == i64::MAX {
                break;
            }
            if window >= take as i64 {
                if this
                    .shared
                    .peer_window
                    .compare_exchange(
                        window,
                        window - take as i64,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break;
                }
                continue;
            }
            let notified = this.shared.credit_ready.notified();
            let mut notified = std::pin::pin!(notified);
            if notified.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }

        permit.send(OutFrame {
            stream_id: this.stream_id,
            cmd: CMD_PSH,
            payload: Bytes::copy_from_slice(&buf[..take]),
        });
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Frames are handed to the session writer, which flushes the socket
        // after every batch.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.shutdown_stream()?;
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        // FIN so the peer learns about the close promptly; if the frame queue
        // is momentarily full, retry from a task instead of dropping it.
        if !self.fin_sent {
            self.fin_sent = true;
            if !self
                .shared
                .try_send_frame(self.stream_id, CMD_FIN, Bytes::new())
                && let Ok(handle) = tokio::runtime::Handle::try_current()
            {
                let shared = self.shared.clone();
                let stream_id = self.stream_id;
                handle.spawn(async move {
                    let _ = shared
                        .out_tx
                        .send(OutFrame {
                            stream_id,
                            cmd: CMD_FIN,
                            payload: Bytes::new(),
                        })
                        .await;
                });
            }
        }
        if self.shared.streams.lock().remove(&self.stream_id).is_some() {
            self.shared.open_streams.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Address helpers (SOCKS5 form, as used by sing-mux stream requests)
// ---------------------------------------------------------------------------

/// Encodes `address` as `[atyp][address][port]`.
pub fn encode_socksaddr(address: &TargetAddress, out: &mut Vec<u8>) {
    match address {
        TargetAddress::Ip(SocketAddr::V4(v4)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddress::Ip(SocketAddr::V6(v6)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddress::Domain(host, port) => {
            out.push(ATYP_DOMAIN);
            let bytes = host.as_bytes();
            let len = bytes.len().min(u8::MAX as usize);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

async fn read_socksaddr<R: AsyncRead + Unpin>(reader: &mut R) -> FluxResult<TargetAddress> {
    let atyp = reader
        .read_u8()
        .await
        .map_err(|e| smux_err(format!("failed to read mux address type: {e}")))?;
    match atyp {
        ATYP_IPV4 => {
            let mut rest = [0u8; 6];
            reader
                .read_exact(&mut rest)
                .await
                .map_err(|e| smux_err(format!("failed to read mux ipv4 address: {e}")))?;
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok(TargetAddress::Ip(SocketAddr::new(ip.into(), port)))
        }
        ATYP_IPV6 => {
            let mut rest = [0u8; 18];
            reader
                .read_exact(&mut rest)
                .await
                .map_err(|e| smux_err(format!("failed to read mux ipv6 address: {e}")))?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok(TargetAddress::Ip(SocketAddr::new(ip.into(), port)))
        }
        ATYP_DOMAIN => {
            let len = reader
                .read_u8()
                .await
                .map_err(|e| smux_err(format!("failed to read mux domain length: {e}")))?
                as usize;
            if len == 0 {
                return Err(smux_err("empty domain in mux stream request"));
            }
            let mut rest = vec![0u8; len + 2];
            reader
                .read_exact(&mut rest)
                .await
                .map_err(|e| smux_err(format!("failed to read mux domain address: {e}")))?;
            let host = String::from_utf8_lossy(&rest[..len]).into_owned();
            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);
            Ok(TargetAddress::Domain(host, port))
        }
        other => Err(smux_err(format!("unsupported mux address type {other}"))),
    }
}

fn encode_stream_request(destination: &TargetAddress, network: NetworkType) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    let flags = match network {
        NetworkType::Udp => STREAM_FLAG_UDP,
        NetworkType::Tcp => 0,
    };
    out.extend_from_slice(&flags.to_be_bytes());
    encode_socksaddr(destination, &mut out);
    out
}

fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

// ---------------------------------------------------------------------------
// Padding chunk layer
// ---------------------------------------------------------------------------

/// Port of sing-mux's `paddingConn`: the first 16 writes of each direction are
/// wrapped in `[data_len][pad_len][data][padding]` chunks.
struct PaddingStream<S> {
    inner: S,
    read_chunks: u32,
    write_chunks: u32,
    data_remaining: usize,
    pad_remaining: usize,
    header: [u8; 4],
    header_filled: usize,
    scratch: [u8; 1024],
    write_pending: Option<Bytes>,
    write_len: usize,
}

impl<S> PaddingStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            read_chunks: 0,
            write_chunks: 0,
            data_remaining: 0,
            pad_remaining: 0,
            header: [0u8; 4],
            header_filled: 0,
            scratch: [0u8; 1024],
            write_pending: None,
            write_len: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.data_remaining > 0 {
                let limit = buf.remaining().min(this.data_remaining);
                if limit == 0 {
                    return Poll::Ready(Ok(()));
                }
                let mut limited = ReadBuf::new(&mut buf.initialize_unfilled()[..limit]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = limited.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        buf.advance(n);
                        this.data_remaining -= n;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            if this.pad_remaining > 0 {
                let take = this.pad_remaining.min(this.scratch.len());
                let mut limited = ReadBuf::new(&mut this.scratch[..take]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = limited.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.pad_remaining -= n;
                        continue;
                    }
                }
            }
            if this.read_chunks < PADDING_CHUNKS {
                while this.header_filled < 4 {
                    let mut limited = ReadBuf::new(&mut this.header[this.header_filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = limited.filled().len();
                            if n == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            this.header_filled += n;
                        }
                    }
                }
                let data_len = u16::from_be_bytes([this.header[0], this.header[1]]) as usize;
                let pad_len = u16::from_be_bytes([this.header[2], this.header[3]]) as usize;
                this.header_filled = 0;
                this.read_chunks += 1;
                this.data_remaining = data_len;
                this.pad_remaining = pad_len;
                continue;
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.write_chunks >= PADDING_CHUNKS && this.write_pending.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_pending.is_none() {
            let data_len = buf.len().min(u16::MAX as usize);
            let pad_len = 256 + (now_ms() as usize % 512);
            let mut chunk = BytesMut::with_capacity(4 + data_len + pad_len);
            chunk.extend_from_slice(&(data_len as u16).to_be_bytes());
            chunk.extend_from_slice(&(pad_len as u16).to_be_bytes());
            chunk.extend_from_slice(&buf[..data_len]);
            chunk.resize(4 + data_len + pad_len, 0);
            this.write_pending = Some(chunk.freeze());
            this.write_len = data_len;
        }
        loop {
            let pending = this.write_pending.clone().expect("chunk pending");
            match Pin::new(&mut this.inner).poll_write(cx, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.write_pending = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(0)) => {
                    this.write_pending = None;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "padding chunk write stalled",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    if n >= pending.len() {
                        let data_len = this.write_len;
                        this.write_pending = None;
                        this.write_chunks += 1;
                        return Poll::Ready(Ok(data_len));
                    }
                    // Partial write: keep going while the sink accepts data.
                    this.write_pending = Some(pending.slice(n..));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client-side multiplexer: pools sessions and opens streams over them.
pub struct MuxClient {
    dialer: Arc<dyn StreamDialer>,
    config: MuxConfig,
    sessions: Mutex<Vec<Arc<MuxSession>>>,
}

impl MuxClient {
    pub fn new(dialer: Arc<dyn StreamDialer>, config: MuxConfig) -> Arc<Self> {
        Arc::new(Self {
            dialer,
            config,
            sessions: Mutex::new(Vec::new()),
        })
    }

    /// Dials a TCP stream to `destination` over the multiplexed session.
    pub async fn dial_stream(&self, destination: &TargetAddress) -> FluxResult<BoxedStream> {
        let stream = self.open_stream(destination, NetworkType::Tcp).await?;
        Ok(Box::new(stream))
    }

    /// Dials a UDP association to `destination` over the multiplexed session.
    pub async fn dial_packet(
        &self,
        destination: &TargetAddress,
    ) -> FluxResult<Box<dyn PacketEndpoint>> {
        let stream = self.open_stream(destination, NetworkType::Udp).await?;
        Ok(Box::new(MuxPacketEndpoint::new(
            stream,
            destination.clone(),
        )))
    }

    async fn open_stream(
        &self,
        destination: &TargetAddress,
        network: NetworkType,
    ) -> FluxResult<MuxStream> {
        let session = self.session().await?;
        let mut stream = session.open_stream().await?;
        let request = encode_stream_request(destination, network);
        stream
            .write_all(&request)
            .await
            .map_err(|e| smux_err(format!("failed to write mux stream request: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| smux_err(format!("failed to flush mux stream request: {e}")))?;
        Ok(stream)
    }

    async fn session(&self) -> FluxResult<Arc<MuxSession>> {
        let mut guard = self.sessions.lock().await;
        guard.retain(|session| session.is_alive());
        if let Some(session) = guard.iter().find(|session| session.has_capacity()) {
            return Ok(session.clone());
        }
        let max_connections = self.config.max_connections.max(1) as usize;
        if guard.len() >= max_connections {
            // Every pooled session is at its stream target: reuse the least
            // loaded one instead of failing (max_streams is a pooling hint on
            // the client, exactly like sing-box).
            if let Some(session) = guard
                .iter()
                .min_by_key(|session| session.shared.open_streams.load(Ordering::Relaxed))
            {
                debug!(
                    "smux: reusing a session above its max_streams target ({})",
                    self.config.max_streams
                );
                return Ok(session.clone());
            }
        }
        let conn = self.dialer.dial().await?;
        let session = MuxSession::connect(conn, self.config.clone()).await?;
        guard.push(session.clone());
        Ok(session)
    }

    /// Closes every pooled session.
    pub async fn close(&self) {
        let mut guard = self.sessions.lock().await;
        guard.clear();
    }

    /// Number of live sessions (used by tests and diagnostics).
    pub async fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .await
            .iter()
            .filter(|session| session.is_alive())
            .count()
    }
}

/// Datagram endpoint over a muxed UDP stream (`[len][payload]` framing).
pub struct MuxPacketEndpoint {
    reader: Arc<Mutex<ReadHalf<MuxStream>>>,
    writer: Arc<Mutex<WriteHalf<MuxStream>>>,
    destination: TargetAddress,
}

impl MuxPacketEndpoint {
    fn new(stream: MuxStream, destination: TargetAddress) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            destination,
        }
    }
}

#[async_trait::async_trait]
impl PacketEndpoint for MuxPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let len = packet.payload.len().min(u16::MAX as usize);
        let mut frame = Vec::with_capacity(2 + len);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
        frame.extend_from_slice(&packet.payload[..len]);
        let mut writer = self.writer.lock().await;
        writer
            .write_all(&frame)
            .await
            .map_err(|e| smux_err(format!("failed to send mux datagram: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| smux_err(format!("failed to flush mux datagram: {e}")))?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut reader = self.reader.lock().await;
        let len = reader
            .read_u16()
            .await
            .map_err(|e| smux_err(format!("failed to read mux datagram length: {e}")))?
            as usize;
        let mut payload = vec![0u8; len];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| smux_err(format!("failed to read mux datagram: {e}")))?;
        Ok(UdpPacket::new(
            Bytes::from(payload),
            self.destination.clone(),
            self.destination.clone(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A stream accepted from a multiplexed session.
pub struct AcceptedStream {
    pub stream: MuxStream,
    pub destination: TargetAddress,
    pub network: NetworkType,
    /// Whether datagrams carry their own destination prefix.
    pub packet_addr: bool,
}

/// Serves a multiplexed session, handing every accepted stream to `accept`.
///
/// The session preface is read (and validated) here, so the caller only needs
/// to have authenticated the connection and detected the mux destination.
pub async fn serve<F>(conn: BoxedStream, config: &MuxConfig, accept: F) -> FluxResult<()>
where
    F: Fn(AcceptedStream) + Send + Sync + 'static,
{
    config.validate()?;
    let mut conn = conn;
    let mut preface = [0u8; 2];
    let timeout = config.handshake_timeout;
    tokio::time::timeout(timeout, conn.read_exact(&mut preface))
        .await
        .map_err(|_| smux_err("timed out reading the multiplex preface"))?
        .map_err(|e| smux_err(format!("failed to read the multiplex preface: {e}")))?;

    let version = preface[0];
    let protocol = preface[1];
    if version > PREFACE_VERSION_1 {
        return Err(smux_err(format!(
            "unsupported multiplex preface version {version}"
        )));
    }
    if protocol != PREFACE_PROTOCOL_SMUX {
        return Err(smux_err(format!(
            "unsupported multiplex protocol id {protocol} (only smux is supported)"
        )));
    }
    let mut padded = false;
    if version == PREFACE_VERSION_1 {
        let mut flags = [0u8; 1];
        conn.read_exact(&mut flags)
            .await
            .map_err(|e| smux_err(format!("failed to read the multiplex padding flag: {e}")))?;
        padded = flags[0] != 0;
        if padded {
            let mut len = [0u8; 2];
            conn.read_exact(&mut len).await.map_err(|e| {
                smux_err(format!("failed to read the multiplex padding length: {e}"))
            })?;
            let padding_len = u16::from_be_bytes(len) as usize;
            let mut discard = vec![0u8; padding_len];
            conn.read_exact(&mut discard)
                .await
                .map_err(|e| smux_err(format!("failed to skip the multiplex padding: {e}")))?;
        }
    }
    if config.padding && !padded {
        return Err(smux_err("non-padded multiplex connection rejected"));
    }

    let conn: BoxedStream = if padded {
        Box::new(PaddingStream::new(conn))
    } else {
        conn
    };

    let (accepts_tx, mut accepts_rx) = mpsc::channel::<PendingAccept>(32);
    let session = MuxSession::start(conn, config.clone(), Role::Server, Some(accepts_tx));
    let accept = Arc::new(accept);

    loop {
        let pending = tokio::select! {
            next = accepts_rx.recv() => match next {
                Some(next) => next,
                None => break,
            },
            _ = session.shared.shutdown.notified() => break,
        };
        let shared = session.shared.clone();
        let accept = accept.clone();
        tokio::spawn(async move {
            let mut stream =
                MuxStream::new(pending.stream_id, shared.clone(), pending.rx, Role::Server);
            let request =
                match tokio::time::timeout(shared.config.handshake_timeout, stream.read_request())
                    .await
                {
                    Ok(Ok(request)) => request,
                    Ok(Err(e)) => {
                        debug!("smux: rejected stream {}: {}", pending.stream_id, e);
                        let _ = stream.reject(&e.to_string()).await;
                        return;
                    }
                    Err(_) => {
                        let _ = stream.reject("stream request timed out").await;
                        return;
                    }
                };
            if stream.accept_ok().await.is_err() {
                return;
            }
            accept(AcceptedStream {
                stream,
                destination: request.destination,
                network: request.network,
                packet_addr: request.packet_addr,
            });
        });
    }
    session.shared.close("accept loop finished");
    Ok(())
}

/// Spawns the standard dispatcher bridge for an accepted mux stream.
pub fn spawn_mux_dispatcher(
    dispatcher: Arc<dyn Dispatcher>,
    inbound_tag: Arc<str>,
    source: SocketAddr,
    accepted: AcceptedStream,
) {
    tokio::spawn(async move {
        let meta = SessionMeta::new(source, accepted.destination, inbound_tag, accepted.network);
        match accepted.network {
            NetworkType::Tcp => {
                dispatcher
                    .dispatch_stream(meta, Box::new(accepted.stream))
                    .await;
            }
            NetworkType::Udp => {
                if let Err(e) =
                    serve_udp_stream(accepted.stream, meta, dispatcher, accepted.packet_addr).await
                {
                    debug!("smux: udp stream ended: {}", e);
                }
            }
        }
    });
}

/// Reads one datagram from a muxed UDP stream.
async fn read_datagram(
    stream: &mut MuxStream,
    packet_addr: bool,
    fallback: &TargetAddress,
) -> FluxResult<Option<UdpPacket>> {
    let destination = if packet_addr {
        read_socksaddr(stream).await?
    } else {
        fallback.clone()
    };
    let len = match stream.read_u16().await {
        Ok(len) => len as usize,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(smux_err(format!("failed to read mux datagram length: {e}"))),
    };
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| smux_err(format!("failed to read mux datagram: {e}")))?;
    Ok(Some(UdpPacket::new(
        Bytes::from(payload),
        destination.clone(),
        destination,
    )))
}

/// Drives a muxed UDP stream into the dispatcher's packet path.
///
/// When `packet_addr` is set every datagram carries its own destination
/// (sing-box's `flagAddr` mode, used by its SOCKS5 UDP associate); the
/// dispatcher routes each datagram independently.
pub async fn serve_udp_stream(
    mut stream: MuxStream,
    mut meta: SessionMeta,
    dispatcher: Arc<dyn Dispatcher>,
    packet_addr: bool,
) -> FluxResult<()> {
    let fallback = meta.destination.clone();
    // The first datagram fixes the association destination used for routing.
    let Some(first) = read_datagram(&mut stream, packet_addr, &fallback).await? else {
        return Ok(());
    };
    meta.destination = first.destination.clone();

    let (packet_tx, packet_rx) = mpsc::channel::<UdpPacket>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<UdpPacket>(64);
    let _ = packet_tx.send(first).await;
    let (mut reader, mut writer) = tokio::io::split(stream);

    let read_task = tokio::spawn(async move {
        loop {
            let destination = if packet_addr {
                match read_socksaddr(&mut reader).await {
                    Ok(destination) => destination,
                    Err(_) => break,
                }
            } else {
                fallback.clone()
            };
            let len = match reader.read_u16().await {
                Ok(len) => len as usize,
                Err(_) => break,
            };
            let mut payload = vec![0u8; len];
            if reader.read_exact(&mut payload).await.is_err() {
                break;
            }
            let packet = UdpPacket::new(Bytes::from(payload), destination.clone(), destination);
            if packet_tx.send(packet).await.is_err() {
                break;
            }
        }
    });

    let write_task = tokio::spawn(async move {
        while let Some(packet) = out_rx.recv().await {
            let mut frame = Vec::with_capacity(32 + packet.payload.len());
            if packet_addr {
                encode_socksaddr(&packet.source, &mut frame);
            }
            let len = packet.payload.len().min(u16::MAX as usize);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
            frame.extend_from_slice(&packet.payload[..len]);
            if writer.write_all(&frame).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
        _ = dispatcher.dispatch_packet(meta, packet_rx, out_tx) => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn duplex_pair(size: usize) -> (BoxedStream, BoxedStream) {
        let (a, b) = tokio::io::duplex(size);
        (Box::new(a), Box::new(b))
    }

    fn raw_pair(size: usize) -> (BoxedStream, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(size);
        (Box::new(a), b)
    }

    async fn open(client: &MuxSession, destination: &TargetAddress) -> MuxStream {
        let mut stream = client.open_stream().await.expect("open stream");
        stream
            .write_all(&encode_stream_request(destination, NetworkType::Tcp))
            .await
            .expect("write request");
        stream.flush().await.expect("flush request");
        stream
    }

    /// Spawns `serve` without borrowing the config across the task boundary.
    fn spawn_server(
        conn: BoxedStream,
        config: &MuxConfig,
        accept: impl Fn(AcceptedStream) + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<FluxResult<()>> {
        let config = config.clone();
        tokio::spawn(async move { serve(conn, &config, accept).await })
    }

    /// Echoes everything back: the standard peer for the loopback tests.
    fn echo_stream(mut stream: MuxStream) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if stream.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    /// Accept handler that holds the *first* stream unread (a stalled
    /// consumer) and echoes every later one.
    fn stall_first(
        hold: Arc<Mutex<mpsc::Sender<MuxStream>>>,
    ) -> impl Fn(AcceptedStream) + Send + Sync + 'static {
        move |accepted: AcceptedStream| {
            let hold = hold.clone();
            tokio::spawn(async move {
                let stream = accepted.stream;
                match hold.lock().await.try_send(stream) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(stream))
                    | Err(mpsc::error::TrySendError::Closed(stream)) => echo_stream(stream),
                }
            });
        }
    }

    fn upd_frame(stream_id: u32, window: u32) -> Vec<u8> {
        let mut frame = FrameHeader::new(CMD_UPD, stream_id, 8).encode().to_vec();
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&window.to_be_bytes());
        frame
    }

    #[test]
    fn frame_header_roundtrip_and_validation() {
        for cmd in [CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP, CMD_UPD] {
            let header = FrameHeader::new(cmd, 5, 1234);
            let decoded = FrameHeader::decode(&header.encode()).expect("decode");
            assert_eq!(decoded, header);
        }

        // Little-endian layout, exactly as observed on the wire from sing-box:
        // `01 02 1b 00 03 00 00 00` = PSH, 27 bytes, stream 3.
        let observed = [0x01u8, 0x02, 0x1b, 0x00, 0x03, 0x00, 0x00, 0x00];
        let header = FrameHeader::decode(&observed).expect("decode observed frame");
        assert_eq!(header.version, SMUX_VERSION);
        assert_eq!(header.cmd, CMD_PSH);
        assert_eq!(header.length, 27);
        assert_eq!(header.stream_id, 3);
        assert_eq!(header.encode(), observed);

        // Wrong version and unknown commands are rejected, never panicking.
        assert!(FrameHeader::decode(&[2, CMD_PSH, 0, 0, 1, 0, 0, 0]).is_err());
        assert!(FrameHeader::decode(&[0, CMD_PSH, 0, 0, 1, 0, 0, 0]).is_err());
        assert!(FrameHeader::decode(&[SMUX_VERSION, 9, 0, 0, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn socksaddr_encoding_matches_the_reference() {
        // Captured from sing-box: request for 1.1.1.1:80.
        let mut out = Vec::new();
        encode_socksaddr(&TargetAddress::ipv4(1, 1, 1, 1, 80), &mut out);
        assert_eq!(out, vec![0x01, 1, 1, 1, 1, 0x00, 0x50]);

        let mut out = Vec::new();
        encode_socksaddr(&TargetAddress::domain(MUX_DESTINATION_FQDN, 444), &mut out);
        assert_eq!(out[0], ATYP_DOMAIN);
        assert_eq!(out[1] as usize, MUX_DESTINATION_FQDN.len());
        assert_eq!(&out[2..out.len() - 2], MUX_DESTINATION_FQDN.as_bytes());
    }

    #[tokio::test]
    async fn stream_ids_are_odd_on_the_client_and_even_on_the_server() {
        let (client_side, _server_side) = duplex_pair(64 * 1024);
        let config = MuxConfig::default();
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client session");

        // The reference client opens 3, 5, 7... (odd, starting at 3).
        let first = client.open_stream().await.expect("open");
        assert_eq!(first.id() % 2, 1);
        assert_eq!(first.id(), FIRST_CLIENT_STREAM_ID);
        let second = client.open_stream().await.expect("open");
        assert_eq!(second.id(), FIRST_CLIENT_STREAM_ID + 2);

        let (out_tx, _out_rx) = mpsc::channel(8);
        let server_shared = Arc::new(Shared {
            config,
            role: Role::Server,
            out_tx,
            streams: PlMutex::new(HashMap::new()),
            next_id: AtomicU32::new(FIRST_SERVER_STREAM_ID),
            open_streams: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            shutdown: Notify::new(),
            last_activity_ms: AtomicU64::new(now_ms()),
            peer_window: AtomicI64::new(i64::MAX),
            credit_ready: Notify::new(),
            out_ready: Notify::new(),
        });
        assert_eq!(server_shared.allocate_id(), 2);
        assert_eq!(server_shared.allocate_id(), 4);
    }

    #[tokio::test]
    async fn even_syn_from_a_peer_is_rejected() {
        let (server_side, mut peer) = raw_pair(64 * 1024);
        // Preface (version 0, smux) then a SYN for an even stream id.
        peer.write_all(&[0x00, 0x00]).await.expect("preface");
        peer.write_all(&FrameHeader::new(CMD_SYN, 2, 0).encode())
            .await
            .expect("syn");

        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        let config = MuxConfig::default();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            serve(server_side, &config, move |_accepted| {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .await
        .expect("serve must terminate on a protocol violation");
        assert!(result.is_ok());
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn roundtrip_over_session_preface_and_frames() {
        let (client_side, server_side) = duplex_pair(64 * 1024);
        let config = MuxConfig::default();
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client session");
        let server = spawn_server(server_side, &config, |accepted| {
            echo_stream(accepted.stream)
        });

        let destination = TargetAddress::domain("example.com", 443);
        let mut stream = open(&client, &destination).await;
        let payload = b"smux round trip payload".repeat(64);
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");

        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.expect("read");
        assert_eq!(echoed, payload);

        // A second stream on the same session is independent.
        let mut second = open(&client, &TargetAddress::ipv4(1, 2, 3, 4, 80)).await;
        second.write_all(b"second stream").await.expect("write");
        second.flush().await.expect("flush");
        let mut buf = [0u8; 13];
        second.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"second stream");

        drop(stream);
        drop(second);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn fin_performs_a_half_close() {
        let (client_side, server_side) = duplex_pair(64 * 1024);
        let config = MuxConfig::default();
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client session");

        // Server: read the request, then wait for EOF before answering, which
        // proves our FIN reaches the peer as a half close.
        let server = spawn_server(server_side, &config, |accepted| {
            tokio::spawn(async move {
                let mut stream = accepted.stream;
                let mut buf = vec![0u8; 4];
                stream.read_exact(&mut buf).await.expect("read ping");
                assert_eq!(&buf, b"ping");
                let mut tail = Vec::new();
                stream.read_to_end(&mut tail).await.expect("read eof");
                assert!(tail.is_empty());
                stream.write_all(b"pong").await.expect("write after EOF");
                stream.flush().await.expect("flush");
            });
        });

        let mut stream = open(&client, &TargetAddress::domain("example.com", 80)).await;
        stream.write_all(b"ping").await.expect("write");
        stream.flush().await.expect("flush");
        // Half close: the write side goes away, the read side stays usable.
        stream.shutdown().await.expect("shutdown");

        let mut pong = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut pong))
            .await
            .expect("server did not answer after our FIN")
            .expect("read pong");
        assert_eq!(&pong, b"pong");

        drop(stream);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn window_exhaustion_blocks_until_an_update_arrives() {
        let (client_side, mut peer) = raw_pair(64 * 1024);
        let client = MuxSession::connect(client_side, MuxConfig::default())
            .await
            .expect("client");
        let mut stream = client.open_stream().await.expect("open");
        let stream_id = stream.id();
        stream
            .write_all(&encode_stream_request(
                &TargetAddress::domain("example.com", 80),
                NetworkType::Tcp,
            ))
            .await
            .expect("request");
        stream.flush().await.expect("flush");

        // Drain the preface + SYN + request so the peer stays in sync.
        drain_for(&mut peer, Duration::from_millis(200)).await;

        // The peer advertises a 4 byte window: the stream may send exactly 4.
        peer.write_all(&upd_frame(stream_id, 4)).await.expect("upd");
        peer.flush().await.expect("flush");
        tokio::time::sleep(Duration::from_millis(100)).await;

        stream
            .write_all(b"abcd")
            .await
            .expect("4 bytes fit the window");

        // The 5th byte must block until the peer extends the window.
        let blocked =
            tokio::time::timeout(Duration::from_millis(300), stream.write_all(b"e")).await;
        assert!(
            blocked.is_err(),
            "write must not exceed the advertised window"
        );

        peer.write_all(&upd_frame(stream_id, 64))
            .await
            .expect("upd");
        peer.flush().await.expect("flush");
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"e"))
            .await
            .expect("window update did not unblock the writer")
            .expect("write after window update");
    }

    #[tokio::test]
    async fn missing_window_update_is_the_v1_default() {
        // Without any UPD the session must behave exactly like smux v1:
        // unlimited send credit.
        let (client_side, server_side) = duplex_pair(256 * 1024);
        let config = MuxConfig::default();
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client");
        let server = spawn_server(server_side, &config, |accepted| {
            echo_stream(accepted.stream)
        });
        let mut stream = open(&client, &TargetAddress::domain("example.com", 80)).await;
        let payload = vec![7u8; 64 * 1024];
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");
        let mut echo = vec![0u8; payload.len()];
        stream.read_exact(&mut echo).await.expect("read");
        assert_eq!(echo, payload);
        drop(stream);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn nop_frames_are_ignored() {
        let (client_side, mut peer) = raw_pair(64 * 1024);
        let client = MuxSession::connect(client_side, MuxConfig::default())
            .await
            .expect("client");
        let mut stream = client.open_stream().await.expect("open");
        let stream_id = stream.id();
        stream
            .write_all(&encode_stream_request(
                &TargetAddress::domain("example.com", 80),
                NetworkType::Tcp,
            ))
            .await
            .expect("request");
        stream.flush().await.expect("flush");
        drain_for(&mut peer, Duration::from_millis(200)).await;

        // Interleave heartbeats with the status byte and payload.
        peer.write_all(&FrameHeader::new(CMD_NOP, 0, 0).encode())
            .await
            .expect("nop");
        peer.write_all(&FrameHeader::new(CMD_NOP, stream_id, 0).encode())
            .await
            .expect("nop");
        let mut psh = FrameHeader::new(CMD_PSH, stream_id, 6).encode().to_vec();
        psh.extend_from_slice(b"\x00hello");
        peer.write_all(&psh).await.expect("psh");
        peer.flush().await.expect("flush");

        let mut buf = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
            .await
            .expect("heartbeats must not disturb the stream")
            .expect("read");
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn malformed_frames_close_the_session_instead_of_panicking() {
        for header in [
            // Unsupported version.
            [2u8, CMD_PSH, 1, 0, 3, 0, 0, 0],
            // Unknown command.
            [SMUX_VERSION, 0x7f, 0, 0, 3, 0, 0, 0],
            // Control frame carrying a payload.
            [SMUX_VERSION, CMD_SYN, 4, 0, 3, 0, 0, 0],
            // PSH for stream 0.
            [SMUX_VERSION, CMD_PSH, 0, 0, 0, 0, 0, 0],
        ] {
            let (client_side, mut peer) = raw_pair(64 * 1024);
            let client = MuxSession::connect(client_side, MuxConfig::default())
                .await
                .expect("client");
            let mut stream = client.open_stream().await.expect("open");
            drain_for(&mut peer, Duration::from_millis(50)).await;
            peer.write_all(&header).await.expect("header");
            peer.flush().await.expect("flush");

            // The stream must observe EOF instead of hanging.
            let mut buf = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            assert!(read.is_ok(), "session did not tear down on {header:?}");
            assert!(matches!(read.unwrap(), Ok(0) | Err(_)));
        }
    }

    #[tokio::test]
    async fn a_slow_stream_does_not_block_the_others() {
        let (client_side, server_side) = duplex_pair(256 * 1024);
        let config = MuxConfig {
            max_buffered_bytes: 64 * 1024,
            max_frame_size: 4096,
            ..Default::default()
        };
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client");

        let (held_tx, _held_rx) = mpsc::channel::<MuxStream>(1);
        let server = spawn_server(
            server_side,
            &config,
            stall_first(Arc::new(Mutex::new(held_tx))),
        );

        let mut slow = open(&client, &TargetAddress::domain("slow.example", 80)).await;
        let mut fast = open(&client, &TargetAddress::domain("fast.example", 80)).await;

        // Fill the slow stream's receive buffer (the peer never reads).
        let chunk = vec![0xABu8; 32 * 1024];
        for _ in 0..4 {
            let _ = tokio::time::timeout(Duration::from_millis(100), slow.write_all(&chunk)).await;
        }

        // The fast stream must still work.
        let payload = b"fast stream survives a neighbour stall".to_vec();
        tokio::time::timeout(Duration::from_secs(2), fast.write_all(&payload))
            .await
            .expect("fast stream blocked by a slow neighbour")
            .expect("write");
        fast.flush().await.expect("flush");
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(2), fast.read_exact(&mut echoed))
            .await
            .expect("fast stream read blocked")
            .expect("read");
        assert_eq!(echoed, payload);

        drop(slow);
        drop(fast);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn overflowing_stream_is_reset_without_killing_the_session() {
        let (client_side, server_side) = duplex_pair(256 * 1024);
        let config = MuxConfig {
            max_buffered_bytes: 32 * 1024,
            max_frame_size: 4096,
            ..Default::default()
        };
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client");

        let (held_tx, _held_rx) = mpsc::channel::<MuxStream>(1);
        let server = spawn_server(
            server_side,
            &config,
            stall_first(Arc::new(Mutex::new(held_tx))),
        );

        let mut slow = open(&client, &TargetAddress::domain("slow.example", 80)).await;
        let mut fast = open(&client, &TargetAddress::domain("fast.example", 80)).await;

        // Push far more than the receive buffer of the stalled stream.
        let chunk = vec![0xCDu8; 16 * 1024];
        let mut reset_seen = false;
        for _ in 0..64 {
            if tokio::time::timeout(Duration::from_millis(100), slow.write_all(&chunk))
                .await
                .is_err()
            {
                break;
            }
            let mut probe = [0u8; 1];
            if matches!(
                tokio::time::timeout(Duration::from_millis(50), slow.read(&mut probe)).await,
                Ok(Ok(0))
            ) {
                reset_seen = true;
                break;
            }
        }
        assert!(reset_seen, "the stalled stream should have been reset");

        let payload = b"session still alive".to_vec();
        tokio::time::timeout(Duration::from_secs(2), fast.write_all(&payload))
            .await
            .expect("fast stream blocked")
            .expect("write");
        fast.flush().await.expect("flush");
        let mut echoed = vec![0u8; payload.len()];
        fast.read_exact(&mut echoed).await.expect("read");
        assert_eq!(echoed, payload);

        drop(slow);
        drop(fast);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn padded_session_preface_and_chunks() {
        // A padding-enabled session between our own halves must round trip,
        // including the 16 chunk wrappers at the start.
        let (client_side, server_side) = duplex_pair(256 * 1024);
        let config = MuxConfig {
            padding: true,
            ..Default::default()
        };
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client");
        let server = spawn_server(server_side, &config, |accepted| {
            echo_stream(accepted.stream)
        });
        let mut stream = open(&client, &TargetAddress::domain("example.com", 80)).await;
        let payload = b"padded payload".repeat(32);
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .expect("read timed out")
            .expect("read");
        assert_eq!(echoed, payload);
        drop(stream);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn unpadded_session_is_rejected_when_padding_is_required() {
        let (server_side, mut peer) = raw_pair(64 * 1024);
        peer.write_all(&[0x00, 0x00]).await.expect("preface");
        let config = MuxConfig {
            padding: true,
            ..Default::default()
        };
        let result =
            tokio::time::timeout(Duration::from_secs(2), serve(server_side, &config, |_| {}))
                .await
                .expect("serve must terminate");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn udp_stream_roundtrip_between_our_halves() {
        // Direct `serve_udp_stream` coverage: datagrams in both addressing
        // modes are decoded and encoded symmetrically.
        let (client_side, server_side) = duplex_pair(64 * 1024);
        let config = MuxConfig::default();
        let client = MuxSession::connect(client_side, config.clone())
            .await
            .expect("client");

        struct EchoPackets;
        #[async_trait::async_trait]
        impl Dispatcher for EchoPackets {
            async fn dispatch_stream(&self, _meta: SessionMeta, _stream: BoxedStream) {}
            async fn dial_outbound(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
                Err(smux_err("not used"))
            }
            async fn bridge_streams(
                &self,
                _meta: SessionMeta,
                _stream: BoxedStream,
                _out: BoxedStream,
            ) {
            }
            async fn dispatch_packet(
                &self,
                _meta: SessionMeta,
                mut rx: mpsc::Receiver<UdpPacket>,
                tx: mpsc::Sender<UdpPacket>,
            ) {
                while let Some(packet) = rx.recv().await {
                    if tx.send(packet).await.is_err() {
                        break;
                    }
                }
            }
        }

        let dispatcher: Arc<dyn Dispatcher> = Arc::new(EchoPackets);
        let server = {
            let config = config.clone();
            let dispatcher = dispatcher.clone();
            tokio::spawn(async move {
                serve(server_side, &config, move |accepted: AcceptedStream| {
                    assert_eq!(accepted.network, NetworkType::Udp);
                    let dispatcher = dispatcher.clone();
                    tokio::spawn(async move {
                        let meta = SessionMeta::new(
                            "127.0.0.1:0".parse().unwrap(),
                            accepted.destination.clone(),
                            "test",
                            NetworkType::Udp,
                        );
                        let _ = serve_udp_stream(
                            accepted.stream,
                            meta,
                            dispatcher,
                            accepted.packet_addr,
                        )
                        .await;
                    });
                })
                .await
            })
        };

        let destination = TargetAddress::domain("dns.example", 53);
        let mut stream = client.open_stream().await.expect("open");
        stream
            .write_all(&encode_stream_request(&destination, NetworkType::Udp))
            .await
            .expect("request");
        stream.flush().await.expect("flush");
        // Two `[len][payload]` datagrams echoed back (the client half already
        // consumed the stream's status byte during its handshake).
        let mut inbound = Vec::new();
        for payload in [&b"first"[..], &b"second"[..]] {
            inbound.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            inbound.extend_from_slice(payload);
        }
        stream.write_all(&inbound).await.expect("write datagrams");
        stream.flush().await.expect("flush");

        for expected in [&b"first"[..], &b"second"[..]] {
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.expect("len");
            let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut payload).await.expect("payload");
            assert_eq!(payload, expected);
        }

        drop(stream);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn mux_destination_detection() {
        assert!(is_mux_destination(&mux_destination()));
        assert!(is_mux_destination(&TargetAddress::domain(
            "SP.MUX.sing-box.ARPA",
            MUX_DESTINATION_PORT
        )));
        assert!(!is_mux_destination(&TargetAddress::domain(
            MUX_DESTINATION_FQDN,
            80
        )));
        assert!(!is_mux_destination(&TargetAddress::ipv4(1, 1, 1, 1, 444)));
    }

    /// Reads and discards whatever the raw peer produced for a while.
    async fn drain_for(peer: &mut tokio::io::DuplexStream, duration: Duration) {
        let mut scratch = vec![0u8; 8192];
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            match tokio::time::timeout(remaining, peer.read(&mut scratch)).await {
                Ok(Ok(0)) | Err(_) => return,
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return,
            }
        }
    }
}
