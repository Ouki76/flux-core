//! mKCP — a reliable byte stream over UDP (KCP ARQ) with Xray-style obfuscation.
//!
//! mKCP is the transport Xray calls `"network": "kcp"`: a KCP retransmission
//! layer (selective ACK, RTT-driven RTO, fast retransmit, windows) carried in
//! UDP datagrams that are framed to look like something else — SRTP, uTP,
//! WeChat video, DTLS or WireGuard — and then masked so the payload is not
//! recognisable as KCP either.
//!
//! # Wire format
//!
//! Every datagram is one segment, wrapped as
//! `[obfuscation header][mask envelope][segment]`:
//!
//! * `obfuscation header` — 0/4/13 bytes depending on [`KcpObfs`], the analogue
//!   of Xray's `header.config.type`. It carries a per-stream counter so two
//!   datagrams never look identical.
//! * `mask envelope` — the "original" mask Xray always applies to mKCP
//!   (`NewSimpleAuthenticator` in older trees, `finalmask/mkcp/original` in
//!   current ones): `fnv1a32(len ‖ payload) · len u16 · payload`, zero-padded
//!   to a 4-byte multiple and then run through a cumulative XOR
//!   (`x[i] ^= x[i-4]`, forwards to seal, backwards to open). The first four
//!   bytes — the hash — stay in the clear, so a datagram remains verifiable
//!   after a byte in transit is corrupted, and both ends agree on framing.
//! * `segment` — 24-byte little-endian header plus payload:
//!
//! ```text
//! off  size  field
//!   0     4  conv   conversation id
//!   4     1  cmd    81 PUSH · 82 ACK · 83 WASK · 84 WINS
//!   5     1  frg    fragment index, 255 for the first fragment of a write
//!   6     2  wnd    free receive slots advertised by the sender
//!   8     4  ts     sender clock, ms since the stream started
//!  12     4  sn     segment number
//!  16     4  una    next segment number expected from the peer (cumulative ack)
//!  20     4  len    payload length; the datagram must contain exactly this
//! ```
//!
//! PUSH payloads carry stream bytes; ACK payloads are `(sn, ts)` pairs of
//! `u32` little-endian, which is what lets the sender measure the RTT of an
//! individual segment and stop retransmitting it.
//!
//! # Deliberate divergences from Xray
//!
//! The segment layout above is the ikcp/kcp-go one, which is what this crate
//! was asked to implement. Xray's own mKCP — every release from v1.8 through
//! v26 — uses a *different* segment layout (`conv u16`, commands 0..3, big
//! endian, 18-byte DATA overhead, `transport/internet/kcp/segment.go`), so the
//! two are not interchangeable; see the module's report for the exact
//! differences. The obfuscation layer, on the other hand, is
//! byte-exact with Xray (`transport/internet/headers/*` and
//! `crypt.go` / `finalmask/mkcp/original`), so swapping the segment codec is
//! the only change needed to talk to a real Xray node.
//!
//! # Behaviour
//!
//! * One task drives [`flush`](Conn) on `interval_ms`; there is no task per
//!   segment. Reads and writes only ever take a short lock and hand work to the
//!   driver.
//! * The send buffer is bounded by `snd_wnd` segments: a writer that outruns the
//!   peer gets `Pending`, never unbounded growth, and a peer that stops ACKing
//!   trips the retry limit and fails the stream instead of buffering forever.
//! * Datagrams that fail deobfuscation, carry a foreign conversation id, claim a
//!   length beyond the MTU or are truncated are dropped silently — a hostile
//!   peer can only cost CPU, never a panic.
//!
//! Note on fragmentation bookkeeping: `frg` follows the historic KCP convention
//! of counting *down* from 255, so a 40 KiB write over a 1310-byte MSS leaves as
//! `frg = 255, 254, …`. The reader reassembles by `sn` order, which is what makes
//! a lost fragment recoverable instead of fatal.

use bytes::Bytes;
use flux_types::{FluxError, FluxResult};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// Size of the segment header, in bytes.
pub const SEGMENT_HEADER_LEN: usize = 24;
/// `cmd` of a data segment.
pub const CMD_PUSH: u8 = 81;
/// `cmd` of an acknowledgement segment.
pub const CMD_ACK: u8 = 82;
/// `cmd` of a window probe ("what is your window?").
pub const CMD_WASK: u8 = 83;
/// `cmd` of a window update, sent in reply to [`CMD_WASK`].
pub const CMD_WINS: u8 = 84;

/// A single write is fragmented into at most this many segments, which is what
/// keeps `frg = 255 - index` representable.
const MAX_FRAGMENTS: usize = 256;
/// Upper bound on a datagram we are willing to read from the socket.
const MAX_DATAGRAM: usize = 65_535;
/// Initial RTO, before the first RTT sample exists, in milliseconds.
const RTO_INITIAL_MS: u64 = 100;
/// Retransmission timeout ceiling, in milliseconds.
const RTO_MAX_MS: u64 = 10_000;
/// A segment retried more often than this kills the stream (ikcp's `dead_link`).
const MAX_RETRIES: u32 = 20;
/// How often one segment may be repaired by fast retransmit before it has to
/// wait for its timer (kcp-go's `fastlimit`). Without this, a burst that
/// overflows the peer's socket buffer turns every ACK into a retransmission.
const FAST_RETRANSMIT_LIMIT: u32 = 5;
/// No datagram at all for this long, with unacknowledged data outstanding, means
/// the peer is gone.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Send a window probe after this long without sending anything, which doubles
/// as a keepalive for an otherwise idle stream.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(10);
/// How long [`accept`] waits for the first datagram of a conversation.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Depth of the per-conversation datagram queue between the socket driver and
/// the stream task. A slow reader loses datagrams, which KCP recovers from.
const INBOX_DEPTH: usize = 1024;

// ---------------------------------------------------------------------------
// Obfuscation
// ---------------------------------------------------------------------------

/// The header an mKCP datagram is dressed in.
///
/// These are the modes Xray exposes as `header.config.type`; the byte layout of
/// each one is taken from the upstream implementation, but the *contents* are
/// pure camouflage: a receiver strips the fixed-size header and never validates
/// it, so only the length matters for interoperability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KcpObfs {
    /// No header at all. The mask envelope is still applied, because that is
    /// what Xray does when no header is configured.
    None,
    /// SRTP: `0xB5E8` then a 16-bit packet counter. The mode Xray users
    /// actually configure.
    #[default]
    Srtp,
    /// uTP: connection id, `ST_DATA` byte and extension byte.
    Utp,
    /// WeChat video call framing: a 13-byte opus-ish header with a sequence.
    WechatVideo,
    /// DTLS 1.2 application data record header.
    Dtls,
    /// WireGuard transport message header.
    Wireguard,
}

impl KcpObfs {
    /// Number of bytes this mode prepends to a datagram.
    pub fn header_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Srtp | Self::Utp | Self::Wireguard => 4,
            Self::WechatVideo | Self::Dtls => 13,
        }
    }

    /// Name used in logs and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Srtp => "srtp",
            Self::Utp => "utp",
            Self::WechatVideo => "wechat-video",
            Self::Dtls => "dtls",
            Self::Wireguard => "wireguard",
        }
    }
}

/// Per-stream header generator: the counters must advance monotonically, so the
/// state cannot be shared between streams on one socket.
struct ObfsState {
    mode: KcpObfs,
    counter: u16,
    seq: u32,
    dtls_len: u16,
}

impl ObfsState {
    fn new(mode: KcpObfs) -> Self {
        Self {
            mode,
            counter: rand::random(),
            seq: rand::random(),
            dtls_len: 17,
        }
    }

    /// Writes `header ‖ mask(segment)` into `out`.
    fn wrap(&mut self, segment: &[u8], out: &mut Vec<u8>) {
        let len = self.mode.header_len();
        if len > 0 {
            let mut header = [0u8; 13];
            match self.mode {
                KcpObfs::None => {}
                KcpObfs::Srtp => {
                    self.counter = self.counter.wrapping_add(1);
                    header[0..2].copy_from_slice(&0xB5E8u16.to_be_bytes());
                    header[2..4].copy_from_slice(&self.counter.to_be_bytes());
                }
                KcpObfs::Utp => {
                    // uTP: connection id, ST_DATA (0x01), empty extension.
                    header[0..2].copy_from_slice(&self.counter.to_be_bytes());
                    header[2] = 0x01;
                    header[3] = 0x00;
                }
                KcpObfs::WechatVideo => {
                    self.seq = self.seq.wrapping_add(1);
                    header[0] = 0xA1;
                    header[1] = 0x08;
                    header[2..6].copy_from_slice(&self.seq.to_be_bytes());
                    header[6..13].copy_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
                }
                KcpObfs::Dtls => {
                    header[0] = 23; // application_data
                    header[1] = 0xFE;
                    header[2] = 0xFD; // DTLS 1.2
                    // Epoch stays 0, sequence advances, record length ramps the
                    // same way Xray's does so it is not a constant.
                    header[7..11].copy_from_slice(&self.seq.to_be_bytes());
                    self.seq = self.seq.wrapping_add(1);
                    header[11..13].copy_from_slice(&self.dtls_len.to_be_bytes());
                    self.dtls_len += 17;
                    if self.dtls_len > 100 {
                        self.dtls_len -= 50;
                    }
                }
                KcpObfs::Wireguard => {
                    header[0] = 0x04; // transport data message
                }
            }
            out.extend_from_slice(&header[..len]);
        }
        envelope::seal(segment, out);
    }
}

/// Xray's "original" mKCP mask: a length-prefixed, fnv1a32-checked frame that is
/// cumulative-XORed so the payload has no recognisable structure.
///
/// Reversible by construction: the padding is only there so the XOR walks whole
/// 4-byte words, and it is truncated again before the datagram is sent.
mod envelope {
    /// Bytes the mask adds to a payload.
    pub const OVERHEAD: usize = 6;

    /// `[fnv1a32 ‖ len u16 ‖ payload]`, padded and XOR-chained.
    pub fn seal(plain: &[u8], out: &mut Vec<u8>) {
        debug_assert!(plain.len() <= u16::MAX as usize);
        let mut body = Vec::with_capacity(OVERHEAD + plain.len() + 3);
        body.resize(OVERHEAD, 0);
        body[4..6].copy_from_slice(&(plain.len() as u16).to_be_bytes());
        body.extend_from_slice(plain);

        let hash = fnv1a32(&body[4..]);
        body[0..4].copy_from_slice(&hash.to_be_bytes());

        let unpadded = body.len();
        let xtra = 4 - unpadded % 4;
        if xtra != 4 {
            body.resize(unpadded + xtra, 0);
        }
        xor_forward(&mut body);
        body.truncate(unpadded);
        out.extend_from_slice(&body);
    }

    /// Inverse of [`seal`]; `None` means "not ours, or corrupted in flight".
    pub fn open(padded: &[u8]) -> Option<Vec<u8>> {
        let unpadded = padded.len();
        let mut body = padded.to_vec();
        let xtra = 4 - unpadded % 4;
        if xtra != 4 {
            body.resize(unpadded + xtra, 0);
        }
        xor_backward(&mut body);
        body.truncate(unpadded);

        if body.len() < OVERHEAD {
            return None;
        }
        let hash = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if fnv1a32(&body[4..]) != hash {
            return None;
        }
        let len = u16::from_be_bytes([body[4], body[5]]) as usize;
        if body.len() - OVERHEAD != len {
            return None;
        }
        Some(body.split_off(OVERHEAD))
    }

    /// `x[i] ^= x[i-4]`, so each byte is chained to the one four before it.
    fn xor_forward(buf: &mut [u8]) {
        for i in 4..buf.len() {
            buf[i] ^= buf[i - 4];
        }
    }

    fn xor_backward(buf: &mut [u8]) {
        for i in (4..buf.len()).rev() {
            buf[i] ^= buf[i - 4];
        }
    }

    fn fnv1a32(data: &[u8]) -> u32 {
        let mut hash = 0x811c_9dc5u32;
        for byte in data {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        hash
    }
}

// ---------------------------------------------------------------------------
// Segment codec
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Segment {
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    data: Vec<u8>,
}

fn encode_segment(conv: u32, seg: &Segment, out: &mut Vec<u8>) {
    out.extend_from_slice(&conv.to_le_bytes());
    out.push(seg.cmd);
    out.push(seg.frg);
    out.extend_from_slice(&seg.wnd.to_le_bytes());
    out.extend_from_slice(&seg.ts.to_le_bytes());
    out.extend_from_slice(&seg.sn.to_le_bytes());
    out.extend_from_slice(&seg.una.to_le_bytes());
    out.extend_from_slice(&(seg.data.len() as u32).to_le_bytes());
    out.extend_from_slice(&seg.data);
}

/// Parses one segment out of a deobfuscated datagram.
///
/// Returns `None` for anything that is not a well-formed segment for `conv`:
/// short buffers, a foreign conversation id, an unknown command, or a `len` that
/// does not describe the datagram exactly (which covers both truncation and a
/// length field larger than what arrived).
fn decode_segment(conv: u32, buf: &[u8]) -> Option<Segment> {
    if buf.len() < SEGMENT_HEADER_LEN {
        return None;
    }
    if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != conv {
        return None;
    }
    let cmd = buf[4];
    if !matches!(cmd, CMD_PUSH | CMD_ACK | CMD_WASK | CMD_WINS) {
        return None;
    }
    let len = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]) as usize;
    if buf.len() - SEGMENT_HEADER_LEN != len {
        return None;
    }
    Some(Segment {
        cmd,
        frg: buf[5],
        wnd: u16::from_le_bytes([buf[6], buf[7]]),
        ts: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        sn: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        una: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        data: buf[SEGMENT_HEADER_LEN..].to_vec(),
    })
}

/// Strips the obfuscation layer. `None` means the datagram must be dropped.
fn unwrap_datagram(obfs: KcpObfs, datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() <= obfs.header_len() {
        return None;
    }
    envelope::open(&datagram[obfs.header_len()..])
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tuning for one mKCP conversation, plus its camouflage mode.
#[derive(Clone, Copy, Debug)]
pub struct KcpConfig {
    /// Conversation id. `0` asks [`connect`] / [`accept`] to pick one.
    pub conv: u32,
    /// Largest datagram, in bytes. Xray's default is 1350; the KCP payload is
    /// this minus the header and obfuscation overhead.
    pub mtu: usize,
    /// Send window, in segments. Also the hard bound on memory a peer that
    /// stops ACKing can make us hold.
    pub snd_wnd: u16,
    /// Receive window, in segments: how much out-of-order data is buffered.
    pub rcv_wnd: u16,
    /// How often the driver flushes and checks for retransmissions.
    pub interval_ms: u32,
    /// Duplicate ACKs before a segment is retransmitted without waiting for its
    /// timer (fast retransmit).
    pub resend: u32,
    /// `true` keeps the window fixed (`snd_wnd`), which is what Xray calls
    /// `congestion: false` and its own default. `false` enables a simple
    /// slow-start / congestion-avoidance controller on top.
    pub no_congestion: bool,
    /// Datagram camouflage.
    pub obfs: KcpObfs,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            conv: 0,
            mtu: 1350,
            snd_wnd: 512,
            rcv_wnd: 512,
            interval_ms: 10,
            resend: 2,
            no_congestion: true,
            obfs: KcpObfs::Srtp,
        }
    }
}

impl KcpConfig {
    /// Largest segment payload for these settings.
    pub fn mss(&self) -> usize {
        self.mtu
            .saturating_sub(SEGMENT_HEADER_LEN + self.obfs.header_len() + envelope::OVERHEAD)
    }

    /// Bytes the obfuscation layer adds to every datagram.
    fn obfs_overhead(&self) -> usize {
        self.obfs.header_len() + envelope::OVERHEAD
    }

    fn validate(&self) -> FluxResult<()> {
        let overhead = SEGMENT_HEADER_LEN + self.obfs_overhead();
        if self.mtu <= overhead + 16 {
            return Err(FluxError::Config(format!(
                "mKCP mtu {} is too small: {} bytes of header/obfuscation overhead ({}) leave no room for data",
                self.mtu,
                overhead,
                self.obfs.as_str()
            )));
        }
        if self.mtu > MAX_DATAGRAM {
            return Err(FluxError::Config(format!(
                "mKCP mtu {} exceeds the maximum UDP datagram size {}",
                self.mtu, MAX_DATAGRAM
            )));
        }
        if self.interval_ms == 0 {
            return Err(FluxError::Config(
                "mKCP interval_ms must be at least 1".into(),
            ));
        }
        if self.snd_wnd == 0 || self.rcv_wnd == 0 {
            return Err(FluxError::Config(
                "mKCP send and receive windows must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// Counters, mostly useful for tests and for proving that ARQ is doing work.
#[derive(Clone, Copy, Debug, Default)]
pub struct KcpStats {
    /// Segments handed to the socket, retransmissions included.
    pub segments_sent: u64,
    /// Segments sent more than once.
    pub segments_retransmitted: u64,
    /// Retransmissions caused by duplicate ACKs.
    pub fast_retransmits: u64,
    /// Retransmissions caused by the timer expiring.
    pub timer_retransmits: u64,
    /// Segment bytes handed to the socket.
    pub bytes_sent: u64,
    /// Datagrams the socket refused (would block or error); TCP-style
    /// backpressure does not exist for UDP, so KCP retransmits instead.
    pub datagrams_refused: u64,
    /// Datagrams accepted for this conversation.
    pub datagrams_received: u64,
    /// Payload bytes accepted into the receive queue.
    pub bytes_received: u64,
    /// Current retransmission timeout, in milliseconds.
    pub rto_ms: u64,
    /// Smoothed RTT, in microseconds.
    pub srtt_us: u64,
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// A queued payload, already cut to fit one segment.
struct QueuedSeg {
    data: Bytes,
    frg: u8,
}

/// Splits one write into at most [`MAX_FRAGMENTS`] segments, each at most `mss`
/// bytes. `frg` counts down from 255 so the last fragment of a write is the one
/// with the smallest index — the KCP convention that lets a receiver recognise
/// the tail of a message.
fn fragment(data: &[u8], mss: usize) -> Vec<QueuedSeg> {
    let mss = mss.max(1);
    let mut out = Vec::with_capacity(data.len().div_ceil(mss).min(MAX_FRAGMENTS));
    for (index, chunk) in data.chunks(mss).take(MAX_FRAGMENTS).enumerate() {
        out.push(QueuedSeg {
            data: Bytes::copy_from_slice(chunk),
            frg: (255 - index) as u8,
        });
    }
    out
}

/// A segment that has been sent and is waiting to be acknowledged.
struct OutSeg {
    data: Bytes,
    frg: u8,
    /// Wire timestamp of the most recent transmission.
    ts: u32,
    /// Local send time of the most recent transmission, for RTT measurement.
    sent_at: Instant,
    /// How many times this segment has been transmitted.
    xmit: u32,
    /// Current retransmission timeout in microseconds (grows on timeout).
    rto_us: u64,
    /// When to retransmit without waiting for duplicate ACKs.
    deadline: Instant,
    /// Duplicate ACKs seen for a later segment.
    fastack: u32,
    /// How many of those already caused a fast retransmit.
    fast_xmit: u32,
}

struct Conn {
    cfg: KcpConfig,
    conv: u32,
    obfs: ObfsState,
    socket: Arc<UdpSocket>,
    peer: Option<SocketAddr>,
    start: Instant,

    // Send side.
    snd_una: u32,
    snd_nxt: u32,
    snd_queue: VecDeque<QueuedSeg>,
    snd_buf: BTreeMap<u32, OutSeg>,
    cwnd: u32,
    ssthresh: u32,
    last_cwnd_inc: Instant,

    // Receive side.
    rcv_nxt: u32,
    rcv_buf: BTreeMap<u32, Bytes>,
    recv_queue: VecDeque<Bytes>,
    ack_list: Vec<(u32, u32)>,

    // RTT estimation (RFC 6298 style).
    srtt_us: u64,
    rttvar_us: u64,
    rto_us: u64,

    // Windows and liveness.
    peer_wnd: u16,
    /// Window advertised on the last segment we sent, to notice when a reader
    /// frees space in a window we had closed.
    advertised_wnd: u16,
    /// Set when the reader consumed data while the advertised window was zero.
    window_update: bool,
    next_probe: Instant,
    last_recv: Instant,
    last_send: Instant,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    dead: Option<io::ErrorKind>,

    stats: KcpStats,
}

impl Conn {
    fn new(cfg: KcpConfig, conv: u32, socket: Arc<UdpSocket>, peer: Option<SocketAddr>) -> Self {
        let now = Instant::now();
        let wnd = u32::from(cfg.snd_wnd);
        // With congestion control enabled the window has to be earned; a fixed
        // window is the whole point of `no_congestion`.
        let initial_cwnd = if cfg.no_congestion { wnd } else { wnd.min(4) };
        Self {
            obfs: ObfsState::new(cfg.obfs),
            cfg,
            conv,
            socket,
            peer,
            start: now,
            snd_una: 0,
            snd_nxt: 0,
            snd_queue: VecDeque::new(),
            snd_buf: BTreeMap::new(),
            cwnd: initial_cwnd,
            ssthresh: wnd,
            last_cwnd_inc: now,
            rcv_nxt: 0,
            rcv_buf: BTreeMap::new(),
            recv_queue: VecDeque::new(),
            ack_list: Vec::new(),
            srtt_us: 0,
            rttvar_us: 0,
            rto_us: 0,
            // Until the peer tells us, assume it can take as much as we can
            // send: a client must be able to push the first request without
            // having received anything yet.
            peer_wnd: cfg.snd_wnd,
            advertised_wnd: cfg.rcv_wnd,
            window_update: false,
            next_probe: now,
            last_recv: now,
            last_send: now,
            read_waker: None,
            write_waker: None,
            dead: None,
            stats: KcpStats::default(),
        }
    }

    fn now_ms(&self, now: Instant) -> u32 {
        now.duration_since(self.start).as_millis() as u32
    }

    fn rto(&self) -> Duration {
        let us = if self.rto_us == 0 {
            RTO_INITIAL_MS * 1000
        } else {
            self.rto_us
        };
        Duration::from_micros(us)
    }

    /// RTO floor.
    ///
    /// A whole window leaves in one flush, so the last datagrams of a burst wait
    /// behind the others in the peer's socket and in its task: the RTT that
    /// matters for the tail of the burst is the burst-processing time, not the
    /// idle-path RTT. Five flush intervals is the smallest floor that does not
    /// retransmit datagrams which are merely queued, and it matches KCP's own
    /// `RTO_MIN` habit of being much larger than the tick.
    fn rto_min_us(&self) -> u64 {
        (u64::from(self.cfg.interval_ms) * 5).max(50) * 1000
    }

    /// Free receive slots, counting both the out-of-order buffer and the data
    /// the application has not read yet.
    ///
    /// Advertising only the out-of-order part would tell the peer the window is
    /// open while the reader is behind, so the peer would keep sending into a
    /// buffer that is full and the excess would be dropped unacknowledged — the
    /// sender then repairs it on a timer, which looks like 60 % loss on a link
    /// that lost nothing.
    fn rcv_wnd_free(&self) -> u16 {
        let used = (self.rcv_buf.len() + self.recv_queue.len()).min(u16::MAX as usize) as u16;
        self.cfg.rcv_wnd.saturating_sub(used)
    }

    fn rcv_window_full(&self) -> bool {
        self.rcv_buf.len() + self.recv_queue.len() >= usize::from(self.cfg.rcv_wnd)
    }

    /// Segments we may have in flight right now.
    fn effective_wnd(&self) -> u32 {
        let own = if self.cfg.no_congestion {
            u32::from(self.cfg.snd_wnd)
        } else {
            self.cwnd.clamp(1, u32::from(self.cfg.snd_wnd))
        };
        own.min(u32::from(self.peer_wnd))
    }

    // -- sending ----------------------------------------------------------

    fn send_segment(&mut self, seg: Segment, now: Instant) {
        let Some(peer) = self.peer else {
            return;
        };
        let mut segment = Vec::with_capacity(SEGMENT_HEADER_LEN + seg.data.len());
        encode_segment(self.conv, &seg, &mut segment);

        let mut datagram = Vec::with_capacity(segment.len() + self.cfg.obfs_overhead());
        self.obfs.wrap(&segment, &mut datagram);

        // Non-blocking on purpose: backpressure has to be expressed by the KCP
        // window, not by a send queue inside the socket. A datagram the socket
        // refuses is simply not sent; the retransmission timer covers it.
        match self.socket.try_send_to(&datagram, peer) {
            Ok(sent) => {
                self.advertised_wnd = seg.wnd;
                self.stats.segments_sent += 1;
                self.stats.bytes_sent += sent as u64;
                self.last_send = now;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // The socket is briefly busy; KCP's timer is the backpressure
                // mechanism, so dropping here costs a retransmission, not data.
                self.stats.datagrams_refused += 1;
            }
            Err(_) => {
                self.stats.datagrams_refused += 1;
            }
        }
    }

    fn send_push(&mut self, sn: u32, now: Instant) {
        let Some(seg) = self.snd_buf.get(&sn) else {
            return;
        };
        let (frg, ts, data) = (seg.frg, seg.ts, seg.data.clone());
        let wnd = self.rcv_wnd_free();
        let una = self.rcv_nxt;
        self.send_segment(
            Segment {
                cmd: CMD_PUSH,
                frg,
                wnd,
                ts,
                sn,
                una,
                data: data.to_vec(),
            },
            now,
        );
    }

    fn send_ack(&mut self, now: Instant) {
        if self.ack_list.is_empty() {
            return;
        }
        let per_segment = (self.cfg.mss() / 8).max(1);
        while !self.ack_list.is_empty() {
            let take = self.ack_list.len().min(per_segment);
            let pairs: Vec<(u32, u32)> = self.ack_list.drain(..take).collect();
            let mut data = Vec::with_capacity(pairs.len() * 8);
            for (sn, ts) in pairs {
                data.extend_from_slice(&sn.to_le_bytes());
                data.extend_from_slice(&ts.to_le_bytes());
            }
            let seg = Segment {
                cmd: CMD_ACK,
                frg: 0,
                wnd: self.rcv_wnd_free(),
                ts: self.now_ms(now),
                sn: 0,
                una: self.rcv_nxt,
                data,
            };
            self.send_segment(seg, now);
        }
    }

    fn send_probe(&mut self, now: Instant) {
        let seg = Segment {
            cmd: CMD_WASK,
            frg: 0,
            wnd: self.rcv_wnd_free(),
            ts: self.now_ms(now),
            sn: 0,
            una: self.rcv_nxt,
            data: Vec::new(),
        };
        self.send_segment(seg, now);
    }

    fn send_window_reply(&mut self, now: Instant) {
        let seg = Segment {
            cmd: CMD_WINS,
            frg: 0,
            wnd: self.rcv_wnd_free(),
            ts: self.now_ms(now),
            sn: 0,
            una: self.rcv_nxt,
            data: Vec::new(),
        };
        self.send_segment(seg, now);
    }

    /// Moves queued payloads into the send buffer while the window allows it.
    fn fill_window(&mut self, now: Instant) {
        let wnd = self.effective_wnd();
        while (self.snd_buf.len() as u32) < wnd {
            let Some(queued) = self.snd_queue.pop_front() else {
                break;
            };
            let sn = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            let rto_us = self.rto().as_micros() as u64;
            let ts = self.now_ms(now);
            self.snd_buf.insert(
                sn,
                OutSeg {
                    data: queued.data,
                    frg: queued.frg,
                    ts,
                    sent_at: now,
                    xmit: 1,
                    rto_us,
                    deadline: now + Duration::from_micros(rto_us),
                    fastack: 0,
                    fast_xmit: 0,
                },
            );
            self.send_push(sn, now);
        }
    }

    /// Retransmits overdue segments and applies fast retransmit.
    fn retransmit(&mut self, now: Instant) {
        let rto = self.rto();
        let ts = self.now_ms(now);
        let mut expired: Vec<u32> = Vec::new();
        let mut fast: Vec<u32> = Vec::new();
        for (sn, seg) in &self.snd_buf {
            if now >= seg.deadline {
                expired.push(*sn);
            } else if seg.fastack >= self.cfg.resend
                && seg.fastack > 0
                && seg.fast_xmit < FAST_RETRANSMIT_LIMIT
            {
                fast.push(*sn);
            }
        }

        for sn in fast {
            if let Some(seg) = self.snd_buf.get_mut(&sn) {
                seg.xmit = seg.xmit.saturating_add(1);
                seg.fastack = 0;
                seg.fast_xmit = seg.fast_xmit.saturating_add(1);
                seg.deadline = now + rto;
                seg.ts = ts;
                seg.sent_at = now;
            }
            self.stats.segments_retransmitted += 1;
            self.stats.fast_retransmits += 1;
            self.on_loss(true);
            self.send_push(sn, now);
        }

        for sn in expired {
            let Some(seg) = self.snd_buf.get_mut(&sn) else {
                continue;
            };
            seg.xmit = seg.xmit.saturating_add(1);
            seg.fastack = 0;
            // Exponential backoff, capped, as KCP and TCP both do.
            seg.rto_us = (seg.rto_us * 2).min(RTO_MAX_MS * 1000);
            seg.deadline = now + Duration::from_micros(seg.rto_us);
            seg.ts = ts;
            seg.sent_at = now;
            let xmit = seg.xmit;
            if xmit > MAX_RETRIES {
                tracing::debug!(
                    conv = self.conv,
                    sn,
                    "mKCP segment exceeded its retry budget"
                );
                self.kill(io::ErrorKind::TimedOut);
                return;
            }
            self.stats.segments_retransmitted += 1;
            self.stats.timer_retransmits += 1;
            self.on_loss(false);
            self.send_push(sn, now);
        }
    }

    /// Window probing and an idle keepalive, both through WASK/WINS.
    fn keepalive(&mut self, now: Instant) {
        if self.peer_wnd == 0
            && (!self.snd_queue.is_empty() || !self.snd_buf.is_empty())
            && now >= self.next_probe
        {
            self.next_probe = now + self.rto().max(Duration::from_millis(200));
            self.send_probe(now);
        } else if now.duration_since(self.last_send) >= KEEPALIVE_IDLE {
            self.send_probe(now);
        }
    }

    fn check_dead(&mut self, now: Instant) {
        if self.dead.is_some() {
            return;
        }
        if !self.snd_buf.is_empty() && now.duration_since(self.last_recv) > IDLE_TIMEOUT {
            self.kill(io::ErrorKind::TimedOut);
        }
    }

    fn kill(&mut self, reason: io::ErrorKind) {
        if self.dead.is_some() {
            return;
        }
        self.dead = Some(reason);
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    /// Drives one period of the protocol.
    fn flush(&mut self, now: Instant) {
        if self.dead.is_some() || self.peer.is_none() {
            return;
        }
        self.send_ack(now);
        if self.window_update && self.rcv_wnd_free() > 0 {
            self.window_update = false;
            self.send_window_reply(now);
        }
        self.fill_window(now);
        self.retransmit(now);
        self.keepalive(now);
        self.check_dead(now);
    }

    // -- receiving --------------------------------------------------------

    /// Feeds one deobfuscated segment. The socket demultiplexer has already
    /// stripped the obfuscation, so this is what the driver calls.
    fn on_segment(&mut self, segment: &[u8], from: SocketAddr, now: Instant) {
        if self.dead.is_some() {
            return;
        }
        // Anything larger than the MTU cannot be something we produced, so it is
        // either hostile or a configuration mismatch.
        if segment.len() > self.cfg.mtu {
            return;
        }
        match self.peer {
            None => self.peer = Some(from),
            Some(peer) if peer != from => return,
            Some(_) => {}
        }
        let Some(seg) = decode_segment(self.conv, segment) else {
            return;
        };

        self.last_recv = now;
        self.peer_wnd = seg.wnd;
        self.stats.datagrams_received += 1;

        match seg.cmd {
            CMD_PUSH => self.on_push(seg),
            CMD_ACK => self.on_ack(&seg, now),
            CMD_WASK => self.send_window_reply(now),
            CMD_WINS => self.next_probe = now,
            _ => {}
        }
    }

    fn on_push(&mut self, seg: Segment) {
        let sn = seg.sn;
        // Already delivered: re-acknowledge, because our earlier ACK was
        // probably the datagram that got lost.
        if sn < self.rcv_nxt {
            self.ack_list.push((sn, seg.ts));
            return;
        }
        if self.rcv_window_full() {
            return;
        }
        self.rcv_buf.entry(sn).or_insert_with(|| {
            self.stats.bytes_received += seg.data.len() as u64;
            Bytes::from(seg.data.clone())
        });
        self.ack_list.push((sn, seg.ts));
        self.deliver();
    }

    /// Hands in-order segments to the reader. A slow reader stops delivery
    /// rather than growing an unbounded queue; the window then closes.
    fn deliver(&mut self) {
        while self.recv_queue.len() < usize::from(self.cfg.rcv_wnd) {
            let Some(data) = self.rcv_buf.remove(&self.rcv_nxt) else {
                break;
            };
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            if !data.is_empty() {
                self.recv_queue.push_back(data);
            }
        }
        if !self.recv_queue.is_empty()
            && let Some(waker) = self.read_waker.take()
        {
            waker.wake();
        }
    }

    fn on_ack(&mut self, seg: &Segment, now: Instant) {
        let mut acked = 0u32;
        let mut highest = self.snd_una;

        // An ACK payload is `(sn, ts)` pairs. The `ts` half is the peer's echo of
        // our wire timestamp, kept so the format stays standard; the RTT itself
        // is measured from the local `sent_at`, which has microsecond resolution
        // instead of the millisecond the wire field can carry.
        let (pairs, _) = seg.data.as_chunks::<8>();
        for pair in pairs {
            let sn = u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]);
            if sn < self.snd_una || sn >= self.snd_nxt {
                continue;
            }
            if let Some(out) = self.snd_buf.get(&sn) {
                // Karn's rule: only trust a sample from a segment that was sent
                // exactly once, otherwise it is ambiguous which copy it covers.
                if out.xmit == 1 {
                    self.update_rtt(now.duration_since(out.sent_at).as_micros() as u64);
                }
            }
            if self.snd_buf.remove(&sn).is_some() {
                acked += 1;
                highest = highest.max(sn.wrapping_add(1));
            }
        }

        // Cumulative acknowledgement: everything below `una` is delivered.
        if seg.una > self.snd_una {
            if let Some(out) = self.snd_buf.get(&seg.una.wrapping_sub(1))
                && out.xmit == 1
            {
                self.update_rtt(now.duration_since(out.sent_at).as_micros() as u64);
            }
            highest = highest.max(seg.una);
            let done: Vec<u32> = self.snd_buf.range(..seg.una).map(|(sn, _)| *sn).collect();
            acked += done.len() as u32;
            for sn in done {
                self.snd_buf.remove(&sn);
            }
            self.snd_una = seg.una;
        }

        if acked > 0 {
            for (sn, out) in self.snd_buf.iter_mut() {
                if *sn < highest {
                    out.fastack = out.fastack.saturating_add(1);
                }
            }
            self.on_ack_progress(acked, now);
            if let Some(waker) = self.write_waker.take() {
                waker.wake();
            }
        }
    }

    fn update_rtt(&mut self, rtt_us: u64) {
        let rtt_us = rtt_us.max(1);
        if self.srtt_us == 0 {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            let delta = self.srtt_us.abs_diff(rtt_us);
            self.rttvar_us = (3 * self.rttvar_us + delta) / 4;
            self.srtt_us = (7 * self.srtt_us + rtt_us) / 8;
        }
        let floor = self.rto_min_us();
        let rto = (self.srtt_us + 4 * self.rttvar_us).clamp(floor, RTO_MAX_MS * 1000);
        self.rto_us = rto;
    }

    fn on_loss(&mut self, fast: bool) {
        if self.cfg.no_congestion {
            return;
        }
        let inflight = self.snd_buf.len() as u32;
        self.ssthresh = (inflight / 2).max(2);
        self.cwnd = if fast {
            self.ssthresh.saturating_add(3)
        } else {
            2
        };
        self.last_cwnd_inc = Instant::now();
    }

    fn on_ack_progress(&mut self, acked: u32, now: Instant) {
        if self.cfg.no_congestion {
            return;
        }
        let cap = u32::from(self.cfg.snd_wnd);
        if self.cwnd < self.ssthresh {
            self.cwnd = (self.cwnd + acked).min(cap);
        } else if now.duration_since(self.last_cwnd_inc) >= self.rto() {
            self.cwnd = (self.cwnd + 1).min(cap);
            self.last_cwnd_inc = now;
        }
    }

    fn snapshot(&self) -> KcpStats {
        let mut stats = self.stats;
        stats.rto_ms = self.rto().as_millis() as u64;
        stats.srtt_us = self.srtt_us;
        stats
    }
}

// ---------------------------------------------------------------------------
// Socket demultiplexer
// ---------------------------------------------------------------------------

/// Hand-off point between the socket demultiplexer and one conversation's
/// driver.
///
/// A queue plus a permit-based [`Notify`], rather than a channel, because a KCP
/// driver wakes on *either* an arriving datagram or its own timer, and a wakeup
/// that is lost there parks the conversation forever: `Notify` stores the permit
/// even when nobody is waiting, and `notified()` is documented as cancel safe
/// inside `select!`, so no datagram can arrive silently.
struct Inbox {
    queue: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
    notify: Notify,
}

impl Inbox {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        })
    }

    /// Enqueues one datagram. A full inbox drops it, exactly like a full socket
    /// buffer would; the loss is harmless because KCP retransmits.
    fn push(&self, item: (SocketAddr, Vec<u8>)) {
        {
            let mut queue = self.queue.lock();
            if queue.len() >= INBOX_DEPTH {
                return;
            }
            queue.push_back(item);
        }
        self.notify.notify_one();
    }

    fn pop(&self) -> Option<(SocketAddr, Vec<u8>)> {
        self.queue.lock().pop_front()
    }

    fn take_all(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut queue = self.queue.lock();
        if queue.is_empty() {
            return Vec::new();
        }
        queue.drain(..).collect()
    }
}

/// Everything sharing one UDP socket: the conversation routes plus the
/// camouflage mode they were created with.
///
/// `accept` hands out a socket the caller owns, so several conversations can
/// live on it; without this they would steal each other's datagrams.
struct Hub {
    socket: Arc<UdpSocket>,
    obfs: KcpObfs,
    routes: HashMap<u32, Arc<Inbox>>,
    /// Route used by an `accept` that has not learned its conversation id yet.
    any: Option<Arc<Inbox>>,
    closed: bool,
}

impl Hub {
    fn is_idle(&self) -> bool {
        self.routes.is_empty() && self.any.is_none()
    }
}

static HUBS: OnceLock<Mutex<HashMap<usize, Arc<Mutex<Hub>>>>> = OnceLock::new();

fn hubs() -> &'static Mutex<HashMap<usize, Arc<Mutex<Hub>>>> {
    HUBS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Identity of a socket for the registry. The map holds the `Arc<UdpSocket>`
/// alive, so the address cannot be reused while an entry exists.
fn socket_key(socket: &Arc<UdpSocket>) -> usize {
    Arc::as_ptr(socket) as usize
}

/// Returns (and if needed creates) the demultiplexer for `socket`.
fn hub_for(socket: &Arc<UdpSocket>, obfs: KcpObfs) -> (Arc<Mutex<Hub>>, usize) {
    let key = socket_key(socket);
    let mut map = hubs().lock();
    if let Some(hub) = map.get(&key) {
        return (hub.clone(), key);
    }
    let hub = Arc::new(Mutex::new(Hub {
        socket: socket.clone(),
        obfs,
        routes: HashMap::new(),
        any: None,
        closed: false,
    }));
    map.insert(key, hub.clone());
    drop(map);
    tokio::spawn(dispatch(hub.clone()));
    (hub, key)
}

/// Single reader for the socket: deobfuscates once, then routes by conversation
/// id. Unknown conversations are dropped here, which is the first line of
/// defence against stray or hostile traffic.
async fn dispatch(hub: Arc<Mutex<Hub>>) {
    let (socket, obfs) = {
        let hub = hub.lock();
        (hub.socket.clone(), hub.obfs)
    };
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let received =
            tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf[..])).await;
        let (n, from) = match received {
            Ok(Ok(pair)) => pair,
            // Timeout is how we notice that every conversation on this socket
            // is gone; a hard error means the socket itself is broken.
            Err(_) => {
                if hub.lock().closed {
                    break;
                }
                continue;
            }
            Ok(Err(_)) => break,
        };
        // Header-only segments (ACK, WASK, WINS) are exactly the minimum size,
        // so this must be a strict comparison.
        if n < obfs.header_len() + envelope::OVERHEAD + SEGMENT_HEADER_LEN {
            continue;
        }
        let Some(segment) = unwrap_datagram(obfs, &buf[..n]) else {
            continue;
        };
        if segment.len() < SEGMENT_HEADER_LEN {
            continue;
        }
        let conv = u32::from_le_bytes([segment[0], segment[1], segment[2], segment[3]]);
        let hub = hub.lock();
        let target = hub.routes.get(&conv).or(hub.any.as_ref()).cloned();
        drop(hub);
        if let Some(inbox) = target {
            inbox.push((from, segment));
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Asks the kernel for roomy socket buffers.
///
/// KCP sends a whole window in one `flush`, which is 512 datagrams with the
/// default configuration; the 212 KiB default receive buffer holds about a
/// tenth of that, so without this a burst is lost on the receive side before
/// the peer's task can drain it. Best effort: an unprivileged process is
/// limited by `net.core.rmem_max`, and a socket that refuses the size still
/// works, just with more retransmissions.
fn tune_socket(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
}

/// A live mKCP conversation.
///
/// Reads yield stream bytes in order, writes are fragmented and retransmitted as
/// needed. Dropping the stream releases the conversation and stops its driver.
pub struct KcpStream {
    inner: Arc<Mutex<Conn>>,
    hub: Arc<Mutex<Hub>>,
    key: usize,
    conv: u32,
    task: tokio::task::JoinHandle<()>,
    local: Option<SocketAddr>,
}

impl KcpStream {
    /// Conversation id in use (generated when the config asked for `0`).
    pub fn conv(&self) -> u32 {
        self.conv
    }

    /// Local address of the underlying UDP socket.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }

    /// Peer address, once known.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.lock().peer
    }

    /// Protocol counters, including retransmissions and RTT.
    pub fn stats(&self) -> KcpStats {
        self.inner.lock().snapshot()
    }
}

impl std::fmt::Debug for KcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpStream")
            .field("conv", &self.conv)
            .field("local", &self.local)
            .field("peer", &self.peer_addr())
            .finish()
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        self.task.abort();
        let mut hub = self.hub.lock();
        hub.routes.remove(&self.conv);
        let closed = hub.is_idle();
        if closed {
            hub.closed = true;
        }
        drop(hub);
        if closed {
            hubs().lock().remove(&self.key);
        }
    }
}

/// Connects to `peer` and returns a duplex byte stream.
///
/// mKCP has no handshake: the stream is usable immediately and the first write
/// makes the conversation visible to the peer.
pub async fn connect(peer: SocketAddr, cfg: KcpConfig) -> FluxResult<KcpStream> {
    cfg.validate()?;
    let bind: SocketAddr = if peer.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket =
        Arc::new(UdpSocket::bind(bind).await.map_err(|e| {
            FluxError::Network(format!("mKCP could not bind a local UDP socket: {e}"))
        })?);
    tune_socket(&socket);
    let (hub, key) = hub_for(&socket, cfg.obfs);
    let conv = if cfg.conv == 0 {
        rand::random::<u32>()
    } else {
        cfg.conv
    };
    let inbox = Inbox::new();
    hub.lock().routes.insert(conv, inbox.clone());

    let mut conn = Conn::new(cfg, conv, socket, Some(peer));
    // One window probe makes the conversation recognisable to a peer that is
    // waiting in `accept` before any payload exists.
    let now = Instant::now();
    conn.send_probe(now);
    Ok(spawn_stream(conn, hub, key, inbox))
}

/// Accepts one conversation on `socket`, demultiplexed by `cfg.conv`.
///
/// A `conv` of `0` accepts the next conversation that arrives on the socket and
/// adopts its id; only one such unlearned accept can be pending per socket, and
/// the conversation id must not already be live. The call resolves once the
/// peer's first datagram has been seen, and gives up after 30 seconds so a
/// silent peer cannot hang a listener loop forever.
///
/// The UDP socket's buffers are raised on a best-effort basis: a 512-segment
/// window is roughly 700 KiB of burst, far more than the default 212 KiB
/// receive buffer can hold. A socket whose kernel refuses the increase still
/// works, it just retransmits more.
pub async fn accept(socket: Arc<UdpSocket>, cfg: KcpConfig) -> FluxResult<KcpStream> {
    cfg.validate()?;
    tune_socket(&socket);
    let (hub, key) = hub_for(&socket, cfg.obfs);
    let inbox = Inbox::new();

    let (conv, first) = if cfg.conv == 0 {
        hub.lock().any = Some(inbox.clone());
        let result = next_datagram(&inbox).await;
        let mut hub = hub.lock();
        hub.any = None;
        match result {
            Ok((addr, segment)) => {
                let conv = conversation_of(&segment)?;
                hub.routes.insert(conv, inbox.clone());
                (conv, (addr, segment))
            }
            Err(e) => {
                drop(hub);
                return Err(e);
            }
        }
    } else {
        if hub.lock().routes.insert(cfg.conv, inbox.clone()).is_some() {
            return Err(FluxError::Config(format!(
                "mKCP conversation {:#x} is already accepted on this socket",
                cfg.conv
            )));
        }
        match next_datagram(&inbox).await {
            Ok(first) => (cfg.conv, first),
            Err(e) => {
                hub.lock().routes.remove(&cfg.conv);
                return Err(e);
            }
        }
    };

    let mut conn = Conn::new(cfg, conv, socket, None);
    conn.on_segment(&first.1, first.0, Instant::now());
    Ok(spawn_stream(conn, hub, key, inbox))
}

fn conversation_of(segment: &[u8]) -> FluxResult<u32> {
    if segment.len() < SEGMENT_HEADER_LEN {
        return Err(FluxError::Protocol {
            protocol: "mkcp",
            message: "first datagram is shorter than a segment header".into(),
        });
    }
    Ok(u32::from_le_bytes([
        segment[0], segment[1], segment[2], segment[3],
    ]))
}

/// Waits for one datagram on `inbox`, giving up after [`ACCEPT_TIMEOUT`].
async fn next_datagram(inbox: &Arc<Inbox>) -> FluxResult<(SocketAddr, Vec<u8>)> {
    let deadline = tokio::time::Instant::now() + ACCEPT_TIMEOUT;
    loop {
        if let Some(item) = inbox.pop() {
            return Ok(item);
        }
        // Register before waiting again, so a datagram that lands between the
        // pop and the wait leaves a permit instead of being missed.
        let notified = inbox.notify.notified();
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return Err(FluxError::Timeout(format!(
                "no mKCP conversation arrived within {}s",
                ACCEPT_TIMEOUT.as_secs()
            )));
        }
    }
}

fn spawn_stream(conn: Conn, hub: Arc<Mutex<Hub>>, key: usize, inbox: Arc<Inbox>) -> KcpStream {
    let conv = conn.conv;
    let local = conn.socket.local_addr().ok();
    let inner = Arc::new(Mutex::new(conn));
    let task = tokio::spawn(drive(inner.clone(), inbox));
    KcpStream {
        inner,
        hub,
        key,
        conv,
        task,
        local,
    }
}

/// The one task that drives a conversation: it feeds received datagrams in and
/// runs `flush` on `interval_ms`. Everything else just inspects or feeds state.
async fn drive(inner: Arc<Mutex<Conn>>, inbox: Arc<Inbox>) {
    let interval = {
        let conn = inner.lock();
        Duration::from_millis(u64::from(conn.cfg.interval_ms.max(1)))
    };

    loop {
        // Register before draining: anything that arrives while the batch is
        // being processed leaves a permit that the wait below consumes at once.
        let notified = inbox.notify.notified();
        let batch = inbox.take_all();
        if batch.is_empty() {
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(interval) => {}
            }
        }

        let now = Instant::now();
        let mut conn = inner.lock();
        for (addr, segment) in batch {
            conn.on_segment(&segment, addr, now);
        }
        conn.flush(now);
        if conn.dead.is_some() {
            return;
        }
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().inner.lock();
        if let Some(front) = conn.recv_queue.front() {
            let take = front.len().min(buf.remaining());
            if take == 0 {
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&front[..take]);
            if take == front.len() {
                conn.recv_queue.pop_front();
            } else {
                let rest = front.slice(take..);
                conn.recv_queue[0] = rest;
            }
            // Freeing space in a window we had advertised as zero needs an
            // explicit update, or the peer stays parked in its probe loop.
            if conn.advertised_wnd == 0 {
                conn.window_update = true;
            }
            return Poll::Ready(Ok(()));
        }
        if let Some(kind) = conn.dead {
            return Poll::Ready(Err(io::Error::new(kind, "mKCP stream lost")));
        }
        conn.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut conn = self.get_mut().inner.lock();
        if let Some(kind) = conn.dead {
            return Poll::Ready(Err(io::Error::new(kind, "mKCP stream lost")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mss = conn.cfg.mss();
        let queued = conn.snd_buf.len() + conn.snd_queue.len();
        let free = usize::from(conn.cfg.snd_wnd).saturating_sub(queued);
        if free == 0 {
            // Nothing may enter the send buffer: make sure what is there is on
            // the wire, then wait for acknowledgements to free a slot.
            conn.flush(Instant::now());
            conn.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let take = buf.len().min(free.min(MAX_FRAGMENTS) * mss);
        for segment in fragment(&buf[..take], mss) {
            conn.snd_queue.push_back(segment);
        }
        conn.flush(Instant::now());
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().inner.lock();
        if let Some(kind) = conn.dead {
            return Poll::Ready(Err(io::Error::new(kind, "mKCP stream lost")));
        }
        conn.flush(Instant::now());
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket as TokioUdp;

    /// Deterministic xorshift, so a "20 % loss" run is reproducible.
    struct Rng(u32);

    impl Rng {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }

        fn percent(&mut self) -> u32 {
            self.next() % 100
        }
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u64).wrapping_mul(31).wrapping_add(u64::from(seed)) as u8)
            .collect()
    }

    async fn server_socket() -> Arc<UdpSocket> {
        let socket = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        Arc::new(socket)
    }

    /// The stream has to be usable as a boxed transport in the pipeline.
    #[test]
    fn stream_satisfies_the_required_bounds() {
        fn assert_send_unpin_static<T: Send + Unpin + 'static>() {}
        fn assert_async_rw<T: AsyncRead + AsyncWrite + Send + Unpin>() {}
        assert_send_unpin_static::<KcpStream>();
        assert_async_rw::<KcpStream>();
        assert_send_unpin_static::<KcpConfig>();
    }

    // -- codec ------------------------------------------------------------

    #[test]
    fn segment_round_trip() {
        let seg = Segment {
            cmd: CMD_PUSH,
            frg: 200,
            wnd: 512,
            ts: 7,
            sn: 42,
            una: 41,
            data: b"hello kcp".to_vec(),
        };
        let mut buf = Vec::new();
        encode_segment(0xDEAD_BEEF, &seg, &mut buf);
        assert_eq!(buf.len(), SEGMENT_HEADER_LEN + 9);

        let decoded = decode_segment(0xDEAD_BEEF, &buf).expect("valid segment");
        assert_eq!(decoded.cmd, CMD_PUSH);
        assert_eq!(decoded.frg, 200);
        assert_eq!(decoded.wnd, 512);
        assert_eq!(decoded.ts, 7);
        assert_eq!(decoded.sn, 42);
        assert_eq!(decoded.una, 41);
        assert_eq!(decoded.data, b"hello kcp");
    }

    #[test]
    fn segment_header_is_little_endian_and_24_bytes() {
        let seg = Segment {
            cmd: CMD_ACK,
            frg: 0,
            wnd: 0x0102,
            ts: 0xAABB_CCDD,
            sn: 0x1122_3344,
            una: 0x5566_7788,
            data: Vec::new(),
        };
        let mut buf = Vec::new();
        encode_segment(0x0A0B_0C0D, &seg, &mut buf);
        assert_eq!(buf.len(), 24);
        assert_eq!(&buf[0..4], &[0x0D, 0x0C, 0x0B, 0x0A]);
        assert_eq!(buf[4], CMD_ACK);
        assert_eq!(&buf[6..8], &[0x02, 0x01]);
        assert_eq!(&buf[8..12], &[0xDD, 0xCC, 0xBB, 0xAA]);
        assert_eq!(&buf[12..16], &[0x44, 0x33, 0x22, 0x11]);
        assert_eq!(&buf[16..20], &[0x88, 0x77, 0x66, 0x55]);
        assert_eq!(&buf[20..24], &[0, 0, 0, 0]);
    }

    #[test]
    fn overlong_len_field_is_rejected() {
        let seg = Segment {
            cmd: CMD_PUSH,
            frg: 0,
            wnd: 1,
            ts: 1,
            sn: 1,
            una: 0,
            data: vec![0u8; 16],
        };
        let mut buf = Vec::new();
        encode_segment(1, &seg, &mut buf);
        // Claim 4096 bytes of payload in a 40-byte datagram.
        buf[20..24].copy_from_slice(&4096u32.to_le_bytes());
        assert!(decode_segment(1, &buf).is_none());
        // A length larger than the MTU is rejected by the same check once the
        // datagram is inspected as a whole.
        assert!(decode_segment(1, &buf[..SEGMENT_HEADER_LEN]).is_none());
    }

    #[test]
    fn truncated_segment_is_rejected() {
        let seg = Segment {
            cmd: CMD_PUSH,
            frg: 0,
            wnd: 1,
            ts: 1,
            sn: 1,
            una: 0,
            data: vec![7u8; 32],
        };
        let mut buf = Vec::new();
        encode_segment(1, &seg, &mut buf);
        // Cut the payload in half without touching the length field.
        buf.truncate(SEGMENT_HEADER_LEN + 16);
        assert!(decode_segment(1, &buf).is_none());
        // A datagram shorter than the header itself.
        assert!(decode_segment(1, &buf[..10]).is_none());
        assert!(decode_segment(1, &[]).is_none());
    }

    #[test]
    fn unknown_conv_and_cmd_are_rejected() {
        let seg = Segment {
            cmd: CMD_PUSH,
            frg: 0,
            wnd: 1,
            ts: 1,
            sn: 1,
            una: 0,
            data: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        encode_segment(0x1234, &seg, &mut buf);
        assert!(decode_segment(0x1235, &buf).is_none());
        let mut bogus = buf.clone();
        bogus[4] = 0x7F; // not a command we speak
        assert!(decode_segment(0x1234, &bogus).is_none());
    }

    #[test]
    fn envelope_round_trip_and_corruption() {
        for len in [0usize, 1, 2, 3, 4, 5, 23, 24, 1310, 4096] {
            let plain = payload(len, 9);
            let mut framed = Vec::new();
            envelope::seal(&plain, &mut framed);
            assert!(framed.len() >= plain.len() + envelope::OVERHEAD);
            assert_eq!(envelope::open(&framed).as_deref(), Some(plain.as_slice()));
        }

        let plain = payload(64, 1);
        let mut framed = Vec::new();
        envelope::seal(&plain, &mut framed);
        // Flip one payload byte: the fnv hash must catch it.
        let last = framed.len() - 1;
        framed[last] ^= 0x40;
        assert!(envelope::open(&framed).is_none());
        // Truncate: the length check must catch it.
        let mut framed2 = Vec::new();
        envelope::seal(&plain, &mut framed2);
        framed2.truncate(framed2.len() - 4);
        assert!(envelope::open(&framed2).is_none());
        // Arbitrary bytes are never a valid frame.
        assert!(envelope::open(&payload(128, 2)).is_none());
        assert!(envelope::open(&[]).is_none());
    }

    #[test]
    fn obfs_headers_have_the_expected_shape() {
        // SRTP: constant prefix, counter that advances.
        let mut state = ObfsState::new(KcpObfs::Srtp);
        let mut first = Vec::new();
        state.wrap(b"segment", &mut first);
        let mut second = Vec::new();
        state.wrap(b"segment", &mut second);
        assert_eq!(&first[0..2], &[0xB5, 0xE8]);
        assert_eq!(&second[0..2], &[0xB5, 0xE8]);
        assert_ne!(&first[2..4], &second[2..4], "counter must advance");
        // Round trip through the reader.
        assert_eq!(
            unwrap_datagram(KcpObfs::Srtp, &first).as_deref(),
            Some(b"segment".as_slice())
        );

        // The remaining modes only differ in header length and framing.
        for (mode, len) in [
            (KcpObfs::None, 0usize),
            (KcpObfs::Srtp, 4),
            (KcpObfs::Utp, 4),
            (KcpObfs::WechatVideo, 13),
            (KcpObfs::Dtls, 13),
            (KcpObfs::Wireguard, 4),
        ] {
            let mut state = ObfsState::new(mode);
            let mut framed = Vec::new();
            state.wrap(b"payload!", &mut framed);
            assert_eq!(mode.header_len(), len, "{mode:?}");
            assert_eq!(
                unwrap_datagram(mode, &framed).as_deref(),
                Some(b"payload!".as_slice()),
                "{mode:?} must round trip"
            );
            // A datagram that is only a header must be dropped, not panic.
            assert!(unwrap_datagram(mode, &framed[..len]).is_none());
            assert!(unwrap_datagram(mode, &[]).is_none());
        }

        // WireGuard is a constant, WeChat carries a monotonically increasing sn.
        let mut wg = ObfsState::new(KcpObfs::Wireguard);
        let mut a = Vec::new();
        wg.wrap(b"x", &mut a);
        assert_eq!(&a[0..4], &[0x04, 0x00, 0x00, 0x00]);
        let mut wc = ObfsState::new(KcpObfs::WechatVideo);
        let mut b1 = Vec::new();
        let mut b2 = Vec::new();
        wc.wrap(b"x", &mut b1);
        wc.wrap(b"x", &mut b2);
        assert_eq!(&b1[0..2], &[0xA1, 0x08]);
        assert_ne!(&b1[2..6], &b2[2..6]);
    }

    #[test]
    fn mss_accounts_for_every_layer() {
        let cfg = KcpConfig {
            mtu: 1350,
            obfs: KcpObfs::Srtp,
            ..KcpConfig::default()
        };
        assert_eq!(cfg.mss(), 1350 - 24 - 4 - 6);
        let plain = KcpConfig {
            mtu: 1350,
            obfs: KcpObfs::None,
            ..KcpConfig::default()
        };
        assert_eq!(plain.mss(), 1350 - 24 - 6);
        // A datagram built at the MTU must not exceed it.
        let mut state = ObfsState::new(KcpObfs::Srtp);
        let mut framed = Vec::new();
        state.wrap(&vec![0u8; cfg.mss()], &mut framed);
        assert!(framed.len() <= 1350);
    }

    #[test]
    fn invalid_configs_are_refused() {
        let tiny = KcpConfig {
            mtu: 40,
            ..KcpConfig::default()
        };
        assert!(matches!(tiny.validate(), Err(FluxError::Config(_))));
        let no_interval = KcpConfig {
            interval_ms: 0,
            ..KcpConfig::default()
        };
        assert!(matches!(no_interval.validate(), Err(FluxError::Config(_))));
        let zero_wnd = KcpConfig {
            snd_wnd: 0,
            ..KcpConfig::default()
        };
        assert!(matches!(zero_wnd.validate(), Err(FluxError::Config(_))));
        assert!(KcpConfig::default().validate().is_ok());
    }

    #[test]
    fn fragments_count_down_from_255() {
        let cfg = KcpConfig::default();
        let mss = cfg.mss();
        let data = payload(mss * 3 + 7, 3);
        let queued = fragment(&data, mss);

        assert_eq!(queued.len(), 4);
        let frg: Vec<u8> = queued.iter().map(|q| q.frg).collect();
        assert_eq!(frg, vec![255, 254, 253, 252]);

        // Reassembly is concatenation in order, which is what the reader does.
        let mut assembled = Vec::new();
        for item in &queued {
            assembled.extend_from_slice(&item.data);
        }
        assert_eq!(assembled, data);

        // The last fragment is short; the others are full.
        assert_eq!(queued[3].data.len(), 7);
        assert_eq!(queued[0].data.len(), mss);

        // A write that fits in one segment is a single fragment.
        let single = fragment(b"short", mss);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].frg, 255);
    }

    // -- end to end -------------------------------------------------------

    /// Server side of an echo: accept, then copy everything back in chunks.
    ///
    /// It pumps instead of reading the whole payload first, because two peers
    /// that each write their full payload before reading would deadlock once
    /// the payload exceeds a receive window.
    async fn echo_server(socket: Arc<UdpSocket>, cfg: KcpConfig, expect: usize) -> KcpStats {
        let mut stream = tokio::time::timeout(Duration::from_secs(60), accept(socket, cfg))
            .await
            .expect("accept timed out")
            .expect("accept failed");
        let mut buf = vec![0u8; 16 * 1024];
        let mut remaining = expect;
        while remaining > 0 {
            let want = remaining.min(buf.len());
            let n = stream.read(&mut buf[..want]).await.expect("server read");
            if n == 0 {
                break;
            }
            stream
                .write_all(&buf[..n])
                .await
                .expect("server echo failed");
            remaining -= n;
        }
        stream.flush().await.expect("flush failed");
        let stats = stream.stats();
        // Keep the conversation alive long enough for the last ACKs to arrive,
        // so the client is not left retransmitting into a closed stream.
        tokio::time::sleep(Duration::from_millis(100)).await;
        stats
    }

    /// One echo exchange on an open stream: writes `data` while concurrently
    /// reading `data.len()` bytes back, the way a proxy actually uses a stream.
    /// Returns what came back plus the client-side counters.
    async fn exchange(stream: KcpStream, data: Vec<u8>) -> (Vec<u8>, KcpStats) {
        let inner = stream.inner.clone();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let expected = data.len();
        let write_half = async move {
            writer.write_all(&data).await.expect("client write failed");
            writer.flush().await.expect("client flush failed");
        };
        let read_half = async move {
            let mut got = vec![0u8; expected];
            reader
                .read_exact(&mut got)
                .await
                .expect("client read failed");
            got
        };
        let ((), echoed) = tokio::join!(write_half, read_half);
        let stats = inner.lock().snapshot();
        (echoed, stats)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn round_trip_one_mib() {
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0001,
            ..KcpConfig::default()
        };

        let server = tokio::spawn(echo_server(socket, cfg, 1024 * 1024));
        let client = connect(addr, cfg).await.expect("connect failed");
        let data = payload(1024 * 1024, 5);
        let (echoed, stats) = exchange(client, data.clone()).await;

        assert_eq!(echoed.len(), data.len());
        assert!(echoed == data, "1 MiB round trip is not byte-exact");
        println!("1 MiB loopback: {stats:?}");
        server.await.expect("server task panicked");
    }

    /// A relay in front of the server socket that can drop, reorder or corrupt.
    struct Relay {
        socket: Arc<UdpSocket>,
        server: SocketAddr,
        client: Option<SocketAddr>,
        drop_percent: u32,
        reorder: bool,
        hold: Vec<(Vec<u8>, SocketAddr)>,
        rng: Rng,
        inject: usize,
        obfs: KcpObfs,
    }

    impl Relay {
        fn new(
            socket: Arc<UdpSocket>,
            server: SocketAddr,
            drop_percent: u32,
            seed: u32,
            obfs: KcpObfs,
        ) -> Self {
            Self {
                socket,
                server,
                client: None,
                drop_percent,
                reorder: false,
                hold: Vec::new(),
                rng: Rng(seed),
                inject: 0,
                obfs,
            }
        }

        async fn run(mut self, stop: tokio::sync::oneshot::Receiver<()>) {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let mut stop = stop;
            let mut housekeeping = tokio::time::interval(Duration::from_millis(25));
            loop {
                tokio::select! {
                    _ = &mut stop => break,
                    received = self.socket.recv_from(&mut buf) => {
                        let Ok((n, from)) = received else { break };
                        let datagram = buf[..n].to_vec();
                        self.handle(datagram, from).await;
                    }
                    _ = housekeeping.tick() => {
                        // Deliver anything a reordering hold has left over.
                        self.flush_hold().await;
                    }
                }
            }
            self.flush_hold().await;
        }

        async fn handle(&mut self, datagram: Vec<u8>, from: SocketAddr) {
            if from == self.server {
                // Server -> client, forwarded to whoever last spoke to us.
                if let Some(client) = self.client
                    && self.rng.percent() >= self.drop_percent
                {
                    let _ = self.socket.send_to(&datagram, client).await;
                }
                return;
            }

            // Client -> server.
            self.client = Some(from);
            if self.rng.percent() < self.drop_percent {
                return;
            }

            if self.inject > 0 {
                self.inject -= 1;
                for hostile in self.hostile_datagrams(&datagram) {
                    let _ = self.socket.send_to(&hostile, self.server).await;
                }
            }

            if self.reorder {
                self.hold.push((datagram, self.server));
                if self.hold.len() >= 2 {
                    // Deliver the pair newest-first: guaranteed out of order.
                    let second = self.hold.pop().unwrap();
                    let first = self.hold.pop().unwrap();
                    let _ = self.socket.send_to(&second.0, second.1).await;
                    let _ = self.socket.send_to(&first.0, first.1).await;
                }
            } else {
                let _ = self.socket.send_to(&datagram, self.server).await;
            }
        }

        /// Well-framed garbage that a real peer could send: a segment with a
        /// lying length field, a truncated one, and one for a foreign
        /// conversation. All of it is properly wrapped, so it reaches the
        /// segment parser instead of dying in the obfuscation layer.
        fn hostile_datagrams(&self, datagram: &[u8]) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            // Not even a valid frame.
            out.push(vec![0xAA; 7]);
            out.push(datagram[..datagram.len() / 2].to_vec());

            let Some(segment) = unwrap_datagram(self.obfs, datagram) else {
                return out;
            };
            if segment.len() < SEGMENT_HEADER_LEN {
                return out;
            }
            let wrap = |plain: &[u8]| {
                let mut state = ObfsState::new(self.obfs);
                let mut framed = Vec::new();
                state.wrap(plain, &mut framed);
                framed
            };

            // A PUSH that claims 10 000 bytes of payload while carrying none.
            let mut lying = segment.clone();
            lying[20..24].copy_from_slice(&10_000u32.to_le_bytes());
            out.push(wrap(&lying));

            // A foreign conversation id.
            let mut foreign = segment.clone();
            let conv = u32::from_le_bytes([foreign[0], foreign[1], foreign[2], foreign[3]]);
            foreign[0..4].copy_from_slice(&conv.wrapping_add(1).to_le_bytes());
            out.push(wrap(&foreign));

            // A segment whose payload was cut off but whose length was not.
            let mut truncated = segment.clone();
            truncated.truncate(SEGMENT_HEADER_LEN + 1);
            out.push(wrap(&truncated));

            // An unknown command.
            let mut bogus = segment;
            bogus[4] = 0x7F;
            out.push(wrap(&bogus));
            out
        }

        async fn flush_hold(&mut self) {
            for (datagram, to) in std::mem::take(&mut self.hold) {
                let _ = self.socket.send_to(&datagram, to).await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn round_trip_survives_twenty_percent_loss() {
        let socket = server_socket().await;
        let server_addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0002,
            ..KcpConfig::default()
        };

        let relay_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let relay = Relay::new(relay_socket, server_addr, 20, 0xC0FF_EE01, cfg.obfs);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(stop_rx));

        const SIZE: usize = 256 * 1024;
        let server = tokio::spawn(echo_server(socket, cfg, SIZE));
        let client = connect(relay_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 11);
        let transfer = exchange(client, data.clone());
        let (echoed, stats) = tokio::time::timeout(Duration::from_secs(120), transfer)
            .await
            .expect("transfer under 20 % loss did not finish in time");
        assert!(echoed == data, "lossy round trip is not byte-exact");

        println!("20 % loss: {stats:?}");
        assert!(
            stats.segments_retransmitted > 0,
            "20 % loss must have forced retransmissions, stats: {stats:?}"
        );
        assert_eq!(
            stats.segments_retransmitted,
            stats.fast_retransmits + stats.timer_retransmits,
            "every retransmission should be attributable"
        );
        let server_stats = server.await.expect("server task panicked");
        println!("20 % loss (server side): {server_stats:?}");
        let _ = stop_tx.send(());
        relay_task.await.expect("relay task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn out_of_order_delivery_completes() {
        let socket = server_socket().await;
        let server_addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0003,
            ..KcpConfig::default()
        };

        let relay_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let mut relay = Relay::new(relay_socket, server_addr, 0, 0x1234_5678, cfg.obfs);
        relay.reorder = true;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(stop_rx));

        const SIZE: usize = 64 * 1024;
        let server = tokio::spawn(echo_server(socket, cfg, SIZE));
        let client = connect(relay_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 17);
        let transfer = exchange(client, data.clone());
        let (echoed, stats) = tokio::time::timeout(Duration::from_secs(60), transfer)
            .await
            .expect("reordered transfer did not finish in time");
        assert!(echoed == data, "reordered round trip is not byte-exact");
        println!("out of order: {stats:?}");

        server.await.expect("server task panicked");
        let _ = stop_tx.send(());
        relay_task.await.expect("relay task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hostile_datagrams_are_dropped_without_panic() {
        let socket = server_socket().await;
        let server_addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0004,
            ..KcpConfig::default()
        };

        let relay_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let mut relay = Relay::new(relay_socket, server_addr, 0, 0xABCD_1234, cfg.obfs);
        relay.inject = 3;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(stop_rx));

        const SIZE: usize = 32 * 1024;
        let server = tokio::spawn(echo_server(socket, cfg, SIZE));
        let client = connect(relay_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 23);
        let transfer = exchange(client, data.clone());
        let (echoed, stats) = tokio::time::timeout(Duration::from_secs(60), transfer)
            .await
            .expect("transfer alongside hostile datagrams stalled");
        assert!(echoed == data, "hostile datagrams corrupted the stream");
        println!("hostile: {stats:?}");

        server.await.expect("server task panicked");
        let _ = stop_tx.send(());
        relay_task.await.expect("relay task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_larger_than_mtu_is_fragmented_and_reassembled() {
        let socket = server_socket().await;
        let server_addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0005,
            // A small MTU makes the fragmentation obvious on the wire.
            mtu: 300,
            ..KcpConfig::default()
        };
        let mss = cfg.mss();

        const SIZE: usize = 5000;
        let expected_fragments = SIZE.div_ceil(mss);
        assert!(expected_fragments >= 3, "test needs real fragmentation");

        // A tap that records the `frg` values of the PUSH segments of the first
        // write. One write of SIZE bytes is one fragment run, so the first
        // `expected_fragments` PUSH segments of the conversation are exactly it.
        let tap_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let tap_addr = tap_socket.local_addr().unwrap();
        let (frg_tx, frg_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let tap = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let mut client_addr: Option<SocketAddr> = None;
            let mut seen: Vec<u8> = Vec::new();
            let mut tx = Some(frg_tx);
            loop {
                let Ok((n, from)) = tap_socket.recv_from(&mut buf).await else {
                    break;
                };
                if from == server_addr {
                    if let Some(client) = client_addr {
                        let _ = tap_socket.send_to(&buf[..n], client).await;
                    }
                    continue;
                }
                client_addr = Some(from);
                if tx.is_some() {
                    let seen_push = unwrap_datagram(cfg.obfs, &buf[..n])
                        .and_then(|segment| decode_segment(cfg.conv, &segment))
                        .filter(|seg| seg.cmd == CMD_PUSH && !seg.data.is_empty());
                    if let Some(seg) = seen_push {
                        seen.push(seg.frg);
                        if seen.len() == expected_fragments
                            && let Some(sender) = tx.take()
                        {
                            let _ = sender.send(std::mem::take(&mut seen));
                        }
                    }
                }
                let _ = tap_socket.send_to(&buf[..n], server_addr).await;
            }
        });

        let server = tokio::spawn(echo_server(socket, cfg, SIZE));
        let client = connect(tap_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 29);
        let (echoed, _stats) = exchange(client, data.clone()).await;
        assert!(echoed == data, "fragmented write is not byte-exact");

        let frg = tokio::time::timeout(Duration::from_secs(5), frg_rx)
            .await
            .expect("tap never saw fragments")
            .expect("tap dropped its channel");
        assert_eq!(frg[0], 255, "first fragment must be 255");
        assert_eq!(frg.len(), expected_fragments);
        for window in frg.windows(2) {
            assert_eq!(
                window[1],
                window[0].wrapping_sub(1),
                "fragment indices must count down: {frg:?}"
            );
        }

        server.await.expect("server task panicked");
        tap.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn congestion_controlled_transfer_works() {
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_000A,
            no_congestion: false,
            ..KcpConfig::default()
        };
        let server = tokio::spawn(echo_server(socket, cfg, 128 * 1024));
        let client = connect(addr, cfg).await.expect("connect failed");
        let data = payload(128 * 1024, 37);
        let (echoed, stats) = exchange(client, data.clone()).await;
        assert!(
            echoed == data,
            "congestion-controlled round trip is not byte-exact"
        );
        println!("congestion control: {stats:?}");
        server.await.expect("server task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accept_learns_the_conversation() {
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0, // accept whatever arrives
            ..KcpConfig::default()
        };

        let (conv_tx, conv_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept(socket, cfg).await.expect("accept failed");
            let _ = conv_tx.send(stream.conv());
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.expect("read failed");
            stream.write_all(&buf).await.expect("write failed");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let client = connect(addr, cfg).await.expect("connect failed");
        let client_conv = client.conv();
        let (echoed, _stats) = exchange(client, b"ping".to_vec()).await;
        assert_eq!(&echoed, b"ping");
        assert_eq!(
            conv_rx.await.expect("server never reported its conv"),
            client_conv,
            "accept must adopt the conversation id the client chose"
        );
        server.await.expect("server task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_conversations_share_one_socket() {
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg_a = KcpConfig {
            conv: 0xC0DE_0001,
            ..KcpConfig::default()
        };
        let cfg_b = KcpConfig {
            conv: 0xC0DE_0002,
            ..KcpConfig::default()
        };

        let server_a = tokio::spawn(echo_server(socket.clone(), cfg_a, 4096));
        let server_b = tokio::spawn(echo_server(socket.clone(), cfg_b, 8192));

        let client_a = connect(addr, cfg_a).await.expect("connect failed");
        let client_b = connect(addr, cfg_b).await.expect("connect failed");
        let data_a = payload(4096, 41);
        let data_b = payload(8192, 43);
        let (echo_a, echo_b) = tokio::join!(
            exchange(client_a, data_a.clone()),
            exchange(client_b, data_b.clone())
        );
        assert!(echo_a.0 == data_a, "conversation A got the wrong bytes");
        assert!(echo_b.0 == data_b, "conversation B got the wrong bytes");
        server_a.await.expect("server A panicked");
        server_b.await.expect("server B panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn silent_peer_cannot_grow_the_send_buffer() {
        // A socket nobody reads from and nobody answers: the worst case for the
        // send path, which must stop instead of buffering the whole write.
        let blackhole = server_socket().await;
        let blackhole_addr = blackhole.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0008,
            snd_wnd: 64,
            ..KcpConfig::default()
        };
        let mut client = connect(blackhole_addr, cfg).await.expect("connect failed");
        let chunk = vec![0x5Au8; 8 * 1024];

        let flood = async {
            for _ in 0..1_000 {
                client.write_all(&chunk).await.expect("write failed");
            }
        };
        let blocked = tokio::time::timeout(Duration::from_millis(250), flood).await;
        assert!(
            blocked.is_err(),
            "writing 8 MiB to a silent peer must block once the window is full"
        );

        let inner = client.inner.clone();
        let (queued, sent) = {
            let conn = inner.lock();
            (
                conn.snd_buf.len() + conn.snd_queue.len(),
                conn.stats.segments_sent,
            )
        };
        assert!(
            queued <= usize::from(cfg.snd_wnd),
            "send buffer grew past the window: {queued} segments for a window of {}",
            cfg.snd_wnd
        );
        assert!(
            sent <= 8 * u64::from(cfg.snd_wnd),
            "sent {sent} segments to a peer that never acknowledged one"
        );
    }

    // -- measurements -----------------------------------------------------

    /// Echoes single bytes back until told to stop: the latency counterpart of
    /// [`echo_server`], which answers exactly one fixed-size transfer.
    async fn ping_pong_server(
        socket: Arc<UdpSocket>,
        cfg: KcpConfig,
        stop: tokio::sync::oneshot::Receiver<()>,
    ) {
        let accepted = tokio::time::timeout(Duration::from_secs(60), accept(socket, cfg)).await;
        let Ok(Ok(mut stream)) = accepted else {
            return;
        };
        let mut byte = [0u8; 1];
        tokio::select! {
            _ = stop => {}
            _ = async {
                loop {
                    if stream.read_exact(&mut byte).await.is_err() {
                        break;
                    }
                    if stream.write_all(&byte).await.is_err() {
                        break;
                    }
                }
            } => {}
        }
    }

    /// Throughput and one-way latency, mKCP against a plain UDP echo on the same
    /// machine. Prints its numbers; assertions are deliberately loose so the
    /// test is a measurement, not a flaky benchmark gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn measure_throughput_and_latency() {
        const SIZE: usize = 4 * 1024 * 1024;
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED_0006,
            ..KcpConfig::default()
        };

        // --- plain UDP baseline: echo SIZE bytes with the same datagram size.
        let udp_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let udp_addr = udp_socket.local_addr().unwrap();
        let udp_echo = {
            let socket = udp_socket.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1400];
                loop {
                    let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                        break;
                    };
                    let _ = socket.send_to(&buf[..n], from).await;
                }
            })
        };
        let client_udp = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        client_udp.connect(udp_addr).await.unwrap();
        let chunk = 1310usize;
        let mut got = vec![0u8; 1400];
        let udp_start = Instant::now();
        let mut sent = 0usize;
        while sent < SIZE {
            let n = chunk.min(SIZE - sent);
            client_udp.send(&vec![0x5Au8; n]).await.unwrap();
            let _ = client_udp.recv(&mut got).await.unwrap();
            sent += n;
        }
        let udp_elapsed = udp_start.elapsed();

        // Latency baseline: 200 ping-pongs of one byte.
        let mut udp_lat = Duration::ZERO;
        for _ in 0..200 {
            let start = Instant::now();
            client_udp.send(&[0x01u8]).await.unwrap();
            let _ = client_udp.recv(&mut got).await.unwrap();
            udp_lat += start.elapsed();
        }
        let udp_one_way = udp_lat / 400;
        udp_echo.abort();

        // --- mKCP bulk: same payload size, echoed back by the server.
        let mss = cfg.mss();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE));
        let client = connect(addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 31);
        let kcp_start = Instant::now();
        let write_and_read = exchange(client, data.clone());
        // Joined with the server so a server-side failure surfaces here instead
        // of turning into a silent stall on the client side.
        let (transfer, server_result) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(180), write_and_read),
            server
        );
        let kcp_elapsed = kcp_start.elapsed();
        server_result.expect("server task panicked");
        let (echoed, bulk_stats) = transfer.expect("mKCP measurement transfer did not finish");
        assert!(echoed == data, "measurement transfer must be byte-exact");

        // --- mKCP latency on its own conversation: the bulk server above has
        // already consumed its one payload and gone away.
        let latency_socket = server_socket().await;
        let latency_addr = latency_socket.local_addr().unwrap();
        let latency_cfg = KcpConfig {
            conv: 0x5EED_0007,
            ..KcpConfig::default()
        };
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let pump = tokio::spawn(ping_pong_server(latency_socket, latency_cfg, stop_rx));
        let mut pinger = connect(latency_addr, latency_cfg)
            .await
            .expect("connect failed");

        let mut kcp_lat = Duration::ZERO;
        let mut byte = [0u8; 1];
        for _ in 0..200 {
            let start = Instant::now();
            pinger.write_all(&[0x42u8]).await.expect("write failed");
            pinger.read_exact(&mut byte).await.expect("read failed");
            kcp_lat += start.elapsed();
        }
        let kcp_one_way = kcp_lat / 400;
        let pinger_stats = pinger.stats();
        let _ = stop_tx.send(());
        pump.await.expect("pump task panicked");

        let udp_bps = SIZE as f64 / udp_elapsed.as_secs_f64();
        let kcp_bps = SIZE as f64 / kcp_elapsed.as_secs_f64();
        println!(
            "\n=== mKCP vs plain UDP (loopback, {SIZE} B payload, mss {mss} B, wnd {}) ===\n\
             udp  echo    : {:>8.2} MiB/s   one-way ~{:>7.1} us\n\
             mkcp echo    : {:>8.2} MiB/s   one-way ~{:>7.1} us  ({:.1}% of UDP)\n\
             mkcp bulk    : {} segments, {} retransmitted ({} fast / {} timer), srtt {} us, rto {} ms\n\
             mkcp ping    : srtt {} us, rto {} ms, {} segments\n",
            cfg.snd_wnd,
            udp_bps / (1024.0 * 1024.0),
            udp_one_way.as_secs_f64() * 1e6,
            kcp_bps / (1024.0 * 1024.0),
            kcp_one_way.as_secs_f64() * 1e6,
            kcp_bps / udp_bps * 100.0,
            bulk_stats.segments_sent,
            bulk_stats.segments_retransmitted,
            bulk_stats.fast_retransmits,
            bulk_stats.timer_retransmits,
            bulk_stats.srtt_us,
            bulk_stats.rto_ms,
            pinger_stats.srtt_us,
            pinger_stats.rto_ms,
            pinger_stats.segments_sent,
        );

        // Loose sanity gates: this is loopback, so anything below these numbers
        // means the ARQ is stuck rather than merely slow.
        assert!(
            kcp_bps > 1024.0 * 1024.0,
            "mKCP throughput collapsed: {kcp_bps} B/s"
        );
        assert!(
            kcp_one_way < Duration::from_millis(50),
            "mKCP one-way latency collapsed: {kcp_one_way:?}"
        );
    }
}
