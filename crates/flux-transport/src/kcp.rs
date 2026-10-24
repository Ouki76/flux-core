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
//! differences. The obfuscation layer, on the other hand, is byte-exact with
//! Xray (`transport/internet/headers/*` and `crypt.go` /
//! `finalmask/mkcp/original`), so swapping the segment codec is the only change
//! needed for the framing to match.
//!
//! Three further gaps, all deliberate and all visible to a real Xray peer:
//!
//! * Command set. ikcp has PUSH/ACK/WASK/WINS only; Xray adds `PING` and
//!   `TERMINATE`. A stream here has no close, so a peer that stops without
//!   closing looks like silence, which is why liveness falls back to probing
//!   (see `PEER_SILENCE_LIMIT`).
//! * Payload encryption. Xray's `seed` option replaces the "original" mask with
//!   an AES-GCM AEAD keyed from the seed (`NewAEADAESGCMBasedOnSeed`, now
//!   `finalmask/mkcp/aes128gcm`). [`KcpObfs`] has no such mode, and a peer
//!   configured with `seed` cannot be read by this module.
//! * Congestion control shape. `no_congestion` mirrors Xray's `congestion:
//!   false` (a fixed window), but the adaptive path here is a plain
//!   slow-start/AIMD on the window rather than Xray's
//!   `tti`/`uplinkCapacity`/`cwndMultiplier` pacing.
//!
//! # Behaviour
//!
//! * One task drives `flush` on `Conn` on `interval_ms`; there is no task per
//!   segment. Reads and writes only ever take a short lock and hand work to the
//!   driver.
//! * The send buffer is bounded by `snd_wnd` segments: a writer that outruns the
//!   peer gets `Pending`, never unbounded growth, and a peer that stops ACKing
//!   trips the retry limit and fails the stream instead of buffering forever.
//! * Datagrams that fail deobfuscation, carry a foreign conversation id, claim a
//!   length beyond the MTU or are truncated are dropped silently — a hostile
//!   peer can only cost CPU, never a panic.
//! * RTT is measured from the local send time of the acknowledged segment rather
//!   than from the millisecond `ts` echo, so the estimate has microsecond
//!   resolution; Karn's rule still applies, and no retransmitted segment
//!   contributes a sample.
//! * An idle conversation exchanges a window probe every ten seconds and is
//!   declared lost after a minute of complete silence, because mKCP has no FIN
//!   to tell one end that the other has gone.
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

/// Bytes of every segment prefix: `conv u16 ‖ cmd u8 ‖ option u8`.
pub const SEGMENT_PREFIX_LEN: usize = 4;
/// Total header of a DATA segment (prefix included): the payload follows.
pub const DATA_OVERHEAD: usize = 18;
/// Header of an ACK segment, before the `u32` number list.
pub const ACK_OVERHEAD: usize = 17;
/// Size of a PING or TERMINATE segment, which carries no payload.
pub const CMD_ONLY_LEN: usize = 16;

/// Acknowledgement of data received from the peer.
pub const CMD_ACK: u8 = 0;
/// Stream data.
pub const CMD_DATA: u8 = 1;
/// The peer is closing the conversation.
pub const CMD_TERMINATE: u8 = 2;
/// Liveness probe, also a vehicle for a cumulative acknowledgement.
pub const CMD_PING: u8 = 3;

/// `option` value meaning "this side is closing" (`SegmentOptionClose`).
pub const OPTION_CLOSE: u8 = 1;

/// An ACK segment carries at most this many segment numbers.
pub const MAX_ACK_NUMBERS: usize = 128;

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
/// How often to send a PING when the conversation is otherwise quiet. Xray
/// pings on a three-second timer, and the same value keeps our own liveness
/// detection (`PEER_SILENCE_LIMIT`) honest in both directions.
const PING_IDLE: Duration = Duration::from_secs(3);
/// Nothing at all from the peer for this long, while we keep probing, means the
/// conversation is gone.
///
/// mKCP has no FIN — a stream that is simply abandoned leaves the other end
/// reading into silence — so liveness has to be inferred. Both ends probe every
/// [`KEEPALIVE_IDLE`] when idle and answer probes with a window update, so a
/// live peer is never quiet for a tenth of this, and six lost probes in a row
/// are needed to trip it.
const PEER_SILENCE_LIMIT: Duration = Duration::from_secs(60);
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

/// One wire segment.
///
/// Xray has four commands and three bodies, all big-endian behind a four-byte
/// prefix (`conv u16 ‖ cmd u8 ‖ option u8`). Three things are easy to get wrong
/// and are deliberate here: the conversation id is 16 bits, there is **no
/// fragment index** — the fourth byte is an option flag, and reassembly is by
/// `sn` — and DATA carries no receive window, which only ACK does.
#[derive(Debug, Default)]
struct Segment {
    cmd: u8,
    option: u8,
    /// DATA: sender clock, ms. ACK: the newest timestamp it acknowledges.
    ts: u32,
    /// DATA: segment number.
    sn: u32,
    /// DATA/PING/TERMINATE: next number the sender expects from us (a
    /// cumulative acknowledgement, Xray's `SendingNext`).
    sending_next: u32,
    /// ACK: first number the sender of the ACK has not received (Xray's
    /// `ReceivingNext`).
    receiving_next: u32,
    /// ACK: absolute right edge of the sender's receive window (Xray's
    /// `ReceivingWindow`, which is `next + window size`, not a free count).
    window_edge: u32,
    /// ACK: the segment numbers being acknowledged.
    numbers: Vec<u32>,
    /// PING/TERMINATE: the peer's retransmission timeout, ms.
    peer_rto: u32,
    /// DATA payload.
    data: Vec<u8>,
}

impl Segment {
    fn data(sn: u32, sending_next: u32, ts: u32, data: Vec<u8>) -> Self {
        Self {
            cmd: CMD_DATA,
            ts,
            sn,
            sending_next,
            data,
            ..Self::default()
        }
    }

    fn ack(receiving_next: u32, window_edge: u32, ts: u32, numbers: Vec<u32>) -> Self {
        Self {
            cmd: CMD_ACK,
            ts,
            receiving_next,
            window_edge,
            numbers,
            ..Self::default()
        }
    }

    fn command(cmd: u8, sending_next: u32, receiving_next: u32, peer_rto: u32) -> Self {
        Self {
            cmd,
            sending_next,
            receiving_next,
            peer_rto,
            ..Self::default()
        }
    }

    fn wire_len(&self) -> usize {
        match self.cmd {
            CMD_DATA => DATA_OVERHEAD + self.data.len(),
            CMD_ACK => ACK_OVERHEAD + self.numbers.len() * 4,
            _ => CMD_ONLY_LEN,
        }
    }
}

fn encode_segment(conv: u16, seg: &Segment, out: &mut Vec<u8>) {
    out.extend_from_slice(&conv.to_be_bytes());
    out.push(seg.cmd);
    out.push(seg.option);
    match seg.cmd {
        CMD_DATA => {
            out.extend_from_slice(&seg.ts.to_be_bytes());
            out.extend_from_slice(&seg.sn.to_be_bytes());
            out.extend_from_slice(&seg.sending_next.to_be_bytes());
            out.extend_from_slice(&(seg.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&seg.data);
        }
        CMD_ACK => {
            out.extend_from_slice(&seg.window_edge.to_be_bytes());
            out.extend_from_slice(&seg.receiving_next.to_be_bytes());
            out.extend_from_slice(&seg.ts.to_be_bytes());
            out.push(seg.numbers.len() as u8);
            for number in &seg.numbers {
                out.extend_from_slice(&number.to_be_bytes());
            }
        }
        _ => {
            out.extend_from_slice(&seg.sending_next.to_be_bytes());
            out.extend_from_slice(&seg.receiving_next.to_be_bytes());
            out.extend_from_slice(&seg.peer_rto.to_be_bytes());
        }
    }
}

/// Parses one segment, returning it with the number of bytes it consumed.
///
/// `None` means these bytes are not a well-formed segment for `conv`: too short,
/// a foreign conversation id, an unknown command, or a length field that runs
/// past the datagram (which covers truncation and an inflated `len` alike).
/// Parses a captured datagram and describes it, for diagnosing a foreign peer.
///
/// Exists because "our mKCP is self-consistent" proves nothing: when an Xray node
/// refuses our traffic, the only useful evidence is what the bytes actually mean.
/// Feed it a hex dump from a capture and it prints the header, the mask envelope and
/// every segment field.
#[doc(hidden)]
pub fn debug_parse(obfs: KcpObfs, datagram: &[u8]) -> String {
    let header_len = obfs.header_len();
    if datagram.len() < header_len {
        return format!(
            "datagram of {} bytes is shorter than the {header_len}-byte header",
            datagram.len()
        );
    }
    let header = &datagram[..header_len];
    let Some(plain) = envelope::open(&datagram[header_len..]) else {
        return format!(
            "header={} — mask envelope rejected (bad hash or length); first bytes {:02x?}",
            hex(header),
            &datagram[header_len..datagram.len().min(header_len + 8)]
        );
    };
    if plain.len() < 4 {
        return format!(
            "header={} envelope payload {} bytes, too short",
            hex(header),
            plain.len()
        );
    }
    let conv = u16::from_be_bytes([plain[0], plain[1]]);
    match decode_segment(conv, &plain) {
        Some((seg, used)) => format!(
            "header={} conv={conv} cmd={} option={} ts={} sn={} sending_next={} received_next={} \
             data={} bytes, segment={used} bytes",
            hex(header),
            seg.cmd,
            seg.option,
            seg.ts,
            seg.sn,
            seg.sending_next,
            seg.receiving_next,
            seg.data.len()
        ),
        None => format!(
            "header={} conv={conv} but the segment did not decode; raw {:02x?}",
            hex(header),
            &plain[2..plain.len().min(2 + 20)]
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_segment(conv: u16, buf: &[u8]) -> Option<(Segment, usize)> {
    if buf.len() < SEGMENT_PREFIX_LEN {
        return None;
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != conv {
        return None;
    }
    let cmd = buf[2];
    let option = buf[3];
    let body = &buf[SEGMENT_PREFIX_LEN..];
    let segment = match cmd {
        CMD_DATA => {
            if body.len() < 14 {
                return None;
            }
            let ts = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let sn = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let sending_next = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let len = u16::from_be_bytes([body[12], body[13]]) as usize;
            // A zero-length DATA is unparseable on the Xray side too, so it is
            // never produced and never accepted.
            if len == 0 || body.len() < 14 + len {
                return None;
            }
            Segment {
                cmd,
                option,
                ts,
                sn,
                sending_next,
                data: body[14..14 + len].to_vec(),
                ..Segment::default()
            }
        }
        CMD_ACK => {
            if body.len() < 13 {
                return None;
            }
            let window_edge = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let receiving_next = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let ts = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let count = body[12] as usize;
            if body.len() < 13 + count * 4 {
                return None;
            }
            let mut numbers = Vec::with_capacity(count);
            for index in 0..count {
                let at = 13 + index * 4;
                numbers.push(u32::from_be_bytes([
                    body[at],
                    body[at + 1],
                    body[at + 2],
                    body[at + 3],
                ]));
            }
            Segment {
                cmd,
                option,
                ts,
                receiving_next,
                window_edge,
                numbers,
                ..Segment::default()
            }
        }
        CMD_TERMINATE | CMD_PING => {
            if body.len() < 12 {
                return None;
            }
            Segment {
                cmd,
                option,
                sending_next: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                receiving_next: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                peer_rto: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
                ..Segment::default()
            }
        }
        _ => return None,
    };
    let used = segment.wire_len();
    Some((segment, used))
}

/// Parses every segment in a deobfuscated datagram, stopping at the first one
/// that does not make sense — the same tolerance Xray's `KCPPacketReader` has
/// for coalesced or damaged datagrams.
fn decode_datagram(conv: u16, buf: &[u8]) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let Some((segment, used)) = decode_segment(conv, rest) else {
            break;
        };
        if used == 0 || used > rest.len() {
            break;
        }
        segments.push(segment);
        rest = &rest[used..];
    }
    segments
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
    /// Conversation id, 16 bits on the wire. `0` asks [`connect`] / [`accept`]
    /// to pick one at random; anything above `0xFFFF` is refused, because a peer
    /// could never match it.
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
            .saturating_sub(DATA_OVERHEAD + self.obfs.header_len() + envelope::OVERHEAD)
    }

    /// Bytes the obfuscation layer adds to every datagram.
    fn obfs_overhead(&self) -> usize {
        self.obfs.header_len() + envelope::OVERHEAD
    }

    /// The conversation id as it appears on the wire, generating one when the
    /// configuration asked for `0`.
    fn conversation(&self) -> FluxResult<u16> {
        if self.conv > u32::from(u16::MAX) {
            return Err(FluxError::Config(format!(
                "mKCP conv {} does not fit in the 16 bits Xray puts on the wire (max 65535)",
                self.conv
            )));
        }
        let conv = if self.conv == 0 {
            // Zero would be a valid id, but it is also what an uninitialised
            // config carries, so generate a non-zero one to keep the two apart.
            loop {
                let candidate: u16 = rand::random();
                if candidate != 0 {
                    break candidate;
                }
            }
        } else {
            self.conv as u16
        };
        Ok(conv)
    }

    fn validate(&self) -> FluxResult<()> {
        let overhead = DATA_OVERHEAD + self.obfs_overhead();
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
}

/// Splits one write into segment-sized chunks.
///
/// Xray has no fragment index: a write is just a run of consecutive `sn`s, and
/// the peer concatenates them in order. Splitting is therefore the whole of
/// "fragmentation" on the wire.
fn chunk_write(data: &[u8], mss: usize) -> Vec<QueuedSeg> {
    let mss = mss.max(1);
    data.chunks(mss)
        .map(|chunk| QueuedSeg {
            data: Bytes::copy_from_slice(chunk),
        })
        .collect()
}

/// A segment that has been sent and is waiting to be acknowledged.
struct OutSeg {
    data: Bytes,
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
    conv: u16,
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
    /// Segment numbers to acknowledge, and the newest DATA timestamp among them
    /// (Xray's ACK carries the newest of the timestamps it covers).
    ack_list: Vec<u32>,
    ack_ts: u32,

    // RTT estimation (RFC 6298 style).
    srtt_us: u64,
    rttvar_us: u64,
    rto_us: u64,

    // Windows and liveness.
    /// Absolute right edge of the peer's receive window, as advertised in its
    /// last ACK. Our credit is `peer_edge - snd_una` segments.
    peer_edge: u32,
    /// Edge advertised on the last ACK we sent.
    advertised_edge: u32,
    /// Set when the reader consumed data while the window we advertised was
    /// closed, so the peer needs a window update promptly.
    window_update: bool,
    /// The peer sent TERMINATE: reads drain then report end of stream.
    peer_closed: bool,
    /// We sent TERMINATE.
    closing: bool,
    next_ping: Instant,
    last_recv: Instant,
    last_send: Instant,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    dead: Option<io::ErrorKind>,

    stats: KcpStats,
}

impl Conn {
    fn new(cfg: KcpConfig, conv: u16, socket: Arc<UdpSocket>, peer: Option<SocketAddr>) -> Self {
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
            ack_ts: 0,
            srtt_us: 0,
            rttvar_us: 0,
            rto_us: 0,
            // Xray opens with a 32-segment credit (`remoteNextNumber: 32`), and
            // the same is needed here: a client has to be able to push its
            // first request before any ACK exists. Everything after that comes
            // from the peer's advertised window edge.
            peer_edge: 32.min(wnd),
            advertised_edge: u32::from(cfg.rcv_wnd),
            window_update: false,
            peer_closed: false,
            closing: false,
            next_ping: now,
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
        // Credit is the distance from the oldest unacknowledged segment to the
        // peer's advertised window edge, exactly as Xray computes it.
        let peer = self.peer_edge.saturating_sub(self.snd_una);
        own.min(peer)
    }

    // -- sending ----------------------------------------------------------

    /// Window we advertise: the first number we have not received plus the free
    /// slots behind it. Xray's `ReceivingWindow` is this absolute edge, not a
    /// count, and a sender derives its credit as `edge - first unacknowledged`.
    fn window_edge(&self) -> u32 {
        self.rcv_nxt.wrapping_add(u32::from(self.rcv_wnd_free()))
    }

    fn send_segment(&mut self, seg: Segment, now: Instant) {
        let Some(peer) = self.peer else {
            return;
        };
        let mut plain = Vec::with_capacity(seg.wire_len());
        encode_segment(self.conv, &seg, &mut plain);

        let mut datagram = Vec::with_capacity(plain.len() + self.cfg.obfs_overhead());
        self.obfs.wrap(&plain, &mut datagram);

        // Non-blocking on purpose: backpressure has to be expressed by the KCP
        // window, not by a send queue inside the socket. A datagram the socket
        // refuses is simply not sent; the retransmission timer covers it.
        match self.socket.try_send_to(&datagram, peer) {
            Ok(sent) => {
                if seg.cmd == CMD_ACK {
                    self.advertised_edge = seg.window_edge;
                }
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

    fn send_data(&mut self, sn: u32, now: Instant) {
        let Some(seg) = self.snd_buf.get(&sn) else {
            return;
        };
        let (ts, data) = (seg.ts, seg.data.clone());
        let sending_next = self.rcv_nxt;
        self.send_segment(Segment::data(sn, sending_next, ts, data.to_vec()), now);
    }

    /// Sends the pending acknowledgements, split over as many ACK segments as
    /// the MTU requires, and then sends an empty ACK if the window has to be
    /// reopened.
    fn send_acks(&mut self, now: Instant) {
        if self.ack_list.is_empty() {
            return;
        }
        let per_segment = (self.cfg.mss() / 4).clamp(1, MAX_ACK_NUMBERS);
        let ts = self.ack_ts;
        while !self.ack_list.is_empty() {
            let take = self.ack_list.len().min(per_segment);
            let numbers: Vec<u32> = self.ack_list.drain(..take).collect();
            let seg = Segment::ack(self.rcv_nxt, self.window_edge(), ts, numbers);
            self.send_segment(seg, now);
        }
    }

    fn send_window_update(&mut self, now: Instant) {
        let seg = Segment::ack(
            self.rcv_nxt,
            self.window_edge(),
            self.now_ms(now),
            Vec::new(),
        );
        self.send_segment(seg, now);
    }

    /// A PING doubles as a keepalive and as a cumulative acknowledgement of the
    /// peer's stream, which is exactly how Xray uses it.
    fn send_ping(&mut self, now: Instant) {
        let rto = self.rto().as_millis() as u32;
        let seg = Segment::command(CMD_PING, self.rcv_nxt, self.rcv_nxt, rto);
        self.send_segment(seg, now);
    }

    fn send_terminate(&mut self, now: Instant) {
        let rto = self.rto().as_millis() as u32;
        let mut seg = Segment::command(CMD_TERMINATE, self.rcv_nxt, self.rcv_nxt, rto);
        seg.option = OPTION_CLOSE;
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
                    ts,
                    sent_at: now,
                    xmit: 1,
                    rto_us,
                    deadline: now + Duration::from_micros(rto_us),
                    fastack: 0,
                    fast_xmit: 0,
                },
            );
            self.send_data(sn, now);
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
            self.send_data(sn, now);
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
                tracing::debug!("conv {} sn {sn} exceeded its retry budget", self.conv);
                self.kill(io::ErrorKind::TimedOut);
                return;
            }
            self.stats.segments_retransmitted += 1;
            self.stats.timer_retransmits += 1;
            self.on_loss(false);
            self.send_data(sn, now);
        }
    }

    /// Keepalive, window probing and the peer's liveness all ride on PING,
    /// which is what a real Xray peer sends every three seconds when quiet.
    fn keepalive(&mut self, now: Instant) {
        if now >= self.next_ping {
            self.next_ping = now + PING_IDLE;
            self.send_ping(now);
        }
    }

    fn check_dead(&mut self, now: Instant) {
        if self.dead.is_some() {
            return;
        }
        let silence = now.duration_since(self.last_recv);
        if !self.snd_buf.is_empty() && silence > IDLE_TIMEOUT {
            self.kill(io::ErrorKind::TimedOut);
        } else if silence > PEER_SILENCE_LIMIT {
            // Probes have gone unanswered for a minute: the peer is gone.
            self.kill(io::ErrorKind::ConnectionReset);
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
        self.send_acks(now);
        if self.window_update && self.rcv_wnd_free() > 0 {
            self.window_update = false;
            self.send_window_update(now);
        }
        self.fill_window(now);
        self.retransmit(now);
        self.keepalive(now);
        self.check_dead(now);
    }

    // -- receiving --------------------------------------------------------

    /// Feeds one deobfuscated datagram. The socket demultiplexer has already
    /// stripped the obfuscation, so this is what the driver calls.
    fn on_datagram(&mut self, plain: &[u8], from: SocketAddr, now: Instant) {
        if self.dead.is_some() {
            return;
        }
        // Anything larger than the MTU cannot be something we produced, so it is
        // either hostile or a configuration mismatch.
        if plain.len() > self.cfg.mtu {
            return;
        }
        match self.peer {
            None => self.peer = Some(from),
            Some(peer) if peer != from => return,
            Some(_) => {}
        }
        let conv = self.conv;
        for seg in decode_datagram(conv, plain) {
            self.stats.datagrams_received += 1;
            self.last_recv = now;
            self.on_segment(seg, now);
            if self.dead.is_some() {
                return;
            }
        }
    }

    fn on_segment(&mut self, seg: Segment, now: Instant) {
        // Any segment can carry the peer's cumulative acknowledgement of our
        // stream (`SendingNext`), which is what frees the send buffer.
        if seg.cmd != CMD_ACK {
            self.process_peer_next(seg.sending_next);
        }
        match seg.cmd {
            CMD_DATA => {
                if seg.option == OPTION_CLOSE {
                    self.peer_closed = true;
                }
                self.on_data(seg, now);
            }
            CMD_ACK => self.on_ack(&seg, now),
            CMD_PING => {
                // The peer's RTO is advisory; the local estimate is what this
                // implementation trusts. A PING needs no reply.
                let _ = seg.peer_rto;
            }
            CMD_TERMINATE => {
                self.peer_closed = true;
                if let Some(waker) = self.read_waker.take() {
                    waker.wake();
                }
            }
            _ => {}
        }
    }

    /// Applies a cumulative acknowledgement from the peer.
    fn process_peer_next(&mut self, next: u32) {
        if next <= self.snd_una || next > self.snd_nxt {
            return;
        }
        if let Some(seg) = self.snd_buf.get(&next.wrapping_sub(1))
            && seg.xmit == 1
        {
            let sent_at = seg.sent_at;
            self.update_rtt(sent_at.elapsed().as_micros() as u64);
        }
        let done: Vec<u32> = self.snd_buf.range(..next).map(|(sn, _)| *sn).collect();
        if done.is_empty() {
            return;
        }
        for sn in done {
            self.snd_buf.remove(&sn);
        }
        self.snd_una = next;
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    fn on_data(&mut self, seg: Segment, now: Instant) {
        let sn = seg.sn;
        self.ack_ts = self.ack_ts.max(seg.ts);
        // Already delivered: re-acknowledge, because our earlier ACK was
        // probably the datagram that got lost.
        if sn < self.rcv_nxt {
            self.ack_list.push(sn);
            return;
        }
        if self.rcv_window_full() {
            return;
        }
        self.rcv_buf.entry(sn).or_insert_with(|| {
            self.stats.bytes_received += seg.data.len() as u64;
            Bytes::from(seg.data.clone())
        });
        self.ack_list.push(sn);
        self.deliver();
        let _ = now;
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
        // The peer's window edge is absolute; our credit is the distance from
        // the oldest unacknowledged segment to it.
        self.peer_edge = self.peer_edge.max(seg.window_edge);
        self.process_peer_next(seg.receiving_next);

        if seg.numbers.is_empty() {
            return;
        }
        let mut acked = 0u32;
        let mut highest = self.snd_una;
        for sn in &seg.numbers {
            if *sn < self.snd_una || *sn >= self.snd_nxt {
                continue;
            }
            if let Some(out) = self.snd_buf.get(sn) {
                // Karn's rule: only a sample from a segment sent exactly once is
                // unambiguous. The ACK's own `ts` is the peer's clock, which is
                // not comparable with ours, so the local send time is used.
                if out.xmit == 1 {
                    self.update_rtt(out.sent_at.elapsed().as_micros() as u64);
                }
            }
            if self.snd_buf.remove(sn).is_some() {
                acked += 1;
                highest = highest.max(sn.wrapping_add(1));
            }
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
    routes: HashMap<u16, Arc<Inbox>>,
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
        if n < obfs.header_len() + envelope::OVERHEAD + CMD_ONLY_LEN {
            continue;
        }
        let Some(segment) = unwrap_datagram(obfs, &buf[..n]) else {
            continue;
        };
        if segment.len() < SEGMENT_PREFIX_LEN {
            continue;
        }
        let conv = u16::from_be_bytes([segment[0], segment[1]]);
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
    conv: u16,
    task: tokio::task::JoinHandle<()>,
    local: Option<SocketAddr>,
}

impl KcpStream {
    /// Conversation id in use (generated when the config asked for `0`).
    pub fn conv(&self) -> u32 {
        u32::from(self.conv)
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
    let conv = cfg.conversation()?;
    let (hub, key) = hub_for(&socket, cfg.obfs);
    let inbox = Inbox::new();
    hub.lock().routes.insert(conv, inbox.clone());

    let mut conn = Conn::new(cfg, conv, socket, Some(peer));
    // No opening PING: a real Xray client's first datagram is DATA, and an Xray
    // *server* closes a session that opens with anything else — measured by
    // capturing both sides and decoding them with this module's own parser. Our
    // `accept()` learns the conversation from whatever arrives first, so nothing
    // depends on the ping.
    let _ = &mut conn;
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
        let wanted = cfg.conversation()?;
        if hub.lock().routes.insert(wanted, inbox.clone()).is_some() {
            return Err(FluxError::Config(format!(
                "mKCP conversation {wanted:#06x} is already accepted on this socket"
            )));
        }
        match next_datagram(&inbox).await {
            Ok(first) => (wanted, first),
            Err(e) => {
                hub.lock().routes.remove(&wanted);
                return Err(e);
            }
        }
    };

    let mut conn = Conn::new(cfg, conv, socket, None);
    conn.on_datagram(&first.1, first.0, Instant::now());
    Ok(spawn_stream(conn, hub, key, inbox))
}

fn conversation_of(segment: &[u8]) -> FluxResult<u16> {
    if segment.len() < SEGMENT_PREFIX_LEN {
        return Err(FluxError::Protocol {
            protocol: "mkcp",
            message: "first datagram is shorter than a segment prefix".into(),
        });
    }
    Ok(u16::from_be_bytes([segment[0], segment[1]]))
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
            conn.on_datagram(&segment, addr, now);
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
            if conn.advertised_edge <= conn.rcv_nxt {
                conn.window_update = true;
            }
            return Poll::Ready(Ok(()));
        }
        if let Some(kind) = conn.dead {
            return Poll::Ready(Err(io::Error::new(kind, "mKCP stream lost")));
        }
        if conn.peer_closed {
            // TERMINATE arrived and everything it sent is delivered: EOF, the
            // closest thing mKCP has to a half-close.
            return Poll::Ready(Ok(()));
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
        if conn.peer_closed || conn.closing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP stream closed",
            )));
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
        for queued in chunk_write(&buf[..take], mss) {
            conn.snd_queue.push_back(queued);
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

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().inner.lock();
        if conn.dead.is_none() && !conn.closing {
            let now = Instant::now();
            conn.closing = true;
            // Xray's TERMINATE is the command that tells the peer this stream is
            // finished; without it the peer would sit in a read that never ends.
            conn.send_terminate(now);
            conn.flush(now);
        }
        Poll::Ready(Ok(()))
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
    fn data_segment_round_trip() {
        let seg = Segment::data(42, 41, 7, b"hello kcp".to_vec());
        let mut buf = Vec::new();
        encode_segment(0xBEEF, &seg, &mut buf);
        assert_eq!(buf.len(), DATA_OVERHEAD + 9);

        let (decoded, used) = decode_segment(0xBEEF, &buf).expect("valid segment");
        assert_eq!(used, buf.len());
        assert_eq!(decoded.cmd, CMD_DATA);
        assert_eq!(decoded.option, 0);
        assert_eq!(decoded.ts, 7);
        assert_eq!(decoded.sn, 42);
        assert_eq!(decoded.sending_next, 41);
        assert_eq!(decoded.data, b"hello kcp");
    }

    #[test]
    fn wire_layout_is_xray_shaped() {
        // DATA: conv u16 ‖ 1 ‖ opt ‖ ts ‖ sn ‖ sendingNext ‖ len u16 ‖ payload,
        // all big-endian, 18 bytes of overhead.
        let mut buf = Vec::new();
        encode_segment(
            0x0A0B,
            &Segment::data(0x1122_3344, 0x5566_7788, 0xAABB_CCDD, vec![0x99, 0x88]),
            &mut buf,
        );
        assert_eq!(buf.len(), 20);
        assert_eq!(&buf[0..2], &[0x0A, 0x0B]);
        assert_eq!(buf[2], CMD_DATA);
        assert_eq!(buf[3], 0);
        assert_eq!(&buf[4..8], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&buf[8..12], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&buf[12..16], &[0x55, 0x66, 0x77, 0x88]);
        assert_eq!(&buf[16..18], &[0x00, 0x02]);
        assert_eq!(&buf[18..20], &[0x99, 0x88]);

        // ACK: conv ‖ 0 ‖ opt ‖ receivingWindow ‖ receivingNext ‖ ts ‖ count ‖ sn…
        let mut buf = Vec::new();
        encode_segment(
            0x0A0B,
            &Segment::ack(7, 519, 0x0102_0304, vec![5, 6]),
            &mut buf,
        );
        assert_eq!(buf.len(), ACK_OVERHEAD + 8);
        assert_eq!(&buf[0..2], &[0x0A, 0x0B]);
        assert_eq!(buf[2], CMD_ACK);
        assert_eq!(&buf[4..8], &[0, 0, 0x02, 0x07]); // 519
        assert_eq!(&buf[8..12], &[0, 0, 0, 7]);
        assert_eq!(&buf[12..16], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buf[16], 2);
        assert_eq!(&buf[17..21], &[0, 0, 0, 5]);
        assert_eq!(&buf[21..25], &[0, 0, 0, 6]);

        // PING: conv ‖ cmd ‖ opt ‖ sendingNext ‖ receivingNext ‖ peerRTO.
        let mut buf = Vec::new();
        encode_segment(0x0A0B, &Segment::command(CMD_PING, 3, 4, 5), &mut buf);
        assert_eq!(buf.len(), CMD_ONLY_LEN);
        assert_eq!(buf[2], CMD_PING);
        assert_eq!(&buf[4..8], &[0, 0, 0, 3]);
        assert_eq!(&buf[8..12], &[0, 0, 0, 4]);
        assert_eq!(&buf[12..16], &[0, 0, 0, 5]);
    }

    #[test]
    fn overlong_len_field_is_rejected() {
        let mut buf = Vec::new();
        encode_segment(1, &Segment::data(1, 0, 1, vec![0u8; 16]), &mut buf);
        // Claim 4096 bytes of payload in an 18+16 byte datagram.
        buf[16..18].copy_from_slice(&4096u16.to_be_bytes());
        assert!(decode_segment(1, &buf).is_none());
        // A zero-length DATA cannot be parsed by Xray either, so neither can it
        // be produced or accepted here.
        let mut zero = Vec::new();
        encode_segment(1, &Segment::data(1, 0, 1, Vec::new()), &mut zero);
        assert_eq!(zero.len(), DATA_OVERHEAD);
        assert!(decode_segment(1, &zero).is_none());
        // A datagram shorter than the header itself.
        assert!(decode_segment(1, &buf[..10]).is_none());
        assert!(decode_segment(1, &[]).is_none());
    }

    #[test]
    fn truncated_segment_is_rejected() {
        let mut buf = Vec::new();
        encode_segment(1, &Segment::data(1, 0, 1, vec![7u8; 32]), &mut buf);
        // Cut the payload in half without touching the length field.
        buf.truncate(DATA_OVERHEAD + 16);
        assert!(decode_segment(1, &buf).is_none());
    }

    #[test]
    fn unknown_conv_and_cmd_are_rejected() {
        let mut buf = Vec::new();
        encode_segment(0x1234, &Segment::data(1, 0, 1, vec![1, 2, 3]), &mut buf);
        assert!(decode_segment(0x1235, &buf).is_none());
        // The conversation id is 16 bits: a peer whose id differs in the high
        // half of a 32-bit value is a different conversation, not a match.
        assert!(decode_segment(0x0000, &[0x00, 0x00, 0x01, 0x00]).is_none());
        let mut bogus = buf.clone();
        bogus[2] = 0x7F; // not a command we speak
        assert!(decode_segment(0x1234, &bogus).is_none());
        // An ACK that claims more numbers than it carries.
        let mut ack = Vec::new();
        encode_segment(0x1234, &Segment::ack(0, 0, 0, vec![1]), &mut ack);
        ack[16] = 9;
        assert!(decode_segment(0x1234, &ack).is_none());
    }

    #[test]
    fn coalesced_segments_in_one_datagram_are_all_parsed() {
        let mut buf = Vec::new();
        encode_segment(0x1234, &Segment::data(1, 0, 1, b"a".to_vec()), &mut buf);
        encode_segment(0x1234, &Segment::data(2, 1, 2, b"b".to_vec()), &mut buf);
        encode_segment(0x1234, &Segment::ack(3, 100, 3, vec![1, 2]), &mut buf);
        let segments = decode_datagram(0x1234, &buf);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].sn, 1);
        assert_eq!(segments[1].data, b"b");
        assert_eq!(segments[2].cmd, CMD_ACK);
        assert_eq!(segments[2].numbers, vec![1, 2]);
        // Trailing garbage stops the parse without discarding what came first.
        buf.extend_from_slice(&[0u8; 3]);
        assert_eq!(decode_datagram(0x1234, &buf).len(), 3);
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
        // Xray: mss = mtu - DataSegmentOverhead(18) - header - seed overhead.
        assert_eq!(cfg.mss(), 1350 - DATA_OVERHEAD - 4 - 6);
        let plain = KcpConfig {
            mtu: 1350,
            obfs: KcpObfs::None,
            ..KcpConfig::default()
        };
        assert_eq!(plain.mss(), 1350 - DATA_OVERHEAD - 6);
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
    fn a_write_is_split_into_contiguous_segments() {
        let cfg = KcpConfig::default();
        let mss = cfg.mss();
        let data = payload(mss * 3 + 7, 3);
        let queued = chunk_write(&data, mss);

        assert_eq!(queued.len(), 4);
        assert_eq!(queued[0].data.len(), mss);
        assert_eq!(queued[3].data.len(), 7);
        let mut assembled = Vec::new();
        for item in &queued {
            assembled.extend_from_slice(&item.data);
        }
        assert_eq!(assembled, data, "chunking must be lossless");

        // Xray has no fragment index: the segments are identified only by their
        // consecutive numbers, which is what `fill_window` assigns.
        let mut buf = Vec::new();
        for (index, item) in queued.iter().enumerate() {
            encode_segment(
                1,
                &Segment::data(index as u32, 0, 0, item.data.to_vec()),
                &mut buf,
            );
        }
        let segments = decode_datagram(1, &buf);
        assert_eq!(segments.len(), 4);
        let numbers: Vec<u32> = segments.iter().map(|seg| seg.sn).collect();
        assert_eq!(numbers, vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_conversation_id_above_16_bits_is_refused() {
        let too_big = KcpConfig {
            conv: 0x1_0000,
            ..KcpConfig::default()
        };
        assert!(matches!(too_big.validate(), Ok(())));
        assert!(matches!(too_big.conversation(), Err(FluxError::Config(_))));
        let ok = KcpConfig {
            conv: 0xFFFF,
            ..KcpConfig::default()
        };
        assert_eq!(ok.conversation().unwrap(), 0xFFFF);
        // Zero means "pick one", and what is picked is never zero.
        let generated = KcpConfig::default().conversation().unwrap();
        assert_ne!(generated, 0);
    }

    // -- end to end -------------------------------------------------------

    /// Server side of an echo: accept, then copy everything back in chunks.
    ///
    /// It pumps instead of reading the whole payload first, because two peers
    /// that each write their full payload before reading would deadlock once
    /// the payload exceeds a receive window. It also stays alive until the
    /// client says it is done: dropping the stream earlier would leave the
    /// client waiting for segments nobody will retransmit, which is exactly what
    /// a KCP peer without a close command looks like.
    async fn echo_server(
        socket: Arc<UdpSocket>,
        cfg: KcpConfig,
        expect: usize,
        done: tokio::sync::oneshot::Receiver<()>,
    ) -> KcpStats {
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
        // Hold the conversation open until the client has read everything back.
        let _ = tokio::time::timeout(Duration::from_secs(30), done).await;
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
            conv: 0x5EE1,
            ..KcpConfig::default()
        };

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, 1024 * 1024, done_rx));
        let client = connect(addr, cfg).await.expect("connect failed");
        let data = payload(1024 * 1024, 5);
        let (echoed, stats) = exchange(client, data.clone()).await;

        assert_eq!(echoed.len(), data.len());
        assert!(echoed == data, "1 MiB round trip is not byte-exact");
        println!("1 MiB loopback: {stats:?}");
        let _ = done_tx.send(());
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
        /// lying length field, a truncated one, one for a foreign conversation
        /// and one with an unknown command. All of it is properly wrapped, so it
        /// reaches the segment parser instead of dying in the obfuscation layer.
        fn hostile_datagrams(&self, datagram: &[u8]) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            // Not even a valid frame.
            out.push(vec![0xAA; 7]);
            out.push(datagram[..datagram.len() / 2].to_vec());

            let Some(plain) = unwrap_datagram(self.obfs, datagram) else {
                return out;
            };
            if plain.len() < DATA_OVERHEAD {
                return out;
            }
            let wrap = |plain: &[u8]| {
                let mut state = ObfsState::new(self.obfs);
                let mut framed = Vec::new();
                state.wrap(plain, &mut framed);
                framed
            };

            // A DATA segment that claims 10 000 bytes of payload.
            let mut lying = plain.clone();
            lying[16..18].copy_from_slice(&10_000u16.to_be_bytes());
            out.push(wrap(&lying));

            // A foreign conversation id.
            let mut foreign = plain.clone();
            let conv = u16::from_be_bytes([foreign[0], foreign[1]]);
            foreign[0..2].copy_from_slice(&conv.wrapping_add(1).to_be_bytes());
            out.push(wrap(&foreign));

            // A segment whose payload was cut off but whose length was not.
            let mut truncated = plain.clone();
            truncated.truncate(DATA_OVERHEAD + 1);
            out.push(wrap(&truncated));

            // An unknown command.
            let mut bogus = plain;
            bogus[2] = 0x7F;
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
            conv: 0x5EE2,
            ..KcpConfig::default()
        };

        let relay_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let relay = Relay::new(relay_socket, server_addr, 20, 0xC0FF_EE01, cfg.obfs);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(stop_rx));

        const SIZE: usize = 256 * 1024;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE, done_rx));
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
        let _ = done_tx.send(());
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
            conv: 0x5EE3,
            ..KcpConfig::default()
        };

        let relay_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let mut relay = Relay::new(relay_socket, server_addr, 0, 0x1234_5678, cfg.obfs);
        relay.reorder = true;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(stop_rx));

        const SIZE: usize = 64 * 1024;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE, done_rx));
        let client = connect(relay_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 17);
        let transfer = exchange(client, data.clone());
        let (echoed, stats) = tokio::time::timeout(Duration::from_secs(60), transfer)
            .await
            .expect("reordered transfer did not finish in time");
        assert!(echoed == data, "reordered round trip is not byte-exact");
        println!("out of order: {stats:?}");
        let _ = done_tx.send(());

        server.await.expect("server task panicked");
        let _ = stop_tx.send(());
        relay_task.await.expect("relay task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hostile_datagrams_are_dropped_without_panic() {
        let socket = server_socket().await;
        let server_addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EE4,
            ..KcpConfig::default()
        };

        let relay_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay_socket.local_addr().unwrap();
        let mut relay = Relay::new(relay_socket, server_addr, 0, 0xABCD_1234, cfg.obfs);
        relay.inject = 3;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(stop_rx));

        const SIZE: usize = 32 * 1024;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE, done_rx));
        let client = connect(relay_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 23);
        let transfer = exchange(client, data.clone());
        let (echoed, stats) = tokio::time::timeout(Duration::from_secs(60), transfer)
            .await
            .expect("transfer alongside hostile datagrams stalled");
        assert!(echoed == data, "hostile datagrams corrupted the stream");
        println!("hostile: {stats:?}");

        let _ = done_tx.send(());
        server.await.expect("server task panicked");
        let _ = stop_tx.send(());
        relay_task.await.expect("relay task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_larger_than_mtu_is_split_and_reassembled() {
        let socket = server_socket().await;
        let server_addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EE5,
            // A small MTU makes the fragmentation obvious on the wire.
            mtu: 300,
            ..KcpConfig::default()
        };
        let mss = cfg.mss();

        const SIZE: usize = 5000;
        let expected_fragments = SIZE.div_ceil(mss);
        assert!(expected_fragments >= 3, "test needs real fragmentation");

        // A tap in front of the server that records the segment number of every
        // DATA segment it forwards. Collecting a set rather than a sequence
        // keeps the assertion honest: loopback delivery order and
        // retransmissions are not something a test should depend on.
        let tap_socket = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
        let tap_addr = tap_socket.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<u32>::new()));
        let tap = tokio::spawn({
            let seen = seen.clone();
            async move {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                let mut client_addr: Option<SocketAddr> = None;
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
                    if let Some(plain) = unwrap_datagram(cfg.obfs, &buf[..n]) {
                        for seg in decode_datagram(cfg.conv as u16, &plain) {
                            if seg.cmd == CMD_DATA && !seg.data.is_empty() {
                                seen.lock().push(seg.sn);
                            }
                        }
                    }
                    let _ = tap_socket.send_to(&buf[..n], server_addr).await;
                }
            }
        });

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE, done_rx));
        let client = connect(tap_addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 29);
        let (echoed, _stats) = exchange(client, data.clone()).await;
        assert!(echoed == data, "fragmented write is not byte-exact");

        let mut numbers: Vec<u32> = seen.lock().clone();
        numbers.sort_unstable();
        numbers.dedup();
        let expected: Vec<u32> = (0..expected_fragments as u32).collect();
        assert_eq!(
            numbers, expected,
            "a {SIZE}-byte write must leave as one contiguous run of segment numbers"
        );

        let _ = done_tx.send(());
        server.await.expect("server task panicked");
        tap.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn congestion_controlled_transfer_works() {
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EEA,
            no_congestion: false,
            ..KcpConfig::default()
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, 128 * 1024, done_rx));
        let client = connect(addr, cfg).await.expect("connect failed");
        let data = payload(128 * 1024, 37);
        let (echoed, stats) = exchange(client, data.clone()).await;
        assert!(
            echoed == data,
            "congestion-controlled round trip is not byte-exact"
        );
        println!("congestion control: {stats:?}");
        let _ = done_tx.send(());
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
            conv: 0xC0D1,
            ..KcpConfig::default()
        };
        let cfg_b = KcpConfig {
            conv: 0xC0D2,
            ..KcpConfig::default()
        };

        let (done_a, done_a_rx) = tokio::sync::oneshot::channel();
        let (done_b, done_b_rx) = tokio::sync::oneshot::channel();
        let server_a = tokio::spawn(echo_server(socket.clone(), cfg_a, 4096, done_a_rx));
        let server_b = tokio::spawn(echo_server(socket.clone(), cfg_b, 8192, done_b_rx));

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
        let _ = done_a.send(());
        let _ = done_b.send(());
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
            conv: 0x5EE8,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_far_larger_than_the_window_is_bounded_and_lossless() {
        // 1 MiB through a 32-segment window: the write path has to accept it in
        // slices and never buffer more than one window of it.
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EEC,
            snd_wnd: 32,
            rcv_wnd: 32,
            ..KcpConfig::default()
        };
        const SIZE: usize = 1024 * 1024;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE, done_rx));
        let client = connect(addr, cfg).await.expect("connect failed");
        let inner = client.inner.clone();

        // Watch the send buffer while the transfer runs: it must never exceed
        // the configured window.
        let watcher = tokio::spawn(async move {
            let mut peak = 0usize;
            for _ in 0..400 {
                {
                    let conn = inner.lock();
                    peak = peak.max(conn.snd_buf.len() + conn.snd_queue.len());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            peak
        });

        let data = payload(SIZE, 47);
        let (echoed, _stats) = exchange(client, data.clone()).await;
        assert!(
            echoed == data,
            "large write through a small window lost data"
        );
        let peak = watcher.await.expect("watcher panicked");
        assert!(
            peak <= usize::from(cfg.snd_wnd),
            "send buffer peaked at {peak} segments for a window of {}",
            cfg.snd_wnd
        );
        let _ = done_tx.send(());
        server.await.expect("server task panicked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn memory_stays_bounded_when_the_reader_stops() {
        // A peer that writes to us while we never read must not be able to make
        // our receive buffer grow: the window closes instead.
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EED,
            snd_wnd: 32,
            rcv_wnd: 32,
            ..KcpConfig::default()
        };

        let (inner_tx, inner_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept(socket, cfg).await.expect("accept failed");
            let _ = inner_tx.send(stream.inner.clone());
            // Hold the stream open and never read from it.
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(stream);
        });

        let mut client = connect(addr, cfg).await.expect("connect failed");
        let chunk = vec![0x5Au8; 64 * 1024];
        let flood = async {
            for _ in 0..200 {
                client.write_all(&chunk).await.expect("write failed");
            }
        };
        let blocked = tokio::time::timeout(Duration::from_millis(500), flood).await;
        assert!(
            blocked.is_err(),
            "a reader that never reads must eventually block the writer"
        );

        let server_inner = inner_rx.await.expect("server never reported its state");
        let (unread, queued, window) = {
            let conn = server_inner.lock();
            (
                conn.rcv_buf.len() + conn.recv_queue.len(),
                conn.snd_buf.len() + conn.snd_queue.len(),
                usize::from(cfg.rcv_wnd),
            )
        };
        assert!(
            unread <= window,
            "receive buffer holds {unread} segments for a window of {window}"
        );
        assert!(
            queued <= usize::from(cfg.snd_wnd),
            "send buffer grew past the window"
        );
        server.abort();
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
        // Deliberately small: this is a measurement, not a stress test, so it
        // must finish quickly in a debug build and in CI. The numbers that
        // matter are quoted from a release build with `--nocapture`.
        const SIZE: usize = 1024 * 1024;
        let socket = server_socket().await;
        let addr = socket.local_addr().unwrap();
        let cfg = KcpConfig {
            conv: 0x5EE6,
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
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(echo_server(socket, cfg, SIZE, done_rx));
        let client = connect(addr, cfg).await.expect("connect failed");
        let data = payload(SIZE, 31);
        let kcp_start = Instant::now();
        let write_and_read = exchange(client, data.clone());
        // Joined with the server so a server-side failure surfaces here instead
        // of turning into a silent stall on the client side. Dropping the `done`
        // sender releases the server, which otherwise holds the stream open.
        let transfer = async move {
            let result = tokio::time::timeout(Duration::from_secs(180), write_and_read).await;
            drop(done_tx);
            result
        };
        let (transfer, server_result) = tokio::join!(transfer, server);
        let kcp_elapsed = kcp_start.elapsed();
        server_result.expect("server task panicked");
        let (echoed, bulk_stats) = transfer.expect("mKCP measurement transfer did not finish");
        assert!(echoed == data, "measurement transfer must be byte-exact");

        // --- mKCP latency on its own conversation: the bulk server above has
        // already consumed its one payload and gone away.
        let latency_socket = server_socket().await;
        let latency_addr = latency_socket.local_addr().unwrap();
        let latency_cfg = KcpConfig {
            conv: 0x5EE7,
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

// ---------------------------------------------------------------------------
// Interop against the real Xray binary
// ---------------------------------------------------------------------------

/// These tests drive the actual `xray` process, so they are `#[ignore]`d and
/// kept out of the hermetic gates. Run them with:
///
/// ```text
/// XRAY_BIN=~/.local/bin/xray cargo test -p flux-transport --lib kcp::interop \
///     -- --ignored --nocapture
/// ```
#[cfg(test)]
mod interop {
    use super::*;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;

    /// VLESS user id used by both directions of the test.
    const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";
    /// Xray 26.3.27 removed `kcpSettings.header`/`seed` in favour of `finalmask`;
    /// the SRTP header is the outermost layer and the "original" mask the inner
    /// one, matching `header ‖ mask(segment)` on the wire.
    const FINALMASK: &str =
        r#""finalmask": {"udp": [{"type": "header-srtp"}, {"type": "mkcp-original"}]}"#;

    fn xray_bin() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("XRAY_BIN") {
            let path = PathBuf::from(path);
            return path.is_file().then_some(path);
        }
        let home = std::env::var("HOME").ok()?;
        let path = PathBuf::from(home).join(".local/bin/xray");
        path.is_file().then_some(path)
    }

    fn some_uuid() -> Vec<u8> {
        // Parse the textual UUID into its 16 bytes.
        let hex: String = UUID.chars().filter(|c| *c != '-').collect();
        (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    /// A running `xray run` with its config file cleaned up on drop.
    struct Xray {
        child: Child,
        dir: PathBuf,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Xray {
        /// Waits for the line Xray logs once every inbound is listening.
        ///
        /// Probing the port is not usable here: Xray binds UDP sockets with
        /// `SO_REUSEPORT`, so a second bind succeeds and would report a
        /// not-yet-started peer as ready.
        fn wait_started(&self, what: &str) {
            for _ in 0..200 {
                {
                    let log = self.log.lock();
                    if log.iter().any(|line| line.contains("started")) {
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let log = self.log.lock().join("\n");
            panic!("xray ({what}) never reported that it started; log:\n{log}");
        }
    }

    impl Drop for Xray {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn start_xray(config: &str) -> Xray {
        let bin = xray_bin().expect("xray binary not found; set XRAY_BIN");
        let dir = std::env::temp_dir().join(format!(
            "flux-mkcp-interop-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, config).unwrap();

        // Validate first so a config mistake is a clear test failure rather than
        // a silent timeout.
        let check = Command::new(&bin)
            .arg("run")
            .arg("-test")
            .arg("-c")
            .arg(&path)
            .output()
            .expect("failed to run xray");
        assert!(
            check.status.success(),
            "xray rejected the config:\n{}\n{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );

        let mut child = Command::new(&bin)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start xray");

        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        if let Some(stderr) = child.stderr.take() {
            let log = log.clone();
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::BufReader::new(stderr)
                    .lines()
                    .map_while(Result::ok)
                {
                    log.lock().push(line);
                }
            });
        }
        Xray { child, dir, log }
    }

    /// TCP echo server used as the traffic's destination.
    async fn tcp_echo() -> u16 {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// The VLESS request a client sends: version, user id, no addons, command,
    /// port, address type and address.
    fn vless_request(port: u16) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&some_uuid());
        out.push(0); // no addons
        out.push(1); // TCP
        out.extend_from_slice(&port.to_be_bytes());
        out.push(1); // IPv4
        out.extend_from_slice(&[127, 0, 0, 1]);
        out
    }

    /// Reads a VLESS request from a stream, returning the destination port and
    /// address. Anything the peer sends after the header is returned with it.
    async fn read_vless_request<S>(stream: &mut S) -> std::io::Result<(u16, String)>
    where
        S: AsyncReadExt + Unpin,
    {
        let mut fixed = [0u8; 1 + 16 + 1];
        stream.read_exact(&mut fixed).await?;
        assert_eq!(fixed[0], 0, "VLESS version");
        let addons = usize::from(fixed[17]);
        if addons > 0 {
            let mut skipped = vec![0u8; addons];
            stream.read_exact(&mut skipped).await?;
        }
        let mut rest = [0u8; 1 + 2 + 1];
        stream.read_exact(&mut rest).await?;
        assert_eq!(rest[0], 1, "only TCP requests are handled here");
        let port = u16::from_be_bytes([rest[1], rest[2]]);
        let address = match rest[3] {
            1 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            2 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut name = vec![0u8; usize::from(len[0])];
                stream.read_exact(&mut name).await?;
                String::from_utf8_lossy(&name).into_owned()
            }
            other => panic!("unexpected VLESS address type {other}"),
        };
        Ok((port, address))
    }

    /// Ours (client) → Xray (server): a VLESS request and payload over our KCP
    /// stream, answered by xray's freedom outbound talking to a local echo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the xray binary; see the module comment"]
    async fn our_client_to_xray_server() {
        if xray_bin().is_none() {
            eprintln!("SKIP: no xray binary");
            return;
        }
        let echo_port = tcp_echo().await;
        let kcp_port = free_port();
        let config = format!(
            r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "port": {kcp_port}, "listen": "127.0.0.1", "protocol": "vless",
    "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
    "streamSettings": {{
      "network": "kcp",
      "kcpSettings": {{"mtu": 1350, "tti": 20, "uplinkCapacity": 5, "downlinkCapacity": 20, "congestion": false}},
      {FINALMASK}
    }}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#
        );
        let xray = start_xray(&config);
        xray.wait_started("kcp inbound");

        let cfg = KcpConfig {
            conv: 0x5EE1,
            ..KcpConfig::default()
        };
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            connect(format!("127.0.0.1:{kcp_port}").parse().unwrap(), cfg),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed");

        let request = vless_request(echo_port);
        let payload = b"flux-core speaks mkcp to xray";
        stream.write_all(&request).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();

        let mut header = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
            .await
            .expect("no VLESS response header")
            .expect("read failed");
        assert_eq!(header[0], 0, "VLESS response version");
        let addons = usize::from(header[1]);
        if addons > 0 {
            let mut skipped = vec![0u8; addons];
            stream.read_exact(&mut skipped).await.unwrap();
        }
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
            .await
            .expect("no echoed payload")
            .expect("read failed");
        assert_eq!(echoed, payload, "xray did not echo the payload back");
        println!("our client -> xray server: {} bytes echoed", echoed.len());
    }

    /// Xray (client) → ours (server): xray's dokodemo-door inbound forwards to a
    /// VLESS outbound over mKCP, which our `accept` terminates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs the xray binary; see the module comment"]
    async fn xray_client_to_our_server() {
        if xray_bin().is_none() {
            eprintln!("SKIP: no xray binary");
            return;
        }
        let echo_port = tcp_echo().await;
        let our_port = free_port();
        let door_port = free_port();

        let socket = Arc::new(
            tokio::net::UdpSocket::bind(("127.0.0.1", our_port))
                .await
                .unwrap(),
        );
        let cfg = KcpConfig {
            conv: 0, // adopt whatever the client chose
            ..KcpConfig::default()
        };
        let server = tokio::spawn(async move {
            let mut stream = tokio::time::timeout(Duration::from_secs(20), accept(socket, cfg))
                .await
                .expect("accept timed out")
                .expect("accept failed");
            println!("accepted conversation {:#06x}", stream.conv());
            let (port, address) = read_vless_request(&mut stream)
                .await
                .expect("VLESS request");
            assert_eq!(port, echo_port, "unexpected destination port");
            assert_eq!(address, "127.0.0.1");

            let mut upstream = tokio::net::TcpStream::connect((address.as_str(), port))
                .await
                .expect("upstream connect failed");
            // A VLESS response is the version and an empty addon list.
            stream.write_all(&[0u8, 0u8]).await.unwrap();
            stream.flush().await.unwrap();
            tokio::io::copy_bidirectional(&mut stream, &mut upstream)
                .await
                .expect("relay failed");
        });

        let config = format!(
            r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "port": {door_port}, "listen": "127.0.0.1", "protocol": "dokodemo-door",
    "settings": {{"address": "127.0.0.1", "port": {echo_port}, "network": "tcp"}}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{"vnext": [{{"address": "127.0.0.1", "port": {our_port},
      "users": [{{"id": "{UUID}", "encryption": "none"}}]}}]}},
    "streamSettings": {{
      "network": "kcp",
      "kcpSettings": {{"mtu": 1350, "tti": 20, "uplinkCapacity": 5, "downlinkCapacity": 20, "congestion": false}},
      {FINALMASK}
    }}
  }}]
}}"#
        );
        let xray = start_xray(&config);
        xray.wait_started("dokodemo-door inbound");

        let mut door = tokio::net::TcpStream::connect(("127.0.0.1", door_port))
            .await
            .expect("dokodemo-door connect failed");
        let payload = b"xray speaks mkcp to flux-core";
        door.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), door.read_exact(&mut echoed))
            .await
            .expect("xray never delivered the echoed bytes")
            .expect("read failed");
        assert_eq!(echoed, payload, "round trip through xray is not byte-exact");
        println!("xray client -> our server: {} bytes echoed", echoed.len());
        drop(door);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }
}
