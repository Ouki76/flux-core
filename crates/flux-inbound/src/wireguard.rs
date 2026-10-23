//! WireGuard / AmneziaWG server-side inbound.
//!
//! Terminates WireGuard tunnels from authorized peers: performs the Noise IK
//! handshake responder role (with MAC1 anti-DoS screening, TAI64N freshness
//! validation, peer allow-list and per-peer preshared keys), then feeds
//! decrypted inner IP packets into the shared smoltcp userspace stack
//! (`tun::run_stack_channels`) which dispatches TCP streams and UDP flows
//! into the regular routing pipeline.

use async_trait::async_trait;
use dashmap::DashMap;
use flux_protocol::wireguard::{
    AwgConfig, WG_AEAD_TAG_LEN, WG_DATA_HEADER_LEN, WG_REJECT_AFTER_TIME_SECS, WireGuardHandshake,
    WireGuardPeerAuth, WireGuardSession,
};
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;

/// Default inner IP MTU for WireGuard tunnels (1500 - 80 bytes of WG/UDP/IP overhead).
pub const WG_INBOUND_DEFAULT_MTU: usize = 1420;
/// Channel capacity between the UDP receive loop and the smoltcp stack actor.
const FRAME_CHANNEL_CAP: usize = 2048;

/// Upper bound on concurrent sessions held by the inbound. Each authenticated
/// handshake creates one; a misbehaving (but authorized) peer must not be able
/// to grow this map without limit.
const MAX_SESSIONS: usize = 4096;
/// How often the session reaper scans for expired sessions.
const REAPER_INTERVAL: Duration = Duration::from_secs(30);

/// An authorized peer of this WireGuard inbound.
#[derive(Clone, Debug)]
pub struct WireGuardInboundPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Allowed source IPs for inner tunnel traffic. Empty = allow any source IP.
    pub allowed_ips: Vec<ipnet::IpNet>,
}

/// Per-peer live session state.
struct PeerSessionState {
    session: tokio::sync::Mutex<WireGuardSession>,
    /// Last authenticated remote address (updated on roaming).
    addr: parking_lot::Mutex<SocketAddr>,
    created: Instant,
    allowed_ips: Vec<ipnet::IpNet>,
}

pub struct WireGuardInbound {
    tag: String,
    listen_addr: SocketAddr,
    private_key: [u8; 32],
    peers: Vec<WireGuardInboundPeer>,
    awg: AwgConfig,
    mtu: usize,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Handles of the listener-owning tasks; `stop()` joins them so that
    /// returning from `stop()` means the port is actually released.
    tasks: crate::InboundTasks,
}

impl WireGuardInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        private_key: [u8; 32],
        peers: Vec<WireGuardInboundPeer>,
        awg: Option<AwgConfig>,
        mtu: Option<usize>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            private_key,
            peers,
            awg: awg.unwrap_or_default(),
            mtu: mtu.unwrap_or(WG_INBOUND_DEFAULT_MTU),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            tasks: crate::InboundTasks::new(),
        }
    }
}

#[async_trait]
impl Inbound for WireGuardInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "wireguard"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        if self.peers.is_empty() {
            return Err(FluxError::Config(format!(
                "wireguard inbound '{}': at least one peer must be configured",
                self.tag
            )));
        }

        let socket = UdpSocket::bind(self.listen_addr).await.map_err(|e| {
            FluxError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "wireguard inbound '{}' failed to bind {}: {}",
                    self.tag, self.listen_addr, e
                ),
            ))
        })?;
        let socket = Arc::new(socket);
        tune_socket_buffers(&socket);
        self.running.store(true, Ordering::SeqCst);

        info!(
            "[{}] WireGuard inbound listening on {} ({} authorized peer(s), MTU {})",
            self.tag,
            self.listen_addr,
            self.peers.len(),
            self.mtu
        );

        // Live sessions keyed by our receiver index; inner-src-IP → index for replies.
        let sessions: Arc<DashMap<u32, Arc<PeerSessionState>>> = Arc::new(DashMap::new());
        let ip_to_index: Arc<DashMap<IpAddr, u32>> = Arc::new(DashMap::new());
        // Greatest TAI64N seen per peer. WireGuard requires a responder to reject
        // any initiation that is not strictly newer than the last one accepted;
        // the freshness window alone allowed a captured initiation to be replayed
        // indefinitely (burning four X25519 operations and replacing the peer's
        // session each time).
        let peer_timestamps: Arc<DashMap<[u8; 32], [u8; 12]>> = Arc::new(DashMap::new());

        // smoltcp stack channels
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(FRAME_CHANNEL_CAP);
        let (stack_out_tx, stack_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(FRAME_CHANNEL_CAP);

        let tag: Arc<str> = Arc::from(self.tag.as_str());

        // 1. Userspace TCP/IP stack actor.
        {
            let tag = tag.clone();
            let running = self.running.clone();
            let shutdown_rx = self.shutdown_tx.subscribe();
            let mtu = self.mtu;
            self.tasks.spawn(async move {
                crate::tun::run_stack_channels(
                    mtu,
                    tag,
                    dispatcher,
                    shutdown_rx,
                    frame_rx,
                    stack_out_tx,
                )
                .await;
                running.store(false, Ordering::SeqCst);
            });
        }

        // 2. Single tunnel pump: handshakes + decrypt → stack, and stack → encrypt
        //    → socket, in one task.
        //
        //    These two directions used to be separate tasks that woke each other
        //    (and the smoltcp actor) once per packet burst; a request/response
        //    flow always has work in both directions, so one task handling both
        //    halves the scheduler round trips per burst and lets a wakeup do
        //    ingress *and* egress.
        {
            let socket = socket.clone();
            let sessions = sessions.clone();
            let ip_to_index = ip_to_index.clone();
            let peer_timestamps = peer_timestamps.clone();
            let tag = tag.clone();
            let running = self.running.clone();
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let mut stack_out_rx = stack_out_rx;
            let local_static = StaticSecret::from(self.private_key);
            let peers_auth: Vec<WireGuardPeerAuth> = self
                .peers
                .iter()
                .map(|p| WireGuardPeerAuth {
                    public_key: p.public_key,
                    preshared_key: p.preshared_key,
                })
                .collect();
            let peers_allowed: Vec<([u8; 32], Vec<ipnet::IpNet>)> = self
                .peers
                .iter()
                .map(|p| (p.public_key, p.allowed_ips.clone()))
                .collect();
            let awg = self.awg.clone();

            self.tasks.spawn(async move {
                let fd = socket.as_raw_fd();
                let mut rx = UdpBatch::new();
                let mut tx = UdpBatch::new();
                let mut gso = GsoBatch::new();
                // Inner source IP → session index, cached so a steady flow does
                // not take the route map's write lock once per packet.
                let mut last_route: Option<(IpAddr, u32)> = None;
                // Datagram buffers are recycled: after the first burst each
                // encrypted packet is built in a buffer from this pool, so a
                // steady flow allocates nothing on the send path.
                let mut pool: Vec<Vec<u8>> = Vec::new();
                let mut pending_out: Option<Vec<u8>> = None;

                loop {
                    // ---- A. Flush egress: everything the stack has produced,
                    //         encrypted into one `sendmmsg` burst.
                    let mut batch: Vec<Vec<u8>> = Vec::new();
                    if let Some(p) = pending_out.take() {
                        batch.push(p);
                    }
                    while batch.len() < UDP_BATCH {
                        match stack_out_rx.try_recv() {
                            Ok(p) => batch.push(p),
                            Err(_) => break,
                        }
                    }
                    if !batch.is_empty() {
                        let mut sealed: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
                        let mut dsts: Vec<SocketAddr> = Vec::with_capacity(batch.len());
                        for ip_pkt in batch.iter() {
                            let Some((_, dst_ip)) = inner_addrs(ip_pkt) else {
                                continue;
                            };
                            let Some(idx) = ip_to_index.get(&dst_ip).map(|v| *v) else {
                                debug!(
                                    "[{}] wireguard egress: no session for inner dst {}",
                                    tag, dst_ip
                                );
                                continue; // no session owns this inner destination
                            };
                            let Some(state) = sessions.get(&idx).map(|v| v.value().clone()) else {
                                continue;
                            };
                            let addr = *state.addr.lock();
                            let mut out = pool.pop().unwrap_or_default();
                            let ok = {
                                let mut sess = state.session.lock().await;
                                match sess.encrypt_data_packet_into(ip_pkt, &mut out) {
                                    Ok(()) => true,
                                    Err(e) => {
                                        debug!("[{}] wireguard encrypt failed: {}", tag, e);
                                        false
                                    }
                                }
                            };
                            if ok {
                                sealed.push(out);
                                dsts.push(addr);
                            } else {
                                pool.push(out);
                            }
                        }
                        gso.send_burst(&socket, fd, &mut tx, &sealed, &dsts).await;
                        pool.append(&mut sealed);
                    }

                    // ---- B. Wait for the next burst of datagrams, or for the
                    //         stack to produce output.
                    rx.arm();
                    let got = tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        res = socket.async_io(Interest::READABLE, || rx.recv(fd, UDP_BATCH)) => match res {
                            Ok(n) => n,
                            Err(e) => {
                                if running.load(Ordering::Relaxed) {
                                    warn!("[{}] wireguard udp recv error: {}", tag, e);
                                }
                                break;
                            }
                        },
                        p = stack_out_rx.recv() => match p {
                            Some(p) => {
                                pending_out = Some(p);
                                continue;
                            }
                            None => break,
                        },
                    };
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    if got == 0 {
                        continue;
                    }

                    for i in 0..got {
                        let Some(peer_addr) = rx.peer(i) else {
                            continue;
                        };
                        let mut buf = rx.take(i);
                        let n = buf.len();
                        if n < 4 {
                            continue; // runt datagram: not a WireGuard message
                        }
                        let msg_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

                        if msg_type == awg.h4 {
                            // ---- Data packet: [h4][receiver_index(4)][counter(8)][ciphertext]
                            // A data packet is at least the 16-byte header plus a
                            // 16-byte Poly1305 tag. Reject runts before indexing: an
                            // attacker could otherwise send `h4` alone and panic this
                            // (the only) receive loop, permanently taking the inbound down.
                            if n < WG_DATA_HEADER_LEN + WG_AEAD_TAG_LEN {
                                continue;
                            }
                            let receiver_index =
                                u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                            let Some(entry) = sessions.get(&receiver_index) else {
                                debug!(
                                    "[{}] wireguard data for unknown session {}",
                                    tag, receiver_index
                                );
                                continue; // unknown/expired session: drop silently
                            };
                            let state = entry.value().clone();
                            drop(entry);

                            // Decrypt in place: the plaintext replaces the ciphertext
                            // inside the receive buffer, so no copy or allocation.
                            let range = {
                                let mut sess = state.session.lock().await;
                                match sess.open_data_packet_in_place(&mut buf) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        debug!(
                                            "[{}] wireguard data decrypt failed from {}: {}",
                                            tag, peer_addr, e
                                        );
                                        continue;
                                    }
                                }
                            };

                            // Authenticated packet: roaming support — track latest peer address.
                            {
                                let mut addr = state.addr.lock();
                                if *addr != peer_addr {
                                    *addr = peer_addr;
                                }
                            }

                            if range.is_empty() {
                                continue; // WireGuard keepalive
                            }

                            // The stack wants the IP packet at offset 0: one in-place
                            // shift instead of a fresh allocation per packet.
                            let plain_len = range.len();
                            buf.copy_within(range, 0);
                            buf.truncate(plain_len);

                            let Some((src_ip, _)) = inner_addrs(&buf) else {
                                continue; // non IP inner traffic: drop
                            };

                            // Enforce per-peer allowed source IPs when configured.
                            if !state.allowed_ips.is_empty()
                                && !state.allowed_ips.iter().any(|net| net.contains(&src_ip))
                            {
                                debug!(
                                    "[{}] wireguard peer {} sent inner packet from disallowed IP {}",
                                    tag, peer_addr, src_ip
                                );
                                continue;
                            }

                            if last_route != Some((src_ip, receiver_index)) {
                                ip_to_index.insert(src_ip, receiver_index);
                                last_route = Some((src_ip, receiver_index));
                            }
                            // Backpressure, not a silent drop. The kernel is
                            // already holding this batch (4 MiB socket buffer),
                            // so waiting for the stack actor preserves the
                            // packet instead of throwing it away — and a thrown
                            // packet inside the tunnel is not free: TCP sees a
                            // loss and stalls the flow for a whole retransmit
                            // timeout (~1 s), which on this benchmark is the
                            // difference between 210 MB/s and 28 MB/s (measured;
                            // one dropped frame on the first burst was enough).
                            //
                            // The wait is bounded so a wedged stack cannot stall
                            // the receive loop forever — this pump also carries
                            // every peer's handshakes.
                            if let Err(e) = frame_tx.try_send(buf) {
                                let buf = e.into_inner();
                                if tokio::time::timeout(
                                    Duration::from_millis(50),
                                    frame_tx.send(buf),
                                )
                                .await
                                .is_err()
                                {
                                    debug!(
                                        "[{}] wireguard stack actor stalled; dropping packet",
                                        tag
                                    );
                                }
                            }
                        } else if n >= awg.s1 as usize + 148
                            && u32::from_le_bytes([
                                buf[awg.s1 as usize],
                                buf[awg.s1 as usize + 1],
                                buf[awg.s1 as usize + 2],
                                buf[awg.s1 as usize + 3],
                            ]) == awg.h1
                        {
                            // ---- Handshake initiation (possibly with AWG s1 junk prefix)
                            // Bind a session slot with a fresh receiver index. `rand::random`
                            // could collide with a live session, which would silently hijack
                            // (and later reap) another peer's tunnel, so retry a few times on
                            // collision instead of trusting the RNG.
                            let Some(receiver_index) = (0..8).find_map(|_| {
                                let candidate = rand::random::<u32>();
                                (!sessions.contains_key(&candidate)).then_some(candidate)
                            }) else {
                                warn!(
                                    "[{}] wireguard session table saturated; rejecting handshake from {}",
                                    tag, peer_addr
                                );
                                continue;
                            };
                            if sessions.len() >= MAX_SESSIONS {
                                warn!(
                                    "[{}] wireguard session limit ({}) reached; rejecting handshake from {}",
                                    tag, MAX_SESSIONS, peer_addr
                                );
                                continue;
                            }
                            let result = WireGuardHandshake::respond_to_initiation_with_peers(
                                &local_static,
                                receiver_index,
                                &awg,
                                &buf,
                                &peers_auth,
                            );
                            match result {
                                Ok(hs) => {
                                    // Reject replayed initiations: the timestamp must be
                                    // strictly newer than the last accepted one per peer.
                                    {
                                        let fresh = match peer_timestamps.get(&hs.peer_public_key) {
                                            Some(last) => hs.peer_timestamp > *last,
                                            None => true,
                                        };
                                        if !fresh {
                                            debug!(
                                                "[{}] wireguard initiation from {} replayed (stale TAI64N); dropped",
                                                tag, peer_addr
                                            );
                                            continue;
                                        }
                                        peer_timestamps
                                            .insert(hs.peer_public_key, hs.peer_timestamp);
                                    }
                                    let allowed_ips = peers_allowed
                                        .iter()
                                        .find(|(pk, _)| *pk == hs.peer_public_key)
                                        .map(|(_, ips)| ips.clone())
                                        .unwrap_or_default();
                                    sessions.insert(
                                        receiver_index,
                                        Arc::new(PeerSessionState {
                                            session: tokio::sync::Mutex::new(hs.session),
                                            addr: parking_lot::Mutex::new(peer_addr),
                                            created: Instant::now(),
                                            allowed_ips,
                                        }),
                                    );
                                    if let Err(e) = socket.send_to(&hs.response, peer_addr).await {
                                        warn!(
                                            "[{}] failed to send wireguard handshake response to {}: {}",
                                            tag, peer_addr, e
                                        );
                                    } else {
                                        debug!(
                                            "[{}] wireguard handshake completed with {} (peer {:02x?}…)",
                                            tag,
                                            peer_addr,
                                            &hs.peer_public_key[..4]
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        "[{}] wireguard initiation from {} rejected: {}",
                                        tag, peer_addr, e
                                    );
                                }
                            }
                        }
                        // Unknown message types (incl. junk/cookie): drop silently.
                    }
                }
            });
        }

        // 3. Session reaper: expire sessions past REJECT_AFTER_TIME (peers must re-handshake).
        {
            let sessions = sessions.clone();
            let ip_to_index = ip_to_index.clone();
            let tag = tag.clone();
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            self.tasks.spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        _ = tokio::time::sleep(REAPER_INTERVAL) => {
                            let expired: Vec<u32> = sessions
                                .iter()
                                .filter(|e| {
                                    e.value().created.elapsed()
                                        > Duration::from_secs(WG_REJECT_AFTER_TIME_SECS)
                                })
                                .map(|e| *e.key())
                                .collect();
                            for idx in expired {
                                sessions.remove(&idx);
                                ip_to_index.retain(|_, v| *v != idx);
                                debug!("[{}] expired wireguard session {}", tag, idx);
                            }
                        }
                    }
                }
            });
        }

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

// ---------------------------------------------------------------------------
// Batched datagram I/O
//
// One datagram per `recv_from`/`send_to` costs a syscall *and* a scheduler round
// trip per inner packet, in each direction; measured on this path it was ~4
// syscalls per packet per side (recvfrom, sendto, epoll_wait, futex) with most
// process CPU inside the kernel. `recvmmsg`/`sendmmsg` move a whole burst per
// syscall, and because both tunnel ends batch, the bursts reinforce each other.
//
// The outbound side of the tunnel (flux-outbound) carries a copy of this helper:
// the two crates are deliberately independent, and this is datapath plumbing
// rather than shared policy.
// ---------------------------------------------------------------------------

/// Datagrams moved by a single `recvmmsg`/`sendmmsg` call.
const UDP_BATCH: usize = 32;

// ---------------------------------------------------------------------------
// UDP segmentation offload (GSO) on the inbound egress.
//
// `UDP_SEGMENT` hands the kernel one super-packet plus a segment size and lets
// it do the segmentation on transmit, so N equal-sized datagrams cost one
// syscall, one route lookup and one skb instead of N. It is a sender-side
// offload: the peer sees ordinary datagrams, which is what makes it usable
// against a stock WireGuard peer rather than only between two flux endpoints.
//
// Measured on this path (bench_wireguard, 64 MiB verified payload per round,
// 6 rounds): per-datagram `sendmmsg` 127-136 MB/s, GSO 199-210 MB/s, and the
// tunnel's CPU per byte falls from 14.0 to 9.6 s/GB.
//
// An earlier cycle enabled this and measured **bimodal** throughput (9.8-25.6
// MB/s in 12/12 runs) and reverted it. The cause was not GSO: it was this
// helper handing the odd-sized frames of a burst to the kernel *after* the
// super-packet that followed them (see `send_burst`). The order-preserving
// version below measures 199-210 MB/s over 12 runs with zero reordering on the
// inner TCP stream.
// ---------------------------------------------------------------------------

const SOL_UDP: libc::c_int = 17;
const UDP_SEGMENT: libc::c_int = 103;
/// Largest super-packet worth building: 32 x 1452 = 46 KiB, comfortably under
/// the 64 KiB per-skb GSO limit.
const GSO_MAX_BYTES: usize = 48 * 1024;

/// Set once the kernel rejects a GSO cmsg, so a kernel without `UDP_SEGMENT`
/// pays for the probe exactly once instead of once per burst.
static GSO_DISABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Escape hatch, shared with the outbound side: `WG_NO_GSO_TX=1` forces plain
/// `sendmmsg` for the whole tunnel datapath.
fn gso_off() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var_os("WG_NO_GSO_TX").is_some())
}

pub(crate) struct GsoBatch {
    buf: Vec<u8>,
    cmsg: [u64; 8],
}

impl GsoBatch {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::with_capacity(GSO_MAX_BYTES),
            cmsg: [0; 8],
        }
    }

    async fn send(
        &mut self,
        socket: &UdpSocket,
        fd: RawFd,
        datagrams: &[&[u8]],
        dst: SocketAddr,
    ) -> std::io::Result<bool> {
        let seg_len = datagrams[0].len();
        self.buf.clear();
        self.buf.reserve(seg_len * datagrams.len());
        for d in datagrams {
            self.buf.extend_from_slice(d);
        }
        let total = self.buf.len();
        let (storage, addr_len) = sockaddr_of(dst);
        {
            let base = self.cmsg.as_mut_ptr() as *mut libc::cmsghdr;
            // SAFETY: `self.cmsg` is 64 bytes of 8-byte-aligned scratch, which is
            // more than `CMSG_SPACE(size_of::<u16>())` requires.
            unsafe {
                (*base).cmsg_len = libc::CMSG_LEN(2) as usize;
                (*base).cmsg_level = SOL_UDP;
                (*base).cmsg_type = UDP_SEGMENT;
                let data = libc::CMSG_DATA(base);
                std::ptr::copy_nonoverlapping((seg_len as u16).to_ne_bytes().as_ptr(), data, 2);
            }
        }
        let ctrl_len = unsafe { libc::CMSG_SPACE(2) } as usize;
        let buf = &self.buf;
        let cmsg = &self.cmsg;
        let ret = socket
            .async_io(Interest::WRITABLE, || {
                let mut name = storage;
                let mut iov = libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: total,
                };
                // SAFETY: plain C structs; every pointer points at `buf`, `name`
                // or `cmsg`, all alive for the duration of the call.
                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
                msg.msg_namelen = addr_len;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg.as_ptr() as *mut libc::c_void;
                msg.msg_controllen = ctrl_len;
                let r = unsafe { libc::sendmsg(fd, &msg, 0) };
                if r < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(r as usize)
                }
            })
            .await;
        let ret = match ret {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };
        if ret != total {
            // A UDP send is all-or-nothing; a short return means the super-packet
            // was split, which would silently corrupt the framing.
            return Err(std::io::Error::other("partial GSO send"));
        }
        Ok(true)
    }

    /// Coalesces consecutive equal-sized datagrams that share a destination,
    /// **in the order given**.
    ///
    /// The leftovers are flushed *before* the super-packet that would otherwise
    /// overtake them: a short segment handed to the kernel after the full-size
    /// segments that follow it in the inner TCP stream arrives out of order, the
    /// receiving stack opens a hole for it, and with a full receive buffer that
    /// hole can shut the advertised window until the retransmit timeout repairs
    /// it. Same defect and same fix as the outbound copy of this helper.
    async fn send_burst(
        &mut self,
        socket: &UdpSocket,
        fd: RawFd,
        batch: &mut UdpBatch,
        datagrams: &[Vec<u8>],
        dsts: &[SocketAddr],
    ) -> usize {
        let mut sent = 0;
        let mut flush = 0usize;
        let mut i = 0usize;
        while i < datagrams.len() {
            let len = datagrams[i].len();
            let dst = dsts[i];
            let mut j = i + 1;
            while j < datagrams.len() && datagrams[j].len() == len && dsts[j] == dst {
                j += 1;
            }
            if j - i < 2
                || len * (j - i) > GSO_MAX_BYTES
                || GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
                || gso_off()
            {
                i = j; // ordinary datagrams, in place
                continue;
            }
            if flush < i {
                sent +=
                    flush_singles(socket, fd, batch, &datagrams[flush..i], &dsts[flush..i]).await;
                flush = i;
            }
            let refs: Vec<&[u8]> = datagrams[i..j].iter().map(|d| d.as_slice()).collect();
            match self.send(socket, fd, &refs, dst).await {
                Ok(true) => {
                    sent += j - i;
                    i = j;
                    flush = i;
                    continue;
                }
                Ok(false) => {
                    GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                    debug!("wg inbound egress: UDP GSO rejected, using sendmmsg");
                }
                Err(e) => {
                    GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                    debug!("wg inbound egress: GSO send failed ({e}), using sendmmsg");
                }
            }
            i = j;
        }
        sent += flush_singles(socket, fd, batch, &datagrams[flush..], &dsts[flush..]).await;
        sent
    }
}

/// One batched `sendmmsg` (retried until the slice is gone) for datagrams that
/// are not part of a GSO super-packet.
async fn flush_singles(
    socket: &UdpSocket,
    fd: RawFd,
    batch: &mut UdpBatch,
    datagrams: &[Vec<u8>],
    dsts: &[SocketAddr],
) -> usize {
    let mut off = 0;
    while off < datagrams.len() {
        let refs: Vec<&[u8]> = datagrams[off..].iter().map(|d| d.as_slice()).collect();
        let ds: Vec<SocketAddr> = dsts[off..].to_vec();
        match socket
            .async_io(Interest::WRITABLE, || batch.send_refs(fd, &refs, &ds))
            .await
        {
            Ok(n) if n > 0 => off += n,
            _ => break,
        }
    }
    off
}
/// Receive slot size: a 1420-byte inner packet plus WG header/tag plus any
/// AmneziaWG junk prefix fits comfortably.
const UDP_DGRAM_CAP: usize = 4096;

/// Reusable scratch space for batched datagram syscalls.
struct UdpBatch {
    /// Receive slots. An armed slot has `len == UDP_DGRAM_CAP`; a slot handed to
    /// the stack is left empty and re-allocated by [`Self::arm`].
    slots: Vec<Vec<u8>>,
    iov: Vec<libc::iovec>,
    hdr: Vec<libc::mmsghdr>,
    addr: Vec<libc::sockaddr_storage>,
}

// SAFETY: `UdpBatch` is scratch space used by exactly one task at a time. Its raw
// pointers are rebuilt from its own heap allocations on every syscall attempt and
// never outlive the struct, so moving it to another thread is sound.
unsafe impl Send for UdpBatch {}

impl UdpBatch {
    fn new() -> Self {
        Self {
            slots: (0..UDP_BATCH).map(|_| vec![0u8; UDP_DGRAM_CAP]).collect(),
            iov: (0..UDP_BATCH)
                .map(|_| libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                })
                .collect(),
            hdr: (0..UDP_BATCH)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            addr: (0..UDP_BATCH)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
        }
    }

    /// (Re)arms empty slots so the kernel may write into all of them.
    fn arm(&mut self) {
        for slot in &mut self.slots {
            if slot.len() != UDP_DGRAM_CAP {
                *slot = vec![0u8; UDP_DGRAM_CAP];
            }
        }
    }

    /// One `recvmmsg` attempt. Returns how many datagrams were read; slot `i`
    /// then holds datagram `i` (its length in `slots[i].len()`).
    fn recv(&mut self, fd: RawFd, max: usize) -> std::io::Result<usize> {
        let max = max.min(UDP_BATCH);
        for i in 0..max {
            self.addr[i] = unsafe { std::mem::zeroed() };
            self.iov[i] = libc::iovec {
                iov_base: self.slots[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: UDP_DGRAM_CAP,
            };
            self.hdr[i] = unsafe { std::mem::zeroed() };
            self.hdr[i].msg_hdr.msg_name = &mut self.addr[i] as *mut _ as *mut libc::c_void;
            self.hdr[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            self.hdr[i].msg_hdr.msg_iov = &mut self.iov[i];
            self.hdr[i].msg_hdr.msg_iovlen = 1;
        }
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                self.hdr.as_mut_ptr(),
                max as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ret = ret as usize;
        for i in 0..ret {
            self.slots[i].truncate(self.hdr[i].msg_len as usize);
        }
        Ok(ret)
    }

    /// Removes slot `i` (the caller owns the bytes from then on).
    fn take(&mut self, i: usize) -> Vec<u8> {
        std::mem::take(&mut self.slots[i])
    }

    /// Source address of the datagram in slot `i`.
    fn peer(&self, i: usize) -> Option<SocketAddr> {
        sockaddr_to_std(&self.addr[i])
    }

    /// One `sendmmsg` attempt, with a destination per datagram (an inbound can
    /// serve several roaming peers at once).
    fn send_refs(
        &mut self,
        fd: RawFd,
        datagrams: &[&[u8]],
        dsts: &[SocketAddr],
    ) -> std::io::Result<usize> {
        let n = datagrams.len().min(dsts.len()).min(UDP_BATCH);
        if n == 0 {
            return Ok(0);
        }
        for i in 0..n {
            let (storage, addr_len) = sockaddr_of(dsts[i]);
            self.addr[i] = storage;
            self.iov[i] = libc::iovec {
                // The kernel only reads the payload; `as_ptr` keeps the borrow honest.
                iov_base: datagrams[i].as_ptr() as *mut libc::c_void,
                iov_len: datagrams[i].len(),
            };
            self.hdr[i] = unsafe { std::mem::zeroed() };
            self.hdr[i].msg_hdr.msg_name = &mut self.addr[i] as *mut _ as *mut libc::c_void;
            self.hdr[i].msg_hdr.msg_namelen = addr_len;
            self.hdr[i].msg_hdr.msg_iov = &mut self.iov[i];
            self.hdr[i].msg_hdr.msg_iovlen = 1;
        }
        let ret = unsafe { libc::sendmmsg(fd, self.hdr.as_mut_ptr(), n as libc::c_uint, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ret as usize)
    }
}

/// Request a deep kernel queue for the tunnel socket.
///
/// The tunnel is a bulk transport: with the default 208 KiB buffer the receiver
/// drains (and wakes) almost as often as the sender sends, so a burst is only a
/// couple of packets. A multi-megabyte queue decouples the two ends and lets one
/// `recvmmsg` collect a genuinely full batch. The kernel caps the request at
/// `net.core.{r,w}mem_max`, so this is a best-effort hint, not a guarantee.
pub(crate) fn tune_socket_buffers(socket: &UdpSocket) {
    const BYTES: libc::c_int = 4 * 1024 * 1024;
    let fd = socket.as_raw_fd();
    let arg = &BYTES as *const libc::c_int as *const libc::c_void;
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a live UDP socket and the option buffer is a valid c_int.
    unsafe {
        let _ = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, arg, len);
        let _ = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, arg, len);
    }
}

fn sockaddr_of(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe { std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sin) };
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe { std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sin6) };
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Inner IPv4/IPv6 source and destination address of a tunnel packet.
///
/// Header-only: the smoltcp stack parses the packet again anyway, so paying for
/// a payload copy here (`tun::parse_ip_packet`) is pure overhead on this path.
fn inner_addrs(pkt: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match pkt.first()? >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
            ))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            Some((
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?)),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same guard as the outbound copy of this helper: the odd-sized frames of a
    /// burst must not leave after the equal-sized run that follows them, or the
    /// peer sees an out-of-order TCP segment and can stall on it for a full
    /// retransmit timeout. See `send_burst`.
    #[tokio::test]
    async fn send_burst_preserves_datagram_order() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fd = tx.as_raw_fd();

        let mut dgrams = vec![vec![1u8; 300]];
        for _ in 0..5 {
            dgrams.push(vec![2u8; 1468]);
        }
        dgrams.push(vec![3u8; 700]);
        let dsts = vec![dst; dgrams.len()];
        let expected: Vec<(u8, usize)> = dgrams.iter().map(|d| (d[0], d.len())).collect();

        let mut gso = GsoBatch::new();
        let mut batch = UdpBatch::new();
        let sent = gso.send_burst(&tx, fd, &mut batch, &dgrams, &dsts).await;
        assert_eq!(sent, dgrams.len(), "every datagram must be accounted for");

        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];
        for _ in 0..dgrams.len() {
            // Generous on purpose: this asserts *ordering*, and a loaded machine (a
            // release build plus benchmarks running beside the suite) can delay a
            // loopback wakeup well past a tight bound. The failure this guards
            // against is a reordered burst, not a slow one.
            let n = tokio::time::timeout(Duration::from_secs(30), rx.recv(&mut buf))
                .await
                .expect("datagram did not arrive")
                .unwrap();
            got.push((buf[0], n));
        }
        assert_eq!(
            got, expected,
            "datagrams left the sender in a different order than the TCP stream needed"
        );
    }
}
