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
    AwgConfig, WG_REJECT_AFTER_TIME_SECS, WireGuardHandshake, WireGuardPeerAuth, WireGuardSession,
};
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;

/// Default inner IP MTU for WireGuard tunnels (1500 - 80 bytes of WG/UDP/IP overhead).
pub const WG_INBOUND_DEFAULT_MTU: usize = 1420;
/// Channel capacity between the UDP receive loop and the smoltcp stack actor.
const FRAME_CHANNEL_CAP: usize = 2048;
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
            tokio::spawn(async move {
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

        // 2. UDP receive loop: handshakes + data packets → stack.
        {
            let socket = socket.clone();
            let sessions = sessions.clone();
            let ip_to_index = ip_to_index.clone();
            let tag = tag.clone();
            let running = self.running.clone();
            let mut shutdown_rx = self.shutdown_tx.subscribe();
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

            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let (n, peer_addr) = tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        res = socket.recv_from(&mut buf) => match res {
                            Ok(v) => v,
                            Err(e) => {
                                if running.load(Ordering::Relaxed) {
                                    warn!("[{}] wireguard udp recv error: {}", tag, e);
                                }
                                break;
                            }
                        },
                    };
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    let pkt = &buf[..n];
                    if pkt.len() < 4 {
                        continue;
                    }

                    let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);

                    if msg_type == awg.h4 {
                        // ---- Data packet: [h4][receiver_index(4)][counter(8)][ciphertext]
                        let receiver_index = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
                        let Some(entry) = sessions.get(&receiver_index) else {
                            debug!(
                                "[{}] wireguard data for unknown session {}",
                                tag, receiver_index
                            );
                            continue; // unknown/expired session: drop silently
                        };
                        let state = entry.value().clone();
                        drop(entry);

                        let plain = {
                            let mut sess = state.session.lock().await;
                            match sess.decrypt_data_packet(pkt) {
                                Ok(p) => p,
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

                        if plain.is_empty() {
                            continue; // WireGuard keepalive
                        }

                        let Some(parsed) = crate::tun::parse_ip_packet(&plain) else {
                            continue; // non TCP/UDP inner traffic: drop
                        };

                        // Enforce per-peer allowed source IPs when configured.
                        if !state.allowed_ips.is_empty()
                            && !state
                                .allowed_ips
                                .iter()
                                .any(|net| net.contains(&parsed.src.ip()))
                        {
                            debug!(
                                "[{}] wireguard peer {} sent inner packet from disallowed IP {}",
                                tag, peer_addr, parsed.src
                            );
                            continue;
                        }

                        ip_to_index.insert(parsed.src.ip(), receiver_index);
                        if frame_tx.try_send(plain).is_err() {
                            debug!(
                                "[{}] wireguard stack frame channel full; dropping packet",
                                tag
                            );
                        }
                    } else if pkt.len() >= awg.s1 as usize + 148
                        && u32::from_le_bytes([
                            pkt[awg.s1 as usize],
                            pkt[awg.s1 as usize + 1],
                            pkt[awg.s1 as usize + 2],
                            pkt[awg.s1 as usize + 3],
                        ]) == awg.h1
                    {
                        // ---- Handshake initiation (possibly with AWG s1 junk prefix)
                        let receiver_index = rand::random::<u32>();
                        let result = WireGuardHandshake::respond_to_initiation_with_peers(
                            &local_static,
                            receiver_index,
                            &awg,
                            pkt,
                            &peers_auth,
                        );
                        match result {
                            Ok(hs) => {
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
            });
        }

        // 3. TX path: stack output → encrypt → send to the owning peer.
        {
            let socket = socket.clone();
            let sessions = sessions.clone();
            let ip_to_index = ip_to_index.clone();
            let tag = tag.clone();
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let mut stack_out_rx = stack_out_rx;
            tokio::spawn(async move {
                loop {
                    let ip_pkt = tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        res = stack_out_rx.recv() => match res {
                            Some(p) => p,
                            None => break,
                        },
                    };
                    let Some(parsed) = crate::tun::parse_ip_packet(&ip_pkt) else {
                        continue;
                    };
                    let Some(idx) = ip_to_index.get(&parsed.dst.ip()).map(|v| *v) else {
                        debug!(
                            "[{}] wireguard egress: no session for inner dst {}",
                            tag,
                            parsed.dst.ip()
                        );
                        continue; // no session owns this inner destination
                    };
                    let Some(state) = sessions.get(&idx).map(|v| v.value().clone()) else {
                        continue;
                    };
                    let encrypted = {
                        let mut sess = state.session.lock().await;
                        match sess.encrypt_data_packet(&ip_pkt) {
                            Ok(p) => p,
                            Err(e) => {
                                debug!("[{}] wireguard encrypt failed: {}", tag, e);
                                continue;
                            }
                        }
                    };
                    let addr = *state.addr.lock();
                    let _ = socket.send_to(&encrypted, addr).await;
                }
            });
        }

        // 4. Session reaper: expire sessions past REJECT_AFTER_TIME (peers must re-handshake).
        {
            let sessions = sessions.clone();
            let ip_to_index = ip_to_index.clone();
            let tag = tag.clone();
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            tokio::spawn(async move {
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
        Ok(())
    }
}
