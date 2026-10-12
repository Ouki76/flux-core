use async_trait::async_trait;
use flux_protocol::wireguard::{
    WG_DEFAULT_KEEPALIVE_SECS, WG_REKEY_AFTER_TIME_SECS, WireGuardConfig, WireGuardHandshake,
    WireGuardSession,
};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Shared tunnel core used by both the outbound and its packet endpoints,
/// so endpoints can transparently trigger a re-handshake when the session ages out.
struct WgTunnel {
    config: WireGuardConfig,
    resolver: Arc<flux_dns::DnsResolver>,
    state: Mutex<WgState>,
    keepalive_started: AtomicBool,
}

impl WgTunnel {
    fn new(config: WireGuardConfig, resolver: Arc<flux_dns::DnsResolver>) -> Self {
        Self {
            config,
            resolver,
            state: Mutex::new(WgState::default()),
            keepalive_started: AtomicBool::new(false),
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

    /// Ensures a fresh session exists, performing a handshake if needed.
    /// Concurrent callers are serialized: only one handshake runs at a time.
    async fn ensure_session(
        &self,
    ) -> FluxResult<(Arc<UdpSocket>, SocketAddr, Arc<Mutex<WireGuardSession>>)> {
        if let Some(v) = self.current_session().await {
            return Ok(v);
        }

        {
            let mut guard = self.state.lock().await;
            if guard.handshake_in_progress {
                drop(guard);
                // Another task is handshaking; wait for it to finish.
                for _ in 0..200 {
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
            Ok((sock, peer, sess)) => {
                guard.socket = Some(sock.clone());
                guard.peer = Some(peer);
                guard.session = Some(sess.clone());
                guard.established = Some(Instant::now());
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

    async fn perform_handshake(
        &self,
    ) -> FluxResult<(Arc<UdpSocket>, SocketAddr, Arc<Mutex<WireGuardSession>>)> {
        let peer = self.resolver.resolve(&self.config.server_address).await?;

        // Reuse the existing socket if the address family still matches.
        let existing = self.state.lock().await.socket.clone();
        let socket = match existing {
            Some(s)
                if s.local_addr()
                    .map(|a| a.is_ipv6() == peer.is_ipv6())
                    .unwrap_or(false) =>
            {
                s
            }
            _ => {
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
                Arc::new(s)
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

        socket
            .send_to(&init_pkt, peer)
            .await
            .map_err(FluxError::Io)?;

        let mut resp_buf = vec![0u8; 1024];
        let (resp_len, _) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv_from(&mut resp_buf))
                .await
                .map_err(|_| FluxError::Timeout("WireGuard handshake response timed out".into()))?
                .map_err(FluxError::Io)?;

        let session = WireGuardHandshake::consume_response(state, &resp_buf[..resp_len])?;
        Ok((socket, peer, Arc::new(Mutex::new(session))))
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
                tokio::time::sleep(Duration::from_secs(1)).await;
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

    fn local_ip_for(&self, dst: IpAddr) -> IpAddr {
        if let Some(ip) = self.config.local_address {
            return ip;
        }
        match dst {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
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

    async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
        Err(FluxError::Protocol {
            protocol: "wireguard",
            message: "WireGuard outbound is an L3 packet tunnel; stream routing requires TUN inbound or packet endpoints (dial_packet)".into(),
        })
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        self.tunnel.start_keepalive_task();
        self.tunnel.ensure_session().await?;

        // WireGuard transports L3 IP packets: a domain destination must be
        // resolved once here so it can be embedded into the inner IP header.
        let dst_addr = self.tunnel.resolver.resolve(&meta.destination).await?;

        Ok(Box::new(WireGuardPacketEndpoint {
            tunnel: self.tunnel.clone(),
            dst: dst_addr,
            src_ip: self.tunnel.local_ip_for(dst_addr.ip()),
        }))
    }
}

pub struct WireGuardPacketEndpoint {
    tunnel: Arc<WgTunnel>,
    dst: SocketAddr,
    src_ip: IpAddr,
}

#[async_trait]
impl PacketEndpoint for WireGuardPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        // Transparent rekey when REKEY_AFTER_TIME expired.
        let (socket, peer, session) = self.tunnel.ensure_session().await?;

        // Encapsulate the UDP payload into an inner IP packet — real WireGuard
        // peers route IP datagrams, not bare UDP payloads.
        let src_port = match &packet.source {
            TargetAddress::Ip(a) => a.port(),
            TargetAddress::Domain(_, p) => *p,
        };
        let ip_pkt = build_ip_udp_packet(self.src_ip, self.dst, src_port, &packet.payload)
            .ok_or_else(|| {
                FluxError::InvalidAddress(format!(
                    "cannot encapsulate UDP packet to {} into an IP datagram",
                    self.dst
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
        let (socket, _peer, session) = self.tunnel.ensure_session().await?;

        let mut buf = vec![0u8; 2048];
        loop {
            let (n, _) = socket.recv_from(&mut buf).await.map_err(FluxError::Io)?;
            let plain = {
                let mut s = session.lock().await;
                match s.decrypt_data_packet(&buf[..n]) {
                    Ok(p) => p,
                    // Non-data messages (handshake/cookie) or corrupted packets: skip.
                    Err(_) => continue,
                }
            };

            // Empty plaintext = WireGuard keepalive; skip.
            if plain.is_empty() {
                continue;
            }

            // Decapsulate the inner IP packet back into a UDP datagram.
            if let Some((src, dst, payload)) = parse_ip_udp_packet(&plain) {
                return Ok(UdpPacket::new(
                    payload.into(),
                    TargetAddress::Ip(src),
                    TargetAddress::Ip(dst),
                ));
            }
            // Non-UDP inner traffic (e.g., ICMP errors): skip.
        }
    }
}

// ---------------------------------------------------------------------------
// Inner IP/UDP datagram helpers (WireGuard tunnels L3 packets)
// ---------------------------------------------------------------------------

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
fn parse_ip_udp_packet(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 28 {
                return None;
            }
            let ihl = (usize::from(pkt[0] & 0x0f)) * 4;
            if pkt.len() < ihl + 8 || pkt[9] != 17 {
                return None;
            }
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            let udp = &pkt[ihl..];
            let sport = u16::from_be_bytes([udp[0], udp[1]]);
            let dport = u16::from_be_bytes([udp[2], udp[3]]);
            let ulen = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
            if ulen < 8 || udp.len() < ulen {
                return None;
            }
            Some((
                SocketAddr::new(IpAddr::V4(src), sport),
                SocketAddr::new(IpAddr::V4(dst), dport),
                udp[8..ulen].to_vec(),
            ))
        }
        6 => {
            if pkt.len() < 48 || pkt[6] != 17 {
                return None;
            }
            let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            if pkt.len() < 40 + plen || plen < 8 {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            let udp = &pkt[40..40 + plen];
            let sport = u16::from_be_bytes([udp[0], udp[1]]);
            let dport = u16::from_be_bytes([udp[2], udp[3]]);
            Some((
                SocketAddr::new(IpAddr::V6(src), sport),
                SocketAddr::new(IpAddr::V6(dst), dport),
                udp[8..].to_vec(),
            ))
        }
        _ => None,
    }
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
}
