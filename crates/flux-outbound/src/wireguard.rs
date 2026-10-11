use async_trait::async_trait;
use flux_protocol::wireguard::{AwgConfig, WireGuardConfig, WireGuardHandshake, WireGuardSession};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub struct WireGuardOutbound {
    tag: String,
    config: WireGuardConfig,
    resolver: Arc<flux_dns::DnsResolver>,
    session: Arc<Mutex<Option<Arc<Mutex<WireGuardSession>>>>>,
}

impl WireGuardOutbound {
    pub fn new(
        tag: impl Into<String>,
        config: WireGuardConfig,
        resolver: Arc<flux_dns::DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            config,
            resolver,
            session: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_awg(mut self, awg: AwgConfig) -> Self {
        self.config.awg = Some(awg);
        self
    }

    async fn get_or_create_session(
        &self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> FluxResult<Arc<Mutex<WireGuardSession>>> {
        let mut guard = self.session.lock().await;
        if let Some(ref s) = *guard {
            return Ok(s.clone());
        }

        let awg = self.config.awg.clone().unwrap_or_default();

        // 1. Send AmneziaWG junk packets if configured
        if awg.jc > 0 {
            let junk_packets = WireGuardHandshake::generate_junk_packets(&awg);
            for junk in junk_packets {
                let _ = socket.send_to(&junk, peer_addr).await;
            }
        }

        // 2. Perform Handshake Initiation
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
            .send_to(&init_pkt, peer_addr)
            .await
            .map_err(FluxError::Io)?;

        // Receive Handshake Response (Message 2) with 5s timeout
        let mut resp_buf = vec![0u8; 1024];
        let (resp_len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut resp_buf),
        )
        .await
        .map_err(|_| FluxError::Timeout("WireGuard handshake response timed out".into()))?
        .map_err(FluxError::Io)?;

        let session = WireGuardHandshake::consume_response(state, &resp_buf[..resp_len])?;
        let session_arc = Arc::new(Mutex::new(session));
        *guard = Some(session_arc.clone());
        Ok(session_arc)
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
        let peer = self.resolver.resolve(&self.config.server_address).await?;
        let is_v6 = peer.is_ipv6();
        let socket = if is_v6 {
            match UdpSocket::bind("[::]:0").await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?,
            }
        } else {
            UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?
        };
        let session_arc = self.get_or_create_session(&socket, peer).await?;

        Ok(Box::new(WireGuardPacketEndpoint {
            socket: Arc::new(socket),
            peer,
            session: session_arc,
            destination: meta.destination.clone(),
        }))
    }
}

pub struct WireGuardPacketEndpoint {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    session: Arc<Mutex<WireGuardSession>>,
    destination: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for WireGuardPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let encrypted = {
            let mut s = self.session.lock().await;
            s.encrypt_data_packet(&packet.payload)?
        };
        self.socket
            .send_to(&encrypted, self.peer)
            .await
            .map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut buf = [0u8; 2048];
        let (n, _) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(FluxError::Io)?;
        let plain = {
            let mut s = self.session.lock().await;
            s.decrypt_data_packet(&buf[..n])?
        };

        Ok(UdpPacket::new(
            plain.into(),
            self.destination.clone(),
            self.destination.clone(),
        ))
    }
}
