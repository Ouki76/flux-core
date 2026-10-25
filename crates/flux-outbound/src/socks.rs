use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_protocol::socks5::{CMD_CONNECT, CMD_UDP_ASSOCIATE, Socks5Handshake};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, StreamDialer,
    TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// /// A SOCKS5 client.
pub struct SocksOutbound {
    tag: String,
    server_address: TargetAddress,
    auth: Option<(String, String)>,
    resolver: Arc<DnsResolver>,
    /// Retained for API compatibility; connection timeouts are enforced by
    /// `dialer` (the carrier) rather than here.
    #[allow(dead_code)]
    connect_timeout: Duration,
    dialer: Arc<dyn StreamDialer>,
}

impl SocksOutbound {
    /// A client named `tag` dialling through `dialer`.
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            auth: None,
            resolver,
            connect_timeout: Duration::from_secs(10),
            dialer,
        }
    }

    /// Authenticates with username and password.
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }
}

#[async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "socks"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let mut stream: BoxedStream = self.dialer.dial().await?;

        let auth_ref = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        Socks5Handshake::client_handshake_with_auth(
            &mut stream,
            CMD_CONNECT,
            &meta.destination,
            auth_ref,
        )
        .await?;

        Ok(stream)
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        // The UDP-associate control channel must travel over the same carrier as
        // TCP traffic (TLS/WebSocket/REALITY/…). Dialling a bare `TcpStream`
        // here bypassed `self.dialer`, so a layered SOCKS outbound silently spoke
        // plaintext for UDP.
        let mut tcp_stream: BoxedStream = self.dialer.dial().await?;

        let auth_ref = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        let relay_opt = Socks5Handshake::client_handshake_with_auth(
            &mut tcp_stream,
            CMD_UDP_ASSOCIATE,
            &meta.destination,
            auth_ref,
        )
        .await?;

        let mut relay_addr = relay_opt.ok_or_else(|| FluxError::Protocol {
            protocol: "socks5-out",
            message: "server did not provide a valid relay address in UDP associate response"
                .into(),
        })?;

        // If the relay address is 0.0.0.0 or [::], substitute the server's IP.
        if relay_addr.ip().is_unspecified() {
            let server_addr = self.resolver.resolve(&self.server_address).await?;
            relay_addr = SocketAddr::new(server_addr.ip(), relay_addr.port());
        }

        let is_v6 = relay_addr.is_ipv6();
        let udp_socket = if is_v6 {
            match UdpSocket::bind("[::]:0").await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?,
            }
        } else {
            UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?
        };

        Ok(Box::new(SocksPacketEndpoint {
            _tcp_conn: Arc::new(Mutex::new(tcp_stream)),
            udp_socket: Arc::new(udp_socket),
            relay_addr,
        }))
    }
}

/// /// A SOCKS5 UDP association.
pub struct SocksPacketEndpoint {
    // Keeps the UDP-associate control connection alive for the lifetime of the
    // endpoint; dropping it tells the server to tear the association down.
    _tcp_conn: Arc<Mutex<BoxedStream>>,
    udp_socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
}

#[async_trait]
impl PacketEndpoint for SocksPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let encoded = encode_socks5_udp(&packet);
        self.udp_socket
            .send_to(&encoded, self.relay_addr)
            .await
            .map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = flux_common::BufferPool::packet_pool().acquire_guard();
        let (len, _from) = self
            .udp_socket
            .recv_from(&mut guard)
            .await
            .map_err(FluxError::Io)?;
        // Report the used length so the pool scrubs only this datagram's prefix.
        guard.set_used(len);
        let payload = bytes::Bytes::copy_from_slice(&guard[..len]);

        let mut pkt = decode_socks5_udp(TargetAddress::Ip(self.relay_addr), payload)?;
        let remote = pkt.destination.clone();
        pkt.source = remote.clone();
        pkt.destination = remote;
        Ok(pkt)
    }
}
