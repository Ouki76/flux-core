use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_protocol::socks5::{CMD_CONNECT, CMD_UDP_ASSOCIATE, Socks5Handshake};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_transport::tcp::TcpTransport;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, StreamDialer,
    TargetAddress, UdpPacket,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

pub struct SocksOutbound {
    tag: String,
    server_address: TargetAddress,
    auth: Option<(String, String)>,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
    dialer: Arc<dyn StreamDialer>,
}

impl SocksOutbound {
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
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let mut tcp_stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

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

        // If relay address returned 0.0.0.0 or [::], use the server's IP address
        if relay_addr.ip().is_unspecified() {
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

pub struct SocksPacketEndpoint {
    _tcp_conn: Arc<Mutex<TcpStream>>,
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
        let payload = bytes::Bytes::copy_from_slice(&guard[..len]);

        let mut pkt = decode_socks5_udp(TargetAddress::Ip(self.relay_addr), payload)?;
        let remote = pkt.destination.clone();
        pkt.source = remote.clone();
        pkt.destination = remote;
        Ok(pkt)
    }
}
