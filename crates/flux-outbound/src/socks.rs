use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use flux_dns::DnsResolver;
use flux_protocol::socks5::{Socks5Handshake, CMD_CONNECT, CMD_UDP_ASSOCIATE};
use flux_protocol::udp::{decode_socks5_udp, encode_socks5_udp};
use flux_transport::tcp::TcpTransport;

pub struct SocksOutbound {
    tag: String,
    server_address: TargetAddress,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
}

impl SocksOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            resolver,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let mut stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        Socks5Handshake::client_handshake(&mut stream, CMD_CONNECT, &meta.destination).await?;

        Ok(Box::new(stream))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let mut tcp_stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        let relay_opt = Socks5Handshake::client_handshake(
            &mut tcp_stream,
            CMD_UDP_ASSOCIATE,
            &meta.destination,
        )
        .await?;

        let mut relay_addr = relay_opt.ok_or_else(|| {
            FluxError::Protocol {
                protocol: "socks5-out",
                message: "server did not provide a valid relay address in UDP associate response".into(),
            }
        })?;

        // If relay address returned 0.0.0.0, use the server's IP address
        if relay_addr.ip().is_unspecified() {
            relay_addr = SocketAddr::new(server_addr.ip(), relay_addr.port());
        }

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?;

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
        let mut buf = vec![0u8; 65535];
        let (len, _from) = self.udp_socket.recv_from(&mut buf).await.map_err(FluxError::Io)?;
        buf.truncate(len);

        decode_socks5_udp(TargetAddress::Ip(self.relay_addr), bytes::Bytes::from(buf))
    }
}
