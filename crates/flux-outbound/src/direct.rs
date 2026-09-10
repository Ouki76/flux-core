use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use async_trait::async_trait;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta,
    TargetAddress, UdpPacket,
};
use flux_dns::DnsResolver;
use flux_transport::tcp::TcpTransport;

pub struct DirectOutbound {
    tag: String,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>, resolver: Arc<DnsResolver>) -> Self {
        Self {
            tag: tag.into(),
            resolver,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let addr = self.resolver.resolve(&meta.destination).await?;
        let stream = TcpTransport::connect(addr, self.connect_timeout).await?;
        Ok(Box::new(stream))
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?;
        
        Ok(Box::new(DirectPacketEndpoint {
            socket: Arc::new(socket),
            resolver: self.resolver.clone(),
        }))
    }
}

pub struct DirectPacketEndpoint {
    socket: Arc<UdpSocket>,
    resolver: Arc<DnsResolver>,
}

#[async_trait]
impl PacketEndpoint for DirectPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let dest_addr = match &packet.destination {
            TargetAddress::Ip(addr) => *addr,
            TargetAddress::Domain(..) => self.resolver.resolve(&packet.destination).await?,
        };

        self.socket
            .send_to(&packet.payload, dest_addr)
            .await
            .map_err(FluxError::Io)?;

        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        let (len, src_addr) = self.socket.recv_from(&mut buf).await.map_err(FluxError::Io)?;

        buf.truncate(len);
        let payload = bytes::Bytes::from(buf);

        Ok(UdpPacket::new(
            payload,
            TargetAddress::Ip(src_addr),
            TargetAddress::Ip(src_addr),
        ))
    }
}
