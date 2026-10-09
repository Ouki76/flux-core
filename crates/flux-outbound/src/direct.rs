use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_transport::tcp::TcpTransport;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

pub struct DirectOutbound {
    tag: String,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
    fragment: Option<flux_transport::fragment::FragmentationConfig>,
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>, resolver: Arc<DnsResolver>) -> Self {
        Self {
            tag: tag.into(),
            resolver,
            connect_timeout: Duration::from_secs(10),
            fragment: None,
        }
    }

    pub fn with_fragmentation(
        mut self,
        cfg: flux_transport::fragment::FragmentationConfig,
    ) -> Self {
        self.fragment = Some(cfg);
        self
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "direct"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let addr = self.resolver.resolve(&meta.destination).await?;
        let stream = TcpTransport::connect(addr, self.connect_timeout).await?;
        if let Some(frag_cfg) = self.fragment {
            Ok(Box::new(flux_transport::fragment::FragmentedStream::new(
                stream, frag_cfg,
            )))
        } else {
            Ok(Box::new(stream))
        }
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let is_v6 = match &meta.destination {
            TargetAddress::Ip(sa) => sa.is_ipv6(),
            TargetAddress::Domain(..) => self
                .resolver
                .resolve(&meta.destination)
                .await
                .map(|a| a.is_ipv6())
                .unwrap_or(false),
        };
        let socket = if is_v6 {
            match UdpSocket::bind("[::]:0").await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?,
            }
        } else {
            UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?
        };

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
        let mut guard = flux_common::BufferPool::packet_pool().acquire_guard();
        let (len, src_addr) = self
            .socket
            .recv_from(&mut guard)
            .await
            .map_err(FluxError::Io)?;
        let payload = bytes::Bytes::copy_from_slice(&guard[..len]);

        Ok(UdpPacket::new(
            payload,
            TargetAddress::Ip(src_addr),
            TargetAddress::Ip(src_addr),
        ))
    }
}
