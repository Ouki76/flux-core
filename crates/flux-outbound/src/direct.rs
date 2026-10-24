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

/// /// Connects to the destination itself, optionally fragmenting the ClientHello.
pub struct DirectOutbound {
    tag: String,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
    fragment: Option<flux_transport::fragment::FragmentationConfig>,
}

impl DirectOutbound {
    /// A direct outbound named `tag`.
    pub fn new(tag: impl Into<String>, resolver: Arc<DnsResolver>) -> Self {
        Self {
            tag: tag.into(),
            resolver,
            connect_timeout: Duration::from_secs(10),
            fragment: None,
        }
    }

    /// Splits the TLS ClientHello when the destination is HTTPS.
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

/// /// A UDP association that sends datagrams straight from a local socket.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> Arc<DnsResolver> {
        // The direct outbound's tests only use literal IP destinations, so the
        // resolver is never asked to look anything up.
        Arc::new(DnsResolver::new(None))
    }

    fn meta(dest: &str) -> SessionMeta {
        SessionMeta::new(
            "127.0.0.1:1234".parse().unwrap(),
            dest.parse().unwrap(),
            "test",
            flux_types::NetworkType::Tcp,
        )
    }

    /// TCP: a real loopback echo round-trip proves the whole dial path.
    #[tokio::test]
    async fn connects_to_a_real_tcp_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let out = DirectOutbound::new("direct", resolver());
        let mut stream = out
            .dial_stream(&meta(&addr.to_string()))
            .await
            .expect("dial a loopback listener");
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// Connecting to a closed port must surface an error, not hang.
    #[tokio::test]
    async fn closed_port_is_an_error() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let out = DirectOutbound::new("direct", resolver());
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            out.dial_stream(&meta(&format!("127.0.0.1:{port}"))),
        )
        .await
        .expect("dial must not hang");
        assert!(res.is_err(), "connecting to a closed port must fail");
    }

    /// UDP: a datagram sent through the endpoint reaches the peer, and the reply
    /// is returned with the responder as both source and destination.
    #[tokio::test]
    async fn udp_round_trip_reports_the_responder() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            peer.send_to(&buf[..n], from).await.unwrap();
        });

        let out = DirectOutbound::new("direct", resolver());
        let ep = out
            .dial_packet(&meta(&peer_addr.to_string()))
            .await
            .expect("dial a UDP endpoint");

        ep.send_packet(UdpPacket {
            source: "127.0.0.1:1234".parse().unwrap(),
            destination: peer_addr.to_string().parse().unwrap(),
            payload: bytes::Bytes::from_static(b"hello-udp"),
        })
        .await
        .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(5), ep.recv_packet())
            .await
            .expect("reply must arrive")
            .expect("recv must succeed");
        assert_eq!(&reply.payload[..], b"hello-udp");
        assert_eq!(
            reply.source,
            peer_addr.to_string().parse::<TargetAddress>().unwrap(),
            "the reply must be attributed to the responder"
        );
    }

    #[test]
    fn is_not_a_group_and_uses_shared_endpoints() {
        let out = DirectOutbound::new("direct", resolver());
        assert!(!out.is_group());
        assert!(
            !out.udp_endpoint_per_destination(),
            "direct encodes the destination in every datagram, so one endpoint is enough"
        );
    }
}
