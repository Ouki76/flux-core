use crate::error::{FluxError, FluxResult};
use crate::session::{SessionMeta, UdpPacket};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// A bidirectional stream of bytes with downcasting capabilities.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> AsyncStream for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub type BoxedStream = Box<dyn AsyncStream>;

/// Composable stream dialer establishing carrier, security, and transport framing layers.
#[async_trait]
pub trait StreamDialer: Send + Sync {
    async fn dial(&self) -> FluxResult<BoxedStream>;
}

/// A UDP packet endpoint representing an outbound association.
#[async_trait]
pub trait PacketEndpoint: Send + Sync {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()>;
    async fn recv_packet(&self) -> FluxResult<UdpPacket>;
}

/// Inbound adapter listening for client connections or packets.
#[async_trait]
pub trait Inbound: Send + Sync {
    fn tag(&self) -> &str;
    fn protocol(&self) -> &'static str {
        "inbound"
    }
    fn listen_addr(&self) -> Option<String> {
        None
    }
    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()>;
    async fn stop(&self) -> FluxResult<()>;
}

/// Outbound adapter routing connections to their ultimate destination.
#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn protocol(&self) -> &'static str {
        "outbound"
    }
    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream>;
    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>>;

    /// Whether this outbound is a group (Selector, UrlTest, etc.)
    fn is_group(&self) -> bool {
        false
    }

    /// Group type string ("Selector", "URLTest", etc.)
    fn group_type(&self) -> Option<&'static str> {
        None
    }

    /// Dynamically change the selected outbound if this is a selector group.
    fn select(&self, _tag: &str) -> FluxResult<()> {
        Err(FluxError::Protocol {
            protocol: "outbound-group",
            message: "this outbound is not a selectable group".into(),
        })
    }

    /// Returns the currently active outbound tag for groups.
    fn current_selected(&self) -> Option<String> {
        None
    }

    /// Returns the list of candidate outbound tags for groups.
    fn candidate_outbounds(&self) -> Vec<String> {
        vec![]
    }

    /// Whether a single UDP endpoint may carry traffic for **multiple**
    /// destinations.
    ///
    /// Most outbounds encode the destination inside every datagram (direct,
    /// Shadowsocks, SOCKS5 UDP, Trojan, VLESS), so one endpoint is enough and the
    /// dispatcher caches it per outbound tag. Protocols that establish a
    /// per-destination association — VMess, whose UDP framing is a bare
    /// length-prefixed stream — must return `true`, otherwise the first
    /// destination's association silently serves every later destination.
    fn udp_endpoint_per_destination(&self) -> bool {
        false
    }

    /// Graceful shutdown hook for background tasks (e.g. probing loops).
    fn stop(&self) {}
}

/// Lookup registry for outbound groups (selector, urltest) to find candidate outbounds.
pub trait OutboundLookup: Send + Sync {
    fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>>;
}

/// Core dispatcher routing traffic from Inbounds to appropriate Outbounds.
#[async_trait]
pub trait Dispatcher: Send + Sync {
    async fn dispatch_stream(&self, meta: SessionMeta, inbound_stream: BoxedStream);
    async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<BoxedStream>;
    async fn bridge_streams(
        &self,
        meta: SessionMeta,
        inbound_stream: BoxedStream,
        outbound_stream: BoxedStream,
    );
    async fn dispatch_packet(
        &self,
        meta: SessionMeta,
        packet_rx: mpsc::Receiver<UdpPacket>,
        packet_tx: mpsc::Sender<UdpPacket>,
    );
}
