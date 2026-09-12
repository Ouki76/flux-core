use std::sync::Arc;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use crate::error::{FluxError, FluxResult};
use crate::session::{SessionMeta, UdpPacket};

/// A bidirectional stream of bytes.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

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
    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()>;
    async fn stop(&self) -> FluxResult<()>;
}

/// Outbound adapter routing connections to their ultimate destination.
#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream>;
    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>>;

    /// Whether this outbound is a group (Selector, UrlTest, etc.)
    fn is_group(&self) -> bool {
        false
    }

    /// Group type string for Clash API compatibility ("Selector", "URLTest", etc.)
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
    async fn bridge_streams(&self, meta: SessionMeta, inbound_stream: BoxedStream, outbound_stream: BoxedStream);
    async fn dispatch_packet(
        &self,
        meta: SessionMeta,
        packet_rx: mpsc::Receiver<UdpPacket>,
        packet_tx: mpsc::Sender<UdpPacket>,
    );
}
