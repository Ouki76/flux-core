use crate::error::{FluxError, FluxResult};
use crate::session::{SessionMeta, UdpPacket};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// A bidirectional stream of bytes with downcasting capabilities.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// The concrete stream behind the trait object, for the places that need to ask
    /// a transport layer what it is (splice eligibility, for instance).
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> AsyncStream for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// An erased stream, as it travels between the inbound, the dispatcher and the
/// outbound.
pub type BoxedStream = Box<dyn AsyncStream>;

/// Composable stream dialer establishing carrier, security, and transport framing layers.
#[async_trait]
pub trait StreamDialer: Send + Sync {
    /// Establishes one stream, with every configured layer already applied.
    async fn dial(&self) -> FluxResult<BoxedStream>;
}

/// A UDP packet endpoint representing an outbound association.
#[async_trait]
pub trait PacketEndpoint: Send + Sync {
    /// Sends one datagram over the association.
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()>;
    /// Waits for the next datagram on the association.
    async fn recv_packet(&self) -> FluxResult<UdpPacket>;
}

/// Inbound adapter listening for client connections or packets.
#[async_trait]
pub trait Inbound: Send + Sync {
    /// The tag this inbound was configured with; routing rules match on it.
    fn tag(&self) -> &str;
    /// The protocol name, for logs and diagnostics.
    fn protocol(&self) -> &'static str {
        "inbound"
    }
    /// Where this inbound listens, for logs. `None` for inbounds that do not bind a
    /// socket (a transparent interceptor using an inherited descriptor, for example).
    fn listen_addr(&self) -> Option<String> {
        None
    }
    /// Binds and begins accepting. Returns once the listener is up, not when it stops.
    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()>;

    /// Stops listening and releases the listening socket.
    ///
    /// The contract is *synchronous release*, not "a shutdown was requested":
    /// when this future resolves, the listener file descriptor must be closed
    /// and the port bindable again. An implementation that only signals a
    /// cancellation channel and returns leaves the socket owned by a task that
    /// may not have been polled yet, and a caller that rebinds the same port
    /// immediately (`Instance::stop()` followed by `start()`, a SIGHUP reload
    /// script, a supervisor restart) then races `EADDRINUSE`.
    ///
    /// Implementations therefore join the task(s) that own the listener — see
    /// `flux_inbound::InboundTasks` — rather than dropping the handle. Two
    /// calls in a row must both succeed, and `stop()` on a never-started
    /// inbound must be a no-op that returns `Ok`.
    async fn stop(&self) -> FluxResult<()>;
}

/// Outbound adapter routing connections to their ultimate destination.
#[async_trait]
pub trait Outbound: Send + Sync {
    /// The outbound's configured tag; routing refers to it by this name.
    fn tag(&self) -> &str;
    /// The protocol name, for logs and diagnostics.
    fn protocol(&self) -> &'static str {
        "outbound"
    }
    /// Opens a stream to the session's destination through this outbound.
    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream>;
    /// Opens a datagram association to the session's destination.
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
    /// Looks an outbound up by its configured tag.
    fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>>;
}

/// Core dispatcher routing traffic from Inbounds to appropriate Outbounds.
#[async_trait]
pub trait Dispatcher: Send + Sync {
    /// Routes a stream: picks an outbound, dials it, and relays until either side
    /// closes. This is the entry point every stream inbound calls.
    async fn dispatch_stream(&self, meta: SessionMeta, inbound_stream: BoxedStream);
    /// Dials the outbound a route selects, without relaying — for callers that need
    /// the stream for something other than a straight copy.
    async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<BoxedStream>;
    /// Relays between two already-established streams.
    async fn bridge_streams(
        &self,
        meta: SessionMeta,
        inbound_stream: BoxedStream,
        outbound_stream: BoxedStream,
    );
    /// Routes a datagram association, relaying until the channel closes.
    async fn dispatch_packet(
        &self,
        meta: SessionMeta,
        packet_rx: mpsc::Receiver<UdpPacket>,
        packet_tx: mpsc::Sender<UdpPacket>,
    );
}
