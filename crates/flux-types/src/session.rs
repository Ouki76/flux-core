use crate::address::TargetAddress;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

/// Whether a session carries a byte stream or datagrams.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkType {
    /// A byte stream: TCP, or anything that presents as one.
    Tcp,
    /// Datagrams: UDP, or a datagram-carrying tunnel.
    Udp,
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// Metadata describing a network session passing through the core.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    /// The peer that opened the connection.
    pub source: SocketAddr,
    /// Where the client asked to go — before any routing decision.
    pub destination: TargetAddress,
    /// Tag of the inbound that accepted it.
    pub inbound_tag: Arc<str>,
    /// Stream or datagram, which decides which dispatcher entry point is used.
    pub network: NetworkType,
    /// The authenticated user, when the inbound's protocol carries one.
    pub user: Option<String>,
}

impl SessionMeta {
    /// A session with no user attached. Inbounds that authenticate a user call
    /// [`SessionMeta::with_user`] afterwards.
    pub fn new(
        source: SocketAddr,
        destination: TargetAddress,
        inbound_tag: impl Into<Arc<str>>,
        network: NetworkType,
    ) -> Self {
        Self {
            source,
            destination,
            inbound_tag: inbound_tag.into(),
            network,
            user: None,
        }
    }

    /// Attaches the authenticated user name, for rules that match on it.
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
}

/// A UDP datagram with its routing endpoints.
#[derive(Clone, Debug)]
pub struct UdpPacket {
    /// Datagram bytes, shared rather than copied between the two halves of a relay.
    pub payload: Bytes,
    /// The address the datagram claims to come from.
    pub source: TargetAddress,
    /// Where it should go.
    pub destination: TargetAddress,
}

impl UdpPacket {
    /// A datagram with its routing endpoints.
    pub fn new(payload: Bytes, source: TargetAddress, destination: TargetAddress) -> Self {
        Self {
            payload,
            source,
            destination,
        }
    }
}
