use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use crate::address::TargetAddress;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkType {
    Tcp,
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
    pub source: SocketAddr,
    pub destination: TargetAddress,
    pub inbound_tag: Arc<str>,
    pub network: NetworkType,
    pub user: Option<String>,
}

impl SessionMeta {
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

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
}

/// A UDP datagram with its routing endpoints.
#[derive(Clone, Debug)]
pub struct UdpPacket {
    pub payload: Bytes,
    pub source: TargetAddress,
    pub destination: TargetAddress,
}

impl UdpPacket {
    pub fn new(payload: Bytes, source: TargetAddress, destination: TargetAddress) -> Self {
        Self {
            payload,
            source,
            destination,
        }
    }
}
