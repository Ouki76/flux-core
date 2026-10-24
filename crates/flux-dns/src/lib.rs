#![warn(missing_docs)]

//! A DNS client, server and cache.
//!
//! Supports UDP and TCP with EDNS(0), DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC,
//! plus a Fake-IP pool for transparent proxying. The wire format lives in [`wire`] and is
//! written defensively: every length, pointer and record count from a peer is validated
//! before it is used, because a resolver is directly reachable by whatever the network
//! sends it.
/// DNS over HTTPS.
pub mod doh;
/// DNS over QUIC.
pub mod doq;
/// DNS over TLS.
pub mod dot;
/// The Fake-IP pool used by transparent proxying.
pub mod fakeip;
/// Server selection, caching and the rule-based split.
pub mod resolver;
/// The DNS wire format: parsing, building and validating messages.
pub mod wire;

pub use doh::*;
pub use doq::*;
pub use dot::*;
pub use fakeip::*;
pub use resolver::*;
pub use wire::*;
