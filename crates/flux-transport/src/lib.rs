#![warn(missing_docs)]

//! Transports: the layers between a proxy and a peer.
//!
//! Each module is one way to carry bytes — a carrier (TCP, UDP, QUIC), a security layer
//! (TLS, REALITY, ShadowTLS) or a framing layer (WebSocket, gRPC, HTTPUpgrade, mKCP).
//! [`pipeline`] composes them into a single dial, which is why every transport is
//! expressed as a stream wrapper rather than as its own connection type.

/// Fills a caller-sized buffer from a stream that hands out one unit per call.
pub mod coalesce;
/// TLS fingerprint profiles: cipher order and key-exchange groups per browser.
pub mod fingerprint;
/// TLS ClientHello fragmentation, to defeat naive SNI inspection.
pub mod fragment;
/// gRPC as a transport, over HTTP/2.
pub mod grpc;
/// HTTP/2 helpers shared by the gRPC transport and the h2 framing layer.
pub mod h2;
/// A minimal HTTP/3 layer, for QUIC-based transports.
pub mod h3_lite;
/// HTTPUpgrade, the lightweight WebSocket alternative.
pub mod httpupgrade;
/// mKCP: reliable streams over UDP, wire-compatible with Xray.
pub mod kcp;
/// Composing carrier, security and framing into one dial.
pub mod pipeline;
/// QUIC, for Hysteria 2 and TUIC.
pub mod quic;
/// QUIC traffic obfuscation.
pub mod quic_obfs;
/// REALITY: TLS that cannot be attributed to this server.
pub mod reality;

/// ShadowTLS: a TLS handshake forwarded to a real site, then hijacked.
pub mod shadowtls;
/// The TCP carrier.
pub mod tcp;
/// TLS with configurable fingerprints and an optional private CA.
pub mod tls;
mod tls13;
/// WebSocket framing.
pub mod websocket;
/// XHTTP (`splithttp`), stream-one mode.
pub mod xhttp;

pub use fingerprint::*;
pub use fragment::*;
pub use grpc::*;
pub use h2::*;
pub use kcp::{KcpConfig, KcpObfs, KcpStats, KcpStream, accept, connect};
pub use pipeline::*;
pub use quic::*;
pub use reality::*;
pub use shadowtls::*;
pub use tcp::*;
pub use tls::*;
