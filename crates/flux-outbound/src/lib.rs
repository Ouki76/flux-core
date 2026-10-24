#![warn(missing_docs)]

//! Outbounds: everything that dials out.
//!
//! One module per protocol, plus the group types (selector, urltest, fallback,
//! load-balance) that pick between other outbounds, and `dialer`, which applies a
//! [`pipeline`](flux_transport::pipeline) to whatever the protocol needs. They all
//! implement the same `Outbound` trait; the group types implement it too, which is what
//! makes a group usable anywhere a single outbound is.

/// Refuses every connection; a routing target for blocked traffic.
pub mod block;
/// The dialer that applies a transport pipeline to an outbound.
pub mod dialer;
/// Connects straight to the destination.
pub mod direct;
/// Tries candidates in order and falls back on failure.
pub mod fallback;
/// An HTTP CONNECT client.
pub mod http;
/// Hysteria 2 over QUIC.
pub mod hysteria2;
/// Spreads connections across several outbounds.
pub mod loadbalance;
/// Latency and reachability probes.
pub mod probe;
/// One outbound chosen by hand or by API.
pub mod selector;
/// Shadowsocks.
pub mod shadowsocks;
/// A SOCKS5 client.
pub mod socks;
/// Trojan.
pub mod trojan;
/// TUIC v5 over QUIC.
pub mod tuic;
/// Picks the fastest outbound by measuring a URL.
pub mod urltest;
/// VLESS.
pub mod vless;
/// VMess.
pub mod vmess;
/// WireGuard and AmneziaWG.
pub mod wireguard;

pub use block::*;
pub use dialer::*;
pub use direct::*;
pub use fallback::*;
pub use http::*;
pub use hysteria2::*;
pub use loadbalance::*;
pub use probe::*;
pub use selector::*;
pub use shadowsocks::*;
pub use socks::*;
pub use trojan::*;
pub use tuic::*;
pub use urltest::*;
pub use vless::*;
pub use vmess::*;
pub use wireguard::*;
