#![warn(missing_docs)]

//! The protocols themselves: what the bytes on the wire mean.
//!
//! Every module here is a stream or datagram protocol, written as a wrapper rather than as
//! a connection type, so a protocol can sit on any transport the `flux-transport` crate
//! offers. Each exposes a `*Protocol` namespace for handshakes and the stream type that
//! carries the data afterwards.
//!
//! The parsers are written against hostile input: every length, address and frame count is
//! validated before use, and `tests/test_fuzz_parsers.rs` drives each of them with random
//! bytes to keep it that way.

/// Plain HTTP proxying.
pub mod http;
/// Hysteria 2 over QUIC.
pub mod hysteria2;
/// smux multiplexing, so several streams share one connection.
pub mod mux;
/// Shadowsocks AEAD.
pub mod shadowsocks;
/// Shadowsocks 2022, with its own framing and replay protection.
pub mod shadowsocks2022;
/// SOCKS5, the client-facing protocol.
pub mod socks5;
/// Trojan: a password over TLS.
pub mod trojan;
/// TUIC v5 over QUIC.
pub mod tuic;
/// Datagram framing shared by the UDP-carrying protocols.
pub mod udp;
/// XTLS Vision traffic shaping.
pub mod vision;
/// VLESS, including the REALITY and Vision flows.
pub mod vless;
/// Post-quantum VLESS Encryption (`mlkem768x25519plus`).
pub mod vless_encryption;
/// VMess, with AEAD headers.
pub mod vmess;
/// WireGuard and AmneziaWG.
pub mod wireguard;

pub use http::*;
pub use hysteria2::*;
pub use mux::*;
pub use shadowsocks::*;
pub use shadowsocks2022::*;
pub use socks5::*;
pub use trojan::*;
pub use tuic::*;
pub use udp::*;
pub use vision::*;
pub use vless::*;
pub use vmess::*;
pub use wireguard::*;
