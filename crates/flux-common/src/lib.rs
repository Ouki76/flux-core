#![warn(missing_docs)]

//! Building blocks shared by every crate: buffer pools, the relay loop, socket
//! options, obfuscation and the Linux splice path.
//!
//! Nothing here knows about protocols; it is the machinery the protocol crates run on.

/// Reusable buffer pools for the datapath.
pub mod buffer;
/// Relaying between two streams.
pub mod copy;
/// Ciphers and key derivation.
pub mod crypto;
/// Traffic obfuscation (Salamander and friends).
pub mod obfs;
/// Socket options applied to every listener and connection.
pub mod socket;
/// Zero-copy relaying on Linux, when both ends are bare sockets.
pub mod splice;

pub use buffer::*;
pub use copy::*;
pub use crypto::*;
pub use obfs::*;
pub use socket::*;
pub use splice::*;
pub mod ratelimit;

pub use ratelimit::*;
