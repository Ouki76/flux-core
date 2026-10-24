#![warn(missing_docs)]

//! Routing: rules in, outbound tags out.
//!
//! A [`Rule`] is a conjunction of conditions — inbound, network, domain,
//! CIDR, port, rule set, GeoIP country, process name — optionally inverted, and the
//! router returns the tag of the first rule that matches, or the default outbound.
//! Matching is order-sensitive and rules are evaluated in configuration order.
//!
//! Nothing here performs I/O: the GeoIP and rule-set data are loaded into registries by
//! the caller, and a rule that needs a registry it was not given *fails to match* rather
//! than matching everything.

/// Country lookup against a MaxMind database.
pub mod geoip;
/// A large set of IP ranges, stored compactly.
pub mod ip_range;
/// Attributing a connection to a process, where the platform allows it.
pub mod process;
/// The rule list and the decision it produces.
pub mod router;
/// A single routing rule and its matchers.
pub mod rule;
/// External rule sets (sing-box `.srs` / plain text).
pub mod ruleset;

pub use geoip::*;
pub use ip_range::*;
pub use process::*;
pub use router::*;
pub use rule::*;
pub use ruleset::*;
