#![warn(missing_docs)]

//! The application: configuration, the running instance, and the API.
//!
//! This is where the pieces are assembled — a configuration is parsed and validated, an
//! [`Instance`] builds the inbounds, outbounds and router from it, and the dispatcher
//! joins them. Configuration validation is deliberately strict: an unknown key is an
//! error naming the key, because a silently ignored option is a configuration that lies
//! about what the proxy does.

/// The local management API: connection table, traffic counters, selectors.
pub mod api;
/// Configuration: schema, parsing and validation.
pub mod config;
/// Joins inbounds to outbounds: routing, relaying, UDP associations.
pub mod dispatcher;
/// A running proxy: builds everything from a configuration and starts it.
pub mod instance;
pub mod ruleset_fetch;
/// Proxy URIs (`vless://…`), for import and export.
pub mod uri;

pub use api::*;
pub use config::*;
pub use dispatcher::*;
pub use instance::*;
pub use uri::*;
