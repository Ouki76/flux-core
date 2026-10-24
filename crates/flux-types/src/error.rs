use thiserror::Error;

/// Every error this workspace returns.
///
/// Variants are deliberately coarse: they say *which layer* failed and the message
/// carries the detail, so a log line is actionable without a stack trace. A caller
/// that must branch on a cause matches the variant; everything else formats it.
#[derive(Error, Debug)]
pub enum FluxError {
    /// The operating system refused or broke an operation: a socket, a file, a device.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A target or listen address could not be parsed.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// A peer violated the protocol it is speaking. `protocol` names the layer, so a
    /// log line is attributable without a stack trace.
    #[error("Protocol error ({protocol}): {message}")]
    Protocol {
        /// The layer that rejected the input, e.g. `"vless"` or `"hysteria2"`.
        protocol: &'static str,
        /// What was wrong, in enough detail for an operator to act on.
        message: String,
    },

    /// Credentials were not accepted: a bad UUID, password, key or certificate.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// One failure cause; the `#[error]` text is what a log shows.
    #[error("Connection refused or blocked: {0}")]
    Blocked(String),

    /// Routing could not produce a decision — no matching rule, a missing outbound tag.
    #[error("Routing error: {0}")]
    Routing(String),

    /// Name resolution failed.
    #[error("DNS error: {0}")]
    Dns(String),

    /// One failure cause; the `#[error]` text is what a log shows.
    #[error("TLS / Crypto error: {0}")]
    Crypto(String),

    /// The configuration is invalid. Always a startup-time failure, never per-connection.
    #[error("Configuration error: {0}")]
    Config(String),

    /// A route named an outbound tag that does not exist.
    #[error("Outbound not found: {0}")]
    OutboundNotFound(String),

    /// One failure cause; the `#[error]` text is what a log shows.
    #[error("Timeout error: {0}")]
    Timeout(String),

    /// An invariant this workspace relies on was broken. Always a bug.
    #[error("Internal error: {0}")]
    Internal(String),

    /// The network layer could not reach or sustain the peer.
    #[error("Network error: {0}")]
    Network(String),
}

/// The result type every fallible function in this workspace returns.
pub type FluxResult<T> = Result<T, FluxError>;
