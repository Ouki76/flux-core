use thiserror::Error;

#[derive(Error, Debug)]
pub enum FluxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Protocol error ({protocol}): {message}")]
    Protocol {
        protocol: &'static str,
        message: String,
    },

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Connection refused or blocked: {0}")]
    Blocked(String),

    #[error("Routing error: {0}")]
    Routing(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("TLS / Crypto error: {0}")]
    Crypto(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Outbound not found: {0}")]
    OutboundNotFound(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type FluxResult<T> = Result<T, FluxError>;
