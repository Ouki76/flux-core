use async_trait::async_trait;
use flux_types::{BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta};

/// /// Refuses every connection, at once and without dialling.
pub struct BlockOutbound {
    tag: String,
}

impl BlockOutbound {
    /// A blocked outbound named `tag`.
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "block"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        Err(FluxError::Blocked(format!(
            "traffic to {} blocked by outbound '{}'",
            meta.destination, self.tag
        )))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        Err(FluxError::Blocked(format!(
            "UDP traffic to {} blocked by outbound '{}'",
            meta.destination, self.tag
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::test_support::meta;

    /// A blocked destination must be refused on both transports, and the refusal
    /// must be the dedicated `Blocked` variant so a caller can tell a policy
    /// decision from a network failure (and, for example, answer the client with
    /// "connection refused" instead of "host unreachable") without parsing text.
    #[tokio::test]
    async fn tcp_is_refused_with_the_blocked_variant() {
        let block = BlockOutbound::new("block");
        let err = match block.dial_stream(&meta()).await {
            Err(e) => e,
            Ok(_) => panic!("a block outbound must never dial"),
        };
        assert!(matches!(err, FluxError::Blocked(_)), "{err:?}");
        assert!(
            err.to_string().contains("blocked"),
            "the message must say what happened: {err}"
        );
    }

    #[tokio::test]
    async fn udp_is_refused_with_the_blocked_variant() {
        let block = BlockOutbound::new("block");
        let err = match block.dial_packet(&meta()).await {
            Err(e) => e,
            Ok(_) => panic!("a block outbound must never dial"),
        };
        assert!(matches!(err, FluxError::Blocked(_)), "{err:?}");
    }

    /// The refusal names the destination and the outbound, which is what makes
    /// a "blocked" line in the log actionable.
    #[tokio::test]
    async fn the_refusal_names_the_destination_and_the_tag() {
        let block = BlockOutbound::new("my-block");
        let err = match block.dial_stream(&meta()).await {
            Err(e) => e,
            Ok(_) => panic!("a block outbound must never dial"),
        };
        let text = err.to_string();
        assert!(text.contains("example.com:443"), "{text}");
        assert!(text.contains("my-block"), "{text}");
        assert_eq!(block.protocol(), "block");
        assert!(!block.is_group());
    }
}
