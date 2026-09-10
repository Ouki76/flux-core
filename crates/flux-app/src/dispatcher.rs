use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use async_trait::async_trait;
use flux_types::{
    BoxedStream, Dispatcher, Outbound, OutboundLookup, PacketEndpoint, SessionMeta, UdpPacket,
};
use flux_router::Router;
use flux_common::copy::copy_bidirectional;

pub struct DefaultDispatcher {
    router: Arc<Router>,
    outbounds: Arc<dyn OutboundLookup>,
}

impl DefaultDispatcher {
    pub fn new(
        router: Arc<Router>,
        outbounds: Arc<dyn OutboundLookup>,
    ) -> Self {
        Self { router, outbounds }
    }

    fn get_outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag)
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dispatch_stream(&self, meta: SessionMeta, inbound_stream: BoxedStream) {
        let outbound_tag = self.router.route(&meta);
        debug!(
            "[{}] Routing stream {} -> {} via [{}]",
            meta.inbound_tag, meta.source, meta.destination, outbound_tag
        );

        let outbound = match self.get_outbound(outbound_tag) {
            Some(o) => o,
            None => {
                error!("outbound '{}' not found for stream", outbound_tag);
                return;
            }
        };

        match outbound.dial_stream(&meta).await {
            Ok(outbound_stream) => {
                tokio::spawn(async move {
                    match copy_bidirectional(inbound_stream, outbound_stream).await {
                        Ok((up, down)) => {
                            debug!(
                                "stream closed gracefully: upload={} B, download={} B",
                                up, down
                            );
                        }
                        Err(e) => {
                            debug!("stream copy terminated: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                warn!("failed to dial outbound [{}]: {}", outbound_tag, e);
            }
        }
    }

    async fn dispatch_packet(
        &self,
        meta: SessionMeta,
        mut packet_rx: mpsc::Receiver<UdpPacket>,
        packet_tx: mpsc::Sender<UdpPacket>,
    ) {
        let outbound_tag = self.router.route(&meta);
        debug!(
            "[{}] Routing UDP {} -> {} via [{}]",
            meta.inbound_tag, meta.source, meta.destination, outbound_tag
        );

        let outbound = match self.get_outbound(outbound_tag) {
            Some(o) => o,
            None => {
                error!("outbound '{}' not found for UDP", outbound_tag);
                return;
            }
        };

        let endpoint: Arc<dyn PacketEndpoint> = match outbound.dial_packet(&meta).await {
            Ok(ep) => Arc::from(ep),
            Err(e) => {
                warn!("failed to dial UDP endpoint [{}]: {}", outbound_tag, e);
                return;
            }
        };

        let ep_send = endpoint.clone();
        let forward_task = tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                if let Err(e) = ep_send.send_packet(packet).await {
                    debug!("failed to forward UDP packet: {}", e);
                    break;
                }
            }
        });

        let ep_recv = endpoint.clone();
        let reply_task = tokio::spawn(async move {
            loop {
                match ep_recv.recv_packet().await {
                    Ok(packet) => {
                        if packet_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("failed to receive UDP reply: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::select! {
            _ = forward_task => {},
            _ = reply_task => {},
        }
    }
}
