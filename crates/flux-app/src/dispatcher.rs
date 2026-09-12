use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use async_trait::async_trait;
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint,
    SessionMeta, UdpPacket,
};
use flux_router::Router;
use flux_common::copy::copy_bidirectional;
use crate::api::TrafficMeter;

pub struct DefaultDispatcher {
    router: Arc<Router>,
    outbounds: Arc<dyn OutboundLookup>,
    meter: Option<Arc<TrafficMeter>>,
}

impl DefaultDispatcher {
    pub fn new(
        router: Arc<Router>,
        outbounds: Arc<dyn OutboundLookup>,
    ) -> Self {
        Self {
            router,
            outbounds,
            meter: None,
        }
    }

    pub fn with_meter(mut self, meter: Arc<TrafficMeter>) -> Self {
        self.meter = Some(meter);
        self
    }

    fn get_outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag)
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let outbound_tag = self.router.route(meta);
        debug!(
            "[{}] Routing stream {} -> {} via [{}]",
            meta.inbound_tag, meta.source, meta.destination, outbound_tag
        );

        let outbound = self.get_outbound(outbound_tag).ok_or_else(|| {
            FluxError::OutboundNotFound(format!("outbound '{}' not found", outbound_tag))
        })?;

        outbound.dial_stream(meta).await
    }

    async fn bridge_streams(&self, _meta: SessionMeta, inbound_stream: BoxedStream, outbound_stream: BoxedStream) {
        let meter = self.meter.clone();
        tokio::spawn(async move {
            match copy_bidirectional(inbound_stream, outbound_stream).await {
                Ok((up, down)) => {
                    if let Some(m) = meter {
                        m.record_traffic(up, down);
                    }
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

    async fn dispatch_stream(&self, meta: SessionMeta, inbound_stream: BoxedStream) {
        match self.dial_outbound(&meta).await {
            Ok(outbound_stream) => {
                self.bridge_streams(meta, inbound_stream, outbound_stream).await;
            }
            Err(e) => {
                warn!("failed to dial outbound for stream {}: {}", meta.destination, e);
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
        let meter_send = self.meter.clone();
        let forward_task = tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                let bytes_len = packet.payload.len() as u64;
                if let Err(e) = ep_send.send_packet(packet).await {
                    debug!("failed to forward UDP packet: {}", e);
                    break;
                }
                if let Some(m) = &meter_send {
                    m.record_traffic(bytes_len, 0);
                }
            }
        });

        let ep_recv = endpoint.clone();
        let meter_recv = self.meter.clone();
        let reply_task = tokio::spawn(async move {
            loop {
                match ep_recv.recv_packet().await {
                    Ok(packet) => {
                        let bytes_len = packet.payload.len() as u64;
                        if packet_tx.send(packet).await.is_err() {
                            break;
                        }
                        if let Some(m) = &meter_recv {
                            m.record_traffic(0, bytes_len);
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
