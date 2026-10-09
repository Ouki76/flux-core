use crate::api::TrafficMeter;
use async_trait::async_trait;
use dashmap::DashMap;
use flux_common::copy::copy_bidirectional;
use flux_router::Router;
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint,
    SessionMeta, UdpPacket,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

struct ActiveConnectionGuard {
    conn_id: Option<String>,
    meter: Option<Arc<TrafficMeter>>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        if let (Some(id), Some(meter)) = (self.conn_id.take(), self.meter.take()) {
            meter.remove_connection(&id);
        }
    }
}

pub struct DefaultDispatcher {
    router: Arc<Router>,
    outbounds: Arc<dyn OutboundLookup>,
    meter: Option<Arc<TrafficMeter>>,
    resolver: Option<Arc<flux_dns::DnsResolver>>,
}

impl DefaultDispatcher {
    pub fn new(router: Arc<Router>, outbounds: Arc<dyn OutboundLookup>) -> Self {
        Self {
            router,
            outbounds,
            meter: None,
            resolver: None,
        }
    }

    pub fn with_meter(mut self, meter: Arc<TrafficMeter>) -> Self {
        self.meter = Some(meter);
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<flux_dns::DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    fn resolve_effective_meta(&self, meta: &SessionMeta) -> SessionMeta {
        if let flux_types::TargetAddress::Ip(sock) = &meta.destination
            && let Some(r) = &self.resolver
            && let Some(fakeip) = r.fake_ip()
            && let Some(domain) = fakeip.lookup_domain(&sock.ip())
        {
            let mut m = meta.clone();
            m.destination = flux_types::TargetAddress::Domain(domain, sock.port());
            return m;
        }
        meta.clone()
    }

    fn get_outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag)
    }
}

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let effective_meta = self.resolve_effective_meta(meta);
        let outbound_tag = self.router.route(&effective_meta);
        debug!(
            "[{}] Routing stream {} -> {} (orig: {}) via [{}]",
            meta.inbound_tag,
            meta.source,
            effective_meta.destination,
            meta.destination,
            outbound_tag
        );

        let outbound = self.get_outbound(outbound_tag).ok_or_else(|| {
            FluxError::OutboundNotFound(format!("outbound '{}' not found", outbound_tag))
        })?;

        outbound.dial_stream(&effective_meta).await
    }

    async fn bridge_streams(
        &self,
        meta: SessionMeta,
        inbound_stream: BoxedStream,
        outbound_stream: BoxedStream,
    ) {
        let meter = self.meter.clone();
        tokio::spawn(async move {
            let (_guard, conn, mut cancel_rx) = if let Some(ref m) = meter {
                let (id, conn, rx) = m.register_connection(&meta);
                (
                    ActiveConnectionGuard {
                        conn_id: Some(id),
                        meter: Some(m.clone()),
                    },
                    Some(conn),
                    Some(rx),
                )
            } else {
                (
                    ActiveConnectionGuard {
                        conn_id: None,
                        meter: None,
                    },
                    None,
                    None,
                )
            };

            #[cfg(target_os = "linux")]
            if let (Some(tcp_in), Some(tcp_out)) = (
                inbound_stream
                    .as_any()
                    .downcast_ref::<tokio::net::TcpStream>(),
                outbound_stream
                    .as_any()
                    .downcast_ref::<tokio::net::TcpStream>(),
            ) {
                let up_counter = conn.as_ref().map(|c| c.upload.clone());
                let down_counter = conn.as_ref().map(|c| c.download.clone());
                let global_up = meter.as_ref().map(|m| m.upload_total.clone());
                let global_down = meter.as_ref().map(|m| m.download_total.clone());

                let copy_fut = flux_common::copy_bidirectional_zero_copy_metered(
                    tcp_in,
                    tcp_out,
                    up_counter.as_deref(),
                    global_up.as_deref(),
                    down_counter.as_deref(),
                    global_down.as_deref(),
                );
                let result = if let (Some(c), Some(rx)) = (&conn, &mut cancel_rx) {
                    tokio::select! {
                        res = copy_fut => res,
                        _ = rx.recv() => {
                            debug!("connection {} cancelled via API", c.id);
                            Ok((0, 0))
                        }
                    }
                } else {
                    copy_fut.await
                };

                let (up, down) = match result {
                    Ok((u, d)) => (u, d),
                    Err(e) => {
                        debug!("zero-copy splice stream ended with error: {}", e);
                        let up_cnt = conn
                            .as_ref()
                            .map(|c| c.upload.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        let down_cnt = conn
                            .as_ref()
                            .map(|c| c.download.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        (up_cnt, down_cnt)
                    }
                };

                debug!(
                    "zero-copy splice stream closed: upload={} B, download={} B",
                    up, down
                );
                return;
            }

            let (inbound_stream, outbound_stream): (BoxedStream, BoxedStream) = if let Some(ref c) =
                conn
            {
                let mut metered = flux_common::copy::MeteredStream::new(
                    inbound_stream,
                    c.upload.clone(),
                    c.download.clone(),
                );
                if let Some(ref m) = meter {
                    metered = metered.with_global(m.upload_total.clone(), m.download_total.clone());
                }
                (Box::new(metered), outbound_stream)
            } else if let Some(ref m) = meter {
                let dummy_up = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let dummy_down = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let metered =
                    flux_common::copy::MeteredStream::new(inbound_stream, dummy_up, dummy_down)
                        .with_global(m.upload_total.clone(), m.download_total.clone());
                (Box::new(metered), outbound_stream)
            } else {
                (inbound_stream, outbound_stream)
            };

            let copy_fut = copy_bidirectional(inbound_stream, outbound_stream);
            let _ = if let (Some(c), Some(rx)) = (&conn, &mut cancel_rx) {
                tokio::select! {
                    res = copy_fut => res,
                    _ = rx.recv() => {
                        debug!("connection {} cancelled via API", c.id);
                        Ok((0, 0))
                    }
                }
            } else {
                copy_fut.await
            };

            let (up, down) = if let Some(ref c) = conn {
                (
                    c.upload.load(std::sync::atomic::Ordering::Relaxed),
                    c.download.load(std::sync::atomic::Ordering::Relaxed),
                )
            } else {
                (0, 0)
            };

            debug!(
                "stream closed gracefully: upload={} B, download={} B",
                up, down
            );
        });
    }

    async fn dispatch_stream(&self, meta: SessionMeta, inbound_stream: BoxedStream) {
        match self.dial_outbound(&meta).await {
            Ok(outbound_stream) => {
                self.bridge_streams(meta, inbound_stream, outbound_stream)
                    .await;
            }
            Err(e) => {
                warn!(
                    "failed to dial outbound for stream {}: {}",
                    meta.destination, e
                );
            }
        }
    }

    async fn dispatch_packet(
        &self,
        meta: SessionMeta,
        mut packet_rx: mpsc::Receiver<UdpPacket>,
        packet_tx: mpsc::Sender<UdpPacket>,
    ) {
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let endpoints: DashMap<String, Arc<dyn PacketEndpoint>> = DashMap::new();
        let meter = self.meter.clone();

        while let Some(packet) = packet_rx.recv().await {
            let bytes_len = packet.payload.len() as u64;

            // Dynamically resolve target outbound for THIS specific packet
            let mut pkt_meta = meta.clone();
            pkt_meta.destination = packet.destination.clone();
            let effective_meta = self.resolve_effective_meta(&pkt_meta);
            let outbound_tag = self.router.route(&effective_meta);

            // Get or create outbound endpoint
            let endpoint = if let Some(ep) = endpoints.get(outbound_tag) {
                ep.clone()
            } else {
                let outbound = match self.get_outbound(outbound_tag) {
                    Some(o) => o,
                    None => {
                        error!(
                            "outbound '{}' not found for UDP destination {}",
                            outbound_tag, effective_meta.destination
                        );
                        continue;
                    }
                };

                let ep: Arc<dyn PacketEndpoint> = match outbound.dial_packet(&effective_meta).await
                {
                    Ok(ep) => Arc::from(ep),
                    Err(e) => {
                        warn!(
                            "failed to dial UDP endpoint [{}] for {}: {}",
                            outbound_tag, effective_meta.destination, e
                        );
                        continue;
                    }
                };

                // Spawn reply listener for this endpoint that forwards packets back to packet_tx
                let ep_recv = ep.clone();
                let reply_tx = packet_tx.clone();
                let meter_recv = meter.clone();
                let token = cancel_token.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            res = ep_recv.recv_packet() => match res {
                                Ok(reply) => {
                                    let r_len = reply.payload.len() as u64;
                                    if reply_tx.send(reply).await.is_err() {
                                        break;
                                    }
                                    if let Some(m) = &meter_recv {
                                        m.record_traffic(0, r_len);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                });

                endpoints.insert(outbound_tag.to_string(), ep.clone());
                ep
            };

            if let Err(e) = endpoint.send_packet(packet).await {
                debug!("failed to forward UDP packet: {}", e);
            } else if let Some(m) = &meter {
                m.record_traffic(bytes_len, 0);
            }
        }

        cancel_token.cancel();
    }
}
