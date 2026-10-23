use crate::api::TrafficMeter;
use async_trait::async_trait;
use flux_router::Router;
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Outbound, OutboundLookup, PacketEndpoint,
    SessionMeta, UdpPacket,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
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

/// Cache key for UDP packet endpoints.
///
/// The destination is `Some` only for outbounds whose UDP association is bound to
/// a single destination (see `Outbound::udp_endpoint_per_destination`).
type EndpointKey = (Arc<str>, Option<flux_types::TargetAddress>);

/// One cached packet endpoint plus the stop handle of the reply pump that reads
/// from it.
///
/// The reply pump is a detached task holding its own `Arc<dyn PacketEndpoint>`,
/// so dropping a cache entry stopped nothing by itself: an evicted, replaced or
/// failed endpoint kept its socket, its task and its `packet_tx` clone alive
/// until the whole association ended. `MAX_ENDPOINTS_PER_TAG` therefore bounded
/// the map but not the resources behind it — a client walking N destinations on
/// a per-destination outbound (VMess) leaked N sockets and N tasks, and no code
/// path could ever reclaim them. Cancelling on drop ties the pump's lifetime to
/// the entry's on *every* removal path (eviction, replacement, send error, dead
/// read loop, association teardown).
struct CachedEndpoint {
    endpoint: Arc<dyn PacketEndpoint>,
    stop: CancellationToken,
}

impl Drop for CachedEndpoint {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Endpoints for one outbound tag.
///
/// Protocols that carry the destination inside every datagram share a single
/// endpoint; protocols that bind one association per destination (VMess) get a
/// nested map. Storing it this way means the lookup path never has to rebuild the
/// cache key — and therefore never has to clone the (possibly reverse-mapped)
/// effective destination just to find the entry.
enum EndpointSlot {
    Shared(CachedEndpoint),
    PerDestination(std::collections::HashMap<flux_types::TargetAddress, CachedEndpoint>),
}

impl EndpointSlot {
    fn get(
        &self,
        dest: &flux_types::TargetAddress,
        per_destination: bool,
    ) -> Option<Arc<dyn PacketEndpoint>> {
        match (self, per_destination) {
            (EndpointSlot::Shared(ep), false) => Some(ep.endpoint.clone()),
            (EndpointSlot::PerDestination(map), true) => map.get(dest).map(|c| c.endpoint.clone()),
            _ => None,
        }
    }
}

/// Forgets one cached association: `Some(dest)` for a per-destination slot,
/// `None` for a slot that serves every destination with one endpoint.
///
/// Dropping the entry is what stops its reply pump — see [`CachedEndpoint`].
fn drop_cached_endpoint(
    endpoints: &mut std::collections::HashMap<Arc<str>, EndpointSlot>,
    tag: &str,
    dest: Option<&flux_types::TargetAddress>,
) {
    match dest {
        None => {
            endpoints.remove(tag);
        }
        Some(dest) => {
            if let Some(EndpointSlot::PerDestination(map)) = endpoints.get_mut(tag) {
                map.remove(dest);
            }
        }
    }
}

/// Removes the cache entry that holds `failed`, if there is one.
///
/// Identification is by pointer identity rather than by route-cache key: a send
/// error is rare, while the successful-send path must not clone a destination
/// per datagram. A `PerDestination` slot left empty is not removed — it is a
/// handle to a `HashMap` header, and the next datagram re-dials straight into it.
fn drop_failed_endpoint(
    endpoints: &mut std::collections::HashMap<Arc<str>, EndpointSlot>,
    failed: &Arc<dyn PacketEndpoint>,
) {
    endpoints.retain(|_, slot| match slot {
        EndpointSlot::Shared(cached) => !Arc::ptr_eq(&cached.endpoint, failed),
        EndpointSlot::PerDestination(map) => {
            map.retain(|_, cached| !Arc::ptr_eq(&cached.endpoint, failed));
            true
        }
    });
}

/// Upper bound on nested per-destination endpoints for one outbound tag.
const MAX_ENDPOINTS_PER_TAG: usize = 256;

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

    /// Returns the effective session metadata after Fake-IP reverse mapping.
    /// Borrows the original metadata when no remapping applies, avoiding a clone.
    fn resolve_effective_meta<'m>(
        &self,
        meta: &'m SessionMeta,
    ) -> std::borrow::Cow<'m, SessionMeta> {
        if let flux_types::TargetAddress::Ip(sock) = &meta.destination
            && let Some(r) = &self.resolver
            && let Some(fakeip) = r.fake_ip()
            && let Some(domain) = fakeip.lookup_domain(&sock.ip())
        {
            let mut m = meta.clone();
            m.destination = flux_types::TargetAddress::Domain(domain, sock.port());
            return std::borrow::Cow::Owned(m);
        }
        std::borrow::Cow::Borrowed(meta)
    }

    /// Metadata to *route* with, which may differ from the metadata to *dial* with.
    ///
    /// A rule that decides on the destination's address (`ip_cidr`, `geoip`, or a
    /// rule set containing CIDRs) can only fire for a domain if the name is
    /// resolved first. Competitors resolve by default and let a rule opt out with
    /// `no-resolve`; here the router is synchronous and has no resolver, so the
    /// dispatcher asks whether any rule needs an address and resolves for the
    /// routing decision only — the dial keeps the domain, so the outbound still
    /// does its own resolution and SNI as before.
    ///
    /// A resolution failure is never fatal: routing falls back to the domain, which
    /// is exactly the behaviour that existed before this was added.
    async fn route_meta<'m>(
        &self,
        meta: &'m flux_types::SessionMeta,
    ) -> std::borrow::Cow<'m, flux_types::SessionMeta> {
        use flux_types::TargetAddress;
        if !matches!(meta.destination, TargetAddress::Domain(..)) {
            return std::borrow::Cow::Borrowed(meta);
        }
        if !self.router.needs_resolved_destination() {
            return std::borrow::Cow::Borrowed(meta);
        }
        let Some(resolver) = &self.resolver else {
            return std::borrow::Cow::Borrowed(meta);
        };
        match tokio::time::timeout(DNS_ROUTE_TIMEOUT, resolver.resolve(&meta.destination)).await {
            Ok(Ok(addr)) => {
                let mut resolved = meta.clone();
                resolved.destination = TargetAddress::Ip(addr);
                std::borrow::Cow::Owned(resolved)
            }
            Ok(Err(e)) => {
                debug!(
                    "routing {} without an address: resolution failed ({e})",
                    meta.destination
                );
                std::borrow::Cow::Borrowed(meta)
            }
            Err(_) => {
                debug!(
                    "routing {} without an address: resolution timed out after {:?}",
                    meta.destination, DNS_ROUTE_TIMEOUT
                );
                std::borrow::Cow::Borrowed(meta)
            }
        }
    }

    fn get_outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag)
    }

    /// Routes `destination` and establishes a UDP endpoint for the resulting
    /// outbound, registering it in `endpoints` for subsequent datagrams.
    ///
    /// Returns `None` when the destination cannot be served (unknown outbound or
    /// a failed dial); the caller drops the packet.
    #[allow(clippy::too_many_arguments)]
    async fn dial_udp_endpoint(
        &self,
        meta: &SessionMeta,
        endpoints: &mut std::collections::HashMap<Arc<str>, EndpointSlot>,
        route_cache: &mut std::collections::HashMap<
            flux_types::TargetAddress,
            (Arc<str>, flux_types::TargetAddress),
        >,
        destination: &flux_types::TargetAddress,
        cancel_token: &tokio_util::sync::CancellationToken,
        packet_tx: &mpsc::Sender<UdpPacket>,
        dead_ep_tx: &mpsc::UnboundedSender<EndpointKey>,
        per_destination_tags: &mut std::collections::HashSet<Arc<str>>,
        conn_download: Option<Arc<std::sync::atomic::AtomicU64>>,
    ) -> Option<Arc<dyn PacketEndpoint>> {
        const MAX_ROUTE_CACHE_ENTRIES: usize = 4096;

        let (tag, eff_dest) = match route_cache.get(destination) {
            Some((tag, dest)) => (tag.clone(), dest.clone()),
            None => {
                let mut pkt_meta = meta.clone();
                pkt_meta.destination = destination.clone();
                let effective_meta = self.resolve_effective_meta(&pkt_meta);
                let routing_meta = self.route_meta(&effective_meta).await;
                let tag: Arc<str> = self.router.route(&routing_meta).into();
                let dest = effective_meta.destination.clone();
                if route_cache.len() >= MAX_ROUTE_CACHE_ENTRIES {
                    // Evict a single arbitrary entry instead of flushing the whole
                    // cache: a full clear would re-run the rule engine for every
                    // known destination on the next packet (thundering herd).
                    if let Some(key) = route_cache.keys().next().cloned() {
                        route_cache.remove(&key);
                    }
                }
                route_cache.insert(destination.clone(), (tag.clone(), dest.clone()));
                (tag, dest)
            }
        };

        let outbound = match self.get_outbound(&tag) {
            Some(o) => o,
            None => {
                error!(
                    "outbound '{}' not found for UDP destination {}",
                    tag, eff_dest
                );
                return None;
            }
        };

        let mut dial_meta = meta.clone();
        dial_meta.destination = eff_dest.clone();

        let ep: Arc<dyn PacketEndpoint> = match outbound.dial_packet(&dial_meta).await {
            Ok(ep) => Arc::from(ep),
            Err(e) => {
                warn!(
                    "failed to dial UDP endpoint [{}] for {}: {}",
                    tag, eff_dest, e
                );
                return None;
            }
        };

        let per_destination = outbound.udp_endpoint_per_destination();
        if per_destination {
            per_destination_tags.insert(tag.clone());
        }

        // Register the cache key *before* spawning: the reply pump needs an owned
        // copy of it to report its own death, and `tag`/`eff_dest` are consumed here.
        let key: EndpointKey = if per_destination {
            (tag.clone(), Some(eff_dest.clone()))
        } else {
            (tag.clone(), None)
        };

        let ep_recv = ep.clone();
        let reply_tx = packet_tx.clone();
        let meter_recv = self.meter.clone();
        let conn_recv = conn_download.clone();
        let token = cancel_token.clone();
        let client_addr = flux_types::TargetAddress::Ip(meta.source);
        let dead_tx = dead_ep_tx.clone();
        let dead_key = key.clone();
        // Cancelled when this endpoint leaves the cache (see `CachedEndpoint`).
        let stop = CancellationToken::new();
        let stop_pump = stop.clone();
        tokio::spawn(async move {
            // Only a read loop that ended on its own is "dead": an endpoint we
            // deliberately stopped must not report its key, or the stale report
            // would evict the *replacement* endpoint registered under the same
            // key moments later.
            let mut died = false;
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = stop_pump.cancelled() => break,
                    res = ep_recv.recv_packet() => match res {
                        Ok(mut reply) => {
                            let r_len = reply.payload.len() as u64;
                            // Normalize reply addressing: some endpoints (e.g. direct)
                            // report destination = responder instead of the original
                            // client. Transparent inbounds (TUN/TPROXY/WireGuard) need
                            // destination = client to route the inner reply packet back.
                            reply.destination = client_addr.clone();
                            if reply_tx.send(reply).await.is_err() {
                                break;
                            }
                            if let Some(c) = &conn_recv {
                                c.fetch_add(r_len, std::sync::atomic::Ordering::Relaxed);
                            }
                            if let Some(m) = &meter_recv {
                                m.record_traffic(0, r_len);
                            }
                        }
                        Err(e) => {
                            debug!("UDP endpoint [{}] read loop ended: {}", dead_key.0, e);
                            died = true;
                            break;
                        }
                    }
                }
            }
            // Let the owning task forget this endpoint so the next datagram
            // re-dials instead of talking to a closed socket.
            if died {
                let _ = dead_tx.send(dead_key);
            }
        });

        let cached = CachedEndpoint {
            endpoint: ep.clone(),
            stop,
        };
        match endpoints.entry(tag.clone()) {
            std::collections::hash_map::Entry::Vacant(v) => {
                let slot = if per_destination {
                    EndpointSlot::PerDestination(std::iter::once((eff_dest, cached)).collect())
                } else {
                    EndpointSlot::Shared(cached)
                };
                v.insert(slot);
            }
            std::collections::hash_map::Entry::Occupied(mut o) => match o.get_mut() {
                EndpointSlot::PerDestination(map) => {
                    // Cap the nested map: a client addressing many destinations
                    // must not grow this (and its reply tasks) without bound.
                    // The evicted entry's `Drop` stops its reply pump, so the cap
                    // covers the sockets and tasks, not just the map slot.
                    if map.len() >= MAX_ENDPOINTS_PER_TAG
                        && !map.contains_key(&eff_dest)
                        && let Some(arbitrary) = map.keys().next().cloned()
                    {
                        debug!(
                            "UDP endpoint cache for [{}] full ({}); evicting {}",
                            tag, MAX_ENDPOINTS_PER_TAG, arbitrary
                        );
                        map.remove(&arbitrary);
                    }
                    map.insert(eff_dest, cached);
                }
                EndpointSlot::Shared(existing) => {
                    // Assigning drops the previous endpoint, which stops its
                    // pump before the new one starts receiving.
                    *existing = cached;
                }
            },
        }
        Some(ep)
    }
}

/// Budget for the address lookup that routing may need. Short on purpose: a slow
/// resolver must not add its latency to every connection, and routing without an
/// address is always a valid fallback.
const DNS_ROUTE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

#[async_trait]
impl Dispatcher for DefaultDispatcher {
    async fn dial_outbound(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let effective_meta = self.resolve_effective_meta(meta);
        let routing_meta = self.route_meta(&effective_meta).await;
        let outbound_tag = self.router.route(&routing_meta);
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

            let mut inbound_stream = inbound_stream;
            let mut outbound_stream = outbound_stream;
            // `copy_bidirectional` beats the pooled split variant by a measured
            // 13.5% throughput and 9.5% CPU on the relay benchmark, at identical
            // RSS (23.8 MB under 100 connections): `tokio::io::split` wraps the
            // stream in a mutex that both directions contend for, so the pooled
            // implementation serialised the two halves of every connection.
            // 64 KiB buffers, one task, no split: every protocol tunnel wraps the
            // socket, so the splice path above never applies to them and they used
            // to inherit `copy_bidirectional`'s 8 KiB buffers.
            let copy_fut = flux_common::copy::copy_bidirectional_buffered(
                &mut inbound_stream,
                &mut outbound_stream,
                64 * 1024,
            );
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
        // A UDP association is a connection as far as an operator is concerned: it
        // has a source, a destination, a lifetime and byte counters, and the API's
        // "close connection" must be able to stop it. It used to register nothing,
        // so `flux_active_connections` never counted it, `DELETE /connections`
        // could not close it, and its traffic was only visible in the global total.
        let mut conn_reg = self.meter.as_ref().map(|m| m.register_connection(&meta));
        let mut cancel_conn = conn_reg.as_mut().map(|(_, _, rx)| {
            std::mem::replace(rx, tokio::sync::broadcast::channel(1).1)
        });
        let conn_download = conn_reg.as_ref().map(|(_, c, _)| c.download.clone());
        // Endpoints are only accessed from this task; a plain HashMap avoids DashMap sharding overhead.
        let mut endpoints: std::collections::HashMap<Arc<str>, EndpointSlot> =
            std::collections::HashMap::new();
        // Per-destination routing cache: (outbound tag, effective destination after Fake-IP remap).
        // Avoids re-running the full rule engine for every single packet.
        let mut route_cache: std::collections::HashMap<
            flux_types::TargetAddress,
            (Arc<str>, flux_types::TargetAddress),
        > = std::collections::HashMap::new();
        let meter = self.meter.clone();
        // Reply pumps report the tag of an endpoint whose read loop ended (fatal
        // error or EOF) so the cached entry can be dropped and re-dialled.
        // Without this the map keeps a permanently dead endpoint and every later
        // datagram for that outbound is written into the void.
        let (dead_ep_tx, mut dead_ep_rx) = mpsc::unbounded_channel::<EndpointKey>();
        // Outbound tags whose UDP endpoint is bound to one destination.
        let mut per_destination_tags: std::collections::HashSet<Arc<str>> =
            std::collections::HashSet::new();

        loop {
            let packet = tokio::select! {
                biased;
                // The API asked for this association to be closed.
                _ = async {
                    match cancel_conn.as_mut() {
                        Some(rx) => {
                            let _ = rx.recv().await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    debug!("UDP association cancelled via API");
                    break;
                }
                packet = packet_rx.recv() => match packet {
                    Some(p) => p,
                    None => break,
                },
            };
            while let Ok(key) = dead_ep_rx.try_recv() {
                debug!(
                    "UDP endpoint [{}] closed; it will be re-dialled on demand",
                    key.0
                );
                drop_cached_endpoint(&mut endpoints, key.0.as_ref(), key.1.as_ref());
            }
            let bytes_len = packet.payload.len() as u64;

            // ---- Fast path: routing decision and endpoint both cached. This is
            // every datagram after the first per destination, and it neither
            // allocates nor clones the tag or destination.
            //
            // The routing cache holds the *effective* destination (after Fake-IP
            // reverse mapping), which is exactly what the endpoint is registered
            // under; rebuilding the key from `packet.destination` would miss
            // whenever remapping applied and re-dial on every single datagram.
            let cached_endpoint = route_cache
                .get(&packet.destination)
                .and_then(|(tag, dest)| {
                    endpoints.get(tag.as_ref()).and_then(|slot| {
                        slot.get(dest, per_destination_tags.contains(tag.as_ref()))
                    })
                });

            let endpoint = match cached_endpoint {
                Some(ep) => ep,
                None => {
                    let endpoint = self
                        .dial_udp_endpoint(
                            &meta,
                            &mut endpoints,
                            &mut route_cache,
                            &packet.destination,
                            &cancel_token,
                            &packet_tx,
                            &dead_ep_tx,
                            &mut per_destination_tags,
                            conn_download.clone(),
                        )
                        .await;
                    match endpoint {
                        Some(ep) => ep,
                        None => continue,
                    }
                }
            };

            if let Err(e) = endpoint.send_packet(packet).await {
                // The write side can die before the read pump notices (stream
                // reset, ICMP error). Drop the association we just failed on so
                // the next datagram re-dials instead of writing into a dead
                // socket — and *only* that one. Removing the whole tag used to
                // discard every other destination's association for the same
                // outbound, so one broken destination forced a fresh dial (and a
                // fresh VMess UDP association) for all of them on their next
                // packet.
                //
                // The victim is found by pointer identity, so the successful-send
                // path pays nothing for this: no destination clone and no second
                // route-cache lookup per datagram.
                debug!("failed to forward UDP packet: {}; dropping endpoint", e);
                drop_failed_endpoint(&mut endpoints, &endpoint);
            } else {
                if let Some((_, conn, _)) = conn_reg.as_ref() {
                    conn.upload
                        .fetch_add(bytes_len, std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(m) = &meter {
                    m.record_traffic(bytes_len, 0);
                }
            }
        }

        cancel_token.cancel();
        if let Some((id, _, _)) = conn_reg.take()
            && let Some(m) = &self.meter
        {
            m.remove_connection(&id);
        }
    }
}

#[cfg(test)]
mod endpoint_slot_tests {
    use super::*;
    use flux_types::{PacketEndpoint, UdpPacket};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Dummy(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl PacketEndpoint for Dummy {
        async fn send_packet(&self, _packet: UdpPacket) -> FluxResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn recv_packet(&self) -> FluxResult<UdpPacket> {
            std::future::pending().await
        }
    }

    fn dest(s: &str) -> flux_types::TargetAddress {
        s.parse().unwrap()
    }

    /// The key must resolve for the *effective* destination the endpoint was
    /// registered under, which is not the raw packet destination once Fake-IP
    /// reverse mapping is involved. Getting this wrong re-dialled (and leaked) an
    /// endpoint per datagram.
    #[test]
    fn per_destination_lookup_uses_the_effective_destination() {
        let counter = Arc::new(AtomicUsize::new(0));
        let ep: Arc<dyn PacketEndpoint> = Arc::new(Dummy(counter.clone()));
        let cached = |ep: Arc<dyn PacketEndpoint>| CachedEndpoint {
            endpoint: ep,
            stop: CancellationToken::new(),
        };

        let mut map: std::collections::HashMap<flux_types::TargetAddress, CachedEndpoint> =
            std::collections::HashMap::new();
        let effective = dest("example.com:443");
        map.insert(effective.clone(), cached(ep.clone()));

        let slot = EndpointSlot::PerDestination(map);
        assert!(
            slot.get(&effective, true).is_some(),
            "lookup by the registered destination must hit"
        );
        assert!(
            slot.get(&dest("198.18.0.5:443"), true).is_none(),
            "lookup by a raw Fake-IP address must miss"
        );
        // A shared slot ignores the destination entirely.
        let shared = EndpointSlot::Shared(cached(ep));
        assert!(shared.get(&dest("1.1.1.1:53"), false).is_some());
        assert!(
            shared.get(&dest("1.1.1.1:53"), true).is_none(),
            "a shared slot must not answer per-destination lookups"
        );
    }
}

// ---------------------------------------------------------------------------
// BEGIN AUDIT TESTS
//
// Black-box tests over the `Dispatcher` trait entry points: they only use the
// public constructor plus the fake outbounds below, so the same module can be
// run against the pre-fix implementation to produce before/after evidence.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod dispatcher_audit_tests {
    use super::*;
    use bytes::Bytes;
    use flux_router::{DomainMatch, PortRange, Rule};
    use flux_types::NetworkType;
    use flux_types::TargetAddress;
    use std::collections::HashSet;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as O};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{sleep, timeout};

    fn dst(s: &str) -> TargetAddress {
        s.parse().expect("test destination must parse")
    }

    fn src(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn meta(port: u16, destination: TargetAddress, network: NetworkType) -> SessionMeta {
        SessionMeta::new(src(port), destination, "mixed-in", network)
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            sleep(Duration::from_millis(2)).await;
        }
    }

    // ---- outbound registry -------------------------------------------------

    #[derive(Default)]
    struct FxRegistry {
        map: std::collections::HashMap<String, Arc<dyn Outbound>>,
    }

    impl FxRegistry {
        fn with(outbound: Arc<dyn Outbound>) -> Self {
            let mut map = std::collections::HashMap::new();
            map.insert(outbound.tag().to_string(), outbound);
            Self { map }
        }

        fn insert(&mut self, outbound: Arc<dyn Outbound>) {
            self.map.insert(outbound.tag().to_string(), outbound);
        }
    }

    impl OutboundLookup for FxRegistry {
        fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
            self.map.get(tag).cloned()
        }
    }

    fn build(
        outbound: Arc<dyn Outbound>,
        router: Router,
        meter: Option<Arc<TrafficMeter>>,
    ) -> Arc<DefaultDispatcher> {
        let mut d = DefaultDispatcher::new(Arc::new(router), Arc::new(FxRegistry::with(outbound)));
        if let Some(m) = meter {
            d = d.with_meter(m);
        }
        Arc::new(d)
    }

    // ---- stream outbound driven by the test --------------------------------

    /// Hands the relay one half of a `duplex` pipe and keeps the other half, so a
    /// test decides when (and whether) either direction closes.
    struct PipeOutbound {
        tag: String,
        dials: AtomicUsize,
        seen: Mutex<Vec<TargetAddress>>,
        peers: Mutex<Vec<DuplexStream>>,
    }

    impl PipeOutbound {
        fn new(tag: &str) -> Arc<Self> {
            Arc::new(Self {
                tag: tag.into(),
                dials: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
                peers: Mutex::new(Vec::new()),
            })
        }
        fn dials(&self) -> usize {
            self.dials.load(O::SeqCst)
        }
        fn seen(&self) -> Vec<TargetAddress> {
            self.seen.lock().unwrap().clone()
        }
        fn close_peers(&self) {
            self.peers.lock().unwrap().clear();
        }
    }

    #[async_trait::async_trait]
    impl Outbound for PipeOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }
        async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
            self.dials.fetch_add(1, O::SeqCst);
            self.seen.lock().unwrap().push(meta.destination.clone());
            let (bridge, peer) = tokio::io::duplex(4096);
            self.peers.lock().unwrap().push(peer);
            Ok(Box::new(bridge))
        }
        async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
            Err(FluxError::Protocol {
                protocol: "test",
                message: format!("no udp for {}", meta.destination),
            })
        }
    }

    /// Connects to a real localhost listener, so the relay takes the zero-copy
    /// (or `copy_direction_ref`) path over actual sockets.
    struct TcpOutbound {
        tag: String,
        target: SocketAddr,
        dials: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Outbound for TcpOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }
        async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            self.dials.fetch_add(1, O::SeqCst);
            Ok(Box::new(TcpStream::connect(self.target).await?))
        }
        async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
            Err(FluxError::Protocol {
                protocol: "test",
                message: "no udp".into(),
            })
        }
    }

    /// Inbound stream that delivers `data`, stalls one poll, then fails the way a
    /// reset peer does — the copy ends with `Err`, never `Ok`.
    struct ResettingStream {
        data: Vec<u8>,
        stage: u8,
    }

    impl AsyncRead for ResettingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.stage {
                0 => {
                    let n = self.data.len().min(buf.remaining());
                    let bytes = self.data[..n].to_vec();
                    buf.put_slice(&bytes);
                    self.stage = 1;
                    Poll::Ready(Ok(()))
                }
                1 => {
                    self.stage = 2;
                    let waker = cx.waker().clone();
                    tokio::spawn(async move {
                        sleep(Duration::from_millis(50)).await;
                        waker.wake();
                    });
                    Poll::Pending
                }
                _ => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "peer reset",
                ))),
            }
        }
    }

    impl AsyncWrite for ResettingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // ---- packet outbound driven by the test --------------------------------

    /// A UDP endpoint the test can send replies through, break, and count while
    /// it is alive (a live count is how a leaked reply pump becomes visible).
    struct FakeEndpoint {
        fail_dest: Arc<Mutex<Option<TargetAddress>>>,
        send_failures: Arc<AtomicUsize>,
        fail_recv: Arc<AtomicBool>,
        sent: Arc<Mutex<Vec<UdpPacket>>>,
        replies: tokio::sync::Mutex<mpsc::UnboundedReceiver<UdpPacket>>,
        live: Arc<AtomicUsize>,
    }

    impl Drop for FakeEndpoint {
        fn drop(&mut self) {
            self.live.fetch_sub(1, O::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl PacketEndpoint for FakeEndpoint {
        async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
            let broken = self
                .fail_dest
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|d| *d == packet.destination);
            if broken {
                self.send_failures.fetch_add(1, O::SeqCst);
                return Err(FluxError::Io(io::Error::from(
                    io::ErrorKind::ConnectionReset,
                )));
            }
            self.sent.lock().unwrap().push(packet);
            Ok(())
        }
        async fn recv_packet(&self) -> FluxResult<UdpPacket> {
            if self.fail_recv.swap(false, O::SeqCst) {
                return Err(FluxError::Io(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            let mut replies = self.replies.lock().await;
            replies
                .recv()
                .await
                .ok_or_else(|| FluxError::Io(io::Error::from(io::ErrorKind::BrokenPipe)))
        }
    }

    #[derive(Default)]
    struct FakeUdp {
        per_destination: bool,
        dials: AtomicUsize,
        dialed: Mutex<Vec<TargetAddress>>,
        reply_txs: Mutex<Vec<mpsc::UnboundedSender<UdpPacket>>>,
        sent: Arc<Mutex<Vec<UdpPacket>>>,
        fail_dest: Arc<Mutex<Option<TargetAddress>>>,
        send_failures: Arc<AtomicUsize>,
        fail_recv: Arc<AtomicBool>,
        live: Arc<AtomicUsize>,
    }

    impl FakeUdp {
        fn new(per_destination: bool) -> Arc<Self> {
            Arc::new(Self {
                per_destination,
                ..Default::default()
            })
        }
        fn dials(&self) -> usize {
            self.dials.load(O::SeqCst)
        }
        fn dialed(&self) -> Vec<TargetAddress> {
            self.dialed.lock().unwrap().clone()
        }
        fn sent(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
        fn live(&self) -> usize {
            self.live.load(O::SeqCst)
        }
        fn send_failures(&self) -> usize {
            self.send_failures.load(O::SeqCst)
        }
        fn break_sends_to(&self, dest: &TargetAddress) {
            *self.fail_dest.lock().unwrap() = Some(dest.clone());
        }
        fn break_next_read(&self) {
            self.fail_recv.store(true, O::SeqCst);
        }
        fn reply(&self, index: usize, packet: UdpPacket) {
            let _ = self.reply_txs.lock().unwrap()[index].send(packet);
        }
    }

    #[async_trait::async_trait]
    impl Outbound for FakeUdp {
        fn tag(&self) -> &str {
            "direct"
        }
        async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            Err(FluxError::Protocol {
                protocol: "test",
                message: "no stream".into(),
            })
        }
        async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
            self.dials.fetch_add(1, O::SeqCst);
            self.dialed.lock().unwrap().push(meta.destination.clone());
            let (tx, rx) = mpsc::unbounded_channel();
            self.reply_txs.lock().unwrap().push(tx);
            self.live.fetch_add(1, O::SeqCst);
            Ok(Box::new(FakeEndpoint {
                fail_dest: self.fail_dest.clone(),
                send_failures: self.send_failures.clone(),
                fail_recv: self.fail_recv.clone(),
                sent: self.sent.clone(),
                replies: tokio::sync::Mutex::new(rx),
                live: self.live.clone(),
            }))
        }
        fn udp_endpoint_per_destination(&self) -> bool {
            self.per_destination
        }
    }

    fn datagram(dest: &TargetAddress) -> UdpPacket {
        UdpPacket::new(
            Bytes::from_static(b"q"),
            TargetAddress::Ip(src(1)),
            dest.clone(),
        )
    }

    struct UdpSession {
        tx: mpsc::Sender<UdpPacket>,
        rx: mpsc::Receiver<UdpPacket>,
        handle: tokio::task::JoinHandle<()>,
    }

    async fn udp_session(
        disp: &Arc<DefaultDispatcher>,
        source_port: u16,
        target: &TargetAddress,
    ) -> UdpSession {
        let (tx, inbound) = mpsc::channel::<UdpPacket>(16);
        let (out_tx, rx) = mpsc::channel::<UdpPacket>(16);
        let d = disp.clone();
        let m = meta(source_port, target.clone(), NetworkType::Udp);
        let handle = tokio::spawn(async move {
            d.dispatch_packet(m, inbound, out_tx).await;
        });
        UdpSession { tx, rx, handle }
    }

    // =======================================================================
    // 1. Per-connection accounting
    // =======================================================================

    /// One dispatch = exactly one table entry, and the entry is gone after a
    /// clean close. A leak here is invisible until the table is exhausted.
    #[tokio::test]
    async fn a_stream_is_registered_once_and_removed_when_it_closes() {
        let meter = TrafficMeter::new();
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        let (inbound, mut client) = tokio::io::duplex(256);
        let dest = dst("example.com:443");
        disp.dispatch_stream(
            meta(41001, dest.clone(), NetworkType::Tcp),
            Box::new(inbound),
        )
        .await;

        wait_for("the connection to be registered", || {
            meter.connections.len() == 1
        })
        .await;
        assert_eq!(out.dials(), 1, "one dispatch must dial exactly once");
        let entry = meter.connections.iter().next().expect("one entry").clone();
        assert_eq!(entry.meta.destination, dest);

        // Nothing else registers itself while the relay runs.
        sleep(Duration::from_millis(20)).await;
        assert_eq!(meter.connections.len(), 1, "registered exactly once");

        // Clean close from both ends.
        let _ = client.shutdown().await;
        drop(client);
        out.close_peers();
        wait_for("the connection to be unregistered", || {
            meter.connections.is_empty()
        })
        .await;
        assert!(meter.connections.get(&entry.id).is_none());
    }

    /// `DELETE /connections/<id>` must both free the slot *and* stop the relay;
    /// the natural exit must not then trip over the already-removed entry.
    #[tokio::test]
    async fn closing_a_connection_through_the_api_tears_the_relay_down() {
        let meter = TrafficMeter::new();
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        let (inbound, mut client) = tokio::io::duplex(256);
        disp.dispatch_stream(
            meta(41002, dst("example.com:443"), NetworkType::Tcp),
            Box::new(inbound),
        )
        .await;

        wait_for("the connection to be registered", || {
            meter.connections.len() == 1
        })
        .await;
        let id = meter.connections.iter().next().unwrap().id.clone();

        assert!(
            meter.close_connection(&id),
            "the API must find the connection it just registered"
        );
        let mut buf = [0u8; 16];
        match timeout(Duration::from_secs(2), client.read(&mut buf)).await {
            Ok(Ok(n)) => assert_eq!(n, 0, "client must see EOF, not the relay continuing"),
            Ok(Err(_)) => {} // reset also counts as torn down
            Err(_) => panic!("a connection closed through the API must not keep relaying"),
        }

        wait_for("the table to drain after the API close", || {
            meter.connections.is_empty()
        })
        .await;
        assert!(
            !meter.close_connection(&id),
            "a second close must report 'not found' instead of panicking"
        );
    }

    /// Closing through the API at the same moment the peer leaves is the race the
    /// two removal paths (`remove_connection` from the guard, `close_connection`
    /// from the API) genuinely lose: no double-remove panic, no stuck entry.
    #[tokio::test]
    async fn a_close_racing_the_natural_close_is_harmless() {
        let meter = TrafficMeter::new();
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        for round in 0..25u16 {
            let (inbound, client) = tokio::io::duplex(256);
            disp.dispatch_stream(
                meta(43000 + round, dst("race.example:443"), NetworkType::Tcp),
                Box::new(inbound),
            )
            .await;
            wait_for("registration", || !meter.connections.is_empty()).await;
            let id = meter.connections.iter().next().unwrap().id.clone();

            // Both paths at once: the client disappears and the API closes.
            let closer = {
                let meter = meter.clone();
                let id = id.clone();
                tokio::spawn(async move { meter.close_connection(&id) })
            };
            drop(client);
            out.close_peers();
            let _ = closer.await;
            wait_for("the table to drain", || meter.connections.is_empty()).await;
        }
    }

    /// Every connection of a burst is counted once, has a unique id, and the
    /// table is empty again afterwards.
    #[tokio::test]
    async fn a_burst_of_connections_is_registered_once_each_and_all_released() {
        let meter = TrafficMeter::new();
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        let mut clients = Vec::new();
        for i in 0..32u16 {
            let (inbound, client) = tokio::io::duplex(256);
            disp.dispatch_stream(
                meta(
                    44000 + i,
                    dst(&format!("h{i}.example:443")),
                    NetworkType::Tcp,
                ),
                Box::new(inbound),
            )
            .await;
            clients.push(client);
        }
        wait_for("32 registered connections", || {
            meter.connections.len() == 32
        })
        .await;
        assert_eq!(out.dials(), 32);
        let ids: HashSet<String> = meter.connections.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids.len(), 32, "connection ids must be unique");

        assert_eq!(meter.close_all_connections(), 32);
        drop(clients);
        out.close_peers();
        wait_for("the table to drain", || meter.connections.is_empty()).await;
        assert_eq!(meter.close_all_connections(), 0, "closing twice is a no-op");
    }

    /// The byte counters are read out of the connection *after* the copy ended, so
    /// an error in the copy must not wipe the bytes already transferred.
    #[tokio::test]
    async fn the_byte_counters_are_recorded_when_the_copy_ends_with_an_error() {
        let meter = TrafficMeter::new();
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        disp.dispatch_stream(
            meta(41003, dst("example.com:443"), NetworkType::Tcp),
            Box::new(ResettingStream {
                data: b"hello".to_vec(),
                stage: 0,
            }),
        )
        .await;

        // The connection's own counters are reachable only while it is
        // registered, and the relay can finish before this poll loop sees it —
        // `dispatch_stream` awaits the whole thing. So take the reading from the
        // per-connection counters only if a window is still open, and always
        // assert the global totals, which is what the property is about.
        let mut conn_counters = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(entry) = meter.connections.iter().next() {
                conn_counters = Some((entry.upload.clone(), entry.download.clone()));
                break;
            }
            if meter.upload_total.load(O::Relaxed) > 0 {
                break;
            }
            sleep(Duration::from_millis(1)).await;
        }
        wait_for("the failed relay to be unregistered", || {
            meter.connections.is_empty()
        })
        .await;
        // When the relay finished before we could read its counters, the global
        // totals are the assertion that matters; the per-connection check is
        // skipped rather than faked.
        if let Some((up, down)) = conn_counters {
            assert_eq!(
                up.load(O::Relaxed),
                5,
                "bytes read before the reset must still be counted on the connection"
            );
            assert_eq!(down.load(O::Relaxed), 0);
        }

        assert_eq!(
            meter.upload_total.load(O::Relaxed),
            5,
            "bytes read before the reset must still be counted globally"
        );
        assert_eq!(meter.download_total.load(O::Relaxed), 0);
    }

    /// An outbound that dies mid-stream must close the client, not leave it
    /// waiting for a reply that can never arrive.
    #[tokio::test]
    async fn an_outbound_error_closes_the_client() {
        /// Sends one byte, then fails the way a reset peer does.
        struct BrokenOutbound;

        #[async_trait::async_trait]
        impl Outbound for BrokenOutbound {
            fn tag(&self) -> &str {
                "direct"
            }
            async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
                Ok(Box::new(ResettingStream {
                    data: b"x".to_vec(),
                    stage: 0,
                }))
            }
            async fn dial_packet(
                &self,
                _meta: &SessionMeta,
            ) -> FluxResult<Box<dyn PacketEndpoint>> {
                Err(FluxError::Protocol {
                    protocol: "test",
                    message: "no udp".into(),
                })
            }
        }

        let meter = TrafficMeter::new();
        let disp = build(
            Arc::new(BrokenOutbound),
            Router::new(vec![], "direct"),
            Some(meter.clone()),
        );
        let (inbound, mut client) = tokio::io::duplex(256);
        disp.dispatch_stream(
            meta(41005, dst("example.com:443"), NetworkType::Tcp),
            Box::new(inbound),
        )
        .await;

        let mut buf = Vec::new();
        match timeout(Duration::from_secs(3), client.read_to_end(&mut buf)).await {
            Ok(Ok(_)) => assert_eq!(
                buf, b"x",
                "the client reads the tail and then EOF, not a hang"
            ),
            Ok(Err(_)) => {}
            Err(_) => panic!("an outbound error must not leave the client hanging"),
        }
        wait_for("the connection to be unregistered", || {
            meter.connections.is_empty()
        })
        .await;
        assert_eq!(
            meter.download_total.load(O::Relaxed),
            1,
            "the byte delivered before the error is still counted as download"
        );
        assert_eq!(
            meter.upload_total.load(O::Relaxed),
            0,
            "the client wrote nothing, so nothing is upload"
        );
    }

    /// Client half-closes: the FIN must reach the outbound while the reverse
    /// direction stays open long enough to deliver the tail.
    #[tokio::test]
    async fn half_close_reaches_the_outbound_and_the_tail_reaches_the_client() {
        let target = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let target_addr = target.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"hi", "the client's FIN must reach the outbound");
            s.write_all(b"bye").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let meter = TrafficMeter::new();
        let out: Arc<TcpOutbound> = Arc::new(TcpOutbound {
            tag: "direct".into(),
            target: target_addr,
            dials: AtomicUsize::new(0),
        });
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listen_addr = listener.local_addr().unwrap();
        let d = disp.clone();
        let accepted = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            d.dispatch_stream(
                meta(41004, dst("example.com:443"), NetworkType::Tcp),
                Box::new(s),
            )
            .await;
        });

        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        client.write_all(b"hi").await.unwrap();
        client.shutdown().await.unwrap(); // half close: FIN, still readable
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        assert_eq!(
            tail, b"bye",
            "the outbound->client half must survive the client's FIN"
        );

        server.await.unwrap();
        accepted.await.unwrap();
        wait_for("the connection to be unregistered", || {
            meter.connections.is_empty()
        })
        .await;
        assert_eq!(out.dials.load(O::SeqCst), 1);
        assert_eq!(
            meter.upload_total.load(O::Relaxed),
            2,
            "upload accounting over real sockets"
        );
        assert_eq!(
            meter.download_total.load(O::Relaxed),
            3,
            "download accounting over real sockets"
        );
    }

    // =======================================================================
    // 2. UDP sessions
    // =======================================================================

    /// Two clients hitting the same target must not share an association, and a
    /// reply must go to the client whose association produced it.
    #[tokio::test]
    async fn two_udp_clients_never_share_an_association() {
        let meter = TrafficMeter::new();
        let out = FakeUdp::new(false);
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), Some(meter.clone()));

        let target = dst("9.9.9.9:53");
        let mut one = udp_session(&disp, 40001, &target).await;
        let mut two = udp_session(&disp, 40002, &target).await;

        one.tx.send(datagram(&target)).await.unwrap();
        wait_for("client 1 to dial", || out.dials() == 1).await;
        two.tx.send(datagram(&target)).await.unwrap();
        wait_for("client 2 to dial", || out.dials() == 2).await;
        assert_eq!(
            out.dialed(),
            vec![target.clone(), target.clone()],
            "each association must dial its own endpoint"
        );
        assert_eq!(out.sent(), 2, "both datagrams reached the outbound");

        out.reply(
            0,
            UdpPacket::new(Bytes::from_static(b"r1"), target.clone(), target.clone()),
        );
        let got = timeout(Duration::from_secs(2), one.rx.recv())
            .await
            .expect("client 1's reply must be forwarded")
            .expect("reply");
        assert_eq!(got.payload, Bytes::from_static(b"r1"));
        assert_eq!(
            got.destination,
            TargetAddress::Ip(src(40001)),
            "the reply must be re-addressed to the owning client"
        );
        assert!(
            two.rx.try_recv().is_err(),
            "client 2 must not receive client 1's reply"
        );
        assert_eq!(
            meter.upload_total.load(O::Relaxed),
            2,
            "both datagrams are counted on upload"
        );
        assert_eq!(
            meter.download_total.load(O::Relaxed),
            2,
            "the 2-byte reply is counted on download"
        );

        // Client 1 leaves: its endpoint and reply pump must go with it.
        drop(one.tx);
        let _ = timeout(Duration::from_secs(2), one.handle)
            .await
            .expect("the association must end when its client does");
        wait_for("client 1's endpoint to be torn down", || out.live() == 1).await;
        // A late reply on the dead endpoint is dropped, never re-delivered.
        out.reply(
            0,
            UdpPacket::new(Bytes::from_static(b"late"), target.clone(), target.clone()),
        );
        sleep(Duration::from_millis(20)).await;
        assert!(two.rx.try_recv().is_err(), "no cross-session delivery");

        drop(two.tx);
        let _ = timeout(Duration::from_secs(2), two.handle)
            .await
            .expect("client 2's association must end too");
        wait_for("every endpoint to be torn down", || out.live() == 0).await;
    }

    /// The per-destination cache is capped at `MAX_ENDPOINTS_PER_TAG`; the reply
    /// pumps and sockets behind it must be capped with it.
    #[tokio::test]
    async fn the_endpoint_cache_bounds_reply_pumps_and_not_just_map_entries() {
        let out = FakeUdp::new(true);
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), None);

        let target = dst("203.0.113.1:53");
        let session = udp_session(&disp, 40003, &target).await;
        let _keep_replies_alive = &session.rx;

        let extra = 50usize;
        let total = MAX_ENDPOINTS_PER_TAG + extra;
        for i in 0..total {
            let dest = TargetAddress::domain(format!("d{i}.example"), 53);
            session.tx.send(datagram(&dest)).await.unwrap();
        }
        wait_for("every destination to be dialled", || out.dials() == total).await;

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let live = out.live();
            if live <= MAX_ENDPOINTS_PER_TAG + 8 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{live} live UDP endpoints after {total} distinct destinations on ONE association, \
                 while the cache caps entries at {MAX_ENDPOINTS_PER_TAG}: the evicted entries' reply \
                 pumps (one socket + one task each) were never stopped"
            );
            sleep(Duration::from_millis(10)).await;
        }

        drop(session.tx);
        let _ = timeout(Duration::from_secs(2), session.handle)
            .await
            .expect("the association must end");
        wait_for(
            "every endpoint to be torn down with the association",
            || out.live() == 0,
        )
        .await;
    }

    /// A send error means *this* destination's association is dead — not every
    /// other destination's that happens to share the same outbound.
    #[tokio::test]
    async fn a_failed_send_only_drops_its_own_destination() {
        let out = FakeUdp::new(true);
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), None);

        let target = dst("203.0.113.2:53");
        let a = TargetAddress::domain("a.example", 53);
        let b = TargetAddress::domain("b.example", 53);
        let session = udp_session(&disp, 40004, &target).await;

        session.tx.send(datagram(&a)).await.unwrap();
        session.tx.send(datagram(&b)).await.unwrap();
        wait_for("both destinations dialled", || out.dials() == 2).await;

        out.break_sends_to(&a);
        session.tx.send(datagram(&a)).await.unwrap();
        wait_for("the send to a to fail", || out.send_failures() == 1).await;

        // b is still cached: a datagram to b must not dial again.
        session.tx.send(datagram(&b)).await.unwrap();
        wait_for("b to be sent", || out.sent() == 3).await;
        assert_eq!(
            out.dials(),
            2,
            "a send error on a.example threw away b.example's live association"
        );

        // The broken association, and only it, is re-dialled on demand.
        session.tx.send(datagram(&a)).await.unwrap();
        wait_for("a to be re-dialled", || out.dials() == 3).await;

        drop(session.tx);
        let _ = timeout(Duration::from_secs(2), session.handle)
            .await
            .expect("the association must end");
        wait_for("every endpoint to be torn down", || out.live() == 0).await;
    }

    /// When a read loop ends on its own the cached endpoint is dropped and the
    /// next datagram re-dials instead of writing into the void.
    #[tokio::test]
    async fn a_dead_read_loop_makes_the_next_datagram_redial() {
        let out = FakeUdp::new(false);
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), None);

        let target = dst("203.0.113.3:53");
        let mut session = udp_session(&disp, 40005, &target).await;
        session.tx.send(datagram(&target)).await.unwrap();
        wait_for("the first dial", || out.dials() == 1).await;

        // Wake the pump with a reply, then make its next read fail.
        out.break_next_read();
        out.reply(
            0,
            UdpPacket::new(Bytes::from_static(b"r"), target.clone(), target.clone()),
        );
        let _ = timeout(Duration::from_secs(2), session.rx.recv())
            .await
            .expect("reply")
            .expect("packet");
        sleep(Duration::from_millis(30)).await;

        session.tx.send(datagram(&target)).await.unwrap();
        wait_for("a fresh endpoint after the read loop died", || {
            out.dials() == 2
        })
        .await;

        drop(session.tx);
        let _ = timeout(Duration::from_secs(2), session.handle)
            .await
            .expect("the association must end");
    }

    // =======================================================================
    // 3. Outbound selection
    // =======================================================================

    /// A tag the router names but the registry does not hold (a reload race, a
    /// rule pointing at a removed group) is an error, not a panic.
    #[tokio::test]
    async fn an_unknown_outbound_tag_is_a_clean_error() {
        let meter = TrafficMeter::new();
        let disp = Arc::new(
            DefaultDispatcher::new(
                Arc::new(Router::new(vec![], "ghost")),
                Arc::new(FxRegistry::default()),
            )
            .with_meter(meter.clone()),
        );

        let err = disp
            .dial_outbound(&meta(1, dst("example.com:443"), NetworkType::Tcp))
            .await
            .err()
            .expect("an unknown tag must not dial");
        assert!(
            matches!(err, FluxError::OutboundNotFound(_)),
            "unexpected error: {err}"
        );

        // The stream path closes the client instead of hanging.
        let (inbound, mut client) = tokio::io::duplex(64);
        disp.dispatch_stream(
            meta(1, dst("example.com:443"), NetworkType::Tcp),
            Box::new(inbound),
        )
        .await;
        let mut buf = [0u8; 4];
        assert!(
            matches!(
                timeout(Duration::from_secs(2), client.read(&mut buf)).await,
                Ok(Ok(0) | Err(_))
            ),
            "the client must be closed, not left hanging"
        );
        assert!(
            meter.connections.is_empty(),
            "a connection that never relayed must not be registered"
        );

        // The packet path drops the datagram and returns quietly.
        let target = dst("203.0.113.4:53");
        let session = udp_session(&disp, 40006, &target).await;
        session.tx.send(datagram(&target)).await.unwrap();
        drop(session.tx);
        timeout(Duration::from_secs(2), session.handle)
            .await
            .expect("dispatch_packet must return after an unknown tag")
            .expect("no panic");
        assert_eq!(meter.upload_total.load(O::Relaxed), 0);
    }

    /// A `block` outbound refuses both networks through the dispatcher.
    #[tokio::test]
    async fn a_block_outbound_refuses() {
        let block: Arc<dyn Outbound> = Arc::new(flux_outbound::BlockOutbound::new("block"));
        let disp = build(block, Router::new(vec![], "block"), None);
        let m = meta(1, dst("ads.example:443"), NetworkType::Tcp);

        let res = disp.dial_outbound(&m).await;
        assert!(
            matches!(&res, Err(FluxError::Blocked(_))),
            "a block outbound must refuse the stream, got {:?}",
            res.as_ref().err().map(|e| e.to_string())
        );

        let target = dst("ads.example:443");
        let session = udp_session(&disp, 40007, &target).await;
        session.tx.send(datagram(&target)).await.unwrap();
        drop(session.tx);
        timeout(Duration::from_secs(2), session.handle)
            .await
            .expect("dispatch_packet must return for a blocked destination")
            .expect("no panic");
    }

    /// A domain reaches the outbound as a domain, and the dispatcher dials once:
    /// resolution happens inside the outbound, so it cannot happen twice.
    #[tokio::test]
    async fn a_domain_is_handed_to_the_outbound_unresolved_and_dialled_once() {
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let disp = build(as_out, Router::new(vec![], "direct"), None);

        let dest = dst("example.com:443");
        let _stream = disp
            .dial_outbound(&meta(1, dest.clone(), NetworkType::Tcp))
            .await
            .expect("dial");
        assert_eq!(out.dials(), 1, "one dial per dispatch");
        assert_eq!(
            out.seen(),
            vec![dest],
            "the outbound must receive the domain itself"
        );
    }

    /// Fake-IP reverse mapping happens before routing *and* before dialling.
    #[tokio::test]
    async fn a_fake_ip_destination_is_remapped_before_routing_and_dialling() {
        let pool = Arc::new(flux_dns::FakeIpPool::default_pool());
        let fake_ip = pool.allocate("remapped.example");
        let resolver = Arc::new(flux_dns::DnsResolver::new(Some(pool)));
        let out = PipeOutbound::new("proxy");
        let as_out: Arc<dyn Outbound> = out.clone();
        let router = Router::new(
            vec![Rule {
                domains: vec![DomainMatch::suffix("remapped.example")],
                outbound: "proxy".into(),
                ..Default::default()
            }],
            "block",
        );
        let disp = Arc::new(
            DefaultDispatcher::new(Arc::new(router), Arc::new(FxRegistry::with(as_out)))
                .with_resolver(resolver),
        );

        let fake = TargetAddress::Ip(SocketAddr::new(IpAddr::V4(fake_ip), 443));
        disp.dial_outbound(&meta(1, fake, NetworkType::Tcp))
            .await
            .expect("the remapped domain must route to the proxy");
        assert_eq!(
            out.seen(),
            vec![TargetAddress::domain("remapped.example", 443)],
            "the reverse-mapped domain is what the outbound dials"
        );
    }

    // =======================================================================
    // 6. Fuzzing the entry points
    // =======================================================================

    /// Adversarial session metadata (empty host, absurd ports, IPv6, oversized
    /// labels) must never panic, and every dial must either succeed or be a
    /// deliberate refusal.
    #[tokio::test]
    async fn adversarial_sessions_never_panic() {
        let out = PipeOutbound::new("direct");
        let as_out: Arc<dyn Outbound> = out.clone();
        let mut registry = FxRegistry::with(as_out);
        registry.insert(Arc::new(flux_outbound::BlockOutbound::new("block")));
        let router = Router::new(
            vec![
                Rule {
                    domains: vec![DomainMatch::suffix("ads.example")],
                    outbound: "block".into(),
                    ..Default::default()
                },
                Rule {
                    ports: vec![PortRange::single(443)],
                    outbound: "direct".into(),
                    ..Default::default()
                },
            ],
            "direct",
        );
        let disp = Arc::new(DefaultDispatcher::new(Arc::new(router), Arc::new(registry)));

        let long_label = "a".repeat(255);
        let cases = vec![
            TargetAddress::domain("", 0),
            TargetAddress::domain("", 65535),
            TargetAddress::domain(".", 1),
            TargetAddress::domain("..", 1),
            TargetAddress::domain("-leading-dash.example", 443),
            TargetAddress::domain("exa mple.com", 443),
            TargetAddress::domain("ex\0ample.com", 80),
            TargetAddress::domain(format!("{long_label}.{long_label}.ads.example"), 443),
            TargetAddress::domain("a".repeat(4096), 1),
            TargetAddress::domain("ｆｕｌｌｗｉｄｔｈ.example", 443),
            TargetAddress::domain("*.example", 443),
            TargetAddress::Ip("0.0.0.0:0".parse().unwrap()),
            TargetAddress::Ip("[::]:0".parse().unwrap()),
            TargetAddress::Ip("[fe80::1]:65535".parse().unwrap()),
            TargetAddress::Ip("[::ffff:127.0.0.1]:80".parse().unwrap()),
        ];

        let mut dialled = 0;
        for dest in cases {
            let m = meta(1, dest.clone(), NetworkType::Tcp);
            match disp.dial_outbound(&m).await {
                Ok(_) => dialled += 1,
                Err(FluxError::Blocked(_)) => {}
                Err(e) => panic!("{dest} produced {e} instead of a dial or a refusal"),
            }
        }
        assert!(dialled > 0, "the fuzz cases must exercise the dial path");

        // Same destinations over the packet path: the dial fails per packet, which
        // must be dropped without a panic or a stuck association.
        let target = dst("203.0.113.5:53");
        let session = udp_session(&disp, 40008, &target).await;
        for i in 0..25 {
            let dest = TargetAddress::domain(format!("{long_label}.{i}.ads.example"), 443);
            let _ = session.tx.send(datagram(&dest)).await;
            let _ = session.tx.send(datagram(&TargetAddress::Ip(src(i)))).await;
        }
        drop(session.tx);
        timeout(Duration::from_secs(5), session.handle)
            .await
            .expect("dispatch_packet must terminate")
            .expect("no panic");
    }
}

#[cfg(test)]
mod udp_association_tests {
    use super::*;
    use crate::api::TrafficMeter;
    use flux_types::{NetworkType, Outbound, SessionMeta, TargetAddress, UdpPacket};
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// A UDP endpoint that echoes back what it receives.
    struct EchoPacketEndpoint;

    #[async_trait::async_trait]
    impl flux_types::PacketEndpoint for EchoPacketEndpoint {
        async fn send_packet(&self, _packet: UdpPacket) -> FluxResult<()> {
            Ok(())
        }
        async fn recv_packet(&self) -> FluxResult<UdpPacket> {
            std::future::pending().await
        }
    }

    struct UdpOutbound {
        tag: String,
    }

    #[async_trait::async_trait]
    impl Outbound for UdpOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }
        fn protocol(&self) -> &'static str {
            "test"
        }
        async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            Err(flux_types::FluxError::Config("stream unsupported".into()))
        }
        async fn dial_packet(
            &self,
            _meta: &SessionMeta,
        ) -> FluxResult<Box<dyn flux_types::PacketEndpoint>> {
            Ok(Box::new(EchoPacketEndpoint))
        }
    }

    impl OutboundLookup for UdpRegistry {
        fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
            (tag == "direct").then(|| {
                Arc::new(UdpOutbound {
                    tag: "direct".into(),
                }) as Arc<dyn Outbound>
            })
        }
    }

    struct UdpRegistry;

    fn build(meter: Arc<TrafficMeter>) -> Arc<DefaultDispatcher> {
        Arc::new(
            DefaultDispatcher::new(
                Arc::new(Router::new(vec![], "direct")),
                Arc::new(UdpRegistry),
            )
            .with_meter(meter),
        )
    }

    fn meta() -> SessionMeta {
        SessionMeta::new(
            SocketAddr::from(([127, 0, 0, 1], 40001)),
            "example.com:53".parse::<TargetAddress>().unwrap(),
            "mixed-in",
            NetworkType::Udp,
        )
    }

    /// A UDP association must appear in the connection table while it lives, so an
    /// operator can see it and the API can close it.
    #[tokio::test]
    async fn a_udp_association_is_registered_while_it_lives() {
        let meter = Arc::new(TrafficMeter::new());
        let disp = build((*meter).clone());
        let (tx, rx) = mpsc::channel::<UdpPacket>(8);
        let (reply_tx, _reply_rx) = mpsc::channel::<UdpPacket>(8);

        let task = {
            let disp = disp.clone();
            tokio::spawn(async move { disp.dispatch_packet(meta(), rx, reply_tx).await })
        };
        // Drive one datagram so the association is established.
        tx.send(UdpPacket::new(
            bytes::Bytes::from_static(b"hello"),
            "127.0.0.1:40001".parse().unwrap(),
            "example.com:53".parse().unwrap(),
        ))
        .await
        .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while meter.connections.is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let entry = meter
            .connections
            .iter()
            .next()
            .expect("a UDP association must be in the connection table")
            .clone();
        assert_eq!(entry.meta.network, NetworkType::Udp);
        drop(entry);

        // Closing the channel ends the association and releases the entry.
        drop(tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !meter.connections.is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            meter.connections.is_empty(),
            "the association must be unregistered when it ends"
        );
        assert!(
            meter
                .upload_total
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 5,
            "the association's traffic must reach the global counter"
        );
    }

    /// `DELETE /api/v1/connections/<id>` must actually stop a UDP association —
    /// before this it was registered nowhere and could not be closed at all.
    #[tokio::test]
    async fn the_api_can_close_a_udp_association() {
        let meter = Arc::new(TrafficMeter::new());
        let disp = build((*meter).clone());
        let (tx, rx) = mpsc::channel::<UdpPacket>(8);
        let (reply_tx, _reply_rx) = mpsc::channel::<UdpPacket>(8);

        let task = {
            let disp = disp.clone();
            tokio::spawn(async move { disp.dispatch_packet(meta(), rx, reply_tx).await })
        };
        tx.send(UdpPacket::new(
            bytes::Bytes::from_static(b"x"),
            "127.0.0.1:40001".parse().unwrap(),
            "example.com:53".parse().unwrap(),
        ))
        .await
        .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while meter.connections.is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let id = meter
            .connections
            .iter()
            .next()
            .expect("registered")
            .id
            .clone();
        meter.close_connection(&id);

        let finished = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        assert!(
            finished.is_ok(),
            "closing the association through the API must end the relay task"
        );
        // The receiver is still open on our side, so the task can only have ended
        // because of the cancellation.
        let _ = tx;
    }
}
