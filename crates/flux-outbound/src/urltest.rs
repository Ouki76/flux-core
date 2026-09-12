use std::sync::Arc;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tracing::{debug, info};
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, OutboundLookup, PacketEndpoint,
    SessionMeta, TargetAddress,
};

pub struct UrlTestOutbound {
    tag: String,
    outbounds: Vec<String>,
    url: String,
    target_addr: TargetAddress,
    host_header: String,
    request_path: String,
    interval: Duration,
    tolerance: Duration,
    current_best: Arc<RwLock<Option<String>>>,
    latencies: Arc<DashMap<String, Duration>>,
    lookup: Arc<dyn OutboundLookup>,
}

impl UrlTestOutbound {
    pub fn new(
        tag: impl Into<String>,
        outbounds: Vec<String>,
        url: Option<String>,
        interval: Option<Duration>,
        tolerance: Option<Duration>,
        lookup: Arc<dyn OutboundLookup>,
    ) -> Self {
        let tag = tag.into();
        let url_str = url.unwrap_or_else(|| "http://cp.cloudflare.com/generate_204".into());
        let (target_addr, host_header, request_path) = parse_test_url(&url_str);

        let initial_best = outbounds.first().cloned();

        Self {
            tag,
            outbounds,
            url: url_str,
            target_addr,
            host_header,
            request_path,
            interval: interval.unwrap_or(Duration::from_secs(300)),
            tolerance: tolerance.unwrap_or(Duration::from_millis(50)),
            current_best: Arc::new(RwLock::new(initial_best)),
            latencies: Arc::new(DashMap::new()),
            lookup,
        }
    }

    /// Spawns the background health check probe loop.
    pub fn start_probing(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                this.probe_all().await;
                sleep(this.interval).await;
            }
        });
    }

    pub async fn probe_all(&self) {
        for tag in &self.outbounds {
            if let Some(rtt) = self.probe_candidate(tag).await {
                self.latencies.insert(tag.clone(), rtt);
                debug!("[{}] Candidate '{}' RTT: {:?}", self.tag, tag, rtt);
            } else {
                self.latencies.remove(tag);
                debug!("[{}] Candidate '{}' probe failed / unreachable", self.tag, tag);
            }
        }
        self.recalculate_best();
    }

    async fn probe_candidate(&self, tag: &str) -> Option<Duration> {
        let outbound = self.lookup.get(tag)?;
        let meta = SessionMeta::new(
            "127.0.0.1:0".parse().ok()?,
            self.target_addr.clone(),
            format!("{}-healthcheck", self.tag),
            NetworkType::Tcp,
        );

        let start = Instant::now();
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(5),
            outbound.dial_stream(&meta),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Send HTTP GET
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: flux-core-healthcheck\r\nConnection: close\r\n\r\n",
            self.request_path, self.host_header
        );

        if stream.write_all(req.as_bytes()).await.is_err() {
            return None;
        }

        let mut buf = [0u8; 32];
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => Some(start.elapsed()),
            _ => None,
        }
    }

    fn recalculate_best(&self) {
        let mut best_tag: Option<String> = None;
        let mut min_rtt = Duration::MAX;

        for tag in &self.outbounds {
            if let Some(rtt_entry) = self.latencies.get(tag) {
                let rtt = *rtt_entry.value();
                if rtt < min_rtt {
                    min_rtt = rtt;
                    best_tag = Some(tag.clone());
                }
            }
        }

        if let Some(new_best) = best_tag {
            let mut guard = self.current_best.write();
            if let Some(current) = guard.as_ref()
                && let Some(cur_rtt_entry) = self.latencies.get(current)
            {
                let cur_rtt = *cur_rtt_entry.value();
                // Apply tolerance: only switch if new_best is significantly better
                if cur_rtt <= min_rtt + self.tolerance {
                    return;
                }
            }
            info!(
                "[{}] Switched best outbound to '{}' (RTT: {:?})",
                self.tag, new_best, min_rtt
            );
            *guard = Some(new_best);
        }
    }

    pub fn current_best_tag(&self) -> Option<String> {
        self.current_best.read().clone()
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn get_active(&self) -> FluxResult<Arc<dyn Outbound>> {
        let best = self.current_best_tag().or_else(|| self.outbounds.first().cloned()).ok_or_else(|| {
            FluxError::OutboundNotFound(format!("urltest '{}': no outbounds configured", self.tag))
        })?;

        self.lookup.get(&best).ok_or_else(|| {
            FluxError::OutboundNotFound(format!(
                "urltest '{}': active outbound '{}' not found in registry",
                self.tag, best
            ))
        })
    }
}

fn parse_test_url(url: &str) -> (TargetAddress, String, String) {
    let is_https = url.starts_with("https://");
    let default_port = if is_https { 443 } else { 80 };

    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host_port, path) = match without_scheme.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (without_scheme, "/".to_string()),
    };

    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
    } else {
        (host_port.to_string(), default_port)
    };

    let target = TargetAddress::domain(host.clone(), port);
    (target, host, path)
}

#[async_trait]
impl Outbound for UrlTestOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let active = self.get_active()?;
        active.dial_stream(meta).await
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let active = self.get_active()?;
        active.dial_packet(meta).await
    }

    fn is_group(&self) -> bool {
        true
    }

    fn group_type(&self) -> Option<&'static str> {
        Some("URLTest")
    }

    fn current_selected(&self) -> Option<String> {
        self.current_best_tag()
    }

    fn candidate_outbounds(&self) -> Vec<String> {
        self.outbounds.clone()
    }
}
