use crate::instance::OutboundRegistry;
use dashmap::DashMap;
use flux_dns::DnsResolver;
use flux_router::Router;
use flux_types::{FluxResult, Inbound, NetworkType, SessionMeta, TargetAddress};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tracing::info;

pub struct ActiveConnection {
    pub id: String,
    pub start_time: Instant,
    pub meta: SessionMeta,
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    pub cancel_tx: tokio::sync::broadcast::Sender<()>,
}

#[derive(Default)]
pub struct TrafficMeter {
    pub upload_total: Arc<AtomicU64>,
    pub download_total: Arc<AtomicU64>,
    pub upload_speed: AtomicU64,
    pub download_speed: AtomicU64,
    pub connections: Arc<DashMap<String, Arc<ActiveConnection>>>,
}

impl TrafficMeter {
    pub fn new() -> Arc<Self> {
        let this = Arc::new(Self {
            upload_total: Arc::new(AtomicU64::new(0)),
            download_total: Arc::new(AtomicU64::new(0)),
            upload_speed: AtomicU64::new(0),
            download_speed: AtomicU64::new(0),
            connections: Arc::new(DashMap::new()),
        });
        let weak = Arc::downgrade(&this);
        tokio::spawn(async move {
            let mut last_up = 0u64;
            let mut last_down = 0u64;
            loop {
                sleep(Duration::from_secs(1)).await;
                let Some(meter) = weak.upgrade() else {
                    break;
                };
                let cur_up = meter.upload_total.load(Ordering::Relaxed);
                let cur_down = meter.download_total.load(Ordering::Relaxed);

                meter
                    .upload_speed
                    .store(cur_up.saturating_sub(last_up), Ordering::Relaxed);
                meter
                    .download_speed
                    .store(cur_down.saturating_sub(last_down), Ordering::Relaxed);

                last_up = cur_up;
                last_down = cur_down;
            }
        });
        this
    }

    pub fn record_traffic(&self, up: u64, down: u64) {
        self.upload_total.fetch_add(up, Ordering::Relaxed);
        self.download_total.fetch_add(down, Ordering::Relaxed);
    }

    pub fn register_connection(
        &self,
        meta: &SessionMeta,
    ) -> (
        String,
        Arc<ActiveConnection>,
        tokio::sync::broadcast::Receiver<()>,
    ) {
        let id = format!("{:x}", uuid::Uuid::new_v4().as_simple());
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let conn = Arc::new(ActiveConnection {
            id: id.clone(),
            start_time: Instant::now(),
            meta: meta.clone(),
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            cancel_tx: tx,
        });
        self.connections.insert(id.clone(), conn.clone());
        (id, conn, rx)
    }

    pub fn remove_connection(&self, id: &str) {
        self.connections.remove(id);
    }

    pub fn close_connection(&self, id: &str) -> bool {
        if let Some((_, conn)) = self.connections.remove(id) {
            let _ = conn.cancel_tx.send(());
            true
        } else {
            false
        }
    }

    pub fn close_all_connections(&self) -> usize {
        let mut count = 0;
        let ids: Vec<String> = self.connections.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            if self.close_connection(&id) {
                count += 1;
            }
        }
        count
    }
}

#[derive(Clone)]
pub struct ApiContext {
    pub registry: Arc<OutboundRegistry>,
    pub meter: Arc<TrafficMeter>,
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub router: Option<Arc<Router>>,
    pub resolver: Option<Arc<DnsResolver>>,
    pub secret: Option<String>,
    pub allow_insecure: bool,
    pub start_time: Instant,
}

pub struct ApiServer {
    listen: String,
    ctx: ApiContext,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl ApiServer {
    pub fn new(
        listen: impl ToString,
        registry: Arc<OutboundRegistry>,
        meter: Arc<TrafficMeter>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            listen: listen.to_string(),
            ctx: ApiContext {
                registry,
                meter,
                router: None,
                inbounds: vec![],
                resolver: None,
                secret: None,
                allow_insecure: false,
                start_time: Instant::now(),
            },
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_router(mut self, router: Arc<Router>) -> Self {
        self.ctx.router = Some(router);
        self
    }

    pub fn with_inbounds(mut self, inbounds: Vec<Arc<dyn Inbound>>) -> Self {
        self.ctx.inbounds = inbounds;
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.ctx.resolver = Some(resolver);
        self
    }

    pub fn with_secret(mut self, secret: Option<String>) -> Self {
        // An empty/whitespace-only secret is not a secret. Treating it as `Some("")`
        // would defeat the unsafe-bind guard (which checks `is_none()`) and let a
        // `Authorization: Bearer ` header authenticate.
        self.ctx.secret = secret.filter(|s| !s.trim().is_empty());
        self
    }

    pub fn with_allow_insecure(mut self, allow: bool) -> Self {
        self.ctx.allow_insecure = allow;
        self
    }

    pub async fn start(&self) -> FluxResult<()> {
        self.running.store(true, Ordering::SeqCst);
        let ctx = Arc::new(self.ctx.clone());
        let listen = self.listen.clone();

        #[cfg(unix)]
        if listen.starts_with("unix://") || listen.ends_with(".sock") {
            let socket_path = listen.strip_prefix("unix://").unwrap_or(&listen);
            let _ = std::fs::remove_file(socket_path);
            let listener =
                tokio::net::UnixListener::bind(socket_path).map_err(flux_types::FluxError::Io)?;
            info!(
                "Flux Core Native API server listening on unix://{}",
                socket_path
            );

            let mut shutdown_rx = self.shutdown_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    let (socket, _) = tokio::select! {
                        res = listener.accept() => match res {
                            Ok(res) => res,
                            Err(_) => break,
                        },
                        _ = shutdown_rx.recv() => break,
                    };

                    let c = ctx.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(15),
                            handle_http_connection(socket, c),
                        )
                        .await;
                    });
                }
            });
            return Ok(());
        }

        let addr: SocketAddr = listen.parse().map_err(|e| {
            flux_types::FluxError::Config(format!("invalid API listen address {}: {}", listen, e))
        })?;

        if self.ctx.secret.is_none() && addr.ip().is_unspecified() && !self.ctx.allow_insecure {
            tracing::error!(
                "CRITICAL SECURITY ERROR: API server configured to listen on public/unspecified address {} without a secret token! Set 'secret' or explicitly set 'allow_insecure_api: true' in config.api.",
                addr
            );
            return Err(flux_types::FluxError::Config(format!(
                "insecure API listening on {} without secret rejected. Set 'allow_insecure_api: true' in config to override.",
                addr
            )));
        }

        if self.ctx.secret.is_none() && !addr.ip().is_loopback() {
            tracing::warn!(
                "Flux Native API is listening on non-loopback address {} without an authentication secret! Any network peer can control the proxy.",
                addr
            );
        }

        // Deliberately *not* SO_REUSEPORT: the management API is a single-owner
        // resource, and port sharing would let any same-uid process race or
        // hijack API traffic. Only the proxy's data-plane listeners need
        // SO_REUSEPORT (for zero-downtime reload).
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(flux_types::FluxError::Io)?;
        info!("Flux Core Native API server listening on http://{}", addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                let (socket, _) = tokio::select! {
                    res = listener.accept() => match res {
                        Ok(res) => res,
                        Err(_) => break,
                    },
                    _ = shutdown_rx.recv() => break,
                };

                let c = ctx.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(15),
                        handle_http_connection(socket, c),
                    )
                    .await;
                });
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        Ok(())
    }
}

fn is_private_or_restricted_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let oct = v4.octets();
            let is_cgnat = oct[0] == 100 && (oct[1] & 0xC0) == 64;
            let is_benchmarking = oct[0] == 198 && (oct[1] == 18 || oct[1] == 19);
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || is_cgnat
                || is_benchmarking
                || oct[0] == 0
        }
        std::net::IpAddr::V6(v6) => {
            let oct = v6.octets();
            let is_ula = (oct[0] & 0xFE) == 0xFC;
            let is_link_local = oct[0] == 0xFE && (oct[1] & 0xC0) == 0x80;
            if let Some(v4) = v6.to_ipv4_mapped()
                && is_private_or_restricted_ip(std::net::IpAddr::V4(v4))
            {
                return true;
            }
            v6.is_loopback() || v6.is_unspecified() || is_ula || is_link_local
        }
    }
}

/// True when `origin` is a same-machine HTTP origin
/// (`http(s)://localhost[:port]`, `http(s)://127.0.0.1[:port]`, `http(s)://[::1][:port]`).
///
/// A prefix test is *not* sufficient: `http://localhost.attacker.tld` starts with
/// `http://localhost` yet is fully attacker-controlled. The authority is therefore
/// parsed and the host compared exactly. Anything unparseable counts as external.
fn origin_is_local(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    // An origin never carries a path, but be liberal: keep only the authority.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Drop any userinfo component.
    let host_port = match authority.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority,
    };
    let host = if let Some(after_bracket) = host_port.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:port`
        let Some((host, tail)) = after_bracket.split_once(']') else {
            return false;
        };
        if !tail.is_empty() && (!tail.starts_with(':') || tail[1..].parse::<u16>().is_err()) {
            return false;
        }
        host
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => {
                if port.parse::<u16>().is_err() {
                    return false;
                }
                host
            }
            None => host_port,
        }
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

async fn handle_http_connection<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut socket: S,
    ctx: Arc<ApiContext>,
) {
    let reg = &ctx.registry;
    let met = &ctx.meter;
    let inbs = &ctx.inbounds;
    let rtr = &ctx.router;
    let rslv = &ctx.resolver;
    let sec = &ctx.secret;
    let start_time = ctx.start_time;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];

    // 1. Read headers until \r\n\r\n
    let mut header_end = None;
    while buf.len() < 16384 {
        let n = match socket.read(&mut chunk).await {
            Ok(n) if n > 0 => n,
            _ => return,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let Some(h_end) = header_end else {
        return;
    };

    let header_str = String::from_utf8_lossy(&buf[..h_end]).into_owned();
    let lines: Vec<&str> = header_str.lines().collect();
    let first_line = lines.first().copied().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let uri = parts.next().unwrap_or("/").to_string();

    // Parse Content-Length with strict bounds checking.
    //
    // Ambiguity is rejected rather than resolved: two Content-Length headers, or
    // a Content-Length together with Transfer-Encoding, is the classic request
    // smuggling pair when a reverse proxy sits in front of this API and disagrees
    // with us about where the body ends. We do not implement chunked bodies, so a
    // Transfer-Encoding header is refused outright instead of being ignored (an
    // ignored `chunked` makes the body length zero here while the front end
    // forwards a body that then becomes the next request).
    const MAX_API_BODY_SIZE: usize = 1024 * 1024; // 1 MB
    let mut content_length: Option<usize> = None;
    for line in &lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        if key.eq_ignore_ascii_case("transfer-encoding") {
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"transfer-encoding is not supported\"}";
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
            return;
        }
        if key.eq_ignore_ascii_case("content-length") {
            let Ok(parsed) = v.trim().parse::<usize>() else {
                let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"invalid content-length\"}";
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
                return;
            };
            match content_length {
                None => content_length = Some(parsed),
                Some(prev) if prev == parsed => {}
                Some(_) => {
                    let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"conflicting content-length headers\"}";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                    return;
                }
            }
        }
    }
    let content_length = content_length.unwrap_or(0);

    if content_length > MAX_API_BODY_SIZE {
        let resp = "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"payload too large\"}";
        let _ = socket.write_all(resp.as_bytes()).await;
        let _ = socket.shutdown().await;
        return;
    }

    // 2. Read remaining body
    while buf.len() < h_end + content_length {
        let needed = (h_end + content_length).saturating_sub(buf.len());
        let to_read = needed.min(chunk.len());
        let n = match socket.read(&mut chunk[..to_read]).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        buf.extend_from_slice(&chunk[..n]);
    }

    let body_slice = if buf.len() >= h_end + content_length {
        &buf[h_end..h_end + content_length]
    } else if buf.len() >= h_end {
        &buf[h_end..]
    } else {
        &[]
    };
    let body_str = String::from_utf8_lossy(body_slice);

    let (path_only, query_str) = uri.split_once('?').unwrap_or((&uri, ""));
    let path_clean = if path_only.len() > 1 && path_only.ends_with('/') {
        path_only.trim_end_matches('/')
    } else {
        path_only
    };

    // Check Authorization if secret is configured
    let mut is_authorized = sec.is_none();
    if let Some(expected_secret) = sec {
        for line in &lines {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("authorization")
            {
                let trimmed = v.trim();
                if let Some(token) = trimmed
                    .strip_prefix("Bearer ")
                    .or_else(|| trimmed.strip_prefix("bearer "))
                    && flux_common::constant_time_eq_str(token.trim(), expected_secret.as_str())
                {
                    is_authorized = true;
                    break;
                }
            }
        }
        if !is_authorized && !query_str.is_empty() {
            for param in query_str.split('&') {
                if let Some((k, v)) = param.split_once('=')
                    && k == "token"
                    && flux_common::constant_time_eq_str(v, expected_secret.as_str())
                {
                    is_authorized = true;
                    break;
                }
            }
        }
    }

    // Detect cross-origin requests BEFORE any state-changing dispatch.
    let mut has_external_origin = false;
    for line in &lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("origin")
        {
            let origin = v.trim();
            if !origin_is_local(origin) {
                has_external_origin = true;
            }
            break;
        }
    }

    // CSRF & Cross-Origin protection: reject cross-origin requests from external websites if no secret is configured
    // or if attempting query-string authentication from an untrusted origin.
    // This MUST run before dispatch: state-changing endpoints (DELETE connections, outbound select,
    // delay probes) would otherwise execute even though the response is rejected afterwards.
    if (sec.is_none() || (!query_str.is_empty() && query_str.contains("token=")))
        && has_external_origin
        && method != "OPTIONS"
    {
        let resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"cross-origin access without Authorization header is forbidden\"}";
        let _ = socket.write_all(resp.as_bytes()).await;
        let _ = socket.flush().await;
        let _ = socket.shutdown().await;
        return;
    }

    let (status, body) = if method == "OPTIONS" {
        ("200 OK", String::new())
    } else if !is_authorized {
        (
            "401 Unauthorized",
            json!({"error": "unauthorized"}).to_string(),
        )
    } else if path_clean == "/api/v1/version" && method == "GET" {
        // Flux Core Version API
        let data = json!({
            "engine": "flux-core",
            "version": format!("flux-core {}", env!("CARGO_PKG_VERSION")),
            "target": std::env::consts::ARCH,
            "os": std::env::consts::OS,
            "api_version": "v1"
        });
        ("200 OK", data.to_string())
    } else if path_clean == "/api/v1/status" && method == "GET" {
        // Flux Core Status API
        let data = json!({
            "version": format!("flux-core {}", env!("CARGO_PKG_VERSION")),
            "uptime_seconds": start_time.elapsed().as_secs(),
            "active_connections": met.connections.len(),
            "upload_total": met.upload_total.load(Ordering::Relaxed),
            "download_total": met.download_total.load(Ordering::Relaxed),
            "upload_speed": met.upload_speed.load(Ordering::Relaxed),
            "download_speed": met.download_speed.load(Ordering::Relaxed),
            "outbounds_count": reg.map.len(),
            "inbounds_count": inbs.len()
        });
        ("200 OK", data.to_string())
    } else if path_clean == "/api/v1/metrics" && method == "GET" {
        // Prometheus text exposition format (v0.0.4).
        let up_total = met.upload_total.load(Ordering::Relaxed);
        let down_total = met.download_total.load(Ordering::Relaxed);
        let up_speed = met.upload_speed.load(Ordering::Relaxed);
        let down_speed = met.download_speed.load(Ordering::Relaxed);
        let active = met.connections.len();
        let body = format!(
            "# HELP flux_uptime_seconds Process uptime in seconds.\n\
             # TYPE flux_uptime_seconds gauge\n\
             flux_uptime_seconds {}\n\
             # HELP flux_active_connections Currently tracked active connections.\n\
             # TYPE flux_active_connections gauge\n\
             flux_active_connections {}\n\
             # HELP flux_upload_bytes_total Total bytes uploaded since start.\n\
             # TYPE flux_upload_bytes_total counter\n\
             flux_upload_bytes_total {}\n\
             # HELP flux_download_bytes_total Total bytes downloaded since start.\n\
             # TYPE flux_download_bytes_total counter\n\
             flux_download_bytes_total {}\n\
             # HELP flux_upload_speed_bps Current upload throughput in bytes/sec.\n\
             # TYPE flux_upload_speed_bps gauge\n\
             flux_upload_speed_bps {}\n\
             # HELP flux_download_speed_bps Current download throughput in bytes/sec.\n\
             # TYPE flux_download_speed_bps gauge\n\
             flux_download_speed_bps {}\n\
             # HELP flux_outbounds_configured Configured outbound count.\n\
             # TYPE flux_outbounds_configured gauge\n\
             flux_outbounds_configured {}\n\
             # HELP flux_inbounds_active Running inbound listener count.\n\
             # TYPE flux_inbounds_active gauge\n\
             flux_inbounds_active {}\n\
             # HELP flux_build_info Build and version metadata.\n\
             # TYPE flux_build_info gauge\n\
             flux_build_info{{version=\"{}\", target=\"{}\", os=\"{}\"}} 1\n",
            start_time.elapsed().as_secs(),
            active,
            up_total,
            down_total,
            up_speed,
            down_speed,
            reg.map.len(),
            inbs.len(),
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            std::env::consts::OS,
        );
        ("200 OK", body)
    } else if path_clean == "/api/v1/traffic" && method == "GET" {
        // Flux Core Traffic API
        let data = json!({
            "upload_speed": met.upload_speed.load(Ordering::Relaxed),
            "download_speed": met.download_speed.load(Ordering::Relaxed),
            "upload_total": met.upload_total.load(Ordering::Relaxed),
            "download_total": met.download_total.load(Ordering::Relaxed)
        });
        ("200 OK", data.to_string())
    } else if path_clean == "/api/v1/inbounds" && method == "GET" {
        // Flux Core Inbounds List API
        let inbounds_list: Vec<serde_json::Value> = inbs
            .iter()
            .map(|i| {
                json!({
                    "tag": i.tag(),
                    "protocol": i.protocol(),
                    "listen": i.listen_addr()
                })
            })
            .collect();
        let data = json!({ "inbounds": inbounds_list });
        ("200 OK", data.to_string())
    } else if path_clean == "/api/v1/dns/resolve" && (method == "GET" || method == "POST") {
        // Flux Core DNS Debug / Test Resolution API
        let mut domain_name = String::new();
        if method == "GET" {
            for param in query_str.split('&') {
                if let Some((k, v)) = param.split_once('=')
                    && (k == "name" || k == "domain" || k == "host")
                {
                    domain_name = crate::uri::urlencoding_decode(v);
                    break;
                }
            }
        } else {
            let req_json: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
            domain_name = req_json
                .get("name")
                .or_else(|| req_json.get("domain"))
                .or_else(|| req_json.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
        }

        if domain_name.is_empty() {
            (
                "400 Bad Request",
                json!({"error": "missing 'name' or 'domain' parameter"}).to_string(),
            )
        } else if let Some(resolver) = rslv {
            let target = TargetAddress::domain(&domain_name, 80);
            match resolver.resolve(&target).await {
                Ok(resolved_addr) => {
                    let ip = resolved_addr.ip();
                    let is_fake = resolver
                        .fake_ip()
                        .map(|f| f.contains_ip(&ip))
                        .unwrap_or(false);
                    let real_domain = if is_fake {
                        resolver.fake_ip().and_then(|f| f.lookup_domain(&ip))
                    } else {
                        None
                    };
                    let data = json!({
                        "name": domain_name,
                        "ip": ip.to_string(),
                        "is_fake_ip": is_fake,
                        "fake_ip_mapped_domain": real_domain
                    });
                    ("200 OK", data.to_string())
                }
                Err(e) => (
                    "502 Bad Gateway",
                    json!({"error": format!("DNS resolution failed: {}", e)}).to_string(),
                ),
            }
        } else {
            (
                "503 Service Unavailable",
                json!({"error": "DNS resolver not available"}).to_string(),
            )
        }
    } else if path_clean == "/api/v1/route/test" && method == "POST" {
        // Flux Core Route Tracer / Dry-Run API
        let req_json: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
        let dst_str = req_json
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("example.com:443");
        let net_str = req_json
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp");
        let inb_str = req_json
            .get("inbound")
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        let dst = dst_str
            .parse::<TargetAddress>()
            .unwrap_or_else(|_| TargetAddress::domain(dst_str, 80));
        let net = match net_str.to_ascii_lowercase().as_str() {
            "udp" => NetworkType::Udp,
            _ => NetworkType::Tcp,
        };
        let dummy_src = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let meta = SessionMeta::new(dummy_src, dst.clone(), inb_str, net);

        let matched_tag = if let Some(router) = rtr {
            router.route(&meta).to_string()
        } else {
            "direct".to_string()
        };

        let active_node = if let Some(out) = reg.get_outbound(&matched_tag) {
            if out.is_group() {
                out.current_selected().unwrap_or(matched_tag.clone())
            } else {
                matched_tag.clone()
            }
        } else {
            matched_tag.clone()
        };

        let data = json!({
            "destination": dst.to_string(),
            "network": net.to_string(),
            "inbound": inb_str,
            "matched_outbound": matched_tag,
            "active_target_outbound": active_node
        });
        ("200 OK", data.to_string())
    } else if path_clean == "/api/v1/rules" && method == "GET" {
        // Flux Core Rules Inspection API
        let mut rules_list = Vec::new();
        let default_out = if let Some(router) = rtr {
            for rule in router.rules() {
                let domains: Vec<String> = rule
                    .domains
                    .iter()
                    .map(|d| match d {
                        flux_router::DomainMatch::Exact(p) => format!("exact:{}", p),
                        flux_router::DomainMatch::Suffix(s) => format!("suffix:{}", s),
                        flux_router::DomainMatch::Keyword(k) => format!("keyword:{}", k),
                    })
                    .collect();
                let cidrs: Vec<String> = rule.ip_cidrs.iter().map(|c| c.to_string()).collect();
                let ports: Vec<String> = rule
                    .ports
                    .iter()
                    .map(|p| {
                        if p.start == p.end {
                            p.start.to_string()
                        } else {
                            format!("{}-{}", p.start, p.end)
                        }
                    })
                    .collect();
                let networks: Vec<String> = rule.networks.iter().map(|n| n.to_string()).collect();

                rules_list.push(json!({
                    "outbound": rule.outbound,
                    "invert": rule.invert,
                    "inbounds": rule.inbound_tags,
                    "networks": networks,
                    "domains": domains,
                    "ip_cidrs": cidrs,
                    "ports": ports,
                    "rule_set": rule.rule_set
                }));
            }
            router.default_outbound().to_string()
        } else {
            "direct".to_string()
        };
        let data = json!({
            "rules": rules_list,
            "final": default_out
        });
        ("200 OK", data.to_string())
    } else if path_clean == "/api/v1/outbounds" && method == "GET" {
        // Flux Core Outbounds List API
        let mut list = Vec::new();
        for entry in reg.map.iter() {
            let tag = entry.key();
            let outbound = entry.value();
            list.push(json!({
                "tag": tag,
                "protocol": outbound.protocol(),
                "is_group": outbound.is_group(),
                "current": outbound.current_selected(),
                "candidates": outbound.candidate_outbounds()
            }));
        }
        let data = json!({ "outbounds": list });
        ("200 OK", data.to_string())
    } else if path_clean.starts_with("/api/v1/outbounds/") && method == "GET" {
        let sub = path_clean.strip_prefix("/api/v1/outbounds/").unwrap_or("");

        if let Some(target_tag) = sub.strip_suffix("/delay") {
            // Outbound delay latency probe
            if let Some(out) = reg.get_outbound(target_tag) {
                let mut timeout_ms = 5000u64;
                let mut test_url = "http://cp.cloudflare.com/generate_204".to_string();
                for param in query_str.split('&') {
                    if let Some((k, v)) = param.split_once('=') {
                        if k == "timeout" {
                            if let Ok(t) = v.parse::<u64>() {
                                timeout_ms = t;
                            }
                        } else if k == "url" {
                            test_url = v.to_string();
                        }
                    }
                }
                let (target_addr, host_header, req_path, is_tls) =
                    flux_types::parse_probe_url(&test_url);
                let is_forbidden = match &target_addr {
                    TargetAddress::Ip(addr) => is_private_or_restricted_ip(addr.ip()),
                    TargetAddress::Domain(domain, port) => {
                        let d = domain.to_ascii_lowercase();
                        if d == "169.254.169.254"
                            || d == "localhost"
                            || d.ends_with(".localhost")
                            || d.ends_with(".internal")
                            || d.ends_with(".local")
                            || d.ends_with(".lan")
                            || d.ends_with(".home.arpa")
                        {
                            true
                        } else if let Ok(ip) = d.parse::<std::net::IpAddr>() {
                            is_private_or_restricted_ip(ip)
                        } else if let Some(resolver) = rslv {
                            match resolver.resolve_domain(&d, *port).await {
                                Ok(resolved_sock) => {
                                    is_private_or_restricted_ip(resolved_sock.ip())
                                }
                                // Fail closed: if the name cannot be resolved we
                                // cannot prove it is safe, so the probe is refused
                                // instead of being allowed through.
                                Err(_) => true,
                            }
                        } else if let Ok(addrs) =
                            tokio::net::lookup_host(format!("{}:{}", d, port)).await
                        {
                            addrs
                                .into_iter()
                                .any(|sa| is_private_or_restricted_ip(sa.ip()))
                        } else {
                            // Resolution failed: fail closed (see above).
                            true
                        }
                    }
                };
                if is_forbidden {
                    (
                        "403 Forbidden",
                        json!({ "error": "forbidden probe destination" }).to_string(),
                    )
                } else {
                    // Reuse the shared probe implementation: it performs a real TLS
                    // handshake for https:// URLs, matching UrlTest group behavior.
                    let probe_res = flux_outbound::probe::probe_outbound(
                        &out,
                        &target_addr,
                        &host_header,
                        &req_path,
                        is_tls,
                        "api-delay-test",
                        Duration::from_millis(timeout_ms),
                    )
                    .await;
                    match probe_res {
                        Some(delay) => (
                            "200 OK",
                            json!({ "delay": delay.as_millis() as u64 }).to_string(),
                        ),
                        None => (
                            "504 Gateway Timeout",
                            json!({ "error": "timeout" }).to_string(),
                        ),
                    }
                }
            } else {
                (
                    "404 Not Found",
                    json!({"error": format!("outbound '{}' not found", target_tag)}).to_string(),
                )
            }
        } else {
            // Single outbound info
            let target_tag = sub.trim_end_matches('/');
            if let Some(out) = reg.get_outbound(target_tag) {
                let data = json!({
                    "tag": target_tag,
                    "protocol": out.protocol(),
                    "is_group": out.is_group(),
                    "current": out.current_selected(),
                    "candidates": out.candidate_outbounds()
                });
                ("200 OK", data.to_string())
            } else {
                (
                    "404 Not Found",
                    json!({"error": format!("outbound '{}' not found", target_tag)}).to_string(),
                )
            }
        }
    } else if path_clean.starts_with("/api/v1/outbounds/") && (method == "PUT" || method == "POST")
    {
        // Switch the selected outbound in a group. The endpoint is documented as
        // `.../outbounds/<group>/select`; require the suffix so that an unrelated
        // future `/outbounds/<tag>/<action>` route cannot silently mutate state.
        let selector_tag = path_clean
            .strip_prefix("/api/v1/outbounds/")
            .unwrap_or("")
            .strip_suffix("/select")
            .unwrap_or("")
            .trim_matches('/');
        let parsed_body: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
        let target_name = parsed_body
            .get("name")
            .or_else(|| parsed_body.get("target"))
            .or_else(|| parsed_body.get("outbound"))
            .and_then(|n| n.as_str())
            .unwrap_or_default();

        if let Some(out) = reg.get_outbound(selector_tag) {
            match out.select(target_name) {
                Ok(()) => ("204 No Content", String::new()),
                Err(e) => (
                    "400 Bad Request",
                    json!({"error": e.to_string()}).to_string(),
                ),
            }
        } else {
            (
                "404 Not Found",
                json!({"error": format!("selector outbound '{}' not found", selector_tag)})
                    .to_string(),
            )
        }
    } else if path_clean.starts_with("/api/v1/connections") && method == "DELETE" {
        let subpath = path_clean.strip_prefix("/api/v1/connections").unwrap_or("");
        let subpath_clean = subpath.trim_start_matches('/');
        if subpath_clean.is_empty() {
            met.close_all_connections();
            ("204 No Content", String::new())
        } else {
            if met.close_connection(subpath_clean) {
                ("204 No Content", String::new())
            } else {
                (
                    "404 Not Found",
                    json!({"error": "connection not found"}).to_string(),
                )
            }
        }
    } else if path_clean == "/api/v1/connections" && method == "GET" {
        let mut conn_list = Vec::new();
        for entry in met.connections.iter() {
            let conn = entry.value();
            conn_list.push(json!({
                "id": conn.id,
                "metadata": {
                    "network": conn.meta.network.to_string(),
                    "source_ip": conn.meta.source.ip().to_string(),
                    "source_port": conn.meta.source.port(),
                    "destination_ip": conn.meta.destination.host(),
                    "destination_port": conn.meta.destination.port(),
                    "host": conn.meta.destination.host(),
                    "inbound": conn.meta.inbound_tag.as_ref()
                },
                "upload": conn.upload.load(Ordering::Relaxed),
                "download": conn.download.load(Ordering::Relaxed),
                "elapsed_ms": conn.start_time.elapsed().as_millis()
            }));
        }
        let data = json!({
            "connections": conn_list,
            "upload_total": met.upload_total.load(Ordering::Relaxed),
            "download_total": met.download_total.load(Ordering::Relaxed)
        });
        ("200 OK", data.to_string())
    } else {
        ("404 Not Found", json!({"error": "not found"}).to_string())
    };

    let cors_header = if has_external_origin {
        ""
    } else {
        "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\n"
    };

    let content_type = if path_clean == "/api/v1/metrics" {
        "text/plain; version=0.0.4; charset=utf-8"
    } else {
        "application/json"
    };
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        cors_header,
        body.len(),
        body
    );

    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.flush().await;
    let _ = socket.shutdown().await;
}
