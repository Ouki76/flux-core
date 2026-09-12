use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::info;
use serde_json::json;
use flux_types::FluxResult;
use crate::instance::OutboundRegistry;

#[derive(Default)]
pub struct TrafficMeter {
    pub upload_total: AtomicU64,
    pub download_total: AtomicU64,
    pub upload_speed: AtomicU64,
    pub download_speed: AtomicU64,
}

impl TrafficMeter {
    pub fn new() -> Arc<Self> {
        let this = Arc::new(Self::default());
        let meter = this.clone();
        tokio::spawn(async move {
            let mut last_up = 0u64;
            let mut last_down = 0u64;
            loop {
                sleep(Duration::from_secs(1)).await;
                let cur_up = meter.upload_total.load(Ordering::Relaxed);
                let cur_down = meter.download_total.load(Ordering::Relaxed);

                meter.upload_speed.store(cur_up.saturating_sub(last_up), Ordering::Relaxed);
                meter.download_speed.store(cur_down.saturating_sub(last_down), Ordering::Relaxed);

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
}

pub struct ApiServer {
    listen_addr: SocketAddr,
    registry: Arc<OutboundRegistry>,
    meter: Arc<TrafficMeter>,
    running: Arc<AtomicBool>,
}

impl ApiServer {
    pub fn new(
        listen_addr: SocketAddr,
        registry: Arc<OutboundRegistry>,
        meter: Arc<TrafficMeter>,
    ) -> Self {
        Self {
            listen_addr,
            registry,
            meter,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start(&self) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(flux_types::FluxError::Io)?;
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let registry = self.registry.clone();
        let meter = self.meter.clone();

        info!("Clash REST API server listening on http://{}", self.listen_addr);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => break,
                };

                let reg = registry.clone();
                let met = meter.clone();

                tokio::spawn(async move {
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
                    let mut lines = header_str.lines();
                    let first_line = lines.next().unwrap_or("");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("GET").to_string();
                    let uri = parts.next().unwrap_or("/").to_string();

                    // Parse Content-Length
                    let mut content_length = 0usize;
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':')
                            && k.trim().eq_ignore_ascii_case("content-length")
                        {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }

                    // 2. Read remaining body if not yet fully in buffer
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

                    let (status, body) = if method == "OPTIONS" {
                        ("200 OK", String::new())
                    } else if uri == "/" || uri == "/version" {
                        let data = json!({ "version": "flux-core 0.1.0" });
                        ("200 OK", data.to_string())
                    } else if uri == "/traffic" {
                        let data = json!({
                            "up": met.upload_speed.load(Ordering::Relaxed),
                            "down": met.download_speed.load(Ordering::Relaxed)
                        });
                        ("200 OK", data.to_string())
                    } else if uri == "/proxies" && method == "GET" {
                        let mut proxies = serde_json::Map::new();
                        // Iterate through known outbounds with group introspection
                        for entry in reg.map.iter() {
                            let tag = entry.key();
                            let outbound = entry.value();
                            if outbound.is_group() {
                                proxies.insert(
                                    tag.clone(),
                                    json!({
                                        "name": tag,
                                        "type": outbound.group_type().unwrap_or("Selector"),
                                        "now": outbound.current_selected().unwrap_or_default(),
                                        "all": outbound.candidate_outbounds(),
                                        "history": []
                                    }),
                                );
                            } else {
                                proxies.insert(
                                    tag.clone(),
                                    json!({
                                        "name": tag,
                                        "type": "Outbound",
                                        "history": []
                                    }),
                                );
                            }
                        }
                        let resp = json!({ "proxies": proxies });
                        ("200 OK", resp.to_string())
                    } else if uri.starts_with("/proxies/") && method == "PUT" {
                        let selector_tag = uri.strip_prefix("/proxies/").unwrap_or("");
                        let target_name = serde_json::from_str::<serde_json::Value>(&body_str)
                            .ok()
                            .and_then(|v| v.get("name").and_then(|n| n.as_str().map(String::from)))
                            .unwrap_or_default();

                        if let Some(out) = reg.get_outbound(selector_tag) {
                            match out.select(&target_name) {
                                Ok(()) => ("204 No Content", String::new()),
                                Err(e) => ("400 Bad Request", json!({"error": e.to_string()}).to_string()),
                            }
                        } else {
                            ("404 Not Found", json!({"error": format!("selector '{}' not found", selector_tag)}).to_string())
                        }
                    } else if uri == "/connections" {
                        let data = json!({
                            "connections": [],
                            "uploadTotal": met.upload_total.load(Ordering::Relaxed),
                            "downloadTotal": met.download_total.load(Ordering::Relaxed)
                        });
                        ("200 OK", data.to_string())
                    } else {
                        ("404 Not Found", json!({"error": "not found"}).to_string())
                    };

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );

                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}
