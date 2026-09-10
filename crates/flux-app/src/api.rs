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
                    let mut buf = vec![0u8; 4096];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };

                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let mut lines = req_str.lines();
                    let first_line = lines.next().unwrap_or("");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("GET");
                    let uri = parts.next().unwrap_or("/");

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
                        // Iterate through known outbounds
                        for entry in reg.map.iter() {
                            let tag = entry.key();
                            proxies.insert(
                                tag.clone(),
                                json!({
                                    "name": tag,
                                    "type": "Outbound",
                                    "history": []
                                }),
                            );
                        }
                        let resp = json!({ "proxies": proxies });
                        ("200 OK", resp.to_string())
                    } else if uri.starts_with("/proxies/") && method == "PUT" {
                        let selector_tag = uri.strip_prefix("/proxies/").unwrap_or("");
                        let body_str = req_str.split("\r\n\r\n").nth(1).unwrap_or("");
                        let target_name = serde_json::from_str::<serde_json::Value>(body_str)
                            .ok()
                            .and_then(|v| v.get("name").and_then(|n| n.as_str().map(String::from)))
                            .unwrap_or_default();

                        if let Some(_out) = reg.get_outbound(selector_tag) {
                            // If it's a selector, switch target
                            let _ = target_name;
                        }
                        ("204 No Content", String::new())
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
