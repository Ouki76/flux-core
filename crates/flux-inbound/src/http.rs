use async_trait::async_trait;
use flux_protocol::http::HttpHandshake;
use flux_types::{Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

pub struct HttpInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<(String, String)>,
    pipeline: flux_transport::pipeline::ServerTransportPipeline,
    rate_limiter: Option<Arc<flux_common::RateLimiter>>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl HttpInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users: vec![],
            pipeline: flux_transport::pipeline::ServerTransportPipeline::raw(),
            rate_limiter: None,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<flux_common::RateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    pub fn with_users(mut self, users: Vec<(String, String)>) -> Self {
        self.users = users;
        self
    }

    pub fn with_pipeline(
        mut self,
        pipe: flux_transport::pipeline::ServerTransportPipeline,
    ) -> Self {
        self.pipeline = pipe;
        self
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "http"
    }

    fn listen_addr(&self) -> Option<String> {
        Some(self.listen_addr.to_string())
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = crate::create_reuse_port_listener(self.listen_addr)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let users = Arc::new(self.users.clone());
        let pipeline = Arc::new(self.pipeline.clone());
        let rate_limiter = self.rate_limiter.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] HTTP inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok(res) => res,
                            Err(e) => {
                                if running.load(Ordering::Relaxed) {
                                    warn!("[{}] accept error: {}", tag, e);
                                }
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("[{}] HTTP listener shutting down cleanly", tag);
                        break;
                    }
                };
                // Rate limiting: reject before any per-connection work.
                let conn_guard = match &rate_limiter {
                    Some(rl) => match rl.try_acquire(client_addr.ip()) {
                        Some(g) => Some(g),
                        None => {
                            debug!(
                                "[{}] connection from {} rejected by rate limiter",
                                tag, client_addr
                            );
                            continue;
                        }
                    },
                    None => None,
                };
                crate::optimize_tcp_socket(&socket);

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();
                let pipe = pipeline.clone();

                tokio::spawn(async move {
                    let _conn_guard = conn_guard;
                    let mut stream = match pipe.unwrap(socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "[{}] client {} HTTP transport handshake failed: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                    };

                    let handshake_fut =
                        HttpHandshake::server_handshake_with_auth(&mut stream, Some(&user_list));
                    let (target, prefix_opt, auth_user) = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        handshake_fut,
                    )
                    .await
                    {
                        Ok(Ok(t)) => t,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] client {} HTTP handshake failed: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "[{}] client {} HTTP handshake timed out",
                                inbound_tag, client_addr
                            );
                            return;
                        }
                    };

                    let mut meta =
                        SessionMeta::new(client_addr, target, inbound_tag, NetworkType::Tcp);
                    if let Some(u) = auth_user {
                        meta = meta.with_user(u);
                    }

                    let stream: flux_types::BoxedStream = if let Some(prefix) = prefix_opt {
                        Box::new(flux_common::copy::PrefixedStream::new(stream, prefix))
                    } else {
                        stream
                    };

                    disp.dispatch_stream(meta, stream).await;
                });
            }
        });

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
        Ok(())
    }
}
