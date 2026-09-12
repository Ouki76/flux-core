use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};
use async_trait::async_trait;
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta};
use flux_protocol::http::HttpHandshake;

pub struct HttpInbound {
    tag: String,
    listen_addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl HttpInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());

        info!("[{}] HTTP inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let (mut socket, client_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(e) => {
                        if running.load(Ordering::Relaxed) {
                            warn!("[{}] accept error: {}", tag, e);
                        }
                        break;
                    }
                };
                crate::optimize_tcp_socket(&socket);

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();

                tokio::spawn(async move {
                    let (target, prefix_opt) = match HttpHandshake::server_handshake(&mut socket).await {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("[{}] client {} HTTP handshake failed: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    let meta = SessionMeta::new(
                        client_addr,
                        target,
                        inbound_tag,
                        NetworkType::Tcp,
                    );

                    let stream: flux_types::BoxedStream = if let Some(prefix) = prefix_opt {
                        Box::new(flux_common::copy::PrefixedStream::new(socket, prefix))
                    } else {
                        Box::new(socket)
                    };

                    disp.dispatch_stream(meta, stream).await;
                });
            }
        });

        Ok(())
    }

    async fn stop(&self) -> FluxResult<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}
