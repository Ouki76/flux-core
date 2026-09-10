use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;
use async_trait::async_trait;
use flux_types::{
    BoxedStream, Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use flux_protocol::vless::{VlessProtocol, VLESS_CMD_TCP};

pub struct VlessInbound {
    tag: String,
    listen_addr: SocketAddr,
    uuids: Vec<Uuid>,
    tls_acceptor: Option<TlsAcceptor>,
    reality_config: Option<flux_transport::reality::RealityServerConfig>,
    running: Arc<AtomicBool>,
}

impl VlessInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        uuids: Vec<Uuid>,
        tls_acceptor: Option<TlsAcceptor>,
        reality_config: Option<flux_transport::reality::RealityServerConfig>,
    ) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            uuids,
            tls_acceptor,
            reality_config,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let uuids = self.uuids.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let reality_config = self.reality_config.clone();

        info!("[{}] VLESS inbound listening on {}", tag, self.listen_addr);

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
                let _ = socket.set_nodelay(true);

                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let uuids = uuids.clone();
                let acceptor = tls_acceptor.clone();
                let reality_cfg = reality_config.clone();

                tokio::spawn(async move {
                    let mut stream: BoxedStream = if let Some(r_cfg) = reality_cfg {
                        match flux_transport::reality::RealityHandshake::server_handshake(&mut socket, &r_cfg).await {
                            Ok(_) => Box::new(socket),
                            Err(e) => {
                                warn!("[{}] Reality handshake failed from {}: {}", inbound_tag, client_addr, e);
                                return;
                            }
                        }
                    } else if let Some(tls) = acceptor {
                        match tls.accept(socket).await {
                            Ok(s) => Box::new(s),
                            Err(e) => {
                                warn!("[{}] TLS handshake error from {}: {}", inbound_tag, client_addr, e);
                                return;
                            }
                        }
                    } else {
                        Box::new(socket)
                    };

                    let req = match VlessProtocol::read_request_header(&mut stream, &uuids).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("[{}] VLESS handshake failed from {}: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    if req.command != VLESS_CMD_TCP {
                        warn!("[{}] VLESS unsupported command: {}", inbound_tag, req.command);
                        return;
                    }

                    if let Err(e) = VlessProtocol::write_response_header(&mut stream).await {
                        warn!("[{}] VLESS write response header failed: {}", inbound_tag, e);
                        return;
                    }

                    let meta = SessionMeta::new(
                        client_addr,
                        req.address,
                        inbound_tag,
                        NetworkType::Tcp,
                    );

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
