use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use async_trait::async_trait;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use flux_protocol::trojan::{hash_trojan_password, TrojanProtocol, TROJAN_CMD_CONNECT};

pub struct TrojanInbound {
    tag: String,
    listen_addr: SocketAddr,
    password_hashes: Vec<String>,
    tls_acceptor: TlsAcceptor,
    running: Arc<AtomicBool>,
}

impl TrojanInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        passwords: Vec<String>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        let password_hashes = passwords.into_iter().map(|p| hash_trojan_password(&p)).collect();
        Self {
            tag: tag.into(),
            listen_addr,
            password_hashes,
            tls_acceptor,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let hashes = self.password_hashes.clone();
        let acceptor = self.tls_acceptor.clone();

        info!("[{}] Trojan inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let (socket, client_addr) = match listener.accept().await {
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
                let valid_hashes = hashes.clone();
                let tls = acceptor.clone();

                tokio::spawn(async move {
                    let mut tls_stream = match tls.accept(socket).await {
                        Ok(s) => Box::new(s),
                        Err(e) => {
                            warn!("[{}] TLS handshake error from {}: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    let (cmd, target) = match TrojanProtocol::read_request_header(&mut tls_stream, &valid_hashes).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("[{}] Trojan auth/request failed from {}: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };

                    if cmd != TROJAN_CMD_CONNECT {
                        warn!("[{}] Trojan UDP over TCP not supported", inbound_tag);
                        return;
                    }

                    let meta = SessionMeta::new(
                        client_addr,
                        target,
                        inbound_tag,
                        NetworkType::Tcp,
                    );

                    disp.dispatch_stream(meta, tls_stream).await;
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
