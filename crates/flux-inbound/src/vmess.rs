use async_trait::async_trait;
use flux_protocol::vmess::{VMESS_CMD_UDP, VmessProtocol, VmessStream};
use flux_types::{BoxedStream, Dispatcher, FluxResult, Inbound, NetworkType, SessionMeta};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;

pub struct VmessInbound {
    tag: String,
    listen_addr: SocketAddr,
    users: Vec<Uuid>,
    tls_acceptor: Option<TlsAcceptor>,
    running: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl VmessInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        users: Vec<Uuid>,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tag: tag.into(),
            listen_addr,
            users,
            tls_acceptor,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }
}

#[async_trait]
impl Inbound for VmessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "vmess"
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
        let tls_acceptor = self.tls_acceptor.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("[{}] VMess inbound listening on {}", tag, self.listen_addr);

        tokio::spawn(async move {
            loop {
                let (socket, client_addr) = tokio::select! {
                    res = listener.accept() => match res {
                        Ok(res) => res,
                        Err(e) => {
                            if running.load(Ordering::Relaxed) {
                                warn!("[{}] VMess accept error: {}", tag, e);
                            }
                            break;
                        }
                    },
                    _ = shutdown_rx.recv() => break,
                };

                crate::optimize_tcp_socket(&socket);
                let disp = dispatcher.clone();
                let inbound_tag = tag.clone();
                let user_list = users.clone();
                let acceptor_opt = tls_acceptor.clone();

                tokio::spawn(async move {
                    let mut stream: BoxedStream = if let Some(ref acceptor) = acceptor_opt {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            acceptor.accept(socket),
                        )
                        .await
                        {
                            Ok(Ok(tls_stream)) => Box::new(tls_stream),
                            Ok(Err(e)) => {
                                warn!(
                                    "[{}] TLS handshake failed from {}: {}",
                                    inbound_tag, client_addr, e
                                );
                                return;
                            }
                            Err(_) => {
                                warn!(
                                    "[{}] TLS handshake timed out from {}",
                                    inbound_tag, client_addr
                                );
                                return;
                            }
                        }
                    } else {
                        Box::new(socket)
                    };

                    let req = match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        VmessProtocol::read_request_header(&mut stream, &user_list),
                    )
                    .await
                    {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            warn!(
                                "[{}] VMess header failed from {}: {}",
                                inbound_tag, client_addr, e
                            );
                            return;
                        }
                        Err(_) => {
                            warn!(
                                "[{}] VMess header timed out from {}",
                                inbound_tag, client_addr
                            );
                            return;
                        }
                    };

                    let network = if req.command == VMESS_CMD_UDP {
                        NetworkType::Udp
                    } else {
                        NetworkType::Tcp
                    };

                    let meta = SessionMeta::new(
                        client_addr,
                        req.address.clone(),
                        inbound_tag.clone(),
                        network,
                    );

                    let vmess_stream = VmessStream::new_server(
                        stream,
                        req.session_key,
                        req.session_iv,
                        req.security,
                    );

                    disp.dispatch_stream(meta, Box::new(vmess_stream)).await;
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
