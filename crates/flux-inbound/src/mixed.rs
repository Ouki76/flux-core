use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};
use async_trait::async_trait;
use flux_types::{Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta};
use flux_protocol::socks5::{Socks5Command, Socks5Handshake, REP_SUCCESS};
use flux_protocol::http::HttpHandshake;

pub struct MixedInbound {
    tag: String,
    listen_addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl MixedInbound {
    pub fn new(tag: impl Into<String>, listen_addr: SocketAddr) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for MixedInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());

        info!("[{}] Mixed (SOCKS5/HTTP) inbound listening on {}", tag, self.listen_addr);

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
                    // Peek the first byte to detect protocol
                    let mut peek_buf = [0u8; 1];
                    let n = match socket.peek(&mut peek_buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            warn!("[{}] client {} peek failed: {}", inbound_tag, client_addr, e);
                            return;
                        }
                    };
                    if n == 0 {
                        return;
                    }

                    if peek_buf[0] == 0x05 {
                        // SOCKS5
                        if let Err(e) = Socks5Handshake::server_handshake(&mut socket).await {
                            warn!("[{}] SOCKS5 handshake failed: {}", inbound_tag, e);
                            return;
                        }
                        let req = match Socks5Handshake::read_request(&mut socket).await {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("[{}] SOCKS5 read request failed: {}", inbound_tag, e);
                                return;
                            }
                        };

                        if req.command == Socks5Command::Connect {
                            let meta = SessionMeta::new(
                                client_addr,
                                req.address,
                                inbound_tag.clone(),
                                NetworkType::Tcp,
                            );

                            let outbound_stream = match disp.dial_outbound(&meta).await {
                                Ok(s) => s,
                                Err(FluxError::Blocked(msg)) => {
                                    warn!("[{}] connection to {} blocked: {}", inbound_tag, meta.destination, msg);
                                    let _ = Socks5Handshake::send_reply(&mut socket, 0x02, None).await;
                                    return;
                                }
                                Err(e) => {
                                    warn!("[{}] connection to {} failed: {}", inbound_tag, meta.destination, e);
                                    let _ = Socks5Handshake::send_reply(&mut socket, 0x05, None).await;
                                    return;
                                }
                            };

                            if let Err(e) = Socks5Handshake::send_reply(&mut socket, REP_SUCCESS, None).await {
                                warn!("[{}] SOCKS5 send reply failed: {}", inbound_tag, e);
                                return;
                            }

                            disp.bridge_streams(meta, Box::new(socket), outbound_stream).await;
                        } else {
                            warn!("[{}] non-CONNECT not supported in mixed TCP mode", inbound_tag);
                        }
                    } else {
                        // HTTP proxy
                        let (target, prefix_opt) = match HttpHandshake::server_handshake(&mut socket).await {
                            Ok(t) => t,
                            Err(e) => {
                                warn!("[{}] HTTP handshake failed: {}", inbound_tag, e);
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
                    }
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
