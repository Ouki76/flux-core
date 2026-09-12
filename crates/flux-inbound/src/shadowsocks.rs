use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};
use async_trait::async_trait;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, NetworkType, SessionMeta,
};
use flux_protocol::socks5::Socks5Handshake;
use flux_protocol::shadowsocks::{
    derive_master_key, derive_subkey, ShadowsocksCipher, ShadowsocksStream, SALT_LEN, TAG_LEN,
};

pub struct ShadowsocksInbound {
    tag: String,
    listen_addr: SocketAddr,
    master_key: [u8; 32],
    running: Arc<AtomicBool>,
}

impl ShadowsocksInbound {
    pub fn new(
        tag: impl Into<String>,
        listen_addr: SocketAddr,
        password: &str,
    ) -> Self {
        Self {
            tag: tag.into(),
            listen_addr,
            master_key: derive_master_key(password),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Inbound for ShadowsocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self, dispatcher: Arc<dyn Dispatcher>) -> FluxResult<()> {
        let listener = TcpListener::bind(self.listen_addr).await.map_err(FluxError::Io)?;

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let tag: Arc<str> = Arc::from(self.tag.as_str());
        let master_key = self.master_key;

        info!("[{}] Shadowsocks AEAD inbound listening on {}", tag, self.listen_addr);

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
                    // 1. Read client salt
                    let mut salt = [0u8; SALT_LEN];
                    if let Err(e) = socket.read_exact(&mut salt).await {
                        warn!("[{}] failed to read SS client salt: {}", inbound_tag, e);
                        return;
                    }

                    // 2. Derive subkey & cipher
                    let subkey = derive_subkey(&master_key, &salt);
                    let mut dec = ShadowsocksCipher::new(&subkey);

                    // 3. Read encrypted payload length (2 bytes + 16 bytes tag)
                    let mut enc_len = [0u8; 2 + TAG_LEN];
                    if let Err(e) = socket.read_exact(&mut enc_len).await {
                        warn!("[{}] failed to read SS payload len: {}", inbound_tag, e);
                        return;
                    }

                    let len_bytes = match dec.decrypt(&enc_len) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("[{}] SS len decrypt failed: {}", inbound_tag, e);
                            return;
                        }
                    };
                    let payload_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

                    // 4. Read encrypted payload (address)
                    let mut enc_payload = vec![0u8; payload_len + TAG_LEN];
                    if let Err(e) = socket.read_exact(&mut enc_payload).await {
                        warn!("[{}] failed to read SS payload: {}", inbound_tag, e);
                        return;
                    }

                    let payload = match dec.decrypt(&enc_payload) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("[{}] SS payload decrypt failed: {}", inbound_tag, e);
                            return;
                        }
                    };

                    // Parse SOCKS5 address
                    if payload.is_empty() {
                        return;
                    }
                    let atyp = payload[0];
                    let mut cursor = std::io::Cursor::new(&payload[1..]);
                    let target = match Socks5Handshake::read_address(&mut cursor, atyp).await {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("[{}] SS target address parse error: {}", inbound_tag, e);
                            return;
                        }
                    };

                    let meta = SessionMeta::new(
                        client_addr,
                        target,
                        inbound_tag,
                        NetworkType::Tcp,
                    );

                    // Generate server salt and prepare server encoder
                    let mut server_salt = [0u8; SALT_LEN];
                    rand::thread_rng().fill_bytes(&mut server_salt);
                    if socket.write_all(&server_salt).await.is_err() {
                        return;
                    }
                    let server_subkey = derive_subkey(&master_key, &server_salt);
                    let server_enc = ShadowsocksCipher::new(&server_subkey);

                    let ss_stream = ShadowsocksStream::new(socket, server_enc, Some(dec), master_key);

                    disp.dispatch_stream(meta, Box::new(ss_stream)).await;
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
