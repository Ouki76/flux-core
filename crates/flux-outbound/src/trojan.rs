use async_trait::async_trait;
use flux_protocol::mux::{MuxClient, MuxConfig, mux_destination};
use flux_protocol::socks5::Socks5Handshake;
use flux_protocol::trojan::TrojanProtocol;
use flux_protocol::udp::encode_trojan_udp;
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    StreamDialer, TargetAddress, UdpPacket,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// /// A Trojan client.
pub struct TrojanOutbound {
    tag: String,
    password_hash: String,
    dialer: Arc<dyn StreamDialer>,
    /// Stream multiplexer, when `multiplex.enabled` is set on the node.
    mux: Option<Arc<MuxClient>>,
}

impl TrojanOutbound {
    /// A client named `tag` with this password.
    pub fn new(
        tag: impl Into<String>,
        password: impl Into<String>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        let password_str = password.into();
        let password_hash = flux_protocol::trojan::hash_trojan_password(&password_str);
        Self {
            tag: tag.into(),
            password_hash,
            dialer,
            mux: None,
        }
    }

    /// Enables multiplexing over a shared smux session.
    pub fn with_mux(mut self, config: MuxConfig) -> Self {
        let mux_dialer = Arc::new(TrojanMuxDialer {
            inner: self.dialer.clone(),
            password_hash: self.password_hash.clone(),
        });
        self.mux = Some(MuxClient::new(mux_dialer, config));
        self
    }
}

/// Opens the physical carrier for a multiplexed session.
struct TrojanMuxDialer {
    inner: Arc<dyn StreamDialer>,
    password_hash: String,
}

#[async_trait]
impl StreamDialer for TrojanMuxDialer {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let mut stream = self.inner.dial().await?;
        TrojanProtocol::write_request_header_with_hash(
            &mut stream,
            &self.password_hash,
            NetworkType::Tcp,
            &mux_destination(),
        )
        .await?;
        Ok(stream)
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "trojan"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(mux) = &self.mux {
            return mux.dial_stream(&meta.destination).await;
        }
        let mut stream = self.dialer.dial().await?;

        TrojanProtocol::write_request_header_with_hash(
            &mut stream,
            &self.password_hash,
            NetworkType::Tcp,
            &meta.destination,
        )
        .await?;

        Ok(stream)
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        if let Some(mux) = &self.mux {
            return mux.dial_packet(&meta.destination).await;
        }
        let mut stream = self.dialer.dial().await?;

        TrojanProtocol::write_request_header_with_hash(
            &mut stream,
            &self.password_hash,
            NetworkType::Udp,
            &meta.destination,
        )
        .await?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Box::new(TrojanPacketEndpoint {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            _server_target: meta.destination.clone(),
        }))
    }
}

/// /// A UDP association over Trojan.
pub struct TrojanPacketEndpoint {
    reader: Arc<Mutex<tokio::io::ReadHalf<BoxedStream>>>,
    writer: Arc<Mutex<tokio::io::WriteHalf<BoxedStream>>>,
    _server_target: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for TrojanPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let encoded = encode_trojan_udp(&packet);
        let mut guard = self.writer.lock().await;
        guard.write_all(&encoded).await.map_err(FluxError::Io)?;
        guard.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.reader.lock().await;

        let mut atyp_buf = [0u8; 1];
        guard
            .read_exact(&mut atyp_buf)
            .await
            .map_err(FluxError::Io)?;
        let target = Socks5Handshake::read_address(&mut *guard, atyp_buf[0]).await?;

        let mut len_buf = [0u8; 2];
        guard
            .read_exact(&mut len_buf)
            .await
            .map_err(FluxError::Io)?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;
        if payload_len > 65507 {
            return Err(FluxError::Protocol {
                protocol: "trojan",
                message: format!(
                    "trojan UDP payload size {} exceeds 65507 bytes",
                    payload_len
                ),
            });
        }

        let mut crlf = [0u8; 2];
        guard.read_exact(&mut crlf).await.map_err(FluxError::Io)?;

        let mut payload = vec![0u8; payload_len];
        guard
            .read_exact(&mut payload)
            .await
            .map_err(FluxError::Io)?;

        Ok(UdpPacket::new(payload.into(), target.clone(), target))
    }
}
