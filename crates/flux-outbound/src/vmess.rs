use async_trait::async_trait;
use flux_protocol::mux::{MuxClient, MuxConfig, mux_destination};
use flux_protocol::vmess::{
    VMESS_SECURITY_AES_128_GCM, VMESS_SECURITY_CHACHA20_POLY1305, VmessProtocol, VmessStream,
};
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    StreamDialer, TargetAddress, UdpPacket,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

/// /// A VMess client.
pub struct VmessOutbound {
    tag: String,
    uuid: Uuid,
    security: u8,
    dialer: Arc<dyn StreamDialer>,
    /// Stream multiplexer, when `multiplex.enabled` is set on the node.
    mux: Option<Arc<MuxClient>>,
}

impl VmessOutbound {
    /// A client named `tag` for this UUID and security type.
    pub fn new(
        tag: impl Into<String>,
        uuid: Uuid,
        security_str: Option<&str>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        let security = match security_str
            .unwrap_or("aes-128-gcm")
            .to_ascii_lowercase()
            .as_str()
        {
            "chacha20-poly1305" | "chacha20" => VMESS_SECURITY_CHACHA20_POLY1305,
            _ => VMESS_SECURITY_AES_128_GCM,
        };

        Self {
            tag: tag.into(),
            uuid,
            security,
            dialer,
            mux: None,
        }
    }

    /// Enables multiplexing over a shared smux session.
    pub fn with_mux(mut self, config: MuxConfig) -> Self {
        let mux_dialer = Arc::new(VmessMuxDialer {
            inner: self.dialer.clone(),
            uuid: self.uuid,
            security: self.security,
        });
        self.mux = Some(MuxClient::new(mux_dialer, config));
        self
    }
}

/// Opens the physical carrier for a multiplexed session: a VMess request to the
/// reserved mux destination, wrapped in the VMess AEAD stream.
struct VmessMuxDialer {
    inner: Arc<dyn StreamDialer>,
    uuid: Uuid,
    security: u8,
}

#[async_trait]
impl StreamDialer for VmessMuxDialer {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let mut stream = self.inner.dial().await?;
        let (key, iv, resp_header) = VmessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Tcp,
            &mux_destination(),
            self.security,
        )
        .await?;
        let vmess_stream: BoxedStream = Box::new(VmessStream::new_client(
            stream,
            key,
            iv,
            self.security,
            resp_header,
            0x05,
        ));
        Ok(vmess_stream)
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "vmess"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(mux) = &self.mux {
            return mux.dial_stream(&meta.destination).await;
        }
        let mut stream = self.dialer.dial().await?;

        let (key, iv, resp_header) = VmessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Tcp,
            &meta.destination,
            self.security,
        )
        .await?;

        let vmess_stream =
            VmessStream::new_client(stream, key, iv, self.security, resp_header, 0x05);
        Ok(Box::new(vmess_stream))
    }

    fn udp_endpoint_per_destination(&self) -> bool {
        // VMess UDP frames are `[len][payload]` on a stream bound to the
        // destination in the request header: one association per destination.
        true
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        if let Some(mux) = &self.mux {
            return mux.dial_packet(&meta.destination).await;
        }
        let mut stream = self.dialer.dial().await?;

        let (key, iv, resp_header) = VmessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Udp,
            &meta.destination,
            self.security,
        )
        .await?;

        let vmess_stream: BoxedStream = Box::new(VmessStream::new_client(
            stream,
            key,
            iv,
            self.security,
            resp_header,
            0x05,
        ));
        let (reader, writer) = tokio::io::split(vmess_stream);

        Ok(Box::new(VmessPacketEndpoint {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            destination: meta.destination.clone(),
        }))
    }
}

/// /// A UDP association over VMess.
pub struct VmessPacketEndpoint {
    reader: Arc<Mutex<tokio::io::ReadHalf<BoxedStream>>>,
    writer: Arc<Mutex<tokio::io::WriteHalf<BoxedStream>>>,
    destination: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for VmessPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let payload_len = packet.payload.len() as u16;
        let mut frame = Vec::with_capacity(2 + packet.payload.len());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&packet.payload);

        let mut guard = self.writer.lock().await;
        guard.write_all(&frame).await.map_err(FluxError::Io)?;
        guard.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.reader.lock().await;

        let mut len_buf = [0u8; 2];
        guard
            .read_exact(&mut len_buf)
            .await
            .map_err(FluxError::Io)?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;

        let mut payload = vec![0u8; payload_len];
        guard
            .read_exact(&mut payload)
            .await
            .map_err(FluxError::Io)?;

        Ok(UdpPacket::new(
            payload.into(),
            self.destination.clone(),
            self.destination.clone(),
        ))
    }
}
