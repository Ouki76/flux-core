use async_trait::async_trait;
use flux_protocol::mux::{MuxClient, MuxConfig, mux_destination};
use flux_protocol::udp::{decode_vless_udp_packet, encode_vless_udp_packet};
use flux_protocol::vless::{VLESS_VERSION, VlessProtocol};
use flux_types::{
    BoxedStream, FluxError, FluxResult, NetworkType, Outbound, PacketEndpoint, SessionMeta,
    StreamDialer, TargetAddress, UdpPacket,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

/// /// A VLESS client.
pub struct VlessOutbound {
    tag: String,
    uuid: Uuid,
    flow: Option<String>,
    dialer: Arc<dyn StreamDialer>,
    /// Stream multiplexer, when `multiplex.enabled` is set on the node.
    mux: Option<Arc<MuxClient>>,
}

impl VlessOutbound {
    /// A client named `tag` for this UUID, optionally using Vision.
    pub fn new(
        tag: impl Into<String>,
        uuid: Uuid,
        flow: Option<String>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            uuid,
            flow,
            dialer,
            mux: None,
        }
    }

    /// Enables multiplexing: every dialled stream is tunnelled over a shared
    /// smux session instead of its own connection.
    pub fn with_mux(mut self, config: MuxConfig) -> FluxResult<Self> {
        if self.flow.as_deref() == Some(flux_protocol::vision::VISION_FLOW) {
            return Err(FluxError::Config(
                "multiplex is incompatible with the vless flow 'xtls-rprx-vision'".into(),
            ));
        }
        let mux_dialer = Arc::new(VlessMuxDialer {
            inner: self.dialer.clone(),
            uuid: self.uuid,
        });
        self.mux = Some(MuxClient::new(mux_dialer, config));
        Ok(self)
    }
}

/// Opens the physical carrier for a multiplexed session: a VLESS request to the
/// reserved mux destination (exactly what sing-box sends).
struct VlessMuxDialer {
    inner: Arc<dyn StreamDialer>,
    uuid: Uuid,
}

#[async_trait]
impl StreamDialer for VlessMuxDialer {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let mut stream = self.inner.dial().await?;
        VlessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Tcp,
            &mux_destination(),
            None,
        )
        .await?;
        // The VLESS server answers with its own header before any payload; the
        // mux session must only ever see the tunnel bytes.
        Ok(Box::new(flux_protocol::vless::VlessClientStream::new(
            stream,
        )))
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "vless"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(mux) = &self.mux {
            return mux.dial_stream(&meta.destination).await;
        }
        let mut stream = self.dialer.dial().await?;

        VlessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Tcp,
            &meta.destination,
            self.flow.as_deref(),
        )
        .await?;

        let client_stream = flux_protocol::vless::VlessClientStream::new(stream);
        if self.flow.as_deref() == Some(flux_protocol::vision::VISION_FLOW) {
            // Vision wraps the tunnel after the VLESS header: both directions are
            // padded until the TLS handshake finishes, and the 16-byte frame
            // prefix must be the user's UUID.
            Ok(Box::new(flux_protocol::vision::VisionStream::new(
                client_stream,
                *self.uuid.as_bytes(),
            )))
        } else {
            Ok(Box::new(client_stream))
        }
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        if let Some(mux) = &self.mux {
            return mux.dial_packet(&meta.destination).await;
        }
        let mut stream = self.dialer.dial().await?;

        VlessProtocol::write_request_header(
            &mut stream,
            &self.uuid,
            NetworkType::Udp,
            &meta.destination,
            None,
        )
        .await?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Box::new(VlessPacketEndpoint {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            header_stripped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            destination: meta.destination.clone(),
        }))
    }
}

/// /// A UDP association over VLESS packet-address mode.
pub struct VlessPacketEndpoint {
    reader: Arc<Mutex<tokio::io::ReadHalf<BoxedStream>>>,
    writer: Arc<Mutex<tokio::io::WriteHalf<BoxedStream>>>,
    header_stripped: Arc<std::sync::atomic::AtomicBool>,
    destination: TargetAddress,
}

#[async_trait]
impl PacketEndpoint for VlessPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let encoded = encode_vless_udp_packet(&packet);
        let mut guard = self.writer.lock().await;
        guard.write_all(&encoded).await.map_err(FluxError::Io)?;
        guard.flush().await.map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.reader.lock().await;

        // Strip the 2-byte VLESS response header [version, addon_len] on the first packet
        if !self
            .header_stripped
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let mut header = [0u8; 2];
            guard.read_exact(&mut header).await.map_err(FluxError::Io)?;
            if header[0] != VLESS_VERSION {
                return Err(FluxError::Protocol {
                    protocol: "vless",
                    message: format!("unexpected vless response version: {}", header[0]),
                });
            }
            let addon_len = header[1] as usize;
            if addon_len > 0 {
                let mut drain = vec![0u8; addon_len];
                guard.read_exact(&mut drain).await.map_err(FluxError::Io)?;
            }
            self.header_stripped
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        decode_vless_udp_packet(&mut *guard, &self.destination).await
    }
}
