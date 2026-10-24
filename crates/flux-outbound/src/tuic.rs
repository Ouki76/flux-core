use async_trait::async_trait;
use dashmap::DashMap;
use flux_protocol::tuic::TuicV5Config;
use flux_protocol::tuic::TuicV5Protocol;
use flux_transport::quic::QuicTransport;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

/// Per-connection UDP-over-datagram demultiplexer state.
struct DatagramDemux {
    sessions: DashMap<u16, mpsc::Sender<UdpPacket>>,
}

/// /// A TUIC v5 client.
pub struct TuicOutbound {
    tag: String,
    config: TuicV5Config,
    resolver: Arc<flux_dns::DnsResolver>,
    endpoint: Arc<Mutex<Option<quinn::Endpoint>>>,
    connection: Arc<Mutex<Option<quinn::Connection>>>,
    demux: Arc<Mutex<Option<Arc<DatagramDemux>>>>,
    next_session_id: Arc<AtomicU16>,
    dialer: Option<Arc<dyn flux_types::StreamDialer>>,
}

impl TuicOutbound {
    /// A client for `config`.
    pub fn new(
        tag: impl Into<String>,
        config: TuicV5Config,
        resolver: Arc<flux_dns::DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            config,
            resolver,
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
            demux: Arc::new(Mutex::new(None)),
            next_session_id: Arc::new(AtomicU16::new(1)),
            dialer: None,
        }
    }

    /// For layered transports (e.g. TUIC over TCP+Reality): delegate stream
    /// establishment to the underlying dialer instead of raw QUIC.
    pub fn new_with_dialer(
        tag: impl Into<String>,
        config: TuicV5Config,
        dialer: Arc<dyn flux_types::StreamDialer>,
    ) -> Self {
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));
        Self {
            tag: tag.into(),
            config,
            resolver,
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
            demux: Arc::new(Mutex::new(None)),
            next_session_id: Arc::new(AtomicU16::new(1)),
            dialer: Some(dialer),
        }
    }

    /// Connects and authenticates (TUIC v5: AUTHENTICATE on a dedicated
    /// unidirectional stream, token = TLS ExportKeyingMaterial).
    async fn get_connection(&self) -> FluxResult<quinn::Connection> {
        let peer_addr = self
            .resolver
            .resolve_domain(&self.config.server, self.config.server_port)
            .await?;

        let mut conn_guard = self.connection.lock().await;
        if let Some(ref conn) = *conn_guard
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }

        let mut ep_guard = self.endpoint.lock().await;
        let endpoint = if let Some(ref ep) = *ep_guard
            && ep
                .local_addr()
                .map(|a| a.is_ipv6() == peer_addr.is_ipv6())
                .unwrap_or(false)
        {
            ep.clone()
        } else {
            let alpn: Vec<Vec<u8>> = self
                .config
                .alpn
                .clone()
                .map(|v| v.into_iter().map(|s| s.into_bytes()).collect())
                .unwrap_or_else(|| vec![b"tuic".to_vec(), b"tuic-v5".to_vec(), b"h3".to_vec()]);
            let ep = QuicTransport::create_client_endpoint_with_ca(
                peer_addr.is_ipv6(),
                alpn,
                self.config.insecure,
                &self.config.ca_certs,
            )?;
            *ep_guard = Some(ep.clone());
            ep
        };

        let sni = self
            .config
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let conn = QuicTransport::connect(&endpoint, peer_addr, sni).await?;

        // Authenticate: dedicated unidirectional stream with the EKM token.
        let mut token = [0u8; 32];
        conn.export_keying_material(
            &mut token,
            self.config.uuid.as_bytes(),
            self.config.password.as_bytes(),
        )
        .map_err(|e| {
            FluxError::Crypto(format!("tuic TLS export_keying_material failed: {:?}", e))
        })?;
        let auth_frame = TuicV5Protocol::build_auth_frame(&self.config.uuid, &token);
        let mut uni = conn.open_uni().await.map_err(|e| {
            FluxError::Network(format!("tuic failed to open auth uni-stream: {}", e))
        })?;
        uni.write_all(&auth_frame)
            .await
            .map_err(|e| FluxError::Network(format!("tuic auth write: {}", e)))?;
        uni.finish()
            .map_err(|e| FluxError::Network(format!("tuic auth finish: {:?}", e)))?;

        // Fresh connection → fresh datagram demultiplexer.
        let demux = Arc::new(DatagramDemux {
            sessions: DashMap::new(),
        });
        {
            let mut d = self.demux.lock().await;
            *d = Some(demux.clone());
        }
        {
            let conn_c = conn.clone();
            let demux_c = demux.clone();
            let tag = self.tag.clone();
            tokio::spawn(async move {
                loop {
                    match conn_c.read_datagram().await {
                        Ok(dgram) => {
                            if let Ok((session_id, _pid, addr, payload)) =
                                TuicV5Protocol::parse_packet_frame(&dgram)
                                && let Some(tx) = demux_c.sessions.get(&session_id)
                            {
                                let pkt = UdpPacket::new(payload.into(), addr.clone(), addr);
                                let _ = tx.try_send(pkt);
                            }
                        }
                        Err(e) => {
                            debug!("[{}] tuic datagram reader closed: {}", tag, e);
                            break;
                        }
                    }
                }
            });
        }

        *conn_guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "tuic"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(ref d) = self.dialer {
            // Layered mode (TUIC frames over an arbitrary stream transport):
            // timestamped AUTH frame, then the CONNECT command. The token covers
            // the timestamp, so a captured frame cannot be replayed.
            let mut stream = d.dial().await?;
            let auth_frame =
                TuicV5Protocol::build_stream_auth_frame(&self.config.uuid, &self.config.password);
            let cmd_frame = TuicV5Protocol::build_command_frame(
                flux_protocol::tuic::TUIC_CMD_CONNECT,
                &meta.destination,
            );
            stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
            stream.write_all(&cmd_frame).await.map_err(FluxError::Io)?;
            stream.flush().await.map_err(FluxError::Io)?;
            return Ok(stream);
        }

        let conn = self.get_connection().await?;
        let mut stream: BoxedStream = Box::new(QuicTransport::open_bi_stream(&conn).await?);
        let cmd_frame = TuicV5Protocol::build_connect_frame(&meta.destination);
        stream.write_all(&cmd_frame).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;
        Ok(stream)
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let conn = self.get_connection().await?;
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let demux = self
            .demux
            .lock()
            .await
            .clone()
            .ok_or_else(|| FluxError::Network("tuic demux not initialized".into()))?;

        let (tx, rx) = mpsc::channel::<UdpPacket>(64);
        demux.sessions.insert(session_id, tx);

        Ok(Box::new(TuicDatagramEndpoint {
            conn,
            session_id,
            next_packet_id: AtomicU16::new(0),
            rx: Mutex::new(rx),
            destination: meta.destination.clone(),
            demux,
        }))
    }
}

/// TUIC v5 UDP endpoint: QUIC datagrams with PACKET frames.
pub struct TuicDatagramEndpoint {
    conn: quinn::Connection,
    session_id: u16,
    next_packet_id: AtomicU16,
    rx: Mutex<mpsc::Receiver<UdpPacket>>,
    #[allow(dead_code)]
    destination: TargetAddress,
    demux: Arc<DatagramDemux>,
}

#[async_trait]
impl PacketEndpoint for TuicDatagramEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let pid = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let frame = TuicV5Protocol::build_packet_frame(
            self.session_id,
            pid,
            &packet.destination,
            &packet.payload,
        );
        self.conn
            .send_datagram(frame.into())
            .map_err(|e| FluxError::Network(format!("tuic send_datagram failed: {}", e)))?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.rx.lock().await;
        guard
            .recv()
            .await
            .ok_or_else(|| FluxError::Network("tuic datagram session closed".into()))
    }
}

impl Drop for TuicDatagramEndpoint {
    fn drop(&mut self) {
        self.demux.sessions.remove(&self.session_id);
        // Best-effort DISSOCIATE (fire-and-forget).
        let _ = self
            .conn
            .send_datagram(TuicV5Protocol::build_dissociate_frame(self.session_id).into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_tuic_endpoint_family_matching() {
        let cfg = TuicV5Config {
            server: "127.0.0.1".into(),
            server_port: 8443,
            uuid: uuid::Uuid::nil(),
            password: "test".into(),
            congestion_control: "bbr".into(),
            zero_rtt: false,
            insecure: false,
            ca_certs: vec![],
            server_name: None,
            alpn: None,
        };
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));
        let outbound = TuicOutbound::new("tuic-out", cfg, resolver);

        assert!(outbound.endpoint.lock().await.is_none());

        let peer_v4: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let peer_v6: SocketAddr = "[::1]:8443".parse().unwrap();

        {
            let mut ep_guard = outbound.endpoint.lock().await;
            let ep_v4 = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
            *ep_guard = Some(ep_v4);
        }

        {
            let ep_guard = outbound.endpoint.lock().await;
            let matches_v4 = ep_guard
                .as_ref()
                .and_then(|ep| ep.local_addr().ok())
                .map(|a| a.is_ipv6() == peer_v4.is_ipv6())
                .unwrap_or(false);
            assert!(matches_v4);

            let matches_v6 = ep_guard
                .as_ref()
                .and_then(|ep| ep.local_addr().ok())
                .map(|a| a.is_ipv6() == peer_v6.is_ipv6())
                .unwrap_or(false);
            assert!(!matches_v6);
        }
    }
}
