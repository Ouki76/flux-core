use async_trait::async_trait;
use flux_protocol::hysteria2::{
    BrutalPacer, HYSTERIA2_CMD_TCP, Hysteria2Config, Hysteria2Protocol, PortHopper,
};
use flux_transport::quic::QuicTransport;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};

type UdpDemuxMap = Arc<dashmap::DashMap<u32, tokio::sync::mpsc::Sender<UdpPacket>>>;

pub struct Hysteria2Outbound {
    tag: String,
    config: Hysteria2Config,
    resolver: Arc<flux_dns::DnsResolver>,
    port_hopper: Arc<Mutex<PortHopper>>,
    pacer: Arc<Mutex<BrutalPacer>>,
    endpoint: Arc<Mutex<Option<quinn::Endpoint>>>,
    connection: Arc<Mutex<Option<quinn::Connection>>>,
    /// Keeps the HTTP/3 auth request stream open for the connection's lifetime;
    /// dropping it would reset the stream the server is holding.
    auth_stream: Arc<Mutex<Option<quinn::SendStream>>>,
    dialer: Option<Arc<dyn flux_types::StreamDialer>>,
    /// Per-connection datagram demultiplexer, tagged with the QUIC connection it
    /// belongs to (`Connection::stable_id`) so a reconnect rebuilds it instead of
    /// leaving sessions registered against a dead connection.
    udp_demux: Arc<Mutex<Option<(usize, UdpDemuxMap)>>>,
    next_udp_session: Arc<std::sync::atomic::AtomicU32>,
}

impl Hysteria2Outbound {
    pub fn new(
        tag: impl Into<String>,
        config: Hysteria2Config,
        resolver: Arc<flux_dns::DnsResolver>,
    ) -> Self {
        let hopper = PortHopper::new(config.ports.clone(), config.hop_interval_secs);
        let pacer = BrutalPacer::new(config.up_mbps);

        Self {
            tag: tag.into(),
            config,
            resolver,
            port_hopper: Arc::new(Mutex::new(hopper)),
            pacer: Arc::new(Mutex::new(pacer)),
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
            auth_stream: Arc::new(Mutex::new(None)),
            dialer: None,
            udp_demux: Arc::new(Mutex::new(None)),
            next_udp_session: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }
    }

    pub fn new_with_dialer(
        tag: impl Into<String>,
        config: Hysteria2Config,
        dialer: Arc<dyn flux_types::StreamDialer>,
    ) -> Self {
        let hopper = PortHopper::new(config.ports.clone(), config.hop_interval_secs);
        let pacer = BrutalPacer::new(config.up_mbps);
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));

        Self {
            tag: tag.into(),
            config,
            resolver,
            port_hopper: Arc::new(Mutex::new(hopper)),
            pacer: Arc::new(Mutex::new(pacer)),
            endpoint: Arc::new(Mutex::new(None)),
            connection: Arc::new(Mutex::new(None)),
            auth_stream: Arc::new(Mutex::new(None)),
            dialer: Some(dialer),
            udp_demux: Arc::new(Mutex::new(None)),
            next_udp_session: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }
    }

    pub fn pacer(&self) -> &Arc<Mutex<BrutalPacer>> {
        &self.pacer
    }

    async fn get_connection(&self) -> FluxResult<quinn::Connection> {
        let port = self.port_hopper.lock().await.current_port();
        let peer_addr = self
            .resolver
            .resolve_domain(&self.config.server, port)
            .await?;

        let mut conn_guard = self.connection.lock().await;
        if let Some(ref conn) = *conn_guard
            && conn.close_reason().is_none()
            && conn.remote_address().port() == port
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
                .unwrap_or_else(|| vec![b"h3".to_vec(), b"hysteria2".to_vec()]);
            let ep = if let Some(obfs_pwd) = &self.config.obfs {
                QuicTransport::create_client_endpoint_obfs(
                    peer_addr.is_ipv6(),
                    alpn,
                    self.config.insecure,
                    obfs_pwd,
                )?
            } else {
                QuicTransport::create_client_endpoint_with_ca(
                    peer_addr.is_ipv6(),
                    alpn,
                    self.config.insecure,
                    &self.config.ca_certs,
                )?
            };
            *ep_guard = Some(ep.clone());
            ep
        };

        let sni = self
            .config
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let conn = QuicTransport::connect(&endpoint, peer_addr, sni).await?;
        // Authenticate over HTTP/3 with our own minimal client: the `h3` crate
        // needed ~5.5 s to deliver the response our server produces in ~1 ms.
        let t_auth = std::time::Instant::now();
        let h3 = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            flux_transport::h3_lite::client_auth_request(&conn, &self.config.password, 0),
        )
        .await
        .map_err(|_| FluxError::Timeout("HTTP/3 authentication timed out".into()))??;
        tracing::trace!("hysteria2 auth took {:?}", t_auth.elapsed());
        *self.auth_stream.lock().await = Some(h3);
        *conn_guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "hysteria2"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(ref d) = self.dialer {
            let mut stream = d.dial().await?;
            let auth_frame = Hysteria2Protocol::build_auth_frame(&self.config.password);
            let req_frame =
                Hysteria2Protocol::build_request_frame(HYSTERIA2_CMD_TCP, &meta.destination);

            stream.write_all(&auth_frame).await.map_err(FluxError::Io)?;
            stream.write_all(&req_frame).await.map_err(FluxError::Io)?;
            stream.flush().await.map_err(FluxError::Io)?;
            Ok(stream)
        } else {
            let conn = self.get_connection().await?;
            let mut stream = QuicTransport::open_bi_stream(&conn).await?;
            let req_frame = Hysteria2Protocol::encode_tcp_request(&meta.destination);
            stream.write_all(&req_frame).await.map_err(FluxError::Io)?;
            stream.flush().await.map_err(FluxError::Io)?;
            Hysteria2Protocol::read_tcp_response(&mut stream).await?;
            Ok(Box::new(stream))
        }
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        let conn = self.get_connection().await?;
        let session_id = self.next_udp_session.fetch_add(1, Ordering::Relaxed);

        // Register this session in the per-connection datagram demuxer.
        let (tx, rx) = mpsc::channel::<UdpPacket>(64);
        let conn_id = conn.stable_id();
        {
            let mut demux = self.udp_demux.lock().await;
            // A replaced connection (reconnect / port hop) invalidates both the
            // reader task and every registered session: rebuild the demuxer, or
            // all UDP replies for the new connection are silently dropped.
            let needs_rebuild = match demux.as_ref() {
                Some((id, _)) => *id != conn_id,
                None => true,
            };
            if needs_rebuild {
                // Spawn the per-connection datagram reader.
                let conn_c = conn.clone();
                let sessions: UdpDemuxMap = Arc::new(dashmap::DashMap::new());
                let sessions_c = sessions.clone();
                tokio::spawn(async move {
                    while let Ok(d) = conn_c.read_datagram().await {
                        if d.len() < 9 {
                            continue;
                        }
                        let sid = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                        let vlen = d[8] as usize;
                        if d.len() < 9 + vlen {
                            continue;
                        }
                        let dest_str = String::from_utf8_lossy(&d[9..9 + vlen]).to_string();
                        let payload = &d[9 + vlen..];
                        let target: Result<TargetAddress, _> = dest_str.parse();
                        if let Ok(t) = target
                            && let Some(tx) = sessions_c.get(&sid)
                        {
                            let pkt = UdpPacket::new(payload.to_vec().into(), t.clone(), t);
                            let _ = tx.try_send(pkt);
                        }
                    }
                });
                *demux = Some((conn_id, sessions));
            }
            if let Some((_, d)) = demux.as_ref() {
                d.insert(session_id, tx);
            }
        }

        Ok(Box::new(Hysteria2DatagramEndpoint {
            conn,
            session_id,
            next_packet_id: std::sync::atomic::AtomicU16::new(0),
            rx: Mutex::new(rx),
            pacer: self.pacer.clone(),
        }))
    }
}

/// Hysteria 2 UDP endpoint over QUIC datagrams:
/// `[sessionID u32 BE][packetID u16 BE][fragID u8][fragTotal u8][vstring dest][data]`.
pub struct Hysteria2DatagramEndpoint {
    conn: quinn::Connection,
    session_id: u32,
    next_packet_id: std::sync::atomic::AtomicU16,
    rx: Mutex<mpsc::Receiver<UdpPacket>>,
    pacer: Arc<Mutex<BrutalPacer>>,
}

#[async_trait]
impl PacketEndpoint for Hysteria2DatagramEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let pid = self
            .next_packet_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dest_str = packet.destination.to_string();

        let mut frame = Vec::with_capacity(9 + dest_str.len() + packet.payload.len());
        frame.extend_from_slice(&self.session_id.to_be_bytes());
        frame.extend_from_slice(&pid.to_be_bytes());
        frame.push(0); // frag id
        frame.push(1); // frag total
        frame.push(dest_str.len() as u8);
        frame.extend_from_slice(dest_str.as_bytes());
        frame.extend_from_slice(&packet.payload);

        // Brutal pacing for bandwidth control
        self.pacer.lock().await.pace(frame.len()).await;

        self.conn
            .send_datagram(frame.into())
            .map_err(|e| FluxError::Network(format!("hy2 send_datagram failed: {}", e)))?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut guard = self.rx.lock().await;
        guard
            .recv()
            .await
            .ok_or_else(|| FluxError::Network("hy2 datagram session closed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_hysteria2_endpoint_family_matching() {
        let cfg = Hysteria2Config {
            server: "127.0.0.1".into(),
            ports: vec![443],
            password: "test".into(),
            up_mbps: 100,
            down_mbps: 100,
            hop_interval_secs: 30,
            insecure: false,
            ca_certs: vec![],
            server_name: None,
            obfs: None,
            alpn: None,
            h3: false,
        };
        let resolver = Arc::new(flux_dns::DnsResolver::new(None));
        let outbound = Hysteria2Outbound::new("hy2-out", cfg, resolver);

        let peer_v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_v6: SocketAddr = "[::1]:443".parse().unwrap();

        assert!(outbound.endpoint.lock().await.is_none());

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
