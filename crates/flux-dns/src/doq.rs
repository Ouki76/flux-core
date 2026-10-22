use crate::dot::split_host_port;
use crate::wire::{Answer, DnsMessage, Name, QueryError};
use flux_types::{FluxError, FluxResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Deadline for a complete DoQ query (connect + stream + exchange).
///
/// The connection mutex is held across the exchange, so an unresponsive peer
/// would otherwise block every later lookup to this server forever.
const DOQ_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest message a DoQ stream can carry: RFC 9250 §5.1 uses the same 2-byte
/// length prefix as RFC 7858, so 64 KiB, not the 4 KiB UDP payload size the
/// client used to enforce.
pub(crate) const MAX_DOQ_MESSAGE: usize = u16::MAX as usize;

#[derive(Clone)]
pub struct DoqClient {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    connection: Arc<tokio::sync::Mutex<Option<quinn::Connection>>>,
    endpoint: Arc<tokio::sync::Mutex<Option<quinn::Endpoint>>>,
    /// Test-only seam: trust anchors for the QUIC client. The production path
    /// always uses the webpki roots, which cannot contain a certificate
    /// generated for a loopback test.
    #[cfg(test)]
    test_roots: Option<tokio_rustls::rustls::RootCertStore>,
}

impl std::fmt::Debug for DoqClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoqClient")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("sni", &self.sni)
            .finish()
    }
}

/// Whether a stream error means the *connection* is gone (as opposed to the
/// stream being reset on a connection that is still usable).
fn write_error_is_stale(e: &quinn::WriteError) -> bool {
    matches!(
        e,
        quinn::WriteError::ConnectionLost(_) | quinn::WriteError::ClosedStream
    )
}

fn read_error_is_stale(e: &quinn::ReadExactError) -> bool {
    matches!(
        e,
        quinn::ReadExactError::ReadError(
            quinn::ReadError::ConnectionLost(_) | quinn::ReadError::ClosedStream
        )
    )
}

impl DoqClient {
    pub fn new(url_or_addr: &str) -> Self {
        let clean = url_or_addr
            .strip_prefix("quic://")
            .or_else(|| url_or_addr.strip_prefix("doq://"))
            .unwrap_or(url_or_addr);

        let (host, port) = split_host_port(clean, 853);

        Self {
            sni: host.clone(),
            server_host: host,
            server_port: port,
            connection: Arc::new(tokio::sync::Mutex::new(None)),
            endpoint: Arc::new(tokio::sync::Mutex::new(None)),
            #[cfg(test)]
            test_roots: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_trust_anchors(
        mut self,
        roots: tokio_rustls::rustls::RootCertStore,
    ) -> Self {
        self.test_roots = Some(roots);
        self
    }

    /// The trust anchors a QUIC handshake is verified against.
    fn root_store(&self) -> tokio_rustls::rustls::RootCertStore {
        #[cfg(test)]
        if let Some(roots) = &self.test_roots {
            return roots.clone();
        }
        let mut store = tokio_rustls::rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    }

    async fn get_connection(&self, connect_addr: SocketAddr) -> FluxResult<quinn::Connection> {
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
                .map(|a| a.is_ipv6() == connect_addr.is_ipv6())
                .unwrap_or(false)
        {
            ep.clone()
        } else {
            let mut crypto = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(self.root_store())
                .with_no_client_auth();
            crypto.alpn_protocols = vec![b"doq".to_vec()];

            let client_cfg = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                    FluxError::Crypto(format!("failed to configure QUIC client: {}", e))
                })?,
            ));

            let bind_addr = if connect_addr.is_ipv6() {
                SocketAddr::from(([0; 16], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };

            let mut ep = quinn::Endpoint::client(bind_addr).map_err(FluxError::Io)?;
            ep.set_default_client_config(client_cfg);
            *ep_guard = Some(ep.clone());
            ep
        };

        let conn = endpoint
            .connect(connect_addr, &self.sni)
            .map_err(|e| FluxError::Network(format!("QUIC connection setup failed: {}", e)))?
            .await
            .map_err(|e| FluxError::Network(format!("DoQ connection failed: {}", e)))?;

        *conn_guard = Some(conn.clone());
        Ok(conn)
    }

    /// Queries DNS-over-QUIC (RFC 9250) server.
    ///
    /// Returns the parsed [`Answer`] so the caller can follow a CNAME that came
    /// back without its target record and distinguish a clean NODATA from a
    /// transport failure (which decides negative caching).
    pub async fn query_doq(
        &self,
        name: &Name,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<Answer, QueryError> {
        let connect_addr: SocketAddr = if let Ok(ip) = self.server_host.parse() {
            SocketAddr::new(ip, self.server_port)
        } else {
            let addr_str = format!("{}:{}", self.server_host, self.server_port);
            let mut addrs = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(|e| QueryError::Transport(FluxError::Io(e)))?;
            addrs.next().ok_or_else(|| {
                QueryError::Transport(FluxError::Dns(format!(
                    "failed to resolve DoQ server host '{}'",
                    self.server_host
                )))
            })?
        };

        match tokio::time::timeout(
            DOQ_IO_TIMEOUT,
            self.query_doq_inner(connect_addr, name, ecs, qtype),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                // The exchange was abandoned mid-flight, so the connection's
                // stream state is unknown. Evicting it is what stops the next
                // query from inheriting the same stall for another deadline.
                *self.connection.lock().await = None;
                Err(QueryError::Transport(FluxError::Timeout(format!(
                    "DoQ query to {} timed out after {:?}",
                    self.server_host, DOQ_IO_TIMEOUT
                ))))
            }
        }
    }

    async fn query_doq_inner(
        &self,
        connect_addr: SocketAddr,
        name: &Name,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<Answer, QueryError> {
        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_for_name(name, qtype, ecs, tx_id);
        let mut last_error: Option<QueryError> = None;

        // One retry: a pooled QUIC connection can die between queries (idle
        // timeout, peer restart, NAT rebinding), and the first query on a dead
        // connection used to fail outright because only `open_bi` failures were
        // treated as stale. A *fresh* stream can fail too, which is exactly the
        // "first query works, second fails" case.
        for attempt in 0..2 {
            let connection = match self.get_connection(connect_addr).await {
                Ok(conn) => conn,
                Err(e) => {
                    last_error = Some(QueryError::Transport(e));
                    continue;
                }
            };

            match self.exchange_once(&connection, &query, tx_id, name, qtype).await {
                Ok(answer) => return Ok(answer),
                Err((error, stale)) => {
                    if stale {
                        // Evict, so neither this attempt nor the next query is
                        // handed a connection whose state is unknown.
                        *self.connection.lock().await = None;
                    } else if attempt == 1 {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            QueryError::Transport(FluxError::Dns(format!(
                "DoQ query to {} failed after reconnect",
                self.server_host
            )))
        }))
    }

    /// One query/response on its own bidirectional stream (RFC 9250 §5.1).
    ///
    /// `Err((error, stale))` means the exchange failed; `stale` says whether the
    /// connection itself must be evicted rather than reused.
    async fn exchange_once(
        &self,
        connection: &quinn::Connection,
        query: &[u8],
        tx_id: u16,
        name: &Name,
        qtype: u16,
    ) -> Result<Answer, (QueryError, bool)> {
        let (mut send_stream, mut recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| (QueryError::Transport(FluxError::Network(e.to_string())), true))?;

        send_stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .map_err(|e| {
                (
                    QueryError::Transport(FluxError::Network(e.to_string())),
                    write_error_is_stale(&e),
                )
            })?;
        send_stream.write_all(query).await.map_err(|e| {
            (
                QueryError::Transport(FluxError::Network(e.to_string())),
                write_error_is_stale(&e),
            )
        })?;
        // FIN after the query: one transaction per stream, never reused.
        send_stream.finish().map_err(|e| {
            (
                QueryError::Transport(FluxError::Network(format!("DoQ finish failed: {}", e))),
                false,
            )
        })?;

        let mut len_buf = [0u8; 2];
        recv_stream.read_exact(&mut len_buf).await.map_err(|e| {
            (
                QueryError::Transport(FluxError::Network(e.to_string())),
                read_error_is_stale(&e),
            )
        })?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len > MAX_DOQ_MESSAGE {
            // Unreachable with a 2-byte prefix, kept as the explicit statement
            // that the ceiling is 64 KiB and not the 4 KiB UDP payload size.
            return Err((
                QueryError::Malformed(format!("DoQ response size {resp_len} too large")),
                false,
            ));
        }

        let mut resp_buf = vec![0u8; resp_len];
        recv_stream.read_exact(&mut resp_buf).await.map_err(|e| {
            (
                QueryError::Transport(FluxError::Network(e.to_string())),
                read_error_is_stale(&e),
            )
        })?;

        // The id must echo the query. A DoQ stream carries exactly one
        // transaction, so a different id is not "probably fine": it is an
        // answer to a question nobody asked in this stream.
        DnsMessage::validate_response_header(&resp_buf, tx_id)
            .map_err(|e| (QueryError::Transport(e), false))?;

        DnsMessage::parse_response(&resp_buf, name, qtype).map_err(|e| (e, false))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dot::test_support::{expected_address, response_for, test_pki};
    use crate::wire::QTYPE_A;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_rustls::rustls;

    /// How the fake DoQ server behaves.
    #[derive(Clone, Copy, Debug)]
    enum DoqBehavior {
        /// Correct id, one A record, on every stream of every connection.
        Answer,
        /// Answers the first stream of each connection, then ignores every
        /// later stream on that connection (a peer that went silent without
        /// closing).
        AnswerFirstThenIgnore,
        /// Correct framing, wrong transaction id.
        WrongId,
        /// Announced 0xFFFF bytes then three, then FIN.
        AbsurdPrefix,
        /// Half the body then a stream reset.
        ResetMidResponse,
        /// Answers, then closes the whole connection.
        AnswerThenCloseConnection,
        /// Answers with `n` A records (a message above 4 KiB).
        Big(usize),
        /// Resets the first stream of each connection, then answers normally.
        ResetFirstStreamPerConnection,
        /// Accepts the connection and never answers a stream.
        Silent,
    }

    struct FakeDoqServer {
        addr: SocketAddr,
        accepts: Arc<AtomicUsize>,
        cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    }

    impl FakeDoqServer {
        fn client(&self) -> DoqClient {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.cert.clone()).unwrap();
            DoqClient::new(&format!("quic://{}", self.addr)).with_trust_anchors(roots)
        }

        fn untrusting_client(&self) -> DoqClient {
            DoqClient::new(&format!("quic://{}", self.addr))
        }

        fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }
    }

    /// Spawns a real QUIC (RFC 9250) server on loopback.
    async fn spawn_doq_server(behavior: DoqBehavior) -> FakeDoqServer {
        let (cert, key) = test_pki();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        cfg.alpn_protocols = vec![b"doq".to_vec()];
        let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(cfg).unwrap();
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));

        let endpoint = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let mut streams = 0usize;
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        streams += 1;
                        // Read the query with its 2-byte length prefix.
                        let mut len_buf = [0u8; 2];
                        if recv.read_exact(&mut len_buf).await.is_err() {
                            continue;
                        }
                        let mut query = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                        if recv.read_exact(&mut query).await.is_err() {
                            continue;
                        }

                        match behavior {
                            DoqBehavior::AnswerFirstThenIgnore if streams > 1 => {
                                std::future::pending::<()>().await
                            }
                            DoqBehavior::Silent => std::future::pending::<()>().await,
                            DoqBehavior::Answer | DoqBehavior::AnswerFirstThenIgnore => {
                                let resp = response_for(&query, None, 1);
                                let _ = send.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&resp).await;
                                let _ = send.finish();
                            }
                            DoqBehavior::WrongId => {
                                let id = u16::from_be_bytes([query[0], query[1]]).wrapping_add(1);
                                let resp = response_for(&query, Some(id), 1);
                                let _ = send.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&resp).await;
                                let _ = send.finish();
                            }
                            DoqBehavior::AbsurdPrefix => {
                                let _ = send.write_all(&[0xff, 0xff, 1, 2, 3]).await;
                                let _ = send.finish();
                            }
                            DoqBehavior::ResetFirstStreamPerConnection if streams == 1 => {
                                send.reset(quinn::VarInt::from_u32(0)).ok();
                                continue;
                            }
                            DoqBehavior::ResetFirstStreamPerConnection => {
                                let resp = response_for(&query, None, 1);
                                let _ = send.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&resp).await;
                                let _ = send.finish();
                            }
                            DoqBehavior::ResetMidResponse => {
                                let resp = response_for(&query, None, 1);
                                let _ = send.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&resp[..resp.len() / 2]).await;
                                send.reset(quinn::VarInt::from_u32(0)).ok();
                            }
                            DoqBehavior::AnswerThenCloseConnection => {
                                let resp = response_for(&query, None, 1);
                                let _ = send.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&resp).await;
                                let _ = send.finish();
                                // Let the response reach the peer before the
                                // connection goes away, otherwise the client
                                // loses the answer instead of the connection.
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                conn.close(quinn::VarInt::from_u32(0), b"done");
                                break;
                            }
                            DoqBehavior::Big(answers) => {
                                let resp = response_for(&query, None, answers);
                                let _ = send.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = send.write_all(&resp).await;
                                let _ = send.finish();
                            }
                        }
                    }
                });
            }
        });

        FakeDoqServer {
            addr,
            accepts,
            cert,
        }
    }

    async fn ask(client: &DoqClient) -> Result<Answer, QueryError> {
        let name = Name::from_str("example.com").unwrap();
        client.query_doq(&name, None, QTYPE_A).await
    }

    // -- the transport works at all ---------------------------------------

    /// The headline gap: nothing in this repository ever executed a DoQ query.
    /// One bidirectional stream per query, 2-byte length prefix, FIN after the
    /// query, response parsed as an answer.
    #[tokio::test]
    async fn completes_a_query_over_quic() {
        let srv = spawn_doq_server(DoqBehavior::Answer).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a DoQ query must not stall")
            .expect("a DoQ query must succeed against a conforming server");
        assert_eq!(answer, expected_address());
    }

    /// RFC 9250 §5.1: the client finishes its send side after the single query,
    /// so the server sees a complete stream rather than one waiting for more.
    #[tokio::test]
    async fn the_client_finishes_the_query_stream() {
        let (cert, key) = test_pki();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        cfg.alpn_protocols = vec![b"doq".to_vec()];
        let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(cfg).unwrap();
        let endpoint =
            quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quic_cfg)), "127.0.0.1:0".parse().unwrap())
                .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            // `read_to_end` only returns once the peer sent FIN: if the client
            // kept the send side open this would hang.
            let framed = recv.read_to_end(4096).await.expect("stream must be closed by the client");
            let resp = response_for(&framed[2..], None, 1);
            send.write_all(&(resp.len() as u16).to_be_bytes()).await.unwrap();
            send.write_all(&resp).await.unwrap();
            send.finish().ok();
            let _ = tx.send(framed);
            std::future::pending::<()>().await
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = DoqClient::new(&format!("quic://{addr}")).with_trust_anchors(roots);

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a client that never finishes its stream would hang here")
            .expect("the query must be answered");
        assert_eq!(answer, expected_address());

        let framed = rx.await.unwrap();
        let announced = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(announced, framed.len() - 2, "the 2-byte prefix must cover the whole message");
    }

    /// Same 64 KiB ceiling as DoT: an answer above the old 4 KiB cap is legal.
    #[tokio::test]
    async fn accepts_a_response_larger_than_4_kib() {
        let srv = spawn_doq_server(DoqBehavior::Big(300)).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a 4.8 KiB response must not stall")
            .expect("a 4.8 KiB DoQ response must be accepted");
        assert_eq!(answer, expected_address());
    }

    // -- message id -------------------------------------------------------

    /// A DoQ stream carries exactly one transaction, so the response id must
    /// echo the query id. A different id is not this query's answer.
    #[tokio::test]
    async fn rejects_a_response_with_a_mismatched_id() {
        let srv = spawn_doq_server(DoqBehavior::WrongId).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a mismatched id must fail fast, not hang")
            .expect_err("a mismatched transaction id must be rejected");
        assert!(
            err.to_string().contains("mismatched DNS transaction ID"),
            "unexpected error: {err}"
        );
    }

    // -- error paths ------------------------------------------------------

    #[tokio::test]
    async fn an_absurd_length_prefix_is_an_error() {
        let srv = spawn_doq_server(DoqBehavior::AbsurdPrefix).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("an absurd prefix must not hang")
            .expect_err("a truncated 0xFFFF message must not be accepted");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_reset_mid_response_is_an_error() {
        let srv = spawn_doq_server(DoqBehavior::ResetMidResponse).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a reset stream must not hang")
            .expect_err("a response cut mid-body must not be accepted");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
    }

    /// The client must verify the QUIC/TLS certificate: a self-signed peer it
    /// was not told to trust is an error, not a connection.
    #[tokio::test]
    async fn a_self_signed_server_is_rejected_without_trust() {
        let srv = spawn_doq_server(DoqBehavior::Answer).await;
        let client = srv.untrusting_client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a bad certificate must fail the query, not hang")
            .expect_err("an untrusted self-signed certificate must be rejected");
        let text = err.to_string();
        assert!(
            text.contains("certificate")
                || text.contains("handshake")
                || text.contains("DoQ connection failed"),
            "unexpected error: {text}"
        );
    }

    /// A peer that accepts the connection and never answers must hit the
    /// deadline.
    #[tokio::test]
    async fn a_silent_server_times_out() {
        let srv = spawn_doq_server(DoqBehavior::Silent).await;
        let client = srv.client();

        let started = std::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a silent peer must not hang")
            .expect_err("a silent peer is a timeout, not an answer");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "took {:?}",
            started.elapsed()
        );
    }

    /// A stream reset on a healthy connection is recoverable: the connection is
    /// still usable, so the query is retried on a fresh stream instead of being
    /// reported as a failure (and the connection is not thrown away).
    #[tokio::test]
    async fn recovers_from_a_stream_failure_on_a_healthy_connection() {
        let srv = spawn_doq_server(DoqBehavior::ResetFirstStreamPerConnection).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a resetted stream must not hang")
            .expect("a reset stream on a healthy connection must be retried");
        assert_eq!(answer, expected_address());
        assert_eq!(srv.accepts(), 1, "the connection itself was fine: no redial");
    }

    // -- reuse and pooling ------------------------------------------------

    #[tokio::test]
    async fn a_healthy_connection_is_reused() {
        let srv = spawn_doq_server(DoqBehavior::Answer).await;
        let client = srv.client();

        for _ in 0..3 {
            ask(&client).await.expect("every query must succeed");
        }
        assert_eq!(srv.accepts(), 1, "the QUIC connection must be reused");
    }

    /// A pooled connection the peer closed must not be handed out again.
    #[tokio::test]
    async fn a_closed_pooled_connection_is_replaced() {
        let srv = spawn_doq_server(DoqBehavior::AnswerThenCloseConnection).await;
        let client = srv.client();

        ask(&client).await.expect("first query must succeed");
        let second = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("the second query must not hang")
            .expect("a closed pooled connection must be replaced, not reused");
        assert_eq!(second, expected_address());
    }

    /// A connection that stalls mid-exchange must be evicted, not cached: the
    /// query *after* a timed-out one must dial afresh instead of inheriting the
    /// same dead connection and timing out again.
    #[tokio::test]
    async fn a_stalled_connection_is_evicted() {
        let srv = spawn_doq_server(DoqBehavior::AnswerFirstThenIgnore).await;
        let client = srv.client();

        ask(&client).await.expect("first query must succeed");
        let stalled = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("the stalled query must return");
        assert!(stalled.is_err(), "a silent peer is a timeout");

        let recovered = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("the recovery query must not hang")
            .expect("a timed-out connection must be evicted, not reused");
        assert_eq!(recovered, expected_address());
        assert_eq!(srv.accepts(), 2, "the client must have dialled a new connection");
    }

    #[test]
    fn parses_bracketed_ipv6_and_plain_server_forms() {
        let v6 = DoqClient::new("quic://[2606:4700:4700::1111]");
        assert_eq!(v6.server_host, "2606:4700:4700::1111");
        assert_eq!(v6.server_port, 853);

        let with_port = DoqClient::new("quic://[2606:4700:4700::1111]:8853");
        assert_eq!(with_port.server_port, 8853);

        let named = DoqClient::new("quic://dns.adguard.com");
        assert!(format!("{named:?}").contains("DoqClient"));
        assert_eq!(named.server_host, "dns.adguard.com");
        assert_eq!(named.server_port, 853);
        assert_eq!(named.sni, "dns.adguard.com");
    }

    #[tokio::test]
    async fn test_doq_endpoint_family_switch() {
        let resolver = DoqClient::new("quic://127.0.0.1:853");

        let addr_v4: SocketAddr = "127.0.0.1:853".parse().unwrap();
        let addr_v6: SocketAddr = "[::1]:853".parse().unwrap();

        {
            let mut ep_guard = resolver.endpoint.lock().await;
            let ep_v4 = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))).unwrap();
            *ep_guard = Some(ep_v4);
        }

        let ep_guard = resolver.endpoint.lock().await;
        let ep = ep_guard.as_ref().unwrap();
        let local = ep.local_addr().unwrap();
        assert_eq!(local.is_ipv6(), addr_v4.is_ipv6());
        assert_ne!(local.is_ipv6(), addr_v6.is_ipv6());
    }

    /// A real resolver, when the network is there. Ignored by default.
    #[tokio::test]
    #[ignore = "needs the public internet"]
    async fn queries_a_real_doq_resolver() {
        if let Err(e) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            eprintln!("SKIP live DoQ test: no UDP socket ({e})");
            return;
        }
        let client = DoqClient::new("quic://dns.adguard.com");
        let name = Name::from_str("example.com").unwrap();
        match client.query_doq(&name, None, QTYPE_A).await {
            Ok(Answer::Address { ip, .. }) => {
                assert!(matches!(ip, IpAddr::V4(_)), "expected an A record, got {ip}");
            }
            Ok(other) => panic!("expected an A record, got {other:?}"),
            Err(e) => panic!("a real DoQ resolver must answer: {e}"),
        }
    }
}
