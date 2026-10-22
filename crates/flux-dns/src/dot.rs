use crate::wire::{Answer, DnsMessage, Name, QueryError};
use flux_transport::tcp::TcpTransport;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{BoxedStream, FluxError, FluxResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// Deadline for each DoT network step (connect, write, read).
const DOT_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest message a 2-byte length prefix can announce (RFC 7858 §3.3, which
/// reuses the RFC 1035 §4.2.2 TCP framing).
///
/// The cap used to be 4096 — the *UDP* payload size — so a legitimate DNSSEC or
/// multi-record answer above 4 KiB was rejected as "response too large" even
/// though a stream transport carries up to 64 KiB.
pub(crate) const MAX_DOT_MESSAGE: usize = u16::MAX as usize;

/// Splits `[scheme://]host[:port]` into `(host, port)`.
///
/// A bracketed IPv6 literal keeps its brackets out of the host: `rsplit_once(':')`
/// on the raw string used to split *inside* the address, turning
/// `[2606:4700:4700::1111]` into the nonsense host `[2606:4700:4700:`. A bare
/// IPv6 literal (`::1`) is recognised by containing more than one colon and is
/// taken whole, with the default port.
pub(crate) fn split_host_port(clean: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = clean.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }

    match clean.rsplit_once(':') {
        // Exactly one colon: `host:port`. More than one means a bare IPv6
        // address, which must not be split.
        Some((host, port)) if !host.contains(':') => {
            (host.to_string(), port.parse::<u16>().unwrap_or(default_port))
        }
        _ => (clean.to_string(), default_port),
    }
}

/// Writes one DNS message with the RFC 7858 two-byte big-endian length prefix.
pub(crate) async fn write_message<W>(writer: &mut W, query: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if query.len() > MAX_DOT_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS query does not fit the two-byte length prefix",
        ));
    }
    writer.write_all(&(query.len() as u16).to_be_bytes()).await?;
    writer.write_all(query).await?;
    writer.flush().await
}

/// Reads exactly one length-prefixed DNS message.
///
/// `read_exact` is what makes a short read safe: a message split across several
/// reads is only returned once all of the announced length has arrived, and a
/// peer that closes early — or announces 0xFFFF bytes and sends three — ends in
/// `UnexpectedEof` instead of a silently truncated packet.
pub(crate) async fn read_message<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[derive(Clone)]
pub struct DotClient {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    stream: Arc<Mutex<Option<BoxedStream>>>,
    /// Test-only seam: replaces the real TLS dial. Production code always dials
    /// through [`TlsTransport`] with the webpki root store, which offers no way
    /// to trust a locally generated certificate, so the round-trip tests inject
    /// an already-connected stream here instead.
    #[cfg(test)]
    connector: Option<TestConnector>,
}

#[cfg(test)]
pub(crate) type TestConnector = Arc<
    dyn Fn() -> futures_util::future::BoxFuture<'static, FluxResult<BoxedStream>> + Send + Sync,
>;

impl std::fmt::Debug for DotClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotClient")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("sni", &self.sni)
            .finish()
    }
}

impl DotClient {
    pub fn new(url_or_addr: &str) -> Self {
        let clean = url_or_addr
            .strip_prefix("tls://")
            .or_else(|| url_or_addr.strip_prefix("dot://"))
            .unwrap_or(url_or_addr);

        let (host, port) = split_host_port(clean, 853);

        Self {
            sni: host.clone(),
            server_host: host,
            server_port: port,
            stream: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            connector: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_connector(mut self, connector: TestConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    async fn connect_stream(&self) -> FluxResult<BoxedStream> {
        #[cfg(test)]
        if let Some(connector) = &self.connector {
            return connector().await;
        }

        let connect_addr: SocketAddr = if let Ok(ip) = self.server_host.parse() {
            SocketAddr::new(ip, self.server_port)
        } else {
            let addr_str = format!("{}:{}", self.server_host, self.server_port);
            let mut addrs = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(FluxError::Io)?;
            addrs.next().ok_or_else(|| {
                FluxError::Dns(format!(
                    "failed to resolve DoT server host '{}'",
                    self.server_host
                ))
            })?
        };

        let tcp_stream = TcpTransport::connect(connect_addr, Duration::from_secs(4)).await?;
        let tls_cfg = TlsClientConfig::new(&self.sni).with_alpn(vec!["dot".into()]);
        TlsTransport::connect(tcp_stream, &tls_cfg).await
    }

    /// Queries DNS-over-TLS (RFC 7858) server with connection reuse across queries.
    ///
    /// Returns the parsed [`Answer`] so the caller can follow a CNAME that came
    /// back without its target record and distinguish a clean NODATA from a
    /// transport failure (which decides negative caching).
    pub async fn query_dot(
        &self,
        name: &Name,
        ecs: Option<ipnet::IpNet>,
        qtype: u16,
    ) -> Result<Answer, QueryError> {
        let tx_id = rand::random::<u16>();
        let query = DnsMessage::build_query_for_name(name, qtype, ecs, tx_id);

        let mut guard = self.stream.lock().await;
        let mut last_error: Option<QueryError> = None;

        for _attempt in 0..2 {
            if guard.is_none() {
                // Bound connect/query: a stalled upstream must never hold this
                // connection (and its mutex) indefinitely.
                match tokio::time::timeout(DOT_IO_TIMEOUT, self.connect_stream()).await {
                    Ok(Ok(s)) => *guard = Some(s),
                    Ok(Err(e)) => {
                        last_error = Some(QueryError::Transport(e));
                        continue;
                    }
                    Err(_) => {
                        last_error = Some(QueryError::Transport(FluxError::Timeout(format!(
                            "DoT connect to {} timed out",
                            self.server_host
                        ))));
                        continue;
                    }
                }
            }

            let exchange = {
                let Some(stream) = guard.as_mut() else { continue };
                tokio::time::timeout(DOT_IO_TIMEOUT, async {
                    write_message(&mut **stream, &query).await?;
                    read_message(&mut **stream).await
                })
                .await
            };

            let resp = match exchange {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    // A broken exchange leaves the stream's framing at an
                    // unknown offset: evict it rather than parse whatever the
                    // next read happens to return.
                    *guard = None;
                    last_error = Some(QueryError::Transport(FluxError::Io(e)));
                    continue;
                }
                Err(_) => {
                    *guard = None;
                    last_error = Some(QueryError::Transport(FluxError::Timeout(format!(
                        "DoT query to {} timed out",
                        self.server_host
                    ))));
                    continue;
                }
            };

            // The response id must echo this query's id: a pooled connection
            // that hands back someone else's answer is a desynchronised stream,
            // not an answer, so it is rejected *and* evicted.
            if let Err(e) = DnsMessage::validate_response_header(&resp, tx_id) {
                *guard = None;
                last_error = Some(QueryError::Transport(e));
                continue;
            }

            // An error RCODE (NXDOMAIN/NODATA) is a valid answer, not a broken
            // connection: the parser turns it into a negative result.
            return DnsMessage::parse_response(&resp, name, qtype);
        }

        Err(last_error.unwrap_or_else(|| {
            QueryError::Transport(FluxError::Dns(format!(
                "DoT query to {} failed",
                self.server_host
            )))
        }))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Shared fixtures for the three stream transports: a throwaway PKI, a DoT
/// server, and the DNS wire responses the fake servers send back.
///
/// Everything runs on loopback, so the suite needs no public internet; the only
/// test that touches the network is the explicitly ignored one at the bottom of
/// this file.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::wire::{DnsMessage, Name, QTYPE_A};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    /// A throwaway server certificate valid for `127.0.0.1` (IP SAN) and
    /// `localhost`, plus its key.
    pub(crate) fn test_pki() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        )
    }

    /// A response that echoes `query`'s id (or uses `id_override`) and carries
    /// `answers` A records, which is how a message above 4 KiB is built.
    pub(crate) fn response_for(query: &[u8], id_override: Option<u16>, answers: usize) -> Vec<u8> {
        let tx_id = id_override.unwrap_or_else(|| u16::from_be_bytes([query[0], query[1]]));
        let mut out = Vec::with_capacity(32 + answers * 16);
        out.extend_from_slice(&tx_id.to_be_bytes());
        out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA, NOERROR
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&(answers as u16).to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out.extend_from_slice(&query[12..]); // question, verbatim
        for i in 0..answers {
            out.extend_from_slice(&[
                0xc0, 0x0c, // name pointer to the question
                0x00, 0x01, // TYPE A
                0x00, 0x01, // CLASS IN
                0x00, 0x00, 0x01, 0x2c, // TTL 300
                0x00, 0x04, // RDLENGTH
                10, 0, 0, (i % 256) as u8,
            ]);
        }
        out
    }

    /// A connector that dials `addr` over TLS trusting `roots` — the
    /// "deliberately configured trusting client" the production client cannot
    /// express, because [`TlsClientConfig`] only knows webpki roots.
    pub(crate) fn tls_connector(
        addr: SocketAddr,
        roots: Vec<CertificateDer<'static>>,
        alpn: &'static str,
    ) -> super::TestConnector {
        Arc::new(move || {
            let roots = roots.clone();
            Box::pin(async move {
                let mut store = RootCertStore::empty();
                for cert in roots {
                    store
                        .add(cert)
                        .map_err(|e| FluxError::Crypto(format!("bad test root: {e}")))?;
                }
                let mut cfg = ClientConfig::builder()
                    .with_root_certificates(store)
                    .with_no_client_auth();
                cfg.alpn_protocols = vec![alpn.as_bytes().to_vec()];
                let tcp = TcpTransport::connect(addr, Duration::from_secs(2)).await?;
                let sni = tokio_rustls::rustls::pki_types::ServerName::try_from("127.0.0.1")
                    .map_err(|e| FluxError::Crypto(format!("bad test SNI: {e}")))?
                    .to_owned();
                let stream = TlsConnector::from(Arc::new(cfg))
                    .connect(sni, tcp)
                    .await
                    .map_err(FluxError::Io)?;
                Ok(Box::new(stream) as BoxedStream)
            })
        })
    }

    /// A connector that returns a plain TCP stream, for framing tests that do
    /// not want the TLS layer in the way.
    pub(crate) fn tcp_connector(addr: SocketAddr) -> super::TestConnector {
        Arc::new(move || {
            Box::pin(async move {
                let tcp = TcpTransport::connect(addr, Duration::from_secs(2)).await?;
                Ok(Box::new(tcp) as BoxedStream)
            })
        })
    }

    /// How the fake DoT server answers one query.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum DotBehavior {
        /// Correct id and one A record.
        Answer,
        /// Correct framing, but the answer belongs to another query.
        WrongId,
        /// A wrong id for the very first query only, then correct answers.
        WrongIdFirstQuery,
        /// Correct answer, written one byte at a time (short reads).
        Dribble,
        /// Half the announced body, then the connection dies.
        CloseMidResponse,
        /// Accepts, then closes without writing a byte.
        CloseImmediately,
        /// Announces 0xFFFF bytes and sends three.
        AbsurdPrefix,
        /// Accepts and never answers.
        Silent,
        /// Answers, then closes the connection (a stale pooled connection).
        AnswerThenClose,
        /// Answers with `n` A records, so the message can exceed 4 KiB.
        Big(usize),
    }

    /// A loopback DoT server plus everything a test needs to talk to it.
    pub(crate) struct FakeDotServer {
        pub addr: SocketAddr,
        pub accepts: Arc<AtomicUsize>,
        pub cert: CertificateDer<'static>,
    }

    impl FakeDotServer {
        /// A client that trusts this server (the happy path).
        pub(crate) fn client(&self) -> super::DotClient {
            super::DotClient::new(&format!("tls://{}", self.addr))
                .with_connector(tls_connector(self.addr, vec![self.cert.clone()], "dot"))
        }

        /// A client that has *not* been told to trust this server.
        pub(crate) fn untrusting_client(&self) -> super::DotClient {
            super::DotClient::new(&format!("tls://{}", self.addr))
        }

        pub(crate) fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }
    }

    /// Spawns a DoT server on loopback. The accepted-connection counter is how
    /// the tests tell connection reuse from reconnection.
    pub(crate) async fn spawn_dot_server(behavior: DotBehavior) -> FakeDotServer {
        let (cert, key) = test_pki();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        cfg.alpn_protocols = vec![b"dot".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        let served = Arc::new(AtomicUsize::new(0));

        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let served = served.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    loop {
                        let mut len_buf = [0u8; 2];
                        if tls.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let mut query = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                        if tls.read_exact(&mut query).await.is_err() {
                            return;
                        }
                        match behavior {
                            DotBehavior::Answer => {
                                let resp = response_for(&query, None, 1);
                                if write_message(&mut tls, &resp).await.is_err() {
                                    return;
                                }
                            }
                            DotBehavior::WrongId => {
                                let id = u16::from_be_bytes([query[0], query[1]]).wrapping_add(1);
                                let resp = response_for(&query, Some(id), 1);
                                if write_message(&mut tls, &resp).await.is_err() {
                                    return;
                                }
                            }
                            DotBehavior::WrongIdFirstQuery => {
                                let first = served.fetch_add(1, Ordering::SeqCst) == 0;
                                let id = first.then(|| {
                                    u16::from_be_bytes([query[0], query[1]]).wrapping_add(1)
                                });
                                let resp = response_for(&query, id, 1);
                                if write_message(&mut tls, &resp).await.is_err() {
                                    return;
                                }
                            }
                            DotBehavior::Dribble => {
                                let resp = response_for(&query, None, 1);
                                let mut framed = (resp.len() as u16).to_be_bytes().to_vec();
                                framed.extend_from_slice(&resp);
                                for byte in framed {
                                    if tls.write_all(&[byte]).await.is_err() {
                                        return;
                                    }
                                    let _ = tls.flush().await;
                                    tokio::time::sleep(Duration::from_millis(1)).await;
                                }
                            }
                            DotBehavior::CloseMidResponse => {
                                let resp = response_for(&query, None, 1);
                                let _ = tls.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = tls.write_all(&resp[..resp.len() / 2]).await;
                                let _ = tls.flush().await;
                                return;
                            }
                            DotBehavior::CloseImmediately => return,
                            DotBehavior::AbsurdPrefix => {
                                let _ = tls.write_all(&[0xff, 0xff, 1, 2, 3]).await;
                                let _ = tls.flush().await;
                                return;
                            }
                            DotBehavior::Silent => std::future::pending::<()>().await,
                            DotBehavior::AnswerThenClose => {
                                let resp = response_for(&query, None, 1);
                                let _ = write_message(&mut tls, &resp).await;
                                return;
                            }
                            DotBehavior::Big(answers) => {
                                let resp = response_for(&query, None, answers);
                                if write_message(&mut tls, &resp).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        FakeDotServer {
            addr,
            accepts,
            cert,
        }
    }

    /// Runs one A query for `example.com` through `client`.
    pub(crate) async fn ask(client: &super::DotClient) -> Result<Answer, QueryError> {
        let name = Name::from_str("example.com").unwrap();
        client.query_dot(&name, None, QTYPE_A).await
    }

    /// The first A record every fake server hands out.
    pub(crate) fn expected_address() -> Answer {
        Answer::Address {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            ttl: 300,
        }
    }

    /// The question section (everything after the 12-byte header) of a query
    /// built the way the client builds it.
    pub(crate) fn question_of_query() -> Vec<u8> {
        let name = Name::from_str("example.com").unwrap();
        DnsMessage::build_query_for_name(&name, QTYPE_A, None, 0)[12..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    // -- framing ----------------------------------------------------------

    /// RFC 7858 §3.3: the message on the wire is a 2-byte big-endian length
    /// followed by the DNS payload, and the server sees exactly that.
    #[tokio::test]
    async fn query_is_framed_with_a_two_byte_length_prefix() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut prefix = [0u8; 2];
                    if sock.read_exact(&mut prefix).await.is_err() {
                        return;
                    }
                    let mut body = vec![0u8; u16::from_be_bytes(prefix) as usize];
                    if sock.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let resp = response_for(&body, None, 1);
                    let _ = tx.send(body);
                    if write_message(&mut sock, &resp).await.is_err() {
                        return;
                    }
                    // Keep the connection open: the client is still holding it.
                    std::future::pending::<()>().await
                });
            }
        });

        let client = DotClient::new(&format!("tls://{addr}")).with_connector(tcp_connector(addr));
        let answer = tokio::time::timeout(Duration::from_secs(10), ask(&client))
            .await
            .expect("the framed query must not stall")
            .expect("a correctly framed exchange must succeed");
        assert_eq!(answer, expected_address());

        let received = rx.recv().await.unwrap();
        assert_eq!(
            &received[12..],
            question_of_query().as_slice(),
            "the framed payload must be a real DNS query for example.com/A"
        );
    }

    /// A response that arrives in many small reads is still one message: a short
    /// read must not be mistaken for a complete (or a truncated) answer.
    #[tokio::test]
    async fn a_response_split_across_reads_is_reassembled() {
        let srv = spawn_dot_server(DotBehavior::Dribble).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(10), ask(&client))
            .await
            .expect("a dribbled response must not stall")
            .expect("a response split across reads must be reassembled");
        assert_eq!(answer, expected_address());
    }

    /// Stream transports carry up to 64 KiB: an answer above the old 4 KiB cap
    /// is legal and must not be rejected as "too large".
    #[tokio::test]
    async fn accepts_a_response_larger_than_4_kib() {
        let srv = spawn_dot_server(DotBehavior::Big(300)).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(10), ask(&client))
            .await
            .expect("a 4.8 KiB answer must not stall")
            .expect("a 4.8 KiB answer must be accepted over DoT");
        assert_eq!(answer, expected_address());
    }

    // -- message id -------------------------------------------------------

    /// The id in the response must match the query. A different id is someone
    /// else's answer (or a desynchronised stream) and must never be returned.
    #[tokio::test]
    async fn rejects_a_response_with_a_mismatched_id() {
        let srv = spawn_dot_server(DotBehavior::WrongId).await;
        let client = srv.client();

        let result = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a mismatched id must fail fast, not hang");
        let err = result.expect_err("a mismatched transaction id must be rejected");
        assert!(
            err.to_string().contains("mismatched DNS transaction ID"),
            "unexpected error: {err}"
        );
    }

    /// A desynchronised stream (an answer with someone else's id) must be
    /// evicted and retried once: rejecting the bad answer must not also lose the
    /// query when a fresh connection would answer correctly.
    #[tokio::test]
    async fn a_desynchronised_stream_is_evicted_and_retried() {
        let srv = spawn_dot_server(DotBehavior::WrongIdFirstQuery).await;
        let client = srv.client();

        let answer = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("a wrong-id answer must not hang")
            .expect("the retry on a fresh connection must succeed");
        assert_eq!(answer, expected_address());
        assert_eq!(srv.accepts(), 2, "the poisoned connection must be evicted");
    }

    // -- error paths ------------------------------------------------------

    /// The peer answers with half a message and closes: that is a transport
    /// failure, never a partial answer.
    #[tokio::test]
    async fn a_peer_that_closes_mid_response_is_an_error() {
        let srv = spawn_dot_server(DotBehavior::CloseMidResponse).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a half-written response must not hang")
            .expect_err("a response cut mid-body must not be accepted");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
        // The broken connection is not retried forever: one retry, then give up.
        assert_eq!(srv.accepts(), 2);
    }

    /// A peer that accepts the connection and sends nothing at all.
    #[tokio::test]
    async fn a_peer_that_sends_zero_bytes_is_an_error() {
        let srv = spawn_dot_server(DotBehavior::CloseImmediately).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("an empty peer must not hang")
            .expect_err("EOF with no bytes is not an answer");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
    }

    /// An announced length of 0xFFFF followed by three bytes: the framing says
    /// 65535 bytes are coming and only three arrive, which must be an error —
    /// not a 3-byte "message" and not a silent truncation.
    #[tokio::test]
    async fn an_absurd_length_prefix_is_an_error() {
        let srv = spawn_dot_server(DotBehavior::AbsurdPrefix).await;
        let client = srv.client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("an absurd prefix must not hang")
            .expect_err("a truncated 0xFFFF message must not be accepted");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
    }

    /// The framing layer itself: a body shorter than the prefix is EOF, and a
    /// zero-length "message" is never mistaken for a DNS answer.
    #[tokio::test]
    async fn read_message_never_returns_a_short_body() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // 40 announced, 20 sent, then EOF.
            let _ = server.write_all(&40u16.to_be_bytes()).await;
            let _ = server.write_all(&[0u8; 20]).await;
            server.shutdown().await.unwrap();
        });
        let err = read_message(&mut client).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = server.write_all(&0u16.to_be_bytes()).await;
            let _ = server.shutdown().await;
        });
        let empty = read_message(&mut client).await.unwrap();
        assert!(empty.is_empty());
        assert!(DnsMessage::validate_response_header(&empty, 0).is_err());
    }

    /// A server that never answers must hit the deadline instead of holding the
    /// client's mutex forever.
    #[tokio::test]
    async fn an_unresponsive_server_times_out() {
        let srv = spawn_dot_server(DotBehavior::Silent).await;
        let client = srv.client();

        let started = std::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(30), ask(&client))
            .await
            .expect("the resolver must not hang on a silent peer")
            .expect_err("a silent peer is a timeout, not an answer");
        assert!(matches!(err, QueryError::Transport(_)), "got {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "bounded attempts took {:?}",
            started.elapsed()
        );
    }

    /// Certificate verification must be on by default: a self-signed server the
    /// client was not told to trust is a hard error, not a silent accept.
    #[tokio::test]
    async fn a_self_signed_server_is_rejected_without_trust() {
        let srv = spawn_dot_server(DotBehavior::Answer).await;
        // No connector override: the production path, webpki roots only.
        let client = srv.untrusting_client();

        let err = tokio::time::timeout(Duration::from_secs(20), ask(&client))
            .await
            .expect("a bad certificate must fail the query, not hang")
            .expect_err("an untrusted self-signed certificate must be rejected");
        let text = err.to_string();
        assert!(
            text.contains("certificate") || text.contains("handshake") || text.contains("TLS"),
            "unexpected error: {text}"
        );
    }

    // -- reuse and pooling ------------------------------------------------

    /// Three queries, one connection: DoT is pooled on purpose.
    #[tokio::test]
    async fn a_healthy_connection_is_reused() {
        let srv = spawn_dot_server(DotBehavior::Answer).await;
        let client = srv.client();

        for _ in 0..3 {
            ask(&client).await.expect("every query must succeed");
        }
        assert_eq!(srv.accepts(), 1, "the pooled connection must be reused");
    }

    /// A pooled connection the peer has already closed must not be handed out
    /// again: the first query works, the second must transparently reconnect
    /// instead of failing.
    #[tokio::test]
    async fn a_closed_pooled_connection_is_replaced() {
        let srv = spawn_dot_server(DotBehavior::AnswerThenClose).await;
        let client = srv.client();

        ask(&client).await.expect("first query must succeed");
        let second = tokio::time::timeout(Duration::from_secs(15), ask(&client))
            .await
            .expect("the second query must not hang")
            .expect("a stale pooled connection must be replaced, not reused");
        assert_eq!(second, expected_address());
        assert_eq!(srv.accepts(), 2, "the client must have reconnected once");
    }

    /// A failed connection must not be retried forever: a dead server costs at
    /// most the two bounded attempts, and the next query starts over.
    #[tokio::test]
    async fn a_failed_connection_is_evicted() {
        let srv = spawn_dot_server(DotBehavior::CloseImmediately).await;
        let client = srv.client();

        assert!(ask(&client).await.is_err());
        let after_first = srv.accepts();
        assert!(ask(&client).await.is_err());
        assert!(
            srv.accepts() > after_first,
            "the second query must dial again instead of reusing a dead stream"
        );
    }

    // -- configuration ----------------------------------------------------

    #[test]
    fn parses_bracketed_ipv6_and_plain_server_forms() {
        let v6 = DotClient::new("tls://[2606:4700:4700::1111]");
        assert_eq!(v6.server_host, "2606:4700:4700::1111");
        assert_eq!(v6.server_port, 853);

        let v6_port = DotClient::new("tls://[2606:4700:4700::1111]:8853");
        assert_eq!(v6_port.server_host, "2606:4700:4700::1111");
        assert_eq!(v6_port.server_port, 8853);

        let bare_v6 = DotClient::new("tls://::1");
        assert_eq!(bare_v6.server_host, "::1");
        assert_eq!(bare_v6.server_port, 853);

        let plain = DotClient::new("tls://1.1.1.1:853");
        assert_eq!(plain.server_host, "1.1.1.1");
        assert_eq!(plain.server_port, 853);

        let host = DotClient::new("dot://dns.google");
        assert!(format!("{host:?}").contains("DotClient"), "Debug must name the client");
        assert_eq!(host.server_host, "dns.google");
        assert_eq!(host.server_port, 853);
        assert_eq!(host.sni, "dns.google");
    }
}

// ---------------------------------------------------------------------------
// Real-network smoke test
// ---------------------------------------------------------------------------

/// The loopback tests prove the *client*; only a real resolver proves the world.
/// Ignored by default and loud about being skipped:
/// `cargo test -p flux-dns -- --ignored`.
#[cfg(test)]
mod live_network {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    #[ignore = "needs the public internet"]
    async fn queries_a_real_dot_resolver() {
        if let Err(e) = tokio::net::TcpStream::connect("1.1.1.1:853").await {
            eprintln!("SKIP live DoT test: no route to 1.1.1.1:853 ({e})");
            return;
        }
        let client = DotClient::new("tls://1.1.1.1");
        let name = Name::from_str("example.com").unwrap();
        let answer = client
            .query_dot(&name, None, crate::wire::QTYPE_A)
            .await
            .expect("a real DoT resolver must answer");
        assert!(
            matches!(answer, Answer::Address { .. }),
            "expected an A record, got {answer:?}"
        );
    }
}
