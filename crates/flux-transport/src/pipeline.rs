use crate::reality::{RealityClientConfig, RealityHandshake, RealityServerConfig};
use crate::shadowtls::{ShadowTlsClientConfig, ShadowTlsHandshake, ShadowTlsServerConfig};
use crate::tcp::TcpTransport;
use crate::tls::{TlsClientConfig, TlsTransport};
use async_trait::async_trait;
use flux_types::{BoxedStream, FluxError, FluxResult, StreamDialer, TargetAddress};
use std::collections::HashMap;
use std::time::Duration;

/// Plaintext rustls may hold before it stops accepting writes.
///
/// One relay buffer plus a framing header has to fit, or a vectored write of a whole frame
/// is always short and the layer above falls back to copying.
pub(crate) const TLS_WRITE_BUFFER: usize = flux_common::copy::RELAY_BUFFER_BYTES + 16 * 1024;

#[derive(Clone, Debug)]
/// A client-side security layer to apply, outermost last.
pub enum SecurityLayer {
    /// No layer at all.
    None,
    /// TLS, client side.
    Tls(TlsClientConfig),
    /// REALITY, client side.
    Reality(RealityClientConfig),
    /// ShadowTLS, client side.
    ShadowTls(ShadowTlsClientConfig),
    /// Split the TLS ClientHello into fragments.
    Fragment(crate::fragment::FragmentationConfig),
}

#[derive(Clone, Debug, Default)]
/// A client-side framing layer to apply, innermost first.
pub enum FramingLayer {
    #[default]
    /// No framing: the bytes pass through untouched.
    Raw,
    /// WebSocket framing, RFC 6455.
    WebSocket {
        /// Request path from the configuration.
        path: String,
        /// Extra HTTP headers to send with the upgrade request.
        headers: HashMap<String, String>,
    },
    /// Upgrade framing.
    HttpUpgrade {
        /// Request path from the configuration.
        path: String,
        /// Extra HTTP headers to send with the upgrade request.
        headers: HashMap<String, String>,
    },
    /// HTTP/2 framing.
    Http2 {
        /// Request path from the configuration.
        path: String,
        /// Extra HTTP headers to send with the upgrade request.
        headers: HashMap<String, String>,
    },
    ///  framing over HTTP/2.
    /// XHTTP (`splithttp`), stream-one mode.
    Xhttp {
        /// Base path; a per-connection suffix is appended to it.
        path: String,
        /// Extra headers.
        headers: HashMap<String, String>,
    },
    /// gRPC framing over HTTP/2.
    Grpc {
        /// gRPC service name used in the request path.
        service_name: String,
        /// Extra HTTP headers to send with the upgrade request.
        headers: HashMap<String, String>,
    },
}

/// Dynamic, composable layered transport pipeline:
/// [L4 Carrier] ──► [L5 Security Layer] ──► [L6 Framing Layer]
/// A dial plan: how to reach one server and what to wrap the connection in.
pub struct LayeredTransportPipeline {
    /// Set when the node's carrier is mKCP instead of TCP.
    /// Set when the carrier is mKCP rather than TCP.
    pub kcp: Option<crate::kcp::KcpConfig>,
    server_address: TargetAddress,
    resolved_addr: std::net::SocketAddr,
    connect_timeout: Duration,
    securities: Vec<SecurityLayer>,
    framings: Vec<FramingLayer>,
    host_header: String,
}

impl LayeredTransportPipeline {
    /// A plan for `server_address`, already resolved to `resolved_addr`.
    pub fn new(server_address: TargetAddress, resolved_addr: std::net::SocketAddr) -> Self {
        let host = server_address.host();
        Self {
            kcp: None,
            server_address,
            resolved_addr,
            connect_timeout: Duration::from_secs(10),
            securities: Vec::new(),
            framings: Vec::new(),
            host_header: host,
        }
    }

    /// Selects mKCP as the carrier instead of TCP.
    /// Carries the connection over mKCP instead of TCP.
    pub fn with_kcp(mut self, kcp: crate::kcp::KcpConfig) -> Self {
        self.kcp = Some(kcp);
        self
    }

    /// How long the whole dial may take; the transport's own timeout still applies.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Appends one security layer.
    pub fn with_security(mut self, sec: SecurityLayer) -> Self {
        self.securities.push(sec);
        self
    }

    /// Replaces the security layers wholesale.
    pub fn with_securities(mut self, secs: Vec<SecurityLayer>) -> Self {
        self.securities = secs;
        self
    }

    /// Appends one framing layer.
    pub fn with_framing(mut self, framing: FramingLayer) -> Self {
        self.framings.push(framing);
        self
    }

    /// Replaces the framing layers wholesale.
    pub fn with_framings(mut self, framings: Vec<FramingLayer>) -> Self {
        self.framings = framings;
        self
    }

    /// Host header for the HTTP-shaped framings; defaults to the server address.
    pub fn with_host_header(mut self, host: impl Into<String>) -> Self {
        self.host_header = host.into();
        self
    }

    /// The address this plan dials, as the peer knows it (before resolution).
    pub fn server_address(&self) -> &TargetAddress {
        &self.server_address
    }
}

impl LayeredTransportPipeline {
    /// One dial attempt. `allow_native` is false for the rustls fallback, so a server that
    /// cannot speak TLS 1.3 is reached with a stack that also negotiates 1.2.
    async fn dial_with(&self, allow_native: bool) -> FluxResult<BoxedStream> {
        // 1. Layer 1 (Carrier): TCP, or mKCP when the node asks for it. KCP is a
        // reliable byte stream over UDP, so everything above this line — TLS,
        // REALITY, WebSocket, the protocol itself — is unchanged.
        let mut stream: BoxedStream = match &self.kcp {
            Some(kcp_cfg) => {
                let kcp_stream = tokio::time::timeout(
                    self.connect_timeout,
                    crate::kcp::connect(self.resolved_addr, *kcp_cfg),
                )
                .await
                .map_err(|_| FluxError::Timeout("mKCP connect timed out".into()))??;
                Box::new(kcp_stream)
            }
            None => {
                let tcp_stream =
                    TcpTransport::connect(self.resolved_addr, self.connect_timeout).await?;
                Box::new(tcp_stream)
            }
        };

        // 2. Layer 2 (Security): Sequentially apply security layers
        for sec in &self.securities {
            stream = match sec {
                SecurityLayer::None => stream,
                SecurityLayer::Tls(cfg) => {
                    let mut cfg = cfg.clone();
                    if !allow_native {
                        cfg.native = false;
                    }
                    TlsTransport::connect(stream, &cfg).await?
                }
                SecurityLayer::Reality(cfg) => {
                    let s = RealityHandshake::client_handshake(stream, cfg).await?;
                    Box::new(s)
                }
                SecurityLayer::ShadowTls(cfg) => {
                    ShadowTlsHandshake::client_handshake(stream, cfg).await?
                }
                SecurityLayer::Fragment(cfg) => {
                    Box::new(crate::fragment::FragmentedStream::new(stream, *cfg))
                }
            };
        }

        // 3. Layer 3 (Framing): Sequentially apply framing layers
        for framing in &self.framings {
            stream = match framing {
                FramingLayer::Raw => stream,
                FramingLayer::Xhttp { path, headers } => {
                    let st =
                        crate::xhttp::connect(stream, &self.host_header, path, headers).await?;
                    Box::new(st)
                }
                FramingLayer::WebSocket { path, headers } => {
                    let ws = crate::websocket::client_handshake(
                        stream,
                        &self.host_header,
                        path,
                        headers,
                    )
                    .await?;
                    Box::new(ws)
                }
                FramingLayer::HttpUpgrade { path, headers } => {
                    crate::httpupgrade::client_handshake(stream, &self.host_header, path, headers)
                        .await?
                }
                FramingLayer::Http2 { path, headers } => {
                    let h2 = crate::h2::H2Transport::client_handshake(
                        stream,
                        &self.host_header,
                        path,
                        headers,
                    )
                    .await?;
                    Box::new(h2)
                }
                FramingLayer::Grpc {
                    service_name,
                    headers,
                } => {
                    let grpc = crate::grpc::GrpcTransport::client_handshake(
                        stream,
                        &self.host_header,
                        service_name,
                        headers,
                    )
                    .await?;
                    Box::new(grpc)
                }
            };
        }

        Ok(stream)
    }
}

#[async_trait]
impl StreamDialer for LayeredTransportPipeline {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let started = std::time::Instant::now();
        let first = match tokio::time::timeout(self.connect_timeout, self.dial_with(true)).await {
            Ok(res) => res,
            Err(_) => {
                return Err(flux_types::FluxError::Timeout(format!(
                    "layered transport dial to {} timed out after {:?}",
                    self.server_address, self.connect_timeout
                )));
            }
        };

        // A server that cannot speak TLS 1.3 is old, not hostile. The native client exists for
        // its ClientHello; if that is the only reason the dial failed, redial once with rustls,
        // which negotiates 1.2 as well. Every other error is returned untouched — a failed
        // certificate check must never be retried with a different stack.
        let Some(err) = first.as_ref().err() else {
            return first;
        };
        // Retry only for a handshake this client could not complete, and never for a rejected
        // certificate: that decision belongs to whichever stack made it, and swapping stacks to
        // get a different answer is the definition of a downgrade.
        let retryable = match err {
            flux_types::FluxError::Protocol { protocol, message } if *protocol == "tls13" => {
                !crate::tls13::is_verification_failure(message)
            }
            _ => false,
        };
        let text = err.to_string();
        if !retryable || !self.securities.iter().any(is_native_tls) {
            return first;
        }
        tracing::debug!(
            "the server did not negotiate TLS 1.3; retrying this dial with rustls ({text})"
        );
        let remaining = self
            .connect_timeout
            .saturating_sub(started.elapsed())
            .max(std::time::Duration::from_millis(500));
        match tokio::time::timeout(remaining, self.dial_with(false)).await {
            Ok(Ok(stream)) => Ok(stream),
            // The fallback failing is less informative than the original error.
            _ => first,
        }
    }
}

/// Whether a security layer is the one this client's own handshake would drive.
fn is_native_tls(layer: &SecurityLayer) -> bool {
    matches!(layer, SecurityLayer::Tls(cfg) if cfg.native)
}

#[derive(Clone)]
/// A server-side security layer, built from configuration.
pub enum ServerSecurityLayer {
    /// No layer at all.
    None,
    /// TLS, server side.
    Tls(tokio_rustls::TlsAcceptor),
    /// REALITY, server side.
    Reality(RealityServerConfig),
    /// ShadowTLS, server side.
    ShadowTls(ShadowTlsServerConfig),
}

#[derive(Clone, Debug, Default)]
/// A server-side framing layer, built from configuration.
pub enum ServerFramingLayer {
    #[default]
    /// No framing: the bytes pass through untouched.
    Raw,
    /// WebSocket framing, RFC 6455.
    WebSocket {
        /// Request path; the transport default when `None`.
        path: Option<String>,
    },
    /// XHTTP (`splithttp`), stream-one mode.
    Xhttp {
        /// Base path; the client appends a per-connection suffix.
        path: Option<String>,
    },
    /// Upgrade framing.
    HttpUpgrade {
        /// Request path; the transport default when `None`.
        path: Option<String>,
    },
    /// Raw HTTP/2 framing.
    Http2,
    /// gRPC framing over HTTP/2.
    Grpc,
}

/// Namespace for the server-side handshake helpers.
pub struct ServerLayeredTransportPipeline;

impl ServerLayeredTransportPipeline {}

#[derive(Clone)]
/// What a server accepts: the layers in configuration order and the handshake timeout.
pub struct ServerTransportPipeline {
    /// Security layers, applied outermost last.
    pub securities: Vec<ServerSecurityLayer>,
    /// Framing layers, applied innermost first.
    pub framings: Vec<ServerFramingLayer>,
    /// How long a peer has to complete the handshake.
    pub timeout: Duration,
}

impl ServerTransportPipeline {
    /// A pipeline over the given layers, with the default timeout.
    pub fn new(securities: Vec<ServerSecurityLayer>, framings: Vec<ServerFramingLayer>) -> Self {
        Self {
            securities,
            framings,
            timeout: Duration::from_secs(15),
        }
    }

    /// The common case: exactly one security and one framing layer.
    pub fn single(security: ServerSecurityLayer, framing: ServerFramingLayer) -> Self {
        Self {
            securities: vec![security],
            framings: vec![framing],
            timeout: Duration::from_secs(15),
        }
    }

    /// A pipeline with no layers, for a plain listener.
    pub fn raw() -> Self {
        Self::new(vec![], vec![])
    }

    /// Applies this pipeline's layers to a freshly connected stream.
    pub async fn unwrap<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
    >(
        &self,
        carrier_stream: S,
    ) -> FluxResult<BoxedStream> {
        let boxed: BoxedStream = Box::new(carrier_stream);
        let fut = async {
            let mut stream = boxed;

            // 1. Unwrap security layers in sequence
            for sec in &self.securities {
                stream = match sec {
                    ServerSecurityLayer::None => stream,
                    ServerSecurityLayer::Tls(acceptor) => {
                        let mut s = acceptor.accept(stream).await.map_err(FluxError::Io)?;
                        // A writer above this layer may hand rustls a whole 64 KiB frame
                        // plus its header in one vectored write, and rustls' default
                        // 64 KiB buffer limit makes that a short write every time. Raising
                        // it lets the frame pass through in one call instead of being
                        // copied into a frame buffer first.
                        s.get_mut().1.set_buffer_limit(Some(TLS_WRITE_BUFFER));
                        Box::new(s)
                    }
                    ServerSecurityLayer::Reality(cfg) => {
                        let s = RealityHandshake::server_handshake(stream, cfg).await?;
                        Box::new(s)
                    }
                    ServerSecurityLayer::ShadowTls(cfg) => {
                        ShadowTlsHandshake::server_handshake(stream, cfg).await?
                    }
                };
            }

            // 2. Unwrap framing layers in sequence
            for framing in &self.framings {
                stream = match framing {
                    ServerFramingLayer::Raw => stream,
                    ServerFramingLayer::Xhttp { path } => {
                        let st = crate::xhttp::accept(
                            stream,
                            path.as_deref().unwrap_or(crate::xhttp::DEFAULT_XHTTP_PATH),
                        )
                        .await?;
                        Box::new(st)
                    }
                    ServerFramingLayer::WebSocket { path } => {
                        let ws =
                            crate::websocket::server_handshake(stream, path.as_deref()).await?;
                        Box::new(ws)
                    }
                    ServerFramingLayer::HttpUpgrade { path } => {
                        crate::httpupgrade::server_handshake(stream, path.as_deref()).await?
                    }
                    ServerFramingLayer::Http2 => {
                        let h2 = crate::h2::H2Transport::server_handshake(stream).await?;
                        Box::new(h2)
                    }
                    ServerFramingLayer::Grpc => {
                        let grpc = crate::grpc::GrpcTransport::server_handshake(stream).await?;
                        Box::new(grpc)
                    }
                };
            }

            Ok(stream)
        };

        match tokio::time::timeout(self.timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(FluxError::Timeout(
                "server transport pipeline handshake timed out".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The pipeline is where every security and framing layer is composed; a bug
    /// here means the wrong protocol goes on the wire. Each test stands up a real
    /// server listener, dials it through the client pipeline and asserts a
    /// byte-exact round trip in both directions.
    async fn serve_one(server: ServerTransportPipeline) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut stream) = server.unwrap(socket).await else {
                return;
            };
            let mut buf = vec![0u8; 9];
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }
            assert_eq!(&buf, b"from-cli!");
            let _ = stream.write_all(b"from-srv!").await;
            let _ = stream.flush().await;
            // Give the peer time to read before dropping the stream: dropping an
            // H2/gRPC response immediately can race the RST_STREAM against the
            // data, which is a test artefact rather than a tunnel bug.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        addr
    }

    async fn round_trip(client: LayeredTransportPipeline) {
        let mut stream = tokio::time::timeout(std::time::Duration::from_secs(10), client.dial())
            .await
            .expect("client handshake must not hang")
            .expect("client handshake");
        stream.write_all(b"from-cli!").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; 9];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut buf),
        )
        .await
        .expect("server must answer")
        .expect("read");
        assert_eq!(&buf, b"from-srv!");
    }

    fn client(addr: std::net::SocketAddr) -> LayeredTransportPipeline {
        LayeredTransportPipeline::new(TargetAddress::domain("example.com", 443), addr)
    }

    #[tokio::test]
    async fn raw_to_raw_round_trips() {
        let addr = serve_one(ServerTransportPipeline::raw()).await;
        round_trip(client(addr)).await;
    }

    #[tokio::test]
    async fn websocket_round_trips() {
        let addr = serve_one(ServerTransportPipeline::new(
            vec![ServerSecurityLayer::None],
            vec![ServerFramingLayer::WebSocket {
                path: Some("/tunnel".into()),
            }],
        ))
        .await;
        let c = client(addr).with_framing(FramingLayer::WebSocket {
            path: "/tunnel".into(),
            headers: HashMap::new(),
        });
        round_trip(c).await;
    }

    #[tokio::test]
    async fn httpupgrade_round_trips() {
        let addr = serve_one(ServerTransportPipeline::new(
            vec![ServerSecurityLayer::None],
            vec![ServerFramingLayer::HttpUpgrade {
                path: Some("/up".into()),
            }],
        ))
        .await;
        let c = client(addr).with_framing(FramingLayer::HttpUpgrade {
            path: "/up".into(),
            headers: HashMap::new(),
        });
        round_trip(c).await;
    }

    #[tokio::test]
    async fn http2_round_trips() {
        let addr = serve_one(ServerTransportPipeline::new(
            vec![ServerSecurityLayer::None],
            vec![ServerFramingLayer::Http2],
        ))
        .await;
        let c = client(addr).with_framing(FramingLayer::Http2 {
            path: "/".into(),
            headers: HashMap::new(),
        });
        round_trip(c).await;
    }

    #[tokio::test]
    async fn grpc_round_trips() {
        let addr = serve_one(ServerTransportPipeline::new(
            vec![ServerSecurityLayer::None],
            vec![ServerFramingLayer::Grpc],
        ))
        .await;
        let c = client(addr).with_framing(FramingLayer::Grpc {
            service_name: "Tun".into(),
            headers: HashMap::new(),
        });
        round_trip(c).await;
    }

    /// Two layers compose: fragmentation *under* WebSocket framing. The fragment
    /// layer must not corrupt the framing it wraps.
    #[tokio::test]
    async fn fragment_under_websocket_composes() {
        let addr = serve_one(ServerTransportPipeline::new(
            vec![ServerSecurityLayer::None],
            vec![ServerFramingLayer::WebSocket {
                path: Some("/x".into()),
            }],
        ))
        .await;
        let c = client(addr)
            .with_security(SecurityLayer::Fragment(
                crate::fragment::FragmentationConfig {
                    enabled: true,
                    length_min: 2,
                    length_max: 4,
                    interval_ms: 1,
                },
            ))
            .with_framing(FramingLayer::WebSocket {
                path: "/x".into(),
                headers: HashMap::new(),
            });
        round_trip(c).await;
    }

    /// A path mismatch must be rejected, not silently accepted on the wrong path.
    #[tokio::test]
    async fn websocket_path_mismatch_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            ServerTransportPipeline::new(
                vec![ServerSecurityLayer::None],
                vec![ServerFramingLayer::WebSocket {
                    path: Some("/expected".into()),
                }],
            )
            .unwrap(socket)
            .await
            .map(|_| ())
        });

        let c = client(addr).with_framing(FramingLayer::WebSocket {
            path: "/wrong".into(),
            headers: HashMap::new(),
        });
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), c.dial()).await;

        let res = tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
            .await
            .expect("server must not hang")
            .expect("join");
        assert!(res.is_err(), "a path mismatch must be rejected");
    }

    #[tokio::test]
    async fn server_address_survives_construction() {
        let p = client("127.0.0.1:443".parse().unwrap());
        assert_eq!(p.server_address().host(), "example.com");
        assert_eq!(p.server_address().port(), 443);
    }
}

#[cfg(test)]
mod stage_agreement_tests {
    /// Every stage above the socket must hold one relay buffer plus its own overhead.
    ///
    /// This is the invariant that broke three times: a frame capped at 16 KiB under a relay
    /// buffer of 64 KiB, then a frame capped at 64 KiB under a relay buffer of 256 KiB. Each
    /// constant was correct when written and wrong afterwards, and no test compared them.
    #[test]
    fn pipeline_stages_agree_on_the_relay_buffer() {
        use flux_common::copy::RELAY_BUFFER_BYTES as RELAY;

        // The TLS record buffer holds a whole relay buffer plus a frame header and the
        // record's own overhead, so one relay write never has to be split. Const-evaluated
        // rather than asserted at runtime: both sides are compile-time constants.
        const _: () = assert!(super::TLS_WRITE_BUFFER >= RELAY + 8 * 1024);

        // A WebSocket frame carries exactly one relay write; the writer caps at this value
        // and the reader's test asserts the same number.
        assert_eq!(
            crate::websocket::FRAME_CAP,
            RELAY,
            "the WebSocket frame cap must equal the relay buffer, or a write is split into several frames"
        );

        // An h2 stream window holds at least one relay write, and the connection window at
        // least two, so a single stream is never throttled by the connection.
        let stream = crate::h2::shared::STREAM_WINDOW as usize;
        let connection = crate::h2::shared::CONNECTION_WINDOW as usize;
        assert!(
            stream >= RELAY,
            "h2 stream window {} is below the relay buffer {}",
            stream,
            RELAY
        );
        assert!(
            connection >= 2 * stream,
            "h2 connection window {} is below twice the stream window {}",
            connection,
            stream
        );
    }
}
