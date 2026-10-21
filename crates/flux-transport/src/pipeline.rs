use crate::reality::{RealityClientConfig, RealityHandshake, RealityServerConfig};
use crate::shadowtls::{ShadowTlsClientConfig, ShadowTlsHandshake, ShadowTlsServerConfig};
use crate::tcp::TcpTransport;
use crate::tls::{TlsClientConfig, TlsTransport};
use async_trait::async_trait;
use flux_types::{BoxedStream, FluxError, FluxResult, StreamDialer, TargetAddress};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum SecurityLayer {
    None,
    Tls(TlsClientConfig),
    Reality(RealityClientConfig),
    ShadowTls(ShadowTlsClientConfig),
    Fragment(crate::fragment::FragmentationConfig),
}

#[derive(Clone, Debug, Default)]
pub enum FramingLayer {
    #[default]
    Raw,
    WebSocket {
        path: String,
        headers: HashMap<String, String>,
    },
    HttpUpgrade {
        path: String,
        headers: HashMap<String, String>,
    },
    Http2 {
        path: String,
        headers: HashMap<String, String>,
    },
    Grpc {
        service_name: String,
        headers: HashMap<String, String>,
    },
}

/// Dynamic, composable layered transport pipeline:
/// [L4 Carrier] ──► [L5 Security Layer] ──► [L6 Framing Layer]
pub struct LayeredTransportPipeline {
    server_address: TargetAddress,
    resolved_addr: std::net::SocketAddr,
    connect_timeout: Duration,
    securities: Vec<SecurityLayer>,
    framings: Vec<FramingLayer>,
    host_header: String,
}

impl LayeredTransportPipeline {
    pub fn new(server_address: TargetAddress, resolved_addr: std::net::SocketAddr) -> Self {
        let host = server_address.host();
        Self {
            server_address,
            resolved_addr,
            connect_timeout: Duration::from_secs(10),
            securities: Vec::new(),
            framings: Vec::new(),
            host_header: host,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_security(mut self, sec: SecurityLayer) -> Self {
        self.securities.push(sec);
        self
    }

    pub fn with_securities(mut self, secs: Vec<SecurityLayer>) -> Self {
        self.securities = secs;
        self
    }

    pub fn with_framing(mut self, framing: FramingLayer) -> Self {
        self.framings.push(framing);
        self
    }

    pub fn with_framings(mut self, framings: Vec<FramingLayer>) -> Self {
        self.framings = framings;
        self
    }

    pub fn with_host_header(mut self, host: impl Into<String>) -> Self {
        self.host_header = host.into();
        self
    }

    pub fn server_address(&self) -> &TargetAddress {
        &self.server_address
    }
}

#[async_trait]
impl StreamDialer for LayeredTransportPipeline {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        let dial_fut = async {
            // 1. Layer 1 (Carrier): Establish base TCP connection
            let tcp_stream =
                TcpTransport::connect(self.resolved_addr, self.connect_timeout).await?;
            let mut stream: BoxedStream = Box::new(tcp_stream);

            // 2. Layer 2 (Security): Sequentially apply security layers
            for sec in &self.securities {
                stream = match sec {
                    SecurityLayer::None => stream,
                    SecurityLayer::Tls(cfg) => TlsTransport::connect(stream, cfg).await?,
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
                        crate::httpupgrade::client_handshake(
                            stream,
                            &self.host_header,
                            path,
                            headers,
                        )
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
        };

        match tokio::time::timeout(self.connect_timeout, dial_fut).await {
            Ok(res) => res,
            Err(_) => Err(flux_types::FluxError::Timeout(format!(
                "layered transport dial to {} timed out after {:?}",
                self.server_address, self.connect_timeout
            ))),
        }
    }
}

#[derive(Clone)]
pub enum ServerSecurityLayer {
    None,
    Tls(tokio_rustls::TlsAcceptor),
    Reality(RealityServerConfig),
    ShadowTls(ShadowTlsServerConfig),
}

#[derive(Clone, Debug, Default)]
pub enum ServerFramingLayer {
    #[default]
    Raw,
    WebSocket {
        path: Option<String>,
    },
    HttpUpgrade {
        path: Option<String>,
    },
    Http2,
    Grpc,
}

pub struct ServerLayeredTransportPipeline;

impl ServerLayeredTransportPipeline {}

#[derive(Clone)]
pub struct ServerTransportPipeline {
    pub securities: Vec<ServerSecurityLayer>,
    pub framings: Vec<ServerFramingLayer>,
    pub timeout: Duration,
}

impl ServerTransportPipeline {
    pub fn new(securities: Vec<ServerSecurityLayer>, framings: Vec<ServerFramingLayer>) -> Self {
        Self {
            securities,
            framings,
            timeout: Duration::from_secs(15),
        }
    }

    pub fn single(security: ServerSecurityLayer, framing: ServerFramingLayer) -> Self {
        Self {
            securities: vec![security],
            framings: vec![framing],
            timeout: Duration::from_secs(15),
        }
    }

    pub fn raw() -> Self {
        Self::new(vec![], vec![])
    }

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
                        let s = acceptor.accept(stream).await.map_err(FluxError::Io)?;
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
