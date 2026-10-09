use crate::reality::{RealityClientConfig, RealityHandshake};
use crate::tcp::TcpTransport;
use crate::tls::{TlsClientConfig, TlsTransport};
use async_trait::async_trait;
use flux_types::{BoxedStream, FluxResult, StreamDialer, TargetAddress};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum SecurityLayer {
    None,
    Tls(TlsClientConfig),
    Reality(RealityClientConfig),
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
    security: SecurityLayer,
    framing: FramingLayer,
    host_header: String,
}

impl LayeredTransportPipeline {
    pub fn new(server_address: TargetAddress, resolved_addr: std::net::SocketAddr) -> Self {
        let host = server_address.host();
        Self {
            server_address,
            resolved_addr,
            connect_timeout: Duration::from_secs(10),
            security: SecurityLayer::None,
            framing: FramingLayer::Raw,
            host_header: host,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_security(mut self, sec: SecurityLayer) -> Self {
        self.security = sec;
        self
    }

    pub fn with_framing(mut self, framing: FramingLayer) -> Self {
        self.framing = framing;
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

            // 2. Layer 2 (Security): Apply TLS, REALITY, or None
            let secure_stream: BoxedStream = match &self.security {
                SecurityLayer::None => Box::new(tcp_stream),
                SecurityLayer::Tls(cfg) => TlsTransport::connect(tcp_stream, cfg).await?,
                SecurityLayer::Reality(cfg) => {
                    let s = RealityHandshake::client_handshake(tcp_stream, cfg).await?;
                    Box::new(s)
                }
            };

            // 3. Layer 3 (Framing): Apply WebSocket, HTTPUpgrade, or Raw Stream
            let framed_stream: BoxedStream = match &self.framing {
                FramingLayer::Raw => secure_stream,
                FramingLayer::WebSocket { path, headers } => {
                    let ws = crate::websocket::client_handshake(
                        secure_stream,
                        &self.host_header,
                        path,
                        headers,
                    )
                    .await?;
                    Box::new(ws)
                }
                FramingLayer::HttpUpgrade { path, headers } => {
                    crate::httpupgrade::client_handshake(
                        secure_stream,
                        &self.host_header,
                        path,
                        headers,
                    )
                    .await?
                }
                FramingLayer::Http2 { path, headers } => {
                    let h2 = crate::h2::H2Transport::client_handshake(
                        secure_stream,
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
                        secure_stream,
                        &self.host_header,
                        service_name,
                        headers,
                    )
                    .await?;
                    Box::new(grpc)
                }
            };

            Ok(framed_stream)
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
