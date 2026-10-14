use flux_types::{FluxError, FluxResult};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// A bidirectional stream operating over an active QUIC stream.
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

pub struct QuicTransport;

impl QuicTransport {
    /// Builds the shared QUIC client configuration (TLS + transport params).
    fn build_client_config(alpn: Vec<Vec<u8>>, insecure: bool) -> FluxResult<quinn::ClientConfig> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let crypto = if insecure {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let mut config = crypto;
        config.alpn_protocols = alpn;

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        transport.max_concurrent_bidi_streams(256u32.into());
        transport.max_concurrent_uni_streams(256u32.into());
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport.datagram_send_buffer_size(4 * 1024 * 1024);
        if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)) {
            transport.max_idle_timeout(Some(idle));
        }

        let mut client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(config).map_err(|e| {
                FluxError::Crypto(format!("failed to configure QUIC TLS 1.3: {}", e))
            })?,
        ));
        client_cfg.transport_config(Arc::new(transport));
        Ok(client_cfg)
    }

    /// Creates a client QUIC Endpoint with the specified ALPN protocols.
    pub fn create_client_endpoint(
        is_ipv6: bool,
        alpn: Vec<Vec<u8>>,
        insecure: bool,
    ) -> FluxResult<quinn::Endpoint> {
        let client_cfg = Self::build_client_config(alpn, insecure)?;
        let bind_addr = if is_ipv6 {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };

        let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(FluxError::Io)?;
        endpoint.set_default_client_config(client_cfg);
        Ok(endpoint)
    }

    /// Client endpoint with Salamander-obfuscated UDP (Hysteria 2 `obfs`).
    pub fn create_client_endpoint_obfs(
        is_ipv6: bool,
        alpn: Vec<Vec<u8>>,
        insecure: bool,
        obfs_password: &str,
    ) -> FluxResult<quinn::Endpoint> {
        let client_cfg = Self::build_client_config(alpn, insecure)?;
        let bind_addr = if is_ipv6 {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let socket = std::net::UdpSocket::bind(bind_addr).map_err(FluxError::Io)?;
        socket.set_nonblocking(true).map_err(FluxError::Io)?;
        let runtime = crate::quic_obfs::SalamanderRuntime::new(obfs_password);
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime as Arc<dyn quinn::Runtime>,
        )
        .map_err(FluxError::Io)?;
        endpoint.set_default_client_config(client_cfg);
        Ok(endpoint)
    }

    /// Server endpoint with Salamander-obfuscated UDP (Hysteria 2 `obfs`).
    pub fn create_server_endpoint_obfs(
        listen_addr: SocketAddr,
        certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
        key: tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>,
        alpn: Vec<Vec<u8>>,
        obfs_password: &str,
    ) -> FluxResult<quinn::Endpoint> {
        let mut server_crypto = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                FluxError::Crypto(format!("failed to configure QUIC server TLS: {}", e))
            })?;
        server_crypto.alpn_protocols = alpn;

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(256u32.into());
        transport.max_concurrent_uni_streams(256u32.into());
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport.datagram_send_buffer_size(4 * 1024 * 1024);
        if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)) {
            transport.max_idle_timeout(Some(idle));
        }

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(|e| {
                FluxError::Crypto(format!("failed to create QUIC server config: {}", e))
            })?,
        ));
        server_config.transport_config(Arc::new(transport));

        let socket = std::net::UdpSocket::bind(listen_addr).map_err(FluxError::Io)?;
        socket.set_nonblocking(true).map_err(FluxError::Io)?;
        let runtime = crate::quic_obfs::SalamanderRuntime::new(obfs_password);
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime as Arc<dyn quinn::Runtime>,
        )
        .map_err(FluxError::Io)
    }

    /// Creates a server QUIC Endpoint with certificates, private key, and ALPN protocols.
    pub fn create_server_endpoint(
        listen_addr: SocketAddr,
        certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
        key: tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>,
        alpn: Vec<Vec<u8>>,
    ) -> FluxResult<quinn::Endpoint> {
        let mut server_crypto = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                FluxError::Crypto(format!("failed to configure QUIC server TLS: {}", e))
            })?;
        server_crypto.alpn_protocols = alpn;

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(256u32.into());
        transport.max_concurrent_uni_streams(256u32.into());
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport.datagram_send_buffer_size(4 * 1024 * 1024);
        if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)) {
            transport.max_idle_timeout(Some(idle));
        }

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(|e| {
                FluxError::Crypto(format!("failed to create QUIC server config: {}", e))
            })?,
        ));
        server_config.transport_config(Arc::new(transport));

        quinn::Endpoint::server(server_config, listen_addr).map_err(FluxError::Io)
    }

    /// Establishes an authenticated QUIC connection to the destination server.
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> FluxResult<quinn::Connection> {
        let conn_connecting = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| FluxError::Network(format!("QUIC connection setup failed: {}", e)))?;

        tokio::time::timeout(std::time::Duration::from_secs(10), conn_connecting)
            .await
            .map_err(|_| {
                FluxError::Timeout(format!("QUIC connection to {} timed out", server_addr))
            })?
            .map_err(|e| FluxError::Network(format!("QUIC handshake failed: {}", e)))
    }

    /// Opens a bidirectional QUIC stream on the connection.
    pub async fn open_bi_stream(conn: &quinn::Connection) -> FluxResult<QuicBiStream> {
        let (send, recv) = tokio::time::timeout(std::time::Duration::from_secs(10), conn.open_bi())
            .await
            .map_err(|_| FluxError::Timeout("opening QUIC stream timed out".into()))?
            .map_err(|e| FluxError::Network(format!("failed to open QUIC stream: {}", e)))?;
        Ok(QuicBiStream::new(send, recv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quic_endpoint_address_family_matching() {
        let ep_v4 =
            QuicTransport::create_client_endpoint(false, vec![b"test".to_vec()], true).unwrap();
        let addr_v4 = ep_v4.local_addr().unwrap();
        assert!(!addr_v4.is_ipv6());

        let ep_v6 =
            QuicTransport::create_client_endpoint(true, vec![b"test".to_vec()], true).unwrap();
        let addr_v6 = ep_v6.local_addr().unwrap();
        assert!(addr_v6.is_ipv6());

        let peer_v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_v6: SocketAddr = "[::1]:443".parse().unwrap();

        assert!(
            ep_v4
                .local_addr()
                .map(|a| a.is_ipv6() == peer_v4.is_ipv6())
                .unwrap_or(false)
        );
        assert!(
            !ep_v4
                .local_addr()
                .map(|a| a.is_ipv6() == peer_v6.is_ipv6())
                .unwrap_or(false)
        );
        assert!(
            ep_v6
                .local_addr()
                .map(|a| a.is_ipv6() == peer_v6.is_ipv6())
                .unwrap_or(false)
        );
        assert!(
            !ep_v6
                .local_addr()
                .map(|a| a.is_ipv6() == peer_v4.is_ipv6())
                .unwrap_or(false)
        );
    }
}
