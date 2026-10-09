use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub use crate::fingerprint::TlsFingerprint;

pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Clone, Debug)]
pub struct TlsClientConfig {
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    pub insecure: bool,
    pub fingerprint: Option<TlsFingerprint>,
}

impl TlsClientConfig {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: vec![],
            insecure: false,
            fingerprint: None,
        }
    }

    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn.into_iter().map(|s| s.into_bytes()).collect();
        self
    }

    pub fn with_fingerprint(mut self, fp: TlsFingerprint) -> Self {
        self.fingerprint = Some(fp);
        self
    }
}

/// Dangerous verifier that accepts any certificate (for testing / self-signed)
#[derive(Debug)]
pub(crate) struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct TlsTransport;

impl TlsTransport {
    pub fn create_client_connector(cfg: &TlsClientConfig) -> FluxResult<TlsConnector> {
        let provider = match cfg.fingerprint.unwrap_or_default() {
            TlsFingerprint::Chrome => crate::fingerprint::create_chrome_provider(),
            TlsFingerprint::Firefox => crate::fingerprint::create_firefox_provider(),
            TlsFingerprint::Safari => crate::fingerprint::create_safari_provider(),
            TlsFingerprint::Random => match rand::random::<u8>() % 3 {
                0 => crate::fingerprint::create_chrome_provider(),
                1 => crate::fingerprint::create_firefox_provider(),
                _ => crate::fingerprint::create_safari_provider(),
            },
        };

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_config = if cfg.insecure {
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| FluxError::Crypto(format!("failed to set TLS versions: {}", e)))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| FluxError::Crypto(format!("failed to set TLS versions: {}", e)))?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let mut config = client_config;
        if !cfg.alpn.is_empty() {
            config.alpn_protocols = cfg.alpn.clone();
        } else {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }

        Ok(TlsConnector::from(Arc::new(config)))
    }

    pub fn create_server_acceptor(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        alpn: Vec<Vec<u8>>,
    ) -> FluxResult<TlsAcceptor> {
        init_crypto_provider();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                FluxError::Crypto(format!("failed to configure TLS server cert: {}", e))
            })?;

        if !alpn.is_empty() {
            config.alpn_protocols = alpn;
        }

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    pub fn load_certs_and_key(
        cert_path: &str,
        key_path: &str,
    ) -> FluxResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_content = std::fs::read(cert_path).map_err(FluxError::Io)?;
        let key_content = std::fs::read(key_path).map_err(FluxError::Io)?;

        let pems = pem::parse_many(&cert_content)
            .map_err(|e| FluxError::Crypto(format!("failed to parse cert pem: {}", e)))?;
        let certs: Vec<CertificateDer<'static>> = pems
            .into_iter()
            .map(|p| CertificateDer::from(p.into_contents()))
            .collect();

        if certs.is_empty() {
            return Err(FluxError::Crypto(
                "no certificates found in pem file".into(),
            ));
        }

        let key_pem = pem::parse(&key_content)
            .map_err(|e| FluxError::Crypto(format!("failed to parse key pem: {}", e)))?;

        let key = match key_pem.tag() {
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(key_pem.into_contents().into()),
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(key_pem.into_contents().into()),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(key_pem.into_contents().into()),
            _ => PrivateKeyDer::Pkcs8(key_pem.into_contents().into()),
        };

        Ok((certs, key))
    }

    pub async fn connect<S>(stream: S, cfg: &TlsClientConfig) -> FluxResult<BoxedStream>
    where
        S: AsyncStream + 'static,
    {
        let connector = Self::create_client_connector(cfg)?;
        let domain = ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| {
                FluxError::Crypto(format!("invalid server name {}: {}", cfg.server_name, e))
            })?
            .to_owned();

        let tls_stream = connector.connect(domain, stream).await.map_err(|e| {
            FluxError::Crypto(format!(
                "TLS handshake failed with {}: {}",
                cfg.server_name, e
            ))
        })?;

        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tls_handshake() {
        init_crypto_provider();
        // Generate self-signed certificate using rcgen
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let acceptor =
            TlsTransport::create_server_acceptor(vec![cert_der], key_der, vec![]).unwrap();
        let client_cfg = TlsClientConfig::new("localhost").with_insecure(true);

        let (client_raw, server_raw) = tokio::io::duplex(4096);

        let srv_task = tokio::spawn(async move {
            let mut srv_tls = acceptor.accept(server_raw).await.unwrap();
            let mut buf = vec![0u8; 5];
            srv_tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping!");
            srv_tls.write_all(b"pong!").await.unwrap();
            srv_tls.shutdown().await.unwrap();
        });

        let cli_task = tokio::spawn(async move {
            let mut cli_tls = TlsTransport::connect(client_raw, &client_cfg)
                .await
                .unwrap();
            cli_tls.write_all(b"ping!").await.unwrap();
            let mut buf = vec![0u8; 5];
            cli_tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong!");
        });

        srv_task.await.unwrap();
        cli_task.await.unwrap();
    }
}
