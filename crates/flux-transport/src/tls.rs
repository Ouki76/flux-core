use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use std::collections::HashMap;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub use crate::fingerprint::TlsFingerprint;

/// Installs the process-wide rustls provider exactly once.
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Clone, Debug)]
/// Client-side TLS settings.
pub struct TlsClientConfig {
    /// SNI to present.
    pub server_name: String,
    /// ALPN protocols to offer.
    pub alpn: Vec<Vec<u8>>,
    /// Skip certificate verification. Only for tests and pinned self-signed setups.
    pub insecure: bool,
    /// Which browser profile to imitate, when any.
    pub fingerprint: Option<TlsFingerprint>,
    /// PEM files of extra trust anchors, appended to the built-in roots.
    ///
    /// Without this a deployment behind a private CA had exactly one option:
    /// `insecure: true`, which disables verification entirely and accepts any
    /// certificate — a far worse trade than pinning the CA that actually signs
    /// your nodes.
    pub ca_certs: Vec<std::path::PathBuf>,
    /// Use this crate's own TLS 1.3 client instead of rustls.
    ///
    /// **On by default:** the ClientHello is the reason this exists — ours is browser-shaped
    /// with GREASE (RFC 8701) in the cipher list, the extension list and `supported_groups`,
    /// and rustls cannot produce that. It is at parity on throughput and connection rate, and
    /// tested against the real `sing-box` and `xray` binaries.
    ///
    /// The one thing it cannot do is TLS 1.2, so the dial path retries once with rustls when
    /// the handshake fails for a reason other than a rejected certificate. Setting this to
    /// `false` skips that retry entirely.
    pub native: bool,
    /// Force the TLS 1.2 client instead of the 1.3 one.
    ///
    /// Set by the dial path for its second attempt, after a server refused TLS 1.3. Not part of
    /// the configuration surface: a user asks for `native`, not for a version.
    pub(crate) force_tls12: bool,
}

impl TlsClientConfig {
    /// Defaults for `server_name`: verification on, no ALPN, no fingerprint.
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: vec![],
            insecure: false,
            fingerprint: None,
            ca_certs: vec![],
            native: true,
            force_tls12: false,
        }
    }

    /// Turns certificate verification off.
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Offers these ALPN protocols.
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn.into_iter().map(|s| s.into_bytes()).collect();
        self
    }

    /// Imitates this browser's cipher and group ordering.
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

/// Cache of built client connectors, keyed by
/// `(fingerprint, insecure, alpn)`. Bounded by the number of distinct
/// combinations a configuration can express (fingerprint × insecure × alpn sets),
/// which is tiny in practice; no eviction is needed.
type ConnectorKey = (TlsFingerprint, bool, Vec<Vec<u8>>, Vec<String>);

fn client_connector_cache() -> &'static parking_lot::Mutex<HashMap<ConnectorKey, TlsConnector>> {
    static CACHE: std::sync::OnceLock<parking_lot::Mutex<HashMap<ConnectorKey, TlsConnector>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// Appends the certificates in `paths` to `store`, returning a configuration error
/// that names the file when one is unreadable, malformed or empty.
///
/// Shared by the stream TLS client and the QUIC clients so a private CA behaves the
/// same on both, and so neither can silently fall back to the public roots.
pub fn add_ca_certs(store: &mut RootCertStore, paths: &[std::path::PathBuf]) -> FluxResult<()> {
    for path in paths {
        let pem = std::fs::read(path).map_err(|e| {
            FluxError::Config(format!(
                "cannot read tls ca_cert_path '{}': {e}",
                path.display()
            ))
        })?;
        let pems = pem::parse_many(&pem).map_err(|e| {
            FluxError::Config(format!(
                "tls ca_cert_path '{}' is not valid PEM: {e}",
                path.display()
            ))
        })?;
        let mut added = 0usize;
        for p in pems {
            store
                .add(CertificateDer::from(p.into_contents()))
                .map_err(|e| {
                    FluxError::Config(format!(
                        "tls ca_cert_path '{}' contains an unusable certificate: {e}",
                        path.display()
                    ))
                })?;
            added += 1;
        }
        if added == 0 {
            return Err(FluxError::Config(format!(
                "tls ca_cert_path '{}' contains no certificates",
                path.display()
            )));
        }
    }
    Ok(())
}

/// TLS over a carrier, with a configurable fingerprint.
pub struct TlsTransport;

impl TlsTransport {
    /// Builds (and caches) a client connector.
    ///
    /// Both the `CryptoProvider` (cipher-suite and key-exchange tables) and the
    /// ~150-entry `RootCertStore` used to be rebuilt on **every dial** — i.e. on
    /// every DoT/DoH query, latency probe and ruleset fetch. They are immutable
    /// for a given `(fingerprint, insecure, alpn)` triple, so the resulting
    /// `ClientConfig` is cached and only the cheap `Arc` clone is returned.
    /// `Random` resolves to a concrete profile per call and then uses that
    /// profile's cache entry, so it still varies per dial.
    pub fn create_client_connector(cfg: &TlsClientConfig) -> FluxResult<TlsConnector> {
        let fingerprint = match cfg.fingerprint.unwrap_or_default() {
            TlsFingerprint::Random => match rand::random::<u8>() % 3 {
                0 => TlsFingerprint::Chrome,
                1 => TlsFingerprint::Firefox,
                _ => TlsFingerprint::Safari,
            },
            other => other,
        };

        let alpn: Vec<Vec<u8>> = if cfg.alpn.is_empty() {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            cfg.alpn.clone()
        };

        // The extra anchors are part of the identity of the connector, so they
        // belong in the cache key: two servers with different private CAs must not
        // share one.
        let ca_key: Vec<String> = cfg
            .ca_certs
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let key = (fingerprint, cfg.insecure, alpn, ca_key);
        if let Some(cached) = client_connector_cache().lock().get(&key).cloned() {
            return Ok(cached);
        }

        let provider = match fingerprint {
            TlsFingerprint::Chrome | TlsFingerprint::Random => {
                crate::fingerprint::create_chrome_provider()
            }
            TlsFingerprint::Firefox => crate::fingerprint::create_firefox_provider(),
            TlsFingerprint::Safari => crate::fingerprint::create_safari_provider(),
        };

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        add_ca_certs(&mut root_store, &cfg.ca_certs)?;

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
        config.alpn_protocols = key.2.clone();
        let connector = TlsConnector::from(Arc::new(config));
        client_connector_cache()
            .lock()
            .insert(key, connector.clone());
        Ok(connector)
    }

    /// Builds an acceptor from a certificate chain and key.
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

    /// Reads a PEM certificate chain and key from disk.
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

    /// Runs the handshake over `stream` and returns the encrypted stream.
    /// Our own TLS 1.2 handshake, sharing the trust store and ALPN handling of the 1.3 one.
    async fn connect_native12<S>(stream: S, cfg: &TlsClientConfig) -> FluxResult<BoxedStream>
    where
        S: AsyncStream + 'static,
    {
        use crate::tls12;
        let trust = Self::native_trust(cfg)?;
        let alpn: Vec<&[u8]> = cfg.alpn.iter().map(|p| p.as_slice()).collect();
        let hello = tls12::ClientHello12Config {
            server_name: &cfg.server_name,
            alpn: &alpn,
            trust: &trust,
            insecure: cfg.insecure,
        };
        let stream = tls12::connect(stream, &hello).await?;
        Ok(Box::new(stream))
    }

    /// Builds the trust store the native clients share: system roots, plus any configured CA.
    fn native_trust(cfg: &TlsClientConfig) -> FluxResult<crate::tls13::verify::TrustStore> {
        let mut trust = if cfg.insecure {
            crate::tls13::verify::TrustStore::empty()
        } else {
            crate::tls13::verify::TrustStore::system()
        };
        for path in &cfg.ca_certs {
            let pem = std::fs::read(path).map_err(|e| {
                FluxError::Config(format!("cannot read CA file {}: {e}", path.display()))
            })?;
            if trust.add_pem(&pem)? == 0 {
                return Err(FluxError::Config(format!(
                    "CA file {} contains no CERTIFICATE blocks",
                    path.display()
                )));
            }
        }
        Ok(trust)
    }

    /// Our own handshake, with the same configuration surface as the rustls path.
    async fn connect_native<S>(stream: S, cfg: &TlsClientConfig) -> FluxResult<BoxedStream>
    where
        S: AsyncStream + 'static,
    {
        use crate::tls13;
        let mut trust = if cfg.insecure {
            tls13::verify::TrustStore::empty()
        } else {
            tls13::verify::TrustStore::system()
        };
        for path in &cfg.ca_certs {
            let pem = std::fs::read(path).map_err(|e| {
                FluxError::Config(format!("cannot read CA file {}: {e}", path.display()))
            })?;
            let added = trust.add_pem(&pem)?;
            if added == 0 {
                return Err(FluxError::Config(format!(
                    "CA file {} contains no CERTIFICATE blocks",
                    path.display()
                )));
            }
        }
        let alpn: Vec<&[u8]> = cfg.alpn.iter().map(|p| p.as_slice()).collect();
        let hello = tls13::ClientHelloConfig {
            server_name: &cfg.server_name,
            alpn: &alpn,
            trust: &trust,
            insecure: cfg.insecure,
        };
        let stream = tls13::connect(stream, &hello).await?;
        Ok(Box::new(stream))
    }

    /// Connects with a TLS 1.3 handshake, using rustls unless `cfg.native` asks otherwise.
    pub async fn connect<S>(stream: S, cfg: &TlsClientConfig) -> FluxResult<BoxedStream>
    where
        S: AsyncStream + 'static,
    {
        if cfg.native {
            return if cfg.force_tls12 {
                let stream = Self::connect_native12(stream, cfg).await?;
                Ok(Box::new(stream))
            } else {
                Self::connect_native(stream, cfg).await
            };
        }
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

        // The server side has had an enlarged write buffer since the WebSocket framing work;
        // the client never had one, which left the *upload* direction on rustls' 64 KiB
        // default while the download used the larger one. Both directions of a relay matter,
        // so both ends get the same limit.
        let mut tls_stream = tls_stream;
        tls_stream
            .get_mut()
            .1
            .set_buffer_limit(Some(crate::pipeline::TLS_WRITE_BUFFER));

        // rustls hands back one TLS record (16 KiB) per `poll_read`; the relay reads in
        // 64 KiB buffers. Coalescing here keeps the reads whole without touching the
        // dependency.
        Ok(Box::new(crate::coalesce::CoalesceReader::new(tls_stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A private CA must be usable **without** disabling verification.
    ///
    /// Before `ca_certs` existed the only way to talk to a node behind an internal
    /// CA was `insecure: true`, which accepts any certificate — strictly worse than
    /// pinning the CA that actually signs your nodes. This proves the pinned CA is
    /// what makes the handshake succeed, not a loosened verifier.
    #[tokio::test]
    async fn a_private_ca_is_trusted_when_pinned_and_not_otherwise() {
        use std::time::Duration;

        let dir = std::env::temp_dir().join(format!("flux_privca_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");

        // Self-signed localhost certificate: not in the built-in roots.
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();

        let (certs, key) = TlsTransport::load_certs_and_key(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();
        let acceptor = TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(sock).await {
                        let _ = tls.write_all(b"ok").await;
                    }
                });
            }
        });

        let attempt = |cfg: TlsClientConfig| async move {
            let connector = TlsTransport::create_client_connector(&cfg)?;
            let tcp =
                tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
                    .await
                    .map_err(|_| FluxError::Timeout("connect".into()))??;
            let domain = ServerName::try_from("localhost")
                .map_err(|e| FluxError::Crypto(e.to_string()))?
                .to_owned();
            let mut tls =
                tokio::time::timeout(Duration::from_secs(5), connector.connect(domain, tcp))
                    .await
                    .map_err(|_| FluxError::Timeout("handshake".into()))??;
            let mut buf = [0u8; 2];
            let _ = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await;
            Ok::<(), FluxError>(())
        };

        // Untrusted by default.
        let plain = TlsClientConfig::new("localhost");
        assert!(
            attempt(plain).await.is_err(),
            "a self-signed certificate must not validate against the built-in roots"
        );

        // Trusted once the CA is pinned.
        let mut pinned = TlsClientConfig::new("localhost");
        pinned.ca_certs = vec![cert_path.clone()];
        attempt(pinned)
            .await
            .expect("a pinned private CA must make the handshake succeed");

        // A file that is not a certificate is a configuration error, not a silent
        // fallback to the built-in roots.
        let mut broken = TlsClientConfig::new("localhost");
        let bogus = dir.join("bogus.pem");
        std::fs::write(&bogus, b"not a pem file").unwrap();
        broken.ca_certs = vec![bogus];
        let err = match TlsTransport::create_client_connector(&broken) {
            Ok(_) => panic!("an unusable CA file must be refused"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("ca_cert_path"),
            "the error must name the field: {err}"
        );

        // And a missing file names the path.
        let mut missing = TlsClientConfig::new("localhost");
        missing.ca_certs = vec![dir.join("does-not-exist.pem")];
        let err = match TlsTransport::create_client_connector(&missing) {
            Ok(_) => panic!("a missing CA file must be refused"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("does-not-exist"), "{err}");
    }

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

#[cfg(test)]
mod connector_cache_tests {
    use super::*;

    #[test]
    fn client_connector_is_cached() {
        let cfg = TlsClientConfig::new("example.com");
        let a = TlsTransport::create_client_connector(&cfg).unwrap();
        let b = TlsTransport::create_client_connector(&cfg).unwrap();
        assert!(
            Arc::ptr_eq(&a.config().clone(), &b.config().clone()),
            "an identical config must reuse the cached ClientConfig"
        );
    }

    #[test]
    fn distinct_configs_get_distinct_connectors() {
        let mut a_cfg = TlsClientConfig::new("example.com");
        a_cfg.alpn = vec![b"h2".to_vec()];
        let mut b_cfg = TlsClientConfig::new("example.com");
        b_cfg.alpn = vec![b"http/1.1".to_vec()];
        let a = TlsTransport::create_client_connector(&a_cfg).unwrap();
        let b = TlsTransport::create_client_connector(&b_cfg).unwrap();
        assert!(!Arc::ptr_eq(&a.config().clone(), &b.config().clone()));
        assert_eq!(a.config().alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(b.config().alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn insecure_and_verified_are_separate_cache_entries() {
        let mut verified = TlsClientConfig::new("example.com");
        verified.insecure = false;
        let mut insecure = TlsClientConfig::new("example.com");
        insecure.insecure = true;
        let a = TlsTransport::create_client_connector(&verified).unwrap();
        let b = TlsTransport::create_client_connector(&insecure).unwrap();
        assert!(!Arc::ptr_eq(&a.config().clone(), &b.config().clone()));
    }
}
