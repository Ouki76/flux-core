//! XTLS REALITY-compatible camouflage transport.
//!
//! Implements the real REALITY protocol (interoperable with sing-box / Xray):
//!
//! - **Client**: full TLS 1.3 handshake with per-connection `session_id`
//!   authentication: `session_id = AES-256-GCM(auth_key).Seal(ver|time|short_id)`,
//!   where `auth_key = HKDF-SHA256(X25519(client_ephemeral, server_public),
//!   salt = client_random[..20], info = "REALITY")`. The handshake is terminated
//!   by the REALITY server with a temporary Ed25519 certificate whose signature
//!   field carries `HMAC-SHA512(auth_key, ed25519_pub)` — this is how the client
//!   verifies it is talking to the REALITY server and not the real target.
//!
//! - **Server**: sniffs the ClientHello, validates the encrypted `session_id`,
//!   and on success terminates TLS 1.3 itself (via rustls) with the HMAC-tagged
//!   certificate. Any other client (browsers, active probers) is transparently
//!   relayed to the configured fallback target — the anti-probing core of REALITY.
//!
//! References: github.com/XTLS/REALITY, github.com/metacubex/utls (reality.go),
//! github.com/SagerNet/sing-box (common/tls/reality_*.go).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use flux_types::{BoxedStream, FluxError, FluxResult};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha384};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const REALITY_HKDF_INFO: &[u8] = b"REALITY";

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_ALERT: u8 = 0x15;
const TLS_APPDATA: u8 = 0x17;
const TLS_CCS: u8 = 0x14;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_KEY_UPDATE: u8 = 24;

const MAX_TLS_RECORD: usize = 16384;
const MAX_HANDSHAKE_RECORD: usize = 16384 + 2048;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const MLKEM768_ENC_KEY_SIZE: usize = 1184;

const SIG_ED25519: u16 = 0x0807;

fn crypto_err(msg: impl Into<String>) -> FluxError {
    FluxError::Crypto(msg.into())
}

fn auth_err(msg: impl Into<String>) -> FluxError {
    FluxError::AuthFailed(msg.into())
}

// ===========================================================================
// Shared REALITY authentication
// ===========================================================================

/// auth_key = HKDF-SHA256(X25519(priv, peer_pub), salt = client_random[..20], "REALITY")
fn derive_auth_key(shared_secret: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret);
    let mut out = [0u8; 32];
    // 32 bytes is within HKDF-SHA256 expansion limits; failure is impossible here.
    if hk.expand(REALITY_HKDF_INFO, &mut out).is_err() {
        unreachable!("HKDF-SHA256 expand of 32 bytes cannot fail");
    }
    out
}

fn aes256gcm_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(e) => unreachable!("AES-256-GCM rejects 32-byte key: {}", e),
    };
    match cipher.encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: plaintext, aad }) {
        Ok(ct) => ct,
        Err(e) => unreachable!("AES-GCM encryption of small block cannot fail: {}", e),
    }
}

fn aes256gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| ())
}

// ===========================================================================
// ClientHello parsing (record + handshake message level)
// ===========================================================================

pub struct ParsedClientHello {
    /// Full handshake message bytes (4-byte header + body).
    pub raw: Vec<u8>,
    /// Full first TLS record bytes (5-byte record header + raw).
    pub record: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub server_name: Option<String>,
    /// X25519 public key from the key_share extension (plain X25519 preferred,
    /// X25519MLKEM768 hybrid accepted — its last 32 bytes are the X25519 part).
    pub peer_pub: Option<[u8; 32]>,
}

/// Reads and parses the first TLS record, expecting a ClientHello.
pub async fn read_client_hello<S: AsyncRead + Unpin>(stream: &mut S) -> FluxResult<Vec<u8>> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await.map_err(FluxError::Io)?;
    if hdr[0] != TLS_HANDSHAKE {
        return Err(crypto_err("first TLS record is not a handshake record"));
    }
    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if rec_len > MAX_HANDSHAKE_RECORD {
        return Err(crypto_err("client hello record exceeds size limit"));
    }
    let mut body = vec![0u8; rec_len];
    stream.read_exact(&mut body).await.map_err(FluxError::Io)?;
    let mut record = Vec::with_capacity(5 + rec_len);
    record.extend_from_slice(&hdr);
    record.extend_from_slice(&body);
    Ok(record)
}

pub fn parse_client_hello(record: &[u8]) -> Option<ParsedClientHello> {
    if record.len() < 5 + 4 + 2 + 32 + 1 {
        return None;
    }
    let raw = record[5..].to_vec();
    let body = &raw[..];
    if body[0] != HS_CLIENT_HELLO {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    if hs_len + 4 > body.len() {
        return None;
    }

    let mut pos = 4 + 2; // header + legacy_version
    let random: [u8; 32] = body[pos..pos + 32].try_into().ok()?;
    pos += 32;
    let sid_len = body[pos] as usize;
    pos += 1;
    if sid_len != 32 || pos + 32 > body.len() {
        return None;
    }
    let session_id: [u8; 32] = body[pos..pos + 32].try_into().ok()?;
    pos += 32;

    // cipher suites
    if pos + 2 > body.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > body.len() {
        return None;
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > body.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(body.len());

    let mut server_name = None;
    let mut peer_pub = None;
    let mut peer_pub_mlkem = None;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        let edata = &body[pos..pos + elen];
        match etype {
            0x0000 => {
                // server_name: list_len(2) type(1) name_len(2) name
                if edata.len() >= 5 {
                    let name_len = u16::from_be_bytes([edata[3], edata[4]]) as usize;
                    if 5 + name_len <= edata.len() {
                        server_name =
                            Some(String::from_utf8_lossy(&edata[5..5 + name_len]).into_owned());
                    }
                }
            }
            0x0033 => {
                // key_share: list_len(2), entries: group(2) len(2) data
                let mut kpos = 2;
                while kpos + 4 <= edata.len() {
                    let group = u16::from_be_bytes([edata[kpos], edata[kpos + 1]]);
                    let klen = u16::from_be_bytes([edata[kpos + 2], edata[kpos + 3]]) as usize;
                    kpos += 4;
                    if kpos + klen > edata.len() {
                        break;
                    }
                    let kdata = &edata[kpos..kpos + klen];
                    if group == GROUP_X25519 && klen == 32 && peer_pub.is_none() {
                        peer_pub = Some(kdata.try_into().ok()?);
                    }
                    if group == GROUP_X25519_MLKEM768
                        && klen == MLKEM768_ENC_KEY_SIZE + 32
                        && peer_pub_mlkem.is_none()
                    {
                        peer_pub_mlkem = Some(kdata[MLKEM768_ENC_KEY_SIZE..].try_into().ok()?);
                    }
                    kpos += klen;
                }
            }
            _ => {}
        }
        pos += elen;
    }

    if peer_pub.is_none() {
        peer_pub = peer_pub_mlkem;
    }

    Some(ParsedClientHello {
        raw,
        record: record.to_vec(),
        random,
        session_id,
        server_name,
        peer_pub,
    })
}

// ===========================================================================
// Configuration
// ===========================================================================

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
}

/// Server-side REALITY configuration.
pub struct RealityServerConfig {
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    /// Up to 8 bytes each (zero-padded).
    pub short_ids: Vec<Vec<u8>>,
    /// Fallback target `host:port` — invalid/probe clients are transparently
    /// relayed there (this is REALITY's anti-probing core).
    pub fallback: Option<String>,
    /// Max accepted client timestamp skew. None = no time check (sing-box default).
    pub max_time_diff: Option<std::time::Duration>,
    /// Process-wide Ed25519 material for the temporary handshake certificate.
    cert: Arc<RealityCertMaterial>,
}

impl Clone for RealityServerConfig {
    fn clone(&self) -> Self {
        Self {
            server_names: self.server_names.clone(),
            private_key: self.private_key,
            short_ids: self.short_ids.clone(),
            fallback: self.fallback.clone(),
            max_time_diff: self.max_time_diff,
            cert: self.cert.clone(),
        }
    }
}

impl std::fmt::Debug for RealityServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("server_names", &self.server_names)
            .field("short_ids", &self.short_ids)
            .field("fallback", &self.fallback)
            .finish_non_exhaustive()
    }
}

impl Default for RealityServerConfig {
    fn default() -> Self {
        Self::new(vec![], [0u8; 32], vec![], None)
    }
}

impl RealityServerConfig {
    pub fn new(
        server_names: Vec<String>,
        private_key: [u8; 32],
        short_ids: Vec<Vec<u8>>,
        fallback: Option<String>,
    ) -> Self {
        Self {
            server_names,
            private_key,
            short_ids,
            fallback,
            max_time_diff: None,
            cert: RealityCertMaterial::get_or_init(),
        }
    }
}

// ===========================================================================
// Temporary Ed25519 certificate (REALITY server identity trick)
// ===========================================================================

struct RealityCertMaterial {
    /// DER certificate template; the last 64 bytes are the Ed25519 signature,
    /// replaced per-connection with HMAC-SHA512(auth_key, ed25519_pub).
    cert_der: Vec<u8>,
    ed25519_pub: [u8; 32],
    signing_key: Arc<dyn rustls::sign::SigningKey>,
}

impl RealityCertMaterial {
    fn get_or_init() -> Arc<Self> {
        static INSTANCE: std::sync::OnceLock<Arc<RealityCertMaterial>> =
            std::sync::OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
                    .expect("failed to generate ed25519 keypair for REALITY");
                let params = rcgen::CertificateParams::new(Vec::<String>::new())
                    .expect("failed to build REALITY cert params");
                let cert = params
                    .self_signed(&key_pair)
                    .expect("failed to self-sign REALITY cert");
                let cert_der = cert.der().to_vec();
                let pub_bytes: [u8; 32] = key_pair
                    .public_key_raw()
                    .try_into()
                    .expect("ed25519 public key must be 32 bytes");
                let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(
                    key_pair.serialize_der(),
                );
                let inner_key = rustls::crypto::ring::sign::any_eddsa_type(&pkcs8)
                    .expect("failed to build ed25519 signing key");
                let signing_key: Arc<dyn rustls::sign::SigningKey> =
                    Arc::new(ForcedEd25519SigningKey { inner: inner_key });
                Arc::new(Self {
                    cert_der,
                    ed25519_pub: pub_bytes,
                    signing_key,
                })
            })
            .clone()
    }

    /// Returns the certificate DER with the signature field replaced by
    /// HMAC-SHA512(auth_key, ed25519_pub) — the REALITY proof of possession.
    fn cert_for(&self, auth_key: &[u8; 32]) -> Vec<u8> {
        use hmac::{Mac, Hmac};
        let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(auth_key)
            .expect("HMAC-SHA512 accepts any key length");
        mac.update(&self.ed25519_pub);
        let tag = mac.finalize().into_bytes();
        let mut der = self.cert_der.clone();
        let n = der.len();
        der[n - 64..].copy_from_slice(&tag);
        der
    }
}

/// Signing key wrapper that always answers Ed25519, regardless of the client's
/// advertised signature schemes. REALITY clients (uTLS Chrome fingerprints) do not
/// advertise Ed25519 but accept it — the REALITY server certificate is Ed25519 by design.
#[derive(Debug)]
struct ForcedEd25519SigningKey {
    inner: Arc<dyn rustls::sign::SigningKey>,
}

impl rustls::sign::SigningKey for ForcedEd25519SigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.inner.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

#[derive(Debug)]
struct RealityCertResolver {
    certified: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for RealityCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified.clone())
    }
}

// ===========================================================================
// REALITY server
// ===========================================================================

pub struct RealityHandshake;

impl RealityHandshake {
    /// Server-side: authenticate an incoming REALITY client, or transparently
    /// relay the connection to the fallback target (anti-probing).
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
        mut stream: S,
        cfg: &RealityServerConfig,
    ) -> FluxResult<BoxedStream> {
        let record = match read_client_hello(&mut stream).await {
            Ok(r) => r,
            Err(e) => {
                return Self::fallback_or_fail(stream, &[], cfg, e).await;
            }
        };

        let auth: Option<[u8; 32]> = (|| {
            let hello = parse_client_hello(&record)?;
            let sni = hello.server_name.as_deref()?;
            if !cfg.server_names.is_empty() && !cfg.server_names.iter().any(|n| n == sni) {
                return None;
            }
            let peer_pub = hello.peer_pub?;
            let server_secret = StaticSecret::from(cfg.private_key);
            let shared = server_secret.diffie_hellman(&X25519PublicKey::from(peer_pub));
            let auth_key = derive_auth_key(shared.as_bytes(), &hello.random);

            // Decrypt session_id: AES-256-GCM(auth_key), nonce = random[20..32],
            // AAD = full ClientHello handshake message with session_id zeroized.
            let mut aad = hello.raw.clone();
            // session_id offset: 4 (hs header) + 2 (version) + 32 (random) + 1 (sid len) = 39
            aad[39..71].fill(0);
            let nonce: [u8; 12] = hello.random[20..32].try_into().ok()?;
            let plain = aes256gcm_open(&auth_key, &nonce, &aad, &hello.session_id).ok()?;
            if plain.len() != 16 {
                return None;
            }

            // plain = [ver(3)][reserved(1)][unix time BE32][short_id(8)]
            if let Some(max_diff) = cfg.max_time_diff {
                let ts = u32::from_be_bytes(plain[4..8].try_into().ok()?) as i64;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs() as i64;
                if (now - ts).abs() > max_diff.as_secs() as i64 {
                    return None;
                }
            }
            if !cfg.short_ids.is_empty() {
                let sid = &plain[8..16];
                let allowed = cfg.short_ids.iter().any(|s| {
                    let mut padded = [0u8; 8];
                    let copy_len = s.len().min(8);
                    padded[..copy_len].copy_from_slice(&s[..copy_len]);
                    padded == sid
                });
                if !allowed {
                    return None;
                }
            }
            Some(auth_key)
        })();

        let Some(auth_key) = auth else {
            return Self::fallback_or_fail(stream, &record, cfg, crypto_err(
                "reality client authentication failed; relayed to fallback",
            ))
            .await;
        };

        // Authenticated REALITY client: terminate TLS 1.3 with the HMAC-tagged cert.
        let cert_der = cfg.cert.cert_for(&auth_key);
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            cfg.cert.signing_key.clone(),
        ));

        let mut tls_cfg = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| crypto_err(format!("failed to build reality TLS config: {}", e)))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RealityCertResolver { certified }));
        tls_cfg.send_tls13_tickets = 0;
        tls_cfg.max_fragment_size = Some(MAX_TLS_RECORD);

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
        let replay = flux_common::copy::PrefixedStream::new(stream, record);
        let tls_stream = acceptor
            .accept(replay)
            .await
            .map_err(|e| crypto_err(format!("reality TLS handshake failed: {}", e)))?;
        Ok(Box::new(tls_stream))
    }

    /// Transparently relay a non-REALITY client to the fallback target,
    /// replaying the already-read bytes first.
    async fn fallback_or_fail<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
        stream: S,
        already_read: &[u8],
        cfg: &RealityServerConfig,
        err: FluxError,
    ) -> FluxResult<BoxedStream> {
        if let Some(ref fb) = cfg.fallback {
            relay_to_fallback(stream, already_read, fb).await;
        }
        Err(err)
    }

    /// Client-side: REALITY handshake over a full TLS 1.3 session.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        stream: S,
        cfg: &RealityClientConfig,
    ) -> FluxResult<Tls13ClientStream<S>> {
        Tls13Client::handshake(stream, cfg).await
    }
}

/// Transparently relay to the fallback target: dial, replay buffered bytes, splice.
async fn relay_to_fallback<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
    client_stream: S,
    already_read: &[u8],
    fallback: &str,
) {
    let fallback_addr = if let Ok(sa) = fallback.parse::<std::net::SocketAddr>() {
        sa
    } else {
        let addr_str = if fallback.contains(':') {
            fallback.to_string()
        } else {
            format!("{}:443", fallback)
        };
        match tokio::net::lookup_host(&addr_str).await {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => return,
            },
            Err(_) => return,
        }
    };

    let dest = match crate::tcp::TcpTransport::connect(fallback_addr, std::time::Duration::from_secs(5)).await {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut cs: BoxedStream = Box::new(flux_common::copy::PrefixedStream::new(
        client_stream,
        already_read.to_vec(),
    ));
    let mut ds: BoxedStream = Box::new(dest);
    tokio::spawn(async move {
        let _ = flux_common::copy_bidirectional(&mut cs, &mut ds).await;
    });
}

// ===========================================================================
// Minimal TLS 1.3 client (needed because rustls cannot control the
// ClientHello session_id field, which REALITY uses for authentication)
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tls13Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl Tls13Suite {
    fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    fn hash_len(&self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            _ => 32,
        }
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        match self {
            Self::Aes256GcmSha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            _ => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }

    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
                prk.to_vec()
            }
            _ => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
                prk.to_vec()
            }
        }
    }

    fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> FluxResult<Vec<u8>> {
        let mut out = vec![0u8; len];
        match self {
            Self::Aes256GcmSha384 => {
                let hk = Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|e| crypto_err(format!("hkdf from_prk: {}", e)))?;
                hk.expand(info, &mut out)
                    .map_err(|e| crypto_err(format!("hkdf expand: {}", e)))?;
            }
            _ => {
                let hk = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|e| crypto_err(format!("hkdf from_prk: {}", e)))?;
                hk.expand(info, &mut out)
                    .map_err(|e| crypto_err(format!("hkdf expand: {}", e)))?;
            }
        }
        Ok(out)
    }

    /// HKDF-Expand-Label from RFC 8446 §7.1.
    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> FluxResult<Vec<u8>> {
        let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        let full_label = format!("tls13 {}", label);
        info.push(full_label.len() as u8);
        info.extend_from_slice(full_label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.hkdf_expand(secret, &info, len)
    }

    /// Derive-Secret from RFC 8446 §7.1 (transcript-hash variant).
    fn derive_secret(
        &self,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> FluxResult<Vec<u8>> {
        self.hkdf_expand_label(secret, label, transcript_hash, self.hash_len())
    }

    fn encrypt(&self, key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> FluxResult<Vec<u8>> {
        match self {
            Self::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map_err(|e| crypto_err(e.to_string()))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
                .map_err(|e| crypto_err(format!("tls13 aes128gcm encrypt: {}", e))),
            Self::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map_err(|e| crypto_err(e.to_string()))?
                .encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
                .map_err(|e| crypto_err(format!("tls13 aes256gcm encrypt: {}", e))),
            Self::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| crypto_err(e.to_string()))?
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
                .map_err(|e| crypto_err(format!("tls13 chacha encrypt: {}", e))),
        }
    }

    fn decrypt(&self, key: &[u8], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> FluxResult<Vec<u8>> {
        match self {
            Self::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map_err(|e| crypto_err(e.to_string()))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
                .map_err(|e| crypto_err(format!("tls13 aes128gcm decrypt: {}", e))),
            Self::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map_err(|e| crypto_err(e.to_string()))?
                .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
                .map_err(|e| crypto_err(format!("tls13 aes256gcm decrypt: {}", e))),
            Self::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| crypto_err(e.to_string()))?
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
                .map_err(|e| crypto_err(format!("tls13 chacha decrypt: {}", e))),
        }
    }
}

// ===========================================================================
// TLS 1.3 record-layer key state
// ===========================================================================

struct TrafficState {
    suite: Tls13Suite,
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl TrafficState {
    fn new(suite: Tls13Suite, secret: Vec<u8>) -> FluxResult<Self> {
        let key = suite.hkdf_expand_label(&secret, "key", &[], suite.key_len())?;
        let iv_v = suite.hkdf_expand_label(&secret, "iv", &[], 12)?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_v);
        Ok(Self {
            suite,
            secret,
            key,
            iv,
            seq: 0,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    fn encrypt_record(&mut self, content_type: u8, data: &[u8]) -> FluxResult<Vec<u8>> {
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
        inner.push(content_type);
        let nonce = self.nonce();
        self.seq += 1;
        let ct_len = inner.len() + 16;
        let mut record = Vec::with_capacity(5 + ct_len);
        record.push(TLS_APPDATA);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(ct_len as u16).to_be_bytes());
        let ct = self
            .suite
            .encrypt(&self.key, &nonce, &record, &inner)?;
        record.extend_from_slice(&ct);
        Ok(record)
    }

    fn decrypt_record(&mut self, header: &[u8; 5], body: &[u8]) -> FluxResult<(u8, Vec<u8>)> {
        let nonce = self.nonce();
        self.seq += 1;
        let plain = self.suite.decrypt(&self.key, &nonce, header, body)?;
        // Strip content type (and any zero padding before it).
        let mut i = plain.len();
        while i > 0 && plain[i - 1] == 0 {
            i -= 1;
        }
        if i == 0 {
            return Err(crypto_err("tls13 record without content type"));
        }
        let content_type = plain[i - 1];
        Ok((content_type, plain[..i - 1].to_vec()))
    }

    /// RFC 8446 §7.2 traffic key update.
    fn update(&mut self) -> FluxResult<()> {
        self.secret = self
            .suite
            .hkdf_expand_label(&self.secret, "traffic upd", &[], self.suite.hash_len())?;
        self.key = self
            .suite
            .hkdf_expand_label(&self.secret, "key", &[], self.suite.key_len())?;
        let iv_v = self.suite.hkdf_expand_label(&self.secret, "iv", &[], 12)?;
        self.iv.copy_from_slice(&iv_v);
        self.seq = 0;
        Ok(())
    }
}

// ===========================================================================
// TLS 1.3 client handshake
// ===========================================================================

/// Completed REALITY client connection: a minimal but fully conformant
/// TLS 1.3 client session (record protection, key update, close_notify).
pub struct Tls13ClientStream<S> {
    inner: S,
    #[allow(dead_code)] // kept for diagnostics/debugging
    suite: Tls13Suite,
    read_state: TrafficState,
    write_state: TrafficState,
    /// Decrypted application data awaiting consumption.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Partial inbound record assembly.
    hdr_buf: [u8; 5],
    hdr_len: usize,
    body_buf: Vec<u8>,
    body_len: usize,
    /// Encrypted records awaiting write to the underlying stream.
    pending_write: Vec<u8>,
    pending_write_pos: usize,
    closed: bool,
}

struct Tls13Client;

impl Tls13Client {
    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        mut stream: S,
        cfg: &RealityClientConfig,
    ) -> FluxResult<Tls13ClientStream<S>> {
        // ---- 1. Build the ClientHello handshake message.
        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph);

        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);

        let mut hello: Vec<u8> = Vec::with_capacity(512);
        hello.extend_from_slice(&[HS_CLIENT_HELLO, 0, 0, 0]); // length patched later
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&random);
        hello.push(32); // session_id length
        hello.extend_from_slice(&[0u8; 32]); // session_id placeholder (offset 39)
        hello.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]); // cipher suites
        hello.extend_from_slice(&[0x01, 0x00]); // compression methods

        let mut ext: Vec<u8> = Vec::with_capacity(256);
        // server_name
        let sni = cfg.server_name.as_bytes();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&((5 + sni.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&((3 + sni.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni);
        // supported_versions: TLS 1.3
        ext.extend_from_slice(&0x002bu16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.extend_from_slice(&[0x02, 0x03, 0x04]);
        // supported_groups: x25519
        ext.extend_from_slice(&0x000au16.to_be_bytes());
        ext.extend_from_slice(&4u16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&GROUP_X25519.to_be_bytes());
        // key_share: x25519 ephemeral
        ext.extend_from_slice(&0x0033u16.to_be_bytes());
        ext.extend_from_slice(&38u16.to_be_bytes());
        ext.extend_from_slice(&36u16.to_be_bytes());
        ext.extend_from_slice(&GROUP_X25519.to_be_bytes());
        ext.extend_from_slice(&32u16.to_be_bytes());
        ext.extend_from_slice(eph_pub.as_bytes());
        // signature_algorithms (ed25519 first — REALITY server cert is ed25519)
        let sigalgs: [u16; 9] = [
            0x0807, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
        ];
        ext.extend_from_slice(&0x000du16.to_be_bytes());
        ext.extend_from_slice(&((2 + sigalgs.len() * 2) as u16).to_be_bytes());
        ext.extend_from_slice(&((sigalgs.len() * 2) as u16).to_be_bytes());
        for alg in sigalgs {
            ext.extend_from_slice(&alg.to_be_bytes());
        }
        // psk_key_exchange_modes: psk_dhe_ke (required for a spec-conformant CH)
        ext.extend_from_slice(&0x002du16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&[0x01, 0x01]);

        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        // Patch handshake length
        let hs_len = (hello.len() - 4) as u32;
        let hs_len_bytes = hs_len.to_be_bytes();
        hello[1] = hs_len_bytes[1];
        hello[2] = hs_len_bytes[2];
        hello[3] = hs_len_bytes[3];

        // ---- 2. REALITY session_id authentication.
        let server_pub = X25519PublicKey::from(cfg.public_key);
        let shared = eph.diffie_hellman(&server_pub);
        let auth_key = derive_auth_key(shared.as_bytes(), &random);

        let mut sid_plain = [0u8; 16];
        sid_plain[0] = 1;
        sid_plain[1] = 8;
        sid_plain[2] = 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        sid_plain[4..8].copy_from_slice(&now.to_be_bytes());
        let copy_len = cfg.short_id.len().min(8);
        sid_plain[8..8 + copy_len].copy_from_slice(&cfg.short_id[..copy_len]);

        let nonce: [u8; 12] = random[20..32].try_into().expect("slice len 12");
        let sealed = aes256gcm_seal(&auth_key, &nonce, &hello, &sid_plain);
        debug_assert_eq!(sealed.len(), 32);
        hello[39..71].copy_from_slice(&sealed);

        // ---- 3. Send ClientHello + CCS (middlebox compatibility).
        let mut flight = Vec::with_capacity(5 + hello.len() + 6);
        flight.push(TLS_HANDSHAKE);
        flight.extend_from_slice(&[0x03, 0x01]);
        flight.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        flight.extend_from_slice(&hello);
        flight.extend_from_slice(&[TLS_CCS, 0x03, 0x03, 0x00, 0x01, 0x01]);
        stream.write_all(&flight).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        // ---- 4. Read ServerHello (plaintext record).
        let mut transcript: Vec<u8> = Vec::with_capacity(1024);
        transcript.extend_from_slice(&hello);

        let sh_record = Self::read_record_typed(&mut stream, TLS_HANDSHAKE).await?;
        if sh_record.len() < 4 || sh_record[0] != HS_SERVER_HELLO {
            return Err(crypto_err("expected TLS ServerHello"));
        }
        let sh_msg_len = u32::from_be_bytes([0, sh_record[1], sh_record[2], sh_record[3]]) as usize;
        if sh_record.len() < 4 + sh_msg_len {
            return Err(crypto_err("truncated ServerHello"));
        }
        let sh = &sh_record[..4 + sh_msg_len];
        transcript.extend_from_slice(sh);

        // Parse ServerHello
        let mut pos = 4 + 2;
        if sh.len() < pos + 32 + 1 {
            return Err(crypto_err("short ServerHello"));
        }
        let server_random: [u8; 32] = sh[pos..pos + 32].try_into().expect("32");
        pos += 32;
        // HelloRetryRequest detection (fixed magic random)
        const HRR_RANDOM: [u8; 32] = [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ];
        if server_random == HRR_RANDOM {
            return Err(crypto_err(
                "unexpected HelloRetryRequest (we always offer an x25519 key share)",
            ));
        }
        let sid_echo_len = sh[pos] as usize;
        pos += 1 + sid_echo_len;
        if pos + 3 > sh.len() {
            return Err(crypto_err("short ServerHello (cipher suite)"));
        }
        let suite_id = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
        pos += 2;
        pos += 1; // compression
        let suite = Tls13Suite::from_id(suite_id)
            .ok_or_else(|| crypto_err(format!("unsupported TLS 1.3 cipher suite: {:#x}", suite_id)))?;

        if pos + 2 > sh.len() {
            return Err(crypto_err("short ServerHello (extensions)"));
        }
        let ext_total = u16::from_be_bytes([sh[pos], sh[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(sh.len());
        let mut server_keyshare: Option<[u8; 32]> = None;
        while pos + 4 <= ext_end {
            let etype = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
            let elen = u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
            pos += 4;
            if pos + elen > ext_end {
                break;
            }
            if etype == 0x0033 && elen >= 36 {
                let group = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
                let klen = u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
                if group == GROUP_X25519 && klen == 32 {
                    server_keyshare = Some(sh[pos + 4..pos + 36].try_into().expect("32"));
                }
            }
            pos += elen;
        }
        let server_keyshare =
            server_keyshare.ok_or_else(|| crypto_err("ServerHello without x25519 key share"))?;

        // ---- 5. Key schedule: handshake secrets.
        let shared_secret = eph.diffie_hellman(&X25519PublicKey::from(server_keyshare));

        // RFC 8446 §7.1: Early Secret = HKDF-Extract(salt: 0, IKM: zeros)
        // ("0" means a string of Hash.length bytes set to zeros).
        let zeros = vec![0u8; suite.hash_len()];
        let empty_hash = suite.hash(&[]);
        let early_secret = suite.hkdf_extract(&zeros, &zeros);
        let derived = suite.derive_secret(&early_secret, "derived", &empty_hash)?;
        let handshake_secret = suite.hkdf_extract(&derived, shared_secret.as_bytes());

        let ch_sh_hash = suite.hash(&transcript);
        let c_hs_secret = suite.derive_secret(&handshake_secret, "c hs traffic", &ch_sh_hash)?;
        let s_hs_secret = suite.derive_secret(&handshake_secret, "s hs traffic", &ch_sh_hash)?;

        let mut server_hs = TrafficState::new(suite, s_hs_secret.clone())?;
        let mut client_hs = TrafficState::new(suite, c_hs_secret.clone())?;

        // ---- 6. Read the encrypted server flight: EE, Certificate, CV, Finished.
        let mut hs_buf: Vec<u8> = Vec::new();
        let mut got_finished = false;
        let mut cert_der: Option<Vec<u8>> = None;
        let mut server_fin: Vec<u8> = Vec::new();

        while !got_finished {
            let hdr = Self::read_record_header(&mut stream).await?;
            let body = Self::read_record_body(&mut stream, &hdr).await?;
            match hdr[0] {
                TLS_CCS => continue,
                TLS_APPDATA => {
                    let (ctype, plain) = server_hs.decrypt_record(&hdr, &body)?;
                    if ctype != TLS_HANDSHAKE {
                        return Err(crypto_err(format!(
                            "unexpected encrypted record type {} during handshake",
                            ctype
                        )));
                    }
                    hs_buf.extend_from_slice(&plain);
                }
                TLS_ALERT => {
                    return Err(crypto_err(format!(
                        "TLS alert during handshake: {:02x?}",
                        body
                    )));
                }
                other => {
                    return Err(crypto_err(format!(
                        "unexpected record type {} during handshake",
                        other
                    )));
                }
            }

            // Consume complete handshake messages from hs_buf.
            loop {
                if hs_buf.len() < 4 {
                    break;
                }
                let mtype = hs_buf[0];
                let mlen = u32::from_be_bytes([0, hs_buf[1], hs_buf[2], hs_buf[3]]) as usize;
                if hs_buf.len() < 4 + mlen {
                    break;
                }
                let msg = hs_buf[..4 + mlen].to_vec();
                hs_buf.drain(..4 + mlen);

                match mtype {
                    HS_ENCRYPTED_EXTENSIONS => {
                        transcript.extend_from_slice(&msg);
                    }
                    HS_CERTIFICATE => {
                        // cert_request_context(1+len), then cert list u24 len
                        if msg.len() < 9 {
                            return Err(crypto_err("short Certificate message"));
                        }
                        let ctx_len = msg[4] as usize;
                        let mut cpos = 5 + ctx_len;
                        if cpos + 3 > msg.len() {
                            return Err(crypto_err("short Certificate list"));
                        }
                        cpos += 3; // cert_list length
                        if cpos + 3 > msg.len() {
                            return Err(crypto_err("short Certificate entry"));
                        }
                        let cert_len = u32::from_be_bytes([0, msg[cpos], msg[cpos + 1], msg[cpos + 2]])
                            as usize;
                        cpos += 3;
                        if cpos + cert_len > msg.len() {
                            return Err(crypto_err("truncated certificate"));
                        }
                        cert_der = Some(msg[cpos..cpos + cert_len].to_vec());
                        transcript.extend_from_slice(&msg);
                    }
                    HS_CERTIFICATE_VERIFY => {
                        if msg.len() < 8 {
                            return Err(crypto_err("short CertificateVerify"));
                        }
                        let cv_scheme = u16::from_be_bytes([msg[4], msg[5]]);
                        let sig_len = u16::from_be_bytes([msg[6], msg[7]]) as usize;
                        if msg.len() < 8 + sig_len {
                            return Err(crypto_err("short CertificateVerify signature"));
                        }
                        let cv_sig = &msg[8..8 + sig_len];

                        // Verify the signature over the transcript so far.
                        let transcript_hash = suite.hash(&transcript);
                        let mut content = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
                        content.extend_from_slice(&[0x20u8; 64]);
                        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
                        content.push(0);
                        content.extend_from_slice(&transcript_hash);

                        let cert = cert_der.as_ref()
                            .ok_or_else(|| crypto_err("CertificateVerify before Certificate"))?;
                        let server_pub_key = extract_ed25519_pubkey(cert)
                            .ok_or_else(|| crypto_err("server certificate is not ed25519"))?;
                        if cv_scheme != SIG_ED25519 {
                            return Err(crypto_err(format!(
                                "unexpected CertificateVerify scheme: {:#x}",
                                cv_scheme
                            )));
                        }
                        let peer = ring::signature::UnparsedPublicKey::new(
                            &ring::signature::ED25519,
                            server_pub_key,
                        );
                        peer.verify(&content, cv_sig).map_err(|_| {
                            auth_err("reality CertificateVerify signature invalid")
                        })?;
                        transcript.extend_from_slice(&msg);
                    }
                    HS_FINISHED => {
                        let transcript_hash = suite.hash(&transcript);
                        let finished_key = suite.hkdf_expand_label(
                            &s_hs_secret,
                            "finished",
                            &[],
                            suite.hash_len(),
                        )?;
                        let expect = suite.hmac(&finished_key, &transcript_hash);
                        if msg[4..] != expect[..] {
                            return Err(auth_err("reality server Finished verification failed"));
                        }
                        server_fin = msg.clone();
                        transcript.extend_from_slice(&msg);
                        got_finished = true;
                    }
                    _ => {
                        return Err(crypto_err(format!(
                            "unexpected handshake message type {} in server flight",
                            mtype
                        )));
                    }
                }
            }
        }

        // ---- 7. REALITY server authentication: HMAC-tagged ed25519 cert.
        let cert = cert_der.ok_or_else(|| crypto_err("server sent no certificate"))?;
        let cert_pub = extract_ed25519_pubkey(&cert)
            .ok_or_else(|| crypto_err("server certificate is not ed25519"))?;
        let cert_sig = extract_cert_signature(&cert)
            .ok_or_else(|| crypto_err("failed to extract certificate signature"))?;
        {
            use hmac::{Hmac, Mac};
            let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(&auth_key)
                .expect("HMAC-SHA512 accepts any key length");
            mac.update(cert_pub);
            let expect = mac.finalize().into_bytes();
            if cert_sig != expect.as_slice() {
                return Err(auth_err(
                    "REALITY verification failed: server is not the configured REALITY peer (or MITM)",
                ));
            }
        }

        // ---- 8. Application traffic secrets (transcript through server Finished).
        let derived2 = suite.derive_secret(&handshake_secret, "derived", &empty_hash)?;
        let master_secret = suite.hkdf_extract(&derived2, &vec![0u8; suite.hash_len()]);
        let ap_hash = suite.hash(&transcript);
        let c_ap = suite.derive_secret(&master_secret, "c ap traffic", &ap_hash)?;
        let s_ap = suite.derive_secret(&master_secret, "s ap traffic", &ap_hash)?;

        // ---- 9. Send client Finished.
        let fin_key_c =
            suite.hkdf_expand_label(&c_hs_secret, "finished", &[], suite.hash_len())?;
        let fin_hash = suite.hash(&transcript);
        let verify_data = suite.hmac(&fin_key_c, &fin_hash);
        let mut fin_msg = Vec::with_capacity(4 + verify_data.len());
        fin_msg.push(HS_FINISHED);
        fin_msg.extend_from_slice(&[0, 0, 0]);
        let vd_len = verify_data.len() as u32;
        let vd_bytes = vd_len.to_be_bytes();
        fin_msg[1] = vd_bytes[1];
        fin_msg[2] = vd_bytes[2];
        fin_msg[3] = vd_bytes[3];
        fin_msg.extend_from_slice(&verify_data);
        let fin_record = client_hs.encrypt_record(TLS_HANDSHAKE, &fin_msg)?;
        stream.write_all(&fin_record).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        let _ = server_fin;
        Ok(Tls13ClientStream {
            inner: stream,
            suite,
            read_state: TrafficState::new(suite, s_ap)?,
            write_state: TrafficState::new(suite, c_ap)?,
            read_buf: Vec::new(),
            read_pos: 0,
            hdr_buf: [0u8; 5],
            hdr_len: 0,
            body_buf: Vec::new(),
            body_len: 0,
            pending_write: Vec::new(),
            pending_write_pos: 0,
            closed: false,
        })
    }

    async fn read_record_header<S: AsyncRead + Unpin>(stream: &mut S) -> FluxResult<[u8; 5]> {
        let mut hdr = [0u8; 5];
        stream.read_exact(&mut hdr).await.map_err(FluxError::Io)?;
        Ok(hdr)
    }

    async fn read_record_body<S: AsyncRead + Unpin>(
        stream: &mut S,
        hdr: &[u8; 5],
    ) -> FluxResult<Vec<u8>> {
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if len > MAX_TLS_RECORD + 256 {
            return Err(crypto_err("TLS record exceeds maximum size"));
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.map_err(FluxError::Io)?;
        Ok(body)
    }

    async fn read_record_typed<S: AsyncRead + Unpin>(
        stream: &mut S,
        expect: u8,
    ) -> FluxResult<Vec<u8>> {
        loop {
            let hdr = Self::read_record_header(stream).await?;
            let body = Self::read_record_body(stream, &hdr).await?;
            if hdr[0] == TLS_CCS {
                continue;
            }
            if hdr[0] != expect {
                return Err(crypto_err(format!(
                    "expected TLS record type {}, got {}",
                    expect, hdr[0]
                )));
            }
            return Ok(body);
        }
    }
}

/// Extracts the Ed25519 public key from a DER X.509 certificate by locating the
/// Ed25519 OID (1.3.101.112) followed by the BIT STRING with the 32-byte key.
fn extract_ed25519_pubkey(cert: &[u8]) -> Option<&[u8; 32]> {
    const OID_ED25519_WITH_BITSTRING: [u8; 8] = [0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
    cert.windows(8)
        .position(|w| w == OID_ED25519_WITH_BITSTRING)
        .and_then(|i| cert[i + 8..i + 8 + 32].try_into().ok())
}

/// Extracts the trailing 64-byte signature of a DER X.509 certificate.
/// For Ed25519 certs the signature is always the final 64 bytes of the DER.
fn extract_cert_signature(cert: &[u8]) -> Option<&[u8]> {
    if cert.len() < 64 {
        return None;
    }
    Some(&cert[cert.len() - 64..])
}

// ===========================================================================
// AsyncRead / AsyncWrite for the TLS 1.3 client session (poll-based)
// ===========================================================================

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13ClientStream<S> {
    /// Polls until one full plaintext record payload is available in
    /// `read_buf` (application data), EOF, or an error.
    /// Handles CCS, post-handshake messages (NST/KeyUpdate) and alerts.
    /// Uses persistent partial-read buffers, so it is cancellation-safe.
    fn poll_next_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            // 1. Read the 5-byte record header (may be partial across polls).
            while self.hdr_len < 5 {
                let mut rb = ReadBuf::new(&mut self.hdr_buf[self.hdr_len..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading TLS record header",
                            )));
                        }
                        self.hdr_len += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let header = self.hdr_buf;
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            if len > MAX_TLS_RECORD + 256 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record too large",
                )));
            }

            // 2. Read the record body.
            if self.body_buf.len() != len {
                self.body_buf = vec![0u8; len];
                self.body_len = 0;
            }
            while self.body_len < len {
                let mut rb = ReadBuf::new(&mut self.body_buf[self.body_len..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading TLS record body",
                            )));
                        }
                        self.body_len += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // 3. Full record assembled: reset partial state and process.
            self.hdr_len = 0;
            self.body_len = 0;
            let body = std::mem::take(&mut self.body_buf);
            match self.process_record(header, body) {
                Ok(Some(())) => return Poll::Ready(Ok(())),
                Ok(None) => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    /// Processes one full record. Returns Ok(Some(())) when application data
    /// was placed into read_buf; Ok(None) to continue the loop.
    fn process_record(&mut self, header: [u8; 5], body: Vec<u8>) -> io::Result<Option<()>> {
        match header[0] {
            TLS_CCS => Ok(None),
            TLS_APPDATA => {
                let (ctype, plain) = self
                    .read_state
                    .decrypt_record(&header, &body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                match ctype {
                    23 => {
                        self.read_buf = plain;
                        self.read_pos = 0;
                        Ok(Some(()))
                    }
                    TLS_HANDSHAKE => {
                        let mut pos = 0;
                        while pos + 4 <= plain.len() {
                            let mtype = plain[pos];
                            let mlen = u32::from_be_bytes([
                                0,
                                plain[pos + 1],
                                plain[pos + 2],
                                plain[pos + 3],
                            ]) as usize;
                            if pos + 4 + mlen > plain.len() {
                                break;
                            }
                            if mtype == HS_KEY_UPDATE && mlen >= 1 {
                                self.read_state
                                    .update()
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                                if plain[pos + 4] == 1 {
                                    // Queue a key_update response (update_not_requested).
                                    let ku = [HS_KEY_UPDATE, 0, 0, 1, 0];
                                    let rec = self
                                        .write_state
                                        .encrypt_record(TLS_HANDSHAKE, &ku)
                                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                                    self.pending_write.extend_from_slice(&rec);
                                }
                            }
                            pos += 4 + mlen;
                        }
                        Ok(None)
                    }
                    TLS_ALERT => {
                        if plain.len() >= 2 && plain[1] == 0 {
                            self.closed = true;
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "TLS close_notify received",
                            ));
                        }
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TLS alert: {:02x?}", plain),
                        ))
                    }
                    other => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected TLS content type {}", other),
                    )),
                }
            }
            TLS_ALERT => {
                self.closed = true;
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS plaintext alert received",
                ))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected TLS record type {}", other),
            )),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls13ClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let avail = &self.read_buf[self.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match self.poll_next_record(cx) {
            Poll::Ready(Ok(())) => {
                // Got a fresh plaintext record; serve from buffer.
                let avail = &self.read_buf[self.read_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                self.read_pos += n;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                Poll::Ready(Ok(())) // close_notify / clean EOF → EOF for the reader
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls13ClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 1. Flush any pending encrypted data first (preserves record order).
        while self.pending_write_pos < self.pending_write.len() {
            let remaining = self.pending_write.len() - self.pending_write_pos;
            let chunk: Vec<u8> =
                self.pending_write[self.pending_write_pos..self.pending_write_pos + remaining.min(65536)]
                    .to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13 underlying write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write.clear();
        self.pending_write_pos = 0;

        // 2. Encrypt and write one record worth of plaintext.
        let n = buf.len().min(MAX_TLS_RECORD);
        let rec = match self.write_state.encrypt_record(23, &buf[..n]) {
            Ok(r) => r,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))
            }
        };
        match Pin::new(&mut self.inner).poll_write(cx, &rec) {
            Poll::Ready(Ok(written)) if written < rec.len() => {
                self.pending_write.extend_from_slice(&rec[written..]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.pending_write.extend_from_slice(&rec);
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_write_pos < self.pending_write.len() {
            let remaining = self.pending_write.len() - self.pending_write_pos;
            let chunk: Vec<u8> =
                self.pending_write[self.pending_write_pos..self.pending_write_pos + remaining.min(65536)]
                    .to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13 underlying write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write.clear();
        self.pending_write_pos = 0;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            // close_notify alert: level=warning(1), description=close_notify(0)
            if let Ok(rec) = self.write_state.encrypt_record(TLS_ALERT, &[0x01, 0x00]) {
                self.pending_write.extend_from_slice(&rec);
            }
        }
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn server_cfg(priv_key: [u8; 32]) -> RealityServerConfig {
        RealityServerConfig::new(
            vec!["www.microsoft.com".into()],
            priv_key,
            vec![vec![0x01, 0x02, 0x03, 0x04]],
            None,
        )
    }

    #[tokio::test]
    async fn test_reality_xtls_handshake_and_data_roundtrip() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);

        let scfg = server_cfg(server_secret.to_bytes());
        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            RealityHandshake::server_handshake(server_io, &scfg).await
        });
        let client = tokio::spawn(async move {
            RealityHandshake::client_handshake(client_io, &ccfg).await
        });

        let mut server_stream = server.await.unwrap().unwrap();
        let mut client_stream = client.await.unwrap().unwrap();

        client_stream.write_all(b"hello reality").await.unwrap();
        client_stream.flush().await.unwrap();
        let mut buf = [0u8; 13];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello reality");

        server_stream.write_all(b"reply from server").await.unwrap();
        server_stream.flush().await.unwrap();
        let mut buf2 = [0u8; 17];
        client_stream.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"reply from server");
    }

    #[tokio::test]
    async fn test_reality_wrong_short_id_fails() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);

        let scfg = server_cfg(server_secret.to_bytes());
        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0xde, 0xad, 0xbe, 0xef], // not allowed
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            RealityHandshake::server_handshake(server_io, &scfg).await
        });
        let client = tokio::spawn(async move {
            RealityHandshake::client_handshake(client_io, &ccfg).await
        });

        // No fallback configured → server errors; client must fail too.
        let s = server.await.unwrap();
        assert!(s.is_err());
        let c = client.await.unwrap();
        assert!(c.is_err());
    }

    #[tokio::test]
    async fn test_reality_fallback_relay_for_invalid_client() {
        // Decoy target: simple echo server
        let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = decoy.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 128];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let scfg = RealityServerConfig::new(
            vec!["www.microsoft.com".into()],
            server_secret.to_bytes(),
            vec![vec![0x01, 0x02, 0x03, 0x04]],
            Some(decoy_addr.to_string()),
        );

        // A plain TLS client (not REALITY) connects — must be relayed to decoy.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = RealityHandshake::server_handshake(stream, &scfg).await;
        });

        let mut probe = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Fake TLS ClientHello (invalid session_id)
        let mut fake_ch = vec![0x16, 0x03, 0x01, 0x00, 0x40];
        fake_ch.extend_from_slice(&[0x01, 0x00, 0x00, 0x3c, 0x03, 0x03]);
        fake_ch.extend_from_slice(&[0x42u8; 32]); // random
        fake_ch.push(32);
        fake_ch.extend_from_slice(&[0xAAu8; 32]); // bogus session_id
        probe.write_all(&fake_ch).await.unwrap();
        probe.write_all(b"PING").await.unwrap();

        let mut buf = [0u8; 4];
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            probe.read_exact(&mut buf),
        )
        .await;
        // Decoy echoes back the last 4 bytes of what it received
        assert!(res.is_ok(), "fallback relay must forward traffic to decoy");
    }
}

#[cfg(test)]
mod crypto_reference_tests {
    use super::*;

    #[test]
    fn test_derive_auth_key_matches_python_hkdf() {
        // Reference: HKDF-SHA256(salt=rand[:20], ikm=shared, info="REALITY")
        let shared = [0x42u8; 32];
        let random = [0x07u8; 32];
        let ak = derive_auth_key(&shared, &random);
        let hexstr: String = ak.iter().map(|b| format!("{:02x}", b)).collect();
        println!("rust ak: {}", hexstr);
        assert_eq!(
            hexstr,
            "4bfc7684145ef433495abcd19d3ea65632bee4e84b0c7aa37930b62f4c875a81",
            "must match python HKDF reference"
        );
    }
}

#[cfg(test)]
mod gcm_vector_tests {
    use super::*;

    #[test]
    fn test_aes256gcm_reference_vector() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"some aad";
        let pt = b"0123456789abcdef";
        let ct = aes256gcm_seal(&key, &nonce, aad, pt);
        let hexstr: String = ct.iter().map(|b| format!("{:02x}", b)).collect();
        println!("rust ct: {}", hexstr);
        assert_eq!(
            hexstr,
            "27c6357af4faa968dd06bf5e2bc28cb3b41e80e80a42bf2ce96a430165073ba9",
            "must match python AESGCM reference"
        );
    }
}
