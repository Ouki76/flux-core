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

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use flux_types::{BoxedStream, FluxError, FluxResult};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use ring::aead::{Aad, Algorithm, LessSafeKey, Nonce as RingNonce, UnboundKey};
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
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
/// RFC 8701 GREASE values. A browser puts one of these in its cipher list, extension list
/// and group list, chosen per connection, and peers must ignore it.
const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];
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
    match cipher.encrypt(
        aes_gcm::Nonce::from_slice(nonce),
        Payload {
            msg: plaintext,
            aad,
        },
    ) {
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
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

// ===========================================================================
// ClientHello parsing (record + handshake message level)
// ===========================================================================

/// The parts of a ClientHello REALITY needs to make its decision.
pub struct ParsedClientHello {
    /// Full handshake message bytes (4-byte header + body).
    pub raw: Vec<u8>,
    /// Full first TLS record bytes (5-byte record header + raw).
    pub record: Vec<u8>,
    /// The 32-byte client random that carries the authentication material.
    pub random: [u8; 32],
    /// Session id carried in the TLS handshake.
    pub session_id: [u8; 32],
    /// SNI, when the client sent one.
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

/// Extracts what REALITY needs from a raw ClientHello record, or `None` if malformed.
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
/// Client-side REALITY settings.
pub struct RealityClientConfig {
    /// SNI to present; must be one the server accepts.
    pub server_name: String,
    /// The server's x25519 public key.
    pub public_key: [u8; 32],
    /// Short id, which authenticates the client inside the handshake.
    pub short_id: Vec<u8>,
}

/// Server-side REALITY configuration.
pub struct RealityServerConfig {
    /// Names this server will answer for.
    pub server_names: Vec<String>,
    /// The server's x25519 private key.
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
    /// Builds a client config for one server.
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
    /// Raw Ed25519 keypair for signing the TLS 1.3 CertificateVerify.
    ed25519_key: ring::signature::Ed25519KeyPair,
}

impl RealityCertMaterial {
    fn get_or_init() -> Arc<Self> {
        static INSTANCE: std::sync::OnceLock<Arc<RealityCertMaterial>> = std::sync::OnceLock::new();
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
                let pkcs8 = key_pair.serialize_der();
                let ed25519_key = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8)
                    .expect("failed to build ring ed25519 keypair");
                Arc::new(Self {
                    cert_der,
                    ed25519_pub: pub_bytes,
                    ed25519_key,
                })
            })
            .clone()
    }

    /// Signs the TLS 1.3 CertificateVerify content with the Ed25519 key.
    fn sign(&self, content: &[u8]) -> Vec<u8> {
        self.ed25519_key.sign(content).as_ref().to_vec()
    }

    /// Returns the certificate DER with the signature field replaced by
    /// HMAC-SHA512(auth_key, ed25519_pub) — the REALITY proof of possession.
    fn cert_for(&self, auth_key: &[u8; 32]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(auth_key)
            .expect("HMAC-SHA512 accepts any key length");
        mac.update(&self.ed25519_pub);
        let tag = mac.finalize().into_bytes();
        let mut der = self.cert_der.clone();
        // The certificate is generated in-process by `rcgen` and always carries
        // a 64-byte Ed25519 signature, but keep the slice total anyway so a
        // future shorter certificate cannot panic the handshake path.
        if let Some(sig) = der.len().checked_sub(64).and_then(|n| der.get_mut(n..)) {
            sig.copy_from_slice(&tag);
        }
        der
    }
}

// ===========================================================================
// REALITY server
// ===========================================================================

/// Namespace for the REALITY handshake, both sides.
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
            return Self::fallback_or_fail(
                stream,
                &record,
                cfg,
                crypto_err("reality client authentication failed; relayed to fallback"),
            )
            .await;
        };

        // Authenticated REALITY client. Probe the fallback target to mirror its
        // handshake record framing (REALITY's signature feature: the answer is
        // byte-shape-indistinguishable from the real target's), then terminate
        // TLS 1.3 ourselves with the HMAC-tagged certificate.
        let mimic = match &cfg.fallback {
            Some(dest) => match probe_target_handshake(dest, &record).await {
                Ok(m) => Some(m),
                Err(e) => {
                    // Target unreachable/misbehaving: relay everything like an invalid client.
                    tracing::debug!("reality target probe failed ({}), relaying", e);
                    return Self::fallback_or_fail(
                        stream,
                        &record,
                        cfg,
                        crypto_err(format!("reality target probe failed: {}", e)),
                    )
                    .await;
                }
            },
            None => None,
        };

        let tls_stream = Tls13Server::handshake(stream, &record, &auth_key, cfg, mimic).await?;
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
    ) -> FluxResult<Tls13Stream<S>> {
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

    let dest =
        match crate::tcp::TcpTransport::connect(fallback_addr, std::time::Duration::from_secs(5))
            .await
        {
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

    /// The `ring` AEAD algorithm for this suite.
    fn ring_alg(&self) -> &'static Algorithm {
        match self {
            Self::Aes128GcmSha256 => &ring::aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &ring::aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &ring::aead::CHACHA20_POLY1305,
        }
    }

    /// Expands a traffic key into a sealing/opening key. `ring` keeps the whole
    /// expanded key schedule, so this is done once per key, not per record.
    fn new_key(&self, key: &[u8]) -> FluxResult<LessSafeKey> {
        UnboundKey::new(self.ring_alg(), key)
            .map(LessSafeKey::new)
            .map_err(|_| crypto_err("tls13 aead: invalid key length"))
    }

    /// In-place AEAD seal: encrypts `buf` in place and returns the tag.
    fn seal(
        &self,
        cipher: &LessSafeKey,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> FluxResult<[u8; 16]> {
        let tag = cipher
            .seal_in_place_separate_tag(
                RingNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                buf,
            )
            .map_err(|_| crypto_err("tls13 aead encrypt failed"))?;
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    /// In-place AEAD open: `buf` holds ciphertext followed by the 16-byte tag.
    /// On success `buf` holds the plaintext and its length is returned.
    fn open(
        &self,
        cipher: &LessSafeKey,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
    ) -> FluxResult<usize> {
        let plain = cipher
            .open_in_place(
                RingNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                buf,
            )
            .map_err(|_| crypto_err("tls13 aead decrypt failed"))?;
        Ok(plain.len())
    }
}

// ===========================================================================
// TLS 1.3 record-layer key state
// ===========================================================================

struct TrafficState {
    suite: Tls13Suite,
    secret: Vec<u8>,
    key: Vec<u8>,
    /// Expanded AEAD key schedule for `key`. Building this per record (as the
    /// previous `aes-gcm` path did through `new_from_slice`) redoes the key
    /// expansion once per 16 KiB of payload.
    cipher: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl TrafficState {
    fn new(suite: Tls13Suite, secret: Vec<u8>) -> FluxResult<Self> {
        let key = suite.hkdf_expand_label(&secret, "key", &[], suite.key_len())?;
        let iv_v = suite.hkdf_expand_label(&secret, "iv", &[], 12)?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_v);
        let cipher = suite.new_key(&key)?;
        Ok(Self {
            suite,
            secret,
            key,
            cipher,
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
        self.encrypt_record_padded(content_type, data, 0)
    }

    /// Encrypts a record, padding the TLSInnerPlaintext with `pad_len` trailing
    /// zeros (RFC 8446 §5.4 legal; used for REALITY target record-size mimicry).
    fn encrypt_record_padded(
        &mut self,
        content_type: u8,
        data: &[u8],
        pad_len: usize,
    ) -> FluxResult<Vec<u8>> {
        let mut record = Vec::with_capacity(5 + data.len() + 1 + pad_len + 16);
        record.extend_from_slice(&[0u8; 5]); // header, patched below
        record.extend_from_slice(data);
        record.push(content_type);
        record.resize(record.len() + pad_len, 0);
        let ct_len = record.len() - 5 + 16;
        let header = [TLS_APPDATA, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
        let nonce = self.nonce();
        self.seq += 1;
        let tag = self
            .suite
            .seal(&self.cipher, &nonce, &header, &mut record[5..])?;
        record.extend_from_slice(&tag);
        record[..5].copy_from_slice(&header);
        Ok(record)
    }

    /// Seals one record appended to `out`: header ‖ ciphertext ‖ tag.
    ///
    /// Every offset is relative to `start`, not to the start of `out` — the original
    /// version assumed the caller had cleared the buffer (`out.len() - 5`), which made
    /// the second record of a multi-record write carry a length covering both. The AEAD
    /// then authenticated the wrong header and the peer rejected it with "aead decrypt
    /// failed", which is exactly how this surfaced.
    fn seal_into(&mut self, content_type: u8, data: &[u8], out: &mut Vec<u8>) -> FluxResult<()> {
        out.reserve(5 + data.len() + 1 + 16);
        let start = out.len();
        out.extend_from_slice(&[0u8; 5]); // header, patched below
        out.extend_from_slice(data);
        out.push(content_type);
        let ct_len = out.len() - start - 5 + 16;
        let header = [TLS_APPDATA, 0x03, 0x03, (ct_len >> 8) as u8, ct_len as u8];
        let nonce = self.nonce();
        self.seq += 1;
        let tag = self
            .suite
            .seal(&self.cipher, &nonce, &header, &mut out[start + 5..])?;
        out.extend_from_slice(&tag);
        out[start..start + 5].copy_from_slice(&header);
        Ok(())
    }

    fn decrypt_record(&mut self, header: &[u8; 5], body: &[u8]) -> FluxResult<(u8, Vec<u8>)> {
        let mut buf = body.to_vec();
        let (ctype, plen) = self.decrypt_in_place(header, &mut buf)?;
        buf.truncate(plen);
        Ok((ctype, buf))
    }

    /// Decrypts one record body in place: `body` must hold the full ciphertext
    /// including the 16-byte tag, and is left holding the TLSInnerPlaintext
    /// (payload ‖ content type ‖ zero padding). No allocation, no copy.
    ///
    /// Returns the inner content type and the payload length inside `body`.
    fn decrypt_in_place(&mut self, header: &[u8; 5], body: &mut [u8]) -> FluxResult<(u8, usize)> {
        if body.len() < 16 {
            return Err(crypto_err("tls13 record shorter than its tag"));
        }
        let nonce = self.nonce();
        self.seq += 1;
        let plen = self
            .suite
            .open(&self.cipher, &nonce, header, body)
            .inspect_err(|_| {
                // Never leave a partially-decrypted record behind.
                body.fill(0);
            })?;
        let plain = &body[..plen];
        // Strip content type (and any zero padding before it).
        let mut i = plen;
        while i > 0 && plain[i - 1] == 0 {
            i -= 1;
        }
        if i == 0 {
            return Err(crypto_err("tls13 record without content type"));
        }
        Ok((plain[i - 1], i - 1))
    }

    /// RFC 8446 §7.2 traffic key update.
    fn update(&mut self) -> FluxResult<()> {
        self.secret = self.suite.hkdf_expand_label(
            &self.secret,
            "traffic upd",
            &[],
            self.suite.hash_len(),
        )?;
        self.key = self
            .suite
            .hkdf_expand_label(&self.secret, "key", &[], self.suite.key_len())?;
        self.cipher = self.suite.new_key(&self.key)?;
        let iv_v = self.suite.hkdf_expand_label(&self.secret, "iv", &[], 12)?;
        self.iv.copy_from_slice(&iv_v);
        self.seq = 0;
        Ok(())
    }
}

// ===========================================================================
// TLS 1.3 client handshake
// ===========================================================================

/// Completed REALITY TLS 1.3 session (client or server role):
/// full record protection, post-handshake messages, key update, close_notify.
pub struct Tls13Stream<S> {
    inner: S,
    #[allow(dead_code)] // kept for diagnostics/debugging
    suite: Tls13Suite,
    read_state: TrafficState,
    write_state: TrafficState,
    /// Start/length of decrypted application data awaiting consumption. The
    /// plaintext lives *inside* `body_buf` (decrypted in place), so a received
    /// record never needs an allocation or a copy of its payload.
    read_pos: usize,
    read_len: usize,
    /// Partial inbound record assembly.
    hdr_buf: [u8; 5],
    hdr_len: usize,
    /// Record ciphertext (or, once decrypted, its plaintext). Kept at its high
    /// water mark and never `clear()`ed: a `len()`-based reuse check silently
    /// reallocated and re-zeroed 16 KiB per record.
    body_buf: Vec<u8>,
    body_len: usize,
    /// Reusable staging buffer for one outgoing record (header ‖ ciphertext ‖ tag).
    /// Allocated once per connection; a record costs no allocation at all.
    tx_buf: Vec<u8>,
    /// Encrypted records awaiting write to the underlying stream.
    pending_write: Vec<u8>,
    pending_write_pos: usize,
    /// Plaintext bytes whose record is buffered but not yet acknowledged to the
    /// caller (the transport returned `Pending` while writing it).
    pending_unacked: usize,
    closed: bool,
}

struct Tls13Client;

impl Tls13Client {
    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        mut stream: S,
        cfg: &RealityClientConfig,
    ) -> FluxResult<Tls13Stream<S>> {
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
        // Cipher suites, Chrome's list with a GREASE value in front (RFC 8701). A ClientHello
        // that offers only the three TLS 1.3 suites and no GREASE is not something any browser
        // sends, and its JA3 is a stable signature — which is exactly what this transport exists
        // to avoid. Only the 1.3 suites can be selected (supported_versions offers nothing else),
        // so the legacy entries are decoration for the observer.
        let grease = GREASE_VALUES[(random[0] as usize) % GREASE_VALUES.len()];
        let suites: [u16; 10] = [
            grease, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
        ];
        hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for suite in suites {
            hello.extend_from_slice(&suite.to_be_bytes());
        }
        hello.extend_from_slice(&[0x01, 0x00]); // compression methods

        let mut ext: Vec<u8> = Vec::with_capacity(256);
        // A GREASE extension of the same value, first in the list.
        ext.extend_from_slice(&grease.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        // extended_master_secret: every browser sends it, empty body.
        ext.extend_from_slice(&0x0017u16.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        // renegotiation_info: a single zero byte, as browsers send for a fresh connection.
        ext.extend_from_slice(&0xff01u16.to_be_bytes());
        ext.extend_from_slice(&1u16.to_be_bytes());
        ext.push(0);
        // server_name
        let sni = cfg.server_name.as_bytes();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&((5 + sni.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&((3 + sni.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni);
        // ALPN: a ClientHello without it is a loud non-browser signal — every
        // browser offers `h2` and `http/1.1`, and the cover site almost certainly
        // serves HTTP/2. The REALITY server ignores the contents (it authenticates
        // the session id), so this only affects what an on-path observer sees.
        let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let alpn_list_len: usize = alpn.iter().map(|p| 1 + p.len()).sum();
        ext.extend_from_slice(&0x0010u16.to_be_bytes()); // extension_type
        ext.extend_from_slice(&((2 + alpn_list_len) as u16).to_be_bytes()); // ext length
        ext.extend_from_slice(&(alpn_list_len as u16).to_be_bytes()); // protocol list
        for proto in alpn {
            ext.push(proto.len() as u8);
            ext.extend_from_slice(proto);
        }
        // supported_versions: TLS 1.3
        ext.extend_from_slice(&0x002bu16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.extend_from_slice(&[0x02, 0x03, 0x04]);
        // ec_point_formats: uncompressed only, as every browser sends.
        ext.extend_from_slice(&0x000bu16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&[1, 0]);
        // session_ticket: empty, which is what a browser without a cached ticket sends.
        ext.extend_from_slice(&0x0023u16.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        // supported_groups: GREASE first, then the curves we can actually use.
        let groups: [u16; 4] = [grease, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
        ext.extend_from_slice(&0x000au16.to_be_bytes());
        ext.extend_from_slice(&((2 + groups.len() * 2) as u16).to_be_bytes());
        ext.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for group in groups {
            ext.extend_from_slice(&group.to_be_bytes());
        }
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
        let suite = Tls13Suite::from_id(suite_id).ok_or_else(|| {
            crypto_err(format!("unsupported TLS 1.3 cipher suite: {:#x}", suite_id))
        })?;

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
                        let cert_len =
                            u32::from_be_bytes([0, msg[cpos], msg[cpos + 1], msg[cpos + 2]])
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

                        let cert = cert_der
                            .as_ref()
                            .ok_or_else(|| crypto_err("CertificateVerify before Certificate"))?;
                        if cv_scheme == SIG_ED25519 {
                            let server_pub_key = extract_ed25519_pubkey(cert)
                                .ok_or_else(|| crypto_err("server certificate is not ed25519"))?;
                            let peer = ring::signature::UnparsedPublicKey::new(
                                &ring::signature::ED25519,
                                server_pub_key,
                            );
                            peer.verify(&content, cv_sig).map_err(|_| {
                                auth_err("reality CertificateVerify signature invalid")
                            })?;
                        } else {
                            // Non-Ed25519 cert: real target or MITM, never a REALITY server.
                            // The connection will only be used for spider crawling and dropped.
                            tracing::debug!(
                                "REALITY: non-ed25519 CertificateVerify scheme {:#x} (spider path)",
                                cv_scheme
                            );
                        }
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
        let verified = 'check: {
            let Some(cert_pub) = extract_ed25519_pubkey(&cert) else {
                break 'check false; // real target / MITM with a non-ed25519 cert → spider
            };
            let Some(cert_sig) = extract_cert_signature(&cert) else {
                break 'check false;
            };
            {
                use hmac::{Hmac, Mac};
                let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(&auth_key)
                    .expect("HMAC-SHA512 accepts any key length");
                mac.update(cert_pub);
                let expect = mac.finalize().into_bytes();
                let verified = cert_sig == expect.as_slice();
                if !verified {
                    tracing::debug!(
                        "REALITY: received real certificate (potential MITM or redirection), entering spider mode"
                    );
                }
                verified
            }
        };

        // ---- 8. Application traffic secrets (transcript through server Finished).
        let derived2 = suite.derive_secret(&handshake_secret, "derived", &empty_hash)?;
        let master_secret = suite.hkdf_extract(&derived2, &vec![0u8; suite.hash_len()]);
        let ap_hash = suite.hash(&transcript);
        let c_ap = suite.derive_secret(&master_secret, "c ap traffic", &ap_hash)?;
        let s_ap = suite.derive_secret(&master_secret, "s ap traffic", &ap_hash)?;

        // ---- 9. Send client Finished.
        let fin_key_c = suite.hkdf_expand_label(&c_hs_secret, "finished", &[], suite.hash_len())?;
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
        let mut tls_stream = Tls13Stream {
            inner: stream,
            suite,
            read_state: TrafficState::new(suite, s_ap)?,
            write_state: TrafficState::new(suite, c_ap)?,
            read_pos: 0,
            read_len: 0,
            hdr_buf: [0u8; 5],
            hdr_len: 0,
            body_buf: Vec::new(),
            body_len: 0,
            tx_buf: Vec::new(),
            pending_write: Vec::new(),
            pending_write_pos: 0,
            pending_unacked: 0,
            closed: false,
        };
        if !verified {
            // Verification failed: we're talking to the real target or a MITM.
            // Behave like an ordinary browser loading the site (spider mode), then abort.
            spider_crawl(&mut tls_stream, &cfg.server_name).await;
            return Err(auth_err(
                "REALITY verification failed: processed invalid connection (potential MITM or redirection)",
            ));
        }
        Ok(tls_stream)
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
    // `windows(8)` only guarantees that the *match start* is in bounds, so the
    // 32 key bytes after it must be bounds-checked separately: the certificate
    // comes from the network (fallback target / on-path box) and is fully
    // attacker-controlled at this point.
    let start = cert
        .windows(OID_ED25519_WITH_BITSTRING.len())
        .position(|w| w == OID_ED25519_WITH_BITSTRING)?;
    let key = cert.get(start + 8..start + 8 + 32)?;
    key.try_into().ok()
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

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13Stream<S> {
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

            // 2. Read the record body. `body_buf` keeps its high-water-mark
            // length (it is never cleared), so in steady state this is a pure
            // buffer reuse: no allocation and no re-zeroing per record.
            if self.body_buf.len() < len {
                self.body_buf.resize(len, 0);
            }
            while self.body_len < len {
                let mut rb = ReadBuf::new(&mut self.body_buf[self.body_len..len]);
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
            match self.process_record(header, len) {
                Ok(Some(())) => return Poll::Ready(Ok(())),
                Ok(None) => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    /// Processes one full record of `len` body bytes sitting in `body_buf`.
    /// Returns Ok(Some(())) when application data was decrypted in place;
    /// Ok(None) to continue the loop.
    fn process_record(&mut self, header: [u8; 5], len: usize) -> io::Result<Option<()>> {
        match header[0] {
            TLS_CCS => Ok(None),
            TLS_APPDATA => {
                let (ctype, plen) = self
                    .read_state
                    .decrypt_in_place(&header, &mut self.body_buf[..len])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                match ctype {
                    23 => {
                        // Plaintext is already in `body_buf [0..plen]`.
                        self.read_pos = 0;
                        self.read_len = plen;
                        Ok(Some(()))
                    }
                    TLS_HANDSHAKE => {
                        let plain = &self.body_buf[..plen];
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
                                self.read_state.update().map_err(|e| {
                                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                                })?;
                                if plain[pos + 4] == 1 {
                                    // Queue a key_update response (update_not_requested).
                                    let ku = [HS_KEY_UPDATE, 0, 0, 1, 0];
                                    let rec = self
                                        .write_state
                                        .encrypt_record(TLS_HANDSHAKE, &ku)
                                        .map_err(|e| {
                                        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                                    })?;
                                    self.pending_write.extend_from_slice(&rec);
                                }
                            }
                            pos += 4 + mlen;
                        }
                        Ok(None)
                    }
                    TLS_ALERT => {
                        let plain = &self.body_buf[..plen];
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls13Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fill the caller's buffer, not one TLS record per poll. A record is 16 KiB
        // and the relay reads with 64 KiB, so returning after each record made every
        // buffer four separate read/write cycles — the same defect that cost the
        // Shadowsocks and WebSocket transports.
        let mut put = 0usize;
        loop {
            if self.read_pos < self.read_len {
                // Serve straight out of the record buffer the plaintext was
                // decrypted into: one copy, into the caller, and nothing else.
                let n = (self.read_len - self.read_pos).min(buf.remaining());
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                let start = self.read_pos;
                buf.put_slice(&self.body_buf[start..start + n]);
                self.read_pos += n;
                put += n;
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            match self.poll_next_record(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Poll::Ready(Ok(())); // close_notify / clean EOF → EOF
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return if put > 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13Stream<S> {
    /// Pushes buffered ciphertext to the underlying stream, retaining progress
    /// across polls. `Ok(false)` means the transport returned `Pending`.
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        let Self {
            pending_write,
            pending_write_pos,
            inner,
            ..
        } = self;
        while *pending_write_pos < pending_write.len() {
            let end = pending_write.len().min(*pending_write_pos + 65536);
            // Slice the buffer directly: copying each chunk out (`to_vec`) was a
            // 64 KiB allocation + copy per flushed chunk.
            match Pin::new(&mut *inner).poll_write(cx, &pending_write[*pending_write_pos..end]) {
                Poll::Ready(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13 underlying write returned 0",
                    ));
                }
                Poll::Ready(Ok(n)) => *pending_write_pos += n,
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => return Ok(false),
            }
        }
        pending_write.clear();
        *pending_write_pos = 0;
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls13Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        // 1. Flush any pending encrypted data first (preserves record order).
        match this.poll_flush_pending(cx) {
            Ok(true) => {}
            Ok(false) => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        }

        // A record that was buffered because the transport returned `Pending` was
        // never acknowledged to the caller: `write_all` will retry with the same
        // buffer. Now that it is on the wire, acknowledge it and stop — falling
        // through would encrypt the very same plaintext a second time, which is
        // exactly the duplicate-data corruption that showed up as a position
        // mismatch in sustained transfers.
        if this.pending_unacked > 0 {
            let acknowledged = this.pending_unacked.min(buf.len());
            this.pending_unacked = 0;
            return Poll::Ready(Ok(acknowledged));
        }

        // 2. Encrypt one record worth of plaintext into the reusable staging
        //    buffer (no allocation in steady state) and hand it to the transport.
        // Seal as many records as the caller's buffer provides, up to the relay's copy
        // buffer, and hand them to the transport in one write. One record per call made
        // a 64 KiB write four records and four syscalls — the defect found in the
        // WebSocket, Shadowsocks, REALITY-read and VMess paths.
        let cap = buf.len().min(flux_common::copy::RELAY_BUFFER_BYTES);
        let mut n = 0usize;
        this.tx_buf.clear();
        while n < cap {
            let step = (cap - n).min(MAX_TLS_RECORD);
            if let Err(e) = this
                .write_state
                .seal_into(23, &buf[n..n + step], &mut this.tx_buf)
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
            n += step;
        }

        let Self {
            tx_buf,
            inner,
            pending_write,
            pending_unacked,
            ..
        } = this;
        let rec_len = tx_buf.len();
        match Pin::new(&mut *inner).poll_write(cx, tx_buf) {
            Poll::Ready(Ok(written)) if written < rec_len => {
                // `written` bytes are on the wire and the plaintext they encode is
                // acknowledged now; only the tail stays buffered.
                pending_write.extend_from_slice(&tx_buf[written..]);
                *pending_unacked = 0;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Nothing was written and nothing is acknowledged: buffer the whole
                // record and remember that `n` plaintext bytes are still pending
                // from the caller's point of view.
                pending_write.extend_from_slice(tx_buf);
                *pending_unacked = n;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Ok(true) => Pin::new(&mut this.inner).poll_flush(cx),
            Ok(false) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.closed {
            this.closed = true;
            // close_notify alert: level=warning(1), description=close_notify(0)
            this.tx_buf.clear();
            if this
                .write_state
                .seal_into(TLS_ALERT, &[0x01, 0x00], &mut this.tx_buf)
                .is_ok()
            {
                let Self {
                    tx_buf,
                    pending_write,
                    ..
                } = this;
                pending_write.extend_from_slice(tx_buf);
            } else {
                this.tx_buf.clear();
            }
        }
        match this.poll_flush_pending(cx) {
            Ok(true) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Ok(false) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

// ===========================================================================
// REALITY target handshake probing (record-framing mimicry)
// ===========================================================================

/// Record sizes observed in the target's TLS 1.3 server flight.
/// Layout mirrors the reference implementation:
/// [ServerHello, CCS, EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket]
#[derive(Clone, Copy, Debug, Default)]
pub struct TargetMimicry {
    /// Total record sizes (5-byte header included); 0 = absent.
    pub record_sizes: [usize; 7],
}

impl TargetMimicry {
    fn size(&self, idx: usize) -> Option<usize> {
        (self.record_sizes[idx] > 0).then_some(self.record_sizes[idx])
    }
}

/// Dials the fallback target, replays the ClientHello, and parses the record
/// boundaries of the target's TLS 1.3 server flight. Validates that the target
/// actually speaks TLS 1.3 with an X25519 (or X25519MLKEM768) key share —
/// exactly like the reference implementation.
/// How long the probe waits for the *rest* of a target's TLS flight once the
/// ServerHello has arrived. A real target sends the whole flight in one burst, so
/// this only bounds the pathological case; it is not a handshake budget.
const SEQUEL_IDLE: u64 = 100;

/// Cached result of probing a fallback target, keyed by target string.
///
/// The record framing is a property of the target's TLS stack, not of the
/// connection, so probing it per connection adds that cost to every handshake —
/// measured as a 5 s stall against a rustls target before the probe loop was
/// fixed, and still a needless round trip afterwards.
static MIMICRY_CACHE: std::sync::OnceLock<
    parking_lot::Mutex<std::collections::HashMap<String, (std::time::Instant, TargetMimicry)>>,
> = std::sync::OnceLock::new();

const MIMICRY_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const MIMICRY_CACHE_MAX: usize = 32;

fn mimicry_cache() -> &'static parking_lot::Mutex<
    std::collections::HashMap<String, (std::time::Instant, TargetMimicry)>,
> {
    MIMICRY_CACHE.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
}

async fn probe_target_handshake(dest: &str, ch_record: &[u8]) -> FluxResult<TargetMimicry> {
    {
        let cache = mimicry_cache().lock();
        if let Some((at, mimicry)) = cache.get(dest)
            && at.elapsed() < MIMICRY_TTL
        {
            return Ok(*mimicry);
        }
    }
    let mimicry = probe_target_handshake_uncached(dest, ch_record).await?;
    {
        let mut cache = mimicry_cache().lock();
        if cache.len() >= MIMICRY_CACHE_MAX && !cache.contains_key(dest) {
            cache.clear();
        }
        cache.insert(dest.to_string(), (std::time::Instant::now(), mimicry));
    }
    Ok(mimicry)
}

async fn probe_target_handshake_uncached(
    dest: &str,
    ch_record: &[u8],
) -> FluxResult<TargetMimicry> {
    let addr = if let Ok(sa) = dest.parse::<std::net::SocketAddr>() {
        sa
    } else {
        let addr_str = if dest.contains(':') {
            dest.to_string()
        } else {
            format!("{}:443", dest)
        };
        tokio::net::lookup_host(&addr_str)
            .await
            .map_err(FluxError::Io)?
            .next()
            .ok_or_else(|| FluxError::Dns(format!("cannot resolve reality target '{}'", dest)))?
    };

    let mut target = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| FluxError::Timeout("reality target dial timed out".into()))?
    .map_err(FluxError::Io)?;

    target.write_all(ch_record).await.map_err(FluxError::Io)?;
    target.flush().await.map_err(FluxError::Io)?;

    let mut mimicry = TargetMimicry::default();
    let mut collected = 0usize;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

    // Read records: SH, optional CCS, then encrypted EE/Cert/CV/Fin (+ optional NST).
    //
    // `record_sizes` slots are fixed: [0]=ServerHello, [1]=CCS, [2]=EE,
    // [3]=Certificate, [4]=CertificateVerify, [5]=Finished. A CCS must therefore
    // not advance the slot cursor, and EE must always land in slot 2 whether or
    // not a CCS was sent — indexing by the loop counter shifted every size by one
    // record when the target omitted CCS, defeating the mimicry.
    let mut app_slot: usize = 2;
    for i in 0..7 {
        // The first record gets the generous deadline (a slow target may still be
        // connecting); every later one is part of a burst the target sends
        // immediately, so waiting seconds for a record that is simply not coming
        // only delays the handshake. This is what made a rustls fallback cost 5 s
        // per connection while an OpenSSL one cost milliseconds: the loop was
        // waiting out the deadline instead of noticing the flight had ended.
        let until = if i == 0 {
            deadline
        } else {
            let sequel =
                tokio::time::Instant::now() + std::time::Duration::from_millis(SEQUEL_IDLE);
            sequel.min(deadline)
        };
        let mut hdr = [0u8; 5];
        let read = tokio::time::timeout_at(until, target.read_exact(&mut hdr)).await;
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(FluxError::Io(e)),
            Err(_) => break, // timeout: use whatever we have
        }
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if len > MAX_HANDSHAKE_RECORD {
            return Err(crypto_err("reality target sent oversized record"));
        }
        // Skip the body; we only need record boundaries.
        let mut body = vec![0u8; len];
        tokio::time::timeout_at(until, target.read_exact(&mut body))
            .await
            .map_err(|_| FluxError::Timeout("reality target read timed out".into()))?
            .map_err(FluxError::Io)?;
        collected += 5 + len;

        match i {
            0 => {
                // Must be a handshake record with a valid TLS 1.3 ServerHello.
                if hdr[0] != TLS_HANDSHAKE || body.len() < 4 + 2 + 32 {
                    return Err(crypto_err("reality target did not send a ServerHello"));
                }
                // Check the ServerHello selects TLS 1.3 (supported_versions ext) and
                // offers a valid key share — mirroring the reference's validation.
                if body[0] != HS_SERVER_HELLO {
                    return Err(crypto_err(
                        "reality target: first message is not ServerHello",
                    ));
                }
                let valid = {
                    let sh = &body[..];
                    // minimal scan for supported_versions=0x0304 and key_share ext
                    let mut ok13 = false;
                    let mut okks = false;
                    if sh.len() > 4 + 2 + 32 {
                        let mut pos = 4 + 2 + 32;
                        if pos < sh.len() {
                            let sid_len = sh[pos] as usize;
                            pos += 1 + sid_len + 2 + 1; // sid echo + cipher + compression
                            if pos + 2 <= sh.len() {
                                let ext_total = u16::from_be_bytes([sh[pos], sh[pos + 1]]) as usize;
                                pos += 2;
                                let ext_end = (pos + ext_total).min(sh.len());
                                while pos + 4 <= ext_end {
                                    let et = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
                                    let el =
                                        u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
                                    pos += 4;
                                    if pos + el > ext_end {
                                        break;
                                    }
                                    if et == 0x002b && el == 2 && sh[pos..pos + 2] == [0x03, 0x04] {
                                        ok13 = true;
                                    }
                                    if et == 0x0033 {
                                        let group = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
                                        let klen =
                                            u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
                                        if (group == GROUP_X25519 && klen == 32)
                                            || (group == GROUP_X25519_MLKEM768
                                                && klen == MLKEM768_ENC_KEY_SIZE + 32)
                                        {
                                            okks = true;
                                        }
                                    }
                                    pos += el;
                                }
                            }
                        }
                    }
                    ok13 && okks
                };
                if !valid {
                    return Err(crypto_err(
                        "reality target ServerHello is not TLS 1.3 with a valid key share",
                    ));
                }
                mimicry.record_sizes[0] = 5 + len;
            }
            1 => {
                if hdr[0] == TLS_CCS {
                    mimicry.record_sizes[1] = 5 + len;
                } else if hdr[0] == TLS_APPDATA {
                    // No CCS: this record is EncryptedExtensions.
                    mimicry.record_sizes[app_slot] = 5 + len;
                    app_slot += 1;
                } else {
                    return Err(crypto_err(
                        "reality target: unexpected record after ServerHello",
                    ));
                }
            }
            2..=6 => {
                if hdr[0] != TLS_APPDATA {
                    return Err(crypto_err("reality target: expected encrypted record"));
                }
                if app_slot < mimicry.record_sizes.len() {
                    mimicry.record_sizes[app_slot] = 5 + len;
                }
                app_slot += 1;
                // Finished record ends the flight: we can't reliably distinguish
                // NST without decrypting, so we stop after the 5th flight record
                // (SH, CCS?, EE, Cert, CV, Fin) — extra NST records (if any) are
                // intentionally left unread and the socket is dropped.
            }
            _ => {}
        }
        // Stop early once we have Fin (6 records with CCS, or 5 without).
        if (mimicry.record_sizes[1] > 0 && i >= 5) || (mimicry.record_sizes[1] == 0 && i >= 4) {
            break;
        }
        if collected > MAX_HANDSHAKE_RECORD * 8 {
            break;
        }
    }

    if mimicry.record_sizes[0] == 0 {
        return Err(crypto_err("reality target sent no ServerHello"));
    }
    Ok(mimicry)
}

// ===========================================================================
// TLS 1.3 server handshake (manual — full control over record framing)
// ===========================================================================

struct Tls13Server;

impl Tls13Server {
    /// Completes a TLS 1.3 server handshake for an authenticated REALITY client.
    /// `ch_record` is the already-read first record containing the ClientHello.
    /// When `mimic` is present, encrypted handshake records are padded to the
    /// target's exact record sizes.
    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        mut stream: S,
        ch_record: &[u8],
        auth_key: &[u8; 32],
        cfg: &RealityServerConfig,
        mimic: Option<TargetMimicry>,
    ) -> FluxResult<Tls13Stream<S>> {
        let hello = parse_client_hello(ch_record)
            .ok_or_else(|| crypto_err("failed to re-parse client hello"))?;
        let peer_pub = hello
            .peer_pub
            .ok_or_else(|| crypto_err("client hello without x25519 key share"))?;

        // Pick the first client-offered cipher suite we support.
        let client_suites = parse_cipher_suites(&hello.raw)
            .ok_or_else(|| crypto_err("failed to parse client cipher suites"))?;
        let suite = client_suites
            .iter()
            .find_map(|id| Tls13Suite::from_id(*id))
            .ok_or_else(|| crypto_err("no common TLS 1.3 cipher suite"))?;

        // ---- ServerHello
        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph);
        let mut server_random = [0u8; 32];
        OsRng.fill_bytes(&mut server_random);

        let mut sh: Vec<u8> = Vec::with_capacity(128);
        sh.extend_from_slice(&[HS_SERVER_HELLO, 0, 0, 0]);
        sh.extend_from_slice(&[0x03, 0x03]); // legacy_version
        sh.extend_from_slice(&server_random);
        sh.push(32);
        sh.extend_from_slice(&hello.session_id); // echo client's session_id
        sh.extend_from_slice(&suite_id(suite).to_be_bytes());
        sh.push(0); // compression: null
        // extensions: supported_versions + key_share
        let mut ext: Vec<u8> = Vec::with_capacity(48);
        ext.extend_from_slice(&0x002bu16.to_be_bytes());
        ext.extend_from_slice(&2u16.to_be_bytes());
        ext.extend_from_slice(&[0x03, 0x04]);
        ext.extend_from_slice(&0x0033u16.to_be_bytes());
        ext.extend_from_slice(&36u16.to_be_bytes());
        ext.extend_from_slice(&GROUP_X25519.to_be_bytes());
        ext.extend_from_slice(&32u16.to_be_bytes());
        ext.extend_from_slice(eph_pub.as_bytes());
        sh.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        sh.extend_from_slice(&ext);
        let sh_len = (sh.len() - 4) as u32;
        let sh_len_b = sh_len.to_be_bytes();
        sh[1] = sh_len_b[1];
        sh[2] = sh_len_b[2];
        sh[3] = sh_len_b[3];

        let mut transcript: Vec<u8> = Vec::with_capacity(1024);
        transcript.extend_from_slice(&hello.raw);
        transcript.extend_from_slice(&sh);

        // ---- Key schedule
        let shared = eph.diffie_hellman(&X25519PublicKey::from(peer_pub));
        let zeros = vec![0u8; suite.hash_len()];
        let empty_hash = suite.hash(&[]);
        let early_secret = suite.hkdf_extract(&zeros, &zeros);
        let derived = suite.derive_secret(&early_secret, "derived", &empty_hash)?;
        let handshake_secret = suite.hkdf_extract(&derived, shared.as_bytes());
        let ch_sh_hash = suite.hash(&transcript);
        let c_hs_secret = suite.derive_secret(&handshake_secret, "c hs traffic", &ch_sh_hash)?;
        let s_hs_secret = suite.derive_secret(&handshake_secret, "s hs traffic", &ch_sh_hash)?;
        let mut server_hs = TrafficState::new(suite, s_hs_secret.clone())?;
        let mut client_hs = TrafficState::new(suite, c_hs_secret.clone())?;

        // ---- Emit the server flight, mirroring the target's record framing.
        let mut flight: Vec<u8> = Vec::with_capacity(4096);
        // ServerHello (plaintext, natural size — reference does not pad it)
        flight.push(TLS_HANDSHAKE);
        flight.extend_from_slice(&[0x03, 0x03]);
        flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        flight.extend_from_slice(&sh);
        // CCS if the target sent one
        if let Some(m) = mimic
            && m.record_sizes[1] > 0
        {
            flight.extend_from_slice(&[TLS_CCS, 0x03, 0x03, 0x00, 0x01, 0x01]);
        }

        // EncryptedExtensions: empty extension list
        let ee = [HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0];
        transcript.extend_from_slice(&ee);
        let ee_rec = pad_record(
            &mut server_hs,
            TLS_HANDSHAKE,
            &ee,
            mimic.and_then(|m| m.size(2)),
        )?;
        flight.extend_from_slice(&ee_rec);

        // Certificate: HMAC-tagged ed25519 cert
        let cert_der = cfg.cert.cert_for(auth_key);
        let mut cert_msg = Vec::with_capacity(cert_der.len() + 16);
        cert_msg.push(HS_CERTIFICATE);
        let cert_body_len = (1 + 3 + 3 + cert_der.len() + 2) as u32;
        let cb = cert_body_len.to_be_bytes();
        cert_msg.extend_from_slice(&[cb[1], cb[2], cb[3]]);
        cert_msg.push(0); // certificate_request_context: empty
        let list_len = (3 + cert_der.len() + 2) as u32;
        let ll = list_len.to_be_bytes();
        cert_msg.extend_from_slice(&[ll[1], ll[2], ll[3]]);
        let cl = (cert_der.len() as u32).to_be_bytes();
        cert_msg.extend_from_slice(&[cl[1], cl[2], cl[3]]);
        cert_msg.extend_from_slice(&cert_der);
        cert_msg.extend_from_slice(&[0, 0]); // no extensions
        transcript.extend_from_slice(&cert_msg);
        let cert_rec = pad_record(
            &mut server_hs,
            TLS_HANDSHAKE,
            &cert_msg,
            mimic.and_then(|m| m.size(3)),
        )?;
        flight.extend_from_slice(&cert_rec);

        // CertificateVerify: ed25519 over context + transcript hash
        let th = suite.hash(&transcript);
        let mut content = Vec::with_capacity(64 + 33 + 1 + th.len());
        content.extend_from_slice(&[0x20u8; 64]);
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0);
        content.extend_from_slice(&th);
        let sig = cfg.cert.sign(&content);
        let mut cv_msg = Vec::with_capacity(4 + 2 + 2 + sig.len());
        cv_msg.push(HS_CERTIFICATE_VERIFY);
        let cv_len = ((2 + 2 + sig.len()) as u32).to_be_bytes();
        cv_msg.extend_from_slice(&[cv_len[1], cv_len[2], cv_len[3]]);
        cv_msg.extend_from_slice(&SIG_ED25519.to_be_bytes());
        cv_msg.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        cv_msg.extend_from_slice(&sig);
        transcript.extend_from_slice(&cv_msg);
        let cv_rec = pad_record(
            &mut server_hs,
            TLS_HANDSHAKE,
            &cv_msg,
            mimic.and_then(|m| m.size(4)),
        )?;
        flight.extend_from_slice(&cv_rec);

        // Finished
        let fin_key = suite.hkdf_expand_label(&s_hs_secret, "finished", &[], suite.hash_len())?;
        let fin_th = suite.hash(&transcript);
        let verify_data = suite.hmac(&fin_key, &fin_th);
        let mut fin_msg = Vec::with_capacity(4 + verify_data.len());
        fin_msg.push(HS_FINISHED);
        let fl = (verify_data.len() as u32).to_be_bytes();
        fin_msg.extend_from_slice(&[fl[1], fl[2], fl[3]]);
        fin_msg.extend_from_slice(&verify_data);
        transcript.extend_from_slice(&fin_msg);
        let fin_rec = pad_record(
            &mut server_hs,
            TLS_HANDSHAKE,
            &fin_msg,
            mimic.and_then(|m| m.size(5)),
        )?;
        flight.extend_from_slice(&fin_rec);

        stream.write_all(&flight).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        // ---- Read client's second flight: CCS? + Finished
        let mut hs_buf: Vec<u8> = Vec::new();
        let mut got_finished = false;
        while !got_finished {
            let mut hdr = [0u8; 5];
            stream.read_exact(&mut hdr).await.map_err(FluxError::Io)?;
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if len > MAX_TLS_RECORD + 256 {
                return Err(crypto_err("oversized record in client flight"));
            }
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.map_err(FluxError::Io)?;
            match hdr[0] {
                TLS_CCS => continue,
                TLS_APPDATA => {
                    let (ctype, plain) = client_hs.decrypt_record(&hdr, &body)?;
                    if ctype != TLS_HANDSHAKE {
                        return Err(crypto_err("unexpected record in client second flight"));
                    }
                    hs_buf.extend_from_slice(&plain);
                }
                other => {
                    return Err(crypto_err(format!(
                        "unexpected record type {} in client second flight",
                        other
                    )));
                }
            }
            while hs_buf.len() >= 4 {
                let mlen = u32::from_be_bytes([0, hs_buf[1], hs_buf[2], hs_buf[3]]) as usize;
                if hs_buf.len() < 4 + mlen {
                    break;
                }
                let msg = hs_buf[..4 + mlen].to_vec();
                hs_buf.drain(..4 + mlen);
                if msg[0] != HS_FINISHED {
                    return Err(crypto_err(format!(
                        "expected client Finished, got handshake type {}",
                        msg[0]
                    )));
                }
                let fin_key_c =
                    suite.hkdf_expand_label(&c_hs_secret, "finished", &[], suite.hash_len())?;
                let expect = suite.hmac(&fin_key_c, &suite.hash(&transcript));
                if msg[4..] != expect[..] {
                    return Err(auth_err("reality client Finished verification failed"));
                }
                // NOTE: client Finished is NOT added to the transcript — application
                // traffic secrets are derived through the server Finished (RFC 8446 §7.1).
                got_finished = true;
            }
        }

        // ---- Application traffic secrets
        let derived2 = suite.derive_secret(&handshake_secret, "derived", &empty_hash)?;
        let master_secret = suite.hkdf_extract(&derived2, &zeros);
        let ap_hash = suite.hash(&transcript);
        let c_ap = suite.derive_secret(&master_secret, "c ap traffic", &ap_hash)?;
        let s_ap = suite.derive_secret(&master_secret, "s ap traffic", &ap_hash)?;

        Ok(Tls13Stream {
            inner: stream,
            suite,
            read_state: TrafficState::new(suite, c_ap)?,
            write_state: TrafficState::new(suite, s_ap)?,
            read_pos: 0,
            read_len: 0,
            hdr_buf: [0u8; 5],
            hdr_len: 0,
            body_buf: Vec::new(),
            body_len: 0,
            tx_buf: Vec::new(),
            pending_write: Vec::new(),
            pending_write_pos: 0,
            pending_unacked: 0,
            closed: false,
        })
    }
}

fn suite_id(suite: Tls13Suite) -> u16 {
    match suite {
        Tls13Suite::Aes128GcmSha256 => 0x1301,
        Tls13Suite::Aes256GcmSha384 => 0x1302,
        Tls13Suite::Chacha20Poly1305Sha256 => 0x1303,
    }
}

/// Extracts the client's offered cipher suites from a raw ClientHello.
fn parse_cipher_suites(hello_raw: &[u8]) -> Option<Vec<u16>> {
    let mut pos = 4 + 2 + 32;
    if pos >= hello_raw.len() {
        return None;
    }
    let sid_len = *hello_raw.get(pos)? as usize;
    pos += 1 + sid_len;
    if pos + 2 > hello_raw.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hello_raw[pos], hello_raw[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > hello_raw.len() {
        return None;
    }
    let (chunks, _) = hello_raw[pos..pos + cs_len].as_chunks::<2>();
    Some(chunks.iter().map(|c| u16::from_be_bytes(*c)).collect())
}

/// Encrypts a handshake record, padding the inner plaintext so the total record
/// size matches the target's record (when it fits; otherwise natural size).
fn pad_record(
    state: &mut TrafficState,
    content_type: u8,
    msg: &[u8],
    target_size: Option<usize>,
) -> FluxResult<Vec<u8>> {
    // natural total = 5 (header) + msg + 1 (inner type) + 16 (AEAD tag)
    let natural = 5 + msg.len() + 1 + 16;
    let pad = match target_size {
        Some(t) if t >= natural => t - natural,
        _ => 0,
    };
    state.encrypt_record_padded(content_type, msg, pad)
}

// ===========================================================================
// Spider mode (client-side anti-MITM behavior, parity with sing-box/Xray):
// when REALITY verification fails, we are talking to the real target (or a
// MITM) — behave like an ordinary HTTPS client instead of aborting instantly.
// ===========================================================================

async fn spider_crawl<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut Tls13Stream<S>,
    server_name: &str,
) {
    use rand::Rng;
    let padding_len = rand::rngs::OsRng.gen_range(30..62);
    let padding: String = "0".repeat(padding_len);
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: identity\r\nCookie: padding={}\r\nConnection: close\r\n\r\n",
        server_name, padding
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.flush().await;
    // Read the response (bounded), like a browser loading the landing page.
    let mut buf = vec![0u8; 16384];
    let mut total = 0usize;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let res = tokio::time::timeout_at(deadline, stream.read(&mut buf)).await;
        match res {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                total += n;
                if total >= 1 << 20 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reality_server_mimics_target_record_framing() {
        // TLS 1.3 decoy with a big-ish cert chain to make record sizes distinctive.
        let cert =
            rcgen::generate_simple_self_signed(vec!["www.microsoft.com".to_string()]).unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(
            cert.cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let decoy_acceptor =
            crate::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();

        // Decoy: complete real TLS handshakes and echo.
        let decoy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = decoy_listener.accept().await {
                let acceptor = decoy_acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);
        let scfg = RealityServerConfig::new(
            vec!["www.microsoft.com".into()],
            server_secret.to_bytes(),
            vec![vec![0x01, 0x02, 0x03, 0x04]],
            Some(decoy_addr.to_string()),
        );
        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server =
            tokio::spawn(async move { RealityHandshake::server_handshake(server_io, &scfg).await });
        let client =
            tokio::spawn(async move { RealityHandshake::client_handshake(client_io, &ccfg).await });

        let mut server_stream = server.await.unwrap().unwrap();
        let mut client_stream = client.await.unwrap().unwrap();

        client_stream.write_all(b"mimicry works").await.unwrap();
        client_stream.flush().await.unwrap();
        let mut buf = [0u8; 13];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"mimicry works");
    }

    /// Regression: when the target sends **no** CCS, every recorded size must
    /// still land in its fixed slot ([2]=EE, [3]=Cert, [4]=CV, [5]=Fin). The
    /// parser used to index by loop counter, so EE's slot was overwritten by the
    /// Certificate and the whole flight was padded with the wrong sizes — the
    /// mimicry silently stopped matching the target.
    #[tokio::test]
    async fn test_reality_mimicry_slots_without_ccs() {
        /// Builds a syntactically valid TLS 1.3 ServerHello record body.
        fn server_hello() -> Vec<u8> {
            let mut b = Vec::new();
            b.push(HS_SERVER_HELLO); // handshake type
            b.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake length (unchecked)
            b.extend_from_slice(&[0x03, 0x03]); // legacy_version
            b.extend_from_slice(&[0x11u8; 32]); // random
            b.push(0x00); // session_id length
            b.extend_from_slice(&[0x13, 0x01]); // cipher_suite
            b.push(0x00); // compression
            let mut exts = Vec::new();
            // supported_versions = TLS 1.3
            exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
            // key_share: X25519 with a 32-byte key
            exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
            exts.extend_from_slice(&[0x22u8; 32]);
            b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            b.extend_from_slice(&exts);
            b
        }

        fn record(content_type: u8, payload: &[u8]) -> Vec<u8> {
            let mut r = vec![content_type, 0x03, 0x03];
            r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            r.extend_from_slice(payload);
            r
        }

        let sh = server_hello();
        let ee = vec![0xAAu8; 40];
        let cert = vec![0xBBu8; 900];
        let cv = vec![0xCCu8; 70];
        let fin = vec![0xDDu8; 36];
        let expected = [
            record(TLS_HANDSHAKE, &sh).len(),
            0, // no CCS
            record(TLS_APPDATA, &ee).len(),
            record(TLS_APPDATA, &cert).len(),
            record(TLS_APPDATA, &cv).len(),
            record(TLS_APPDATA, &fin).len(),
            0,
        ];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut flight = Vec::new();
        flight.extend_from_slice(&record(TLS_HANDSHAKE, &sh));
        flight.extend_from_slice(&record(TLS_APPDATA, &ee));
        flight.extend_from_slice(&record(TLS_APPDATA, &cert));
        flight.extend_from_slice(&record(TLS_APPDATA, &cv));
        flight.extend_from_slice(&record(TLS_APPDATA, &fin));
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain whatever ClientHello the prober writes, then reply.
                let mut junk = [0u8; 4096];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    sock.read(&mut junk),
                )
                .await;
                let _ = sock.write_all(&flight).await;
                let _ = sock.flush().await;
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
        });

        let mimicry = probe_target_handshake(&addr.to_string(), b"fake-clienthello")
            .await
            .expect("probe must parse the scripted flight");
        assert_eq!(
            mimicry.record_sizes, expected,
            "record sizes must land in their fixed slots even without a CCS"
        );
        // The slot accessor used for padding must agree.
        assert_eq!(mimicry.size(2), Some(expected[2]));
        assert_eq!(mimicry.size(3), Some(expected[3]));
        assert_eq!(mimicry.size(1), None, "no CCS means slot 1 stays empty");
    }

    #[tokio::test]
    async fn test_reality_spider_mode_on_real_tls_server() {
        // A real (non-REALITY) TLS 1.3 server behind the port: handshake completes,
        // HMAC verification fails, client must spider (HTTP GET) and then abort.
        let cert =
            rcgen::generate_simple_self_signed(vec!["www.microsoft.com".to_string()]).unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(
            cert.cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let acceptor =
            crate::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        // Respond like a web server to the spider's GET.
                        let mut buf = vec![0u8; 8192];
                        if tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            tls.read(&mut buf),
                        )
                        .await
                        .is_ok()
                        {
                            let _ = tls.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            ).await;
                        }
                    }
                });
            }
        });

        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: [0x42u8; 32], // wrong key: server is a plain TLS server
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let res = RealityHandshake::client_handshake(stream, &ccfg).await;
        let err = res.err().expect("must fail against non-REALITY server");
        assert!(
            err.to_string().contains("processed invalid connection"),
            "unexpected error: {}",
            err
        );
    }

    pub(super) fn server_cfg(priv_key: [u8; 32]) -> RealityServerConfig {
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

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server =
            tokio::spawn(async move { RealityHandshake::server_handshake(server_io, &scfg).await });
        let client =
            tokio::spawn(async move { RealityHandshake::client_handshake(client_io, &ccfg).await });

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

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server =
            tokio::spawn(async move { RealityHandshake::server_handshake(server_io, &scfg).await });
        let client =
            tokio::spawn(async move { RealityHandshake::client_handshake(client_io, &ccfg).await });

        // No fallback configured → server errors; client must fail too.
        let s = server.await.unwrap();
        assert!(s.is_err());
        let c = client.await.unwrap();
        assert!(c.is_err());
    }

    /// The full handshake against a **rustls** fallback must not cost seconds.
    ///
    /// This is the shape that broke in production: a REALITY deployment whose
    /// `fallback` is another flux instance (rustls) paid a 5 s handshake per
    /// connection, while the same deployment with an OpenSSL or Go fallback paid
    /// milliseconds — because the probe waited out its deadline for a record that
    /// rustls does not send instead of noticing the flight had ended.
    #[tokio::test]
    async fn a_rustls_fallback_does_not_stall_the_handshake() {
        use std::time::{Duration, Instant};

        // The fallback: a real rustls TLS 1.3 server, as another flux node would be.
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("reality_rb_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("c.pem");
        let key_path = dir.join("k.pem");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
        let (certs, key) = crate::tls::TlsTransport::load_certs_and_key(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();
        let acceptor =
            crate::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(sock).await {
                        let mut buf = [0u8; 4096];
                        let _ = tls.read(&mut buf).await;
                    }
                });
            }
        });

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);
        let mut scfg = server_cfg(server_secret.to_bytes());
        scfg.fallback = Some(fallback_addr.to_string());
        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server =
            tokio::spawn(async move { RealityHandshake::server_handshake(server_io, &scfg).await });
        let client =
            tokio::spawn(async move { RealityHandshake::client_handshake(client_io, &ccfg).await });

        let started = Instant::now();
        let s = server.await.unwrap();
        let elapsed = started.elapsed();
        let _ = client.await;
        if let Err(e) = &s {
            panic!("the handshake against a rustls fallback failed: {e}");
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "the handshake against a rustls fallback took {elapsed:?}; it must cost              milliseconds, not a timeout"
        );
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
            hexstr, "4bfc7684145ef433495abcd19d3ea65632bee4e84b0c7aa37930b62f4c875a81",
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
            hexstr, "27c6357af4faa968dd06bf5e2bc28cb3b41e80e80a42bf2ce96a430165073ba9",
            "must match python AESGCM reference"
        );
    }
}

#[cfg(test)]
mod cert_parse_tests {
    use super::*;

    /// Regression: a hostile "certificate" whose DER ends exactly on the
    /// Ed25519 OID prefix must not panic `extract_ed25519_pubkey`.
    #[test]
    fn extract_ed25519_pubkey_tolerates_truncated_input() {
        const OID: [u8; 8] = [0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
        // OID at the very end: 8 bytes total, no key material follows.
        assert!(extract_ed25519_pubkey(&OID).is_none());
        // OID plus a few of the 32 key bytes.
        let mut partial = OID.to_vec();
        partial.extend_from_slice(&[1, 2, 3]);
        assert!(extract_ed25519_pubkey(&partial).is_none());
        // Shorter than the OID.
        assert!(extract_ed25519_pubkey(&[0x30, 0x82]).is_none());
        assert!(extract_ed25519_pubkey(&[]).is_none());
        // Complete: OID followed by a full 32-byte key.
        let mut full = OID.to_vec();
        full.extend_from_slice(&[0xABu8; 32]);
        assert_eq!(extract_ed25519_pubkey(&full), Some(&[0xABu8; 32]));
    }
}

#[cfg(test)]
mod hostile_transport_tests {
    use super::tests::server_cfg;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A transport that is deliberately hostile to the record layer: every third
    /// poll returns `Pending` (after waking itself, like a socket with no data
    /// yet) and it moves at most 777 bytes per read / 1000 bytes per write.
    ///
    /// This forces partial record assembly and partial writes, i.e. exactly the
    /// `pending_write` / `pending_unacked` accounting that has regressed twice
    /// (duplicate record on retry after `Pending`, and a shifted record slot).
    struct Flaky<S> {
        inner: S,
        polls: usize,
    }

    impl<S> Flaky<S> {
        fn new(inner: S) -> Self {
            Self { inner, polls: 0 }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Flaky<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.as_mut().get_mut();
            this.polls += 1;
            if this.polls.is_multiple_of(3) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let cap = buf.remaining().min(777);
            let mut limited = buf.take(cap);
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => {
                    let n = limited.filled().len();
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Flaky<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.as_mut().get_mut();
            this.polls += 1;
            if this.polls.is_multiple_of(3) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.len().min(1000);
            Pin::new(&mut this.inner).poll_write(cx, &buf[..n])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let inner = &mut self.as_mut().get_mut().inner;
            match Pin::new(&mut *inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => Pin::new(&mut *inner).poll_shutdown(cx),
                other => other,
            }
        }
    }

    /// Sustained transfer over a stuttering, byte-dribbling transport must still
    /// be byte-exact in both directions: no dropped, duplicated or shifted bytes.
    #[tokio::test]
    async fn stuttering_transport_stays_byte_exact() {
        const TOTAL: usize = 256 * 1024;
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);
        let scfg = server_cfg(server_secret.to_bytes());
        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move {
            RealityHandshake::server_handshake(Flaky::new(server_io), &scfg).await
        });
        let client = tokio::spawn(async move {
            RealityHandshake::client_handshake(Flaky::new(client_io), &ccfg).await
        });
        let mut s = server.await.unwrap().unwrap();
        let mut c = client.await.unwrap().unwrap();

        let payload: Vec<u8> = (0..TOTAL)
            .map(|i| (i.wrapping_mul(131) ^ (i >> 5)) as u8)
            .collect();

        let expect = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = Vec::with_capacity(TOTAL);
            let mut buf = vec![0u8; 64 * 1024];
            while got.len() < TOTAL {
                let n = s.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).await.expect("server write");
                got.extend_from_slice(&buf[..n]);
            }
            let _ = s.flush().await;
            got
        });

        let writer = {
            let payload = payload.clone();
            tokio::spawn(async move {
                for chunk in payload.chunks(16 * 1024) {
                    c.write_all(chunk).await.expect("client write");
                }
                c.flush().await.expect("client flush");
                let mut back = vec![0u8; TOTAL];
                let mut filled = 0;
                while filled < TOTAL {
                    let n = c.read(&mut back[filled..]).await.expect("client read");
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                back.truncate(filled);
                back
            })
        };

        let (received, got) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            (writer.await.unwrap(), echo.await.unwrap())
        })
        .await
        .expect("transfer stalled on a stuttering transport");

        assert_eq!(got.len(), expect.len(), "server received a short stream");
        assert_eq!(got, expect, "server received corrupted bytes");
        assert_eq!(
            received.len(),
            expect.len(),
            "client received a short stream"
        );
        assert_eq!(received, expect, "client received corrupted bytes");
    }
}

#[cfg(test)]
mod bulk_integrity_tests {
    use super::tests::server_cfg;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Every byte written must come back byte-for-byte, in order, across many
    /// records. The single-message test above cannot catch record-boundary bugs.
    #[tokio::test]
    async fn bulk_upload_and_download_are_byte_exact() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);
        let scfg = server_cfg(server_secret.to_bytes());
        let ccfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server =
            tokio::spawn(async move { RealityHandshake::server_handshake(server_io, &scfg).await });
        let client =
            tokio::spawn(async move { RealityHandshake::client_handshake(client_io, &ccfg).await });
        let mut s = server.await.unwrap().unwrap();
        let mut c = client.await.unwrap().unwrap();

        // A position-dependent pattern exposes any shift or dropped run.
        const TOTAL: usize = 512 * 1024;
        let payload: Vec<u8> = (0..TOTAL)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
            .collect();

        // Server echoes whatever it reads, on a separate task.
        let expect = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = Vec::with_capacity(TOTAL);
            let mut buf = vec![0u8; 64 * 1024];
            while got.len() < TOTAL {
                let n = s.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).await.expect("server write");
                got.extend_from_slice(&buf[..n]);
            }
            let _ = s.flush().await;
            got
        });

        let writer = {
            let payload = payload.clone();
            tokio::spawn(async move {
                for chunk in payload.chunks(16 * 1024) {
                    c.write_all(chunk).await.expect("client write");
                }
                c.flush().await.expect("client flush");
                let mut back = vec![0u8; TOTAL];
                let mut filled = 0;
                while filled < TOTAL {
                    let n = c.read(&mut back[filled..]).await.expect("client read");
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                back.truncate(filled);
                back
            })
        };

        let received = writer.await.unwrap();
        let got = echo.await.unwrap();
        assert_eq!(got.len(), expect.len(), "server received a short stream");
        assert_eq!(got, expect, "server received corrupted bytes");
        assert_eq!(
            received.len(),
            expect.len(),
            "client received a short stream"
        );
        assert_eq!(received, expect, "client received corrupted bytes");
    }
}

#[cfg(test)]
mod client_hello_shape_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncRead;

    /// Records everything the client writes and never yields on read, so the
    /// handshake stalls right after emitting its first flight.
    struct CapturingStream {
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for CapturingStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl AsyncWrite for CapturingStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Walks the extension block and returns (type, body) pairs, asserting the
    /// declared lengths are self-consistent on the way.
    fn parse_extensions(hello: &[u8]) -> Vec<u16> {
        // First TLS record: type(1) version(2) length(2), then the handshake.
        assert_eq!(hello[0], 0x16, "not a handshake record");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert!(
            record_len <= hello.len() - 5,
            "record length {record_len} exceeds the {} bytes written",
            hello.len() - 5
        );
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(
            record_len,
            4 + hs_len,
            "record and handshake lengths disagree"
        );
        let body = &hello[9..9 + hs_len];
        let sid_len = body[34] as usize;
        let mut i = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2 + cs_len;
        assert_eq!(body[i], 1, "expected exactly one compression method");
        i += 2;
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        assert_eq!(i + ext_len, body.len(), "extension block length mismatch");
        let end = i + ext_len;
        let mut out = Vec::new();
        while i < end {
            let ty = u16::from_be_bytes([body[i], body[i + 1]]);
            let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
            i += 4;
            assert!(i + len <= end, "extension {ty:#06x} overruns the block");
            out.push(ty);
            i += len;
        }
        assert_eq!(i, end, "trailing bytes after the last extension");
        out
    }

    /// The cipher list from the same walk. Kept separate because GREASE has to be visible
    /// there too, and a fingerprint is read from all three lists at once.
    fn parse_ciphers(hello: &[u8]) -> Vec<u16> {
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        let body = &hello[9..9 + hs_len];
        let sid_len = body[34] as usize;
        let i = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        body[i + 2..i + 2 + cs_len]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// RFC 8701: GREASE values have the form `0x?a?a` with both bytes equal.
    fn is_grease(value: u16) -> bool {
        value & 0x0f0f == 0x0a0a && value.to_be_bytes()[0] == value.to_be_bytes()[1]
    }

    /// A ClientHello with no ALPN is a loud non-browser signal, and the shape of
    /// the block must stay self-consistent or a REALITY server (and any on-path
    /// observer) sees something no browser emits.
    #[tokio::test]
    async fn the_client_hello_is_browser_shaped() {
        let (sk, pk) = {
            let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public = x25519_dalek::PublicKey::from(&secret);
            (secret.to_bytes(), public.to_bytes())
        };
        let _ = sk;
        let cfg = RealityClientConfig {
            server_name: "www.example.com".into(),
            public_key: pk,
            short_id: vec![1, 2, 3, 4],
        };
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = CapturingStream {
            written: written.clone(),
        };
        let fut = RealityHandshake::client_handshake(stream, &cfg);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), fut).await;

        let hello = written.lock().unwrap().clone();
        assert!(hello.len() > 60, "nothing was written");
        let exts = parse_extensions(&hello);

        // ALPN (0x0010) must be present: browsers always send it.
        let alpn_pos = exts
            .iter()
            .position(|t| *t == 0x0010)
            .expect("ClientHello has no ALPN extension — a browser always sends one");
        // No duplicate extensions.
        let mut sorted = exts.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(
            before,
            sorted.len(),
            "duplicate extension in ClientHello: {exts:?}"
        );
        let _ = alpn_pos;

        for required in [0x0000u16, 0x002b, 0x000a, 0x0033, 0x000d, 0x0010] {
            assert!(
                exts.contains(&required),
                "required extension {required:#06x} missing from {exts:?}"
            );
        }

        // A browser's hello carries more than the minimum, and carries GREASE in three
        // places. Without them the JA3 is short, stable and unmistakably a library's.
        for browser_ext in [0x0017u16, 0xff01, 0x000b, 0x0023] {
            assert!(
                exts.contains(&browser_ext),
                "browser extension {browser_ext:#06x} missing from {exts:?}"
            );
        }
        assert!(
            exts.iter().any(|t| is_grease(*t)),
            "no GREASE extension in {exts:?}"
        );

        let ciphers = parse_ciphers(&hello);
        assert!(
            is_grease(ciphers[0]),
            "the cipher list must open with GREASE, got {:#06x}",
            ciphers[0]
        );
        assert!(ciphers.contains(&0x1301), "TLS 1.3 suites must be offered");

        // And in supported_groups.
        let groups_off = exts.iter().position(|t| *t == 0x000a).expect("groups");
        let _ = groups_off;
        assert!(
            parse_groups(&hello).iter().any(|g| is_grease(*g)),
            "no GREASE group"
        );
    }

    /// The group list, for the same reason as the cipher list.
    fn parse_groups(hello: &[u8]) -> Vec<u16> {
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        let body = &hello[9..9 + hs_len];
        let sid_len = body[34] as usize;
        let mut i = 35 + sid_len;
        let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2 + cs_len + 2;
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        let end = i + ext_len;
        while i < end {
            let ty = u16::from_be_bytes([body[i], body[i + 1]]);
            let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
            i += 4;
            if ty == 0x000a {
                let list_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
                return body[i + 2..i + 2 + list_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
            }
            i += len;
        }
        Vec::new()
    }
}
