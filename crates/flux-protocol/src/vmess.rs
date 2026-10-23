use flux_types::{FluxError, FluxResult, NetworkType, TargetAddress};
use rand::RngCore;
use ring::aead::{AES_128_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest as Sha2Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

enum VmessHasher {
    Sha256(Sha256),
    Hmac {
        inner: Box<VmessHasher>,
        outer: Box<VmessHasher>,
    },
}

impl VmessHasher {
    fn new_sha256() -> Self {
        Self::Sha256(Sha256::new())
    }

    fn new_hmac(parent_creator: &dyn Fn() -> VmessHasher, key: &[u8]) -> Self {
        let block_size = 64;
        let mut k = key.to_vec();
        if k.len() > block_size {
            let mut h = parent_creator();
            h.update(&k);
            k = h.finalize().to_vec();
        }
        k.resize(block_size, 0);

        let mut inner = parent_creator();
        let mut outer = parent_creator();

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        inner.update(&ipad);
        outer.update(&opad);

        Self::Hmac {
            inner: Box::new(inner),
            outer: Box::new(outer),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(s) => Sha2Digest::update(s, data),
            Self::Hmac { inner, .. } => inner.update(data),
        }
    }

    fn finalize(self) -> [u8; 32] {
        match self {
            Self::Sha256(s) => s.finalize().into(),
            Self::Hmac { inner, mut outer } => {
                let inner_digest = inner.finalize();
                outer.update(&inner_digest);
                outer.finalize()
            }
        }
    }
}

pub fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut creator: Box<dyn Fn() -> VmessHasher> =
        Box::new(|| VmessHasher::new_hmac(&VmessHasher::new_sha256, b"VMess AEAD KDF"));

    for &p in path {
        let parent = creator;
        let p_vec = p.to_vec();
        creator = Box::new(move || VmessHasher::new_hmac(&*parent, &p_vec));
    }

    let mut h = creator();
    h.update(key);
    h.finalize()
}

/// Takes the 96-bit AEAD nonce that `vmess_kdf` produces in its first 12 bytes.
fn nonce12(full: &[u8; 32]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&full[..12]);
    n
}

pub fn vmess_kdf_16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = vmess_kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub fn vmess_user_cmd_key(uuid: &Uuid) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, uuid.as_bytes());
    Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let full = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full);
    out
}

/// Upper bound on the VMess response header length, in bytes.
///
/// A spec-conforming response header is one command byte plus a two-byte
/// payload length, so 4 bytes is already generous; the peer may otherwise
/// claim up to 65535 and force both a large allocation and (before the buffer
/// was sized from the wire) an out-of-bounds slice panic.
pub const MAX_VMESS_RESP_HDR: usize = 4;

pub const VMESS_VERSION: u8 = 1;
pub const VMESS_SECURITY_AES_128_GCM: u8 = 3;
pub const VMESS_SECURITY_CHACHA20_POLY1305: u8 = 4;

pub const VMESS_CMD_TCP: u8 = 1;
pub const VMESS_CMD_UDP: u8 = 2;

pub const VMESS_ATYP_IPV4: u8 = 1;
pub const VMESS_ATYP_DOMAIN: u8 = 2;
pub const VMESS_ATYP_IPV6: u8 = 3;

use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

type Shake128Xof = <Shake128 as ExtendableOutput>::Reader;

#[derive(Clone, Debug)]
pub struct VmessRequest {
    pub uuid: Uuid,
    pub command: u8,
    pub address: TargetAddress,
    pub security: u8,
    pub session_key: [u8; 16],
    pub session_iv: [u8; 16],
    pub resp_header: u8,
    pub option: u8,
}

pub struct VmessProtocol;

impl VmessProtocol {
    /// Generates standard V2Ray VMess AEAD 16-byte AuthID from user UUID and timestamp.
    pub fn create_auth_id(uuid: &Uuid, timestamp: u64) -> [u8; 16] {
        let cmd_key = vmess_user_cmd_key(uuid);
        let auth_key = vmess_kdf_16(&cmd_key, &[b"AES Auth ID Encryption"]);
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&timestamp.to_be_bytes());
        rand::rngs::OsRng.fill_bytes(&mut buf[8..12]);
        let crc = crc32_ieee(&buf[0..12]);
        buf[12..16].copy_from_slice(&crc.to_be_bytes());

        let cipher = <aes::Aes128 as aes::cipher::KeyInit>::new_from_slice(&auth_key).unwrap();
        let mut block = aes::Block::from(buf);
        aes::cipher::BlockEncrypt::encrypt_block(&cipher, &mut block);
        block.into()
    }

    /// Process-wide replay filter for VMess AEAD auth IDs.
    ///
    /// The auth ID encodes a timestamp that is already checked against a 120 s
    /// window, but freshness is not uniqueness: a captured header used to be
    /// accepted again on every replay inside that window (v2ray and Xray both
    /// wrap the decoder in `antireplay.NewReplayFilter(120)` for this reason).
    fn replay_filter() -> &'static crate::shadowsocks2022::ReplayFilter {
        static FILTER: std::sync::OnceLock<crate::shadowsocks2022::ReplayFilter> =
            std::sync::OnceLock::new();
        FILTER.get_or_init(|| crate::shadowsocks2022::ReplayFilter::new(16384))
    }

    /// Verifies standard V2Ray VMess AEAD 16-byte AuthID against a list of valid user UUIDs.
    ///
    /// Also rejects an auth ID that was already accepted (replay).
    pub fn verify_auth_id(auth_id: &[u8; 16], valid_uuids: &[Uuid]) -> Option<(Uuid, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for uuid in valid_uuids {
            let cmd_key = vmess_user_cmd_key(uuid);
            let auth_key = vmess_kdf_16(&cmd_key, &[b"AES Auth ID Encryption"]);
            let cipher = match <aes::Aes128 as aes::cipher::KeyInit>::new_from_slice(&auth_key) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut block = aes::Block::from(*auth_id);
            aes::cipher::BlockDecrypt::decrypt_block(&cipher, &mut block);
            let decrypted = block.as_slice();
            let ts = u64::from_be_bytes(decrypted[0..8].try_into().unwrap());
            let crc = u32::from_be_bytes(decrypted[12..16].try_into().unwrap());
            if crc32_ieee(&decrypted[0..12]) == crc && now.abs_diff(ts) <= 120 {
                // The ID is cryptographically valid; now ensure it is not a
                // replay of an earlier accepted header.
                if !Self::replay_filter().check_and_insert(auth_id, ts) {
                    return None;
                }
                return Some((*uuid, ts));
            }
        }
        None
    }

    /// Encodes and writes standard VMess AEAD request header in a single atomic buffer.
    pub async fn write_request_header<S: AsyncWrite + Unpin>(
        stream: &mut S,
        uuid: &Uuid,
        network: NetworkType,
        destination: &TargetAddress,
        security: u8,
    ) -> FluxResult<([u8; 16], [u8; 16], u8)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cmd_key = vmess_user_cmd_key(uuid);
        let auth_id = Self::create_auth_id(uuid, now);

        let mut conn_nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut conn_nonce);

        let mut session_key = [0u8; 16];
        let mut session_iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut session_key);
        rand::rngs::OsRng.fill_bytes(&mut session_iv);
        let resp_header_b = 0x55u8;

        // Build plain header body
        let mut body = Vec::with_capacity(64);
        body.push(VMESS_VERSION);
        body.extend_from_slice(&session_iv);
        body.extend_from_slice(&session_key);
        body.push(resp_header_b);
        body.push(0x05); // Opt: RequestOptionChunkStream (1) | RequestOptionChunkMasking (4)
        body.push(security & 0x0F); // pad_len = 0, security
        body.push(0x00); // Reserved

        let cmd = match network {
            NetworkType::Tcp => VMESS_CMD_TCP,
            NetworkType::Udp => VMESS_CMD_UDP,
        };
        body.push(cmd);
        body.extend_from_slice(&destination.port().to_be_bytes());

        match destination {
            TargetAddress::Ip(SocketAddr::V4(v4)) => {
                body.push(VMESS_ATYP_IPV4);
                body.extend_from_slice(&v4.ip().octets());
            }
            TargetAddress::Ip(SocketAddr::V6(v6)) => {
                body.push(VMESS_ATYP_IPV6);
                body.extend_from_slice(&v6.ip().octets());
            }
            TargetAddress::Domain(domain, _) => {
                body.push(VMESS_ATYP_DOMAIN);
                let d_bytes = domain.as_bytes();
                body.push(d_bytes.len() as u8);
                body.extend_from_slice(d_bytes);
            }
        }

        // FNV-1a checksum
        let mut fnv = 0x811c9dc5u32;
        for &b in &body {
            fnv ^= b as u32;
            fnv = fnv.wrapping_mul(0x01000193);
        }
        body.extend_from_slice(&fnv.to_be_bytes());

        // Length encryption
        let len_key = vmess_kdf_16(
            &cmd_key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
        );
        let len_nonce_full = vmess_kdf(
            &cmd_key,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
        );
        let len_nonce = nonce12(&len_nonce_full);
        let len_aead = VmessCipher::header_aead(&len_key);

        let len_bytes = (body.len() as u16).to_be_bytes();
        let len_enc = len_aead
            .encrypt(len_nonce, &auth_id, &len_bytes)
            .map_err(|e| FluxError::Crypto(format!("VMess header len encrypt failed: {}", e)))?;

        // Body encryption
        let body_key = vmess_kdf_16(&cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
        let body_nonce_full = vmess_kdf(
            &cmd_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce],
        );
        let body_nonce = nonce12(&body_nonce_full);
        let body_aead = VmessCipher::header_aead(&body_key);

        let body_enc = body_aead
            .encrypt(body_nonce, &auth_id, &body)
            .map_err(|e| FluxError::Crypto(format!("VMess header body encrypt failed: {}", e)))?;

        let mut req_pkt = Vec::with_capacity(16 + len_enc.len() + 8 + body_enc.len());
        req_pkt.extend_from_slice(&auth_id);
        req_pkt.extend_from_slice(&len_enc);
        req_pkt.extend_from_slice(&conn_nonce);
        req_pkt.extend_from_slice(&body_enc);

        stream.write_all(&req_pkt).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        Ok((session_key, session_iv, resp_header_b))
    }

    /// Reads and decodes standard VMess AEAD request header.
    pub async fn read_request_header<S: AsyncRead + Unpin>(
        stream: &mut S,
        valid_uuids: &[Uuid],
    ) -> FluxResult<VmessRequest> {
        let mut auth_id = [0u8; 16];
        stream
            .read_exact(&mut auth_id)
            .await
            .map_err(FluxError::Io)?;

        let (uuid, _ts) = Self::verify_auth_id(&auth_id, valid_uuids)
            .ok_or_else(|| FluxError::AuthFailed("invalid VMess AEAD auth ID".into()))?;

        let cmd_key = vmess_user_cmd_key(&uuid);

        let mut enc_len = [0u8; 18];
        stream
            .read_exact(&mut enc_len)
            .await
            .map_err(FluxError::Io)?;

        let mut conn_nonce = [0u8; 8];
        stream
            .read_exact(&mut conn_nonce)
            .await
            .map_err(FluxError::Io)?;

        let len_key = vmess_kdf_16(
            &cmd_key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
        );
        let len_nonce_full = vmess_kdf(
            &cmd_key,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
        );
        let len_nonce = nonce12(&len_nonce_full);
        let len_aead = VmessCipher::header_aead(&len_key);

        let len_bytes = len_aead
            .decrypt(len_nonce, &auth_id, &enc_len)
            .map_err(|e| FluxError::Crypto(format!("VMess header len decrypt failed: {}", e)))?;
        let body_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

        let mut enc_body = vec![0u8; body_len + 16];
        stream
            .read_exact(&mut enc_body)
            .await
            .map_err(FluxError::Io)?;

        let body_key = vmess_kdf_16(&cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
        let body_nonce_full = vmess_kdf(
            &cmd_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce],
        );
        let body_nonce = nonce12(&body_nonce_full);
        let body_aead = VmessCipher::header_aead(&body_key);

        let body = body_aead
            .decrypt(body_nonce, &auth_id, &enc_body)
            .map_err(|e| FluxError::Crypto(format!("VMess header body decrypt failed: {}", e)))?;

        if body.len() < 42 {
            return Err(FluxError::Protocol {
                protocol: "vmess",
                message: "VMess header body too short".into(),
            });
        }

        let mut session_iv = [0u8; 16];
        session_iv.copy_from_slice(&body[1..17]);

        let mut session_key = [0u8; 16];
        session_key.copy_from_slice(&body[17..33]);

        let resp_header = body[33];
        let option = body[34];
        let security = body[35] & 0x0F;
        let command = body[37];
        let port = u16::from_be_bytes([body[38], body[39]]);
        let atyp = body[40];

        let address = match atyp {
            VMESS_ATYP_IPV4 => {
                if body.len() < 45 {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "truncated vmess ipv4".into(),
                    });
                }
                let ip = Ipv4Addr::new(body[41], body[42], body[43], body[44]);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            VMESS_ATYP_DOMAIN => {
                let dlen = body[41] as usize;
                if body.len() < 42 + dlen {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "truncated vmess domain".into(),
                    });
                }
                let domain =
                    std::str::from_utf8(&body[42..42 + dlen]).map_err(|e| FluxError::Protocol {
                        protocol: "vmess",
                        message: format!("invalid domain: {}", e),
                    })?;
                TargetAddress::domain(domain, port)
            }
            VMESS_ATYP_IPV6 => {
                if body.len() < 57 {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "truncated vmess ipv6".into(),
                    });
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&body[41..57]);
                TargetAddress::Ip(SocketAddr::new(Ipv6Addr::from(octets).into(), port))
            }
            _ => {
                return Err(FluxError::Protocol {
                    protocol: "vmess",
                    message: format!("unsupported address type: {}", atyp),
                });
            }
        };

        Ok(VmessRequest {
            uuid,
            command,
            address,
            security,
            session_key,
            session_iv,
            resp_header,
            option,
        })
    }
}

fn generate_chacha20_key(b: &[u8]) -> [u8; 32] {
    use md5::{Digest, Md5};
    let mut key = [0u8; 32];
    let c1 = Md5::digest(b);
    key[0..16].copy_from_slice(&c1);
    let c2 = Md5::digest(&key[0..16]);
    key[16..32].copy_from_slice(&c2);
    key
}

/// Tag length of every VMess AEAD (AES-128-GCM and ChaCha20-Poly1305).
const VMESS_TAG_LEN: usize = 16;

/// One direction's AEAD key, with the `ring` key schedule expanded exactly once.
///
/// The schedule used to be rebuilt per packet through `Aes128Gcm::new_from_slice`;
/// with `ring` it is built in `UnboundKey::new` at stream setup and reused, which
/// matters because `ring`'s AES-128 schedule costs ~110 ns — more than the old
/// crate's — and a VMess chunk is only 16 KiB.
struct VmessCipher {
    key: LessSafeKey,
}

impl VmessCipher {
    fn new(security: u8, key: &[u8; 16]) -> Self {
        let unbound = if security == VMESS_SECURITY_CHACHA20_POLY1305 {
            // VMess derives the ChaCha key as MD5(key) ‖ MD5(MD5(key)).
            let key32 = generate_chacha20_key(key);
            UnboundKey::new(&CHACHA20_POLY1305, &key32)
        } else {
            UnboundKey::new(&AES_128_GCM, key)
        };
        Self {
            key: LessSafeKey::new(unbound.expect("vmess aead key length")),
        }
    }

    /// The request and response *header* AEADs are always AES-128-GCM.
    fn header_aead(key: &[u8; 16]) -> Self {
        Self::new(VMESS_SECURITY_AES_128_GCM, key)
    }

    /// Seals `buf[start..]` in place and appends the tag to `buf`.
    ///
    /// `start` keeps an already-written prefix (a chunk-length field, or the
    /// response header that precedes the first chunk) in the same buffer, so no
    /// per-chunk scratch buffer is needed.
    fn seal_tail(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
        start: usize,
    ) -> FluxResult<()> {
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut buf[start..],
            )
            .map_err(|_| FluxError::Crypto("vmess encrypt failed".into()))?;
        buf.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Authenticates and decrypts `buf` in place, returning the plaintext.
    fn open_in_place<'a>(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> FluxResult<&'a mut [u8]> {
        self.key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), buf)
            .map_err(|_| FluxError::Crypto("vmess decrypt failed: bad tag".into()))
    }

    /// Decrypts the ciphertext in `buf[start..]` in place and truncates `buf` to
    /// the plaintext length.
    fn open_tail(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
        start: usize,
    ) -> FluxResult<()> {
        let plain_len = self.open_in_place(nonce, aad, &mut buf[start..])?.len();
        buf.truncate(start + plain_len);
        Ok(())
    }

    /// Seals into a freshly allocated buffer (header paths, once per stream).
    fn encrypt(&self, nonce: [u8; 12], aad: &[u8], plain: &[u8]) -> FluxResult<Vec<u8>> {
        let mut out = Vec::with_capacity(plain.len() + VMESS_TAG_LEN);
        out.extend_from_slice(plain);
        self.seal_tail(nonce, aad, &mut out, 0)?;
        Ok(out)
    }

    /// Opens into a freshly allocated buffer (header paths, once per stream).
    fn decrypt(&self, nonce: [u8; 12], aad: &[u8], cipher: &[u8]) -> FluxResult<Vec<u8>> {
        let mut out = Vec::with_capacity(cipher.len());
        out.extend_from_slice(cipher);
        self.open_tail(nonce, aad, &mut out, 0)?;
        Ok(out)
    }
}

/// The two fixed response-header AEAD keys/nonces.
///
/// They depend only on the session key/IV, so they are derived once when the
/// stream is created instead of on every header read/write (each derivation is a
/// full `vmess_kdf` HMAC chain).
struct RespHeaderAead {
    len_key: VmessCipher,
    len_nonce: [u8; 12],
    hdr_key: VmessCipher,
    hdr_nonce: [u8; 12],
}

impl RespHeaderAead {
    fn new(resp_key: &[u8; 16], resp_iv: &[u8; 16]) -> Self {
        let len_key = vmess_kdf_16(resp_key, &[b"AEAD Resp Header Len Key"]);
        let len_nonce_full = vmess_kdf(resp_iv, &[b"AEAD Resp Header Len IV"]);
        let hdr_key = vmess_kdf_16(resp_key, &[b"AEAD Resp Header Key"]);
        let hdr_nonce_full = vmess_kdf(resp_iv, &[b"AEAD Resp Header IV"]);

        let mut len_nonce = [0u8; 12];
        len_nonce.copy_from_slice(&len_nonce_full[..12]);
        let mut hdr_nonce = [0u8; 12];
        hdr_nonce.copy_from_slice(&hdr_nonce_full[..12]);

        Self {
            len_key: VmessCipher::header_aead(&len_key),
            len_nonce,
            hdr_key: VmessCipher::header_aead(&hdr_key),
            hdr_nonce,
        }
    }
}

fn derive_resp_key_iv(key: &[u8; 16], iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let key_hash = <Sha256 as Sha2Digest>::digest(key);
    let mut resp_key = [0u8; 16];
    resp_key.copy_from_slice(&key_hash[..16]);

    let iv_hash = <Sha256 as Sha2Digest>::digest(iv);
    let mut resp_iv = [0u8; 16];
    resp_iv.copy_from_slice(&iv_hash[..16]);

    (resp_key, resp_iv)
}

pub struct VmessStream<S> {
    inner: S,
    enc_cipher: VmessCipher,
    dec_cipher: VmessCipher,
    enc_iv: [u8; 16],
    dec_iv: [u8; 16],
    write_count: u16,
    read_count: u16,
    is_client: bool,
    header_verified: bool,
    expected_resp_header: u8,
    header_written: bool,
    resp_header: u8,
    /// Response-header AEAD keys, derived once per stream.
    resp_aead: RespHeaderAead,
    read_masker: Option<Shake128Xof>,
    write_masker: Option<Shake128Xof>,

    // Client reading response header
    resp_len_buf: [u8; 18],
    resp_len_pos: usize,
    resp_hdr_buf: Vec<u8>,
    resp_hdr_pos: usize,

    write_buf: Vec<u8>,
    write_pos: usize,
    writing_plain_len: usize,

    // Reader state machine for standard 2-byte chunk length + payload
    len_buf: [u8; 2],
    len_pos: usize,
    payload_len: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,

    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> VmessStream<S> {
    pub fn new(inner: S, key: [u8; 16], iv: [u8; 16], security: u8) -> Self {
        Self::new_client(inner, key, iv, security, 0x55, 0x05)
    }

    pub fn new_client(
        inner: S,
        key: [u8; 16],
        iv: [u8; 16],
        security: u8,
        expected_resp_header: u8,
        option: u8,
    ) -> Self {
        let (resp_key, resp_iv) = derive_resp_key_iv(&key, &iv);
        let enc_cipher = VmessCipher::new(security, &key);
        let dec_cipher = VmessCipher::new(security, &resp_key);

        let (write_masker, read_masker) = if option & 0x04 != 0 {
            let mut h_w = Shake128::default();
            h_w.update(&iv);
            let mut h_r = Shake128::default();
            h_r.update(&resp_iv);
            (Some(h_w.finalize_xof()), Some(h_r.finalize_xof()))
        } else {
            (None, None)
        };

        Self {
            inner,
            enc_cipher,
            dec_cipher,
            enc_iv: iv,
            dec_iv: resp_iv,
            write_count: 0,
            read_count: 0,
            is_client: true,
            header_verified: false,
            expected_resp_header,
            header_written: true,
            resp_header: 0,
            resp_aead: RespHeaderAead::new(&resp_key, &resp_iv),
            read_masker,
            write_masker,
            resp_len_buf: [0u8; 18],
            resp_len_pos: 0,
            resp_hdr_buf: Vec::new(),
            resp_hdr_pos: 0,
            write_buf: Vec::with_capacity(16384 + 32),
            write_pos: 0,
            writing_plain_len: 0,
            len_buf: [0u8; 2],
            len_pos: 0,
            payload_len: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    pub fn new_server(
        inner: S,
        key: [u8; 16],
        iv: [u8; 16],
        security: u8,
        resp_header: u8,
        option: u8,
    ) -> Self {
        let (resp_key, resp_iv) = derive_resp_key_iv(&key, &iv);
        let enc_cipher = VmessCipher::new(security, &resp_key);
        let dec_cipher = VmessCipher::new(security, &key);

        let (read_masker, write_masker) = if option & 0x04 != 0 {
            let mut h_r = Shake128::default();
            h_r.update(&iv);
            let mut h_w = Shake128::default();
            h_w.update(&resp_iv);
            (Some(h_r.finalize_xof()), Some(h_w.finalize_xof()))
        } else {
            (None, None)
        };

        Self {
            inner,
            enc_cipher,
            dec_cipher,
            enc_iv: resp_iv,
            dec_iv: iv,
            write_count: 0,
            read_count: 0,
            is_client: false,
            header_verified: true,
            expected_resp_header: 0,
            header_written: false,
            resp_header,
            resp_aead: RespHeaderAead::new(&resp_key, &resp_iv),
            read_masker,
            write_masker,
            resp_len_buf: [0u8; 18],
            resp_len_pos: 0,
            resp_hdr_buf: Vec::new(),
            resp_hdr_pos: 0,
            write_buf: Vec::with_capacity(16384 + 32),
            write_pos: 0,
            writing_plain_len: 0,
            len_buf: [0u8; 2],
            len_pos: 0,
            payload_len: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    fn make_chunk_nonce(base_iv: &[u8; 16], count: u16) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&base_iv[..12]);
        nonce[0..2].copy_from_slice(&count.to_be_bytes());
        nonce
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Step 0: Client verifies AEAD response header on first read
        if this.is_client && !this.header_verified {
            while this.resp_len_pos < 18 {
                let mut tmp = [0u8; 18];
                let needed = 18 - this.resp_len_pos;
                let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading VMess AEAD response header length",
                            )));
                        }
                        let pos = this.resp_len_pos;
                        this.resp_len_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.resp_len_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Decrypted in place in the fixed 18-byte buffer.
            let resp_hdr_len = match this.resp_aead.len_key.open_in_place(
                this.resp_aead.len_nonce,
                b"",
                &mut this.resp_len_buf[..],
            ) {
                Ok(b) => u16::from_be_bytes([b[0], b[1]]) as usize,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("VMess response header len decrypt failed: {}", e),
                    )));
                }
            };

            // The response header is peer-controlled: `resp_hdr_len` is the
            // decrypted length of a small header (command + payload length).
            // Anything larger is either a protocol error or an attempt to make
            // us buffer/index out of bounds.
            if resp_hdr_len > MAX_VMESS_RESP_HDR {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VMess response header too long: {resp_hdr_len} bytes"),
                )));
            }

            let total_resp_hdr = resp_hdr_len + 16;
            if this.resp_hdr_buf.len() != total_resp_hdr {
                this.resp_hdr_buf.clear();
                this.resp_hdr_buf.resize(total_resp_hdr, 0);
                this.resp_hdr_pos = 0;
            }
            while this.resp_hdr_pos < total_resp_hdr {
                let mut tmp = [0u8; 32];
                let needed = total_resp_hdr - this.resp_hdr_pos;
                let to_read = needed.min(tmp.len());
                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading VMess AEAD response header payload",
                            )));
                        }
                        let pos = this.resp_hdr_pos;
                        let end = pos + n;
                        let Some(dst) = this.resp_hdr_buf.get_mut(pos..end) else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "VMess response header buffer overrun",
                            )));
                        };
                        dst.copy_from_slice(&tmp[..n]);
                        this.resp_hdr_pos = end;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Decrypted in place: `resp_hdr_buf` is reusable scratch space.
            if let Err(e) = this.resp_aead.hdr_key.open_tail(
                this.resp_aead.hdr_nonce,
                b"",
                &mut this.resp_hdr_buf,
                0,
            ) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VMess response header payload decrypt failed: {}", e),
                )));
            }

            if this.resp_hdr_buf.is_empty() || this.resp_hdr_buf[0] != this.expected_resp_header {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mismatched VMess response header verification byte",
                )));
            }
            this.header_verified = true;
        }

        // Fill the caller's buffer: the relay reads with 64 KiB and a VMess chunk is
        // 16 KiB, so returning after one chunk made every buffer four read cycles.
        let mut put = 0usize;

        loop {
            // 1. Drain existing decrypted plaintext
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
                this.read_pos += to_copy;
                put += to_copy;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            // 2. Read 2-byte chunk length
            if this.payload_len == 0 {
                while this.len_pos < 2 {
                    let mut tmp = [0u8; 2];
                    let needed = 2 - this.len_pos;
                    let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                if this.len_pos == 0 {
                                    return Poll::Ready(Ok(())); // Clean EOF
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF reading vmess chunk length",
                                )));
                            }
                            let pos = this.len_pos;
                            this.len_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                            this.len_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            // Bytes were already handed to the caller: that is a
                            // successful read even if nothing more is available now.
                            return if put > 0 {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            };
                        }
                    }
                }

                let mut raw_len_bytes = [this.len_buf[0], this.len_buf[1]];
                if let Some(masker) = &mut this.read_masker {
                    let mut mask = [0u8; 2];
                    masker.read(&mut mask);
                    raw_len_bytes[0] ^= mask[0];
                    raw_len_bytes[1] ^= mask[1];
                }

                let total_payload = u16::from_be_bytes(raw_len_bytes) as usize;
                if total_payload < 16 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vmess chunk length smaller than tag",
                    )));
                }
                this.payload_len = total_payload;
                this.payload_buf.resize(total_payload, 0);
                this.payload_pos = 0;
                this.len_pos = 0;
            }

            // 3. Read encrypted payload chunk (chunk_len + 16 bytes tag)
            let total_payload = this.payload_len;
            while this.payload_pos < total_payload {
                let needed = total_payload - this.payload_pos;
                let mut tmp = [0u8; 8192];
                let to_read = needed.min(tmp.len());
                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading vmess payload chunk",
                            )));
                        }
                        let pos = this.payload_pos;
                        this.payload_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.payload_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // Bytes were already handed to the caller: that is a
                        // successful read even if nothing more is available now.
                        return if put > 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        };
                    }
                }
            }

            let nonce = Self::make_chunk_nonce(&this.dec_iv, this.read_count);
            this.read_count = this.read_count.wrapping_add(1);

            if let Err(e) = this
                .dec_cipher
                .open_tail(nonce, b"", &mut this.payload_buf, 0)
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }

            // Swap rather than copy: both buffers are already allocated.
            std::mem::swap(&mut this.read_buf, &mut this.payload_buf);
            this.read_pos = 0;
            this.payload_len = 0;
            this.payload_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_n = this.writing_plain_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                return Poll::Ready(Ok(plain_n));
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Frame several chunks per call, up to the relay's copy buffer. One 16 KiB
        // chunk per `poll_write` turned a 64 KiB write into four frames, four seals
        // and four syscalls — the defect fixed in the WebSocket, Shadowsocks and
        // REALITY transports, which had all been capped at one framing unit per call.
        let cap = buf.len().min(64 * 1024);
        let mut consumed = 0usize;

        this.write_buf.clear();

        // If server hasn't sent AEAD response header yet, prepend it
        if !this.is_client && !this.header_written {
            let len_start = this.write_buf.len();
            this.write_buf.extend_from_slice(&4u16.to_be_bytes());
            this.resp_aead
                .len_key
                .seal_tail(
                    this.resp_aead.len_nonce,
                    b"",
                    &mut this.write_buf,
                    len_start,
                )
                .unwrap();

            let hdr_start = this.write_buf.len();
            this.write_buf
                .extend_from_slice(&[this.resp_header, 0x01, 0x00, 0x00]);
            this.resp_aead
                .hdr_key
                .seal_tail(
                    this.resp_aead.hdr_nonce,
                    b"",
                    &mut this.write_buf,
                    hdr_start,
                )
                .unwrap();

            this.header_written = true;
        }

        while consumed < cap {
            let chunk_size = (cap - consumed).min(16384);
            let plain = &buf[consumed..consumed + chunk_size];

            let total_chunk_len = (chunk_size + 16) as u16;
            let mut len_bytes = total_chunk_len.to_be_bytes();
            if let Some(masker) = &mut this.write_masker {
                let mut mask = [0u8; 2];
                masker.read(&mut mask);
                len_bytes[0] ^= mask[0];
                len_bytes[1] ^= mask[1];
            }

            let nonce = Self::make_chunk_nonce(&this.enc_iv, this.write_count);
            this.write_count = this.write_count.wrapping_add(1);

            this.write_buf.extend_from_slice(&len_bytes);
            // Seal the payload straight into the write buffer: no per-chunk
            // allocation and no second copy.
            let payload_start = this.write_buf.len();
            this.write_buf.extend_from_slice(plain);
            if let Err(e) =
                this.enc_cipher
                    .seal_tail(nonce, b"", &mut this.write_buf, payload_start)
            {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            consumed += chunk_size;
        }
        this.write_pos = 0;
        this.writing_plain_len = consumed;

        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_n = this.writing_plain_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                return Poll::Ready(Ok(plain_n));
            }
        }

        Poll::Pending
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                break;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                break;
            }
            this.write_pos += n;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vmess_aead_roundtrip() {
        let test_uuid = Uuid::new_v4();
        let target = TargetAddress::domain("example.com", 443);

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);

        let user_list = vec![test_uuid];

        let srv = tokio::spawn(async move {
            let req = VmessProtocol::read_request_header(&mut server_io, &user_list)
                .await
                .unwrap();
            assert_eq!(req.uuid, test_uuid);
            assert_eq!(req.address, TargetAddress::domain("example.com", 443));

            let mut stream = VmessStream::new_server(
                server_io,
                req.session_key,
                req.session_iv,
                req.security,
                req.resp_header,
                req.option,
            );
            let mut buf = [0u8; 10];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping vmess");
            stream.write_all(b"pong vmess").await.unwrap();
            stream.flush().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let (key, iv, resp_hdr) = VmessProtocol::write_request_header(
                &mut client_io,
                &test_uuid,
                NetworkType::Tcp,
                &target,
                VMESS_SECURITY_AES_128_GCM,
            )
            .await
            .unwrap();

            let mut stream = VmessStream::new_client(
                client_io,
                key,
                iv,
                VMESS_SECURITY_AES_128_GCM,
                resp_hdr,
                0x05,
            );
            stream.write_all(b"ping vmess").await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = [0u8; 10];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong vmess");
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[test]
    fn test_shake128_reader() {
        use sha3::Shake128;
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = Shake128::default();
        hasher.update(b"test nonce");
        let mut reader = hasher.finalize_xof();
        let mut buf1 = [0u8; 2];
        reader.read(&mut buf1);
        let mut buf2 = [0u8; 2];
        reader.read(&mut buf2);
        assert_ne!(buf1, [0, 0]);
        assert_ne!(buf2, [0, 0]);
    }

    /// Regression: a peer that declares an oversized response header must be
    /// rejected, not panic the client task (the header length is decrypted from
    /// the wire and used to index a fixed-size buffer).
    #[tokio::test]
    async fn test_vmess_rejects_oversized_response_header() {
        let test_uuid = Uuid::new_v4();
        let target = TargetAddress::domain("example.com", 443);
        let (mut client_io, mut server_io) = tokio::io::duplex(4096);

        let srv = tokio::spawn(async move {
            let req = VmessProtocol::read_request_header(&mut server_io, &[test_uuid])
                .await
                .unwrap();

            // Derive the response keys exactly as a real server would.
            let resp_key = vmess_kdf_16(&req.session_key, &[b"AEAD Resp Header Key"]);
            let resp_iv = vmess_kdf(&req.session_iv, &[b"AEAD Resp Header IV"]);

            // Fixed part: option | command | payload length.
            let mut len_block = [0u8; 18];
            len_block[0] = req.option;
            len_block[1] = 0x03; // 18 - 16 + 1
            let len_key = vmess_kdf_16(&resp_key, &[b"AEAD Resp Header Len Key"]);
            let len_nonce = vmess_kdf(&resp_iv, &[b"AEAD Resp Header Len IV"]);
            let cipher = VmessCipher::header_aead(&len_key);
            let enc_len = cipher
                .encrypt(nonce12(&len_nonce), b"", &len_block)
                .unwrap();
            server_io.write_all(&enc_len).await.unwrap();

            // Declare an absurd header length and then supply garbage bytes.
            let mut hdr_block = vec![0u8; 2 + 16];
            hdr_block[0] = 0xFF; // 65535
            hdr_block[1] = 0xFF;
            let hdr_nonce = vmess_kdf(&resp_iv, &[b"AEAD Resp Header IV"]);
            let enc_hdr = cipher
                .encrypt(nonce12(&hdr_nonce), b"", &hdr_block)
                .unwrap();
            server_io.write_all(&enc_hdr).await.unwrap();
            let _ = server_io.write_all(&vec![0u8; 512]).await;
            let _ = server_io.flush().await;
            // Keep the stream alive so the client observes the length error
            // rather than an EOF.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            req
        });

        let cli = tokio::spawn(async move {
            let (key, iv, resp_hdr) = VmessProtocol::write_request_header(
                &mut client_io,
                &test_uuid,
                NetworkType::Tcp,
                &target,
                VMESS_SECURITY_AES_128_GCM,
            )
            .await
            .unwrap();
            let mut stream = VmessStream::new_client(
                client_io,
                key,
                iv,
                VMESS_SECURITY_AES_128_GCM,
                resp_hdr,
                0x05,
            );
            // Whatever happens, it must be an error — never a panic.
            let res = stream.write_all(b"x").await.and(stream.flush().await);
            let mut buf = [0u8; 16];
            let read_res = stream.read(&mut buf).await;
            assert!(
                res.is_err() || read_res.is_err(),
                "an oversized response header must produce an error"
            );
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[test]
    fn test_vmess_kdf_standard_test_vector() {
        let key = b"Demo Key for KDF Value Test";
        let path = [
            b"Demo Path for KDF Value Test".as_slice(),
            b"Demo Path for KDF Value Test2".as_slice(),
            b"Demo Path for KDF Value Test3".as_slice(),
        ];
        let val = vmess_kdf(key, &path);
        let hex = format!("{:x}", bytes::Bytes::copy_from_slice(&val));
        assert_eq!(
            hex,
            "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
        );
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A valid auth ID must be accepted once and rejected on replay, even though
    /// its embedded timestamp is still inside the freshness window.
    #[test]
    fn auth_id_replay_is_rejected() {
        let uuid = Uuid::new_v4();
        let auth_id = VmessProtocol::create_auth_id(&uuid, now_secs());

        let first = VmessProtocol::verify_auth_id(&auth_id, &[uuid]);
        assert!(first.is_some(), "a fresh, valid auth ID must be accepted");

        let replay = VmessProtocol::verify_auth_id(&auth_id, &[uuid]);
        assert!(
            replay.is_none(),
            "replaying the same auth ID must be rejected inside the 120 s window"
        );
    }

    /// Distinct auth IDs for the same user must both be accepted (the filter
    /// keys on the ID, not on the user).
    #[test]
    fn distinct_auth_ids_are_independent() {
        let uuid = Uuid::new_v4();
        let a = VmessProtocol::create_auth_id(&uuid, now_secs());
        let b = VmessProtocol::create_auth_id(&uuid, now_secs());
        assert_ne!(a, b);
        assert!(VmessProtocol::verify_auth_id(&a, &[uuid]).is_some());
        assert!(VmessProtocol::verify_auth_id(&b, &[uuid]).is_some());
    }

    /// An auth ID for an unknown user is rejected regardless of the filter.
    #[test]
    fn unknown_user_is_rejected() {
        let known = Uuid::new_v4();
        let other = Uuid::new_v4();
        let auth_id = VmessProtocol::create_auth_id(&other, now_secs());
        assert!(VmessProtocol::verify_auth_id(&auth_id, &[known]).is_none());
    }
}
