//! VLESS Post-Quantum Encryption (`mlkem768x25519plus`).
//!
//! Implements post-quantum key exchange (hybrid ML-KEM-768 + X25519) and session
//! resumption for VLESS, fully wire-compatible with Xray-core (`proxy/vless/encryption`).
//!
//! Protocol wire format:
//! - Configuration: `mlkem768x25519plus.<native/xorpub/random>.<0rtt/1rtt/seconds>.<padding?>.<keys...>`
//! - Framing: TLS 1.3-shaped records `[23, 3, 3, len_hi, len_lo]` followed by AEAD ciphertext
//!   (AES-256-GCM or ChaCha20-Poly1305) with BLAKE3-derived subkeys.

use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::{KeyIvInit, StreamCipher};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use flux_types::{BoxedStream, FluxError, FluxResult};
use rand::RngCore;
use rand::rngs::OsRng;
use std::io;
use std::pin::Pin;

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// BLAKE3 initial vector words.
const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// BLAKE3 round permutation schedule.
const BLAKE3_MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// BLAKE3 compression function g.
#[inline(always)]
fn blake3_g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One round of BLAKE3 compression.
#[inline(always)]
fn blake3_round(state: &mut [u32; 16], msg: &[u32; 16]) {
    blake3_g(state, 0, 4, 8, 12, msg[0], msg[1]);
    blake3_g(state, 1, 5, 9, 13, msg[2], msg[3]);
    blake3_g(state, 2, 6, 10, 14, msg[4], msg[5]);
    blake3_g(state, 3, 7, 11, 15, msg[6], msg[7]);
    blake3_g(state, 0, 5, 10, 15, msg[8], msg[9]);
    blake3_g(state, 1, 6, 11, 12, msg[10], msg[11]);
    blake3_g(state, 2, 7, 8, 13, msg[12], msg[13]);
    blake3_g(state, 3, 4, 9, 14, msg[14], msg[15]);
}

/// Permute message words.
#[inline(always)]
fn blake3_permute(msg: &mut [u32; 16]) {
    let mut perm = [0u32; 16];
    for i in 0..16 {
        perm[i] = msg[BLAKE3_MSG_PERMUTATION[i]];
    }
    *msg = perm;
}

/// Compress a single BLAKE3 block.
fn blake3_compress(
    cv: &[u32; 8],
    block: &[u8; 64],
    block_len: u8,
    counter: u64,
    flags: u8,
) -> [u32; 16] {
    let mut msg = [0u32; 16];
    for i in 0..16 {
        msg[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len as u32,
        flags as u32,
    ];
    for _ in 0..7 {
        blake3_round(&mut state, &msg);
        blake3_permute(&mut msg);
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

/// Computes BLAKE3 hash of an input up to 1024 bytes with the given flags.
fn blake3_hash_chunk(input: &[u8], key: &[u32; 8], flags: u8) -> [u8; 32] {
    assert!(input.len() <= 1024);
    let mut cv = *key;
    let mut pos = 0;
    let chunk_start = 1 << 0;
    let chunk_end = 1 << 1;
    let root = 1 << 3;

    while pos + 64 < input.len() {
        let mut block = [0u8; 64];
        block.copy_from_slice(&input[pos..pos + 64]);
        let block_flags = flags | if pos == 0 { chunk_start } else { 0 };
        let state = blake3_compress(&cv, &block, 64, 0, block_flags);
        cv.copy_from_slice(&state[..8]);
        pos += 64;
    }

    let mut block = [0u8; 64];
    let rem = &input[pos..];
    block[..rem.len()].copy_from_slice(rem);
    let mut final_flags = flags | chunk_end | root;
    if pos == 0 {
        final_flags |= chunk_start;
    }
    let state = blake3_compress(&cv, &block, rem.len() as u8, 0, final_flags);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Derives a 32-byte key using BLAKE3 KDF matching Go `blake3.DeriveKey(k, string(ctx), key)`.
pub fn blake3_derive_key_raw(ctx: &[u8], key_material: &[u8]) -> [u8; 32] {
    let context_key = if let Ok(s) = std::str::from_utf8(ctx) {
        blake3::hazmat::hash_derive_key_context(s)
    } else if ctx.len() <= 1024 {
        blake3_hash_chunk(ctx, &BLAKE3_IV, 1 << 5 /* DERIVE_KEY_CONTEXT */)
    } else {
        // Multi-chunk context: hash with DERIVE_KEY_CONTEXT flag
        let mut cvs = Vec::new();
        let mut pos = 0;
        let mut chunk_idx = 0u64;
        while pos < ctx.len() {
            let chunk_len = (ctx.len() - pos).min(1024);
            let chunk = &ctx[pos..pos + chunk_len];
            let mut cv = BLAKE3_IV;
            let mut cpos = 0;
            while cpos + 64 < chunk.len() {
                let mut block = [0u8; 64];
                block.copy_from_slice(&chunk[cpos..cpos + 64]);
                let flags = (1 << 5) | if cpos == 0 { 1 << 0 } else { 0 };
                let st = blake3_compress(&cv, &block, 64, chunk_idx, flags);
                cv.copy_from_slice(&st[..8]);
                cpos += 64;
            }
            let mut block = [0u8; 64];
            let rem = &chunk[cpos..];
            block[..rem.len()].copy_from_slice(rem);
            let mut flags = (1 << 5) | (1 << 1);
            if cpos == 0 {
                flags |= 1 << 0;
            }
            let st = blake3_compress(&cv, &block, rem.len() as u8, chunk_idx, flags);
            let mut out = [0u8; 32];
            for i in 0..8 {
                out[i * 4..i * 4 + 4].copy_from_slice(&st[i].to_le_bytes());
            }
            cvs.push(out);
            pos += chunk_len;
            chunk_idx += 1;
        }
        while cvs.len() > 1 {
            let mut next = Vec::with_capacity(cvs.len().div_ceil(2));
            for pair in cvs.chunks(2) {
                if pair.len() == 2 {
                    let mut parent_block = [0u8; 64];
                    parent_block[..32].copy_from_slice(&pair[0]);
                    parent_block[32..].copy_from_slice(&pair[1]);
                    let flags = (1 << 5) | (1 << 2) | if cvs.len() == 2 { 1 << 3 } else { 0 };
                    let st = blake3_compress(&BLAKE3_IV, &parent_block, 64, 0, flags);
                    let mut out = [0u8; 32];
                    for i in 0..8 {
                        out[i * 4..i * 4 + 4].copy_from_slice(&st[i].to_le_bytes());
                    }
                    next.push(out);
                } else {
                    next.push(pair[0]);
                }
            }
            cvs = next;
        }
        cvs[0]
    };

    use blake3::hazmat::HasherExt;
    let mut h = blake3::Hasher::new_from_context_key(&context_key);
    h.update(key_material);
    *h.finalize().as_bytes()
}

/// AES-256-CTR key stream cipher for XorMode::Random.
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Creates an AES-256-CTR stream cipher with key derived from BLAKE3("VLESS", key) and IV.
fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let k = blake3::derive_key("VLESS", key);
    Aes256Ctr::new((&k).into(), iv.into())
}

/// XOR obfuscation mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XorMode {
    /// No obfuscation ("native").
    #[default]
    Native = 0,
    /// XOR public key only ("xorpub").
    XorPub = 1,
    /// Full stream CTR XOR ("random").
    Random = 2,
}

impl XorMode {
    /// Parses the xor mode string from configuration.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "native" => Some(Self::Native),
            "xorpub" => Some(Self::XorPub),
            "random" => Some(Self::Random),
            _ => None,
        }
    }
}

/// Nonce for AEAD: 12 bytes, incremented big-endian.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AeadNonce(pub [u8; 12]);

impl AeadNonce {
    /// Creates a zero nonce.
    pub fn zero() -> Self {
        Self([0u8; 12])
    }

    /// Checks if this is the maximum nonce `[255; 12]`.
    pub fn is_max(&self) -> bool {
        self.0 == [255u8; 12]
    }

    /// Increments the 12-byte nonce big-endian and returns the incremented value (matching Go's IncreaseNonce).
    pub fn inc_fetch(&mut self) -> [u8; 12] {
        for i in 0..12 {
            let idx = 11 - i;
            self.0[idx] = self.0[idx].wrapping_add(1);
            if self.0[idx] != 0 {
                break;
            }
        }
        self.0
    }
}

/// VLESS AEAD cipher: AES-256-GCM or ChaCha20-Poly1305.
pub enum VlessCipher {
    /// AES-256-GCM.
    AesGcm(Box<Aes256Gcm>),
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

/// Authenticated encryption with associated data state for VLESS framing.
pub struct VlessAead {
    cipher: VlessCipher,
    /// Current AEAD nonce.
    pub nonce: AeadNonce,
    /// Whether AES-256-GCM is used (true) or ChaCha20-Poly1305 (false).
    pub use_aes: bool,
}

impl VlessAead {
    /// Constructs a new AEAD instance using BLAKE3 key derivation.
    pub fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let k = blake3_derive_key_raw(ctx, key);
        let cipher = if use_aes {
            VlessCipher::AesGcm(Box::new(Aes256Gcm::new((&k).into())))
        } else {
            VlessCipher::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new((&k).into())))
        };
        Self {
            cipher,
            nonce: AeadNonce::zero(),
            use_aes,
        }
    }

    /// Seals plaintext with the current nonce and additional authenticated data.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let n = self.nonce.inc_fetch();
        let nonce_bytes = Nonce::from_slice(&n);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match &self.cipher {
            VlessCipher::AesGcm(c) => c
                .encrypt(nonce_bytes, payload)
                .expect("AES-GCM seal failed"),
            VlessCipher::ChaCha20Poly1305(c) => c
                .encrypt(nonce_bytes, payload)
                .expect("ChaCha20Poly1305 seal failed"),
        }
    }

    /// Seals plaintext with an explicit nonce.
    pub fn seal_with_nonce(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce_bytes = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match &self.cipher {
            VlessCipher::AesGcm(c) => c
                .encrypt(nonce_bytes, payload)
                .expect("AES-GCM seal failed"),
            VlessCipher::ChaCha20Poly1305(c) => c
                .encrypt(nonce_bytes, payload)
                .expect("ChaCha20Poly1305 seal failed"),
        }
    }

    /// Opens ciphertext with the current nonce and additional authenticated data.
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> FluxResult<Vec<u8>> {
        let n = self.nonce.inc_fetch();
        let nonce_bytes = Nonce::from_slice(&n);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match &self.cipher {
            VlessCipher::AesGcm(c) => {
                c.decrypt(nonce_bytes, payload)
                    .map_err(|e| FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("AES-GCM open failed: {e}"),
                    })
            }
            VlessCipher::ChaCha20Poly1305(c) => {
                c.decrypt(nonce_bytes, payload)
                    .map_err(|e| FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("ChaCha20Poly1305 open failed: {e}"),
                    })
            }
        }
    }

    /// Opens ciphertext with an explicit nonce.
    pub fn open_with_nonce(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> FluxResult<Vec<u8>> {
        let nonce_bytes = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match &self.cipher {
            VlessCipher::AesGcm(c) => {
                c.decrypt(nonce_bytes, payload)
                    .map_err(|e| FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("AES-GCM open failed: {e}"),
                    })
            }
            VlessCipher::ChaCha20Poly1305(c) => {
                c.decrypt(nonce_bytes, payload)
                    .map_err(|e| FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("ChaCha20Poly1305 open failed: {e}"),
                    })
            }
        }
    }
}

/// Encodes a TLS 1.3-shaped record header `[23, 3, 3, l >> 8, l & 0xff]`.
pub fn encode_record_header(len: usize) -> [u8; 5] {
    [23, 3, 3, (len >> 8) as u8, (len & 0xff) as u8]
}

/// Decodes a TLS 1.3-shaped record header. Returns payload length (17..=16640).
pub fn decode_record_header(hdr: &[u8; 5]) -> FluxResult<usize> {
    if hdr[0] != 23 || hdr[1] != 3 || hdr[2] != 3 {
        return Err(FluxError::Protocol {
            protocol: "vless-enc",
            message: format!("invalid record header: {hdr:?}"),
        });
    }
    let l = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
    if !(17..=16640).contains(&l) {
        return Err(FluxError::Protocol {
            protocol: "vless-enc",
            message: format!("invalid record length: {l}"),
        });
    }
    Ok(l)
}

/// Encodes length as 2 big-endian bytes.
pub fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, (l & 0xff) as u8]
}

/// Decodes length from 2 big-endian bytes.
pub fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | (b[1] as usize)
}

/// Padding rule `(probability%, min_len, max_len)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaddingRule {
    /// Probability 0..=100.
    pub prob: u32,
    /// Min length or gap.
    pub min: u32,
    /// Max length or gap.
    pub max: u32,
}

impl PaddingRule {
    /// Samples a value from this rule.
    pub fn sample(&self) -> u32 {
        let roll = OsRng.next_u32() % 100;
        if roll < self.prob {
            if self.max <= self.min {
                self.min
            } else {
                let diff = self.max - self.min;
                self.min + (OsRng.next_u32() % (diff + 1))
            }
        } else {
            0
        }
    }
}

/// Parses padding parameters from the config string.
pub fn parse_padding(padding_str: &str) -> (Vec<PaddingRule>, Vec<PaddingRule>) {
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    if padding_str.is_empty() {
        return (lens, gaps);
    }
    for (i, part) in padding_str.split('.').enumerate() {
        let nums: Vec<&str> = part.split('-').collect();
        if nums.len() == 3
            && let (Ok(p), Ok(min), Ok(max)) = (
                nums[0].parse::<u32>(),
                nums[1].parse::<u32>(),
                nums[2].parse::<u32>(),
            )
        {
            let rule = PaddingRule { prob: p, min, max };
            if i % 2 == 0 {
                lens.push(rule);
            } else {
                gaps.push(rule);
            }
        }
    }
    (lens, gaps)
}

/// Creates random padding bytes based on configured rules.
pub fn create_padding(padding_lens: &[PaddingRule], _padding_gaps: &[PaddingRule]) -> Vec<u8> {
    let total_len = if padding_lens.is_empty() {
        // Default Xray padding: {100, 111, 1111}, {50, 0, 3333}
        let r1 = PaddingRule {
            prob: 100,
            min: 111,
            max: 1111,
        };
        let r2 = PaddingRule {
            prob: 50,
            min: 0,
            max: 3333,
        };
        (r1.sample() + r2.sample()) as usize
    } else {
        padding_lens.iter().map(|r| r.sample() as usize).sum()
    };
    let total_len = total_len.clamp(35, 65535);
    let mut pad = vec![0u8; total_len];
    OsRng.fill_bytes(&mut pad);
    pad
}

/// Decoded client key for VLESS Encryption.
#[derive(Clone)]
pub enum ClientPeerKey {
    /// Classic X25519 public key (32 bytes).
    X25519([u8; 32]),
    /// Post-quantum ML-KEM-768 encapsulation key (1184 bytes).
    MlKem768(Box<ml_kem_768::EncapsKey>),
}

/// Decoded server key for VLESS Decryption.
pub enum ServerPrivateKey {
    /// Classic X25519 private key (32 bytes).
    X25519([u8; 32]),
    /// Post-quantum ML-KEM-768 decapsulation key from 64-byte seed.
    MlKem768 {
        /// Encapsulation key bytes (1184 bytes).
        encap_key_bytes: Box<[u8; 1184]>,
        /// Decapsulation key.
        decap_key: Box<ml_kem_768::DecapsKey>,
    },
}

/// Client configuration for VLESS Encryption.
#[derive(Clone)]
pub struct VlessEncryptionClientConfig {
    /// XOR mode.
    pub xor_mode: XorMode,
    /// Whether 0-RTT ticket resumption is enabled.
    pub zero_rtt: bool,
    /// Padding length rules.
    pub padding_lens: Vec<PaddingRule>,
    /// Padding gap rules.
    pub padding_gaps: Vec<PaddingRule>,
    /// Server public keys for each hop.
    pub keys: Vec<ClientPeerKey>,
    /// Raw key bytes for each hop.
    pub raw_key_bytes: Vec<Vec<u8>>,
    /// Precomputed BLAKE3 hashes for chained hops.
    pub hash32s: Vec<[u8; 32]>,
}

impl VlessEncryptionClientConfig {
    /// Parses client encryption configuration string.
    pub fn parse(s: &str) -> FluxResult<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(FluxError::Config(format!(
                "invalid vless encryption config: must start with mlkem768x25519plus: '{s}'"
            )));
        }
        let xor_mode = XorMode::parse(parts[1]).ok_or_else(|| {
            FluxError::Config(format!(
                "invalid xor mode '{}' in vless encryption",
                parts[1]
            ))
        })?;
        let zero_rtt = parts[2] == "0rtt";

        let mut padding_str = String::new();
        let mut key_strs = Vec::new();
        for &p in &parts[3..] {
            if p.len() < 20 {
                if !padding_str.is_empty() {
                    padding_str.push('.');
                }
                padding_str.push_str(p);
            } else {
                key_strs.push(p);
            }
        }

        if key_strs.is_empty() {
            return Err(FluxError::Config(
                "vless encryption config contains no server public keys".into(),
            ));
        }

        let (padding_lens, padding_gaps) = parse_padding(&padding_str);
        let mut keys = Vec::new();
        let mut raw_key_bytes = Vec::new();
        let mut hash32s = Vec::new();

        use base64::Engine;
        for k_str in key_strs {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(k_str)
                .map_err(|e| {
                    FluxError::Config(format!("invalid base64url key in vless encryption: {e}"))
                })?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                keys.push(ClientPeerKey::X25519(arr));
            } else if bytes.len() == 1184 {
                let mut arr = [0u8; 1184];
                arr.copy_from_slice(&bytes);
                let ek = ml_kem_768::EncapsKey::try_from_bytes(arr).map_err(|e| {
                    FluxError::Config(format!("invalid ML-KEM-768 encapsulation key: {e}"))
                })?;
                keys.push(ClientPeerKey::MlKem768(Box::new(ek)));
            } else {
                return Err(FluxError::Config(format!(
                    "invalid server public key length {} in vless encryption (expected 32 or 1184)",
                    bytes.len()
                )));
            }
            hash32s.push(*blake3::hash(&bytes).as_bytes());
            raw_key_bytes.push(bytes);
        }

        Ok(Self {
            xor_mode,
            zero_rtt,
            padding_lens,
            padding_gaps,
            keys,
            raw_key_bytes,
            hash32s,
        })
    }
}

type SessionTicketCache =
    Arc<parking_lot::RwLock<std::collections::HashMap<[u8; 16], (Vec<u8>, Instant)>>>;

/// Server configuration for VLESS Decryption.
pub struct VlessDecryptionServerConfig {
    /// XOR mode.
    pub xor_mode: XorMode,
    /// Ticket expiration cache seconds (from..to).
    pub seconds_from: u32,
    /// Ticket expiration upper bound.
    pub seconds_to: u32,
    /// Padding rules.
    pub padding_lens: Vec<PaddingRule>,
    /// Padding gaps.
    pub padding_gaps: Vec<PaddingRule>,
    /// Server private keys for each hop.
    pub keys: Vec<ServerPrivateKey>,
    /// Public key bytes for each hop.
    pub public_key_bytes: Vec<Vec<u8>>,
    /// Precomputed BLAKE3 hashes for chained hops.
    pub hash32s: Vec<[u8; 32]>,
    /// Total length of relays field in handshake.
    pub relays_len: usize,
    /// Resumption tickets cache: maps 16-byte ticket -> (pfs_key, expiry).
    sessions: SessionTicketCache,
}

impl VlessDecryptionServerConfig {
    /// Parses server decryption configuration string.
    pub fn parse(s: &str) -> FluxResult<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(FluxError::Config(format!(
                "invalid vless decryption config: must start with mlkem768x25519plus: '{s}'"
            )));
        }
        let xor_mode = XorMode::parse(parts[1]).ok_or_else(|| {
            FluxError::Config(format!(
                "invalid xor mode '{}' in vless decryption",
                parts[1]
            ))
        })?;

        let (seconds_from, seconds_to) = if let Some((from_str, to_str)) = parts[2].split_once('-')
        {
            let from = from_str.trim_end_matches('s').parse::<u32>().unwrap_or(600);
            let to = to_str.trim_end_matches('s').parse::<u32>().unwrap_or(from);
            (from, to)
        } else {
            let from = parts[2].trim_end_matches('s').parse::<u32>().unwrap_or(600);
            (from, 0)
        };

        let mut padding_str = String::new();
        let mut key_strs = Vec::new();
        for &p in &parts[3..] {
            if p.len() < 20 {
                if !padding_str.is_empty() {
                    padding_str.push('.');
                }
                padding_str.push_str(p);
            } else {
                key_strs.push(p);
            }
        }

        if key_strs.is_empty() {
            return Err(FluxError::Config(
                "vless decryption config contains no server private keys".into(),
            ));
        }

        let (padding_lens, padding_gaps) = parse_padding(&padding_str);
        let mut keys = Vec::new();
        let mut public_key_bytes = Vec::new();
        let mut hash32s = Vec::new();
        let mut relays_len = 0usize;

        use base64::Engine;
        for k_str in key_strs {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(k_str)
                .map_err(|e| {
                    FluxError::Config(format!("invalid base64url key in vless decryption: {e}"))
                })?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let secret = StaticSecret::from(arr);
                let pubkey = X25519PublicKey::from(&secret);
                public_key_bytes.push(pubkey.as_bytes().to_vec());
                hash32s.push(*blake3::hash(pubkey.as_bytes()).as_bytes());
                keys.push(ServerPrivateKey::X25519(arr));
                relays_len += 32 + 32;
            } else if bytes.len() == 64 {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                d.copy_from_slice(&bytes[..32]);
                z.copy_from_slice(&bytes[32..]);
                let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
                let ek_bytes = ek.into_bytes();
                public_key_bytes.push(ek_bytes.to_vec());
                hash32s.push(*blake3::hash(&ek_bytes).as_bytes());
                keys.push(ServerPrivateKey::MlKem768 {
                    encap_key_bytes: Box::new(ek_bytes),
                    decap_key: Box::new(dk),
                });
                relays_len += 1088 + 32;
            } else {
                return Err(FluxError::Config(format!(
                    "invalid server private key length {} in vless decryption (expected 32 or 64)",
                    bytes.len()
                )));
            }
        }
        relays_len -= 32;

        Ok(Self {
            xor_mode,
            seconds_from,
            seconds_to,
            padding_lens,
            padding_gaps,
            keys,
            public_key_bytes,
            hash32s,
            relays_len,
            sessions: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        })
    }
}

/// Performs client-side VLESS Encryption handshake.
pub async fn client_handshake<S>(
    mut stream: S,
    cfg: &VlessEncryptionClientConfig,
) -> FluxResult<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let use_aes = true;
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Compute relays and nfs_key
    let mut relays = Vec::new();
    let mut nfs_key = Vec::new();
    let mut last_ctr: Option<Aes256Ctr> = None;

    for (j, k) in cfg.keys.iter().enumerate() {
        let (relays_chunk, hop_nfs_key, index) = match k {
            ClientPeerKey::X25519(peer_pk_bytes) => {
                let eph_sec = StaticSecret::random_from_rng(OsRng);
                let eph_pub = X25519PublicKey::from(&eph_sec);
                let peer_pub = X25519PublicKey::from(*peer_pk_bytes);
                let shared = eph_sec.diffie_hellman(&peer_pub);
                (eph_pub.as_bytes().to_vec(), shared.as_bytes().to_vec(), 32)
            }
            ClientPeerKey::MlKem768(ek) => {
                let (shared_key, ciphertext) =
                    ek.try_encaps().map_err(|e| FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("ML-KEM-768 encapsulation failed: {e}"),
                    })?;
                (
                    ciphertext.into_bytes().to_vec(),
                    shared_key.into_bytes().to_vec(),
                    1088,
                )
            }
        };

        let mut chunk = relays_chunk;
        if cfg.xor_mode != XorMode::Native {
            let mut ctr = new_ctr(&cfg.raw_key_bytes[j], &iv);
            ctr.apply_keystream(&mut chunk[..index]);
        }
        if let Some(mut last) = last_ctr.take() {
            let n = chunk.len().min(32);
            last.apply_keystream(&mut chunk[..n]);
        }

        relays.extend_from_slice(&chunk);
        nfs_key = hop_nfs_key;

        if j < cfg.keys.len() - 1 {
            let mut next_last = new_ctr(&nfs_key, &iv);
            let mut next_hash = cfg.hash32s[j + 1];
            next_last.apply_keystream(&mut next_hash);
            relays.extend_from_slice(&next_hash);
            last_ctr = Some(next_last);
        }
    }

    let mut nfs_aead = VlessAead::new(&iv, &nfs_key, use_aes);

    // Ephemeral PFS key exchange (ML-KEM-768 keypair + X25519 keypair)
    let (pfs_ek, pfs_dk) = ml_kem_768::KG::try_keygen().map_err(|e| FluxError::Protocol {
        protocol: "vless-enc",
        message: format!("ML-KEM-768 keygen failed: {e}"),
    })?;
    let pfs_x25519_sec = StaticSecret::random_from_rng(OsRng);
    let pfs_x25519_pub = X25519PublicKey::from(&pfs_x25519_sec);

    let mut pfs_public_key = Vec::with_capacity(1184 + 32);
    pfs_public_key.extend_from_slice(&pfs_ek.into_bytes());
    pfs_public_key.extend_from_slice(pfs_x25519_pub.as_bytes());

    let pfs_ke_len = 1184 + 32 + 16;
    let enc_pfs_ke_len = nfs_aead.seal(&encode_length(pfs_ke_len), &[]);
    let enc_pfs_public_key = nfs_aead.seal(&pfs_public_key, &[]);

    // Client padding
    let pad_bytes = create_padding(&cfg.padding_lens, &cfg.padding_gaps);
    let pad_total_len = pad_bytes.len() + 16;
    let enc_pad_len = nfs_aead.seal(&encode_length(pad_total_len), &[]);
    let enc_pad = nfs_aead.seal(&pad_bytes, &[]);

    // Assemble and send initial client flight
    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&iv);
    client_hello.extend_from_slice(&relays);
    client_hello.extend_from_slice(&enc_pfs_ke_len);
    client_hello.extend_from_slice(&enc_pfs_public_key);
    client_hello.extend_from_slice(&enc_pad_len);
    client_hello.extend_from_slice(&enc_pad);

    tracing::debug!("VLESS-ENC: sent client hello (len={})", client_hello.len());
    stream
        .write_all(&client_hello)
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // Read server ServerHello
    // 1. Server PFS public key (1088 + 32 = 1120 bytes ciphertext + 16 bytes tag = 1136 bytes)
    let mut enc_server_pfs = vec![0u8; 1088 + 32 + 16];
    stream
        .read_exact(&mut enc_server_pfs)
        .await
        .map_err(FluxError::Io)?;

    let max_nonce = [255u8; 12];
    tracing::debug!(
        "VLESS-ENC: received server pfs (len={})",
        enc_server_pfs.len()
    );
    let server_pfs_public_key = nfs_aead
        .open_with_nonce(&max_nonce, &enc_server_pfs, &[])
        .map_err(|e| FluxError::Protocol {
            protocol: "vless-enc",
            message: format!(
                "failed to open server PFS public key (len={}): {e}",
                enc_server_pfs.len()
            ),
        })?;

    if server_pfs_public_key.len() != 1088 + 32 {
        return Err(FluxError::Protocol {
            protocol: "vless-enc",
            message: format!(
                "invalid server PFS public key length: {}",
                server_pfs_public_key.len()
            ),
        });
    }

    let mut server_mlkem_ct = [0u8; 1088];
    server_mlkem_ct.copy_from_slice(&server_pfs_public_key[..1088]);
    let mut server_x25519_pub_bytes = [0u8; 32];
    server_x25519_pub_bytes.copy_from_slice(&server_pfs_public_key[1088..]);

    let server_mlkem_ciphertext =
        ml_kem_768::CipherText::try_from_bytes(server_mlkem_ct).map_err(|e| {
            FluxError::Protocol {
                protocol: "vless-enc",
                message: format!("invalid server ML-KEM-768 ciphertext: {e}"),
            }
        })?;
    let mlkem_shared =
        pfs_dk
            .try_decaps(&server_mlkem_ciphertext)
            .map_err(|e| FluxError::Protocol {
                protocol: "vless-enc",
                message: format!("ML-KEM-768 decapsulation failed: {e}"),
            })?;
    let x25519_shared =
        pfs_x25519_sec.diffie_hellman(&X25519PublicKey::from(server_x25519_pub_bytes));

    let mut pfs_key = Vec::with_capacity(64);
    pfs_key.extend_from_slice(&mlkem_shared.into_bytes());
    pfs_key.extend_from_slice(x25519_shared.as_bytes());

    let mut united_key = Vec::with_capacity(96);
    united_key.extend_from_slice(&pfs_key);
    united_key.extend_from_slice(&nfs_key);

    let write_aead = VlessAead::new(&pfs_public_key, &united_key, use_aes);
    let mut read_aead = VlessAead::new(&server_pfs_public_key, &united_key, use_aes);

    // Read ticket (16 bytes payload + 16 bytes tag = 32 bytes)
    let mut enc_ticket = [0u8; 32];
    stream
        .read_exact(&mut enc_ticket)
        .await
        .map_err(FluxError::Io)?;
    let ticket = read_aead
        .open(&enc_ticket, &[])
        .map_err(|e| FluxError::Protocol {
            protocol: "vless-enc",
            message: format!("failed to open ticket: {e}"),
        })?;

    // Read server padding: length (2 bytes + 16 bytes tag = 18 bytes) then payload
    let mut enc_srv_pad_len = [0u8; 18];
    stream
        .read_exact(&mut enc_srv_pad_len)
        .await
        .map_err(FluxError::Io)?;
    let srv_pad_len_bytes =
        read_aead
            .open(&enc_srv_pad_len, &[])
            .map_err(|e| FluxError::Protocol {
                protocol: "vless-enc",
                message: format!("failed to open srv_pad_len: {e}"),
            })?;
    let srv_pad_len = decode_length(&srv_pad_len_bytes);
    let mut enc_srv_pad = vec![0u8; srv_pad_len];
    stream
        .read_exact(&mut enc_srv_pad)
        .await
        .map_err(FluxError::Io)?;
    let _srv_pad = read_aead
        .open(&enc_srv_pad, &[])
        .map_err(|e| FluxError::Protocol {
            protocol: "vless-enc",
            message: format!("failed to open srv_pad: {e}"),
        })?;

    let xor_pair = if cfg.xor_mode == XorMode::Random {
        let mut ticket_arr = [0u8; 16];
        ticket_arr.copy_from_slice(&ticket[..16]);
        let ctr_out = new_ctr(&united_key, &iv);
        let ctr_in = new_ctr(&united_key, &ticket_arr);
        Some((ctr_out, ctr_in))
    } else {
        None
    };

    Ok(Box::new(VlessEncryptionStream {
        inner: Box::new(stream),
        write_aead,
        read_aead,
        united_key,
        use_aes,
        xor_pair,
        read_buf: Vec::new(),
        read_pos: 0,
    }))
}

/// Performs server-side VLESS Decryption handshake.
pub async fn server_handshake<S>(
    mut stream: S,
    cfg: &VlessDecryptionServerConfig,
) -> FluxResult<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let use_aes = true;

    // Read iv (16 bytes) and relays
    let mut iv = [0u8; 16];
    stream.read_exact(&mut iv).await.map_err(FluxError::Io)?;

    let mut relays = vec![0u8; cfg.relays_len];
    stream
        .read_exact(&mut relays)
        .await
        .map_err(FluxError::Io)?;

    let mut nfs_key = Vec::new();
    let mut last_ctr: Option<Aes256Ctr> = None;
    let mut relays_slice = &relays[..];

    for (j, k) in cfg.keys.iter().enumerate() {
        let index = match k {
            ServerPrivateKey::X25519(_) => 32,
            ServerPrivateKey::MlKem768 { .. } => 1088,
        };

        if relays_slice.len() < index {
            return Err(FluxError::Protocol {
                protocol: "vless-enc",
                message: "truncated relays in handshake".into(),
            });
        }

        let mut chunk = relays_slice[..index].to_vec();
        if let Some(mut last) = last_ctr.take() {
            let n = chunk.len().min(32);
            last.apply_keystream(&mut chunk[..n]);
        }
        if cfg.xor_mode != XorMode::Native {
            let mut ctr = new_ctr(&cfg.public_key_bytes[j], &iv);
            ctr.apply_keystream(&mut chunk[..index]);
        }

        nfs_key = match k {
            ServerPrivateKey::X25519(priv_bytes) => {
                let sec = StaticSecret::from(*priv_bytes);
                let mut peer_pub_bytes = [0u8; 32];
                peer_pub_bytes.copy_from_slice(&chunk[..32]);
                let peer_pub = X25519PublicKey::from(peer_pub_bytes);
                let shared = sec.diffie_hellman(&peer_pub);
                shared.as_bytes().to_vec()
            }
            ServerPrivateKey::MlKem768 { decap_key, .. } => {
                let mut ct = [0u8; 1088];
                ct.copy_from_slice(&chunk[..1088]);
                let ct_obj = ml_kem_768::CipherText::try_from_bytes(ct).map_err(|e| {
                    FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("invalid client ML-KEM-768 ciphertext: {e}"),
                    }
                })?;
                let shared = decap_key
                    .try_decaps(&ct_obj)
                    .map_err(|e| FluxError::Protocol {
                        protocol: "vless-enc",
                        message: format!("ML-KEM-768 decapsulation failed: {e}"),
                    })?;
                shared.into_bytes().to_vec()
            }
        };

        if j == cfg.keys.len() - 1 {
            break;
        }

        relays_slice = &relays_slice[index..];
        let mut next_ctr = new_ctr(&nfs_key, &iv);
        if relays_slice.len() < 32 {
            return Err(FluxError::Protocol {
                protocol: "vless-enc",
                message: "truncated relay chaining hash".into(),
            });
        }
        let mut hash_chunk = relays_slice[..32].to_vec();
        next_ctr.apply_keystream(&mut hash_chunk);
        if hash_chunk != cfg.hash32s[j + 1] {
            return Err(FluxError::Protocol {
                protocol: "vless-enc",
                message: "unexpected hash32 in relay chaining".into(),
            });
        }
        relays_slice = &relays_slice[32..];
        last_ctr = Some(next_ctr);
    }

    let mut nfs_aead = VlessAead::new(&iv, &nfs_key, use_aes);

    // Read encrypted length prefix (18 bytes)
    let mut enc_len = [0u8; 18];
    stream
        .read_exact(&mut enc_len)
        .await
        .map_err(FluxError::Io)?;
    let dec_len_bytes = nfs_aead.open(&enc_len, &[])?;
    let length = decode_length(&dec_len_bytes);

    if length < 1184 + 32 + 16 {
        return Err(FluxError::Protocol {
            protocol: "vless-enc",
            message: format!("client PFS key length {length} is too short"),
        });
    }

    let mut enc_client_pfs = vec![0u8; length];
    stream
        .read_exact(&mut enc_client_pfs)
        .await
        .map_err(FluxError::Io)?;
    let client_pfs_public_key = nfs_aead.open(&enc_client_pfs, &[])?;

    let mut client_mlkem_ek_bytes = [0u8; 1184];
    client_mlkem_ek_bytes.copy_from_slice(&client_pfs_public_key[..1184]);
    let mut client_x25519_pub_bytes = [0u8; 32];
    client_x25519_pub_bytes.copy_from_slice(&client_pfs_public_key[1184..1184 + 32]);

    let client_mlkem_ek =
        ml_kem_768::EncapsKey::try_from_bytes(client_mlkem_ek_bytes).map_err(|e| {
            FluxError::Protocol {
                protocol: "vless-enc",
                message: format!("invalid client ML-KEM-768 encapsulation key: {e}"),
            }
        })?;
    let (mlkem_shared, server_mlkem_ciphertext) =
        client_mlkem_ek
            .try_encaps()
            .map_err(|e| FluxError::Protocol {
                protocol: "vless-enc",
                message: format!("server ML-KEM-768 encapsulation failed: {e}"),
            })?;

    let server_x25519_sec = StaticSecret::random_from_rng(OsRng);
    let server_x25519_pub = X25519PublicKey::from(&server_x25519_sec);
    let x25519_shared =
        server_x25519_sec.diffie_hellman(&X25519PublicKey::from(client_x25519_pub_bytes));

    let mut pfs_key = Vec::with_capacity(64);
    pfs_key.extend_from_slice(&mlkem_shared.into_bytes());
    pfs_key.extend_from_slice(x25519_shared.as_bytes());

    let mut pfs_public_key = Vec::with_capacity(1088 + 32);
    pfs_public_key.extend_from_slice(&server_mlkem_ciphertext.into_bytes());
    pfs_public_key.extend_from_slice(server_x25519_pub.as_bytes());

    let mut united_key = Vec::with_capacity(96);
    united_key.extend_from_slice(&pfs_key);
    united_key.extend_from_slice(&nfs_key);

    let mut write_aead = VlessAead::new(&pfs_public_key, &united_key, use_aes);
    let read_aead = VlessAead::new(&client_pfs_public_key, &united_key, use_aes);

    let mut ticket = [0u8; 16];
    OsRng.fill_bytes(&mut ticket);

    // Save session ticket for resumption if enabled
    let seconds = if cfg.seconds_to > cfg.seconds_from {
        cfg.seconds_from + (OsRng.next_u32() % (cfg.seconds_to - cfg.seconds_from + 1))
    } else {
        cfg.seconds_from
    };
    if seconds > 0 {
        let expiry = Instant::now() + Duration::from_secs(seconds as u64);
        cfg.sessions
            .write()
            .insert(ticket, (pfs_key.clone(), expiry));
    }

    // Seal and send ServerHello
    // 1. PFS public key (1120 bytes) with MaxNonce
    let max_nonce = [255u8; 12];
    let enc_server_pfs = nfs_aead.seal_with_nonce(&max_nonce, &pfs_public_key, &[]);

    // 2. Ticket (16 bytes)
    let enc_ticket = write_aead.seal(&ticket, &[]);

    // 3. Server padding
    let srv_pad = create_padding(&cfg.padding_lens, &cfg.padding_gaps);
    let enc_srv_pad_len = write_aead.seal(&encode_length(srv_pad.len() + 16), &[]);
    let enc_srv_pad = write_aead.seal(&srv_pad, &[]);

    let mut server_hello = Vec::new();
    server_hello.extend_from_slice(&enc_server_pfs);
    server_hello.extend_from_slice(&enc_ticket);
    server_hello.extend_from_slice(&enc_srv_pad_len);
    server_hello.extend_from_slice(&enc_srv_pad);

    stream
        .write_all(&server_hello)
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // Read client finish padding
    let mut enc_cli_pad_len = [0u8; 18];
    stream
        .read_exact(&mut enc_cli_pad_len)
        .await
        .map_err(FluxError::Io)?;
    let cli_pad_len_bytes = nfs_aead.open(&enc_cli_pad_len, &[])?;
    let cli_pad_len = decode_length(&cli_pad_len_bytes);
    let mut enc_cli_pad = vec![0u8; cli_pad_len];
    stream
        .read_exact(&mut enc_cli_pad)
        .await
        .map_err(FluxError::Io)?;
    let _cli_pad = nfs_aead.open(&enc_cli_pad, &[])?;

    let xor_pair = if cfg.xor_mode == XorMode::Random {
        let ctr_out = new_ctr(&united_key, &ticket);
        let ctr_in = new_ctr(&united_key, &iv);
        Some((ctr_out, ctr_in))
    } else {
        None
    };

    Ok(Box::new(VlessEncryptionStream {
        inner: Box::new(stream),
        write_aead,
        read_aead,
        united_key,
        use_aes,
        xor_pair,
        read_buf: Vec::new(),
        read_pos: 0,
    }))
}

/// Duplex stream wrapper for TLS-like record framed VLESS Encryption.
pub struct VlessEncryptionStream {
    inner: BoxedStream,
    write_aead: VlessAead,
    read_aead: VlessAead,
    united_key: Vec<u8>,
    use_aes: bool,
    xor_pair: Option<(Aes256Ctr, Aes256Ctr)>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl AsyncRead for VlessEncryptionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.read_pos < this.read_buf.len() {
            let available = this.read_buf.len() - this.read_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
            this.read_pos += to_copy;
            if this.read_pos == this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read next record header: 5 bytes [23, 3, 3, len_hi, len_lo]
        let mut hdr = [0u8; 5];
        let mut hdr_read = 0;
        while hdr_read < 5 {
            let mut read_slice = [0u8; 5];
            let mut sub_buf = ReadBuf::new(&mut read_slice[..5 - hdr_read]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut sub_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = sub_buf.filled().len();
                    if filled == 0 {
                        if hdr_read == 0 {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading record header",
                            )));
                        }
                    }
                    hdr[hdr_read..hdr_read + filled].copy_from_slice(sub_buf.filled());
                    hdr_read += filled;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if let Some((_, ref mut in_ctr)) = this.xor_pair {
            in_ctr.apply_keystream(&mut hdr);
        }

        let rec_len = match decode_record_header(&hdr) {
            Ok(l) => l,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
        };

        // Read payload of rec_len bytes
        let mut raw_data = vec![0u8; rec_len];
        let mut data_read = 0;
        while data_read < rec_len {
            let mut sub_buf = ReadBuf::new(&mut raw_data[data_read..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut sub_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = sub_buf.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF reading record payload",
                        )));
                    }
                    data_read += filled;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if let Some((_, ref mut in_ctr)) = this.xor_pair {
            in_ctr.apply_keystream(&mut raw_data);
        }

        let is_max = this.read_aead.nonce.is_max();
        let decrypted = match this.read_aead.open(&raw_data, &hdr) {
            Ok(p) => p,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
        };
        if is_max {
            let mut rekey_ctx = Vec::with_capacity(5 + raw_data.len());
            rekey_ctx.extend_from_slice(&hdr);
            rekey_ctx.extend_from_slice(&raw_data);
            this.read_aead = VlessAead::new(&rekey_ctx, &this.united_key, this.use_aes);
        }

        let to_copy = decrypted.len().min(buf.remaining());
        buf.put_slice(&decrypted[..to_copy]);
        if to_copy < decrypted.len() {
            this.read_buf = decrypted;
            this.read_pos = to_copy;
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VlessEncryptionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        // Chunk into at most 8192 bytes payload
        let chunk_size = buf.len().min(8192);
        let chunk = &buf[..chunk_size];
        let hdr = encode_record_header(chunk_size + 16);

        let is_max = this.write_aead.nonce.is_max();
        let ciphertext = this.write_aead.seal(chunk, &hdr);

        let mut out = Vec::with_capacity(5 + ciphertext.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&ciphertext);

        if is_max {
            this.write_aead = VlessAead::new(&out, &this.united_key, this.use_aes);
        }

        if let Some((ref mut out_ctr, _)) = this.xor_pair {
            out_ctr.apply_keystream(&mut out);
        }

        match Pin::new(&mut this.inner).poll_write(cx, &out) {
            Poll::Ready(Ok(_written)) => Poll::Ready(Ok(chunk_size)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_config_parsing_x25519() {
        let sec = StaticSecret::random_from_rng(OsRng);
        let pubkey = X25519PublicKey::from(&sec);
        let sec_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sec.to_bytes());
        let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.as_bytes());

        let dec_str = format!("mlkem768x25519plus.native.600s.{sec_b64}");
        let enc_str = format!("mlkem768x25519plus.native.0rtt.{pub_b64}");

        let server_cfg = VlessDecryptionServerConfig::parse(&dec_str).expect("parse server cfg");
        assert_eq!(server_cfg.xor_mode, XorMode::Native);
        assert_eq!(server_cfg.seconds_from, 600);
        assert_eq!(server_cfg.keys.len(), 1);

        let client_cfg = VlessEncryptionClientConfig::parse(&enc_str).expect("parse client cfg");
        assert_eq!(client_cfg.xor_mode, XorMode::Native);
        assert_eq!(client_cfg.keys.len(), 1);
    }

    #[test]
    fn test_config_parsing_mlkem768() {
        let seed = [0x55u8; 64];
        let (ek, _) = ml_kem_768::KG::keygen_from_seed(
            seed[..32].try_into().unwrap(),
            seed[32..].try_into().unwrap(),
        );
        let sec_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
        let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ek.into_bytes());

        let dec_str = format!("mlkem768x25519plus.random.300s-600s.{sec_b64}");
        let enc_str = format!("mlkem768x25519plus.random.1rtt.{pub_b64}");

        let server_cfg = VlessDecryptionServerConfig::parse(&dec_str).expect("parse server cfg");
        assert_eq!(server_cfg.xor_mode, XorMode::Random);
        assert_eq!(server_cfg.seconds_from, 300);
        assert_eq!(server_cfg.seconds_to, 600);

        let client_cfg = VlessEncryptionClientConfig::parse(&enc_str).expect("parse client cfg");
        assert_eq!(client_cfg.xor_mode, XorMode::Random);
        assert!(!client_cfg.zero_rtt);
    }

    #[tokio::test]
    async fn test_handshake_roundtrip_x25519_native() {
        run_handshake_roundtrip(XorMode::Native, false).await;
    }

    #[tokio::test]
    async fn test_handshake_roundtrip_x25519_xorpub() {
        run_handshake_roundtrip(XorMode::XorPub, false).await;
    }

    #[tokio::test]
    async fn test_handshake_roundtrip_x25519_random() {
        run_handshake_roundtrip(XorMode::Random, false).await;
    }

    #[tokio::test]
    async fn test_handshake_roundtrip_mlkem768_native() {
        run_handshake_roundtrip(XorMode::Native, true).await;
    }

    #[tokio::test]
    async fn test_handshake_roundtrip_mlkem768_random() {
        run_handshake_roundtrip(XorMode::Random, true).await;
    }

    async fn run_handshake_roundtrip(mode: XorMode, is_mlkem: bool) {
        let (dec_str, enc_str) = if is_mlkem {
            let mut seed = [0u8; 64];
            OsRng.fill_bytes(&mut seed);
            let (ek, _) = ml_kem_768::KG::keygen_from_seed(
                seed[..32].try_into().unwrap(),
                seed[32..].try_into().unwrap(),
            );
            let sec_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
            let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ek.into_bytes());
            let mode_str = match mode {
                XorMode::Native => "native",
                XorMode::XorPub => "xorpub",
                XorMode::Random => "random",
            };
            (
                format!("mlkem768x25519plus.{mode_str}.600s.{sec_b64}"),
                format!("mlkem768x25519plus.{mode_str}.0rtt.{pub_b64}"),
            )
        } else {
            let sec = StaticSecret::random_from_rng(OsRng);
            let pubkey = X25519PublicKey::from(&sec);
            let sec_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sec.to_bytes());
            let pub_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.as_bytes());
            let mode_str = match mode {
                XorMode::Native => "native",
                XorMode::XorPub => "xorpub",
                XorMode::Random => "random",
            };
            (
                format!("mlkem768x25519plus.{mode_str}.600s.{sec_b64}"),
                format!("mlkem768x25519plus.{mode_str}.0rtt.{pub_b64}"),
            )
        };

        let server_cfg = Arc::new(VlessDecryptionServerConfig::parse(&dec_str).unwrap());
        let client_cfg = Arc::new(VlessEncryptionClientConfig::parse(&enc_str).unwrap());

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let scfg = server_cfg.clone();
        let srv_handle = tokio::spawn(async move { server_handshake(server_io, &scfg).await });

        let ccfg = client_cfg.clone();
        let cli_handle = tokio::spawn(async move { client_handshake(client_io, &ccfg).await });

        let (srv_res, cli_res) = tokio::join!(srv_handle, cli_handle);
        let mut srv_stream = srv_res.expect("join srv").expect("server handshake");
        let mut cli_stream = cli_res.expect("join cli").expect("client handshake");

        // Bidirectional bulk transfer test: ping-pong
        let ping_msg = b"hello post-quantum vless encryption";
        cli_stream.write_all(ping_msg).await.expect("cli write");
        cli_stream.flush().await.expect("cli flush");

        let mut buf = vec![0u8; ping_msg.len()];
        srv_stream.read_exact(&mut buf).await.expect("srv read");
        assert_eq!(&buf, ping_msg);

        let pong_msg = b"pong post-quantum vless reply payload";
        srv_stream.write_all(pong_msg).await.expect("srv write");
        srv_stream.flush().await.expect("srv flush");

        let mut buf2 = vec![0u8; pong_msg.len()];
        cli_stream.read_exact(&mut buf2).await.expect("cli read");
        assert_eq!(&buf2, pong_msg);
    }
}
