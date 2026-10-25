use crate::socks5::Socks5Handshake;
use flux_types::{FluxError, FluxResult, TargetAddress};
use lru::LruCache;
use parking_lot::Mutex;
use rand::RngCore;
use ring::aead::{
    AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
};
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The BLAKE3 context string that separates session subkeys from anything else.
pub const SS_2022_KDF_CONTEXT: &str = "shadowsocks 2022 session subkey";
/// How far a timestamp may drift before a salt is rejected as a replay.
pub const SS_2022_REPLAY_WINDOW_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// A Shadowsocks 2022 method, which fixes both key and salt length.
pub enum Ss2022CipherMethod {
    /// BLAKE3 key derivation with AES-128-GCM.
    Blake3Aes128Gcm,
    /// BLAKE3 key derivation with AES-256-GCM.
    Blake3Aes256Gcm,
    /// BLAKE3 key derivation with ChaCha20-Poly1305.
    Blake3ChaCha20Poly1305,
}

impl Ss2022CipherMethod {
    /// `parse_str`.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Some(Self::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::Blake3ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Key length for this method.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Blake3Aes128Gcm => 16,
            Self::Blake3Aes256Gcm => 32,
            Self::Blake3ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length for this method.
    pub fn salt_len(&self) -> usize {
        match self {
            Self::Blake3Aes128Gcm => 16,
            Self::Blake3Aes256Gcm => 32,
            Self::Blake3ChaCha20Poly1305 => 32,
        }
    }
}

/// Remembers salts that have been seen, to reject replays.
pub struct ReplayFilter {
    cache: Mutex<LruCache<Vec<u8>, u64>>,
}

impl ReplayFilter {
    /// Builds the value with the protocol defaults.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Records a salt; false means it was already seen or too old.
    pub fn check_and_insert(&self, salt: &[u8], timestamp: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now.abs_diff(timestamp) > SS_2022_REPLAY_WINDOW_SECS {
            return false;
        }

        let mut guard = self.cache.lock();
        if guard.contains(salt) {
            return false;
        }
        guard.put(salt.to_vec(), timestamp);
        true
    }

    /// Records a salt with no timestamp check.
    pub fn check_and_insert_salt(&self, salt: &[u8]) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut guard = self.cache.lock();
        if guard.contains(salt) {
            return false;
        }
        guard.put(salt.to_vec(), now);
        true
    }
}

/// `derive_2022_subkey`.
pub fn derive_2022_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);

    let mut hasher = blake3::Hasher::new_derive_key(SS_2022_KDF_CONTEXT);
    hasher.update(&material);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; key_len];
    reader.fill(&mut out);
    out
}

/// Tag length of every AEAD used by this module (GCM and Poly1305 are both
/// 128-bit).
const SS2022_TAG_LEN: usize = 16;

/// One cached AEAD session key.
///
/// `ring` expands the key schedule exactly once, in `UnboundKey::new`, and the
/// returned [`LessSafeKey`] owns it, so the algorithm dispatch happens at
/// construction time and every packet reuses the same schedule. The schedule is
/// not free relative to a 16 KiB record, and SS-2022 derives a fresh subkey per
/// session, so construction is hoisted to session setup (and, for UDP, cached
/// per peer session).
///
/// The previous `aes-gcm` types were cached the same way, but they drive `ctr`
/// one block at a time and never pipeline AES-NI; `ring`'s fused AES-GCM is
/// ~6x faster on this machine, which is what this substitution buys.
struct Ss2022Aead {
    key: LessSafeKey,
}

impl Ss2022Aead {
    fn new(method: Ss2022CipherMethod, subkey: &[u8]) -> Self {
        let alg = match method {
            Ss2022CipherMethod::Blake3Aes128Gcm => &AES_128_GCM,
            Ss2022CipherMethod::Blake3Aes256Gcm => &AES_256_GCM,
            Ss2022CipherMethod::Blake3ChaCha20Poly1305 => &CHACHA20_POLY1305,
        };
        let key = UnboundKey::new(alg, subkey).unwrap_or_else(|_| {
            panic!(
                "invalid shadowsocks-2022 subkey: {} bytes, method {:?} wants {}",
                subkey.len(),
                method,
                method.key_len()
            )
        });
        Self {
            key: LessSafeKey::new(key),
        }
    }

    /// Seals `buf[start..]` in place and appends the 16-byte tag to `buf`.
    ///
    /// `start` lets the caller keep an already-serialised prefix — a length
    /// prefix, or the plaintext salt that opens the server's first flight — in
    /// the same buffer, so the write path needs neither a second buffer nor a
    /// copy of the payload.
    fn seal_tail(&self, nonce: [u8; 12], buf: &mut Vec<u8>, start: usize) -> FluxResult<()> {
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut buf[start..],
            )
            .map_err(|_| FluxError::Crypto("shadowsocks-2022 encrypt failed".into()))?;
        buf.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Authenticates and decrypts `buf` in place, returning the plaintext.
    fn open_in_place<'a>(&self, nonce: [u8; 12], buf: &'a mut [u8]) -> FluxResult<&'a mut [u8]> {
        self.key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), buf)
            .map_err(|_| FluxError::Crypto("shadowsocks-2022 decrypt failed: bad tag".into()))
    }

    /// Decrypts the ciphertext in `buf[start..]` in place and truncates `buf` to
    /// the plaintext length.
    fn open_tail(&self, nonce: [u8; 12], buf: &mut Vec<u8>, start: usize) -> FluxResult<()> {
        let plain_len = self.open_in_place(nonce, &mut buf[start..])?.len();
        buf.truncate(start + plain_len);
        Ok(())
    }

    /// Seals into a freshly allocated buffer. Used on the handshake paths, which
    /// run once per connection and read better than two in-place calls.
    fn encrypt(&self, nonce: [u8; 12], plain: &[u8]) -> FluxResult<Vec<u8>> {
        let mut out = Vec::with_capacity(plain.len() + SS2022_TAG_LEN);
        out.extend_from_slice(plain);
        self.seal_tail(nonce, &mut out, 0)?;
        Ok(out)
    }

    /// Opens into a freshly allocated buffer (handshake paths only).
    fn decrypt(&self, nonce: [u8; 12], cipher: &[u8]) -> FluxResult<Vec<u8>> {
        let mut out = Vec::with_capacity(cipher.len());
        out.extend_from_slice(cipher);
        self.open_tail(nonce, &mut out, 0)?;
        Ok(out)
    }
}

fn increase_nonce(nonce: &mut [u8; 12]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// A stream carrying Shadowsocks 2022 chunks.
pub struct Ss2022Stream<S> {
    inner: S,
    method: Ss2022CipherMethod,
    psk: Vec<u8>,
    client_salt: Vec<u8>,
    enc: Ss2022Aead,
    dec: Option<Ss2022Aead>,
    enc_nonce: [u8; 12],
    dec_nonce: [u8; 12],
    response_read: bool,
    is_server: bool,
    server_response_written: bool,
    resp_salt_buf: Vec<u8>,
    resp_salt_pos: usize,
    resp_hdr_buf: Vec<u8>,
    resp_hdr_pos: usize,
    resp_payload_len: usize,
    resp_payload_buf: Vec<u8>,
    resp_payload_pos: usize,

    write_buf: Vec<u8>,
    write_pos: usize,
    writing_plain_len: usize,

    // Reader state machine
    /// Persistent receive buffer: it holds the chunk length and whatever part of
    /// the payload — and of the next chunk — arrived in the same socket read.
    chunk_buf: Vec<u8>,
    /// Bytes valid in `chunk_buf`.
    chunk_filled: usize,
    /// Bytes of `chunk_buf` already consumed.
    chunk_pos: usize,
    /// Decrypted plaintext bytes sitting at `plain_pos`, ready to serve.
    plain_ready: usize,
    /// Where that plaintext starts.
    plain_pos: usize,
    payload_len: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,

    read_buf: Vec<u8>,
    read_pos: usize,
}

/// Ends a read: if bytes were already handed to the caller, that is a successful
/// read even when the socket has nothing more right now.
fn finish_read(put: usize) -> Poll<io::Result<()>> {
    if put > 0 {
        Poll::Ready(Ok(()))
    } else {
        Poll::Pending
    }
}

impl<S> Ss2022Stream<S> {
    /// Drops consumed bytes from the front of the receive buffer.
    fn compact_chunk(&mut self) {
        if self.chunk_pos == 0 {
            return;
        }
        let remaining = self.chunk_filled - self.chunk_pos;
        if remaining > 0 {
            self.chunk_buf
                .copy_within(self.chunk_pos..self.chunk_filled, 0);
        }
        self.chunk_filled = remaining;
        self.chunk_pos = 0;
    }

    /// Client half of the handshake.
    pub fn new_client(
        inner: S,
        method: Ss2022CipherMethod,
        psk: &[u8],
        client_salt: Vec<u8>,
        enc_subkey: Vec<u8>,
        enc_nonce: [u8; 12],
    ) -> Self {
        let salt_len = method.salt_len();
        let fixed_resp_len = 1 + 8 + salt_len + 2 + 16;
        Self {
            inner,
            method,
            psk: psk.to_vec(),
            client_salt,
            enc: Ss2022Aead::new(method, &enc_subkey),
            dec: None,
            enc_nonce,
            dec_nonce: [0u8; 12],
            response_read: false,
            is_server: false,
            server_response_written: true,
            resp_salt_buf: vec![0u8; salt_len],
            resp_salt_pos: 0,
            resp_hdr_buf: vec![0u8; fixed_resp_len],
            resp_hdr_pos: 0,
            resp_payload_len: 0,
            resp_payload_buf: Vec::new(),
            resp_payload_pos: 0,
            write_buf: Vec::with_capacity(16384 + 32),
            write_pos: 0,
            writing_plain_len: 0,
            chunk_buf: vec![0u8; 64 * 1024],
            chunk_filled: 0,
            chunk_pos: 0,
            plain_ready: 0,
            plain_pos: 0,
            payload_len: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Server half of the handshake.
    pub fn new_server(
        inner: S,
        method: Ss2022CipherMethod,
        psk: &[u8],
        client_salt: Vec<u8>,
        dec_subkey: &[u8],
        dec_nonce: [u8; 12],
        initial_chunk: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            method,
            psk: psk.to_vec(),
            client_salt,
            enc: Ss2022Aead::new(method, dec_subkey),
            dec: Some(Ss2022Aead::new(method, dec_subkey)),
            enc_nonce: [0u8; 12],
            dec_nonce,
            response_read: true,
            is_server: true,
            server_response_written: false,
            resp_salt_buf: Vec::new(),
            resp_salt_pos: 0,
            resp_hdr_buf: Vec::new(),
            resp_hdr_pos: 0,
            resp_payload_len: 0,
            resp_payload_buf: Vec::new(),
            resp_payload_pos: 0,
            write_buf: Vec::with_capacity(16384 + 32),
            write_pos: 0,
            writing_plain_len: 0,
            chunk_buf: vec![0u8; 64 * 1024],
            chunk_filled: 0,
            chunk_pos: 0,
            plain_ready: 0,
            plain_pos: 0,
            payload_len: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: initial_chunk,
            read_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Ss2022Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Step 0: Lazy response reading for client
        if !this.response_read {
            let salt_len = this.method.salt_len();
            // A. Read server response salt
            while this.resp_salt_pos < salt_len {
                let needed = salt_len - this.resp_salt_pos;
                let mut tmp = [0u8; 32];
                let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading shadowsocks-2022 server response salt",
                            )));
                        }
                        let pos = this.resp_salt_pos;
                        this.resp_salt_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.resp_salt_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.dec.is_none() {
                let dec_subkey =
                    derive_2022_subkey(&this.psk, &this.resp_salt_buf, this.method.key_len());
                this.dec = Some(Ss2022Aead::new(this.method, &dec_subkey));
            }

            // B. Read server fixed header chunk
            let fixed_resp_len = 1 + 8 + salt_len + 2 + 16;
            while this.resp_hdr_pos < fixed_resp_len {
                let needed = fixed_resp_len - this.resp_hdr_pos;
                let mut tmp = [0u8; 128];
                let to_read = needed.min(tmp.len());
                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading shadowsocks-2022 server response header",
                            )));
                        }
                        let pos = this.resp_hdr_pos;
                        this.resp_hdr_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.resp_hdr_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.resp_payload_len == 0 && this.resp_payload_buf.is_empty() {
                let dec = match this.dec.as_ref() {
                    Some(d) => d,
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "shadowsocks-2022 decryptor not initialized",
                        )));
                    }
                };
                let dec_nonce = this.dec_nonce;
                increase_nonce(&mut this.dec_nonce);
                // Decrypt the header in place: `resp_hdr_buf` is reusable
                // scratch space, so this path allocates nothing.
                if let Err(e) = dec.open_tail(dec_nonce, &mut this.resp_hdr_buf, 0) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
                let resp_fixed = &this.resp_hdr_buf;

                if resp_fixed[0] != 0x01 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected server header type: {}", resp_fixed[0]),
                    )));
                }

                if &resp_fixed[9..9 + salt_len] != this.client_salt.as_slice() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "mismatched client salt in shadowsocks-2022 response",
                    )));
                }

                let p_len =
                    u16::from_be_bytes([resp_fixed[9 + salt_len], resp_fixed[10 + salt_len]])
                        as usize;
                if p_len == 0 {
                    this.response_read = true;
                } else {
                    this.resp_payload_len = p_len;
                    this.resp_payload_buf.resize(p_len + 16, 0);
                    this.resp_payload_pos = 0;
                }
            }

            if !this.response_read {
                let target_len = this.resp_payload_len + 16;
                while this.resp_payload_pos < target_len {
                    let needed = target_len - this.resp_payload_pos;
                    let mut tmp = [0u8; 8192];
                    let to_read = needed.min(tmp.len());
                    let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF reading shadowsocks-2022 initial payload chunk",
                                )));
                            }
                            let pos = this.resp_payload_pos;
                            this.resp_payload_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                            this.resp_payload_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let dec = match this.dec.as_ref() {
                    Some(d) => d,
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "shadowsocks-2022 decryptor not initialized",
                        )));
                    }
                };
                let dec_nonce = this.dec_nonce;
                increase_nonce(&mut this.dec_nonce);
                if let Err(e) = dec.open_tail(dec_nonce, &mut this.resp_payload_buf, 0) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
                // Hand the plaintext to the reader without copying it: the two
                // buffers simply swap roles.
                std::mem::swap(&mut this.read_buf, &mut this.resp_payload_buf);
                this.read_pos = 0;
                this.response_read = true;
            }
        }

        // Bytes handed to the caller in *this* poll call. A chunk is 16 KiB and the
        // relay reads with a 64 KiB buffer, so returning after a single chunk made
        // the relay do four read/write cycles per buffer. Filling what the caller
        // asked for is the difference between 4 round trips and 1.
        let mut put = 0usize;

        loop {
            // 1. Serve plaintext already decrypted in place in the receive buffer.
            if this.plain_ready > 0 {
                let n = this.plain_ready.min(buf.remaining());
                let from = this.plain_pos;
                buf.put_slice(&this.chunk_buf[from..from + n]);
                this.plain_pos += n;
                this.plain_ready -= n;
                put += n;
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            // 1b. Drain the handshake-response plaintext (server side).
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

            // 2. Read 18-byte encrypted chunk length (2 bytes len + 16 bytes tag)
            if this.payload_len == 0 {
                while this.chunk_filled - this.chunk_pos < 18 {
                    this.compact_chunk();
                    let filled = this.chunk_filled;
                    let mut tmp_buf = ReadBuf::new(&mut this.chunk_buf[filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                if this.chunk_filled == this.chunk_pos {
                                    return Poll::Ready(Ok(())); // Clean EOF
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF reading 2022 chunk len",
                                )));
                            }
                            this.chunk_filled += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return finish_read(put),
                    }
                }

                let dec = match this.dec.as_ref() {
                    Some(d) => d,
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "shadowsocks-2022 decryptor not initialized",
                        )));
                    }
                };
                let len_nonce = this.dec_nonce;
                increase_nonce(&mut this.dec_nonce);
                let at = this.chunk_pos;
                let plain_len = match dec.open_in_place(len_nonce, &mut this.chunk_buf[at..at + 18])
                {
                    Ok(b) => u16::from_be_bytes([b[0], b[1]]) as usize,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                };
                this.payload_len = plain_len;
                let total_payload_enc = this.payload_len + 16;
                // `resize` zeroes the *whole* new length even when the buffer is
                // already large enough, so this wrote 16 KiB of zeros per 16 KiB
                // chunk. Only grow.
                if this.payload_buf.len() < total_payload_enc {
                    this.payload_buf.resize(total_payload_enc, 0);
                }
                this.payload_pos = 0;
                this.chunk_pos += 18;
            }

            // 3. Buffer the whole encrypted chunk, then decrypt it **in place** in
            //    the receive buffer and serve it from there.
            //
            // Copying the ciphertext into `payload_buf` first cost a full 16 KiB
            // `memcpy` per chunk: callgrind put 34 % of this path's instructions in
            // `__memcpy_avx`, with exactly one call per chunk (2 052 calls for 32 MiB).
            // Decrypting where the bytes already are removes that copy entirely.
            let total_payload_enc = this.payload_len + 16;
            // The length prefix is 16 bits, so a peer may legitimately send a 65 535-byte
            // chunk — larger than the 64 KiB default buffer. Without this the read loop
            // would ask for zero bytes forever and the connection would hang. Grow to fit
            // (compacting first so the growth is only as large as it must be).
            this.compact_chunk();
            if this.chunk_buf.len() < this.chunk_pos + total_payload_enc {
                this.chunk_buf.resize(this.chunk_pos + total_payload_enc, 0);
            }
            while this.chunk_filled - this.chunk_pos < total_payload_enc {
                this.compact_chunk();
                if this.chunk_buf.len() < this.chunk_pos + total_payload_enc {
                    this.chunk_buf.resize(this.chunk_pos + total_payload_enc, 0);
                }
                let filled = this.chunk_filled;
                let mut tmp_buf = ReadBuf::new(&mut this.chunk_buf[filled..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading 2022 payload chunk",
                            )));
                        }
                        this.chunk_filled += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return finish_read(put),
                }
            }

            let dec = match this.dec.as_ref() {
                Some(d) => d,
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "shadowsocks-2022 decryptor not initialized",
                    )));
                }
            };
            let payload_nonce = this.dec_nonce;
            increase_nonce(&mut this.dec_nonce);
            let at = this.chunk_pos;
            let stop = at + total_payload_enc;
            // `open_in_place` decrypts the ciphertext and drops the tag, returning the
            // plaintext slice in place — no copy, no second buffer.
            if let Err(e) = dec.open_in_place(payload_nonce, &mut this.chunk_buf[at..stop]) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
            // The plaintext now sits at `at` and is served straight out of it; the
            // read cursor moves past the record *including* its 16-byte tag.
            this.plain_pos = at;
            this.plain_ready = this.payload_len;
            this.chunk_pos = at + total_payload_enc;
            this.payload_len = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
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

        if this.is_server && !this.server_response_written {
            let salt_len = this.method.salt_len();
            // Build the whole flight in the (reused) write buffer:
            // salt ‖ sealed fixed header ‖ sealed first payload chunk.
            this.write_buf.clear();
            let salt_start = this.write_buf.len();
            this.write_buf.resize(salt_start + salt_len, 0u8);
            rand::rngs::OsRng.fill_bytes(&mut this.write_buf[salt_start..]);

            let enc_subkey = derive_2022_subkey(
                &this.psk,
                &this.write_buf[salt_start..],
                this.method.key_len(),
            );
            this.enc = Ss2022Aead::new(this.method, &enc_subkey);
            this.enc_nonce = [0u8; 12];

            let chunk_size = buf.len().min(16384);
            let plain = &buf[..chunk_size];

            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let fixed_nonce = this.enc_nonce;
            increase_nonce(&mut this.enc_nonce);
            let fixed_start = this.write_buf.len();
            this.write_buf.push(0x01); // HeaderTypeServer
            this.write_buf.extend_from_slice(&now_sec.to_be_bytes());
            this.write_buf.extend_from_slice(&this.client_salt);
            this.write_buf
                .extend_from_slice(&(chunk_size as u16).to_be_bytes());
            if let Err(e) = this
                .enc
                .seal_tail(fixed_nonce, &mut this.write_buf, fixed_start)
            {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }

            let payload_nonce = this.enc_nonce;
            increase_nonce(&mut this.enc_nonce);
            let payload_start = this.write_buf.len();
            this.write_buf.extend_from_slice(plain);
            if let Err(e) = this
                .enc
                .seal_tail(payload_nonce, &mut this.write_buf, payload_start)
            {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            this.write_pos = 0;
            this.writing_plain_len = chunk_size;
            this.server_response_written = true;

            while this.write_pos < this.write_buf.len() {
                let n = match Pin::new(&mut this.inner)
                    .poll_write(cx, &this.write_buf[this.write_pos..])
                {
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

            return Poll::Pending;
        }

        // Frame as many chunks as the caller's buffer provides, up to the size of
        // the relay's copy buffer, and hand them to the socket in one write.
        //
        // One chunk per `poll_write` meant a 64 KiB write from the relay became four
        // calls, four seals and four syscalls — the same defect that capped the
        // WebSocket transport until its frame size matched the copy buffer.
        let cap = buf.len().min(flux_common::copy::RELAY_BUFFER_BYTES);
        let mut consumed = 0usize;
        this.write_buf.clear();
        while consumed < cap {
            let chunk_size = (cap - consumed).min(16384);
            let plain = &buf[consumed..consumed + chunk_size];

            let len_start = this.write_buf.len();
            this.write_buf
                .extend_from_slice(&(chunk_size as u16).to_be_bytes());
            let len_nonce = this.enc_nonce;
            increase_nonce(&mut this.enc_nonce);
            if let Err(e) = this
                .enc
                .seal_tail(len_nonce, &mut this.write_buf, len_start)
            {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }

            let payload_nonce = this.enc_nonce;
            increase_nonce(&mut this.enc_nonce);
            let payload_start = this.write_buf.len();
            this.write_buf.extend_from_slice(plain);
            if let Err(e) = this
                .enc
                .seal_tail(payload_nonce, &mut this.write_buf, payload_start)
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                break;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Sliding replay window for SS-2022 UDP packet IDs (`SIP022` requires the server
/// to drop duplicate `(session_id, packet_id)` pairs).
///
/// The timestamp check only bounds *freshness*: without this a captured datagram
/// is accepted again on every replay until it ages out of the window.
#[derive(Debug)]
struct UdpReplayWindow {
    /// Highest packet id accepted so far (or `None` before the first packet).
    highest: Option<u64>,
    /// Bitmap of the 64 packet ids below `highest`.
    bitmap: u64,
}

impl UdpReplayWindow {
    const fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
    }

    /// Returns true when `pid` is new (and records it), false for a replay.
    fn accept(&mut self, pid: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(pid);
                self.bitmap = 1;
                true
            }
            Some(high) => {
                if pid > high {
                    let shift = pid - high;
                    self.bitmap = if shift >= 64 {
                        1
                    } else {
                        (self.bitmap << shift) | 1
                    };
                    self.highest = Some(pid);
                    true
                } else {
                    let diff = high - pid;
                    if diff >= 64 {
                        return false; // too old: outside the window
                    }
                    let bit = 1u64 << diff;
                    if self.bitmap & bit != 0 {
                        return false; // duplicate
                    }
                    self.bitmap |= bit;
                    true
                }
            }
        }
    }
}

/// Seals and opens Shadowsocks 2022 datagrams.
pub struct Ss2022UdpPacketCipher {
    method: Ss2022CipherMethod,
    psk: Vec<u8>,
    session_id: [u8; 8],
    packet_id: std::sync::atomic::AtomicU64,
    aead: Ss2022Aead,
    /// Replay window for packets carrying *our* session id.
    own_replay: Mutex<UdpReplayWindow>,
    /// Peer session ids seen so far → (derived AEAD, replay window).
    ///
    /// The cache bounds *memory*: without it, every datagram carrying a fresh
    /// session id would pin a key schedule plus a window forever. Note that it
    /// does not bound work — a fresh session id per datagram still costs one
    /// BLAKE3-XOF plus an AES key schedule, which is inherent to SS-2022 UDP.
    ///
    /// It also makes replay protection best-effort: evicting an entry resets its
    /// window, so a captured datagram can be accepted again after eviction. The
    /// timestamp check (30 s) is the primary defence for UDP, exactly as the spec
    /// intends; the window closes the cheap "resend immediately" case.
    peers: Mutex<LruCache<[u8; 8], (Ss2022Aead, UdpReplayWindow)>>,
}

/// Maximum number of peer UDP session ids remembered per cipher.
///
/// Sized well above the number of peers a relay realistically serves at once, so
/// legitimate traffic does not evict a live window.
const UDP_PEER_CACHE: usize = 1024;

impl Ss2022UdpPacketCipher {
    /// Builds the value with the protocol defaults.
    pub fn new(method: Ss2022CipherMethod, psk: &[u8]) -> Self {
        let mut session_id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut session_id);
        let subkey = derive_2022_subkey(psk, &session_id, method.key_len());
        let aead = Ss2022Aead::new(method, &subkey);
        Self {
            method,
            psk: psk.to_vec(),
            session_id,
            packet_id: std::sync::atomic::AtomicU64::new(0),
            aead,
            own_replay: Mutex::new(UdpReplayWindow::new()),
            peers: Mutex::new(LruCache::new(
                NonZeroUsize::new(UDP_PEER_CACHE).expect("non-zero"),
            )),
        }
    }

    fn make_nonce(pid: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&pid.to_be_bytes());
        nonce
    }

    /// Seals one UDP datagram.
    pub fn encrypt_packet(
        &self,
        destination: &TargetAddress,
        payload: &[u8],
    ) -> FluxResult<Vec<u8>> {
        let pid = self
            .packet_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let addr_bytes = crate::shadowsocks::encode_ss_address(destination);
        let nonce = Self::make_nonce(pid);

        // One buffer: session id ‖ packet id ‖ sealed (timestamp ‖ address ‖
        // payload). Sealing in place keeps the datagram to a single allocation.
        let mut out =
            Vec::with_capacity(16 + 8 + addr_bytes.len() + payload.len() + SS2022_TAG_LEN);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&pid.to_be_bytes());
        let plain_start = out.len();
        out.extend_from_slice(&now_sec.to_be_bytes());
        out.extend_from_slice(&addr_bytes);
        out.extend_from_slice(payload);
        self.aead.seal_tail(nonce, &mut out, plain_start)?;
        Ok(out)
    }

    /// Opens one UDP datagram.
    pub async fn decrypt_packet(&self, buf: &[u8]) -> FluxResult<(TargetAddress, bytes::Bytes)> {
        if buf.len() < 8 + 8 + 8 + 1 + 16 {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-2022-udp",
                message: "received packet too short".into(),
            });
        }

        let pkt_session_id = &buf[0..8];
        let pid = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);

        let nonce = Self::make_nonce(pid);

        // Resolve (and cache) the AEAD for the packet's session id, deriving the
        // subkey at most once per peer session.
        let mut peer_sid = [0u8; 8];
        peer_sid.copy_from_slice(pkt_session_id);
        // Authentication MUST come before the replay window is advanced: a forged
        // datagram that only carried a valid session id and a huge packet id would
        // otherwise push `highest` forward and make every subsequent legitimate
        // packet look "too old", silently killing the tunnel's UDP.
        let plain = if peer_sid == self.session_id {
            // Packet from the peer using our session id.
            let plain = self.aead.decrypt(nonce, &buf[16..])?;
            if !self.own_replay.lock().accept(pid) {
                return Err(FluxError::AuthFailed(
                    "shadowsocks-2022 UDP replay detected".into(),
                ));
            }
            plain
        } else {
            // Packet carrying the peer's own session id: derive (and cache) the
            // subkey once per session instead of per datagram.
            let mut peers = self.peers.lock();
            if peers.get(&peer_sid).is_none() {
                let subkey = derive_2022_subkey(&self.psk, &peer_sid, self.method.key_len());
                peers.put(
                    peer_sid,
                    (
                        Ss2022Aead::new(self.method, &subkey),
                        UdpReplayWindow::new(),
                    ),
                );
            }
            // Decrypt with the (possibly just-derived) session key first…
            let plain = {
                let (aead, _) = peers.get(&peer_sid).expect("just inserted");
                aead.decrypt(nonce, &buf[16..])?
            };
            // …and only record the packet id once it is proven authentic.
            let (_, window) = peers.get_mut(&peer_sid).expect("present");
            if !window.accept(pid) {
                return Err(FluxError::AuthFailed(
                    "shadowsocks-2022 UDP replay detected".into(),
                ));
            }
            plain
        };

        if plain.len() < 8 + 1 {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-2022-udp",
                message: "decrypted packet payload too short".into(),
            });
        }

        let ts = u64::from_be_bytes([
            plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
        ]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.abs_diff(ts) > SS_2022_REPLAY_WINDOW_SECS {
            return Err(FluxError::AuthFailed(
                "shadowsocks-2022 UDP packet timestamp expired".into(),
            ));
        }

        let atyp = plain[8];
        let mut cursor = std::io::Cursor::new(&plain[9..]);
        let target = Socks5Handshake::read_address(&mut cursor, atyp).await?;
        let addr_len = 1 + cursor.position() as usize;
        let payload_offset = 8 + addr_len;

        if payload_offset > plain.len() {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-2022-udp",
                message: "address truncated in packet".into(),
            });
        }

        let payload = bytes::Bytes::copy_from_slice(&plain[payload_offset..]);
        Ok((target, payload))
    }
}

/// Handshakes and framing for Shadowsocks 2022.
pub struct Ss2022Protocol;

impl Ss2022Protocol {
    /// Client-side: initiate Shadowsocks 2022 handshake with timestamp and destination address.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        method: Ss2022CipherMethod,
        psk: &[u8],
        destination: &TargetAddress,
    ) -> FluxResult<Ss2022Stream<S>> {
        let salt_len = method.salt_len();
        let mut client_salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut client_salt);

        let enc_subkey = derive_2022_subkey(psk, &client_salt, method.key_len());
        let aead = Ss2022Aead::new(method, &enc_subkey);

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let addr_bytes = crate::shadowsocks::encode_ss_address(destination);
        // Variable length header: [destination, padding_len (2B), padding]
        let padding_len: u16 = 16;
        let mut padding = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut padding);
        let var_len = addr_bytes.len() + 2 + padding.len();

        // Fixed chunk: [HeaderTypeClient (0x00), timestamp (8B BE), var_len (2B BE)]
        let mut fixed_chunk = Vec::with_capacity(1 + 8 + 2);
        fixed_chunk.push(0x00);
        fixed_chunk.extend_from_slice(&now_sec.to_be_bytes());
        fixed_chunk.extend_from_slice(&(var_len as u16).to_be_bytes());

        let mut enc_nonce = [0u8; 12];
        let enc_fixed = aead.encrypt(enc_nonce, &fixed_chunk)?;
        increase_nonce(&mut enc_nonce);

        // Variable chunk: [addr_bytes, padding_len, padding]
        let mut var_chunk = Vec::with_capacity(var_len);
        var_chunk.extend_from_slice(&addr_bytes);
        var_chunk.extend_from_slice(&padding_len.to_be_bytes());
        var_chunk.extend_from_slice(&padding);

        let enc_var = aead.encrypt(enc_nonce, &var_chunk)?;
        increase_nonce(&mut enc_nonce);

        // Send salt, fixed chunk, and variable chunk together in one packet
        let mut req_buf = Vec::with_capacity(client_salt.len() + enc_fixed.len() + enc_var.len());
        req_buf.extend_from_slice(&client_salt);
        req_buf.extend_from_slice(&enc_fixed);
        req_buf.extend_from_slice(&enc_var);

        stream.write_all(&req_buf).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        Ok(Ss2022Stream::new_client(
            stream,
            method,
            psk,
            client_salt,
            enc_subkey,
            enc_nonce,
        ))
    }

    /// Server-side: authenticate incoming Shadowsocks 2022 client, verify timestamp and replay cache.
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        method: Ss2022CipherMethod,
        psk: &[u8],
        replay: &ReplayFilter,
    ) -> FluxResult<(Ss2022Stream<S>, TargetAddress, Vec<u8>)> {
        let salt_len = method.salt_len();
        let mut client_salt = vec![0u8; salt_len];
        stream
            .read_exact(&mut client_salt)
            .await
            .map_err(FluxError::Io)?;

        let dec_subkey = derive_2022_subkey(psk, &client_salt, method.key_len());
        let aead = Ss2022Aead::new(method, &dec_subkey);

        // 1. Read fixed chunk (11 bytes + 16 bytes tag = 27 bytes)
        let mut enc_fixed = [0u8; 11 + 16];
        stream
            .read_exact(&mut enc_fixed)
            .await
            .map_err(FluxError::Io)?;

        let mut dec_nonce = [0u8; 12];
        let fixed = aead.decrypt(dec_nonce, &enc_fixed)?;
        increase_nonce(&mut dec_nonce);

        if fixed[0] != 0x00 {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-2022",
                message: format!("unexpected client header type: {}", fixed[0]),
            });
        }

        let timestamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        if !replay.check_and_insert(&client_salt, timestamp) {
            return Err(FluxError::AuthFailed(
                "shadowsocks-2022 replay check failed".into(),
            ));
        }

        let var_len = u16::from_be_bytes(fixed[9..11].try_into().unwrap()) as usize;
        let mut enc_var = vec![0u8; var_len + 16];
        stream
            .read_exact(&mut enc_var)
            .await
            .map_err(FluxError::Io)?;

        let var_chunk = aead.decrypt(dec_nonce, &enc_var)?;
        increase_nonce(&mut dec_nonce);

        if var_chunk.is_empty() {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-2022",
                message: "empty address chunk".into(),
            });
        }

        let atyp = var_chunk[0];
        let mut cursor = io::Cursor::new(&var_chunk[1..]);
        let target = Socks5Handshake::read_address(&mut cursor, atyp).await?;
        let consumed = 1 + cursor.position() as usize;

        // Skip padding if present
        let (extra_data, _) = if consumed + 2 <= var_chunk.len() {
            let pad_len =
                u16::from_be_bytes([var_chunk[consumed], var_chunk[consumed + 1]]) as usize;
            let after_pad = consumed + 2 + pad_len;
            if after_pad < var_chunk.len() {
                (var_chunk[after_pad..].to_vec(), ())
            } else {
                (Vec::new(), ())
            }
        } else {
            (Vec::new(), ())
        };

        let ss_stream = Ss2022Stream::new_server(
            stream,
            method,
            psk,
            client_salt,
            &dec_subkey,
            dec_nonce,
            extra_data,
        );
        Ok((ss_stream, target, Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ss_2022_roundtrip() {
        let psk = b"1234567890123456"; // 16-byte key for AES-128
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let replay = ReplayFilter::new(1000);

        let (client_io, server_io) = tokio::io::duplex(4096);

        let target = TargetAddress::domain("example.com", 443);

        let srv = tokio::spawn(async move {
            let (mut srv_stream, srv_target, _extra) =
                Ss2022Protocol::server_handshake(server_io, method, psk, &replay)
                    .await
                    .unwrap();
            assert_eq!(srv_target, TargetAddress::domain("example.com", 443));
            let mut buf = [0u8; 11];
            srv_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping ss2022");
            srv_stream.write_all(b"pong ss2022").await.unwrap();
            srv_stream.flush().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let mut cli_stream = Ss2022Protocol::client_handshake(client_io, method, psk, &target)
                .await
                .unwrap();
            cli_stream.write_all(b"ping ss2022").await.unwrap();
            cli_stream.flush().await.unwrap();
            let mut buf = [0u8; 11];
            cli_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong ss2022");
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_ss_2022_udp_packet_cipher_roundtrip() {
        let psk = b"0123456789abcdef";
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let cipher = Ss2022UdpPacketCipher::new(method, psk);

        let target = TargetAddress::domain("dns.google", 53);
        let payload = b"hello ss2022 udp payload";

        let encrypted = cipher.encrypt_packet(&target, payload).unwrap();
        assert!(encrypted.len() > 16);

        let (dec_target, dec_payload) = cipher.decrypt_packet(&encrypted).await.unwrap();
        assert_eq!(dec_target, target);
        assert_eq!(&dec_payload[..], payload);
    }

    #[test]
    fn test_ss_2022_replay_filter_zero_capacity_no_panic() {
        let filter = ReplayFilter::new(0);
        let salt = b"testsalt";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(filter.check_and_insert(salt, now));
        assert!(!filter.check_and_insert(salt, now));
    }

    #[tokio::test]
    async fn test_ss_2022_udp_packet_cipher_arbitrary_session() {
        let psk = b"0123456789abcdef";
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let sender = Ss2022UdpPacketCipher::new(method, psk);
        let receiver = Ss2022UdpPacketCipher::new(method, psk);
        assert_ne!(sender.session_id, receiver.session_id);

        let target = TargetAddress::domain("example.com", 443);
        let payload = b"arbitrary session udp packet";

        let encrypted = sender.encrypt_packet(&target, payload).unwrap();
        let (dec_target, dec_payload) = receiver.decrypt_packet(&encrypted).await.unwrap();
        assert_eq!(dec_target, target);
        assert_eq!(&dec_payload[..], payload);
    }

    #[tokio::test]
    async fn test_ss_2022_udp_packet_cipher_timestamp_validation() {
        let psk = b"0123456789abcdef";
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let sender = Ss2022UdpPacketCipher::new(method, psk);
        let receiver = Ss2022UdpPacketCipher::new(method, psk);

        let target = TargetAddress::domain("example.com", 443);
        let addr_bytes = crate::shadowsocks::encode_ss_address(&target);
        let payload = b"timestamp test";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Expired timestamp: now - 35s (> 30s)
        let expired_ts = now - (SS_2022_REPLAY_WINDOW_SECS + 5);
        let mut plain_expired = Vec::new();
        plain_expired.extend_from_slice(&expired_ts.to_be_bytes());
        plain_expired.extend_from_slice(&addr_bytes);
        plain_expired.extend_from_slice(payload);
        let nonce0 = Ss2022UdpPacketCipher::make_nonce(0);
        let enc0 = sender.aead.encrypt(nonce0, &plain_expired).unwrap();
        let mut pkt_expired = Vec::new();
        pkt_expired.extend_from_slice(&sender.session_id);
        pkt_expired.extend_from_slice(&0u64.to_be_bytes());
        pkt_expired.extend_from_slice(&enc0);

        let err = receiver.decrypt_packet(&pkt_expired).await.unwrap_err();
        match err {
            FluxError::AuthFailed(msg) => assert!(msg.contains("timestamp expired")),
            other => panic!("expected AuthFailed, got {:?}", other),
        }

        // 2. Future timestamp outside window: now + 35s (> 30s)
        let future_ts = now + (SS_2022_REPLAY_WINDOW_SECS + 5);
        let mut plain_future = Vec::new();
        plain_future.extend_from_slice(&future_ts.to_be_bytes());
        plain_future.extend_from_slice(&addr_bytes);
        plain_future.extend_from_slice(payload);
        let nonce1 = Ss2022UdpPacketCipher::make_nonce(1);
        let enc1 = sender.aead.encrypt(nonce1, &plain_future).unwrap();
        let mut pkt_future = Vec::new();
        pkt_future.extend_from_slice(&sender.session_id);
        pkt_future.extend_from_slice(&1u64.to_be_bytes());
        pkt_future.extend_from_slice(&enc1);

        let err = receiver.decrypt_packet(&pkt_future).await.unwrap_err();
        match err {
            FluxError::AuthFailed(msg) => assert!(msg.contains("timestamp expired")),
            other => panic!("expected AuthFailed, got {:?}", other),
        }

        // 3. Valid timestamp within window: now - 15s (<= 30s)
        let valid_past_ts = now - 15;
        let mut plain_valid = Vec::new();
        plain_valid.extend_from_slice(&valid_past_ts.to_be_bytes());
        plain_valid.extend_from_slice(&addr_bytes);
        plain_valid.extend_from_slice(payload);
        let nonce2 = Ss2022UdpPacketCipher::make_nonce(2);
        let enc2 = sender.aead.encrypt(nonce2, &plain_valid).unwrap();
        let mut pkt_valid = Vec::new();
        pkt_valid.extend_from_slice(&sender.session_id);
        pkt_valid.extend_from_slice(&2u64.to_be_bytes());
        pkt_valid.extend_from_slice(&enc2);

        let (dec_target, dec_payload) = receiver.decrypt_packet(&pkt_valid).await.unwrap();
        assert_eq!(dec_target, target);
        assert_eq!(&dec_payload[..], payload);
    }
}

#[cfg(test)]
mod udp_replay_tests {
    use super::*;

    #[test]
    fn window_accepts_increasing_ids() {
        let mut w = UdpReplayWindow::new();
        for pid in 0..200u64 {
            assert!(w.accept(pid), "fresh id {pid} must be accepted");
        }
    }

    #[test]
    fn window_rejects_duplicates() {
        let mut w = UdpReplayWindow::new();
        assert!(w.accept(42));
        assert!(!w.accept(42), "duplicate must be rejected");
        assert!(w.accept(43));
        assert!(!w.accept(43));
        // Out-of-order but unseen is fine.
        assert!(w.accept(41));
        assert!(!w.accept(41));
    }

    #[test]
    fn window_rejects_too_old_ids() {
        let mut w = UdpReplayWindow::new();
        assert!(w.accept(1000));
        assert!(!w.accept(1000 - 64), "outside the 64-entry window");
    }

    #[test]
    fn window_handles_large_jumps() {
        let mut w = UdpReplayWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(1_000_000), "a big jump resets the bitmap");
        assert!(!w.accept(1_000_000));
        assert!(w.accept(999_999));
        assert!(!w.accept(999_999));
    }

    /// A forged datagram must not advance the replay window.
    ///
    /// The window is keyed on packet ids, so accepting an id before checking the
    /// AEAD tag would let an unauthenticated packet with a huge id push `highest`
    /// forward and make every later legitimate packet look stale — a one-packet
    /// remote DoS for the UDP path.
    #[tokio::test]
    async fn forged_datagram_does_not_poison_the_replay_window() {
        let key = [9u8; 16];
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let sender = Ss2022UdpPacketCipher::new(method, &key);
        let receiver = Ss2022UdpPacketCipher::new(method, &key);
        let target: TargetAddress = "1.2.3.4:53".parse().unwrap();

        // One genuine datagram so the receiver's window is initialised.
        let good = sender.encrypt_packet(&target, b"real").unwrap();
        receiver
            .decrypt_packet(&good)
            .await
            .expect("genuine packet");

        // Forge a packet with the correct session id but a huge packet id and a
        // garbage payload (bad AEAD tag).
        let mut forged = good.clone();
        forged[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        for b in forged[16..].iter_mut() {
            *b ^= 0xFF;
        }
        assert!(
            receiver.decrypt_packet(&forged).await.is_err(),
            "a forged packet must be rejected"
        );

        // The next genuine datagram must still be accepted.
        let next = sender.encrypt_packet(&target, b"after-forgery").unwrap();
        let (_, payload) = receiver
            .decrypt_packet(&next)
            .await
            .expect("a forged packet must not poison the replay window");
        assert_eq!(&payload[..], b"after-forgery");
    }

    /// A replayed SS-2022 UDP datagram must be rejected end to end.
    #[tokio::test]
    async fn replayed_datagram_is_rejected() {
        let key = [7u8; 16];
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let sender = Ss2022UdpPacketCipher::new(method, &key);
        let receiver = Ss2022UdpPacketCipher::new(method, &key);

        let target: TargetAddress = "1.2.3.4:53".parse().unwrap();
        let wire = sender.encrypt_packet(&target, b"query").unwrap();

        // First delivery is accepted.
        let (t, payload) = receiver
            .decrypt_packet(&wire)
            .await
            .expect("first delivery");
        assert_eq!(t, target);
        assert_eq!(&payload[..], b"query");

        // Replay of the exact same bytes must fail.
        let err = receiver.decrypt_packet(&wire).await;
        assert!(
            matches!(err, Err(FluxError::AuthFailed(_))),
            "replay must be rejected, got {err:?}"
        );
    }
}

#[cfg(test)]
mod batching_guard_tests {
    // (module doc below)
    //! Guards for the framing work, written so they fail if the one-chunk-per-call
    //! behaviour ever comes back.
    //!
    //! The fixes were originally justified by measurement alone, and measurement is
    //! not a regression test: a future refactor could restore the old shape and no
    //! test would go red. These count what the stream asks of its transport.

    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// Records the size of every `poll_write` the wrapper performs.
    #[derive(Default)]
    struct CountingWriter {
        writes: Vec<usize>,
        /// How much the inner transport accepts per call.
        accept: usize,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.accept.max(1));
            self.writes.push(n);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for CountingWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A 64 KiB write from the relay must reach the transport as one write, not four.
    ///
    /// This is the fix that took Shadowsocks-2022 from −48 % to −2.7 % against
    /// sing-box: the relay writes 64 KiB and the chunk size is 16 KiB, so one chunk
    /// per call meant four frames, four seals and four syscalls per buffer.
    #[tokio::test]
    async fn a_64_kib_write_reaches_the_transport_in_one_call() {
        let psk = b"1234567890123456";
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let destination = TargetAddress::domain("example.com", 443);

        let mut stream = Ss2022Protocol::client_handshake(
            CountingWriter {
                writes: Vec::new(),
                accept: usize::MAX,
            },
            method,
            psk,
            &destination,
        )
        .await
        .expect("client handshake");

        // The first flight carries the handshake header; the property under test is
        // what a *payload* write does, so the record starts after it.
        let handshake_writes = stream.inner.writes.len();

        let payload = vec![0x5au8; 64 * 1024];
        let written = tokio::io::AsyncWriteExt::write(&mut stream, &payload)
            .await
            .expect("write");

        let calls = stream.inner.writes[handshake_writes..].to_vec();
        assert_eq!(written, 64 * 1024, "the whole buffer must be accepted");
        assert_eq!(
            calls.len(),
            1,
            "64 KiB must reach the transport as one write, not {} (sizes: {calls:?})",
            calls.len()
        );
    }

    /// A reader asking for 64 KiB must get more than one 16 KiB chunk per call.
    ///
    /// Before the fix `poll_read` returned after every decrypted chunk, so the relay
    /// needed four read/write cycles per buffer. This fails if that returns.
    #[tokio::test]
    async fn a_read_fills_more_than_one_chunk() {
        let psk = b"1234567890123456";
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let destination = TargetAddress::domain("example.com", 443);
        let replay = ReplayFilter::new(1000);

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server = tokio::spawn(async move {
            let (mut srv, _target, _extra) =
                Ss2022Protocol::server_handshake(server_io, method, psk, &replay)
                    .await
                    .expect("server handshake");
            let mut buf = vec![0u8; 64 * 1024];
            tokio::io::AsyncReadExt::read(&mut srv, &mut buf)
                .await
                .expect("read")
        });

        let mut client = Ss2022Protocol::client_handshake(client_io, method, psk, &destination)
            .await
            .expect("client handshake");
        let payload = vec![0x11u8; 48 * 1024];
        tokio::io::AsyncWriteExt::write_all(&mut client, &payload)
            .await
            .expect("write");

        let got = server.await.expect("server task");
        assert!(
            got > 16 * 1024,
            "one read returned {got} bytes: the reader is still stopping at a single \
             16 KiB chunk instead of filling the caller's buffer"
        );
    }

    /// A chunk may be as large as the 16-bit length prefix allows: 65 535 bytes of
    /// payload, which does not fit the 64 KiB receive buffer. Our own writer never emits
    /// one (it frames at 16 KiB), so this drives a **raw peer** that seals the stream by
    /// hand — the only way to test the case.
    #[tokio::test]
    async fn a_peer_may_send_a_maximum_size_chunk() {
        let psk = b"1234567890123456";
        let method = Ss2022CipherMethod::Blake3Aes128Gcm;
        let replay = ReplayFilter::new(1000);

        // Seal a record with `aead` at `nonce`, returning payload‖tag.
        let seal = |aead: &Ss2022Aead, nonce: [u8; 12], plain: &[u8]| {
            let mut out = plain.to_vec();
            aead.seal_tail(nonce, &mut out, 0).expect("seal");
            out
        };

        let salt = [0x5au8; 16];
        let subkey = derive_2022_subkey(psk, &salt, method.key_len());
        let aead = Ss2022Aead::new(method, &subkey);

        let mut nonce = [0u8; 12];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Fixed header: type, timestamp, address-chunk length.
        let var_chunk = [0x01u8, 127, 0, 0, 1, 0, 80]; // IPv4 127.0.0.1:80
        let mut fixed = Vec::new();
        fixed.push(0x00);
        fixed.extend_from_slice(&now.to_be_bytes());
        fixed.extend_from_slice(&(var_chunk.len() as u16).to_be_bytes());
        let enc_fixed = seal(&aead, nonce, &fixed);
        increase_nonce(&mut nonce);
        let enc_var = seal(&aead, nonce, &var_chunk);
        increase_nonce(&mut nonce);

        // One chunk carrying the largest length the 16-bit prefix allows.
        let payload: Vec<u8> = (0..65_535).map(|i| (i % 251) as u8).collect();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        let enc_big = seal(&aead, nonce, &framed);
        increase_nonce(&mut nonce);
        let enc_payload = seal(&aead, nonce, &payload);

        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&salt);
        stream_bytes.extend_from_slice(&enc_fixed);
        stream_bytes.extend_from_slice(&enc_var);
        stream_bytes.extend_from_slice(&enc_big);
        stream_bytes.extend_from_slice(&enc_payload);

        let (peer, server_io) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let mut peer = peer;
            tokio::io::AsyncWriteExt::write_all(&mut peer, &stream_bytes)
                .await
                .expect("write stream");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });

        let (mut srv, _target, _extra) =
            Ss2022Protocol::server_handshake(server_io, method, psk, &replay)
                .await
                .expect("server handshake");

        let mut got = vec![0u8; 65_535];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::io::AsyncReadExt::read_exact(&mut srv, &mut got),
        )
        .await
        .expect("a maximum-size chunk must not hang")
        .expect("read the whole chunk");
        assert_eq!(got, payload, "a 65 535-byte chunk must survive intact");
    }
}
