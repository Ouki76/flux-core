use crate::socks5::Socks5Handshake;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce as AesGcmNonce,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use flux_types::{FluxError, FluxResult, TargetAddress};
use lru::LruCache;
use parking_lot::Mutex;
use rand::RngCore;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const SS_2022_KDF_CONTEXT: &str = "shadowsocks 2022 session subkey";
pub const SS_2022_REPLAY_WINDOW_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ss2022CipherMethod {
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3ChaCha20Poly1305,
}

impl Ss2022CipherMethod {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Some(Self::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::Blake3ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::Blake3Aes128Gcm => 16,
            Self::Blake3Aes256Gcm => 32,
            Self::Blake3ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(&self) -> usize {
        match self {
            Self::Blake3Aes128Gcm => 16,
            Self::Blake3Aes256Gcm => 32,
            Self::Blake3ChaCha20Poly1305 => 32,
        }
    }
}

pub struct ReplayFilter {
    cache: Mutex<LruCache<Vec<u8>, u64>>,
}

impl ReplayFilter {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

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

enum Ss2022Aead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

impl Ss2022Aead {
    fn new(method: Ss2022CipherMethod, subkey: &[u8]) -> Self {
        match method {
            Ss2022CipherMethod::Blake3Aes128Gcm => {
                Self::Aes128(Box::new(Aes128Gcm::new_from_slice(subkey).unwrap()))
            }
            Ss2022CipherMethod::Blake3Aes256Gcm => {
                Self::Aes256(Box::new(Aes256Gcm::new_from_slice(subkey).unwrap()))
            }
            Ss2022CipherMethod::Blake3ChaCha20Poly1305 => {
                Self::ChaCha(ChaCha20Poly1305::new_from_slice(subkey).unwrap())
            }
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], plain: &[u8]) -> FluxResult<Vec<u8>> {
        match self {
            Self::Aes128(c) => c.encrypt(AesGcmNonce::from_slice(nonce), plain),
            Self::Aes256(c) => c.encrypt(AesGcmNonce::from_slice(nonce), plain),
            Self::ChaCha(c) => c.encrypt(ChaChaNonce::from_slice(nonce), plain),
        }
        .map_err(|e| FluxError::Crypto(format!("shadowsocks-2022 encrypt failed: {}", e)))
    }

    fn decrypt(&self, nonce: &[u8; 12], cipher: &[u8]) -> FluxResult<Vec<u8>> {
        match self {
            Self::Aes128(c) => c.decrypt(AesGcmNonce::from_slice(nonce), cipher),
            Self::Aes256(c) => c.decrypt(AesGcmNonce::from_slice(nonce), cipher),
            Self::ChaCha(c) => c.decrypt(ChaChaNonce::from_slice(nonce), cipher),
        }
        .map_err(|e| FluxError::Crypto(format!("shadowsocks-2022 decrypt failed: {}", e)))
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
    len_buf: [u8; 18],
    len_pos: usize,
    payload_len: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,

    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> Ss2022Stream<S> {
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
            len_buf: [0u8; 18],
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
            len_buf: [0u8; 18],
            len_pos: 0,
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
                let resp_fixed = match dec.decrypt(&dec_nonce, &this.resp_hdr_buf) {
                    Ok(b) => b,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                };

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
                let initial_data = match dec.decrypt(&dec_nonce, &this.resp_payload_buf) {
                    Ok(b) => b,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                };
                this.read_buf = initial_data;
                this.read_pos = 0;
                this.response_read = true;
            }
        }

        loop {
            // 1. Drain existing decrypted plaintext
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
                this.read_pos += to_copy;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. Read 18-byte encrypted chunk length (2 bytes len + 16 bytes tag)
            if this.payload_len == 0 {
                while this.len_pos < 18 {
                    let mut tmp = [0u8; 18];
                    let needed = 18 - this.len_pos;
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
                                    "unexpected EOF reading 2022 chunk len",
                                )));
                            }
                            let pos = this.len_pos;
                            this.len_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                            this.len_pos += n;
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
                let len_nonce = this.dec_nonce;
                increase_nonce(&mut this.dec_nonce);
                let plain_len_bytes = match dec.decrypt(&len_nonce, &this.len_buf) {
                    Ok(b) => b,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                };
                this.payload_len =
                    u16::from_be_bytes([plain_len_bytes[0], plain_len_bytes[1]]) as usize;
                let total_payload_enc = this.payload_len + 16;
                this.payload_buf.resize(total_payload_enc, 0);
                this.payload_pos = 0;
                this.len_pos = 0;
            }

            // 3. Read encrypted payload chunk
            let total_payload_enc = this.payload_len + 16;
            while this.payload_pos < total_payload_enc {
                let needed = total_payload_enc - this.payload_pos;
                let mut tmp = [0u8; 8192];
                let to_read = needed.min(tmp.len());
                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading 2022 payload chunk",
                            )));
                        }
                        let pos = this.payload_pos;
                        this.payload_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.payload_pos += n;
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
            let payload_nonce = this.dec_nonce;
            increase_nonce(&mut this.dec_nonce);
            let decrypted = match dec.decrypt(&payload_nonce, &this.payload_buf) {
                Ok(b) => b,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
            };

            this.read_buf = decrypted;
            this.read_pos = 0;
            this.payload_len = 0;
            this.payload_pos = 0;
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
            let mut server_salt = vec![0u8; salt_len];
            rand::rngs::OsRng.fill_bytes(&mut server_salt);

            let enc_subkey = derive_2022_subkey(&this.psk, &server_salt, this.method.key_len());
            this.enc = Ss2022Aead::new(this.method, &enc_subkey);
            this.enc_nonce = [0u8; 12];

            let chunk_size = buf.len().min(16384);
            let plain = &buf[..chunk_size];

            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let mut resp_fixed = Vec::with_capacity(1 + 8 + salt_len + 2);
            resp_fixed.push(0x01); // HeaderTypeServer
            resp_fixed.extend_from_slice(&now_sec.to_be_bytes());
            resp_fixed.extend_from_slice(&this.client_salt);
            resp_fixed.extend_from_slice(&(chunk_size as u16).to_be_bytes());

            let fixed_nonce = this.enc_nonce;
            increase_nonce(&mut this.enc_nonce);
            let enc_fixed = match this.enc.encrypt(&fixed_nonce, &resp_fixed) {
                Ok(b) => b,
                Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
            };

            let payload_nonce = this.enc_nonce;
            increase_nonce(&mut this.enc_nonce);
            let enc_payload = match this.enc.encrypt(&payload_nonce, plain) {
                Ok(b) => b,
                Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
            };

            this.write_buf.clear();
            this.write_buf.extend_from_slice(&server_salt);
            this.write_buf.extend_from_slice(&enc_fixed);
            this.write_buf.extend_from_slice(&enc_payload);
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

        let chunk_size = buf.len().min(16384);
        let plain = &buf[..chunk_size];

        let len_bytes = (chunk_size as u16).to_be_bytes();
        let len_nonce = this.enc_nonce;
        increase_nonce(&mut this.enc_nonce);
        let enc_len = match this.enc.encrypt(&len_nonce, &len_bytes) {
            Ok(b) => b,
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        };

        let payload_nonce = this.enc_nonce;
        increase_nonce(&mut this.enc_nonce);
        let enc_payload = match this.enc.encrypt(&payload_nonce, plain) {
            Ok(b) => b,
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        };

        this.write_buf.clear();
        this.write_buf.extend_from_slice(&enc_len);
        this.write_buf.extend_from_slice(&enc_payload);
        this.write_pos = 0;
        this.writing_plain_len = chunk_size;

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

pub struct Ss2022UdpPacketCipher {
    method: Ss2022CipherMethod,
    psk: Vec<u8>,
    session_id: [u8; 8],
    packet_id: std::sync::atomic::AtomicU64,
    aead: Ss2022Aead,
}

impl Ss2022UdpPacketCipher {
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
        }
    }

    fn make_nonce(pid: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&pid.to_be_bytes());
        nonce
    }

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
        let mut plain = Vec::with_capacity(8 + addr_bytes.len() + payload.len());
        plain.extend_from_slice(&now_sec.to_be_bytes());
        plain.extend_from_slice(&addr_bytes);
        plain.extend_from_slice(payload);

        let nonce = Self::make_nonce(pid);
        let ciphertext = self.aead.encrypt(&nonce, &plain)?;

        let mut out = Vec::with_capacity(8 + 8 + ciphertext.len());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&pid.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

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
        let plain = if pkt_session_id == self.session_id {
            self.aead.decrypt(&nonce, &buf[16..])?
        } else {
            let subkey = derive_2022_subkey(&self.psk, pkt_session_id, self.method.key_len());
            let aead = Ss2022Aead::new(self.method, &subkey);
            aead.decrypt(&nonce, &buf[16..])?
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
        let enc_fixed = aead.encrypt(&enc_nonce, &fixed_chunk)?;
        increase_nonce(&mut enc_nonce);

        // Variable chunk: [addr_bytes, padding_len, padding]
        let mut var_chunk = Vec::with_capacity(var_len);
        var_chunk.extend_from_slice(&addr_bytes);
        var_chunk.extend_from_slice(&padding_len.to_be_bytes());
        var_chunk.extend_from_slice(&padding);

        let enc_var = aead.encrypt(&enc_nonce, &var_chunk)?;
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
        let fixed = aead.decrypt(&dec_nonce, &enc_fixed)?;
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

        let var_chunk = aead.decrypt(&dec_nonce, &enc_var)?;
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
        let enc0 = sender.aead.encrypt(&nonce0, &plain_expired).unwrap();
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
        let enc1 = sender.aead.encrypt(&nonce1, &plain_future).unwrap();
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
        let enc2 = sender.aead.encrypt(&nonce2, &plain_valid).unwrap();
        let mut pkt_valid = Vec::new();
        pkt_valid.extend_from_slice(&sender.session_id);
        pkt_valid.extend_from_slice(&2u64.to_be_bytes());
        pkt_valid.extend_from_slice(&enc2);

        let (dec_target, dec_payload) = receiver.decrypt_packet(&pkt_valid).await.unwrap();
        assert_eq!(dec_target, target);
        assert_eq!(&dec_payload[..], payload);
    }
}
