use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadInPlace, KeyInit},
};
use flux_types::{FluxError, FluxResult, TargetAddress};
use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 32;
pub const MAX_PAYLOAD_LEN: usize = 0x3FFF; // 16383 bytes (Shadowsocks AEAD RFC specification)

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CipherKind {
    #[default]
    ChaCha20IetfPoly1305,
    Aes256Gcm,
    Aes128Gcm,
    Ss2022(crate::shadowsocks2022::Ss2022CipherMethod),
}

impl CipherKind {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chacha20-ietf-poly1305" | "chacha20" | "chacha20-poly1305" => {
                Some(Self::ChaCha20IetfPoly1305)
            }
            "aes-256-gcm" | "aes-256" => Some(Self::Aes256Gcm),
            "aes-128-gcm" | "aes-128" => Some(Self::Aes128Gcm),
            "2022-blake3-aes-128-gcm" => Some(Self::Ss2022(
                crate::shadowsocks2022::Ss2022CipherMethod::Blake3Aes128Gcm,
            )),
            "2022-blake3-aes-256-gcm" => Some(Self::Ss2022(
                crate::shadowsocks2022::Ss2022CipherMethod::Blake3Aes256Gcm,
            )),
            "2022-blake3-chacha20-poly1305" => Some(Self::Ss2022(
                crate::shadowsocks2022::Ss2022CipherMethod::Blake3ChaCha20Poly1305,
            )),
            _ => None,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::ChaCha20IetfPoly1305 | Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
            Self::Ss2022(m) => m.key_len(),
        }
    }

    pub fn salt_len(&self) -> usize {
        match self {
            Self::ChaCha20IetfPoly1305 | Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
            Self::Ss2022(m) => m.salt_len(),
        }
    }
}

/// Standard Shadowsocks key derivation with specified key length:
/// If password is a base64 PSK with matching length, decodes directly; otherwise uses standard EVP_BytesToKey (MD5).
pub fn derive_master_key_for_kind(password: &str, kind: CipherKind) -> Vec<u8> {
    derive_master_key_len(password, kind.key_len())
}

pub fn derive_master_key_len(password: &str, key_len: usize) -> Vec<u8> {
    let clean = password.trim();
    use base64::Engine;
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(clean)
        && bytes.len() == key_len
    {
        return bytes;
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean)
        && bytes.len() == key_len
    {
        return bytes;
    }

    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&digest);
    }
    key.truncate(key_len);
    key
}

/// Standard Shadowsocks key derivation (defaults to 32 bytes).
pub fn derive_master_key(password: &str) -> [u8; 32] {
    let k = derive_master_key_len(password, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&k);
    out
}

/// Standard Shadowsocks HKDF-SHA1 subkey derivation.
pub fn derive_subkey(master_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; master_key.len()];
    let _ = hk.expand(SS_SUBKEY_INFO, &mut okm);
    okm
}

enum CipherInner {
    ChaCha(ChaCha20Poly1305),
    Aes256(Box<Aes256Gcm>),
    Aes128(Box<Aes128Gcm>),
}

pub struct ShadowsocksCipher {
    cipher: CipherInner,
    nonce: [u8; 12],
    kind: CipherKind,
}

impl ShadowsocksCipher {
    pub fn new(subkey: &[u8]) -> Self {
        Self::with_kind(CipherKind::ChaCha20IetfPoly1305, subkey)
    }

    pub fn with_kind(kind: CipherKind, subkey: &[u8]) -> Self {
        let cipher = match kind {
            CipherKind::ChaCha20IetfPoly1305 => {
                CipherInner::ChaCha(ChaCha20Poly1305::new_from_slice(subkey).unwrap())
            }
            CipherKind::Aes256Gcm => {
                CipherInner::Aes256(Box::new(Aes256Gcm::new_from_slice(subkey).unwrap()))
            }
            CipherKind::Aes128Gcm => {
                CipherInner::Aes128(Box::new(Aes128Gcm::new_from_slice(subkey).unwrap()))
            }
            CipherKind::Ss2022(m) => match m {
                crate::shadowsocks2022::Ss2022CipherMethod::Blake3Aes128Gcm => {
                    CipherInner::Aes128(Box::new(Aes128Gcm::new_from_slice(subkey).unwrap()))
                }
                crate::shadowsocks2022::Ss2022CipherMethod::Blake3Aes256Gcm => {
                    CipherInner::Aes256(Box::new(Aes256Gcm::new_from_slice(subkey).unwrap()))
                }
                crate::shadowsocks2022::Ss2022CipherMethod::Blake3ChaCha20Poly1305 => {
                    CipherInner::ChaCha(ChaCha20Poly1305::new_from_slice(subkey).unwrap())
                }
            },
        };
        Self {
            cipher,
            nonce: [0u8; 12],
            kind,
        }
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    fn next_nonce(&mut self) -> Nonce {
        let n = Nonce::from(self.nonce);
        for byte in &mut self.nonce {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        n
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce_raw = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_raw);
        match &self.cipher {
            CipherInner::ChaCha(c) => c.encrypt(nonce, plaintext),
            CipherInner::Aes256(c) => c.encrypt(nonce, plaintext),
            CipherInner::Aes128(c) => c.encrypt(nonce, plaintext),
        }
        .map_err(|e| FluxError::Crypto(format!("shadowsocks encrypt failed: {}", e)))
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce_raw = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_raw);
        match &self.cipher {
            CipherInner::ChaCha(c) => c.decrypt(nonce, ciphertext),
            CipherInner::Aes256(c) => c.decrypt(nonce, ciphertext),
            CipherInner::Aes128(c) => c.decrypt(nonce, ciphertext),
        }
        .map_err(|e| FluxError::Crypto(format!("shadowsocks decrypt failed: {}", e)))
    }

    pub fn encrypt_in_place(&mut self, buffer: &mut Vec<u8>) -> FluxResult<()> {
        let nonce_raw = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_raw);
        match &self.cipher {
            CipherInner::ChaCha(c) => c.encrypt_in_place(nonce, b"", buffer),
            CipherInner::Aes256(c) => c.encrypt_in_place(nonce, b"", buffer),
            CipherInner::Aes128(c) => c.encrypt_in_place(nonce, b"", buffer),
        }
        .map_err(|e| FluxError::Crypto(format!("shadowsocks encrypt in place failed: {}", e)))
    }

    pub fn decrypt_in_place(&mut self, buffer: &mut Vec<u8>) -> FluxResult<()> {
        let nonce_raw = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_raw);
        match &self.cipher {
            CipherInner::ChaCha(c) => c.decrypt_in_place(nonce, b"", buffer),
            CipherInner::Aes256(c) => c.decrypt_in_place(nonce, b"", buffer),
            CipherInner::Aes128(c) => c.decrypt_in_place(nonce, b"", buffer),
        }
        .map_err(|e| FluxError::Crypto(format!("shadowsocks decrypt in place failed: {}", e)))
    }
}

/// Serializes TargetAddress in Shadowsocks / SOCKS5 format.
pub fn encode_ss_address(addr: &TargetAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    match addr {
        TargetAddress::Ip(std::net::SocketAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddress::Ip(std::net::SocketAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddress::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            let dlen = bytes.len().min(255);
            buf.push(dlen as u8);
            buf.extend_from_slice(&bytes[..dlen]);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// A stream wrapper that handles Shadowsocks AEAD encryption on writes
/// and decryption on reads with full partial-write buffering.
pub struct ShadowsocksStream<S> {
    inner: S,
    enc: ShadowsocksCipher,
    dec: Option<ShadowsocksCipher>,
    kind: CipherKind,
    master_key: Vec<u8>,
    salt_buf: Vec<u8>,
    salt_pos: usize,
    // Reader chunk state
    len_buf: [u8; 2 + TAG_LEN],
    len_pos: usize,
    payload_len: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,
    chunk_data: Vec<u8>,
    chunk_pos: usize,
    // Writer chunk state: handles partial socket writes and avoids frame corruption
    write_buf: Vec<u8>,
    write_len_buf: Vec<u8>,
    write_payload_buf: Vec<u8>,
    write_pos: usize,
    writing_plain_size: usize,
}

impl<S> ShadowsocksStream<S> {
    pub fn new(
        inner: S,
        enc: ShadowsocksCipher,
        dec: Option<ShadowsocksCipher>,
        master_key: &[u8],
    ) -> Self {
        Self::new_with_initial_chunk(inner, enc, dec, master_key, vec![])
    }

    pub fn new_with_initial_chunk(
        inner: S,
        enc: ShadowsocksCipher,
        dec: Option<ShadowsocksCipher>,
        master_key: &[u8],
        initial_chunk: Vec<u8>,
    ) -> Self {
        let kind = enc.kind();
        let salt_len = kind.salt_len();
        Self {
            inner,
            enc,
            dec,
            kind,
            master_key: master_key.to_vec(),
            salt_buf: vec![0u8; salt_len],
            salt_pos: 0,
            len_buf: [0u8; 2 + TAG_LEN],
            len_pos: 0,
            payload_len: 0,
            payload_buf: Vec::with_capacity(MAX_PAYLOAD_LEN + TAG_LEN),
            payload_pos: 0,
            chunk_data: initial_chunk,
            chunk_pos: 0,
            write_buf: Vec::with_capacity(MAX_PAYLOAD_LEN + TAG_LEN * 2 + 2),
            write_len_buf: Vec::with_capacity(2 + TAG_LEN),
            write_payload_buf: Vec::with_capacity(MAX_PAYLOAD_LEN + TAG_LEN),
            write_pos: 0,
            writing_plain_size: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Step 1: If cipher is not yet initialized (waiting for salt from server)
        if self.dec.is_none() {
            let pos = self.salt_pos;
            let salt_len = self.kind.salt_len();
            let mut tmp = vec![0u8; salt_len - pos];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.salt_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                    self.salt_pos += n;
                    if self.salt_pos == salt_len {
                        let subkey = derive_subkey(&self.master_key, &self.salt_buf);
                        self.dec = Some(ShadowsocksCipher::with_kind(self.kind, &subkey));
                    } else {
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        loop {
            // Step 2: If we have decrypted chunk data, drain it into buf
            if self.chunk_pos < self.chunk_data.len() {
                let available = self.chunk_data.len() - self.chunk_pos;
                let to_write = available.min(buf.remaining());
                if to_write > 0 {
                    buf.put_slice(&self.chunk_data[self.chunk_pos..self.chunk_pos + to_write]);
                    self.chunk_pos += to_write;
                    if self.chunk_pos == self.chunk_data.len() {
                        self.chunk_data.clear();
                        self.chunk_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            // Step 3: Read 18-byte encrypted length
            if self.payload_len == 0 {
                let lpos = self.len_pos;
                let mut ltmp = [0u8; 2 + TAG_LEN];
                let mut ltmp_buf = ReadBuf::new(&mut ltmp[..2 + TAG_LEN - lpos]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut ltmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = ltmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(())); // Clean EOF
                        }
                        self.len_buf[lpos..lpos + n].copy_from_slice(&ltmp[..n]);
                        self.len_pos += n;
                        if self.len_pos == 2 + TAG_LEN {
                            let len_buf = self.len_buf;
                            let Some(dec) = self.dec.as_mut() else {
                                return Poll::Pending;
                            };
                            let dec_len = dec.decrypt(&len_buf).map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                            })?;
                            let raw_len = u16::from_be_bytes([dec_len[0], dec_len[1]]);
                            self.payload_len = (raw_len & 0x3FFF) as usize;
                            let target_len = self.payload_len + TAG_LEN;
                            self.payload_buf.resize(target_len, 0);
                            self.len_pos = 0;
                            self.payload_pos = 0;
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Step 4: Read encrypted payload chunk via zero-heap stack buffer
            if self.payload_len > 0 {
                let ppos = self.payload_pos;
                let target_len = self.payload_len + TAG_LEN;
                let mut tmp = [0u8; 16 * 1024];
                let to_read = (target_len - ppos).min(tmp.len());
                let mut ptmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut ptmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = ptmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF in Shadowsocks chunk",
                            )));
                        }
                        self.payload_buf[ppos..ppos + n].copy_from_slice(&tmp[..n]);
                        self.payload_pos += n;
                        if self.payload_pos == target_len {
                            let this = self.as_mut().get_mut();
                            let Some(dec) = this.dec.as_mut() else {
                                return Poll::Pending;
                            };
                            dec.decrypt_in_place(&mut this.payload_buf).map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                            })?;
                            std::mem::swap(&mut this.chunk_data, &mut this.payload_buf);
                            this.chunk_pos = 0;
                            this.payload_len = 0;
                            this.payload_pos = 0;
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Step 1: If there is an existing buffered frame being transmitted, flush it first
        while self.write_pos < self.write_buf.len() {
            let this = self.as_mut().get_mut();
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write buffered encrypted shadowsocks frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_written = this.writing_plain_size;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_size = 0;
                return Poll::Ready(Ok(plain_written));
            }
        }

        // Step 2: Prepare next encrypted frame from caller buffer using pre-allocated zero-heap buffers
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_size = buf.len().min(MAX_PAYLOAD_LEN);
        let plain_chunk = &buf[..chunk_size];
        let len_bytes = ((chunk_size as u16) & 0x3FFF).to_be_bytes();

        let this = self.as_mut().get_mut();
        this.write_len_buf.clear();
        this.write_len_buf.extend_from_slice(&len_bytes);
        this.enc
            .encrypt_in_place(&mut this.write_len_buf)
            .map_err(|e| io::Error::other(e.to_string()))?;

        this.write_payload_buf.clear();
        this.write_payload_buf.extend_from_slice(plain_chunk);
        this.enc
            .encrypt_in_place(&mut this.write_payload_buf)
            .map_err(|e| io::Error::other(e.to_string()))?;

        this.write_buf.clear();
        this.write_buf.extend_from_slice(&this.write_len_buf);
        this.write_buf.extend_from_slice(&this.write_payload_buf);
        this.write_pos = 0;
        this.writing_plain_size = chunk_size;

        // Step 3: Write as much of the new frame to inner stream as possible
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write encrypted shadowsocks frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_written = this.writing_plain_size;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_size = 0;
                return Poll::Ready(Ok(plain_written));
            }
        }

        Poll::Pending
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let this = self.as_mut().get_mut();
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to flush buffered encrypted shadowsocks frame",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_size = 0;
                break;
            }
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let this = self.as_mut().get_mut();
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_shadowsocks_aead_roundtrip() {
        let master = derive_master_key("secret123");
        let salt = [0x55u8; 32];
        let subkey = derive_subkey(&master, &salt);

        let mut enc = ShadowsocksCipher::new(&subkey);
        let mut dec = ShadowsocksCipher::new(&subkey);

        let data = b"Hello Shadowsocks AEAD!";
        let ciphertext = enc.encrypt(data).unwrap();
        assert_eq!(ciphertext.len(), data.len() + TAG_LEN);

        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, data);
    }

    #[test]
    fn test_shadowsocks_aes_256_gcm_roundtrip() {
        let master = derive_master_key("aes-pass-123");
        let salt = [0x77u8; 32];
        let subkey = derive_subkey(&master, &salt);

        let mut enc = ShadowsocksCipher::with_kind(CipherKind::Aes256Gcm, &subkey);
        let mut dec = ShadowsocksCipher::with_kind(CipherKind::Aes256Gcm, &subkey);

        let data = b"Hello Shadowsocks AES-256-GCM hardware accelerated!";
        let ciphertext = enc.encrypt(data).unwrap();
        assert_eq!(ciphertext.len(), data.len() + TAG_LEN);

        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, data);
    }

    #[tokio::test]
    async fn test_shadowsocks_stream_large_transfer() {
        let master = derive_master_key("large-transfer-pass");
        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];

        let cli_enc = ShadowsocksCipher::new(&derive_subkey(&master, &salt1));
        let cli_dec = ShadowsocksCipher::new(&derive_subkey(&master, &salt2));
        let srv_enc = ShadowsocksCipher::new(&derive_subkey(&master, &salt2));
        let srv_dec = ShadowsocksCipher::new(&derive_subkey(&master, &salt1));

        let (client_raw, server_raw) = tokio::io::duplex(8192); // constrained pipe to force partial writes
        let mut client = ShadowsocksStream::new(client_raw, cli_enc, Some(cli_dec), &master);
        let mut server = ShadowsocksStream::new(server_raw, srv_enc, Some(srv_dec), &master);

        let payload_size = 64 * 1024; // 64 KB
        let send_data: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
        let expected_data = send_data.clone();

        let srv_task = tokio::spawn(async move {
            let mut received = Vec::with_capacity(payload_size);
            let mut buf = vec![0u8; 4096];
            while received.len() < payload_size {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(received, expected_data);
            server.write_all(b"OK_LARGE_TRANSFER").await.unwrap();
            server.flush().await.unwrap();
        });

        let cli_task = tokio::spawn(async move {
            client.write_all(&send_data).await.unwrap();
            client.flush().await.unwrap();

            let mut reply = vec![0u8; 17];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"OK_LARGE_TRANSFER");
        });

        srv_task.await.unwrap();
        cli_task.await.unwrap();
    }
}
