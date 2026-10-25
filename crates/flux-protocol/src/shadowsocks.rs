use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use flux_types::{FluxError, FluxResult, TargetAddress};
use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use ring::aead::{
    AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
};
use sha1::Sha1;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The HKDF info string that derives the per-connection subkey.
pub const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
/// Length of the AEAD tag, in bytes.
pub const TAG_LEN: usize = 16;
/// Salt length for the AEAD key derivation.
pub const SALT_LEN: usize = 32;
/// Largest chunk the AEAD framing allows, from the specification.
pub const MAX_PAYLOAD_LEN: usize = 0x3FFF; // 16383 bytes (Shadowsocks AEAD RFC specification)

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
/// A Shadowsocks cipher: the AEAD methods plus the 2022 family.
pub enum CipherKind {
    #[default]
    /// ChaCha20-Poly1305 with the IETF nonce.
    ChaCha20IetfPoly1305,
    /// AES-256-GCM.
    Aes256Gcm,
    /// AES-128-GCM.
    Aes128Gcm,
    /// A Shadowsocks 2022 method, which has its own framing.
    Ss2022(crate::shadowsocks2022::Ss2022CipherMethod),
}

impl CipherKind {
    /// `parse_str`.
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

    /// Key length for this method.
    pub fn key_len(&self) -> usize {
        match self {
            Self::ChaCha20IetfPoly1305 | Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
            Self::Ss2022(m) => m.key_len(),
        }
    }

    /// Salt length for this method.
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

/// `derive_master_key_len`.
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

/// One AEAD direction of an SS-AEAD stream.
///
/// `ring` expands the key schedule once, inside `UnboundKey::new`, and the
/// resulting [`LessSafeKey`] is kept for the life of the stream: the per-packet
/// cost is pure AEAD with no per-chunk setup. The nonce is the protocol's
/// 96-bit little-endian counter, incremented exactly as before.
///
/// `ring`'s fused AES-GCM pipelines AES-NI, unlike the `aes-gcm` crate (which
/// drives `ctr` one block at a time); measured ~6x faster on this machine for
/// 16 KiB records.
pub struct ShadowsocksCipher {
    key: LessSafeKey,
    nonce: [u8; 12],
    kind: CipherKind,
}

impl ShadowsocksCipher {
    /// Builds the value with the protocol defaults.
    pub fn new(subkey: &[u8]) -> Self {
        Self::with_kind(CipherKind::ChaCha20IetfPoly1305, subkey)
    }

    /// A cipher for `kind`, keyed from `subkey`.
    pub fn with_kind(kind: CipherKind, subkey: &[u8]) -> Self {
        use crate::shadowsocks2022::Ss2022CipherMethod as M;
        let alg = match kind {
            CipherKind::ChaCha20IetfPoly1305 => &CHACHA20_POLY1305,
            CipherKind::Aes256Gcm => &AES_256_GCM,
            CipherKind::Aes128Gcm => &AES_128_GCM,
            // The 2022 methods use the same three primitives with the same tag.
            CipherKind::Ss2022(m) => match m {
                M::Blake3Aes128Gcm => &AES_128_GCM,
                M::Blake3Aes256Gcm => &AES_256_GCM,
                M::Blake3ChaCha20Poly1305 => &CHACHA20_POLY1305,
            },
        };
        let key = UnboundKey::new(alg, subkey).unwrap_or_else(|_| {
            panic!(
                "invalid shadowsocks subkey: {} bytes, {kind:?} wants {}",
                subkey.len(),
                kind.key_len()
            )
        });
        Self {
            key: LessSafeKey::new(key),
            nonce: [0u8; 12],
            kind,
        }
    }

    /// The method this cipher was built for.
    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let n = self.nonce;
        for byte in &mut self.nonce {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        n
    }

    /// Encrypts one piece, advancing the nonce.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce = self.next_nonce();
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        self.seal_in_place(nonce, &mut out)?;
        Ok(out)
    }

    /// Decrypts one piece, advancing the nonce.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce = self.next_nonce();
        let mut out = Vec::with_capacity(ciphertext.len());
        out.extend_from_slice(ciphertext);
        self.open_in_place(nonce, &mut out)?;
        Ok(out)
    }

    /// Encrypts `buffer` in place and appends the tag: no allocation, no copy.
    pub fn encrypt_in_place(&mut self, buffer: &mut Vec<u8>) -> FluxResult<()> {
        let nonce = self.next_nonce();
        self.seal_in_place(nonce, buffer)
    }

    /// Authenticates and decrypts `buffer` in place, truncating it to the
    /// plaintext.
    pub fn decrypt_in_place(&mut self, buffer: &mut Vec<u8>) -> FluxResult<()> {
        let nonce = self.next_nonce();
        self.open_in_place(nonce, buffer)
    }

    /// Seals `buffer[start..]` in place and appends the tag.
    ///
    /// The stream writer uses this to seal the chunk-length prefix and the
    /// payload inside one buffer, so a write costs no allocation and no copy of
    /// the payload.
    /// Seals `buffer[start..]` in place and appends the tag.
    ///
    /// Callers that assemble their own buffer (e.g. `salt || address || payload`
    /// for UDP) use this to avoid a plaintext copy.
    pub fn encrypt_tail(&mut self, buffer: &mut Vec<u8>, start: usize) -> FluxResult<()> {
        let nonce = self.next_nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut buffer[start..],
            )
            .map_err(|_| FluxError::Crypto("shadowsocks encrypt failed".into()))?;
        buffer.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn seal_in_place(&self, nonce: [u8; 12], buffer: &mut Vec<u8>) -> FluxResult<()> {
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), buffer)
            .map_err(|_| FluxError::Crypto("shadowsocks encrypt failed".into()))
    }

    fn open_in_place(&self, nonce: [u8; 12], buffer: &mut Vec<u8>) -> FluxResult<()> {
        let plain_len = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut buffer[..],
            )
            .map_err(|_| FluxError::Crypto("shadowsocks decrypt failed: bad tag".into()))?
            .len();
        buffer.truncate(plain_len);
        Ok(())
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
    write_pos: usize,
    writing_plain_size: usize,
}

impl<S> ShadowsocksStream<S> {
    /// Builds the value with the protocol defaults.
    pub fn new(
        inner: S,
        enc: ShadowsocksCipher,
        dec: Option<ShadowsocksCipher>,
        master_key: &[u8],
    ) -> Self {
        Self::new_with_initial_chunk(inner, enc, dec, master_key, vec![])
    }

    /// Client half, with the first payload chunk already decided.
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
        while self.dec.is_none() {
            let pos = self.salt_pos;
            let salt_len = self.kind.salt_len();
            let mut tmp = vec![0u8; salt_len - pos];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        if self.salt_pos == 0 {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading shadowsocks salt",
                            )));
                        }
                    }
                    self.salt_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                    self.salt_pos += n;
                    if self.salt_pos == salt_len {
                        let subkey = derive_subkey(&self.master_key, &self.salt_buf);
                        self.dec = Some(ShadowsocksCipher::with_kind(self.kind, &subkey));
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Fill what the caller asked for: the relay reads with a 64 KiB buffer and a
        // chunk here is 16 KiB, so returning after one chunk made every buffer four
        // separate read cycles.
        let mut put = 0usize;

        loop {
            // Step 2: If we have decrypted chunk data, drain it into buf
            if self.chunk_pos < self.chunk_data.len() {
                let available = self.chunk_data.len() - self.chunk_pos;
                let to_write = available.min(buf.remaining());
                if to_write > 0 {
                    buf.put_slice(&self.chunk_data[self.chunk_pos..self.chunk_pos + to_write]);
                    self.chunk_pos += to_write;
                    put += to_write;
                    if self.chunk_pos == self.chunk_data.len() {
                        self.chunk_data.clear();
                        self.chunk_pos = 0;
                    }
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
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
                            if self.len_pos == 0 {
                                return Poll::Ready(Ok(())); // Clean EOF
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading shadowsocks chunk length",
                            )));
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
                            if self.payload_buf.len() < target_len {
                                self.payload_buf.resize(target_len, 0);
                            }
                            self.len_pos = 0;
                            self.payload_pos = 0;
                        }
                        continue;
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

            // Step 4: Read encrypted payload chunk via zero-heap stack buffer
            if self.payload_len > 0 {
                let ppos = self.payload_pos;
                let target_len = self.payload_len + TAG_LEN;
                // Read straight into the destination: the stack copy here cost a
                // second copy of every payload byte and capped a read at 16 KiB on
                // top of a 16 KiB chunk.
                let this = self.as_mut().get_mut();
                let mut ptmp_buf = ReadBuf::new(&mut this.payload_buf[ppos..target_len]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut ptmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = ptmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF in Shadowsocks chunk",
                            )));
                        }
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

        // Frame several chunks per call, up to the relay's copy buffer, and write
        // them together: one chunk per call turned a 64 KiB write into four
        // syscalls and four seals.
        let cap = buf.len().min(flux_common::copy::RELAY_BUFFER_BYTES);
        let mut consumed = 0usize;

        let this = self.as_mut().get_mut();
        this.write_buf.clear();
        while consumed < cap {
            let chunk_size = (cap - consumed).min(MAX_PAYLOAD_LEN);
            let plain_chunk = &buf[consumed..consumed + chunk_size];
            let len_bytes = ((chunk_size as u16) & 0x3FFF).to_be_bytes();

            let len_start = this.write_buf.len();
            this.write_buf.extend_from_slice(&len_bytes);
            this.enc
                .encrypt_tail(&mut this.write_buf, len_start)
                .map_err(|e| io::Error::other(e.to_string()))?;

            let payload_start = this.write_buf.len();
            this.write_buf.extend_from_slice(plain_chunk);
            this.enc
                .encrypt_tail(&mut this.write_buf, payload_start)
                .map_err(|e| io::Error::other(e.to_string()))?;
            consumed += chunk_size;
        }

        this.write_pos = 0;
        this.writing_plain_size = consumed;

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

    #[tokio::test]
    async fn test_shadowsocks_truncated_salt_returns_unexpected_eof() {
        let (mut client_raw, server_raw) = tokio::io::duplex(1024);
        let master = derive_master_key("secret123");
        let enc = ShadowsocksCipher::new(&derive_subkey(&master, &[0u8; 32]));
        let mut stream = ShadowsocksStream::new(server_raw, enc, None, &master);

        // Send only 10 bytes of 32-byte salt and close
        client_raw.write_all(&[0x11; 10]).await.unwrap();
        drop(client_raw);

        let mut buf = [0u8; 32];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_shadowsocks_truncated_chunk_len_returns_unexpected_eof() {
        let (mut client_raw, server_raw) = tokio::io::duplex(1024);
        let master = derive_master_key("secret123");
        let enc = ShadowsocksCipher::new(&derive_subkey(&master, &[0u8; 32]));
        let mut stream = ShadowsocksStream::new(server_raw, enc, None, &master);

        // Send full 32-byte salt, followed by only 5 bytes of 18-byte length chunk, then close
        client_raw.write_all(&[0x11; 32]).await.unwrap();
        client_raw.write_all(&[0x22; 5]).await.unwrap();
        drop(client_raw);

        let mut buf = [0u8; 32];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
