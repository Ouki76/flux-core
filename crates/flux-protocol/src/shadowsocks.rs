use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use flux_types::{FluxError, FluxResult, TargetAddress};
use crate::socks5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

pub const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 32;

/// Standard Shadowsocks EVP_BytesToKey (MD5) key derivation.
pub fn derive_master_key(password: &str) -> [u8; 32] {
    let mut key = Vec::with_capacity(32);
    let mut prev = Vec::new();
    while key.len() < 32 {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&digest);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&key[..32]);
    out
}

/// Standard Shadowsocks HKDF-SHA1 subkey derivation.
pub fn derive_subkey(master_key: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut okm = [0u8; 32];
    hk.expand(SS_SUBKEY_INFO, &mut okm).expect("HKDF expand failed");
    okm
}

pub struct ShadowsocksCipher {
    cipher: ChaCha20Poly1305,
    nonce: [u8; 12],
}

impl ShadowsocksCipher {
    pub fn new(subkey: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(subkey).expect("valid key len");
        Self {
            cipher,
            nonce: [0u8; 12],
        }
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
        let nonce = self.next_nonce();
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| FluxError::Crypto(format!("shadowsocks encrypt failed: {}", e)))
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce = self.next_nonce();
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| FluxError::Crypto(format!("shadowsocks decrypt failed: {}", e)))
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
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// A stream wrapper that handles Shadowsocks AEAD encryption on writes
/// and decryption on reads.
pub struct ShadowsocksStream<S> {
    inner: S,
    enc: ShadowsocksCipher,
    dec: Option<ShadowsocksCipher>,
    master_key: [u8; 32],
    salt_buf: [u8; SALT_LEN],
    salt_pos: usize,
    // Reader chunk state
    len_buf: [u8; 2 + TAG_LEN],
    len_pos: usize,
    payload_len: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,
    chunk_data: Vec<u8>,
    chunk_pos: usize,
}

impl<S> ShadowsocksStream<S> {
    pub fn new(
        inner: S,
        enc: ShadowsocksCipher,
        dec: Option<ShadowsocksCipher>,
        master_key: [u8; 32],
    ) -> Self {
        Self {
            inner,
            enc,
            dec,
            master_key,
            salt_buf: [0u8; SALT_LEN],
            salt_pos: 0,
            len_buf: [0u8; 2 + TAG_LEN],
            len_pos: 0,
            payload_len: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            chunk_data: Vec::new(),
            chunk_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Step 1: If cipher is not yet initialized (waiting for salt)
        if self.dec.is_none() {
            let pos = self.salt_pos;
            let mut tmp = [0u8; SALT_LEN];
            let mut tmp_buf = ReadBuf::new(&mut tmp[..SALT_LEN - pos]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.salt_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                    self.salt_pos += n;
                    if self.salt_pos == SALT_LEN {
                        let subkey = derive_subkey(&self.master_key, &self.salt_buf);
                        self.dec = Some(ShadowsocksCipher::new(&subkey));
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
                            let dec = self.dec.as_mut().unwrap();
                            let dec_len = dec.decrypt(&len_buf).map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                            })?;
                            self.payload_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;
                            self.len_pos = 0;
                            self.payload_buf = vec![0u8; self.payload_len + TAG_LEN];
                            self.payload_pos = 0;
                        } else {
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Step 4: Read encrypted payload chunk
            if self.payload_len > 0 {
                let ppos = self.payload_pos;
                let target_len = self.payload_len + TAG_LEN;
                let to_read = target_len - ppos;
                let mut ptmp = vec![0u8; to_read];
                let mut ptmp_buf = ReadBuf::new(&mut ptmp);
                match Pin::new(&mut self.inner).poll_read(cx, &mut ptmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = ptmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF in Shadowsocks chunk",
                            )));
                        }
                        self.payload_buf[ppos..ppos + n].copy_from_slice(&ptmp[..n]);
                        self.payload_pos += n;
                        if self.payload_pos == target_len {
                            let payload_buf = std::mem::take(&mut self.payload_buf);
                            let dec = self.dec.as_mut().unwrap();
                            let decrypted = dec.decrypt(&payload_buf).map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                            })?;
                            self.chunk_data = decrypted;
                            self.chunk_pos = 0;
                            self.payload_len = 0;
                            self.payload_pos = 0;
                        } else {
                            return Poll::Pending;
                        }
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
        let chunk_size = buf.len().min(16384);
        let plain_chunk = &buf[..chunk_size];

        let len_bytes = (chunk_size as u16).to_be_bytes();
        let enc_len = self.enc.encrypt(&len_bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
        let enc_data = self.enc.encrypt(plain_chunk).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;

        let mut out = Vec::with_capacity(enc_len.len() + enc_data.len());
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&enc_data);

        match Pin::new(&mut self.inner).poll_write(cx, &out) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(chunk_size)),
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
}
