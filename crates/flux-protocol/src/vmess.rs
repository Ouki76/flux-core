use aes_gcm::{Aes128Gcm, Nonce as AesNonce, aead::Aead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use flux_types::{FluxError, FluxResult, NetworkType, TargetAddress};
use hmac::{Hmac, Mac as _};
use rand::RngCore;
use sha2::Sha256;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

fn create_hmac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as hmac::Mac>::new_from_slice(key).unwrap()
}

pub const VMESS_VERSION: u8 = 1;
pub const VMESS_SECURITY_AES_128_GCM: u8 = 3;
pub const VMESS_SECURITY_CHACHA20_POLY1305: u8 = 4;

pub const VMESS_CMD_TCP: u8 = 1;
pub const VMESS_CMD_UDP: u8 = 2;

pub const VMESS_ATYP_IPV4: u8 = 1;
pub const VMESS_ATYP_DOMAIN: u8 = 2;
pub const VMESS_ATYP_IPV6: u8 = 3;

#[derive(Clone, Debug)]
pub struct VmessRequest {
    pub uuid: Uuid,
    pub command: u8,
    pub address: TargetAddress,
    pub security: u8,
    pub session_key: [u8; 16],
    pub session_iv: [u8; 16],
}

pub struct VmessProtocol;

impl VmessProtocol {
    /// Generates VMess AEAD 16-byte AuthID from user UUID and timestamp.
    pub fn create_auth_id(uuid: &Uuid, timestamp: u64) -> [u8; 16] {
        let mut mac = create_hmac(uuid.as_bytes());
        mac.update(&timestamp.to_be_bytes());
        let full = hmac::Mac::finalize(mac).into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    /// Verifies VMess AEAD 16-byte AuthID against a list of valid user UUIDs.
    pub fn verify_auth_id(auth_id: &[u8; 16], valid_uuids: &[Uuid]) -> Option<(Uuid, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for uuid in valid_uuids {
            // Fast path: check current second first (most common case)
            let expected_now = Self::create_auth_id(uuid, now);
            if expected_now == *auth_id {
                return Some((*uuid, now));
            }

            // Check +/- 120s sliding window without duplicating delta 0
            for delta in 1..=120 {
                let t_add = now.saturating_add(delta);
                if Self::create_auth_id(uuid, t_add) == *auth_id {
                    return Some((*uuid, t_add));
                }
                let t_sub = now.saturating_sub(delta);
                if Self::create_auth_id(uuid, t_sub) == *auth_id {
                    return Some((*uuid, t_sub));
                }
            }
        }
        None
    }

    /// Encodes and writes VMess AEAD request header.
    pub async fn write_request_header<S: AsyncWrite + Unpin>(
        stream: &mut S,
        uuid: &Uuid,
        network: NetworkType,
        destination: &TargetAddress,
        security: u8,
    ) -> FluxResult<([u8; 16], [u8; 16])> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 1. Write 16-byte AuthID
        let auth_id = Self::create_auth_id(uuid, now);
        stream.write_all(&auth_id).await.map_err(FluxError::Io)?;

        // 2. Generate random 16-byte session key & 16-byte session IV
        let mut session_key = [0u8; 16];
        let mut session_iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut session_key);
        rand::rngs::OsRng.fill_bytes(&mut session_iv);

        // 3. Build plain header body
        let mut body = Vec::with_capacity(64);
        body.push(VMESS_VERSION);
        body.extend_from_slice(&session_iv);
        body.extend_from_slice(&session_key);
        body.push(0x55); // Response auth verification byte
        body.push(0x01); // Opt: standard chunked stream
        body.push(0x00); // P = 0 padding
        body.push(security);
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

        // Derive header AEAD key from UUID and auth_id
        let mut mac = create_hmac(uuid.as_bytes());
        mac.update(&auth_id);
        let header_key_bytes = hmac::Mac::finalize(mac).into_bytes();
        let header_aead =
            <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&header_key_bytes[..16]).unwrap();

        // Length encryption
        let len_bytes = (body.len() as u16).to_be_bytes();
        let len_nonce = AesNonce::from([0u8; 12]);
        let len_enc = header_aead
            .encrypt(&len_nonce, len_bytes.as_slice())
            .map_err(|e| FluxError::Crypto(format!("VMess header len encrypt failed: {}", e)))?;

        // Body encryption
        let body_nonce = AesNonce::from([1u8; 12]);
        let body_enc = header_aead
            .encrypt(&body_nonce, body.as_slice())
            .map_err(|e| FluxError::Crypto(format!("VMess header body encrypt failed: {}", e)))?;

        stream.write_all(&len_enc).await.map_err(FluxError::Io)?;
        stream.write_all(&body_enc).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        Ok((session_key, session_iv))
    }

    /// Reads and decodes VMess AEAD request header.
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

        // Derive header AEAD key
        let mut mac = create_hmac(uuid.as_bytes());
        mac.update(&auth_id);
        let header_key_bytes = hmac::Mac::finalize(mac).into_bytes();
        let header_aead =
            <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&header_key_bytes[..16]).unwrap();

        // Read 2-byte encrypted body length + 16-byte tag (18 bytes)
        let mut enc_len = [0u8; 18];
        stream
            .read_exact(&mut enc_len)
            .await
            .map_err(FluxError::Io)?;

        let len_nonce = AesNonce::from([0u8; 12]);
        let len_bytes = header_aead
            .decrypt(&len_nonce, enc_len.as_slice())
            .map_err(|e| FluxError::Crypto(format!("VMess header len decrypt failed: {}", e)))?;
        let body_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

        // Read encrypted body
        let mut enc_body = vec![0u8; body_len + 16];
        stream
            .read_exact(&mut enc_body)
            .await
            .map_err(FluxError::Io)?;

        let body_nonce = AesNonce::from([1u8; 12]);
        let body = header_aead
            .decrypt(&body_nonce, enc_body.as_slice())
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

        let security = body[36];
        let command = body[38];
        let port = u16::from_be_bytes([body[39], body[40]]);
        let atyp = body[41];

        let address = match atyp {
            VMESS_ATYP_IPV4 => {
                if body.len() < 46 {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "truncated vmess ipv4".into(),
                    });
                }
                let ip = Ipv4Addr::new(body[42], body[43], body[44], body[45]);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            VMESS_ATYP_DOMAIN => {
                if body.len() < 43 {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "missing vmess domain length".into(),
                    });
                }
                let dlen = body[42] as usize;
                if dlen == 0 {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "empty vmess domain length".into(),
                    });
                }
                if body.len() < 43 + dlen {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "truncated vmess domain".into(),
                    });
                }
                let domain = std::str::from_utf8(&body[43..43 + dlen])
                    .map_err(|e| FluxError::Protocol {
                        protocol: "vmess",
                        message: format!("invalid utf-8 domain: {}", e),
                    })?
                    .to_string();
                TargetAddress::Domain(domain, port)
            }
            VMESS_ATYP_IPV6 => {
                if body.len() < 58 {
                    return Err(FluxError::Protocol {
                        protocol: "vmess",
                        message: "truncated vmess ipv6".into(),
                    });
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&body[42..58]);
                let ip = Ipv6Addr::from(ip_bytes);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            _ => {
                return Err(FluxError::Protocol {
                    protocol: "vmess",
                    message: format!("unknown vmess atyp: {}", atyp),
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
        })
    }
}

enum VmessCipher {
    Aes128(Box<Aes128Gcm>),
    ChaCha(ChaCha20Poly1305),
}

impl VmessCipher {
    fn new(security: u8, key: &[u8; 16]) -> Self {
        if security == VMESS_SECURITY_CHACHA20_POLY1305 {
            let mut key32 = [0u8; 32];
            key32[..16].copy_from_slice(key);
            key32[16..].copy_from_slice(key);
            Self::ChaCha(
                <ChaCha20Poly1305 as chacha20poly1305::aead::KeyInit>::new_from_slice(&key32)
                    .unwrap(),
            )
        } else {
            Self::Aes128(Box::new(
                <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(key).unwrap(),
            ))
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], plain: &[u8]) -> FluxResult<Vec<u8>> {
        match self {
            Self::Aes128(c) => c.encrypt(AesNonce::from_slice(nonce), plain),
            Self::ChaCha(c) => c.encrypt(ChaChaNonce::from_slice(nonce), plain),
        }
        .map_err(|e| FluxError::Crypto(format!("vmess encrypt failed: {}", e)))
    }

    fn decrypt(&self, nonce: &[u8; 12], cipher: &[u8]) -> FluxResult<Vec<u8>> {
        match self {
            Self::Aes128(c) => c.decrypt(AesNonce::from_slice(nonce), cipher),
            Self::ChaCha(c) => c.decrypt(ChaChaNonce::from_slice(nonce), cipher),
        }
        .map_err(|e| FluxError::Crypto(format!("vmess decrypt failed: {}", e)))
    }
}

fn derive_resp_key_iv(key: &[u8; 16], iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(key);
    let key_hash = hasher.finalize();
    let mut resp_key = [0u8; 16];
    resp_key.copy_from_slice(&key_hash[..16]);

    let mut hasher = sha2::Sha256::new();
    hasher.update(iv);
    let iv_hash = hasher.finalize();
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
    write_seq: u64,
    read_seq: u64,
    is_client: bool,
    header_verified: bool,
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

impl<S> VmessStream<S> {
    pub fn new(inner: S, key: [u8; 16], iv: [u8; 16], security: u8) -> Self {
        Self::new_client(inner, key, iv, security)
    }

    pub fn new_client(inner: S, key: [u8; 16], iv: [u8; 16], security: u8) -> Self {
        let (resp_key, resp_iv) = derive_resp_key_iv(&key, &iv);
        let enc_cipher = VmessCipher::new(security, &key);
        let dec_cipher = VmessCipher::new(security, &resp_key);
        Self {
            inner,
            enc_cipher,
            dec_cipher,
            enc_iv: iv,
            dec_iv: resp_iv,
            write_seq: 0,
            read_seq: 0,
            is_client: true,
            header_verified: false,
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

    pub fn new_server(inner: S, key: [u8; 16], iv: [u8; 16], security: u8) -> Self {
        let (resp_key, resp_iv) = derive_resp_key_iv(&key, &iv);
        let enc_cipher = VmessCipher::new(security, &resp_key);
        let dec_cipher = VmessCipher::new(security, &key);
        Self {
            inner,
            enc_cipher,
            dec_cipher,
            enc_iv: resp_iv,
            dec_iv: iv,
            write_seq: 0,
            read_seq: 0,
            is_client: false,
            header_verified: true,
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

    fn make_nonce(iv: &[u8; 16], seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&iv[0..4]);
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    fn encrypt_chunk(&self, seq: u64, plain: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce_bytes = Self::make_nonce(&self.enc_iv, seq);
        self.enc_cipher.encrypt(&nonce_bytes, plain)
    }

    fn decrypt_chunk(&self, seq: u64, cipher_bytes: &[u8]) -> FluxResult<Vec<u8>> {
        let nonce_bytes = Self::make_nonce(&self.dec_iv, seq);
        self.dec_cipher.decrypt(&nonce_bytes, cipher_bytes)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

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

            // 2. Read 18-byte chunk length + tag (2 bytes len + 16 bytes tag)
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
                                    "unexpected EOF reading vmess chunk length",
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

                let plain_len = match this.decrypt_chunk(this.read_seq, &this.len_buf) {
                    Ok(b) => u16::from_be_bytes([b[0], b[1]]) as usize,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                };
                this.read_seq += 1;
                this.payload_len = plain_len;
                let total_payload = this.payload_len + 16;
                this.payload_buf.resize(total_payload, 0);
                this.payload_pos = 0;
                this.len_pos = 0;
            }

            // 3. Read encrypted payload chunk
            let total_payload = this.payload_len + 16;
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
                    Poll::Pending => return Poll::Pending,
                }
            }

            let mut decrypted = match this.decrypt_chunk(this.read_seq, &this.payload_buf) {
                Ok(b) => b,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
            };
            this.read_seq += 1;

            // Client-side: strip standard VMess AEAD response header (0x55 verification byte)
            if this.is_client && !this.header_verified {
                this.header_verified = true;
                if decrypted.len() >= 4 && decrypted[0] == 0x55 {
                    let cmd_len = decrypted[3] as usize;
                    let hdr_len = 4 + cmd_len;
                    if decrypted.len() >= hdr_len {
                        decrypted = decrypted[hdr_len..].to_vec();
                    }
                }
            }

            this.read_buf = decrypted;
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

        let chunk_size = buf.len().min(16384);
        let plain = &buf[..chunk_size];

        let len_bytes = (chunk_size as u16).to_be_bytes();
        let enc_len = match this.encrypt_chunk(this.write_seq, &len_bytes) {
            Ok(b) => b,
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        };
        this.write_seq += 1;

        let enc_payload = match this.encrypt_chunk(this.write_seq, plain) {
            Ok(b) => b,
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        };
        this.write_seq += 1;

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

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let test_uuid = Uuid::new_v4();
        let target = TargetAddress::domain("example.com", 443);

        let srv = tokio::spawn(async move {
            let req = VmessProtocol::read_request_header(&mut server_io, &[test_uuid])
                .await
                .unwrap();
            assert_eq!(req.uuid, test_uuid);
            assert_eq!(req.address, TargetAddress::domain("example.com", 443));

            let mut stream =
                VmessStream::new_server(server_io, req.session_key, req.session_iv, req.security);
            let mut buf = [0u8; 10];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping vmess");
            stream.write_all(b"pong vmess").await.unwrap();
            stream.flush().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let (key, iv) = VmessProtocol::write_request_header(
                &mut client_io,
                &test_uuid,
                NetworkType::Tcp,
                &target,
                VMESS_SECURITY_AES_128_GCM,
            )
            .await
            .unwrap();

            let mut stream =
                VmessStream::new_client(client_io, key, iv, VMESS_SECURITY_AES_128_GCM);
            stream.write_all(b"ping vmess").await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = [0u8; 10];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong vmess");
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_vmess_short_body_boundary_safe() {
        let test_uuid = Uuid::new_v4();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let auth_id = VmessProtocol::create_auth_id(&test_uuid, now);

        let mut mac = create_hmac(test_uuid.as_bytes());
        mac.update(&auth_id);
        let header_key_bytes = hmac::Mac::finalize(mac).into_bytes();
        let header_aead =
            <Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(&header_key_bytes[..16]).unwrap();

        // Test lengths: 0, 16, 38, 41, 42
        for short_len in [0usize, 16, 38, 41, 42] {
            let mut body = vec![0u8; short_len];
            if short_len == 42 {
                body[41] = VMESS_ATYP_DOMAIN; // triggers domain boundary
            }
            let enc_len = header_aead
                .encrypt(
                    &AesNonce::from([0u8; 12]),
                    (short_len as u16).to_be_bytes().as_slice(),
                )
                .unwrap();
            let enc_body = header_aead
                .encrypt(&AesNonce::from([1u8; 12]), body.as_slice())
                .unwrap();

            let mut wire = Vec::new();
            wire.extend_from_slice(&auth_id);
            wire.extend_from_slice(&enc_len);
            wire.extend_from_slice(&enc_body);

            let mut cursor = std::io::Cursor::new(wire);
            let res = VmessProtocol::read_request_header(&mut cursor, &[test_uuid]).await;
            assert!(res.is_err(), "expected error for short_len {}", short_len);
        }
    }
}
