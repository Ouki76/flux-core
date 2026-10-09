use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use flux_types::{FluxError, FluxResult};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

pub const REALITY_INFO: &[u8] = b"REALITY";

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
pub const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x01]; // TLS 1.0 record version
pub const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];
pub const TLS_CLIENT_HELLO: u8 = 0x01;
pub const TLS_SERVER_HELLO: u8 = 0x02;

pub const EXT_SESSION_TICKET: u16 = 0x0023;
pub const EXT_CUSTOM_COMPAT: u16 = 0xffa1;

const MAX_PLAINTEXT_CHUNK: usize = 16384; // 16 KB matching TLS record payload limit
const TLS_RECORD_HEADER_LEN: usize = 5;

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RealityServerConfig {
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<Vec<u8>>,
}

pub struct RealityHandshake;

impl RealityHandshake {
    /// Client-side: perform REALITY authentication with standard TLS 1.3 ClientHello camouflage.
    /// Emulates authentic TLS 1.3 ClientHello, disguising ephemeral X25519 key in Session ID
    /// and encrypted short_id in standard SessionTicket TLS extension.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        mut stream: S,
        cfg: &RealityClientConfig,
    ) -> FluxResult<RealityStream<S>> {
        let server_pub = X25519PublicKey::from(cfg.public_key);
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);

        let shared_secret = client_secret.diffie_hellman(&server_pub);

        // Derive client and server AEAD keys (64 bytes OKM) using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(client_pub.as_bytes()), shared_secret.as_bytes());
        let mut okm = [0u8; 64];
        hk.expand(REALITY_INFO, &mut okm)
            .map_err(|_| FluxError::Crypto("HKDF expansion failed in Reality".into()))?;

        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        client_key.copy_from_slice(&okm[0..32]);
        server_key.copy_from_slice(&okm[32..64]);

        let client_cipher = ChaCha20Poly1305::new_from_slice(&client_key)
            .map_err(|e| FluxError::Crypto(format!("failed to init client cipher: {}", e)))?;
        let server_cipher = ChaCha20Poly1305::new_from_slice(&server_key)
            .map_err(|e| FluxError::Crypto(format!("failed to init server cipher: {}", e)))?;

        // Encrypt auth block: short_id (variable len)
        let nonce = Nonce::from([0u8; 12]);
        let ciphertext = client_cipher
            .encrypt(&nonce, cfg.short_id.as_slice())
            .map_err(|e| FluxError::Crypto(format!("failed to encrypt reality auth: {}", e)))?;

        // Format as authentic RFC 8446 TLS 1.3 ClientHello
        let mut client_hello = Vec::with_capacity(512);

        // 1. Handshake header placeholder: Type (0x01) + 3 bytes length
        client_hello.push(TLS_CLIENT_HELLO);
        client_hello.extend_from_slice(&[0, 0, 0]); // Length placeholder

        // 2. Client Version (TLS 1.2 legacy: 0x03, 0x03)
        client_hello.extend_from_slice(&TLS_VERSION_1_2);

        // 3. Random: 32 bytes
        let mut client_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);
        client_hello.extend_from_slice(&client_random);

        // 4. Session ID: 32 bytes -> Contains client_pub!
        client_hello.push(32);
        client_hello.extend_from_slice(client_pub.as_bytes());

        // 5. Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_CHACHA20_POLY1305_SHA256 (0x1303), TLS_AES_256_GCM_SHA384 (0x1302)
        client_hello.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02]);

        // 6. Compression Methods: [1, 0]
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // 7. Extensions:
        let mut extensions = Vec::with_capacity(256);

        // Extension: server_name (SNI: 0x0000)
        let sni_bytes = cfg.server_name.as_bytes();
        let sni_ext_len = 5 + sni_bytes.len();
        extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes()); // ServerNameList length
        extensions.push(0x00); // HostName type
        extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni_bytes);

        // Extension: supported_versions (0x002b) -> TLS 1.3
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // Extension: SessionTicket (0x0023) disguising encrypted auth ticket
        extensions.extend_from_slice(&EXT_SESSION_TICKET.to_be_bytes());
        extensions.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ciphertext);

        // Append extensions length and extensions
        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        // Fix Handshake Length (bytes 1..4)
        let hs_len = (client_hello.len() - 4) as u32;
        let hs_len_bytes = hs_len.to_be_bytes();
        client_hello[1] = hs_len_bytes[1];
        client_hello[2] = hs_len_bytes[2];
        client_hello[3] = hs_len_bytes[3];

        // Wrap into TLS Record: [0x16, 0x03, 0x01, record_len (2 bytes)]
        let mut record = Vec::with_capacity(5 + client_hello.len());
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&TLS_LEGACY_VERSION);
        record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&client_hello);

        stream.write_all(&record).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        // Read TLS 1.3 ServerHello response: [0x16, 0x03, 0x03, len (2 bytes)] + ServerHello payload
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality server hello header: {}", e))
        })?;

        if header[0] != TLS_RECORD_HANDSHAKE {
            return Err(FluxError::Crypto(
                "invalid TLS handshake in reality response".into(),
            ));
        }

        let resp_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if resp_len > MAX_PLAINTEXT_CHUNK + 1024 {
            return Err(FluxError::Crypto(
                "reality server hello length exceeds maximum TLS record size".into(),
            ));
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality server hello body: {}", e))
        })?;

        // Verify ServerHello Type (0x02)
        if resp_buf.is_empty() || resp_buf[0] != TLS_SERVER_HELLO {
            return Err(FluxError::Crypto(
                "expected TLS ServerHello in reality response".into(),
            ));
        }

        Ok(RealityStream::new(stream, client_cipher, server_cipher))
    }

    /// Server-side: authenticate incoming REALITY client from TLS 1.3 ClientHello camouflage.
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        mut stream: S,
        cfg: &RealityServerConfig,
    ) -> FluxResult<RealityStream<S>> {
        let server_secret = StaticSecret::from(cfg.private_key);

        // 1. Read TLS Record Header (5 bytes)
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality TLS record header: {}", e))
        })?;

        if header[0] != TLS_RECORD_HANDSHAKE {
            return Err(FluxError::Crypto(
                "expected TLS handshake record in reality".into(),
            ));
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len > MAX_PLAINTEXT_CHUNK + 1024 {
            return Err(FluxError::Crypto(
                "reality client hello length exceeds maximum TLS record size".into(),
            ));
        }
        let mut record_buf = vec![0u8; record_len];
        stream.read_exact(&mut record_buf).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality TLS ClientHello: {}", e))
        })?;

        if record_buf.is_empty() || record_buf[0] != TLS_CLIENT_HELLO {
            return Err(FluxError::Crypto(
                "expected TLS ClientHello in reality".into(),
            ));
        }

        // Parse ClientHello to extract Session ID (which contains client_pub)
        if record_buf.len() < 4 + 2 + 32 + 1 + 32 {
            return Err(FluxError::Crypto("reality ClientHello too short".into()));
        }

        let session_id_len = record_buf[4 + 2 + 32] as usize;
        if session_id_len != 32 {
            return Err(FluxError::Crypto(
                "reality ClientHello invalid session id length".into(),
            ));
        }

        let session_id_start = 4 + 2 + 32 + 1;
        let mut client_pub_bytes = [0u8; 32];
        client_pub_bytes.copy_from_slice(&record_buf[session_id_start..session_id_start + 32]);

        // Find SessionTicket extension (0x0023) or legacy compat (0xffa1) in extensions
        let mut pos = session_id_start + 32;
        // Skip cipher suites
        if pos + 2 > record_buf.len() {
            return Err(FluxError::Crypto("truncated cipher suites".into()));
        }
        let cs_len = u16::from_be_bytes([record_buf[pos], record_buf[pos + 1]]) as usize;
        pos += 2 + cs_len;
        // Skip compression methods
        if pos + 1 > record_buf.len() {
            return Err(FluxError::Crypto("truncated compression methods".into()));
        }
        let comp_len = record_buf[pos] as usize;
        pos += 1 + comp_len;

        // Extensions
        if pos + 2 > record_buf.len() {
            return Err(FluxError::Crypto("truncated extensions header".into()));
        }
        let ext_total_len = u16::from_be_bytes([record_buf[pos], record_buf[pos + 1]]) as usize;
        pos += 2;

        let ext_end = pos + ext_total_len;
        let mut auth_ciphertext: Option<Vec<u8>> = None;

        while pos + 4 <= ext_end && pos + 4 <= record_buf.len() {
            let ext_type = u16::from_be_bytes([record_buf[pos], record_buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([record_buf[pos + 2], record_buf[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > record_buf.len() {
                break;
            }
            if ext_type == EXT_SESSION_TICKET || ext_type == EXT_CUSTOM_COMPAT {
                auth_ciphertext = Some(record_buf[pos..pos + ext_len].to_vec());
                break;
            }
            pos += ext_len;
        }

        let ciphertext = auth_ciphertext.ok_or_else(|| {
            FluxError::AuthFailed("missing reality auth ticket extension in TLS ClientHello".into())
        })?;

        // Cryptographic verification
        let client_pub = X25519PublicKey::from(client_pub_bytes);
        let shared_secret = server_secret.diffie_hellman(&client_pub);

        let hk = Hkdf::<Sha256>::new(Some(client_pub.as_bytes()), shared_secret.as_bytes());
        let mut okm = [0u8; 64];
        hk.expand(REALITY_INFO, &mut okm)
            .map_err(|_| FluxError::Crypto("HKDF expansion failed in Reality server".into()))?;

        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        client_key.copy_from_slice(&okm[0..32]);
        server_key.copy_from_slice(&okm[32..64]);

        let client_cipher = ChaCha20Poly1305::new_from_slice(&client_key).map_err(|e| {
            FluxError::Crypto(format!("failed to init client cipher on server: {}", e))
        })?;
        let server_cipher = ChaCha20Poly1305::new_from_slice(&server_key).map_err(|e| {
            FluxError::Crypto(format!("failed to init server cipher on server: {}", e))
        })?;

        let nonce = Nonce::from([0u8; 12]);
        let decrypted_short_id = client_cipher
            .decrypt(&nonce, ciphertext.as_slice())
            .map_err(|_| FluxError::AuthFailed("reality auth tag decryption failed".into()))?;

        // Check if decrypted short_id is permitted
        if !cfg.short_ids.is_empty() && !cfg.short_ids.iter().any(|id| id == &decrypted_short_id) {
            return Err(FluxError::AuthFailed("invalid reality short_id".into()));
        }

        // Format and send authentic TLS 1.3 ServerHello
        let mut server_hello = Vec::with_capacity(128);
        server_hello.push(TLS_SERVER_HELLO);
        server_hello.extend_from_slice(&[0, 0, 0]); // Length placeholder
        server_hello.extend_from_slice(&TLS_VERSION_1_2);

        let mut server_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_random);
        server_hello.extend_from_slice(&server_random);

        // Echo Session ID
        server_hello.push(32);
        server_hello.extend_from_slice(&client_pub_bytes);

        // Selected Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        server_hello.extend_from_slice(&[0x13, 0x03]);
        // Compression: 0x00
        server_hello.push(0x00);

        // Extensions: supported_versions (0x002b) -> TLS 1.3
        let extensions = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        server_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        server_hello.extend_from_slice(&extensions);

        // Fix Handshake Length
        let hs_len = (server_hello.len() - 4) as u32;
        let hs_len_bytes = hs_len.to_be_bytes();
        server_hello[1] = hs_len_bytes[1];
        server_hello[2] = hs_len_bytes[2];
        server_hello[3] = hs_len_bytes[3];

        // Wrap into TLS Record
        let mut record = Vec::with_capacity(5 + server_hello.len());
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&TLS_VERSION_1_2);
        record.extend_from_slice(&(server_hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&server_hello);

        stream.write_all(&record).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        // Server writes with server_cipher, reads with client_cipher
        Ok(RealityStream::new(stream, server_cipher, client_cipher))
    }
}

/// A fully encrypted, authenticated bidirectional stream wrapper for REALITY.
/// Encapsulates application data into authentic TLS 1.3 Application Data records (0x17 0x03 0x03)
/// encrypted with ChaCha20-Poly1305 and strictly sequential nonces.
pub struct RealityStream<S> {
    inner: S,
    enc: ChaCha20Poly1305,
    dec: ChaCha20Poly1305,
    write_seq: u64,
    read_seq: u64,

    // Writer state
    write_buf: Vec<u8>,
    write_pos: usize,
    writing_plain_len: usize,

    // Reader state
    read_header_buf: [u8; TLS_RECORD_HEADER_LEN],
    read_header_pos: usize,
    read_payload_buf: Vec<u8>,
    read_payload_len: usize,
    read_payload_pos: usize,

    // Decrypted plaintext buffer
    plain_buf: Vec<u8>,
    plain_pos: usize,
}

impl<S> RealityStream<S> {
    pub fn new(inner: S, enc: ChaCha20Poly1305, dec: ChaCha20Poly1305) -> Self {
        Self {
            inner,
            enc,
            dec,
            write_seq: 0,
            read_seq: 0,
            write_buf: Vec::with_capacity(MAX_PLAINTEXT_CHUNK + 64),
            write_pos: 0,
            writing_plain_len: 0,
            read_header_buf: [0u8; TLS_RECORD_HEADER_LEN],
            read_header_pos: 0,
            read_payload_buf: Vec::with_capacity(MAX_PLAINTEXT_CHUNK + 64),
            read_payload_len: 0,
            read_payload_pos: 0,
            plain_buf: Vec::with_capacity(MAX_PLAINTEXT_CHUNK),
            plain_pos: 0,
        }
    }

    fn make_nonce(seq: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        Nonce::from(nonce)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            // 1. Drain any previously decrypted plaintext
            if this.plain_pos < this.plain_buf.len() {
                let avail = this.plain_buf.len() - this.plain_pos;
                let to_write = avail.min(buf.remaining());
                buf.put_slice(&this.plain_buf[this.plain_pos..this.plain_pos + to_write]);
                this.plain_pos += to_write;
                if this.plain_pos == this.plain_buf.len() {
                    this.plain_buf.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. Read 5-byte TLS record header: [0x17, 0x03, 0x03, len_hi, len_lo]
            while this.read_header_pos < TLS_RECORD_HEADER_LEN {
                let needed = TLS_RECORD_HEADER_LEN - this.read_header_pos;
                let mut tmp = [0u8; TLS_RECORD_HEADER_LEN];
                let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            if this.read_header_pos == 0 {
                                return Poll::Ready(Ok(())); // Clean EOF
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading TLS record header in REALITY stream",
                            )));
                        }
                        let pos = this.read_header_pos;
                        this.read_header_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.read_header_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let rec_type = this.read_header_buf[0];
            if rec_type != TLS_RECORD_APPLICATION_DATA && rec_type != TLS_RECORD_HANDSHAKE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected TLS record type 0x{:02x} in REALITY stream",
                        rec_type
                    ),
                )));
            }

            this.read_payload_len =
                u16::from_be_bytes([this.read_header_buf[3], this.read_header_buf[4]]) as usize;

            if this.read_payload_len > MAX_PLAINTEXT_CHUNK + 1024 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record payload length exceeds maximum RFC size in REALITY stream",
                )));
            }

            if this.read_payload_buf.len() < this.read_payload_len {
                this.read_payload_buf.resize(this.read_payload_len, 0);
            }

            // 3. Read encrypted payload
            while this.read_payload_pos < this.read_payload_len {
                let needed = this.read_payload_len - this.read_payload_pos;
                let mut tmp = [0u8; 4096];
                let to_read = needed.min(tmp.len());
                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF reading encrypted TLS record payload in REALITY",
                            )));
                        }
                        let pos = this.read_payload_pos;
                        this.read_payload_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.read_payload_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // 4. Decrypt payload
            let nonce = Self::make_nonce(this.read_seq);
            let decrypted = match this
                .dec
                .decrypt(&nonce, &this.read_payload_buf[..this.read_payload_len])
            {
                Ok(p) => p,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("REALITY AEAD decryption failed: {}", e),
                    )));
                }
            };
            this.read_seq = this.read_seq.wrapping_add(1);

            // Reset header/payload positions for next frame
            this.read_header_pos = 0;
            this.read_payload_len = 0;
            this.read_payload_pos = 0;

            this.plain_buf = decrypted;
            this.plain_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // 1. Flush any pending encrypted data
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write encrypted REALITY record",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_written = this.writing_plain_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                return Poll::Ready(Ok(plain_written));
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 2. Encrypt up to MAX_PLAINTEXT_CHUNK
        let chunk_len = buf.len().min(MAX_PLAINTEXT_CHUNK);
        let plain_chunk = &buf[..chunk_len];

        let nonce = Self::make_nonce(this.write_seq);
        let ciphertext = match this.enc.encrypt(&nonce, plain_chunk) {
            Ok(c) => c,
            Err(e) => {
                return Poll::Ready(Err(io::Error::other(format!(
                    "REALITY AEAD encrypt failed: {}",
                    e
                ))));
            }
        };
        this.write_seq = this.write_seq.wrapping_add(1);

        // Prepare TLS record: [0x17, 0x03, 0x03, len (2 bytes)] + ciphertext
        this.write_buf.clear();
        this.write_buf.push(TLS_RECORD_APPLICATION_DATA);
        this.write_buf.extend_from_slice(&TLS_VERSION_1_2);
        this.write_buf
            .extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        this.write_buf.extend_from_slice(&ciphertext);
        this.write_pos = 0;
        this.writing_plain_len = chunk_len;

        // 3. Write immediately to inner stream
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write encrypted REALITY record",
                )));
            }
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_written = this.writing_plain_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                return Poll::Ready(Ok(plain_written));
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
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to flush encrypted REALITY record",
                )));
            }
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
        let this = &mut *self;
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
    async fn test_reality_handshake() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);

        let server_cfg = RealityServerConfig {
            server_names: vec!["www.microsoft.com".into()],
            private_key: server_secret.to_bytes(),
            short_ids: vec![vec![0x01, 0x02, 0x03, 0x04]],
        };

        let client_cfg = RealityClientConfig {
            server_name: "www.microsoft.com".into(),
            public_key: server_public.to_bytes(),
            short_id: vec![0x01, 0x02, 0x03, 0x04],
        };

        let (client_io, server_io) = tokio::io::duplex(4096);

        let srv = tokio::spawn(async move {
            let mut stream = RealityHandshake::server_handshake(server_io, &server_cfg)
                .await
                .unwrap();
            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello server");
            stream.write_all(b"hello client").await.unwrap();
            stream.flush().await.unwrap();
        });

        let cli = tokio::spawn(async move {
            let mut stream = RealityHandshake::client_handshake(client_io, &client_cfg)
                .await
                .unwrap();
            stream.write_all(b"hello server").await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello client");
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}
