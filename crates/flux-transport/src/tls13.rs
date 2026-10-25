//! A minimal TLS 1.3 client: records, key schedule and the stream type.
//!
//! This exists because rustls will not let a caller shape the ClientHello — and the shape of
//! that message is a fingerprint. REALITY needs to place authentication material in
//! `session_id`, and it is the reason this code was written; it is being generalised so the
//! ordinary TLS paths can present the same browser-shaped hello instead of rustls' own.
//!
//! What lives here is the parts that are not REALITY-specific: the cipher-suite table with its
//! HKDF, the traffic-key state, and the record layer with its zero-copy read path. The
//! handshake drivers stay with their transports until they are rewritten in terms of this.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use flux_types::FluxResult;
use hkdf::Hkdf;
use ring::aead::{Aad, Algorithm, LessSafeKey, Nonce as RingNonce, UnboundKey};
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A protocol-level error, with the message the caller sees.
pub(crate) fn crypto_err(msg: impl Into<String>) -> flux_types::FluxError {
    flux_types::FluxError::Protocol {
        protocol: "tls13",
        message: msg.into(),
    }
}

/// TLS record and handshake message types, shared by every handshake driver.
#[allow(dead_code)]
pub(crate) const TLS_HANDSHAKE: u8 = 0x16;
#[allow(dead_code)]
pub(crate) const TLS_ALERT: u8 = 0x15;
#[allow(dead_code)]
pub(crate) const TLS_APPDATA: u8 = 0x17;
#[allow(dead_code)]
pub(crate) const TLS_CCS: u8 = 0x14;
#[allow(dead_code)]
pub(crate) const HS_CLIENT_HELLO: u8 = 1;
#[allow(dead_code)]
pub(crate) const HS_SERVER_HELLO: u8 = 2;
#[allow(dead_code)]
pub(crate) const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
#[allow(dead_code)]
pub(crate) const HS_CERTIFICATE: u8 = 11;
#[allow(dead_code)]
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
#[allow(dead_code)]
pub(crate) const HS_FINISHED: u8 = 20;
#[allow(dead_code)]
pub(crate) const HS_KEY_UPDATE: u8 = 24;
#[allow(dead_code)]
pub(crate) const MAX_TLS_RECORD: usize = 16384;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Tls13Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl Tls13Suite {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub(crate) fn hash_len(&self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }

    pub(crate) fn key_len(&self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            _ => 32,
        }
    }

    pub(crate) fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }

    pub(crate) fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
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

    pub(crate) fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
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

    pub(crate) fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> FluxResult<Vec<u8>> {
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
    pub(crate) fn hkdf_expand_label(
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
    pub(crate) fn derive_secret(
        &self,
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> FluxResult<Vec<u8>> {
        self.hkdf_expand_label(secret, label, transcript_hash, self.hash_len())
    }

    /// The `ring` AEAD algorithm for this suite.
    pub(crate) fn ring_alg(&self) -> &'static Algorithm {
        match self {
            Self::Aes128GcmSha256 => &ring::aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &ring::aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &ring::aead::CHACHA20_POLY1305,
        }
    }

    /// Expands a traffic key into a sealing/opening key. `ring` keeps the whole
    /// expanded key schedule, so this is done once per key, not per record.
    pub(crate) fn new_key(&self, key: &[u8]) -> FluxResult<LessSafeKey> {
        UnboundKey::new(self.ring_alg(), key)
            .map(LessSafeKey::new)
            .map_err(|_| crypto_err("tls13 aead: invalid key length"))
    }

    /// In-place AEAD seal: encrypts `buf` in place and returns the tag.
    pub(crate) fn seal(
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
    pub(crate) fn open(
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

/// Per-direction traffic keys and the record sequence number.
pub(crate) struct TrafficState {
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
    pub(crate) fn new(suite: Tls13Suite, secret: Vec<u8>) -> FluxResult<Self> {
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

    pub(crate) fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    pub(crate) fn encrypt_record(&mut self, content_type: u8, data: &[u8]) -> FluxResult<Vec<u8>> {
        self.encrypt_record_padded(content_type, data, 0)
    }

    /// Encrypts a record, padding the TLSInnerPlaintext with `pad_len` trailing
    /// zeros (RFC 8446 §5.4 legal; used for REALITY target record-size mimicry).
    pub(crate) fn encrypt_record_padded(
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
    pub(crate) fn seal_into(
        &mut self,
        content_type: u8,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> FluxResult<()> {
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

    pub(crate) fn decrypt_record(
        &mut self,
        header: &[u8; 5],
        body: &[u8],
    ) -> FluxResult<(u8, Vec<u8>)> {
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
    pub(crate) fn decrypt_in_place(
        &mut self,
        header: &[u8; 5],
        body: &mut [u8],
    ) -> FluxResult<(u8, usize)> {
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
    pub(crate) fn update(&mut self) -> FluxResult<()> {
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
    pub(crate) inner: S,
    #[allow(dead_code)] // kept for diagnostics/debugging
    pub(crate) suite: Tls13Suite,
    pub(crate) read_state: TrafficState,
    pub(crate) write_state: TrafficState,
    /// Start/length of decrypted application data awaiting consumption. The
    /// plaintext lives *inside* `body_buf` (decrypted in place), so a received
    /// record never needs an allocation or a copy of its payload.
    pub(crate) read_pos: usize,
    pub(crate) read_len: usize,
    /// Partial inbound record assembly.
    pub(crate) hdr_buf: [u8; 5],
    pub(crate) hdr_len: usize,
    /// Record ciphertext (or, once decrypted, its plaintext). Kept at its high
    /// water mark and never `clear()`ed: a `len()`-based reuse check silently
    /// reallocated and re-zeroed 16 KiB per record.
    pub(crate) body_buf: Vec<u8>,
    pub(crate) body_len: usize,
    /// Reusable staging buffer for one outgoing record (header ‖ ciphertext ‖ tag).
    /// Allocated once per connection; a record costs no allocation at all.
    pub(crate) tx_buf: Vec<u8>,
    /// Encrypted records awaiting write to the underlying stream.
    pub(crate) pending_write: Vec<u8>,
    pub(crate) pending_write_pos: usize,
    /// Plaintext bytes whose record is buffered but not yet acknowledged to the
    /// caller (the transport returned `Pending` while writing it).
    pub(crate) pending_unacked: usize,
    pub(crate) closed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls13Stream<S> {
    /// Polls until one full plaintext record payload is available in
    /// `read_buf` (application data), EOF, or an error.
    /// Handles CCS, post-handshake messages (NST/KeyUpdate) and alerts.
    /// Uses persistent partial-read buffers, so it is cancellation-safe.
    pub(crate) fn poll_next_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
    pub(crate) fn process_record(&mut self, header: [u8; 5], len: usize) -> io::Result<Option<()>> {
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
    pub(crate) fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
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
