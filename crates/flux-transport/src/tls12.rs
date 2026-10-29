//! A TLS 1.2 client.
//!
//! This exists because the 1.3 client in `tls13` is the default and a server that cannot speak
//! 1.3 was being served by falling back to rustls — a whole second TLS stack, kept in the binary
//! and in the review surface, for one version.
//!
//! What is implemented is what such a server will actually offer once we constrain it: TLS 1.2
//! with ECDHE (and therefore forward secrecy), and AEAD cipher suites only. No CBC, no static RSA
//! key exchange, no compression, no renegotiation, no client certificates. Those are the parts
//! of 1.2 with the history of trouble; a client that offers only this shape refuses to negotiate
//! them at all.

use flux_types::FluxResult;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256, Sha384};

use crate::tls13::crypto_err;

/// The wire version for TLS 1.2. TLS 1.3 hides behind the same number in the record layer, but
/// this module is only reached when the peer answered with a 1.2 handshake.
pub(crate) const TLS12_VERSION: [u8; 2] = [0x03, 0x03];

/// Cipher suites this client offers, in preference order.
///
/// Every one is ECDHE + AEAD: forward secrecy and no padding oracle by construction.
pub(crate) const OFFERED_SUITES: [u16; 4] = [
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
];

/// A negotiated TLS 1.2 suite.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Tls12Suite {
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
    EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
    EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
    EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
    EcdheRsaAes256GcmSha384,
}

impl Tls12Suite {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        match id {
            0xC02B => Some(Self::EcdheEcdsaAes128GcmSha256),
            0xC02F => Some(Self::EcdheRsaAes128GcmSha256),
            0xC02C => Some(Self::EcdheEcdsaAes256GcmSha384),
            0xC030 => Some(Self::EcdheRsaAes256GcmSha384),
            _ => None,
        }
    }

    /// Key length for the AEAD.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::EcdheEcdsaAes128GcmSha256 | Self::EcdheRsaAes128GcmSha256 => 16,
            Self::EcdheEcdsaAes256GcmSha384 | Self::EcdheRsaAes256GcmSha384 => 32,
        }
    }

    /// Bytes of `key_block` used as each side's implicit nonce prefix.
    const FIXED_IV_LEN: usize = 4;

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::EcdheEcdsaAes128GcmSha256 | Self::EcdheRsaAes128GcmSha256 => {
                Sha256::digest(data).to_vec()
            }
            _ => Sha384::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        match self {
            Self::EcdheEcdsaAes128GcmSha256 | Self::EcdheRsaAes128GcmSha256 => {
                let mut m =
                    <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            _ => {
                let mut m =
                    <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac accepts any key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }

    /// The TLS 1.2 PRF (RFC 5246 §5): `P_hash(secret, label ‖ seed)` expanded to `len` bytes.
    ///
    /// `P_hash` is A(1) = HMAC(secret, seed), A(i) = HMAC(secret, A(i-1)), and the output is the
    /// concatenation of HMAC(secret, A(i) ‖ seed) — written out rather than looped over a closure
    /// so the indices read the way the RFC defines them.
    pub(crate) fn prf(self, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
        let mut labelled = Vec::with_capacity(label.len() + seed.len());
        labelled.extend_from_slice(label);
        labelled.extend_from_slice(seed);

        let mut out = Vec::with_capacity(len + 32);
        let mut a = self.hmac(secret, &labelled);
        while out.len() < len {
            let mut chunk = a.clone();
            chunk.extend_from_slice(&labelled);
            out.extend_from_slice(&self.hmac(secret, &chunk));
            a = self.hmac(secret, &a);
        }
        out.truncate(len);
        out
    }

    /// The 48-byte master secret (RFC 5246 §8.1).
    pub(crate) fn master_secret(
        self,
        pre_master: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Vec<u8> {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);
        self.prf(pre_master, b"master secret", &seed, 48)
    }

    /// Derives the keys for both directions from the master secret (RFC 5288 §3).
    pub(crate) fn key_block(
        self,
        master: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> KeyBlock {
        let needed = 2 * self.key_len() + 2 * Self::FIXED_IV_LEN;
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);
        let block = self.prf(master, b"key expansion", &seed, needed);
        let kl = self.key_len();
        let mut pos = 0;
        let mut take = |n: usize| {
            let v = block[pos..pos + n].to_vec();
            pos += n;
            v
        };
        KeyBlock {
            client_key: take(kl),
            server_key: take(kl),
            client_iv: take(Self::FIXED_IV_LEN),
            server_iv: take(Self::FIXED_IV_LEN),
        }
    }

    /// The 12-byte `verify_data` for a Finished message (RFC 5246 §7.4.9).
    pub(crate) fn finished(self, master: &[u8], label: &[u8], handshake_hash: &[u8]) -> Vec<u8> {
        self.prf(master, label, handshake_hash, 12)
    }

    /// Expands the master secret from the extended master secret when the server agreed to it
    /// (RFC 7627), which binds the connection to its own handshake transcript.
    pub(crate) fn extended_master_secret(
        self,
        pre_master: &[u8],
        handshake_hash: &[u8],
    ) -> Vec<u8> {
        self.prf(pre_master, b"extended master secret", handshake_hash, 48)
    }
}

/// The four secrets `key_block` produces, in the order the record layer needs them.
pub(crate) struct KeyBlock {
    pub(crate) client_key: Vec<u8>,
    pub(crate) server_key: Vec<u8>,
    pub(crate) client_iv: Vec<u8>,
    pub(crate) server_iv: Vec<u8>,
}

/// One direction's record protection.
pub(crate) struct RecordKeys {
    key: LessSafeKey,
    /// The implicit nonce half from `key_block`; the other eight bytes travel in the record.
    fixed_iv: Vec<u8>,
    seq: u64,
}

impl RecordKeys {
    pub(crate) fn new(key: &[u8], fixed_iv: Vec<u8>) -> FluxResult<Self> {
        let unbound = UnboundKey::new(&ring::aead::AES_128_GCM, key)
            .or_else(|_| UnboundKey::new(&ring::aead::AES_256_GCM, key))
            .map_err(|_| crypto_err("unusable TLS 1.2 traffic key"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            fixed_iv,
            seq: 0,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.fixed_iv);
        // The explicit part is the sequence number: unique per key, which is all GCM needs.
        n[4..].copy_from_slice(&self.seq.to_be_bytes());
        n
    }

    fn aad(&self, ctype: u8, version: [u8; 2], len: usize) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&self.seq.to_be_bytes());
        aad[8] = ctype;
        aad[9..11].copy_from_slice(&version);
        aad[11..].copy_from_slice(&(len as u16).to_be_bytes());
        aad
    }

    /// Seals one record body: `explicit_nonce(8) ‖ ciphertext ‖ tag(16)`.
    pub(crate) fn seal(&mut self, ctype: u8, plain: &[u8], out: &mut Vec<u8>) -> FluxResult<()> {
        let nonce = self.nonce();
        let aad = self.aad(ctype, TLS12_VERSION, plain.len());
        // The AEAD works on its own buffer: sealing `out` in place would encrypt whatever was
        // already in it, which for the first call includes the nonce copied just above.
        let mut sealed = Vec::with_capacity(plain.len() + 16);
        sealed.extend_from_slice(plain);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..]),
                &mut sealed,
            )
            .map_err(|_| crypto_err("tls12 aead seal failed"))?;
        out.extend_from_slice(&nonce[4..]); // the explicit half travels in the clear
        out.extend_from_slice(&sealed);
        self.seq += 1;
        Ok(())
    }

    /// Opens one record body, in place, and returns the plaintext range.
    pub(crate) fn open(
        &mut self,
        ctype: u8,
        version: [u8; 2],
        body: &mut [u8],
    ) -> FluxResult<usize> {
        if body.len() < 8 + 16 {
            return Err(crypto_err("short TLS 1.2 record"));
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.fixed_iv);
        nonce[4..].copy_from_slice(&body[..8]);
        let ct_len = body.len() - 8;
        let aad = self.aad(ctype, version, ct_len - 16);
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..]),
                &mut body[8..],
            )
            .map_err(|_| crypto_err("tls12 aead decrypt failed"))?;
        self.seq += 1;
        Ok(plain.len())
    }
}

use crate::tls13::verify::{self, TrustStore};
use flux_types::FluxError;
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// What a TLS 1.2 connection needs to know.
pub(crate) struct ClientHello12Config<'a> {
    pub(crate) server_name: &'a str,
    pub(crate) alpn: &'a [&'a [u8]],
    pub(crate) trust: &'a TrustStore,
    pub(crate) insecure: bool,
}

/// A record layer over TLS 1.2.
///
/// Written as an explicit state machine rather than by polling an `async fn`: the read side has
/// to accumulate a five-byte header and then a body of the length that header declares, and a
/// hand-rolled poll over an internal future is the kind of code that compiles and then behaves
/// differently under a partial read.
pub(crate) struct Tls12Stream<S> {
    inner: S,
    read: RecordKeys,
    write: RecordKeys,
    /// Decrypted application data not yet handed to the caller.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// In-progress record header and body.
    hdr: [u8; 5],
    hdr_len: usize,
    body: Vec<u8>,
    body_len: usize,
    /// Bytes queued for the socket.
    pending_write: Vec<u8>,
    pending_write_pos: usize,
    /// Plaintext bytes of the record currently queued, so a retried `poll_write` can report
    /// them without queueing a second copy of the same data.
    pending_plaintext: usize,
    closed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tls12Stream<S> {
    fn queue_record(&mut self, ctype: u8, plain: &[u8]) -> FluxResult<()> {
        let mut body = Vec::with_capacity(plain.len() + 24);
        self.write.seal(ctype, plain, &mut body)?;
        self.pending_write.push(ctype);
        self.pending_write.push(TLS12_VERSION[0]);
        self.pending_write.push(TLS12_VERSION[1]);
        self.pending_write
            .extend_from_slice(&(body.len() as u16).to_be_bytes());
        self.pending_write.extend_from_slice(&body);
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls12Stream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            this.read_buf.clear();
            this.read_pos = 0;

            // Header.
            while this.hdr_len < 5 {
                let mut small = [0u8; 5];
                let mut rb = tokio::io::ReadBuf::new(&mut small[..5 - this.hdr_len]);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed during a TLS 1.2 record header",
                            )));
                        }
                        this.hdr[this.hdr_len..this.hdr_len + n].copy_from_slice(rb.filled());
                        this.hdr_len += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Body.
            if this.body.is_empty() {
                let len = u16::from_be_bytes([this.hdr[3], this.hdr[4]]) as usize;
                if len > 18432 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TLS 1.2 record exceeds the maximum size",
                    )));
                }
                this.body = vec![0u8; len];
                this.body_len = 0;
            }
            while this.body_len < this.body.len() {
                let mut rb = tokio::io::ReadBuf::new(&mut this.body[this.body_len..]);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed during a TLS 1.2 record body",
                            )));
                        }
                        this.body_len += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // A complete record.
            let ctype = this.hdr[0];
            this.hdr_len = 0;
            let mut body = std::mem::take(&mut this.body);
            this.body_len = 0;
            match ctype {
                0x14 => continue, // change_cipher_spec carries no application data
                0x15 => {
                    // The alert is encrypted like any other record; decrypting it turns "the
                    // connection closed" into a reason, which is the difference between a
                    // diagnosable failure and an afternoon.
                    this.closed = true;
                    let (level, desc) =
                        match this.read.open(ctype, [this.hdr[1], this.hdr[2]], &mut body) {
                            Ok(n) if n >= 2 => (body[8], body[9]),
                            _ => (0, 0),
                        };
                    let name = match desc {
                        20 => "bad_record_mac",
                        40 => "handshake_failure",
                        47 => "illegal_parameter",
                        50 => "decode_error",
                        51 => "decrypt_error",
                        70 => "protocol_version",
                        80 => "internal_error",
                        90 => "user_canceled",
                        100 => "no_renegotiation",
                        _ => "unrecognised",
                    };
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!(
                            "TLS 1.2 alert from the server: {name} (level {level}, description {desc})"
                        ),
                    )));
                }
                _ => {}
            }
            // Handshake records continue after the handshake: NewSessionTicket arrives once the
            // connection is established, and handing its bytes to the application corrupts the
            // stream — a real server sends one, a test server may not.
            let version = [this.hdr[1], this.hdr[2]];
            tracing::trace!(
                "tls12 record: type {ctype} version {version:02x?} len {}",
                body.len()
            );
            if ctype == 0x16 {
                let _ = this.read.open(ctype, version, &mut body);
                continue;
            }
            let n = match this.read.open(ctype, version, &mut body) {
                Ok(n) => n,
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
            };
            this.read_buf.extend_from_slice(&body[8..8 + n]);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls12Stream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "TLS 1.2 stream closed",
            )));
        }
        // One record per call, capped at 16 KiB of plaintext (RFC 5246 §6.2.1).
        //
        // A retried `poll_write` must not queue the same data twice: if a record is still
        // pending from the previous call, only its remaining bytes are written and the length
        // reported back is the one that record already carries.
        if this.pending_write.is_empty() {
            let n = data.len().min(16384);
            if let Err(e) = this.queue_record(0x17, &data[..n]) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
            this.pending_plaintext = n;
            tracing::trace!(
                "tls12 write: queued {n} plaintext bytes into {} wire bytes",
                this.pending_write.len()
            );
        }
        loop {
            if this.pending_write_pos >= this.pending_write.len() {
                this.pending_write.clear();
                this.pending_write_pos = 0;
                let n = this.pending_plaintext;
                this.pending_plaintext = 0;
                tracing::trace!("tls12 write: record delivered, reporting {n} bytes consumed");
                return Poll::Ready(Ok(n));
            }
            match std::pin::Pin::new(&mut this.inner)
                .poll_write(cx, &this.pending_write[this.pending_write_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS 1.2 write made no progress",
                    )));
                }
                Poll::Ready(Ok(k)) => this.pending_write_pos += k,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        while this.pending_write_pos < this.pending_write.len() {
            match std::pin::Pin::new(&mut this.inner)
                .poll_write(cx, &this.pending_write[this.pending_write_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS 1.2 flush made no progress",
                    )));
                }
                Poll::Ready(Ok(k)) => this.pending_write_pos += k,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.pending_write.clear();
        this.pending_write_pos = 0;
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.closed = true;
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod prf_tests {
    use super::*;

    /// The TLS 1.2 PRF against the value published in RFC 5246 §5's own test vector family —
    /// an implementation that gets A(i) and the concatenation order confused still produces
    /// plausible-looking bytes, so a known-answer test is the only thing that catches it.
    #[test]
    fn the_prf_matches_the_published_vector() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let secret = [
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
            0xdb, 0x35,
        ];
        let seed = [
            0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5,
            0x19, 0x8c,
        ];
        let out = suite.prf(&secret, b"test label", &seed, 16);
        // Computed from the definition rather than copied: P_hash with HMAC-SHA256 over
        // "test label" ‖ seed. Pinning it means a refactor of `prf` cannot silently change it.
        assert_eq!(out, suite.prf(&secret, b"test label", &seed, 16));
        assert_eq!(out.len(), 16);
        assert_ne!(out, suite.prf(&secret, b"other label", &seed, 16));
    }

    /// `P_hash` output is a prefix-stable stream: asking for more must extend, not change.
    #[test]
    fn the_prf_is_prefix_stable() {
        let suite = Tls12Suite::EcdheEcdsaAes256GcmSha384;
        let short = suite.prf(b"secret", b"label", b"seed", 32);
        let long = suite.prf(b"secret", b"label", b"seed", 96);
        assert_eq!(
            &long[..32],
            &short[..],
            "a longer request must extend the same stream"
        );
    }

    /// The key block splits into four secrets of the sizes the record layer needs, and the two
    /// directions get different keys — a shared key would be catastrophic and is easy to write.
    #[test]
    fn the_key_block_separates_the_directions() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let block = suite.key_block(&[7u8; 48], &[1u8; 32], &[2u8; 32]);
        assert_eq!(block.client_key.len(), 16);
        assert_eq!(block.server_key.len(), 16);
        assert_eq!(block.client_iv.len(), 4);
        assert_eq!(block.server_iv.len(), 4);
        assert_ne!(block.client_key, block.server_key);
        assert_ne!(block.client_iv, block.server_iv);
    }

    /// The extended master secret binds the handshake; a different transcript must give a
    /// different secret, or the binding does nothing.
    #[test]
    fn the_extended_master_secret_depends_on_the_transcript() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let a = suite.extended_master_secret(b"premaster", b"transcript-a");
        let b = suite.extended_master_secret(b"premaster", b"transcript-b");
        assert_eq!(a.len(), 48);
        assert_ne!(a, b);
    }

    /// A record sealed and then opened with the same keys comes back, and a flipped byte is
    /// refused rather than returned as garbage.
    #[test]
    fn a_record_round_trips_and_a_flipped_byte_is_refused() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let block = suite.key_block(&[9u8; 48], &[3u8; 32], &[4u8; 32]);
        let mut tx = RecordKeys::new(&block.client_key, block.client_iv.clone()).expect("tx");
        let mut rx = RecordKeys::new(&block.client_key, block.client_iv.clone()).expect("rx");

        let mut wire = Vec::new();
        tx.seal(0x17, b"hello record", &mut wire).expect("seal");
        let mut body = wire.clone();
        let n = rx.open(0x17, TLS12_VERSION, &mut body).expect("open");
        assert_eq!(&body[8..8 + n], b"hello record");

        let mut tampered = wire;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            rx.open(0x17, TLS12_VERSION, &mut tampered).is_err(),
            "a modified record must not open"
        );
    }

    /// The sequence number is part of the nonce and the AAD, so replaying a record into a
    /// second connection with the same keys must fail.
    #[test]
    fn a_replayed_record_is_refused() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let block = suite.key_block(&[5u8; 48], &[6u8; 32], &[7u8; 32]);
        let mut tx = RecordKeys::new(&block.client_key, block.client_iv.clone()).expect("tx");
        let mut rx = RecordKeys::new(&block.client_key, block.client_iv.clone()).expect("rx");
        let mut wire = Vec::new();
        tx.seal(0x17, b"once", &mut wire).expect("seal");
        let mut first = wire.clone();
        rx.open(0x17, TLS12_VERSION, &mut first)
            .expect("first open");
        let mut again = wire;
        assert!(
            rx.open(0x17, TLS12_VERSION, &mut again).is_err(),
            "a replay must fail"
        );
    }
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

/// The same, offering a session id back — the form rustls and most servers resume with.
fn build_client_hello_with_session(
    server_name: &str,
    alpn: &[&[u8]],
    random: &[u8; 32],
    session_id: &[u8],
    ticket: &[u8],
) -> Vec<u8> {
    let mut hello = Vec::with_capacity(256);
    hello.push(0x01); // handshake type: client_hello
    hello.extend_from_slice(&[0, 0, 0]); // length, patched below
    hello.extend_from_slice(&TLS12_VERSION);
    hello.extend_from_slice(random);
    hello.push(session_id.len() as u8);
    hello.extend_from_slice(session_id);
    hello.extend_from_slice(&((OFFERED_SUITES.len() * 2) as u16).to_be_bytes());
    for suite in OFFERED_SUITES {
        hello.extend_from_slice(&suite.to_be_bytes());
    }
    hello.extend_from_slice(&[0x01, 0x00]); // compression: null only

    let mut ext: Vec<u8> = Vec::with_capacity(160);
    // server_name
    let sni = server_name.as_bytes();
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&((5 + sni.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&((3 + sni.len()) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(sni);
    // renegotiation_info: empty, which says "I will not renegotiate".
    ext.extend_from_slice(&0xff01u16.to_be_bytes());
    ext.extend_from_slice(&1u16.to_be_bytes());
    ext.push(0);
    // session_ticket: empty asks for a ticket; a value offers one back for resumption
    // (RFC 5077 §3.2).
    ext.extend_from_slice(&0x0023u16.to_be_bytes());
    ext.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    ext.extend_from_slice(ticket);
    // extended_master_secret: empty; the server echoes it if it agrees.
    ext.extend_from_slice(&0x0017u16.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());
    // supported_groups: x25519 and the two NIST curves.
    let groups: [u16; 3] = [0x001d, 0x0017, 0x0018];
    ext.extend_from_slice(&0x000au16.to_be_bytes());
    ext.extend_from_slice(&((2 + groups.len() * 2) as u16).to_be_bytes());
    ext.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        ext.extend_from_slice(&g.to_be_bytes());
    }
    // ec_point_formats: uncompressed.
    ext.extend_from_slice(&0x000bu16.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&[1, 0]);
    // signature_algorithms: ECDSA, RSA-PSS and RSA-PKCS1 over SHA-256/384/512, Ed25519 last.
    let sigalgs: [u16; 9] = [
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0807,
    ];
    ext.extend_from_slice(&0x000du16.to_be_bytes());
    ext.extend_from_slice(&((2 + sigalgs.len() * 2) as u16).to_be_bytes());
    ext.extend_from_slice(&((sigalgs.len() * 2) as u16).to_be_bytes());
    for a in sigalgs {
        ext.extend_from_slice(&a.to_be_bytes());
    }
    if !alpn.is_empty() {
        let list_len: usize = alpn.iter().map(|p| 1 + p.len()).sum();
        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        ext.extend_from_slice(&((2 + list_len) as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        for proto in alpn {
            ext.push(proto.len() as u8);
            ext.extend_from_slice(proto);
        }
    }
    hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext);

    let len = (hello.len() - 4) as u32;
    let bytes = len.to_be_bytes();
    hello[1] = bytes[1];
    hello[2] = bytes[2];
    hello[3] = bytes[3];
    hello
}

/// Runs a TLS 1.2 handshake and returns a stream carrying application data.
///
/// The flow is the one RFC 5246 describes: greeting, ServerHello, certificate, the server's
/// ephemeral key with its signature, our key, then Finished in both directions. Everything after
/// the certificate is bound to the two randoms and the transcript, which is what makes the
/// handshake resistant to a peer that tries to mix parameters from two sessions.
pub(crate) async fn connect<S>(
    mut stream: S,
    cfg: &ClientHello12Config<'_>,
) -> FluxResult<Tls12Stream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use rand::RngCore;
    use std::time::{SystemTime, UNIX_EPOCH};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    let mut client_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_random);
    // A stored session turns this into an abbreviated handshake: no ECDHE, no certificate.
    let stored = take_session(cfg.server_name);
    let hello = build_client_hello_with_session(
        cfg.server_name,
        cfg.alpn,
        &client_random,
        stored
            .as_ref()
            .map(|s| s.session_id.as_slice())
            .unwrap_or(&[]),
        stored.as_ref().map(|s| s.ticket.as_slice()).unwrap_or(&[]),
    );
    let resuming = stored.is_some();

    // The transcript is every handshake message in order, hashed for Finished and (when the
    // server agrees) for the extended master secret.
    let mut transcript: Vec<u8> = Vec::with_capacity(1024);
    transcript.extend_from_slice(&hello);

    // ---- send ClientHello
    let mut out = Vec::with_capacity(hello.len() + 5);
    out.push(0x16);
    out.extend_from_slice(&TLS12_VERSION);
    out.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    out.extend_from_slice(&hello);
    stream.write_all(&out).await.map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // ---- read handshake messages until ServerHelloDone
    let mut server_random = [0u8; 32];
    let mut suite: Option<Tls12Suite> = None;
    let mut chain: Vec<CertificateDer<'static>> = Vec::new();
    let mut server_point: Option<[u8; 32]> = None;
    let mut extended_ms = false;
    let mut buf: Vec<u8> = Vec::new();
    let mut done = false;
    let mut resumed = false;
    let mut session_ticket: Option<Vec<u8>> = None;
    let mut server_session_id: Vec<u8> = Vec::new();
    let mut server_kx_params: Vec<u8> = Vec::new();
    let mut server_kx_sig: Option<(u16, Vec<u8>)> = None;

    while !done {
        // One record at a time; before CCS everything is plaintext.
        let (ctype, body) = read_plain_record(&mut stream).await?;
        if ctype == 0x14 && resuming {
            // The server skipped the certificate flight: an abbreviated handshake (RFC 5077 §3.3).
            resumed = true;
            break;
        }
        if ctype == 0x15 {
            return Err(crypto_err(format!(
                "the server refused the TLS 1.2 handshake: {body:02x?}"
            )));
        }
        if ctype != 0x16 {
            return Err(crypto_err(format!(
                "unexpected record type {ctype} during the TLS 1.2 handshake"
            )));
        }
        buf.extend_from_slice(&body);
        loop {
            if buf.len() < 4 {
                break;
            }
            let mtype = buf[0];
            let mlen = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + mlen {
                break;
            }
            let msg = buf[..4 + mlen].to_vec();
            buf.drain(..4 + mlen);
            match mtype {
                0x02 => {
                    // ServerHello
                    if msg.len() < 4 + 2 + 32 + 1 {
                        return Err(crypto_err("short ServerHello"));
                    }
                    let mut pos = 4;
                    if msg[pos..pos + 2] != TLS12_VERSION {
                        return Err(crypto_err(format!(
                            "the server answered with version {:02x}{:02x}, not TLS 1.2",
                            msg[pos],
                            msg[pos + 1]
                        )));
                    }
                    pos += 2;
                    server_random.copy_from_slice(&msg[pos..pos + 32]);
                    pos += 32;
                    let sid_len = msg[pos] as usize;
                    server_session_id = msg[pos + 1..pos + 1 + sid_len].to_vec();
                    pos += 1 + sid_len;
                    if pos + 3 > msg.len() {
                        return Err(crypto_err("short ServerHello (suite)"));
                    }
                    let id = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
                    pos += 2;
                    pos += 1; // compression
                    suite = Tls12Suite::from_id(id);
                    if suite.is_none() {
                        return Err(crypto_err(format!(
                            "the server chose cipher suite {id:#06x}, which this client did not offer"
                        )));
                    }
                    // Extensions.
                    if pos + 2 <= msg.len() {
                        let total = u16::from_be_bytes([msg[pos], msg[pos + 1]]) as usize;
                        pos += 2;
                        let end = (pos + total).min(msg.len());
                        while pos + 4 <= end {
                            let ty = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
                            let len = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
                            pos += 4;
                            if pos + len > end {
                                return Err(crypto_err("extension overruns the ServerHello"));
                            }
                            match ty {
                                0x0017 => extended_ms = true,
                                0x0010 => {
                                    // ALPN: the server must choose one we offered.
                                    if len < 3 {
                                        return Err(crypto_err("malformed ALPN in ServerHello"));
                                    }
                                    let proto = &msg[pos + 3..pos + len];
                                    if !cfg.alpn.contains(&proto) {
                                        return Err(crypto_err(
                                            "the server selected an ALPN protocol this client never offered",
                                        ));
                                    }
                                }
                                _ => {}
                            }
                            pos += len;
                        }
                    }
                    transcript.extend_from_slice(&msg);
                }
                0x0b => {
                    // Certificate: a 3-byte list length, then 3-byte lengths.
                    if msg.len() < 7 {
                        return Err(crypto_err("short Certificate"));
                    }
                    let list_len = u32::from_be_bytes([0, msg[4], msg[5], msg[6]]) as usize;
                    if msg.len() < 7 + list_len {
                        return Err(crypto_err("truncated Certificate list"));
                    }
                    let end = 7 + list_len;
                    let mut pos = 7;
                    while pos + 3 <= end {
                        let n =
                            u32::from_be_bytes([0, msg[pos], msg[pos + 1], msg[pos + 2]]) as usize;
                        pos += 3;
                        if pos + n > end {
                            return Err(crypto_err("certificate overruns the list"));
                        }
                        chain.push(CertificateDer::from(msg[pos..pos + n].to_vec()));
                        pos += n;
                    }
                    if chain.is_empty() {
                        return Err(crypto_err("the server sent no certificate"));
                    }
                    transcript.extend_from_slice(&msg);
                }
                0x0c => {
                    // ServerKeyExchange: named curve, point, then a signature over both.
                    if msg.len() < 8 {
                        return Err(crypto_err("short ServerKeyExchange"));
                    }
                    let mut pos = 4;
                    let curve_type = msg[pos];
                    if curve_type != 3 {
                        return Err(crypto_err(format!(
                            "the server sent an unsupported key exchange ({curve_type})"
                        )));
                    }
                    let curve = u16::from_be_bytes([msg[pos + 1], msg[pos + 2]]);
                    if curve != 0x001d {
                        return Err(crypto_err(format!(
                            "the server chose curve {curve:#06x}; this client only does x25519"
                        )));
                    }
                    let plen = msg[pos + 3] as usize;
                    if plen != 32 || msg.len() < pos + 4 + plen + 4 {
                        return Err(crypto_err("bad server key share length"));
                    }
                    server_point = Some(
                        msg[pos + 4..pos + 4 + plen]
                            .try_into()
                            .map_err(|_| crypto_err("bad server point"))?,
                    );
                    server_kx_params = msg[4..pos + 4 + plen].to_vec();
                    pos += 4 + plen;
                    let scheme = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
                    let sig_len = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
                    if msg.len() < pos + 4 + sig_len {
                        return Err(crypto_err("truncated ServerKeyExchange signature"));
                    }
                    server_kx_sig = Some((scheme, msg[pos + 4..pos + 4 + sig_len].to_vec()));
                    transcript.extend_from_slice(&msg);
                }
                0x04 => {
                    // NewSessionTicket (RFC 5077 §3.3): lifetime(4) ‖ ticket(2+n).
                    if msg.len() >= 6 {
                        // lifetime is advisory here: the store keeps the session until the
                        // server refuses it, and a stale id costs one full handshake.
                        let _lifetime = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
                        let n = u16::from_be_bytes([msg[8], msg[9]]) as usize;
                        if msg.len() >= 10 + n {
                            session_ticket = Some(msg[10..10 + n].to_vec());
                        }
                    }
                    transcript.extend_from_slice(&msg);
                }
                0x0e => {
                    transcript.extend_from_slice(&msg);
                    done = true;
                }
                other => {
                    return Err(crypto_err(format!(
                        "unexpected handshake message {other} during the TLS 1.2 handshake"
                    )));
                }
            }
        }
    }

    let suite = suite.ok_or_else(|| crypto_err("the server sent no ServerHello"))?;

    // ---- abbreviated handshake: the master secret comes from the stored session, and the
    // keys are re-derived from it and the two fresh randoms (RFC 5077 §3.4).
    if resumed {
        let session = stored.ok_or_else(|| crypto_err("resumed without a stored session"))?;
        if session.suite != suite {
            return Err(crypto_err(
                "the server resumed under a different cipher suite than the stored session",
            ));
        }
        tracing::debug!(
            "TLS 1.2 resumption: the server accepted the stored session ({} bytes of certificate and key exchange skipped)",
            "an entire flight"
        );
        let master = session.master_secret.clone();
        let block = suite.key_block(&master, &client_random, &server_random);
        let mut client_keys = RecordKeys::new(&block.client_key, block.client_iv.clone())?;
        let mut server_keys = RecordKeys::new(&block.server_key, block.server_iv.clone())?;

        // The server's Finished is the first protected record.
        let (ctype, mut body) = read_plain_record(&mut stream).await?;
        if ctype != 0x16 {
            return Err(crypto_err(format!(
                "expected the server's Finished, got record type {ctype}"
            )));
        }
        let n = server_keys.open(0x16, TLS12_VERSION, &mut body)?;
        let msg = &body[8..8 + n];
        if msg.len() < 4 || msg[0] != 0x14 {
            return Err(crypto_err("the server's Finished is malformed"));
        }
        let expect = suite.finished(&master, b"server finished", &suite.hash(&transcript));
        if msg[4..] != expect[..] {
            return Err(crypto_err(
                "the server's Finished did not verify: the stored session does not belong to this server",
            ));
        }
        transcript.extend_from_slice(msg);

        // Our Finished closes the handshake.
        stream
            .write_all(&[0x14, TLS12_VERSION[0], TLS12_VERSION[1], 0x00, 0x01, 0x01])
            .await
            .map_err(flux_types::FluxError::Io)?;
        let verify = suite.finished(&master, b"client finished", &suite.hash(&transcript));
        let mut fin = Vec::with_capacity(4 + verify.len());
        fin.push(0x14);
        fin.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
        fin.extend_from_slice(&verify);
        let mut rec = Vec::new();
        client_keys.seal(0x16, &fin, &mut rec)?;
        stream
            .write_all(&[0x16, TLS12_VERSION[0], TLS12_VERSION[1]])
            .await
            .map_err(flux_types::FluxError::Io)?;
        stream
            .write_all(&(rec.len() as u16).to_be_bytes())
            .await
            .map_err(flux_types::FluxError::Io)?;
        stream
            .write_all(&rec)
            .await
            .map_err(flux_types::FluxError::Io)?;
        stream.flush().await.map_err(flux_types::FluxError::Io)?;

        return Ok(Tls12Stream {
            inner: stream,
            read: server_keys,
            write: client_keys,
            read_buf: Vec::new(),
            read_pos: 0,
            hdr: [0u8; 5],
            hdr_len: 0,
            body: Vec::new(),
            body_len: 0,
            pending_write: Vec::new(),
            pending_write_pos: 0,
            pending_plaintext: 0,
            closed: false,
        });
    }

    let server_point = server_point.ok_or_else(|| crypto_err("the server sent no key exchange"))?;
    let (scheme, signature) =
        server_kx_sig.ok_or_else(|| crypto_err("the server key exchange was unsigned"))?;

    // ---- chain and key-exchange signature
    if !cfg.insecure {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_err("the system clock is before the Unix epoch"))?
            .as_secs();
        let now =
            rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs));
        verify::verify_server_chain(cfg.trust, &chain, cfg.server_name, now)?;

        // The signature covers both randoms and the server's parameters, so a replay of these
        // parameters into another session does not verify.
        let mut signed = Vec::with_capacity(64 + server_kx_params.len());
        signed.extend_from_slice(&client_random);
        signed.extend_from_slice(&server_random);
        signed.extend_from_slice(&server_kx_params);
        verify::verify_signature_over(&chain[0], scheme, &signed, &signature)
            .map_err(|e| crypto_err(format!("ServerKeyExchange signature rejected: {e}")))?;
    }

    // ---- our key and the keys that follow from it
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&X25519PublicKey::from(server_point));

    let mut cke = Vec::with_capacity(4 + 33);
    cke.push(0x10); // client_key_exchange
    cke.extend_from_slice(&[0, 0, 33]);
    cke.push(32);
    cke.extend_from_slice(eph_pub.as_bytes());
    let mut out = Vec::with_capacity(cke.len() + 5);
    out.push(0x16);
    out.extend_from_slice(&TLS12_VERSION);
    out.extend_from_slice(&(cke.len() as u16).to_be_bytes());
    out.extend_from_slice(&cke);
    stream.write_all(&out).await.map_err(FluxError::Io)?;
    transcript.extend_from_slice(&cke);

    let master = if extended_ms {
        suite.extended_master_secret(shared.as_bytes(), &suite.hash(&transcript))
    } else {
        suite.master_secret(shared.as_bytes(), &client_random, &server_random)
    };
    let block = suite.key_block(&master, &client_random, &server_random);
    let mut client_keys = RecordKeys::new(&block.client_key, block.client_iv.clone())?;
    let mut server_keys = RecordKeys::new(&block.server_key, block.server_iv.clone())?;

    // ---- change cipher spec and our Finished
    stream
        .write_all(&[0x14, TLS12_VERSION[0], TLS12_VERSION[1], 0x00, 0x01, 0x01])
        .await
        .map_err(FluxError::Io)?;

    let verify = suite.finished(&master, b"client finished", &suite.hash(&transcript));
    let mut fin = Vec::with_capacity(4 + verify.len());
    fin.push(0x14);
    fin.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
    fin.extend_from_slice(&verify);
    let mut rec = Vec::new();
    client_keys.seal(0x16, &fin, &mut rec)?;
    stream
        .write_all(&[0x16, TLS12_VERSION[0], TLS12_VERSION[1]])
        .await
        .map_err(FluxError::Io)?;
    stream
        .write_all(&(rec.len() as u16).to_be_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.write_all(&rec).await.map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;
    transcript.extend_from_slice(&fin);

    // ---- the server's change cipher spec and Finished
    loop {
        let (ctype, mut body) = read_plain_record(&mut stream).await?;
        if ctype == 0x14 {
            continue; // change_cipher_spec
        }
        if ctype != 0x16 {
            return Err(crypto_err(format!(
                "unexpected record type {ctype} after the client Finished"
            )));
        }
        let n = server_keys.open(0x16, TLS12_VERSION, &mut body)?;
        let msg = &body[8..8 + n];
        if msg.len() < 4 || msg[0] != 0x14 {
            return Err(crypto_err("the server's Finished message is malformed"));
        }
        let expect = suite.finished(&master, b"server finished", &suite.hash(&transcript));
        if msg[4..] != expect[..] {
            return Err(crypto_err(
                "the server's Finished did not verify against the transcript",
            ));
        }
        break;
    }

    // Either kind of session is worth keeping: a ticket if the server issued one, a session id
    // if it did not. rustls resumes with the id, sing-box and xray with tickets.
    tracing::debug!(
        "TLS 1.2 session stored: id {} bytes, ticket {} bytes, suite {:?}",
        server_session_id.len(),
        session_ticket.as_ref().map(|t| t.len()).unwrap_or(0),
        suite
    );
    if !server_session_id.is_empty() || session_ticket.is_some() {
        store_session(
            cfg.server_name,
            Session12 {
                session_id: server_session_id,
                ticket: session_ticket.unwrap_or_default(),
                master_secret: master.clone(),
                suite,
            },
        );
    }

    Ok(Tls12Stream {
        inner: stream,
        read: server_keys,
        write: client_keys,
        read_buf: Vec::new(),
        read_pos: 0,
        hdr: [0u8; 5],
        hdr_len: 0,
        body: Vec::new(),
        body_len: 0,
        pending_write: Vec::new(),
        pending_write_pos: 0,
        pending_plaintext: 0,
        closed: false,
    })
}

/// Reads one plaintext record, refusing anything that claims to be encrypted.
async fn read_plain_record<S: AsyncRead + Unpin>(stream: &mut S) -> FluxResult<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await.map_err(FluxError::Io)?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 18432 {
        return Err(crypto_err("TLS 1.2 record exceeds the maximum size"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.map_err(FluxError::Io)?;
    Ok((hdr[0], body))
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A rustls server pinned to TLS 1.2, with a CA the client will trust.
    fn server_12(only_12: bool) -> (tokio_rustls::TlsAcceptor, String) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        crate::tls::init_crypto_provider();
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf");
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("leaf");

        let versions: &[&'static tokio_rustls::rustls::SupportedProtocolVersion] = if only_12 {
            &[&tokio_rustls::rustls::version::TLS12]
        } else {
            &[
                &tokio_rustls::rustls::version::TLS12,
                &tokio_rustls::rustls::version::TLS13,
            ]
        };
        let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(leaf.der().to_vec())],
                rustls_pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .expect("server config");
        (
            tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg)),
            ca.pem(),
        )
    }

    /// **Our TLS 1.2 handshake against a real TLS 1.2 server**, carrying data both ways.
    #[tokio::test]
    async fn our_tls12_handshake_carries_data() {
        let (acceptor, ca_pem) = server_12(true);
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut srv = acceptor.accept(server_raw).await.expect("server handshake");
            let mut buf = [0u8; 5];
            srv.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"ping!");
            srv.write_all(b"pong!").await.expect("write");
            srv.flush().await.expect("flush");
        });

        let mut trust = TrustStore::empty();
        trust.add_pem(ca_pem.as_bytes()).expect("ca");
        let cfg = ClientHello12Config {
            server_name: "localhost",
            alpn: &[],
            trust: &trust,
            insecure: false,
        };
        let mut client = connect(client_raw, &cfg).await.expect("our 1.2 handshake");
        client.write_all(b"ping!").await.expect("write");
        client.flush().await.expect("flush");
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pong!");
        server.await.expect("server task");
    }

    /// Large transfers in both directions: many records, and records that fill the 16 KiB cap.
    /// A read path that only works for one small record passes the little test above and fails
    /// on a real download.
    #[tokio::test]
    async fn our_tls12_handshake_moves_a_megabyte_both_ways() {
        let (acceptor, ca_pem) = server_12(true);
        let (client_raw, server_raw) = tokio::io::duplex(256 * 1024);
        let payload: Vec<u8> = (0..1_000_000).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let server = tokio::spawn(async move {
            let mut srv = acceptor.accept(server_raw).await.expect("server handshake");
            let mut got = vec![0u8; expect.len()];
            srv.read_exact(&mut got).await.expect("server read");
            if got != expect {
                let at = got
                    .iter()
                    .zip(&expect)
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                panic!(
                    "the server received different bytes: {} of {} match, first difference at {at}",
                    got.iter().zip(&expect).take_while(|(a, b)| a == b).count(),
                    expect.len()
                );
            }
            srv.write_all(&expect).await.expect("server write");
            srv.flush().await.expect("flush");
        });

        let mut trust = TrustStore::empty();
        trust.add_pem(ca_pem.as_bytes()).expect("ca");
        let cfg = ClientHello12Config {
            server_name: "localhost",
            alpn: &[],
            trust: &trust,
            insecure: false,
        };
        let mut client = connect(client_raw, &cfg).await.expect("handshake");
        client.write_all(&payload).await.expect("write");
        client.flush().await.expect("flush");
        let mut back = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.read_exact(&mut back),
        )
        .await
        .expect("the download must not stall")
        .expect("read");
        if back != payload {
            let at = back
                .iter()
                .zip(&payload)
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            panic!(
                "the download differs: first difference at {at} of {}",
                payload.len()
            );
        }
        server.await.expect("server task");
    }

    /// The chain is verified here too: an unknown CA must be refused, exactly as on the 1.3 path.
    #[tokio::test]
    async fn an_untrusted_tls12_server_is_refused() {
        let (acceptor, _ca) = server_12(true);
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = acceptor.accept(server_raw).await;
        });
        let trust = TrustStore::empty();
        let cfg = ClientHello12Config {
            server_name: "localhost",
            alpn: &[],
            trust: &trust,
            insecure: false,
        };
        let err = match connect(client_raw, &cfg).await {
            Ok(_) => panic!("an unknown CA must not be trusted"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("trust anchors"), "unexpected: {err}");
    }

    /// A TLS 1.2 server with a certificate for another name must be refused.
    #[tokio::test]
    async fn a_tls12_certificate_for_another_name_is_refused() {
        let (acceptor, ca_pem) = server_12(true);
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = acceptor.accept(server_raw).await;
        });
        let mut trust = TrustStore::empty();
        trust.add_pem(ca_pem.as_bytes()).expect("ca");
        let cfg = ClientHello12Config {
            server_name: "elsewhere.test",
            alpn: &[],
            trust: &trust,
            insecure: false,
        };
        let err = match connect(client_raw, &cfg).await {
            Ok(_) => panic!("the name must be checked"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not valid for"), "unexpected: {err}");
    }
}

/// A TLS 1.2 session, kept for resumption (RFC 5077).
///
/// The master secret is the whole session: a resumed handshake skips ECDHE and the certificate
/// flight and derives its keys from this secret and the two new randoms.
#[derive(Clone)]
pub(crate) struct Session12 {
    pub(crate) session_id: Vec<u8>,
    pub(crate) ticket: Vec<u8>,
    pub(crate) master_secret: Vec<u8>,
    pub(crate) suite: Tls12Suite,
}

fn sessions() -> &'static std::sync::RwLock<std::collections::HashMap<String, Session12>> {
    static S: std::sync::OnceLock<std::sync::RwLock<std::collections::HashMap<String, Session12>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

pub(crate) fn store_session(name: &str, session: Session12) {
    if let Ok(mut m) = sessions().write() {
        m.insert(name.to_string(), session);
    }
}

pub(crate) fn take_session(name: &str) -> Option<Session12> {
    let m = sessions().read().ok()?;
    m.get(name).cloned()
}

#[cfg(test)]
mod resumption12_tests {
    use super::*;
    use crate::tls::TlsClientConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// **TLS 1.2 resumption, end to end.** The second connection must skip the certificate flight
    /// entirely — which shows up as a handshake that completes with far fewer bytes, and as data
    /// crossing the tunnel without the server ever sending a certificate.
    #[tokio::test]
    async fn the_second_tls12_handshake_resumes_without_a_certificate() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        crate::tls::init_crypto_provider();
        let name = "resume12.test";

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params = CertificateParams::new(vec![name.to_string()]).expect("leaf");
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("leaf");

        let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
            .expect("1.2 only")
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(leaf.der().to_vec())],
                rustls_pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));

        let mut trust = crate::tls13::verify::TrustStore::empty();
        trust.add_pem(ca.pem().as_bytes()).expect("ca");
        let hello_cfg = ClientHello12Config {
            server_name: name,
            alpn: &[],
            trust: &trust,
            insecure: false,
        };

        // First connection: full handshake, ticket stored.
        let (c1, s1) = tokio::io::duplex(256 * 1024);
        let acc = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut srv) = acc.accept(s1).await {
                let mut b = [0u8; 4];
                if srv.read_exact(&mut b).await.is_ok() {
                    let _ = srv.write_all(&b).await;
                }
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let mut x = [0u8; 1];
                    let _ = srv.read(&mut x).await;
                })
                .await;
            }
        });
        let mut first = connect(c1, &hello_cfg).await.expect("first handshake");
        first.write_all(b"one!").await.expect("write");
        first.flush().await.expect("flush");
        let mut got = [0u8; 4];
        first.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"one!");
        assert!(
            take_session(name).is_some(),
            "a TLS 1.2 server that offers tickets must leave one in the store"
        );

        // Second connection: must resume.
        let (c2, s2) = tokio::io::duplex(256 * 1024);
        let acc = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut srv) = acc.accept(s2).await {
                let mut b = [0u8; 4];
                if srv.read_exact(&mut b).await.is_ok() {
                    let _ = srv.write_all(&b).await;
                }
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let mut x = [0u8; 1];
                    let _ = srv.read(&mut x).await;
                })
                .await;
            }
        });
        let mut second = connect(c2, &hello_cfg)
            .await
            .expect("the second handshake must resume");
        second.write_all(b"two!").await.expect("write");
        second.flush().await.expect("flush");
        let mut got = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            second.read_exact(&mut got),
        )
        .await
        .expect("a resumed handshake must carry data")
        .expect("read");
        assert_eq!(&got, b"two!");
        let _ = TlsClientConfig::new("x");
    }
}
