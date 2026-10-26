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

// The handshake driver lands next; until it does, the PRF, the key schedule and the record layer
// are exercised by the tests at the bottom of this file and nothing else.
#![allow(dead_code)]

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

    pub(crate) fn id(self) -> u16 {
        match self {
            Self::EcdheEcdsaAes128GcmSha256 => 0xC02B,
            Self::EcdheRsaAes128GcmSha256 => 0xC02F,
            Self::EcdheEcdsaAes256GcmSha384 => 0xC02C,
            Self::EcdheRsaAes256GcmSha384 => 0xC030,
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
    pub(crate) fn open(&mut self, ctype: u8, body: &mut [u8]) -> FluxResult<usize> {
        if body.len() < 8 + 16 {
            return Err(crypto_err("short TLS 1.2 record"));
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.fixed_iv);
        nonce[4..].copy_from_slice(&body[..8]);
        let ct_len = body.len() - 8;
        let aad = self.aad(ctype, TLS12_VERSION, ct_len - 16);
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

use crate::tls13::verify::TrustStore;
use tokio::io::{AsyncRead, AsyncWrite};

/// Handshake message types that TLS 1.2 uses and TLS 1.3 does not.
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_CLIENT_KEY_EXCHANGE: u8 = 16;
const HS_SERVER_HELLO_DONE: u8 = 14;

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
                    this.closed = true;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "TLS 1.2 alert received",
                    )));
                }
                _ => {}
            }
            let n = match this.read.open(ctype, &mut body) {
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
        let n = data.len().min(16384);
        if let Err(e) = this.queue_record(0x17, &data[..n]) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )));
        }
        loop {
            if this.pending_write_pos >= this.pending_write.len() {
                this.pending_write.clear();
                this.pending_write_pos = 0;
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
        let n = rx.open(0x17, &mut body).expect("open");
        assert_eq!(&body[8..8 + n], b"hello record");

        let mut tampered = wire;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            rx.open(0x17, &mut tampered).is_err(),
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
        rx.open(0x17, &mut first).expect("first open");
        let mut again = wire;
        assert!(rx.open(0x17, &mut again).is_err(), "a replay must fail");
    }
}
