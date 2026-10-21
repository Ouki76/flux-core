//! Salamander obfuscation — the packet obfuscator used by Hysteria 2
//! (`obfs: salamander`).
//!
//! # Wire format
//!
//! Every datagram is transformed as:
//!
//! ```text
//! [ salt: 8 bytes ][ ciphertext: N bytes ]
//! ciphertext = plaintext XOR keystream
//! keystream  = BLAKE2b-256(psk ‖ salt) repeated to N bytes
//! ```
//!
//! This matches the reference implementation (`hysteria/core/.../obfs/salamander.go`,
//! also implemented by sing-box/Xray): an **8-byte** salt and an **unkeyed
//! BLAKE2b-256** digest of `psk ‖ salt` expanded by repeating the 32-byte key.
//! Getting either detail wrong yields a datagram stream that no other
//! implementation can read, so both sides must agree exactly.
//!
//! This type is shared by the QUIC runtime wrapper (`flux-transport::quic_obfs`,
//! which obfuscates every UDP datagram underneath quinn) and by the protocol
//! codec, so there is exactly one implementation of the cipher.

use blake2::Blake2b;
use blake2::digest::{Digest, consts::U32};

/// Length of the per-datagram random salt, in bytes (reference: `SaltLength = 8`).
pub const SALAMANDER_SALT_LEN: usize = 8;

const KEY_LEN: usize = 32;

/// Salamander obfuscator keyed by the configured password.
///
/// The password bytes are used verbatim as the PSK (the reference implementation
/// requires at least 4 bytes and does not hash them).
#[derive(Clone)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the PSK.
        f.debug_struct("Salamander")
            .field("psk", &"<redacted>")
            .finish()
    }
}

impl Salamander {
    /// Creates an obfuscator from a password.
    ///
    /// # Errors
    /// Returns an error when the password is shorter than 4 bytes, which the
    /// reference implementation also rejects.
    pub fn new(password: &str) -> Result<Self, &'static str> {
        if password.len() < 4 {
            return Err("salamander: password must be at least 4 bytes");
        }
        Ok(Self {
            psk: password.as_bytes().to_vec(),
        })
    }

    /// Expands the per-datagram keystream into `out` (XORed with nothing).
    fn keystream(psk: &[u8], salt: &[u8], out: &mut [u8]) {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(psk);
        hasher.update(salt);
        let key = hasher.finalize();
        for (i, b) in out.iter_mut().enumerate() {
            *b = key[i % KEY_LEN];
        }
    }

    /// Obfuscates `plaintext` into `out`, prepending a fresh random salt.
    ///
    /// `out` must be at least `plaintext.len() + SALAMANDER_SALT_LEN` bytes long;
    /// it is resized to exactly that length.
    pub fn obfuscate_into(&self, plaintext: &[u8], out: &mut Vec<u8>) {
        use rand::RngCore;
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        out.clear();
        out.reserve(SALAMANDER_SALT_LEN + plaintext.len());
        out.extend_from_slice(&salt);

        let start = out.len();
        out.resize(start + plaintext.len(), 0);
        Self::keystream(&self.psk, &salt, &mut out[start..]);
        for (o, p) in out[start..].iter_mut().zip(plaintext.iter()) {
            *o ^= p;
        }
    }

    /// Obfuscates into a freshly allocated buffer.
    pub fn obfuscate(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + plaintext.len());
        self.obfuscate_into(plaintext, &mut out);
        out
    }

    /// Deobfuscates a datagram in place, returning the plaintext length.
    ///
    /// `len` is the number of valid bytes in `buf`. The plaintext is moved to
    /// the front of `buf`. Returns `None` for a datagram shorter than the salt
    /// (which cannot be a Salamander packet).
    /// Deobfuscates `buf[..len]` in place.
    ///
    /// # Panics
    ///
    /// If `len > buf.len()`. Callers in the receive path clamp `len` against the
    /// buffer size; the assertion makes a future caller fail loudly instead of
    /// reading past the end.
    pub fn deobfuscate_in_place(&self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < SALAMANDER_SALT_LEN {
            return None;
        }
        // Copy the salt out first: the destination range overlaps it.
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        salt.copy_from_slice(&buf[..SALAMANDER_SALT_LEN]);

        let plain_len = len - SALAMANDER_SALT_LEN;
        let mut key = [0u8; KEY_LEN];
        Self::keystream(&self.psk, &salt, &mut key);
        for i in 0..plain_len {
            buf[i] = buf[SALAMANDER_SALT_LEN + i] ^ key[i % KEY_LEN];
        }
        Some(plain_len)
    }

    /// Deobfuscates into a freshly allocated buffer.
    pub fn deobfuscate(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut buf = data.to_vec();
        let len = self.deobfuscate_in_place(&mut buf, data.len())?;
        buf.truncate(len);
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = Salamander::new("salamander-secret").unwrap();
        for len in [0usize, 1, 7, 8, 32, 1400] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let wire = s.obfuscate(&plain);
            assert_eq!(wire.len(), plain.len() + SALAMANDER_SALT_LEN);
            let out = s.deobfuscate(&wire).expect("must decode");
            assert_eq!(out, plain, "roundtrip failed at len {len}");
        }
    }

    #[test]
    fn keystream_matches_blake2b_of_psk_and_salt() {
        // Reference vector: the keystream is BLAKE2b-256(psk ‖ salt) repeated.
        let s = Salamander::new("0123456789abcdef").unwrap();
        let salt = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let mut expected = [0u8; 64];
        Salamander::keystream(&s.psk, &salt, &mut expected);
        for i in 32..64 {
            assert_eq!(expected[i], expected[i - 32], "keystream must repeat");
        }
        // Independent computation.
        let mut h = Blake2b::<U32>::new();
        h.update(b"0123456789abcdef");
        h.update(salt);
        let digest = h.finalize();
        assert_eq!(&expected[..32], digest.as_slice());
    }

    #[test]
    fn each_datagram_gets_a_fresh_salt() {
        let s = Salamander::new("salamander-secret").unwrap();
        let a = s.obfuscate(b"same plaintext");
        let b = s.obfuscate(b"same plaintext");
        assert_ne!(a[..SALAMANDER_SALT_LEN], b[..SALAMANDER_SALT_LEN]);
        assert_ne!(
            a, b,
            "identical ciphertext would leak equality of datagrams"
        );
    }

    #[test]
    fn wrong_password_does_not_recover_plaintext() {
        let good = Salamander::new("right-password").unwrap();
        let bad = Salamander::new("wrong-password").unwrap();
        let wire = good.obfuscate(b"payload that must stay secret");
        let out = bad.deobfuscate(&wire).unwrap();
        assert_ne!(out, b"payload that must stay secret");
    }

    #[test]
    fn runt_datagram_is_rejected() {
        let s = Salamander::new("salamander-secret").unwrap();
        assert!(s.deobfuscate(&[0u8; SALAMANDER_SALT_LEN - 1]).is_none());
        // Exactly a salt, no payload: a valid (empty) packet.
        assert_eq!(s.deobfuscate(&[0u8; SALAMANDER_SALT_LEN]), Some(vec![]));
    }

    #[test]
    fn short_password_is_rejected() {
        assert!(Salamander::new("abc").is_err());
        assert!(Salamander::new("").is_err());
    }
}
