//! TLS 1.3 session resumption: the tickets a server hands out, and the PSKs derived from them.
//!
//! A ticket is only useful if three things line up: the PSK derived from the ticket nonce, the
//! ticket itself, and the cipher suite that produced them. A store that keeps only the ticket
//! bytes looks right and fails on every real server, because the PSK is what authenticates the
//! client and it is derived, never transmitted.
//!
//! The store is filled by a completed handshake; the reader is the `pre_shared_key` extension on
//! the next one, which lands in the following cycle. Until then the types are exercised by the
//! tests at the bottom of this file and by the ticket-store test in `tls13`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::tls13::{Tls13Suite, crypto_err};
use flux_types::FluxResult;

/// One ticket, with everything needed to turn it back into a PSK.
#[derive(Clone, Debug)]
pub(crate) struct StoredTicket {
    /// `PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`.
    pub(crate) psk: Vec<u8>,
    /// The opaque ticket the server will recognise.
    pub(crate) ticket: Vec<u8>,
    /// The suite that produced it: the PSK means nothing under a different one.
    pub(crate) suite: Tls13Suite,
    /// `ticket_lifetime` from the server, in seconds.
    pub(crate) lifetime: u32,
    /// `ticket_age_add`, added to the client's age so the value the server sees is obfuscated.
    pub(crate) age_add: u32,
    /// When this ticket was received.
    pub(crate) received: Instant,
}

impl StoredTicket {
    /// Whether the ticket is still inside the lifetime the server declared.
    pub(crate) fn is_fresh(&self) -> bool {
        self.received.elapsed() < Duration::from_secs(self.lifetime as u64)
    }

    /// The obfuscated age to put in `pre_shared_key`, in milliseconds (RFC 8446 §4.2.11).
    pub(crate) fn obfuscated_age_millis(&self) -> u32 {
        let real_ms = (self.received.elapsed().as_millis() as u64).min(u32::MAX as u64) as u32;
        real_ms.wrapping_add(self.age_add)
    }
}

/// The process-wide store, keyed by the name the connection was made to.
///
/// Keyed by name rather than by address because a node's address can change while the certificate
/// — and therefore the ticket — does not. The lock is a `RwLock` read on every dial and written
/// once per completed handshake, which is the right shape for a benchmark loop rather than a
/// database.
fn store() -> &'static RwLock<HashMap<String, StoredTicket>> {
    static STORE: OnceLock<RwLock<HashMap<String, StoredTicket>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) fn put(server_name: &str, ticket: StoredTicket) {
    if let Ok(mut map) = store().write() {
        map.insert(server_name.to_string(), ticket);
    }
}

pub(crate) fn get(server_name: &str) -> Option<StoredTicket> {
    let map = store().read().ok()?;
    map.get(server_name).filter(|t| t.is_fresh()).cloned()
}

/// Drops every stored ticket. Used by tests so one connection cannot make another pass.
pub(crate) fn clear() {
    if let Ok(mut map) = store().write() {
        map.clear();
    }
}

/// Parses a `NewSessionTicket` and derives the PSK it implies (RFC 8446 §4.6.1, §7.1).
///
/// `rms` is the resumption master secret from the handshake that issued the ticket.
pub(crate) fn parse_ticket(msg: &[u8], rms: &[u8], suite: Tls13Suite) -> FluxResult<StoredTicket> {
    if msg.len() < 4 + 4 + 1 {
        return Err(crypto_err("short NewSessionTicket"));
    }
    let mut pos = 4; // handshake type and 3-byte length
    let lifetime = u32::from_be_bytes([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]]);
    pos += 4;
    let age_add = u32::from_be_bytes([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]]);
    pos += 4;
    if msg.len() < pos + 1 {
        return Err(crypto_err("truncated ticket nonce length"));
    }
    let nonce_len = msg[pos] as usize;
    pos += 1;
    if msg.len() < pos + nonce_len + 2 {
        return Err(crypto_err("truncated ticket nonce"));
    }
    let nonce = &msg[pos..pos + nonce_len];
    pos += nonce_len;
    if msg.len() < pos + 2 {
        return Err(crypto_err("truncated ticket length"));
    }
    let ticket_len = u16::from_be_bytes([msg[pos], msg[pos + 1]]) as usize;
    pos += 2;
    if msg.len() < pos + ticket_len {
        return Err(crypto_err("truncated ticket body"));
    }
    let ticket = msg[pos..pos + ticket_len].to_vec();
    if ticket.is_empty() {
        return Err(crypto_err("the server sent an empty session ticket"));
    }

    let psk = suite.hkdf_expand_label(rms, "resumption", nonce, suite.hash_len())?;
    tracing::trace!(
        "ticket: suite {:?} nonce {} rms {} psk {}",
        suite,
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        rms.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        psk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );
    Ok(StoredTicket {
        psk,
        ticket,
        suite,
        lifetime,
        age_add,
        received: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket_msg(lifetime: u32, age_add: u32, nonce: &[u8], ticket: &[u8]) -> Vec<u8> {
        let mut m = vec![0x04, 0, 0, 0];
        m.extend_from_slice(&lifetime.to_be_bytes());
        m.extend_from_slice(&age_add.to_be_bytes());
        m.push(nonce.len() as u8);
        m.extend_from_slice(nonce);
        m.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        m.extend_from_slice(ticket);
        let len = (m.len() - 4) as u32;
        m[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        m
    }

    /// The PSK is derived from the nonce, so two tickets from the same session carry different
    /// PSKs — a store that keyed on the ticket alone would resume with the wrong secret.
    #[test]
    fn different_nonces_give_different_psks() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let rms = [7u8; 32];
        let a = parse_ticket(&ticket_msg(7200, 0, b"\x00", b"ticket-a"), &rms, suite).expect("a");
        let b = parse_ticket(&ticket_msg(7200, 0, b"\x01", b"ticket-a"), &rms, suite).expect("b");
        assert_eq!(a.ticket, b.ticket, "the tickets are the same");
        assert_ne!(a.psk, b.psk, "but the PSKs must differ");
        assert_eq!(a.psk.len(), 32);
    }

    /// A ticket outside the server's declared lifetime must not be offered.
    #[test]
    fn an_expired_ticket_is_not_returned() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let mut t = parse_ticket(&ticket_msg(0, 0, b"\x00", b"x"), &[1u8; 32], suite).expect("t");
        put("expired.example", t.clone());
        assert!(
            get("expired.example").is_none(),
            "a zero-lifetime ticket is already expired"
        );
        t.lifetime = 60;
        put("fresh.example", t);
        assert!(get("fresh.example").is_some());
        clear();
    }

    /// The age sent to the server is obfuscated by `ticket_age_add`, but the obfuscation must be
    /// reversible: a constant would make every client look like it connected at the same moment.
    #[test]
    fn the_reported_age_is_obfuscated_by_age_add() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let t = parse_ticket(&ticket_msg(7200, 1234, b"\x00", b"x"), &[1u8; 32], suite).expect("t");
        let age = t.obfuscated_age_millis();
        assert!(
            age >= 1234,
            "the age must include the server's offset: {age}"
        );
        assert!(
            age < 1234 + 60_000,
            "and must not include an absurd elapsed time: {age}"
        );
    }

    /// A truncated ticket is refused rather than stored half-parsed.
    #[test]
    fn a_truncated_ticket_is_refused() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let full = ticket_msg(7200, 0, b"\x00", b"some-ticket-bytes");
        for cut in [0, 3, 8, 12, full.len() - 2] {
            assert!(
                parse_ticket(&full[..cut], &[1u8; 32], suite).is_err(),
                "a {cut}-byte ticket must be refused"
            );
        }
        assert!(parse_ticket(&full, &[1u8; 32], suite).is_ok());
    }
}

/// The key the binder is computed with (RFC 8446 §4.2.11.2):
/// `HKDF-Expand-Label(Early Secret, "res binder", Hash(""), Hash.length)`.
///
/// The early secret is `HKDF-Extract(0, PSK)` — the PSK goes in as the IKM, not as the salt, and
/// swapping the two produces a binder that a server rejects without saying why.
pub(crate) fn binder_key(suite: Tls13Suite, psk: &[u8]) -> FluxResult<Vec<u8>> {
    let zeros = vec![0u8; suite.hash_len()];
    let early = suite.hkdf_extract(&zeros, psk);
    let empty_hash = suite.hash(&[]);
    suite.derive_secret(&early, "res binder", &empty_hash)
}

/// The binder itself: an HMAC over the transcript hash of the *truncated* ClientHello.
///
/// `truncated` must be the ClientHello up to and including the identities field — the binders
/// list, including its two-byte length, is excluded. Including it produces a binder that verifies
/// only against yourself.
pub(crate) fn binder(suite: Tls13Suite, key: &[u8], truncated: &[u8]) -> Vec<u8> {
    suite.hmac(key, &suite.hash(truncated))
}

/// Builds the `pre_shared_key` extension body: identities and one binder.
///
/// `binder` must already be the right length for the suite; the function refuses otherwise rather
/// than emitting a hello the server will drop.
pub(crate) fn pre_shared_key_extension(
    ticket: &StoredTicket,
    binder: &[u8],
    suite: Tls13Suite,
) -> FluxResult<Vec<u8>> {
    if binder.len() != suite.hash_len() {
        return Err(crypto_err(format!(
            "binder is {} bytes but this suite needs {}",
            binder.len(),
            suite.hash_len()
        )));
    }
    if ticket.ticket.len() > u16::MAX as usize {
        return Err(crypto_err("session ticket is too large to offer"));
    }
    let mut ext = Vec::with_capacity(4 + ticket.ticket.len() + 4 + binder.len());
    // identities<7..2^16-1>
    ext.extend_from_slice(&((2 + ticket.ticket.len() + 4) as u16).to_be_bytes());
    ext.extend_from_slice(&(ticket.ticket.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ticket.ticket);
    ext.extend_from_slice(&ticket.obfuscated_age_millis().to_be_bytes());
    // binders<33..2^16-1>: a one-byte length per entry plus the binder itself. Writing
    // `2 + binder.len()` here — the shape of the identities field above — produces a hello a
    // server rejects, because the vector's declared length then includes two bytes that are not
    // in it.
    ext.extend_from_slice(&((1 + binder.len()) as u16).to_be_bytes());
    ext.push(binder.len() as u8);
    ext.extend_from_slice(binder);
    Ok(ext)
}

/// `psk_key_exchange_modes` offering only `psk_dhe_ke` (RFC 8446 §4.2.9).
///
/// Pure PSK without DHE is not offered: it loses forward secrecy, and there is no reason to
/// accept that when every TLS 1.3 server supports the DHE form.
pub(crate) fn psk_modes_extension() -> Vec<u8> {
    vec![1, modes::PSK_DHE_KE]
}

pub(crate) mod modes {
    /// `psk_dhe_ke`: PSK with (EC)DHE key establishment.
    pub(crate) const PSK_DHE_KE: u8 = 1;
}

#[cfg(test)]
mod binder_tests {
    use super::*;

    fn ticket() -> StoredTicket {
        parse_ticket(
            &{
                let mut m = vec![0x04, 0, 0, 0];
                m.extend_from_slice(&7200u32.to_be_bytes());
                m.extend_from_slice(&99u32.to_be_bytes());
                m.push(1);
                m.push(0);
                m.extend_from_slice(&4u16.to_be_bytes());
                m.extend_from_slice(b"tkt!");
                let l = (m.len() - 4) as u32;
                m[1..4].copy_from_slice(&l.to_be_bytes()[1..]);
                m
            },
            &[3u8; 32],
            Tls13Suite::Aes128GcmSha256,
        )
        .expect("ticket")
    }

    /// The binder key depends on the PSK: two tickets from the same session must not produce the
    /// same binder key, or the nonce in the derivation is doing nothing.
    #[test]
    fn the_binder_key_depends_on_the_psk() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let a = binder_key(suite, &[1u8; 32]).expect("a");
        let b = binder_key(suite, &[2u8; 32]).expect("b");
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    /// The binder is over the truncated transcript: a different hello must give a different binder,
    /// which is what stops a client from replaying a binder into a modified greeting.
    #[test]
    fn the_binder_covers_the_transcript() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let key = binder_key(suite, &[1u8; 32]).expect("key");
        let a = binder(suite, &key, b"hello-one");
        let b = binder(suite, &key, b"hello-two");
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "the binder must cover the hello it signs");
    }

    /// An identity carries the obfuscated age with it; a zeroed one would tell the server the
    /// client connected at the Unix epoch.
    #[test]
    fn the_psk_extension_carries_the_ticket_and_its_age() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let t = ticket();
        let ext = pre_shared_key_extension(&t, &[0u8; 32], suite).expect("ext");
        // identities length, ticket length, ticket, age, binders length, binder length, binder.
        let ids_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        assert_eq!(ids_len, 2 + t.ticket.len() + 4);
        assert_eq!(&ext[4..4 + t.ticket.len()], b"tkt!");
        let age = u32::from_be_bytes([
            ext[4 + t.ticket.len()],
            ext[5 + t.ticket.len()],
            ext[6 + t.ticket.len()],
            ext[7 + t.ticket.len()],
        ]);
        assert!(age >= 99, "the age must include the server's offset: {age}");
    }

    /// A binder of the wrong length is refused here rather than by a server that silently
    /// ignores the extension.
    #[test]
    fn a_wrong_length_binder_is_refused() {
        let suite = Tls13Suite::Aes128GcmSha256;
        let t = ticket();
        assert!(pre_shared_key_extension(&t, &[0u8; 16], suite).is_err());
        assert!(pre_shared_key_extension(&t, &[0u8; 32], suite).is_ok());
    }
}
