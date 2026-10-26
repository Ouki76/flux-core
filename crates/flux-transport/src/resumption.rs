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
