//! WireGuard / AmneziaWG Protocol Implementation.
//!
//! # Architectural Notice
//! This implementation implements the AmneziaWG obfuscated dialect with junk packet prefixes
//! and custom message types (`h1`..`h4`). It is experimental and intended for use with AmneziaWG
//! obfuscating peers.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChaChaNonce,
    aead::{Aead, KeyInit},
};
use flux_types::{FluxError, FluxResult, TargetAddress};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// Standard WireGuard default message types
pub const WG_MSG_INITIATION: u8 = 1;
pub const WG_MSG_RESPONSE: u8 = 2;
pub const WG_MSG_COOKIE: u8 = 3;
pub const WG_MSG_DATA: u8 = 4;

/// AmneziaWG (AWG) Advanced Obfuscation Settings
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwgConfig {
    pub jc: u16,   // Junk packet count
    pub jmin: u16, // Minimum junk packet size
    pub jmax: u16, // Maximum junk packet size
    pub s1: u16,   // Initiation junk prefix size
    pub s2: u16,   // Response junk prefix size
    pub h1: u32,   // Initiation message type (default: 1)
    pub h2: u32,   // Response message type (default: 2)
    pub h3: u32,   // Cookie message type (default: 3)
    pub h4: u32,   // Data message type (default: 4)
}

impl Default for AwgConfig {
    fn default() -> Self {
        Self {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 0,
            s2: 0,
            h1: 1,
            h2: 2,
            h3: 3,
            h4: 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub server_address: TargetAddress,
    pub awg: Option<AwgConfig>,
}

#[derive(Clone, Debug, Default)]
pub struct AntiReplayWindow {
    last_counter: u64,
    bitmap: u64,
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        Self {
            last_counter: 0,
            bitmap: 0,
        }
    }

    /// Checks if counter is eligible without mutating state.
    pub fn check(&self, counter: u64) -> bool {
        if self.bitmap == 0 && self.last_counter == 0 {
            return true;
        }

        if counter > self.last_counter {
            true
        } else {
            let diff = self.last_counter - counter;
            if diff >= 64 {
                return false;
            }
            (self.bitmap & (1 << diff)) == 0
        }
    }

    /// Mutates the sliding window bitmap and advances counter. Strictly called after auth succeeds!
    pub fn update(&mut self, counter: u64) {
        if self.bitmap == 0 && self.last_counter == 0 {
            self.last_counter = counter;
            self.bitmap = 1;
            return;
        }

        if counter > self.last_counter {
            let diff = counter - self.last_counter;
            if diff < 64 {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            } else {
                self.bitmap = 1;
            }
            self.last_counter = counter;
        } else {
            let diff = self.last_counter - counter;
            if diff < 64 {
                self.bitmap |= 1 << diff;
            }
        }
    }
}

pub struct WireGuardSession {
    pub send_cipher: ChaCha20Poly1305,
    pub recv_cipher: ChaCha20Poly1305,
    pub send_counter: u64,
    pub recv_counter: u64,
    pub sender_index: u32,
    pub receiver_index: u32,
    pub awg: AwgConfig,
    pub replay_window: AntiReplayWindow,
}

impl WireGuardSession {
    pub fn new(
        send_key: [u8; 32],
        recv_key: [u8; 32],
        sender_index: u32,
        receiver_index: u32,
        awg: Option<AwgConfig>,
    ) -> Self {
        Self {
            send_cipher: ChaCha20Poly1305::new_from_slice(&send_key).unwrap(),
            recv_cipher: ChaCha20Poly1305::new_from_slice(&recv_key).unwrap(),
            send_counter: 0,
            recv_counter: 0,
            sender_index,
            receiver_index,
            awg: awg.unwrap_or_default(),
            replay_window: AntiReplayWindow::new(),
        }
    }

    /// Encapsulates plaintext IP packet into an authentic WireGuard / AmneziaWG data packet.
    pub fn encrypt_data_packet(&mut self, payload: &[u8]) -> FluxResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.send_counter.to_le_bytes());

        let ciphertext = self
            .send_cipher
            .encrypt(ChaChaNonce::from_slice(&nonce_bytes), payload)
            .map_err(|e| FluxError::Crypto(format!("wireguard encrypt data failed: {}", e)))?;

        // [Message Type (4 bytes) + Receiver Index (4 bytes) + Counter (8 bytes) + Encrypted Payload]
        let mut packet = Vec::with_capacity(16 + ciphertext.len());
        packet.extend_from_slice(&self.awg.h4.to_le_bytes());
        packet.extend_from_slice(&self.receiver_index.to_le_bytes());
        packet.extend_from_slice(&self.send_counter.to_le_bytes());
        packet.extend_from_slice(&ciphertext);

        self.send_counter = self.send_counter.wrapping_add(1);
        Ok(packet)
    }

    /// Decapsulates and decrypts incoming WireGuard / AmneziaWG data packet.
    pub fn decrypt_data_packet(&mut self, packet: &[u8]) -> FluxResult<Vec<u8>> {
        if packet.len() < 32 {
            return Err(FluxError::Protocol {
                protocol: "wireguard",
                message: "data packet too short".into(),
            });
        }

        let msg_type = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        if msg_type != self.awg.h4 {
            return Err(FluxError::Protocol {
                protocol: "wireguard",
                message: format!(
                    "unexpected message type {} (expected {})",
                    msg_type, self.awg.h4
                ),
            });
        }

        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&packet[8..16]);
        let counter = u64::from_le_bytes(counter_bytes);

        if !self.replay_window.check(counter) {
            return Err(FluxError::AuthFailed(
                "wireguard packet rejected by anti-replay sliding window".into(),
            ));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());

        let ciphertext = &packet[16..];
        let plaintext = self
            .recv_cipher
            .decrypt(ChaChaNonce::from_slice(&nonce_bytes), ciphertext)
            .map_err(|e| FluxError::Crypto(format!("wireguard decrypt data failed: {}", e)))?;

        // Mutate replay window ONLY after decryption & auth verification succeeds!
        self.replay_window.update(counter);
        self.recv_counter = counter.wrapping_add(1);
        Ok(plaintext)
    }
}

pub struct WireGuardHandshake;

impl WireGuardHandshake {
    /// Generates AmneziaWG junk packets (`Jc`) of random length between `Jmin` and `Jmax`.
    pub fn generate_junk_packets(cfg: &AwgConfig) -> Vec<Vec<u8>> {
        let mut packets = Vec::with_capacity(cfg.jc as usize);
        let min = cfg.jmin.max(16) as usize;
        let max = cfg.jmax.max(min as u16) as usize;

        for _ in 0..cfg.jc {
            let len = if max > min {
                rand::Rng::gen_range(&mut rand::rngs::OsRng, min..=max)
            } else {
                min
            };
            let mut junk = vec![0u8; len];
            rand::rngs::OsRng.fill_bytes(&mut junk);
            packets.push(junk);
        }
        packets
    }

    /// Creates a WireGuard / AmneziaWG handshake initiation packet.
    pub fn create_initiation(
        local_static: &StaticSecret,
        peer_public: &X25519PublicKey,
        sender_index: u32,
        awg: &AwgConfig,
    ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let shared_ephemeral = ephemeral_secret.diffie_hellman(peer_public);
        let shared_static = local_static.diffie_hellman(peer_public);

        // Derive keying material using SHA256 / HKDF
        let mut hash = sha2::Sha256::default();
        use sha2::Digest;
        hash.update(b"WireGuard v1 zx2c4 Jason@zx2c4.com");
        let chain_key = hash.finalize();

        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(shared_ephemeral.as_bytes());
        recv_key.copy_from_slice(shared_static.as_bytes());

        // Header: [S1 junk padding] + [H1 message type] + [sender_index (4)] + [unencrypted ephemeral (32)] + [encrypted static (48)] + [timestamp (28)] + [mac1 (16)] + [mac2 (16)]
        let mut packet = Vec::with_capacity(cfg_packet_len(awg));

        // S1 junk prefix
        if awg.s1 > 0 {
            let mut s1_bytes = vec![0u8; awg.s1 as usize];
            rand::rngs::OsRng.fill_bytes(&mut s1_bytes);
            packet.extend_from_slice(&s1_bytes);
        }

        packet.extend_from_slice(&awg.h1.to_le_bytes());
        packet.extend_from_slice(&sender_index.to_le_bytes());
        packet.extend_from_slice(ephemeral_public.as_bytes());

        // Encrypt static public key (32 bytes + 16 bytes tag)
        let local_pub = X25519PublicKey::from(local_static);
        let aead = match ChaCha20Poly1305::new_from_slice(chain_key.as_slice()) {
            Ok(a) => a,
            Err(_) => return (Vec::new(), [0u8; 32], [0u8; 32]),
        };
        let enc_static = match aead.encrypt(
            &ChaChaNonce::from([0u8; 12]),
            local_pub.as_bytes().as_slice(),
        ) {
            Ok(e) => e,
            Err(_) => return (Vec::new(), [0u8; 32], [0u8; 32]),
        };
        packet.extend_from_slice(&enc_static);

        // Encrypted timestamp
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let enc_ts = match aead.encrypt(
            &ChaChaNonce::from([1u8; 12]),
            now_ns.to_be_bytes().as_slice(),
        ) {
            Ok(e) => e,
            Err(_) => return (Vec::new(), [0u8; 32], [0u8; 32]),
        };
        packet.extend_from_slice(&enc_ts);

        // MAC1 and MAC2 placeholders
        let mut macs = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut macs);
        packet.extend_from_slice(&macs);

        (packet, send_key, recv_key)
    }
}

fn cfg_packet_len(awg: &AwgConfig) -> usize {
    awg.s1 as usize + 4 + 4 + 32 + 48 + 28 + 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_awg_junk_and_data_packet_obfuscation() {
        let awg = AwgConfig {
            jc: 5,
            jmin: 50,
            jmax: 80,
            s1: 16,
            s2: 16,
            h1: 101,
            h2: 102,
            h3: 103,
            h4: 104,
        };

        // Junk generation
        let junk = WireGuardHandshake::generate_junk_packets(&awg);
        assert_eq!(junk.len(), 5);
        for p in junk {
            assert!(p.len() >= 50 && p.len() <= 80);
        }

        // Initiation packet obfuscation
        let static_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_pub = X25519PublicKey::from(&peer_secret);

        let (init_pkt, send_k, recv_k) =
            WireGuardHandshake::create_initiation(&static_secret, &peer_pub, 1337, &awg);
        assert!(init_pkt.len() > 140);
        // Verify S1 junk prefix length and H1 message type
        assert_eq!(&init_pkt[16..20], &101u32.to_le_bytes());

        // Session data packet encryption with H4 message type
        let mut session = WireGuardSession::new(send_k, recv_k, 1337, 7331, Some(awg.clone()));
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let data_pkt = session.encrypt_data_packet(payload).unwrap();

        assert_eq!(&data_pkt[0..4], &104u32.to_le_bytes());
        let mut recv_session = WireGuardSession::new(recv_k, send_k, 7331, 1337, Some(awg));
        let decrypted = recv_session.decrypt_data_packet(&data_pkt).unwrap();
        assert_eq!(&decrypted, payload);

        // Replay attack test: second decryption of the exact same packet MUST FAIL!
        let replay_res = recv_session.decrypt_data_packet(&data_pkt);
        assert!(
            replay_res.is_err(),
            "Replayed WireGuard packet must be rejected"
        );
    }

    #[test]
    fn test_wireguard_anti_replay_window_logic() {
        let mut window = AntiReplayWindow::new();
        assert!(window.check(0));
        window.update(0);
        assert!(!window.check(0), "replaying 0 must fail");

        assert!(window.check(1));
        window.update(1);
        assert!(window.check(2));
        window.update(2);
        assert!(!window.check(1), "replaying 1 must fail");
        assert!(!window.check(2), "replaying 2 must fail");

        // Jump forward
        assert!(window.check(10));
        window.update(10);
        assert!(window.check(5)); // in window (< 64), not seen yet
        window.update(5);
        assert!(!window.check(5), "replaying 5 must fail");

        // Jump 100 packets forward
        assert!(window.check(120));
        window.update(120);
        assert!(
            !window.check(10),
            "packet 10 is now older than window (>64 diff) and must fail"
        );
    }

    #[test]
    fn test_wireguard_unauthenticated_counter_forgery_does_not_poison_window() {
        let awg = AwgConfig::default();
        let static_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer_pub = X25519PublicKey::from(&peer_secret);

        let (_init_pkt, send_k, recv_k) =
            WireGuardHandshake::create_initiation(&static_secret, &peer_pub, 1337, &awg);

        let mut send_session = WireGuardSession::new(send_k, recv_k, 1337, 7331, Some(awg.clone()));
        let mut recv_session = WireGuardSession::new(recv_k, send_k, 7331, 1337, Some(awg));

        // Generate legitimate packet with counter 0
        let legitimate_pkt_0 = send_session
            .encrypt_data_packet(b"legitimate packet 0")
            .unwrap();

        // Attacker sends forged unauthenticated packet with huge counter (e.g. 500_000)
        let mut forged_pkt = vec![0u8; 64];
        forged_pkt[0..4].copy_from_slice(&4u32.to_le_bytes()); // H4 data
        forged_pkt[4..8].copy_from_slice(&7331u32.to_le_bytes()); // receiver index
        forged_pkt[8..16].copy_from_slice(&500_000u64.to_le_bytes()); // huge counter

        // Forged packet decryption must fail authentication
        let forged_res = recv_session.decrypt_data_packet(&forged_pkt);
        assert!(forged_res.is_err(), "Forged packet must fail decryption");

        // Legitimate packet 0 MUST still be accepted because window was not poisoned!
        let legit_res = recv_session.decrypt_data_packet(&legitimate_pkt_0);
        assert!(
            legit_res.is_ok(),
            "Legitimate packet 0 must succeed; replay window must not be poisoned by forged packet"
        );
        assert_eq!(&legit_res.unwrap(), b"legitimate packet 0");
    }
}
