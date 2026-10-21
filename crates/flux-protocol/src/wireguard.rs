//! WireGuard / AmneziaWG Protocol Implementation.
//!
//! # Architectural Notice
//! This implementation implements the AmneziaWG obfuscated dialect with junk packet prefixes
//! and custom message types (`h1`..`h4`). It is experimental and intended for use with AmneziaWG
//! obfuscating peers.

use blake2::digest::typenum::U16;
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChaChaNonce,
    aead::{Aead, AeadInPlace, KeyInit},
};
use flux_types::{FluxError, FluxResult, TargetAddress};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn blake2s_hash_concat(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(label);
    hasher.update(data);
    hasher.finalize().into()
}

fn blake2s_mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("Blake2sMac valid key");
    Mac::update(&mut m, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Blake2s256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    let mut inner = Blake2s256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn kdf1(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let t0 = hmac_blake2s(key, data);
    hmac_blake2s(&t0, &[0x01])
}

fn kdf2(key: &[u8; 32], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac_blake2s(key, data);
    let t1 = hmac_blake2s(&t0, &[0x01]);
    let mut t2_in = [0u8; 33];
    t2_in[..32].copy_from_slice(&t1);
    t2_in[32] = 0x02;
    let t2 = hmac_blake2s(&t0, &t2_in);
    (t1, t2)
}

fn kdf3(key: &[u8; 32], data: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = hmac_blake2s(key, data);
    let t1 = hmac_blake2s(&t0, &[0x01]);
    let mut t2_in = [0u8; 33];
    t2_in[..32].copy_from_slice(&t1);
    t2_in[32] = 0x02;
    let t2 = hmac_blake2s(&t0, &t2_in);
    let mut t3_in = [0u8; 33];
    t3_in[..32].copy_from_slice(&t2);
    t3_in[32] = 0x03;
    let t3 = hmac_blake2s(&t0, &t3_in);
    (t1, t2, t3)
}

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
    /// Local tunnel IP address used as the source address of encapsulated IP packets.
    /// Defaults to 10.0.0.2 (or fd00::2 for IPv6 destinations) when not configured.
    pub local_address: Option<std::net::IpAddr>,
    /// Persistent keepalive interval in seconds (WireGuard NAT keepalive). Default: 25.
    pub keepalive_secs: Option<u64>,
    pub awg: Option<AwgConfig>,
}

/// Seconds after session establishment when a new handshake is initiated (RFC: REKEY_AFTER_TIME).
pub const WG_REKEY_AFTER_TIME_SECS: u64 = 120;
/// Seconds after which a session is considered dead even without traffic (RFC: REJECT_AFTER_TIME).
pub const WG_REJECT_AFTER_TIME_SECS: u64 = 180;
/// Default persistent keepalive interval.
pub const WG_DEFAULT_KEEPALIVE_SECS: u64 = 25;
/// On-wire WireGuard data-packet header: `type(4) + receiver_index(4) + counter(8)`.
pub const WG_DATA_HEADER_LEN: usize = 16;
/// Poly1305 authentication tag appended to every data packet.
pub const WG_AEAD_TAG_LEN: usize = 16;

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
        let mut packet = Vec::new();
        self.encrypt_data_packet_into(payload, &mut packet)?;
        Ok(packet)
    }

    /// Same as [`Self::encrypt_data_packet`] but reuses `out`, which keeps the
    /// datapath allocation-free after the first packet on a buffer pool.
    pub fn encrypt_data_packet_into(
        &mut self,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> FluxResult<()> {
        out.clear();
        out.reserve(WG_DATA_HEADER_LEN + payload.len() + WG_AEAD_TAG_LEN);
        out.resize(WG_DATA_HEADER_LEN + payload.len() + WG_AEAD_TAG_LEN, 0);
        out[WG_DATA_HEADER_LEN..WG_DATA_HEADER_LEN + payload.len()].copy_from_slice(payload);
        self.seal_data_packet_in_place(out, payload.len())
    }

    /// Encrypts a data packet whose plaintext is already placed inside `packet`,
    /// turning the buffer into a wire-ready datagram without any allocation or
    /// copy.
    ///
    /// Layout contract (this is the only layout the datapath uses):
    /// `[type 4][receiver 4][counter 8][plaintext @ 16 .. 16+plaintext_len][tag 16]`,
    /// i.e. `packet.len() == 16 + plaintext_len + 16`, with the sender's plaintext
    /// already written at offset 16.
    pub fn seal_data_packet_in_place(
        &mut self,
        packet: &mut [u8],
        plaintext_len: usize,
    ) -> FluxResult<()> {
        debug_assert_eq!(
            packet.len(),
            WG_DATA_HEADER_LEN + plaintext_len + WG_AEAD_TAG_LEN
        );
        let counter = self.send_counter;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());

        packet[0..4].copy_from_slice(&self.awg.h4.to_le_bytes());
        packet[4..8].copy_from_slice(&self.receiver_index.to_le_bytes());
        packet[8..16].copy_from_slice(&counter.to_le_bytes());

        let (body, tag_out) = packet[WG_DATA_HEADER_LEN..].split_at_mut(plaintext_len);
        let tag = self
            .send_cipher
            .encrypt_in_place_detached(ChaChaNonce::from_slice(&nonce_bytes), b"", body)
            .map_err(|e| FluxError::Crypto(format!("wireguard encrypt data failed: {}", e)))?;
        tag_out.copy_from_slice(&tag);

        self.send_counter = counter.wrapping_add(1);
        Ok(())
    }

    /// Decapsulates and decrypts incoming WireGuard / AmneziaWG data packet.
    pub fn decrypt_data_packet(&mut self, packet: &[u8]) -> FluxResult<Vec<u8>> {
        let mut owned = packet.to_vec();
        let range = self.open_data_packet_in_place(&mut owned)?;
        Ok(owned[range].to_vec())
    }

    /// Decapsulates and decrypts an incoming data packet **in place**: the
    /// buffer `packet[..packet_len]` holds the datagram on entry and the
    /// plaintext on success, at the returned range.
    ///
    /// This is the datapath variant: it costs one AEAD pass and no allocation,
    /// where [`Self::decrypt_data_packet`] additionally copies the buffer in and
    /// the plaintext out.
    pub fn open_data_packet_in_place(
        &mut self,
        packet: &mut [u8],
    ) -> FluxResult<std::ops::Range<usize>> {
        let packet_len = packet.len();
        if packet_len < WG_DATA_HEADER_LEN + WG_AEAD_TAG_LEN {
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

        let body_len = packet_len - WG_DATA_HEADER_LEN - WG_AEAD_TAG_LEN;
        let (body, tag) = packet[WG_DATA_HEADER_LEN..].split_at_mut(body_len);
        let mut tag_arr = [0u8; WG_AEAD_TAG_LEN];
        tag_arr.copy_from_slice(tag);
        self.recv_cipher
            .decrypt_in_place_detached(
                ChaChaNonce::from_slice(&nonce_bytes),
                b"",
                body,
                chacha20poly1305::Tag::from_slice(&tag_arr),
            )
            .map_err(|e| FluxError::Crypto(format!("wireguard decrypt data failed: {}", e)))?;

        // Mutate replay window ONLY after decryption & auth verification succeeds!
        self.replay_window.update(counter);
        self.recv_counter = counter.wrapping_add(1);
        Ok(WG_DATA_HEADER_LEN..WG_DATA_HEADER_LEN + body_len)
    }
}

fn blake2s_hash(data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn blake2s_mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut hasher = Blake2s256::new();
    hasher.update(h);
    hasher.update(data);
    hasher.finalize().into()
}

#[derive(Clone, Debug)]
pub struct WireGuardHandshakeState {
    pub c: [u8; 32],
    pub h: [u8; 32],
    pub local_static_priv: [u8; 32],
    pub ephemeral_priv: [u8; 32],
    pub local_index: u32,
    pub awg: AwgConfig,
    pub psk: Option<[u8; 32]>,
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

    /// Creates an authentic WireGuard / AmneziaWG Noise IK handshake initiation packet.
    pub fn create_initiation(
        local_static: &StaticSecret,
        peer_public: &X25519PublicKey,
        sender_index: u32,
        awg: &AwgConfig,
        psk: Option<[u8; 32]>,
    ) -> (Vec<u8>, WireGuardHandshakeState) {
        let initial_construction = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        let initial_identifier = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

        let mut c0 = blake2s_hash(initial_construction);
        let h0 = blake2s_mix_hash(&c0, initial_identifier);
        let h1 = blake2s_mix_hash(&h0, peer_public.as_bytes());

        let mut ephemeral_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let h2 = blake2s_mix_hash(&h1, ephemeral_public.as_bytes());
        c0 = kdf1(&c0, ephemeral_public.as_bytes());

        // Diffie-Hellman 1: Ephemeral - Peer Static
        let ss_es = ephemeral_secret.diffie_hellman(peer_public);
        let (c1, k_static) = kdf2(&c0, ss_es.as_bytes());

        // Encrypt local static public key
        let local_pub = X25519PublicKey::from(local_static);
        let cipher_static = ChaCha20Poly1305::new_from_slice(&k_static).unwrap();
        let enc_static = cipher_static
            .encrypt(
                &ChaChaNonce::from([0u8; 12]),
                chacha20poly1305::aead::Payload {
                    msg: local_pub.as_bytes(),
                    aad: &h2,
                },
            )
            .unwrap();
        let h3 = blake2s_mix_hash(&h2, &enc_static);

        // Diffie-Hellman 2: Static - Peer Static
        let ss_ss = local_static.diffie_hellman(peer_public);
        let (c2, k_ts) = kdf2(&c1, ss_ss.as_bytes());

        // TAI64N timestamp (12 bytes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let tai64_sec = now.as_secs().wrapping_add(0x4000_0000_0000_000a);
        let tai64_nano = now.subsec_nanos();
        let mut tai64n = [0u8; 12];
        tai64n[0..8].copy_from_slice(&tai64_sec.to_be_bytes());
        tai64n[8..12].copy_from_slice(&tai64_nano.to_be_bytes());

        let cipher_ts = ChaCha20Poly1305::new_from_slice(&k_ts).unwrap();
        let enc_ts = cipher_ts
            .encrypt(
                &ChaChaNonce::from([0u8; 12]),
                chacha20poly1305::aead::Payload {
                    msg: &tai64n,
                    aad: &h3,
                },
            )
            .unwrap();
        let h4 = blake2s_mix_hash(&h3, &enc_ts);

        // Packet formatting
        let mut packet = Vec::with_capacity(cfg_packet_len(awg));
        if awg.s1 > 0 {
            let mut s1_bytes = vec![0u8; awg.s1 as usize];
            rand::rngs::OsRng.fill_bytes(&mut s1_bytes);
            packet.extend_from_slice(&s1_bytes);
        }
        packet.extend_from_slice(&awg.h1.to_le_bytes());
        packet.extend_from_slice(&sender_index.to_le_bytes());
        packet.extend_from_slice(ephemeral_public.as_bytes());
        packet.extend_from_slice(&enc_static);
        packet.extend_from_slice(&enc_ts);

        // Mac1 (16 bytes)
        let mac1_key = blake2s_hash_concat(b"mac1----", peer_public.as_bytes());
        let mac1 = blake2s_mac16(&mac1_key, &packet[awg.s1 as usize..]);
        packet.extend_from_slice(&mac1);

        // Mac2 (16 zero bytes)
        packet.extend_from_slice(&[0u8; 16]);

        let state = WireGuardHandshakeState {
            c: c2,
            h: h4,
            local_static_priv: local_static.to_bytes(),
            ephemeral_priv: ephemeral_bytes,
            local_index: sender_index,
            awg: awg.clone(),
            psk,
        };

        (packet, state)
    }

    /// Consumes and validates a WireGuard / AmneziaWG Handshake Response (Message 2),
    /// deriving genuine ChaCha20-Poly1305 transport session keys.
    pub fn consume_response(
        state: WireGuardHandshakeState,
        packet: &[u8],
    ) -> FluxResult<WireGuardSession> {
        let prefix_len = state.awg.s2 as usize;
        let expected_msg_len = prefix_len + 4 + 4 + 4 + 32 + 16 + 16 + 16;
        if packet.len() < expected_msg_len {
            return Err(FluxError::Protocol {
                protocol: "wireguard",
                message: "handshake response packet too short".into(),
            });
        }

        let body = &packet[prefix_len..];
        let msg_type = u32::from_le_bytes(body[0..4].try_into().unwrap());
        if msg_type != state.awg.h2 {
            return Err(FluxError::Protocol {
                protocol: "wireguard",
                message: format!("unexpected response message type: {}", msg_type),
            });
        }

        let server_index = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let receiver_index = u32::from_le_bytes(body[8..12].try_into().unwrap());
        if receiver_index != state.local_index {
            return Err(FluxError::AuthFailed(
                "mismatched receiver index in handshake response".into(),
            ));
        }

        let mut server_ephemeral_bytes = [0u8; 32];
        server_ephemeral_bytes.copy_from_slice(&body[12..44]);
        let server_ephemeral = X25519PublicKey::from(server_ephemeral_bytes);

        let h5 = blake2s_mix_hash(&state.h, &server_ephemeral_bytes);
        let c3 = kdf1(&state.c, &server_ephemeral_bytes);

        // DH 3: Ephemeral - Ephemeral
        let ephemeral_secret = StaticSecret::from(state.ephemeral_priv);
        let ss_ee = ephemeral_secret.diffie_hellman(&server_ephemeral);
        let c4 = kdf1(&c3, ss_ee.as_bytes());

        // DH 4: Local Static - Ephemeral
        let local_static = StaticSecret::from(state.local_static_priv);
        let ss_se = local_static.diffie_hellman(&server_ephemeral);
        let c5 = kdf1(&c4, ss_se.as_bytes());

        // PSK mix
        let psk_bytes = state.psk.unwrap_or([0u8; 32]);
        let (c6, tau, k_empty) = kdf3(&c5, &psk_bytes);
        let h6 = blake2s_mix_hash(&h5, &tau);

        // Verify empty payload authentication tag
        let enc_empty = &body[44..60];
        let cipher_empty = ChaCha20Poly1305::new_from_slice(&k_empty).unwrap();
        cipher_empty
            .decrypt(
                &ChaChaNonce::from([0u8; 12]),
                chacha20poly1305::aead::Payload {
                    msg: enc_empty,
                    aad: &h6,
                },
            )
            .map_err(|e| {
                FluxError::AuthFailed(format!("invalid handshake response MAC tag: {}", e))
            })?;

        // Derive final transport keys
        let (send_key, recv_key) = kdf2(&c6, b"");

        Ok(WireGuardSession::new(
            send_key,
            recv_key,
            state.local_index,
            server_index,
            Some(state.awg),
        ))
    }

    /// Server side: processes Handshake Initiation (Message 1) and formats Handshake Response (Message 2),
    /// deriving genuine ChaCha20-Poly1305 transport session keys.
    ///
    /// NOTE: this variant performs no peer allow-list check; prefer
    /// [`Self::respond_to_initiation_with_peers`] for real server inbounds.
    pub fn respond_to_initiation(
        local_static: &StaticSecret,
        receiver_index: u32,
        awg: &AwgConfig,
        init_pkt: &[u8],
        psk: Option<[u8; 32]>,
    ) -> FluxResult<(Vec<u8>, WireGuardSession)> {
        Self::respond_impl(local_static, receiver_index, awg, init_pkt, None, psk)
            .map(|(response, session, _, _)| (response, session))
    }

    /// Server side with peer allow-list enforcement: the decrypted client static
    /// public key MUST be present in `peers`; the matching peer's preshared key
    /// (if any) is mixed into the handshake. Returns the response packet, the
    /// derived transport session, and the authenticated peer's public key.
    pub fn respond_to_initiation_with_peers(
        local_static: &StaticSecret,
        receiver_index: u32,
        awg: &AwgConfig,
        init_pkt: &[u8],
        peers: &[WireGuardPeerAuth],
    ) -> FluxResult<WireGuardHandshakeResult> {
        let (response, session, peer_public_key, peer_timestamp) = Self::respond_impl(
            local_static,
            receiver_index,
            awg,
            init_pkt,
            Some(peers),
            None,
        )?;
        Ok(WireGuardHandshakeResult {
            response,
            session,
            peer_public_key,
            peer_timestamp,
        })
    }

    fn respond_impl(
        local_static: &StaticSecret,
        receiver_index: u32,
        awg: &AwgConfig,
        init_pkt: &[u8],
        peers: Option<&[WireGuardPeerAuth]>,
        psk: Option<[u8; 32]>,
    ) -> FluxResult<HandshakeParts> {
        let prefix_len = awg.s1 as usize;
        let expected_min_len = prefix_len + 4 + 4 + 32 + 48 + 28 + 32;
        if init_pkt.len() < expected_min_len {
            return Err(FluxError::Protocol {
                protocol: "wireguard",
                message: "initiation packet too short".into(),
            });
        }

        let body = &init_pkt[prefix_len..];
        let msg_type = u32::from_le_bytes(body[0..4].try_into().unwrap());
        if msg_type != awg.h1 {
            return Err(FluxError::Protocol {
                protocol: "wireguard",
                message: format!("unexpected initiation message type: {}", msg_type),
            });
        }

        // MAC1 DoS-protection check (keyed with our own static public key) before any crypto work.
        // Layout: [.. 116-byte Noise body ..][mac1 (16)][mac2 (16)]
        let mac1_offset = prefix_len + 4 + 4 + 32 + 48 + 28;
        if init_pkt.len() >= mac1_offset + 16 {
            let local_pub = X25519PublicKey::from(local_static);
            let mac1_key = blake2s_hash_concat(b"mac1----", local_pub.as_bytes());
            // AmneziaWG: MAC1 covers the message starting at the type field (junk prefix excluded).
            let expected_mac1 = blake2s_mac16(&mac1_key, &init_pkt[prefix_len..mac1_offset]);
            let received_mac1 = &init_pkt[mac1_offset..mac1_offset + 16];
            if !flux_common::constant_time_eq(&expected_mac1, received_mac1) {
                return Err(FluxError::AuthFailed(
                    "wireguard initiation rejected: invalid mac1".into(),
                ));
            }
        }

        let client_index = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let mut client_ephemeral_bytes = [0u8; 32];
        client_ephemeral_bytes.copy_from_slice(&body[8..40]);
        let client_ephemeral = X25519PublicKey::from(client_ephemeral_bytes);

        let initial_construction = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
        let initial_identifier = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
        let local_pub = X25519PublicKey::from(local_static);

        let c0 = blake2s_hash(initial_construction);
        let h0 = blake2s_mix_hash(&c0, initial_identifier);
        let h1 = blake2s_mix_hash(&h0, local_pub.as_bytes());
        let h2 = blake2s_mix_hash(&h1, &client_ephemeral_bytes);
        let c0 = kdf1(&c0, &client_ephemeral_bytes);

        // DH 1: Client Ephemeral - Responder Static
        let ss_es = local_static.diffie_hellman(&client_ephemeral);
        let (c1, k_static) = kdf2(&c0, ss_es.as_bytes());

        // Decrypt client static public key
        let enc_static = &body[40..88];
        let cipher_static = ChaCha20Poly1305::new_from_slice(&k_static).unwrap();
        let client_pub_bytes = cipher_static
            .decrypt(
                &ChaChaNonce::from([0u8; 12]),
                chacha20poly1305::aead::Payload {
                    msg: enc_static,
                    aad: &h2,
                },
            )
            .map_err(|e| {
                FluxError::AuthFailed(format!("failed to decrypt static pub in initiation: {}", e))
            })?;

        let h3 = blake2s_mix_hash(&h2, enc_static);
        let mut client_static_arr = [0u8; 32];
        client_static_arr.copy_from_slice(&client_pub_bytes);
        let client_static = X25519PublicKey::from(client_static_arr);

        // Peer allow-list enforcement (constant-time comparison per entry).
        // Resolves the effective preshared key for the authenticated peer.
        let effective_psk: Option<[u8; 32]> = match peers {
            Some(list) => {
                let mut matched: Option<&WireGuardPeerAuth> = None;
                for p in list {
                    if flux_common::constant_time_eq(&p.public_key, &client_static_arr) {
                        matched = Some(p);
                        break;
                    }
                }
                match matched {
                    Some(p) => p.preshared_key,
                    None => {
                        return Err(FluxError::AuthFailed(
                            "wireguard initiation rejected: unknown peer public key".into(),
                        ));
                    }
                }
            }
            None => psk,
        };

        // DH 2: Client Static - Responder Static
        let ss_ss = local_static.diffie_hellman(&client_static);
        let (c2, k_ts) = kdf2(&c1, ss_ss.as_bytes());

        // Decrypt and validate TAI64N timestamp (anti-replay freshness window).
        let enc_ts = &body[88..116];
        let cipher_ts = ChaCha20Poly1305::new_from_slice(&k_ts).unwrap();
        let ts_plain = cipher_ts
            .decrypt(
                &ChaChaNonce::from([0u8; 12]),
                chacha20poly1305::aead::Payload {
                    msg: enc_ts,
                    aad: &h3,
                },
            )
            .map_err(|e| {
                FluxError::AuthFailed(format!("failed to decrypt timestamp in initiation: {}", e))
            })?;
        let mut peer_timestamp = [0u8; 12];
        if ts_plain.len() == 12 {
            peer_timestamp.copy_from_slice(&ts_plain[..12]);
            let tai64_sec = u64::from_be_bytes(ts_plain[0..8].try_into().unwrap());
            // TAI64N epoch offset: 2^62 + 10 seconds
            let unix_sec = tai64_sec.saturating_sub(0x4000_0000_0000_000a);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Reject stale initiations (older than REJECT_AFTER_TIME) or future-dated ones.
            if unix_sec + WG_REJECT_AFTER_TIME_SECS < now || unix_sec > now + 30 {
                return Err(FluxError::AuthFailed(
                    "wireguard initiation rejected: stale or future timestamp".into(),
                ));
            }
        }
        let h4 = blake2s_mix_hash(&h3, enc_ts);

        // Generate responder ephemeral key
        let mut server_ephemeral_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_ephemeral_bytes);
        let server_ephemeral_secret = StaticSecret::from(server_ephemeral_bytes);
        let server_ephemeral_pub = X25519PublicKey::from(&server_ephemeral_secret);

        let h5 = blake2s_mix_hash(&h4, server_ephemeral_pub.as_bytes());
        let c3 = kdf1(&c2, server_ephemeral_pub.as_bytes());

        // DH 3: Server Ephemeral - Client Ephemeral
        let ss_ee = server_ephemeral_secret.diffie_hellman(&client_ephemeral);
        let c4 = kdf1(&c3, ss_ee.as_bytes());

        // DH 4: Server Ephemeral - Client Static
        let ss_se = server_ephemeral_secret.diffie_hellman(&client_static);
        let c5 = kdf1(&c4, ss_se.as_bytes());

        // PSK mix
        let psk_bytes = effective_psk.unwrap_or([0u8; 32]);
        let (c6, tau, k_empty) = kdf3(&c5, &psk_bytes);
        let h6 = blake2s_mix_hash(&h5, &tau);

        // Encrypt empty payload
        let cipher_empty = ChaCha20Poly1305::new_from_slice(&k_empty).unwrap();
        let enc_empty = cipher_empty
            .encrypt(
                &ChaChaNonce::from([0u8; 12]),
                chacha20poly1305::aead::Payload { msg: b"", aad: &h6 },
            )
            .unwrap();

        // Response packet format: [S2 prefix] + [H2] + [sender_index (4)] + [receiver_index (4)] + [server_ephemeral (32)] + [enc_empty (16)] + [mac1 (16)] + [mac2 (16)]
        let mut resp_pkt = Vec::with_capacity(awg.s2 as usize + 4 + 4 + 4 + 32 + 16 + 16 + 16);
        if awg.s2 > 0 {
            let mut s2_bytes = vec![0u8; awg.s2 as usize];
            rand::rngs::OsRng.fill_bytes(&mut s2_bytes);
            resp_pkt.extend_from_slice(&s2_bytes);
        }
        resp_pkt.extend_from_slice(&awg.h2.to_le_bytes());
        resp_pkt.extend_from_slice(&receiver_index.to_le_bytes());
        resp_pkt.extend_from_slice(&client_index.to_le_bytes());
        resp_pkt.extend_from_slice(server_ephemeral_pub.as_bytes());
        resp_pkt.extend_from_slice(&enc_empty);

        // Mac1 (16 bytes)
        let mac1_key = blake2s_hash_concat(b"mac1----", client_static.as_bytes());
        let mac1 = blake2s_mac16(&mac1_key, &resp_pkt[awg.s2 as usize..]);
        resp_pkt.extend_from_slice(&mac1);
        resp_pkt.extend_from_slice(&[0u8; 16]); // mac2

        let (client_send, client_recv) = kdf2(&c6, b"");

        // Server sends on client_recv and receives on client_send
        let session = WireGuardSession::new(
            client_recv,
            client_send,
            receiver_index,
            client_index,
            Some(awg.clone()),
        );

        Ok((resp_pkt, session, client_static_arr, peer_timestamp))
    }
}

/// Response packet, derived session, authenticated peer key and its TAI64N.
type HandshakeParts = (Vec<u8>, WireGuardSession, [u8; 32], [u8; 12]);

/// An authorized WireGuard peer entry for server-side handshake authentication.
#[derive(Clone, Debug)]
pub struct WireGuardPeerAuth {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
}

/// Result of a peer-authenticated handshake response.
pub struct WireGuardHandshakeResult {
    /// Handshake Response (Message 2) packet to send back to the initiator.
    pub response: Vec<u8>,
    /// Derived transport session (server sends on `client_recv` key).
    pub session: WireGuardSession,
    /// Authenticated peer's static public key.
    pub peer_public_key: [u8; 32],
    /// TAI64N timestamp from the initiation (12 bytes, big-endian nanoseconds).
    ///
    /// The responder must remember the greatest value seen per peer and reject
    /// anything that is not strictly newer (WireGuard's replay defence for
    /// handshake initiations); the caller enforces that with this value.
    pub peer_timestamp: [u8; 12],
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

        let (init_pkt, state) =
            WireGuardHandshake::create_initiation(&static_secret, &peer_pub, 1337, &awg, None);
        assert!(init_pkt.len() > 140);
        // Verify S1 junk prefix length and H1 message type
        assert_eq!(&init_pkt[16..20], &101u32.to_le_bytes());

        // Responder processes Message 1 and sends Message 2
        let (resp_pkt, mut recv_session) =
            WireGuardHandshake::respond_to_initiation(&peer_secret, 7331, &awg, &init_pkt, None)
                .unwrap();

        // Initiator consumes Message 2 and derives matching session
        let mut session = WireGuardHandshake::consume_response(state, &resp_pkt).unwrap();

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let data_pkt = session.encrypt_data_packet(payload).unwrap();

        assert_eq!(&data_pkt[0..4], &104u32.to_le_bytes());
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

        let (init_pkt, state) =
            WireGuardHandshake::create_initiation(&static_secret, &peer_pub, 1337, &awg, None);
        let (resp_pkt, mut recv_session) =
            WireGuardHandshake::respond_to_initiation(&peer_secret, 7331, &awg, &init_pkt, None)
                .unwrap();
        let mut send_session = WireGuardHandshake::consume_response(state, &resp_pkt).unwrap();

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
