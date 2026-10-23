use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::SupportedCipherSuite;
use tokio_rustls::rustls::crypto::ring::cipher_suite::*;
use tokio_rustls::rustls::crypto::ring::kx_group::*;
use tokio_rustls::rustls::crypto::{CryptoProvider, SupportedKxGroup};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum TlsFingerprint {
    #[default]
    Chrome,
    Firefox,
    Safari,
    Random,
}

impl TlsFingerprint {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chrome" | "chrome_120" | "chrome_auto" => Some(Self::Chrome),
            "firefox" | "firefox_120" => Some(Self::Firefox),
            "safari" | "safari_ios" => Some(Self::Safari),
            "random" | "randomized" => Some(Self::Random),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Random => "random",
        }
    }
}

/// Builds a Chrome-profiled CryptoProvider:
/// Prioritizes TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
/// followed by ECDHE-ECDSA and ECDHE-RSA ciphers, with X25519, SECP256R1 and
/// SECP384R1 key-exchange groups (X25519 first, as browsers send it).
pub fn create_chrome_provider() -> CryptoProvider {
    let cipher_suites: Vec<SupportedCipherSuite> = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    let kx_groups: Vec<&'static dyn SupportedKxGroup> = vec![X25519, SECP256R1, SECP384R1];

    let mut provider = tokio_rustls::rustls::crypto::ring::default_provider();
    provider.cipher_suites = cipher_suites;
    provider.kx_groups = kx_groups;
    provider
}

/// Builds a Firefox-profiled CryptoProvider:
/// Prioritizes TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384
/// — the Firefox ordering differs from Chrome's in both the TLS 1.3 suites and
/// the legacy suites, which is the point of having a separate profile.
pub fn create_firefox_provider() -> CryptoProvider {
    let cipher_suites: Vec<SupportedCipherSuite> = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ];

    let kx_groups: Vec<&'static dyn SupportedKxGroup> = vec![X25519, SECP256R1, SECP384R1];

    let mut provider = tokio_rustls::rustls::crypto::ring::default_provider();
    provider.cipher_suites = cipher_suites;
    provider.kx_groups = kx_groups;
    provider
}

/// Builds a Safari-profiled CryptoProvider:
/// Prioritizes TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
pub fn create_safari_provider() -> CryptoProvider {
    let cipher_suites: Vec<SupportedCipherSuite> = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];

    let kx_groups: Vec<&'static dyn SupportedKxGroup> = vec![X25519, SECP256R1, SECP384R1];

    let mut provider = tokio_rustls::rustls::crypto::ring::default_provider();
    provider.cipher_suites = cipher_suites;
    provider.kx_groups = kx_groups;
    provider
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio_rustls::rustls::client::ClientConfig;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

    // ---- TLS wire constants (RFC 8446 / IANA) --------------------------------
    const REC_HANDSHAKE: u8 = 0x16;
    const REC_CCS: u8 = 0x14;
    const HS_CLIENT_HELLO: u8 = 0x01;
    /// Browsers keep the legacy record-layer version at TLS 1.0 in ClientHello.
    const RECORD_VERSION: u16 = 0x0301;
    const LEGACY_VERSION: u16 = 0x0303;
    /// TLS_EMPTY_RENEGOTIATION_INFO_SCSV, appended by rustls when TLS 1.2 is on.
    const SCSV: u16 = 0x00ff;

    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_STATUS_REQUEST: u16 = 0x0005;
    const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
    const EXT_EC_POINT_FORMATS: u16 = 0x000b;
    const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
    const EXT_ALPN: u16 = 0x0010;
    const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
    const EXT_SESSION_TICKET: u16 = 0x0023;
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    const EXT_KEY_SHARE: u16 = 0x0033;

    /// Every extension the emitted ClientHello carries. This *is* the whole
    /// camouflage surface of the rustls-based profiles: a browser sends ~15
    /// (plus GREASE), so this set is deliberately reviewed whenever rustls
    /// changes — see the module report for what is still missing.
    const EMITTED_EXTS: [u16; 11] = [
        EXT_SERVER_NAME,
        EXT_STATUS_REQUEST,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_ALPN,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_SESSION_TICKET,
        EXT_SUPPORTED_VERSIONS,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_KEY_SHARE,
    ];

    const GROUP_X25519: u16 = 0x001d;
    const GROUP_SECP256R1: u16 = 0x0017;
    const GROUP_SECP384R1: u16 = 0x0018;

    // Cipher-suite tables, in the order the profile claims. The wire order is
    // the fingerprint (JA3), so these are exact, not sets.
    const CHROME_SUITES: [u16; 9] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    ];
    const FIREFOX_SUITES: [u16; 9] = [
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
    ];
    const SAFARI_SUITES: [u16; 7] = [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f];

    fn providers() -> Vec<(&'static str, CryptoProvider)> {
        vec![
            ("chrome", create_chrome_provider()),
            ("firefox", create_firefox_provider()),
            ("safari", create_safari_provider()),
        ]
    }

    fn expected_suites(profile: &str) -> &'static [u16] {
        match profile {
            "chrome" => &CHROME_SUITES,
            "firefox" => &FIREFOX_SUITES,
            "safari" => &SAFARI_SUITES,
            other => panic!("unknown profile {other}"),
        }
    }

    fn suite_ids(provider: &CryptoProvider) -> Vec<u16> {
        provider
            .cipher_suites
            .iter()
            .map(|cs| u16::from(cs.suite()))
            .collect()
    }

    fn group_ids(provider: &CryptoProvider) -> Vec<u16> {
        provider
            .kx_groups
            .iter()
            .map(|g| u16::from(g.name()))
            .collect()
    }

    // ---- a strict ClientHello parser ----------------------------------------
    //
    // Mirrors what a real TLS server (or a censor's passive fingerprinter) does
    // with the bytes we put on the wire: every length field must account for
    // exactly the bytes that follow it. Any disagreement is a `Err`, never a
    // panic — the parser is also the harness for the corrupted-input tests.

    struct Cursor<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn pos(&self) -> usize {
            self.pos
        }

        fn left(&self) -> usize {
            self.buf.len() - self.pos
        }

        fn u8(&mut self) -> Result<u8, String> {
            let v = *self.buf.get(self.pos).ok_or_else(|| {
                format!("truncated: u8 at offset {} of {}", self.pos, self.buf.len())
            })?;
            self.pos += 1;
            Ok(v)
        }

        fn u16(&mut self) -> Result<u16, String> {
            let b = self.take(2)?;
            Ok(u16::from_be_bytes([b[0], b[1]]))
        }

        fn u24(&mut self) -> Result<usize, String> {
            let b = self.take(3)?;
            Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
        }

        fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
            let end = self
                .pos
                .checked_add(n)
                .ok_or_else(|| format!("length overflow at offset {}", self.pos))?;
            if end > self.buf.len() {
                return Err(format!(
                    "truncated: wanted {} bytes at offset {}, only {} available",
                    n,
                    self.pos,
                    self.buf.len() - self.pos
                ));
            }
            let out = &self.buf[self.pos..end];
            self.pos = end;
            Ok(out)
        }
    }

    /// Byte offsets of the length fields, so the corruption tests can patch
    /// exactly one field and prove the parser rejects it.
    #[derive(Debug, Clone, Copy)]
    struct Marks {
        record_len: usize,
        handshake_len: usize,
        suite_len: usize,
        ext_block_len: usize,
        /// Length field of the first extension (any extension: rustls shuffles
        /// the order, so its identity varies between generations).
        first_ext_len: usize,
        /// Length field of the last extension, whose value always ends at the
        /// block boundary — the only offset whose corruption is deterministic.
        last_ext_len: usize,
    }

    #[derive(Debug)]
    struct ClientHello {
        record_version: u16,
        legacy_version: u16,
        random: Vec<u8>,
        session_id: Vec<u8>,
        cipher_suites: Vec<u16>,
        compression: Vec<u8>,
        extensions: Vec<(u16, Vec<u8>)>,
        trailing_records: Vec<(u8, u16)>,
        marks: Marks,
    }

    impl ClientHello {
        fn ext(&self, want: u16) -> Option<&[u8]> {
            self.extensions
                .iter()
                .find(|(ty, _)| *ty == want)
                .map(|(_, data)| data.as_slice())
        }

        fn ext_types(&self) -> Vec<u16> {
            self.extensions.iter().map(|(ty, _)| *ty).collect()
        }
    }

    fn parse_client_hello(bytes: &[u8]) -> Result<ClientHello, String> {
        let mut c = Cursor::new(bytes);
        if c.u8()? != REC_HANDSHAKE {
            return Err("first record is not a handshake record".into());
        }
        let record_version = c.u16()?;
        let record_len_at = c.pos();
        let record_len = c.u16()? as usize;
        let hs_start = c.pos();
        let hs_end = hs_start + record_len;
        if hs_end > bytes.len() {
            return Err(format!(
                "record length {record_len} runs past the end of the {} bytes available",
                bytes.len()
            ));
        }

        if c.u8()? != HS_CLIENT_HELLO {
            return Err("first handshake message is not a ClientHello".into());
        }
        let handshake_len_at = c.pos();
        let handshake_len = c.u24()?;
        let body_start = c.pos();
        let body_end = body_start + handshake_len;
        // THE invariant: the record must carry exactly one ClientHello.
        if body_end != hs_end {
            return Err(format!(
                "record length {record_len} disagrees with handshake length {handshake_len}"
            ));
        }

        let legacy_version = c.u16()?;
        let random = c.take(32)?.to_vec();
        let sid_len = c.u8()? as usize;
        let session_id = c.take(sid_len)?.to_vec();

        let suite_len_at = c.pos();
        let suite_len = c.u16()? as usize;
        if suite_len == 0 || !suite_len.is_multiple_of(2) {
            return Err(format!(
                "cipher-suite list length {suite_len} is not an even, non-zero u16"
            ));
        }
        let suite_raw = c.take(suite_len)?;
        let cipher_suites: Vec<u16> = suite_raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .collect();

        let comp_len = c.u8()? as usize;
        let compression = c.take(comp_len)?.to_vec();

        let ext_block_len_at = c.pos();
        let ext_block_len = c.u16()? as usize;
        let ext_start = c.pos();
        let ext_end = ext_start + ext_block_len;
        if ext_end != body_end {
            return Err(format!(
                "extension block length {ext_block_len} ends at {ext_end}, handshake body ends at {body_end}"
            ));
        }

        let mut extensions: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut first_ext_len = 0;
        let mut last_ext_len = 0;
        while c.pos() < ext_end {
            if extensions.is_empty() {
                first_ext_len = c.pos() + 2;
            }
            last_ext_len = c.pos() + 2;
            let ty = c.u16()?;
            let len = c.u16()? as usize;
            let data = c.take(len)?;
            if c.pos() > ext_end {
                return Err(format!(
                    "extension {ty:#06x} declares {len} bytes but overruns the extension block"
                ));
            }
            if extensions.iter().any(|(seen, _)| *seen == ty) {
                return Err(format!("duplicate extension {ty:#06x}"));
            }
            extensions.push((ty, data.to_vec()));
        }
        if c.pos() != ext_end {
            return Err("extension block not consumed exactly".into());
        }

        let mut trailing_records = Vec::new();
        while c.left() > 0 {
            let ty = c.u8()?;
            let ver = c.u16()?;
            let len = c.u16()? as usize;
            c.take(len)?;
            trailing_records.push((ty, ver));
        }

        Ok(ClientHello {
            record_version,
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression,
            extensions,
            trailing_records,
            marks: Marks {
                record_len: record_len_at,
                handshake_len: handshake_len_at,
                suite_len: suite_len_at,
                ext_block_len: ext_block_len_at,
                first_ext_len,
                last_ext_len,
            },
        })
    }

    // ---- generation ---------------------------------------------------------

    fn build_client_config(provider: CryptoProvider, alpn: &[&[u8]]) -> ClientConfig {
        // Rejects per-profile tables that rustls cannot use for TLS 1.2 + 1.3,
        // e.g. a key-exchange group it does not implement.
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("profile must be usable for TLS 1.2 and TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        cfg
    }

    /// The exact bytes this profile puts on the wire as its first flight.
    /// Pins what is actually emitted: the cipher order and the extension *set*.
    ///
    /// The extension *order* is deliberately shuffled per connection (that is the
    /// point of the randomising profiles), so a single JA3 hash is not a stable
    /// property of this client and pinning one would be a lie.
    ///
    /// **This is not a browser fingerprint, and the difference is worth stating.**
    /// Chrome 120 emits 15 extensions with GREASE; we emit these 11, with rustls'
    /// own ordering rolled by our shuffler:
    /// `51-0-10-35-45-16-13-11-23-5-43`. The cipher table is Chrome's; the extension
    /// set is rustls'. So the profiles are "closer than default", not
    /// "browser-grade" — this test keeps the claim honest as much as it catches drift.
    #[test]
    fn emitted_client_hello_has_the_profile_ciphers_and_extension_set() {
        // JA3 extension ids: 0 SNI, 5 status_request, 10 supported_groups,
        // 11 ec_point_formats, 13 signature_algorithms, 16 ALPN, 23 session_ticket,
        // 35 extended_master_secret, 43 supported_versions, 45 psk_key_exchange_modes,
        // 51 key_share.
        let want_exts = vec![0u16, 5, 10, 11, 13, 16, 23, 35, 43, 45, 51];
        let want_ciphers: &[(&str, &[u16])] = &[
            (
                "chrome",
                &[
                    4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 255,
                ],
            ),
            (
                "firefox",
                &[
                    4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 255,
                ],
            ),
            (
                "safari",
                &[4865, 4866, 4867, 49196, 49195, 49200, 49199, 255],
            ),
        ];

        for (name, provider) in providers() {
            let bytes = client_hello_bytes(provider, &[b"h2"], "example.com");
            let hello = parse_client_hello(&bytes).expect("parse");

            assert_eq!(
                hello.cipher_suites,
                *want_ciphers
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, c)| *c)
                    .unwrap_or(&[]),
                "{name}: cipher order is the fingerprint and must not drift"
            );

            let mut got_exts: Vec<u16> = hello.extensions.iter().map(|(ty, _)| *ty).collect();
            got_exts.sort_unstable();
            let mut want = want_exts.clone();
            want.sort_unstable();
            assert_eq!(got_exts, want, "{name}: extension set changed");
        }
    }

    /// The profiles exist to make two connections look different from each other.
    /// If the order were fixed, that purpose would be silently lost.
    #[test]
    fn the_extension_order_is_shuffled_between_connections() {
        let provider = create_chrome_provider();
        let order = |p: CryptoProvider| {
            let bytes = client_hello_bytes(p, &[b"h2"], "example.com");
            parse_client_hello(&bytes)
                .expect("parse")
                .extensions
                .iter()
                .map(|(ty, _)| *ty)
                .collect::<Vec<_>>()
        };
        let first = order(create_chrome_provider());
        let mut differs = false;
        for _ in 0..8 {
            if order(create_chrome_provider()) != first {
                differs = true;
                break;
            }
        }
        let _ = provider;
        assert!(
            differs,
            "extension order never changed across connections — the shuffle is not happening"
        );
    }

    fn client_hello_bytes(provider: CryptoProvider, alpn: &[&[u8]], name: &'static str) -> Vec<u8> {
        let cfg = build_client_config(provider, alpn);
        let name = ServerName::try_from(name).expect("valid server name");
        let mut conn = tokio_rustls::rustls::ClientConnection::new(Arc::new(cfg), name)
            .expect("ClientConnection::new must produce a ClientHello");
        let mut out = Vec::new();
        for _ in 0..8 {
            if !conn.wants_write() {
                break;
            }
            conn.write_tls(&mut out).expect("write_tls");
        }
        assert!(!conn.wants_write(), "first flight must be fully drained");
        out
    }

    // ---- profile tables -----------------------------------------------------

    #[test]
    fn test_tls_fingerprint_profiles() {
        let mut tables: Vec<(&str, Vec<u16>)> = Vec::new();
        for (name, provider) in providers() {
            let suites = suite_ids(&provider);
            assert_eq!(
                suites.as_slice(),
                expected_suites(name),
                "{name}: cipher-suite table does not match the profile it claims"
            );
            tables.push((name, suites.clone()));

            // Browsers put the TLS 1.3 suites first; an interleaved order is a
            // fingerprint even when the set is identical.
            let tls13: Vec<&SupportedCipherSuite> = provider
                .cipher_suites
                .iter()
                .filter(|cs| cs.tls13().is_some())
                .collect();
            assert_eq!(
                tls13.len(),
                3,
                "{name}: must offer exactly the three TLS 1.3 suites"
            );
            assert!(
                provider.cipher_suites[..3]
                    .iter()
                    .all(|cs| cs.tls13().is_some()),
                "{name}: the three TLS 1.3 suites must come first"
            );
            assert!(
                provider.cipher_suites[3..]
                    .iter()
                    .all(|cs| cs.tls13().is_none()),
                "{name}: no TLS 1.3 suite may appear after a TLS 1.2 suite"
            );
            for required in [0x1301u16, 0x1302, 0x1303] {
                assert!(
                    suites.contains(&required),
                    "{name}: missing TLS 1.3 suite {required:#06x} (a browser always offers all three)"
                );
            }

            // Duplicated suites make a ClientHello malformed-looking and are
            // trivially detectable.
            let unique: HashSet<u16> = suites.iter().copied().collect();
            assert_eq!(
                unique.len(),
                suites.len(),
                "{name}: duplicate cipher suite in the table"
            );

            // Key-exchange groups: X25519 first, then the NIST curves.
            assert_eq!(
                group_ids(&provider),
                vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
                "{name}: key-exchange group order is part of the fingerprint"
            );
            let unique_groups: HashSet<u16> = group_ids(&provider).into_iter().collect();
            assert_eq!(unique_groups.len(), 3, "{name}: duplicate kx group");
        }

        // Each profile must be distinguishable from the others: an accidental
        // copy-paste in a builder would silently collapse two profiles into one.
        for i in 0..tables.len() {
            for j in (i + 1)..tables.len() {
                assert_ne!(
                    tables[i].1, tables[j].1,
                    "{} and {} advertise the same cipher table",
                    tables[i].0, tables[j].0
                );
            }
        }
    }

    // ---- the enum -----------------------------------------------------------

    #[test]
    fn test_tls_fingerprint_parsing() {
        let aliases = [
            ("chrome", TlsFingerprint::Chrome),
            ("chrome_120", TlsFingerprint::Chrome),
            ("chrome_auto", TlsFingerprint::Chrome),
            ("  CHROME  ", TlsFingerprint::Chrome),
            ("firefox", TlsFingerprint::Firefox),
            ("firefox_120", TlsFingerprint::Firefox),
            ("FireFox", TlsFingerprint::Firefox),
            ("safari", TlsFingerprint::Safari),
            ("safari_ios", TlsFingerprint::Safari),
            ("SAFARI", TlsFingerprint::Safari),
            ("random", TlsFingerprint::Random),
            ("randomized", TlsFingerprint::Random),
        ];
        for (input, want) in aliases {
            assert_eq!(
                TlsFingerprint::parse_str(input),
                Some(want),
                "alias {input:?} must map to {want:?}"
            );
        }

        // Near misses must NOT silently resolve to a profile: a typo in a
        // config would otherwise negotiate a fingerprint the user did not ask for.
        for bad in [
            "",
            " ",
            "chromeos",
            "chrome120",
            "chrome 120",
            "ff",
            "safari_ios_17",
            "randomize",
            "unknown",
            "chrom",
            "firefoxes",
        ] {
            assert_eq!(TlsFingerprint::parse_str(bad), None, "must reject {bad:?}");
        }

        assert_eq!(
            TlsFingerprint::default(),
            TlsFingerprint::Chrome,
            "the default profile is part of the public contract"
        );

        // Labels are used in config and URIs; they must be unique and round-trip.
        let all = [
            TlsFingerprint::Chrome,
            TlsFingerprint::Firefox,
            TlsFingerprint::Safari,
            TlsFingerprint::Random,
        ];
        let labels: HashSet<&'static str> = all.iter().map(|fp| fp.to_str()).collect();
        assert_eq!(labels.len(), all.len(), "two variants share a label");
        for fp in all {
            assert_eq!(TlsFingerprint::parse_str(fp.to_str()), Some(fp));
            assert_eq!(*fp.to_str(), fp.to_str().to_ascii_lowercase());
        }
    }

    // ---- what actually goes on the wire ------------------------------------

    #[test]
    fn test_tls_fingerprint_client_hello_is_structurally_valid() {
        for (name, provider) in providers() {
            let bytes = client_hello_bytes(provider.clone(), &[b"h2", b"http/1.1"], "example.org");
            let hello = parse_client_hello(&bytes)
                .unwrap_or_else(|e| panic!("{name}: emitted ClientHello is malformed: {e}"));

            assert_eq!(
                hello.record_version, RECORD_VERSION,
                "{name}: record-layer version"
            );
            assert_eq!(
                hello.legacy_version, LEGACY_VERSION,
                "{name}: legacy_version"
            );
            assert_eq!(
                hello.compression,
                vec![0u8],
                "{name}: null compression only"
            );

            // A zero-length session id is a JA3 field and marks the client as
            // non-browser; rustls sends a 32-byte one for middlebox compat.
            assert_eq!(
                hello.session_id.len(),
                32,
                "{name}: legacy_session_id length"
            );

            // The provider table must reach the wire verbatim (plus the SCSV
            // rustls appends when TLS 1.2 is enabled). Any silent drop or
            // reordering inside rustls would break the claimed profile.
            let mut want = suite_ids(&provider);
            want.push(SCSV);
            assert_eq!(
                hello.cipher_suites, want,
                "{name}: cipher suites on the wire"
            );

            // Extension set: complete, duplicate-free, and exactly what we expect.
            let types = hello.ext_types();
            assert_eq!(
                types.iter().copied().collect::<HashSet<_>>().len(),
                types.len(),
                "{name}: duplicated extension on the wire"
            );
            assert_eq!(
                types.iter().copied().collect::<HashSet<_>>(),
                EMITTED_EXTS.iter().copied().collect::<HashSet<_>>(),
                "{name}: unexpected extension set on the wire"
            );

            // SNI: [list_len][type=0][name_len][name]
            let sni = hello.ext(EXT_SERVER_NAME).expect("SNI extension");
            assert_eq!(&sni[..3], &[0x00, 0x0e, 0x00], "{name}: SNI list encoding");
            assert_eq!(&sni[3..5], &[0x00, 0x0b], "{name}: SNI name length");
            assert_eq!(&sni[5..], b"example.org", "{name}: SNI host name");

            // ALPN must advertise exactly what the config asked for, in order.
            let alpn = hello.ext(EXT_ALPN).expect("ALPN extension");
            let list_len = u16::from_be_bytes([alpn[0], alpn[1]]) as usize;
            assert_eq!(list_len, alpn.len() - 2, "{name}: ALPN list length");
            let mut cursor = Cursor::new(&alpn[2..]);
            let mut protos = Vec::new();
            while cursor.left() > 0 {
                let n = cursor.u8().unwrap() as usize;
                protos.push(cursor.take(n).unwrap().to_vec());
            }
            assert_eq!(
                protos,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                "{name}: ALPN protocol list"
            );

            assert_eq!(
                hello
                    .ext(EXT_SUPPORTED_VERSIONS)
                    .expect("supported_versions"),
                &[0x04, 0x03, 0x04, 0x03, 0x03],
                "{name}: must offer TLS 1.3 then TLS 1.2"
            );

            let groups = hello.ext(EXT_SUPPORTED_GROUPS).expect("supported_groups");
            assert_eq!(
                u16::from_be_bytes([groups[0], groups[1]]) as usize,
                groups.len() - 2
            );
            let groups: Vec<u16> = groups[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
                .collect();
            assert_eq!(
                groups,
                group_ids(&provider),
                "{name}: supported_groups order"
            );

            // key_share must offer the first supported group only (what browsers do).
            let ks = hello.ext(EXT_KEY_SHARE).expect("key_share");
            let ks_len = u16::from_be_bytes([ks[0], ks[1]]) as usize;
            assert_eq!(ks_len, ks.len() - 2, "{name}: key_share list length");
            let group = u16::from_be_bytes([ks[2], ks[3]]);
            assert_eq!(
                group, groups[0],
                "{name}: key_share must match the first group"
            );
            assert_eq!(
                u16::from_be_bytes([ks[4], ks[5]]) as usize,
                32,
                "{name}: X25519 share"
            );

            // Signature algorithms: even count, no duplicates, and the two
            // schemes a real cert chain needs.
            let sig = hello
                .ext(EXT_SIGNATURE_ALGORITHMS)
                .expect("signature_algorithms");
            let sig_len = u16::from_be_bytes([sig[0], sig[1]]) as usize;
            assert_eq!(sig_len, sig.len() - 2, "{name}: sig-alg list length");
            assert_eq!(sig_len % 2, 0, "{name}: sig-alg list must be even");
            let sigs: Vec<u16> = sig[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
                .collect();
            assert!(sigs.len() >= 4, "{name}: too few signature algorithms");
            assert_eq!(
                sigs.iter().copied().collect::<HashSet<_>>().len(),
                sigs.len(),
                "{name}: duplicate signature algorithm"
            );
            for required in [0x0403u16, 0x0804] {
                assert!(
                    sigs.contains(&required),
                    "{name}: missing sig alg {required:#06x}"
                );
            }

            assert_eq!(
                hello.ext(EXT_PSK_KEY_EXCHANGE_MODES),
                Some(&[0x01u8, 0x01][..])
            );
            assert_eq!(hello.ext(EXT_EC_POINT_FORMATS), Some(&[0x01u8, 0x00][..]));
            assert_eq!(hello.ext(EXT_SESSION_TICKET), Some(&[][..]));
            assert!(hello.ext(EXT_EXTENDED_MASTER_SECRET).is_some());

            // Nothing but an optional middlebox-compat CCS may follow the
            // ClientHello in the first flight.
            for (ty, _ver) in &hello.trailing_records {
                assert_eq!(
                    *ty, REC_CCS,
                    "{name}: unexpected record after the ClientHello"
                );
            }
        }
    }

    // ---- randomisation ------------------------------------------------------

    #[test]
    fn test_tls_fingerprint_client_hello_randomisation() {
        const ITERATIONS: usize = 50;
        for (name, provider) in providers() {
            let mut seen = HashSet::new();
            let mut last_random: Option<Vec<u8>> = None;
            let mut last_sid: Option<Vec<u8>> = None;
            let mut suite_lists = HashSet::new();
            let mut ext_orders = HashSet::new();

            for i in 0..ITERATIONS {
                let bytes =
                    client_hello_bytes(provider.clone(), &[b"h2", b"http/1.1"], "example.org");
                let hello = parse_client_hello(&bytes).unwrap_or_else(|e| {
                    panic!("{name}: iteration {i} produced a malformed ClientHello: {e}")
                });

                // Random fields must actually be random — a repeated random or
                // session id is both a fingerprint and a nonce-reuse hazard.
                if let Some(prev) = &last_random {
                    assert_ne!(prev, &hello.random, "{name}: repeated client_random at {i}");
                }
                if let Some(prev) = &last_sid {
                    assert_ne!(
                        prev, &hello.session_id,
                        "{name}: repeated session_id at {i}"
                    );
                }
                last_random = Some(hello.random.clone());
                last_sid = Some(hello.session_id.clone());

                assert!(
                    seen.insert(bytes),
                    "{name}: two ClientHellos were byte-identical"
                );

                // The parts the profile controls must stay put across generations.
                suite_lists.insert(hello.cipher_suites.clone());
                ext_orders.insert(hello.ext_types());

                assert_eq!(
                    hello.extensions.len(),
                    EMITTED_EXTS.len(),
                    "{name}: ext count"
                );
                // Structural validity is re-checked by the parser on every run.
                assert_eq!(hello.marks.record_len, 3);
            }

            assert_eq!(
                suite_lists.len(),
                1,
                "{name}: the cipher list must not be randomised"
            );
            assert_eq!(
                seen.len(),
                ITERATIONS,
                "{name}: duplicates in {ITERATIONS} generations"
            );
            // rustls randomises the order of order-insensitive extensions on
            // purpose; if that ever stops, the emitted order is fixed by rustls
            // and must be reviewed against the profile it claims to mimic.
            assert!(
                ext_orders.len() > 1,
                "{name}: extension order never varied in {ITERATIONS} generations"
            );
            // ... but never to the point of losing or duplicating an extension.
            for order in &ext_orders {
                assert_eq!(order.len(), EMITTED_EXTS.len(), "{name}: extension lost");
                assert_eq!(
                    order.iter().copied().collect::<HashSet<_>>().len(),
                    order.len(),
                    "{name}: duplicated extension in a permutation"
                );
            }
        }
    }

    // ---- the parser really enforces the invariants --------------------------

    fn patch_u16(buf: &[u8], at: usize, value: u16) -> Vec<u8> {
        let mut out = buf.to_vec();
        out[at..at + 2].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn patch_u24(buf: &[u8], at: usize, value: usize) -> Vec<u8> {
        let mut out = buf.to_vec();
        let b = (value as u32).to_be_bytes();
        out[at..at + 3].copy_from_slice(&b[1..]);
        out
    }

    fn read_u16(buf: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([buf[at], buf[at + 1]])
    }

    fn read_u24(buf: &[u8], at: usize) -> usize {
        u32::from_be_bytes([0, buf[at], buf[at + 1], buf[at + 2]]) as usize
    }

    #[test]
    fn test_tls_fingerprint_length_fields_are_enforced() {
        let base = client_hello_bytes(create_chrome_provider(), &[b"h2"], "example.org");
        let hello = parse_client_hello(&base).expect("baseline ClientHello must parse");
        let m = hello.marks;

        // Every truncation must be rejected and must not panic.
        for cut in 0..base.len() {
            assert!(
                parse_client_hello(&base[..cut]).is_err(),
                "a {cut}-byte prefix of the ClientHello was accepted"
            );
        }

        // Record length must equal handshake length.
        for delta in [-1i32, 1] {
            let bad = patch_u16(
                &base,
                m.record_len,
                (read_u16(&base, m.record_len) as i32 + delta) as u16,
            );
            assert!(
                parse_client_hello(&bad).is_err(),
                "record length {delta:+} was accepted"
            );
        }

        // Handshake body length must match the declared one.
        for delta in [-1i32, 1] {
            let bad = patch_u24(
                &base,
                m.handshake_len,
                (read_u24(&base, m.handshake_len) as i32 + delta) as usize,
            );
            assert!(
                parse_client_hello(&bad).is_err(),
                "handshake length {delta:+} was accepted"
            );
        }

        // Cipher-suite list: odd or shifted lengths must not slip through.
        let suite_len = read_u16(&base, m.suite_len);
        for bad_len in [suite_len - 1, suite_len + 1, suite_len + 2] {
            let bad = patch_u16(&base, m.suite_len, bad_len);
            assert!(
                parse_client_hello(&bad).is_err(),
                "cipher-suite length {bad_len} was accepted"
            );
        }

        // Extension block length.
        let ext_len = read_u16(&base, m.ext_block_len);
        for bad_len in [ext_len - 2, ext_len + 2] {
            let bad = patch_u16(&base, m.ext_block_len, bad_len);
            assert!(
                parse_client_hello(&bad).is_err(),
                "extension block length {bad_len} was accepted"
            );
        }

        // The final extension's own length field: inflating it always overruns
        // the block, shrinking it always leaves the block short. rustls shuffles
        // extension order per connection and emits some extensions (e.g.
        // `session_ticket`) with an empty body, so when a zero-length extension
        // lands last there is no smaller value to test — skip that half rather
        // than compare 0 with 0.
        let last_len = read_u16(&base, m.last_ext_len);
        let mut bad_lengths = vec![last_len + 4];
        if last_len > 0 {
            bad_lengths.push(last_len - 1);
        }
        for bad_len in bad_lengths {
            let bad = patch_u16(&base, m.last_ext_len, bad_len);
            assert!(
                parse_client_hello(&bad).is_err(),
                "extension length {bad_len} (was {last_len}) was accepted"
            );
        }

        // An outright duplicated extension (the classic malformed-ClientHello
        // probe) must be caught: rebuild the block and fix every outer length.
        let block_start = m.ext_block_len + 2;
        let block_end = block_start + ext_len as usize;
        let first_start = m.first_ext_len - 2;
        let first_len = read_u16(&base, m.first_ext_len) as usize;
        let first_total = 4 + first_len;
        let mut dup = base.clone();
        let copy: Vec<u8> = dup[first_start..first_start + first_total].to_vec();
        dup.splice(block_end..block_end, copy);
        dup = patch_u16(&dup, m.ext_block_len, ext_len + first_total as u16);
        dup = patch_u24(
            &dup,
            m.handshake_len,
            read_u24(&base, m.handshake_len) + first_total,
        );
        dup = patch_u16(
            &dup,
            m.record_len,
            read_u16(&base, m.record_len) + first_total as u16,
        );
        let err = parse_client_hello(&dup).expect_err("a duplicated extension must be rejected");
        assert!(err.contains("duplicate"), "unexpected error: {err}");
    }

    // ---- SNI for IP literals ------------------------------------------------

    #[test]
    fn test_tls_fingerprint_omits_sni_for_ip_literal() {
        let bytes = client_hello_bytes(create_chrome_provider(), &[b"http/1.1"], "203.0.113.9");
        let hello = parse_client_hello(&bytes).expect("IP-literal ClientHello must parse");
        assert!(
            hello.ext(EXT_SERVER_NAME).is_none(),
            "browsers omit SNI for an IP literal; sending one is a fingerprint"
        );
        assert!(hello.ext(EXT_ALPN).is_some(), "ALPN is still advertised");
    }

    // ---- end-to-end: the profile must be usable, not just pretty -----------

    #[tokio::test]
    async fn test_tls_fingerprint_negotiates_tls13_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::tls::init_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certs = vec![CertificateDer::from(cert.cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
            cert.key_pair.serialize_der(),
        ));
        let acceptor =
            crate::tls::TlsTransport::create_server_acceptor(certs, key, vec![b"h2".to_vec()])
                .expect("server acceptor");

        for (name, provider) in providers() {
            let offered = suite_ids(&provider);
            let cfg = build_client_config(provider.clone(), &[b"h2", b"http/1.1"]);
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);

            let acceptor = acceptor.clone();
            let srv = tokio::spawn(async move {
                let mut tls = acceptor.accept(server_io).await.expect("server handshake");
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.expect("read");
                assert_eq!(&buf, b"ping");
                tls.write_all(b"pong").await.expect("write");
                tls.flush().await.expect("flush");
            });

            let cli = tokio::spawn(async move {
                let name = ServerName::try_from("localhost").unwrap();
                let mut tls = connector
                    .connect(name, client_io)
                    .await
                    .expect("client handshake");
                {
                    let (_, conn) = tls.get_ref();
                    assert_eq!(
                        conn.protocol_version(),
                        Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3),
                        "the profile must negotiate TLS 1.3"
                    );
                    assert_eq!(
                        conn.alpn_protocol(),
                        Some(&b"h2"[..]),
                        "ALPN must be negotiated as offered"
                    );
                    let suite = conn.negotiated_cipher_suite().expect("negotiated suite");
                    assert!(
                        offered.contains(&u16::from(suite.suite())),
                        "negotiated suite {:?} was not offered by the profile",
                        suite.suite()
                    );
                    assert!(suite.tls13().is_some(), "must be a TLS 1.3 suite");
                }
                tls.write_all(b"ping").await.expect("write");
                tls.flush().await.expect("flush");
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.expect("read");
                assert_eq!(&buf, b"pong");
            });

            srv.await
                .unwrap_or_else(|e| panic!("{name}: server task failed: {e}"));
            cli.await
                .unwrap_or_else(|e| panic!("{name}: client task failed: {e}"));
        }
    }

    // ---- `Random` is a dispatcher concern, not a provider -------------------

    #[test]
    fn test_tls_fingerprint_random_variant_resolves_to_a_concrete_profile() {
        for _ in 0..40 {
            let cfg = crate::tls::TlsClientConfig::new("example.org")
                .with_insecure(true)
                .with_fingerprint(TlsFingerprint::Random);
            assert!(
                crate::tls::TlsTransport::create_client_connector(&cfg).is_ok(),
                "Random must resolve to one of the three concrete profiles"
            );
        }
        // Each concrete variant must build a connector too (an unhandled match
        // arm would panic here).
        for fp in [
            TlsFingerprint::Chrome,
            TlsFingerprint::Firefox,
            TlsFingerprint::Safari,
        ] {
            let cfg = crate::tls::TlsClientConfig::new("example.org")
                .with_insecure(true)
                .with_fingerprint(fp);
            assert!(
                crate::tls::TlsTransport::create_client_connector(&cfg).is_ok(),
                "{fp:?} must build a client connector"
            );
        }
    }
}
