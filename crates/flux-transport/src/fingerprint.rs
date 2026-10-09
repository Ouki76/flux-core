use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::SupportedCipherSuite;
use tokio_rustls::rustls::crypto::ring::cipher_suite::*;
use tokio_rustls::rustls::crypto::ring::kx_group::*;
use tokio_rustls::rustls::crypto::{CryptoProvider, SupportedKxGroup};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
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
/// followed by ECDHE-ECDSA and ECDHE-RSA ciphers, with X25519 and SECP256R1 curves.
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
/// Prioritizes TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384.
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

    #[test]
    fn test_tls_fingerprint_profiles() {
        let p_chrome = create_chrome_provider();
        assert!(!p_chrome.cipher_suites.is_empty());

        let p_firefox = create_firefox_provider();
        assert!(!p_firefox.cipher_suites.is_empty());

        let p_safari = create_safari_provider();
        assert!(!p_safari.cipher_suites.is_empty());
    }

    #[test]
    fn test_tls_fingerprint_parsing() {
        assert_eq!(
            TlsFingerprint::parse_str("chrome"),
            Some(TlsFingerprint::Chrome)
        );
        assert_eq!(
            TlsFingerprint::parse_str("firefox"),
            Some(TlsFingerprint::Firefox)
        );
        assert_eq!(
            TlsFingerprint::parse_str("safari"),
            Some(TlsFingerprint::Safari)
        );
        assert_eq!(
            TlsFingerprint::parse_str("random"),
            Some(TlsFingerprint::Random)
        );
        assert_eq!(TlsFingerprint::parse_str("unknown"), None);
    }
}
