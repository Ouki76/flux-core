//! Shared cryptographic helpers.
//!
//! Secret comparison lives here so that every call site uses the same
//! constant-time implementation. Five separate copies had accumulated across
//! `flux-protocol` and `flux-app`, with subtly different semantics (some
//! case-folding, some comparing `Uuid` values); consolidating removes the chance
//! of a new call site picking a non-constant-time variant.

/// Constant-time equality for byte strings.
///
/// The length is compared first: it is not secret for the fixed-size secrets used
/// here (a UUID is 16 bytes, a Trojan hash 56, a TUIC token 32). Callers that
/// compare variable-length secrets (API bearer tokens) should be aware that this
/// leaks the length.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // `subtle` provides a `black_box`-guarded, `#[inline(never)]` comparison that
    // LLVM is not allowed to turn into an early-exit `memcmp`. A hand-rolled
    // `diff |= x ^ y` loop carries no such guarantee.
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Constant-time equality for strings (byte-wise, no allocation).
#[inline]
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Constant-time equality where one side is the expected value.
///
/// Semantically identical to [`constant_time_eq`]; named for readability at
/// verification sites.
#[inline]
pub fn verify_secret(expected: &[u8], provided: &[u8]) -> bool {
    constant_time_eq(expected, provided)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_matches_plain_comparison() {
        for (a, b, want) in [
            ("", "", true),
            ("abc", "abc", true),
            ("abc", "abd", false),
            ("abc", "ab", false),
            ("abc", "abc ", false),
            ("Привет", "Привет", true),
            ("Привет", "привет", false),
        ] {
            assert_eq!(constant_time_eq_str(a, b), want, "{a:?} vs {b:?}");
            assert_eq!(verify_secret(a.as_bytes(), b.as_bytes()), want);
        }
    }

    #[test]
    fn single_bit_difference_is_detected() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert!(!constant_time_eq(&a, &b));
        b[31] = 0;
        assert!(constant_time_eq(&a, &b));
    }
}
