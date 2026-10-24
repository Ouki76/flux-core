#![warn(missing_docs)]

//! Shared types: addressed destinations, the error enum, session metadata and the
//! traits the crates in this workspace implement each other against.
//!
//! Nothing here performs I/O; it is the vocabulary the rest of the workspace shares.

/// Destination addresses and their normalisation.
pub mod address;
/// The workspace error type and its result alias.
pub mod error;
/// Session metadata handed to routing and the connection table.
pub mod session;
/// The traits the crates in this workspace implement each other against.
pub mod traits;

pub use address::*;
pub use error::*;
pub use session::*;
pub use traits::*;

/// Decodes an even-length hexadecimal string into bytes.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let clean = s.trim();
    if !clean.len().is_multiple_of(2) {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("01020a0f"), Some(vec![1, 2, 10, 15]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("1"), None);
        assert_eq!(decode_hex("zz"), None);
    }
}
