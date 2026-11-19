use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

/// SHA3-256 of `data`, lowercase hex.
pub fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Constant-time comparison of `data`'s hash against an expected hex digest.
pub fn verify_hash(data: &[u8], expected_hex: &str) -> bool {
    let actual = calculate_hash(data);
    actual.len() == expected_hex.len()
        && bool::from(actual.as_bytes().ct_eq(expected_hex.to_ascii_lowercase().as_bytes()))
}
