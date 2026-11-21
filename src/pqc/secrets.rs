use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// A random 256-bit key that is wiped from memory when dropped.
pub fn create_temporary_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}
