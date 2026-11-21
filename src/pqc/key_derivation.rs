use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const INFO: &[u8] = b"QUARD-AES-256-GCM-v1";

/// Derives a 32-byte AES-256-GCM key from a KEM shared secret.
pub fn derive_key(shared_secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut output_key = Zeroizing::new([0u8; 32]);
    hk.expand(INFO, &mut *output_key).map_err(|_| "Key failed")?;
    Ok(output_key)
}
