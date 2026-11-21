use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::{rngs::OsRng, RngCore};

const AAD: &[u8] = b"Quard-V1";

/// AES-256-GCM with a random 96-bit nonce. Do not encrypt more than ~2^32
/// messages under one key (random-nonce collision bound).
pub fn encrypt(key: &[u8; 32], data: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("Invalid key"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: data, aad: AAD },
        )
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("Invalid key"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}
