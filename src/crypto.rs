use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    Ok((ciphertext, nonce))
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}

pub fn create_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn sign(key: &SigningKey, data: &[u8]) -> [u8; 64] {
    key.sign(data).to_bytes()
}

pub fn verify(key: &VerifyingKey, data: &[u8], signature: &[u8; 64]) -> bool {
    let signature = Signature::from_bytes(signature);
    key.verify(data, &signature).is_ok()
}

pub fn clear_secret(data: &mut Vec<u8>) {
    data.zeroize();
}
