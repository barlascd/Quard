//! ML-KEM-768 + HKDF-SHA256 + AES-256-GCM, composed: anyone holding a
//! recipient's public key can `seal` data that only the recipient can `open`.
use serde::{Deserialize, Serialize};

use super::{encryption, kem, key_derivation};
use ml_kem::ml_kem_768::DecapsulationKey;
use rand::{rngs::OsRng, RngCore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub kem_ciphertext: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn seal(recipient_public_key: &[u8], plaintext: &[u8]) -> anyhow::Result<Envelope> {
    let ek = kem::encapsulation_key_from_bytes(recipient_public_key)?;
    let (kem_ct, secret) = kem::encapsulate(&ek);

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let key = key_derivation::derive_key(&*secret, &salt).map_err(anyhow::Error::msg)?;
    let (ciphertext, nonce) = encryption::encrypt(&key, plaintext)?;

    Ok(Envelope {
        kem_ciphertext: hex::encode(kem_ct),
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn open(dk: &DecapsulationKey, envelope: &Envelope) -> anyhow::Result<Vec<u8>> {
    let secret = kem::decapsulate(dk, &hex::decode(&envelope.kem_ciphertext)?)?;
    let key = key_derivation::derive_key(&*secret, &hex::decode(&envelope.salt)?)
        .map_err(anyhow::Error::msg)?;
    let nonce: [u8; 12] = hex::decode(&envelope.nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?;
    encryption::decrypt(&key, &nonce, &hex::decode(&envelope.ciphertext)?)
}
