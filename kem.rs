use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit},
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
    MlKem768,
};
use zeroize::Zeroizing;

pub const PUBLIC_KEY_LEN: usize = 1184;
pub const CIPHERTEXT_LEN: usize = 1088;
pub const SHARED_SECRET_LEN: usize = 32;

pub type SharedSecret = Zeroizing<[u8; SHARED_SECRET_LEN]>;

/// Generates an ML-KEM-768 key pair.
pub fn generate_keypair() -> (DecapsulationKey, EncapsulationKey) {
    MlKem768::generate_keypair()
}

pub fn encapsulation_key_to_bytes(ek: &EncapsulationKey) -> Vec<u8> {
    ek.to_bytes().to_vec()
}

pub fn encapsulation_key_from_bytes(bytes: &[u8]) -> anyhow::Result<EncapsulationKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        anyhow::bail!("Invalid ML-KEM public key length");
    }
    EncapsulationKey::new_from_slice(bytes).map_err(|_| anyhow::anyhow!("Invalid ML-KEM public key"))
}

/// Returns `(ciphertext, shared_secret)`. Send the ciphertext to the key holder.
pub fn encapsulate(ek: &EncapsulationKey) -> (Vec<u8>, SharedSecret) {
    let (ct, secret) = ek.encapsulate();
    (ct.to_vec(), to_secret(secret.as_ref()))
}

pub fn decapsulate(dk: &DecapsulationKey, ciphertext: &[u8]) -> anyhow::Result<SharedSecret> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        anyhow::bail!("Invalid ML-KEM ciphertext length");
    }
    let ct = Ciphertext::try_from(ciphertext)
        .map_err(|_| anyhow::anyhow!("Invalid ML-KEM ciphertext"))?;
    // ML-KEM uses implicit rejection: a tampered ciphertext does not error,
    // it yields an unrelated secret. The AEAD layer is what detects this.
    Ok(to_secret(dk.decapsulate(&ct).as_ref()))
}

fn to_secret(bytes: &[u8]) -> SharedSecret {
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    out.copy_from_slice(bytes);
    out
}

/// Round-trip self test, usable at startup.
pub fn self_test() -> anyhow::Result<()> {
    let (dk, ek) = generate_keypair();
    let (ct, sender) = encapsulate(&ek);
    let receiver = decapsulate(&dk, &ct)?;
    if *sender != *receiver {
        anyhow::bail!("ML-KEM self test failed");
    }
    Ok(())
}
