use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
    SigningKey, Verifier, VerifyingKey,
};
use std::path::Path;
use zeroize::Zeroizing;

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 1952;
pub const SIGNATURE_LEN: usize = 3309;

/// Domain separation so a Quard signature can't be replayed in another protocol.
const DOMAIN: &[u8] = b"QUARD-MLDSA65-v1|";

fn framed(message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + message.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(message);
    m
}

/// ML-DSA-65 signing key.
pub struct PqSigner {
    key: SigningKey<MlDsa65>,
}

impl PqSigner {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::<MlDsa65>::generate(),
        }
    }

    pub fn from_seed(seed: &[u8]) -> anyhow::Result<Self> {
        if seed.len() != SEED_LEN {
            anyhow::bail!("Invalid ML-DSA seed length");
        }
        let key = SigningKey::<MlDsa65>::new_from_slice(seed)
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA seed"))?;
        Ok(Self { key })
    }

    /// The 32-byte seed from which the whole key is derived.
    pub fn seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.key.to_bytes().to_vec())
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(&framed(message)).to_bytes().to_vec()
    }

    /// Loads a hex-encoded seed from `path`, or creates one (and a `.pub`
    /// file next to it) if the file does not exist.
    pub fn load_or_create(path: &str) -> anyhow::Result<Self> {
        let p = Path::new(path);
        if p.exists() {
            let text = Zeroizing::new(std::fs::read_to_string(p)?);
            let seed = Zeroizing::new(hex::decode(text.trim())?);
            return Self::from_seed(&seed);
        }
        let signer = Self::generate();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_private(p, &hex::encode(&*signer.seed()))?;
        std::fs::write(format!("{path}.pub"), hex::encode(signer.public_key()))?;
        Ok(signer)
    }
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

/// Verifies `signature` over `message` against a raw ML-DSA-65 public key.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
        return false;
    }
    let Ok(vk) = VerifyingKey::<MlDsa65>::new_from_slice(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    vk.verify(&framed(message), &sig).is_ok()
}
