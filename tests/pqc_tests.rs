use std::sync::Arc;

use quard::audit::{verify_chain, verify_signed_chain, AuditLog};
use quard::policy::{evaluate_signed, Decision};
use quard::pqc::{
    encryption, envelope, integrity, kem, key_derivation, secrets,
    signature::{self, PqSigner},
};

fn tmp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!("quard-pqc-{}-{name}", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

// ---------- ML-KEM ----------

#[test]
fn kem_roundtrip_and_sizes() {
    let (dk, ek) = kem::generate_keypair();
    assert_eq!(kem::encapsulation_key_to_bytes(&ek).len(), kem::PUBLIC_KEY_LEN);
    let (ct, a) = kem::encapsulate(&ek);
    assert_eq!(ct.len(), kem::CIPHERTEXT_LEN);
    let b = kem::decapsulate(&dk, &ct).unwrap();
    assert_eq!(*a, *b);
    kem::self_test().unwrap();
}

#[test]
fn kem_public_key_survives_serialization() {
    let (dk, ek) = kem::generate_keypair();
    let ek2 = kem::encapsulation_key_from_bytes(&kem::encapsulation_key_to_bytes(&ek)).unwrap();
    let (ct, a) = kem::encapsulate(&ek2);
    assert_eq!(*a, *kem::decapsulate(&dk, &ct).unwrap());
}

#[test]
fn kem_rejects_bad_lengths_and_implicitly_rejects_tampering() {
    let (dk, ek) = kem::generate_keypair();
    assert!(kem::encapsulation_key_from_bytes(&[0u8; 10]).is_err());
    assert!(kem::decapsulate(&dk, &[0u8; 10]).is_err());

    let (mut ct, secret) = kem::encapsulate(&ek);
    ct[0] ^= 1;
    // Implicit rejection: no error, but a different secret.
    assert_ne!(*secret, *kem::decapsulate(&dk, &ct).unwrap());
}

// ---------- ML-DSA ----------

#[test]
fn signature_roundtrip_and_sizes() {
    let s = PqSigner::generate();
    let sig = s.sign(b"QUARD UPDATE");
    assert_eq!(sig.len(), signature::SIGNATURE_LEN);
    assert_eq!(s.public_key().len(), signature::PUBLIC_KEY_LEN);
    assert!(signature::verify(&s.public_key(), b"QUARD UPDATE", &sig));
}

#[test]
fn signature_rejects_tampering_wrong_key_and_garbage() {
    let s = PqSigner::generate();
    let other = PqSigner::generate();
    let sig = s.sign(b"msg");

    assert!(!signature::verify(&s.public_key(), b"other msg", &sig));
    assert!(!signature::verify(&other.public_key(), b"msg", &sig));
    let mut bad = sig.clone();
    bad[100] ^= 1;
    assert!(!signature::verify(&s.public_key(), b"msg", &bad));
    assert!(!signature::verify(&s.public_key(), b"msg", &[0u8; 5]));
    assert!(!signature::verify(&[0u8; 5], b"msg", &sig));
}

#[test]
fn signing_key_persists_via_seed_file() {
    let path = tmp("key.hex");
    let a = PqSigner::load_or_create(&path).unwrap();
    let b = PqSigner::load_or_create(&path).unwrap(); // loads, doesn't regenerate
    assert_eq!(a.public_key(), b.public_key());
    assert!(signature::verify(&b.public_key(), b"x", &a.sign(b"x")));
    let pubhex = std::fs::read_to_string(format!("{path}.pub")).unwrap();
    assert_eq!(hex::decode(pubhex).unwrap(), a.public_key());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

// ---------- KDF / AEAD / hash / secrets ----------

#[test]
fn hkdf_is_deterministic_and_salt_sensitive() {
    let k1 = key_derivation::derive_key(b"secret", b"salt-a").unwrap();
    let k2 = key_derivation::derive_key(b"secret", b"salt-a").unwrap();
    let k3 = key_derivation::derive_key(b"secret", b"salt-b").unwrap();
    assert_eq!(*k1, *k2);
    assert_ne!(*k1, *k3);
}

#[test]
fn aes_gcm_roundtrip_and_tamper_detection() {
    let key = secrets::create_temporary_key();
    let (mut ct, nonce) = encryption::encrypt(&key, b"hello").unwrap();
    assert_eq!(encryption::decrypt(&key, &nonce, &ct).unwrap(), b"hello");
    ct[0] ^= 1;
    assert!(encryption::decrypt(&key, &nonce, &ct).is_err());
    let other = secrets::create_temporary_key();
    let (ct, nonce) = encryption::encrypt(&key, b"hello").unwrap();
    assert!(encryption::decrypt(&other, &nonce, &ct).is_err());
}

#[test]
fn temporary_keys_are_random_not_zero() {
    let a = secrets::create_temporary_key();
    let b = secrets::create_temporary_key();
    assert_ne!(*a, [0u8; 32]);
    assert_ne!(*a, *b);
}

#[test]
fn sha3_known_vector_and_verify() {
    // NIST: SHA3-256("abc")
    let expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    assert_eq!(integrity::calculate_hash(b"abc"), expected);
    assert!(integrity::verify_hash(b"abc", expected));
    assert!(integrity::verify_hash(b"abc", &expected.to_uppercase()));
    assert!(!integrity::verify_hash(b"abd", expected));
    assert!(!integrity::verify_hash(b"abc", "short"));
}

// ---------- Envelope (KEM + HKDF + AES-GCM) ----------

#[test]
fn envelope_roundtrip_json_and_wrong_recipient() {
    let (dk, ek) = kem::generate_keypair();
    let env = envelope::seal(&kem::encapsulation_key_to_bytes(&ek), b"top secret").unwrap();

    let json = serde_json::to_string(&env).unwrap();
    let env2: envelope::Envelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope::open(&dk, &env2).unwrap(), b"top secret");

    let (other_dk, _) = kem::generate_keypair();
    assert!(envelope::open(&other_dk, &env2).is_err());

    let mut tampered = env2.clone();
    tampered.ciphertext = format!("00{}", &tampered.ciphertext[2..]);
    assert!(envelope::open(&dk, &tampered).is_err());
}

// ---------- Policy ----------

#[test]
fn invalid_signature_is_always_denied() {
    assert_eq!(evaluate_signed(true, true, false, 0.0), Decision::Deny);
    assert_eq!(evaluate_signed(true, true, true, 0.2), Decision::Allow);
    assert_eq!(evaluate_signed(false, true, true, 0.2), Decision::Deny);
    assert_eq!(evaluate_signed(true, true, true, 0.99), Decision::Isolate);
}

// ---------- Signed audit log ----------

#[tokio::test]
async fn signed_audit_log_verifies_and_detects_forgery() {
    let path = tmp("audit.jsonl");
    let signer = Arc::new(PqSigner::generate());
    let pk = signer.public_key();

    let log = AuditLog::with_signer(path.clone(), Some(signer)).unwrap();
    log.append("e1", "alice", "ALLOW", 0.1).await.unwrap();
    log.append("e2", "bob", "DENY", 0.8).await.unwrap();
    assert_eq!(verify_signed_chain(&path, &pk).unwrap(), 2);

    // Wrong public key fails.
    assert!(verify_signed_chain(&path, &PqSigner::generate().public_key()).is_err());

    // Attacker edits a record AND recomputes nothing: hash chain breaks.
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("DENY", "ALLOW")).unwrap();
    assert!(verify_chain(&path).is_err());
}

#[tokio::test]
async fn unsigned_records_fail_signed_verification_but_pass_plain_chain() {
    let path = tmp("unsigned.jsonl");
    let log = AuditLog::new(path.clone()).unwrap();
    log.append("e1", "alice", "ALLOW", 0.1).await.unwrap();
    assert_eq!(verify_chain(&path).unwrap(), 1);
    let pk = PqSigner::generate().public_key();
    assert!(verify_signed_chain(&path, &pk).is_err());
}
