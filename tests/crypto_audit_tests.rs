use quard::audit::{verify_chain, AuditLog};
use quard::crypto;

#[test]
fn encrypt_roundtrip_and_tamper_detection() {
    let key = crypto::generate_key();
    let (mut ct, nonce) = crypto::encrypt(&key, b"secret").unwrap();
    assert_eq!(crypto::decrypt(&key, &nonce, &ct).unwrap(), b"secret");
    ct[0] ^= 1;
    assert!(crypto::decrypt(&key, &nonce, &ct).is_err());
}

#[test]
fn sign_and_verify() {
    let sk = crypto::create_signing_key();
    let sig = crypto::sign(&sk, b"msg");
    assert!(crypto::verify(&sk.verifying_key(), b"msg", &sig));
    assert!(!crypto::verify(&sk.verifying_key(), b"other", &sig));
}

#[tokio::test]
async fn audit_chain_survives_restart_and_detects_tampering() {
    let dir = std::env::temp_dir().join(format!("quard-{}", uuid::Uuid::new_v4()));
    let path = dir.join("audit.jsonl").to_string_lossy().to_string();

    let log = AuditLog::new(path.clone()).unwrap();
    log.append("e1", "alice", "ALLOW", 0.1).await.unwrap();
    log.append("e2", "alice|x", "DENY", 0.8).await.unwrap();

    // "Restart": a new instance must continue the same chain.
    let log2 = AuditLog::new(path.clone()).unwrap();
    log2.append("e3", "bob", "ISOLATE", 0.99).await.unwrap();
    assert_eq!(verify_chain(&path).unwrap(), 3);

    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("DENY", "ALLOW")).unwrap();
    assert!(verify_chain(&path).is_err());

    let _ = std::fs::remove_dir_all(dir);
}
