use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{create_dir_all, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::Arc,
};
use tokio::sync::Mutex;

use crate::pqc::signature::{self, PqSigner};

pub const GENESIS: &str = "GENESIS";

/// Append-only, hash-chained JSONL audit log.
#[derive(Clone)]
pub struct AuditLog {
    path: String,
    previous_hash: Arc<Mutex<String>>,
    /// When set, every record's hash is signed with ML-DSA-65.
    signer: Option<Arc<PqSigner>>,
}

#[derive(Serialize, Deserialize)]
struct AuditRecord {
    timestamp: u64,
    event_id: String,
    user_id: String,
    decision: String,
    risk_score: f32,
    previous_hash: String,
    record_hash: String,
    /// Hex ML-DSA-65 signature over `record_hash`. Absent when signing is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

/// Hash over a JSON array, so delimiter characters inside fields cannot
/// make two different records hash identically.
fn record_hash(
    timestamp: u64,
    event_id: &str,
    user_id: &str,
    decision: &str,
    risk_score: f32,
    previous: &str,
) -> String {
    let canonical =
        serde_json::json!([timestamp, event_id, user_id, decision, risk_score, previous])
            .to_string();
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

impl AuditLog {
    /// Opens the log. If the file already exists, the chain continues from
    /// its last record so restarts do not break it.
    pub fn new(path: String) -> anyhow::Result<Self> {
        Self::with_signer(path, None)
    }

    /// Like [`AuditLog::new`], but signs every new record with `signer`.
    pub fn with_signer(path: String, signer: Option<Arc<PqSigner>>) -> anyhow::Result<Self> {
        let mut last = GENESIS.to_string();
        if Path::new(&path).exists() {
            let reader = BufReader::new(File::open(&path)?);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let rec: AuditRecord = serde_json::from_str(&line)
                    .map_err(|e| anyhow::anyhow!("Corrupt audit log: {e}"))?;
                last = rec.record_hash;
            }
        }
        Ok(Self {
            path,
            previous_hash: Arc::new(Mutex::new(last)),
            signer,
        })
    }

    pub async fn append(
        &self,
        event_id: &str,
        user_id: &str,
        decision: &str,
        risk_score: f32,
    ) -> anyhow::Result<()> {
        let mut previous = self.previous_hash.lock().await;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let hash = record_hash(timestamp, event_id, user_id, decision, risk_score, &previous);
        let signature = self
            .signer
            .as_ref()
            .map(|s| hex::encode(s.sign(hash.as_bytes())));
        let record = AuditRecord {
            timestamp,
            event_id: event_id.to_string(),
            user_id: user_id.to_string(),
            decision: decision.to_string(),
            risk_score,
            previous_hash: previous.clone(),
            record_hash: hash.clone(),
            signature,
        };

        let path = Path::new(&self.path);
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        file.sync_data()?;

        *previous = hash;
        Ok(())
    }
}

/// Re-computes every hash in the file. Returns the number of valid records.
pub fn verify_chain(path: &str) -> anyhow::Result<usize> {
    let reader = BufReader::new(File::open(path)?);
    let mut previous = GENESIS.to_string();
    let mut count = 0;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let r: AuditRecord = serde_json::from_str(&line)?;
        let expected = record_hash(
            r.timestamp,
            &r.event_id,
            &r.user_id,
            &r.decision,
            r.risk_score,
            &previous,
        );
        if r.previous_hash != previous || r.record_hash != expected {
            anyhow::bail!("Audit chain broken at record {}", count + 1);
        }
        previous = r.record_hash;
        count += 1;
    }
    Ok(count)
}

/// Verifies the hash chain *and* the ML-DSA-65 signature on every record.
/// Fails if any record is unsigned or signed by a different key.
pub fn verify_signed_chain(path: &str, public_key: &[u8]) -> anyhow::Result<usize> {
    let count = verify_chain(path)?;
    let reader = BufReader::new(File::open(path)?);
    let mut n = 0;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        n += 1;
        let r: AuditRecord = serde_json::from_str(&line)?;
        let sig = match r.signature {
            Some(s) => hex::decode(s)?,
            None => anyhow::bail!("Record {n} is not signed"),
        };
        if !signature::verify(public_key, r.record_hash.as_bytes(), &sig) {
            anyhow::bail!("Invalid signature on record {n}");
        }
    }
    Ok(count)
}
