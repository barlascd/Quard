use std::sync::Arc;

use quard::{api, audit, audit::AuditLog, config::Config, pqc, pqc::signature::PqSigner};
use tokio::net::TcpListener;

/// `quard verify-audit <log> [<public-key-hex-file>]`
fn verify_audit(args: &[String]) -> anyhow::Result<()> {
    let log = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: quard verify-audit <log> [<public-key-file>]"))?;
    let n = match args.get(1) {
        Some(key_file) => {
            let key = hex::decode(std::fs::read_to_string(key_file)?.trim())?;
            audit::verify_signed_chain(log, &key)?
        }
        None => audit::verify_chain(log)?,
    };
    println!("OK: {n} records verified");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("verify-audit") {
        return verify_audit(&args[1..]);
    }

    let config = Config::from_env()?;
    pqc::kem::self_test()?;

    let signer = match &config.pqc_key_path {
        Some(path) => {
            let signer = PqSigner::load_or_create(path)?;
            println!("Audit log signing: ML-DSA-65 enabled (key: {path})");
            Some(Arc::new(signer))
        }
        None => {
            println!("Audit log signing: disabled (set QS_PQC_KEY_PATH to enable)");
            None
        }
    };

    let audit = AuditLog::with_signer(config.audit_path.clone(), signer)?;
    let state = api::AppState::new(config.clone(), audit)?;

    let listener = TcpListener::bind(&config.bind).await?;
    println!("Quard listening on {}", config.bind);
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
