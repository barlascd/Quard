use quard::{api, audit::AuditLog, config::Config};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    let audit = AuditLog::new(config.audit_path.clone())?;
    let state = api::AppState::new(config.clone(), audit)?;

    let listener = TcpListener::bind(&config.bind).await?;
    println!("Quard listening on {}", config.bind);
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
