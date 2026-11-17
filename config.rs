use std::env;

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub api_token: String,
    pub ai_url: String,
    pub audit_path: String,
    pub authorized_users: Vec<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let token = env::var("QS_API_TOKEN")
            .map_err(|_| anyhow::anyhow!("QS_API_TOKEN is not set"))?;
        if token.len() < 32 {
            anyhow::bail!("API token is too short (minimum 32 characters)");
        }

        let users = env::var("QS_AUTHORIZED_USERS").unwrap_or_default();
        let authorized_users = users
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect();

        Ok(Self {
            bind: env::var("QS_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into()),
            api_token: token,
            ai_url: env::var("QS_AI_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8000/predict".into()),
            audit_path: env::var("QS_AUDIT_PATH")
                .unwrap_or_else(|_| "logs/audit.jsonl".into()),
            authorized_users,
        })
    }
}
