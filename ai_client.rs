use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AIRequest {
    features: [f32; 4],
}

#[derive(Deserialize)]
struct AIResponse {
    risk_score: f32,
}

pub fn build_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?)
}

pub async fn predict(
    client: &reqwest::Client,
    url: &str,
    features: [f32; 4],
) -> anyhow::Result<f32> {
    let response = client
        .post(url)
        .json(&AIRequest { features })
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("AI service failed");
    }

    let result: AIResponse = response.json().await?;
    if !result.risk_score.is_finite() || !(0.0..=1.0).contains(&result.risk_score) {
        anyhow::bail!("Invalid AI result");
    }
    Ok(result.risk_score)
}
