use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub user_id: String,
    pub resource: String,
    pub action: String,
    /// [request_rate, failed_logins, cpu_fraction, process_count]
    pub features: [f32; 4],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub event_id: Uuid,
    pub decision: String,
    pub risk_score: f32,
    pub reason: String,
}

impl SecurityEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.user_id.is_empty() || self.user_id.len() > 128 {
            return Err("Invalid user".into());
        }
        if self.resource.is_empty() || self.resource.len() > 512 {
            return Err("Invalid resource".into());
        }
        if self.action.is_empty() || self.action.len() > 128 {
            return Err("Invalid action".into());
        }
        if !self.features.iter().all(|x| x.is_finite()) {
            return Err("Invalid numerical input".into());
        }
        if self.features[0] < 0.0
            || self.features[1] < 0.0
            || !(0.0..=1.0).contains(&self.features[2])
            || self.features[3] < 0.0
        {
            return Err("Feature out of range".into());
        }
        Ok(())
    }
}
