#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    Isolate,
}

/// Risk at or above this value is denied.
pub const DENY_THRESHOLD: f32 = 0.70;
/// Risk at or above this value triggers the isolation workflow.
pub const ISOLATE_THRESHOLD: f32 = 0.95;

pub fn evaluate(authenticated: bool, authorized: bool, risk_score: f32) -> Decision {
    if !authenticated || !authorized {
        return Decision::Deny;
    }
    if !risk_score.is_finite() || !(0.0..=1.0).contains(&risk_score) {
        return Decision::Deny;
    }
    if risk_score >= ISOLATE_THRESHOLD {
        Decision::Isolate
    } else if risk_score >= DENY_THRESHOLD {
        Decision::Deny
    } else {
        Decision::Allow
    }
}
