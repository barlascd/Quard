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

/// Same as [`evaluate`], but additionally requires a valid post-quantum
/// signature on the request. Mirrors `verification/z3/pqc_policy.py`.
pub fn evaluate_signed(
    authenticated: bool,
    authorized: bool,
    signature_valid: bool,
    risk_score: f32,
) -> Decision {
    if !signature_valid {
        return Decision::Deny;
    }
    evaluate(authenticated, authorized, risk_score)
}
