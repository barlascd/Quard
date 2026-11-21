use quard::isolation::{transition, SystemState::*};
use quard::models::SecurityEvent;
use quard::policy::{evaluate, Decision};

#[test]
fn nan_score_is_denied() {
    assert_eq!(evaluate(true, true, f32::NAN), Decision::Deny);
}

#[test]
fn infinity_is_denied() {
    assert_eq!(evaluate(true, true, f32::INFINITY), Decision::Deny);
}

#[test]
fn score_outside_range_is_denied() {
    assert_eq!(evaluate(true, true, 1.5), Decision::Deny);
    assert_eq!(evaluate(true, true, -0.1), Decision::Deny);
}

#[test]
fn unauthenticated_or_unauthorized_is_denied() {
    assert_eq!(evaluate(false, true, 0.0), Decision::Deny);
    assert_eq!(evaluate(true, false, 0.0), Decision::Deny);
}

#[test]
fn thresholds() {
    assert_eq!(evaluate(true, true, 0.20), Decision::Allow);
    assert_eq!(evaluate(true, true, 0.699), Decision::Allow);
    assert_eq!(evaluate(true, true, 0.70), Decision::Deny);
    assert_eq!(evaluate(true, true, 0.94), Decision::Deny);
    assert_eq!(evaluate(true, true, 0.95), Decision::Isolate);
    assert_eq!(evaluate(true, true, 1.0), Decision::Isolate);
}

fn event(features: [f32; 4]) -> SecurityEvent {
    SecurityEvent {
        user_id: "alice".into(),
        resource: "/db".into(),
        action: "read".into(),
        features,
    }
}

#[test]
fn event_validation() {
    assert!(event([10.0, 0.0, 0.2, 5.0]).validate().is_ok());
    assert!(event([10.0, f32::NAN, 0.2, 5.0]).validate().is_err());
    assert!(event([10.0, -1.0, 0.2, 5.0]).validate().is_err());
    assert!(event([10.0, 0.0, 1.5, 5.0]).validate().is_err());
}

#[test]
fn isolation_state_machine() {
    assert_eq!(transition(Normal, true, false), Restricted);
    assert_eq!(transition(Normal, false, false), Normal);
    assert_eq!(transition(Restricted, true, false), Isolated);
    // Isolated must not be a dead end: it needs an explicit approval.
    assert_eq!(transition(Isolated, false, false), Isolated);
    assert_eq!(transition(Isolated, true, true), Recovery);
    assert_eq!(transition(Recovery, false, true), Normal);
    assert_eq!(transition(Recovery, false, false), Isolated);
    // Normal can never jump straight to Isolated.
    for hr in [false, true] {
        for ap in [false, true] {
            assert_ne!(transition(Normal, hr, ap), Isolated);
        }
    }
}
