use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    ai_client::{self, predict},
    audit::AuditLog,
    config::Config,
    identity::{check_identity, IdentityStatus},
    models::{SecurityDecision, SecurityEvent},
    policy::{evaluate, Decision},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub audit: AuditLog,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config, audit: AuditLog) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            audit,
            http: ai_client::build_client()?,
        })
    }
}

async fn health() -> &'static str {
    "Quard is online"
}

fn valid_token(headers: &HeaderMap, expected: &str) -> bool {
    let Some(header) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = header.to_str() else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    token.len() == expected.len() && bool::from(token.as_bytes().ct_eq(expected.as_bytes()))
}

/// Runs before the body is parsed, so unauthenticated callers always get 401.
async fn require_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !valid_token(request.headers(), &state.config.api_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

async fn security_check(
    State(state): State<AppState>,
    Json(event): Json<SecurityEvent>,
) -> Result<(StatusCode, Json<SecurityDecision>), StatusCode> {
    event.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let identity = check_identity(&state.config, &event.user_id);
    if identity != IdentityStatus::Authenticated {
        return Err(StatusCode::FORBIDDEN);
    }

    let risk = predict(&state.http, &state.config.ai_url, event.features)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // Identity is the allow-list check above; there is no separate
    // authorization layer yet, so `authorized` mirrors it.
    let decision = evaluate(true, true, risk);

    let (label, reason, status) = match decision {
        Decision::Allow => ("ALLOW", "Security policy passed", StatusCode::OK),
        Decision::Deny => ("DENY", "Risk threshold exceeded", StatusCode::FORBIDDEN),
        Decision::Isolate => (
            "ISOLATE",
            "Isolation workflow required",
            StatusCode::FORBIDDEN,
        ),
    };

    let event_id = Uuid::new_v4();
    state
        .audit
        .append(&event_id.to_string(), &event.user_id, label, risk)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        status,
        Json(SecurityDecision {
            event_id,
            decision: label.to_string(),
            risk_score: risk,
            reason: reason.to_string(),
        }),
    ))
}

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/v1/security/check", post(security_check))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
}
