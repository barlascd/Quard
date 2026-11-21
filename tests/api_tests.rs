use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use quard::{api, audit::AuditLog, config::Config};
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn app() -> axum::Router {
    let config = Config {
        bind: "127.0.0.1:0".into(),
        api_token: TOKEN.into(),
        // Nothing listens here, so any request that reaches the AI call
        // fails with 503, which is itself a useful test.
        ai_url: "http://127.0.0.1:9/predict".into(),
        audit_path: std::env::temp_dir()
            .join(format!("quard-api-{}.jsonl", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string(),
        authorized_users: vec!["alice".into()],
        pqc_key_path: None,
    };
    let audit = AuditLog::new(config.audit_path.clone()).unwrap();
    api::router(api::AppState::new(config, audit).unwrap())
}

fn request(token: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/v1/security/check")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn body(user: &str, features: &str) -> String {
    format!(r#"{{"user_id":"{user}","resource":"/db","action":"read","features":{features}}}"#)
}

#[tokio::test]
async fn health_is_public() {
    let res = app()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_or_wrong_token_is_401() {
    let b = body("alice", "[10,0,0.2,5]");
    let res = app().oneshot(request(None, &b)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app().oneshot(request(Some("wrong"), &b)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_features_are_400() {
    let b = body("alice", "[10,-1,0.2,5]");
    let res = app().oneshot(request(Some(TOKEN), &b)).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_user_is_403() {
    let b = body("mallory", "[10,0,0.2,5]");
    let res = app().oneshot(request(Some(TOKEN), &b)).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ai_service_down_is_503() {
    let b = body("alice", "[10,0,0.2,5]");
    let res = app().oneshot(request(Some(TOKEN), &b)).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn garbage_body_without_token_is_401_not_422() {
    let res = app().oneshot(request(None, "not json")).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
