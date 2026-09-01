use async_trait::async_trait;
use authkestra_axum::devsig::DeviceSignatureLayer;
use authkestra_devsig::{IssuerJwks, ReplayError, ReplayStore, VerifierConfig};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

struct DummyStore;
#[async_trait]
impl ReplayStore for DummyStore {
    async fn put_if_absent(&self, _jti: &str, _ttl: Duration) -> Result<bool, ReplayError> {
        Ok(true)
    }
}

#[tokio::test]
async fn test_devsig_rejects_missing_signature() {
    let config = VerifierConfig::new(
        vec!["http://issuer".to_string()],
        vec![],
        Duration::from_secs(5),
        Duration::from_secs(60),
        "audience",
    );
    let jwks = Arc::new(IssuerJwks::new());
    let store = Arc::new(DummyStore);

    let layer = DeviceSignatureLayer::new(config, jwks, store);

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_devsig_rejects_too_large_body() {
    let config = VerifierConfig::new(
        vec!["http://issuer".to_string()],
        vec![],
        Duration::from_secs(5),
        Duration::from_secs(60),
        "audience",
    );
    let jwks = Arc::new(IssuerJwks::new());
    let store = Arc::new(DummyStore);

    let layer = DeviceSignatureLayer::new(config, jwks, store).max_body_size(10);

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let req = Request::builder()
        .uri("/")
        .body(Body::from("this body is clearly more than 10 bytes"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
