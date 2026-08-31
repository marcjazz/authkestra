use actix_web::dev::Service;
use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use async_trait::async_trait;
use authkestra_actix::devsig::DeviceSignatureAuth;
use authkestra_devsig::{IssuerJwks, ReplayError, ReplayStore, VerifierConfig};
use std::sync::Arc;
use std::time::Duration;

struct DummyStore;
#[async_trait]
impl ReplayStore for DummyStore {
    async fn put_if_absent(&self, _jti: &str, _ttl: Duration) -> Result<bool, ReplayError> {
        Ok(true)
    }
}

#[actix_web::test]
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

    let layer = DeviceSignatureAuth::new(config, jwks, store);

    let app = test::init_service(
        App::new()
            .wrap(layer)
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let req = test::TestRequest::get().uri("/").to_request();
    let err = app.call(req).await.unwrap_err();
    let res = err.error_response();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
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

    let layer = DeviceSignatureAuth::new(config, jwks, store).max_body_size(10);

    let app = test::init_service(
        App::new()
            .wrap(layer)
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .set_payload("this body is clearly more than 10 bytes")
        .to_request();
    let err = app.call(req).await.unwrap_err();
    let res = err.error_response();

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
