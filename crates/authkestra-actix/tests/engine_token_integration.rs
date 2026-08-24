//! Integration tests for the Actix adapter's stateless (JWT/token-based)
//! wiring: `Engine::actix_scope_stateless()` and the `AuthToken` extractor.
//!
//! Mirrors `authkestra-axum`'s `engine_token_integration.rs` but through a
//! real `actix_web::App` driven by `actix_web::test::call_service`.

use actix_web::{
    http::{header, StatusCode},
    test, web, App, HttpResponse, Responder,
};
use async_trait::async_trait;
use authkestra_actix::{ActixState, ActixStatelessExt, AuthToken};
use authkestra_engine::auth::{
    AuthError, Identity, OAuthProvider, OAuthToken, Provider, ProviderConfig,
};
use authkestra_engine::flow::{Engine, OAuth2Flow};
use authkestra_engine::AkApiEngine;
use std::collections::HashMap;

struct MockOAuthProvider;

#[async_trait]
impl Provider for MockOAuthProvider {
    async fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "mock".to_string(),
            name: "Mock".to_string(),
            extra: HashMap::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for MockOAuthProvider {
    fn provider_id(&self) -> &str {
        "mock"
    }

    fn get_authorization_url(
        &self,
        state: &str,
        _scopes: &[&str],
        _code_challenge: Option<&str>,
        _nonce: Option<&str>,
    ) -> String {
        format!("https://mock.example.com/authorize?state={state}")
    }

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        if code != "valid-code" {
            return Err(AuthError::Token("invalid code".to_string()));
        }

        let mut attributes = HashMap::new();
        if let Some(n) = nonce {
            attributes.insert("nonce".to_string(), n.to_string());
        }

        Ok((
            Identity {
                provider_id: "mock".to_string(),
                external_id: "user-42".to_string(),
                email: Some("user@example.com".to_string()),
                username: Some("mockuser".to_string()),
                attributes,
            },
            OAuthToken {
                access_token: "at-123".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        ))
    }
}

#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkApiEngine,
}

async fn protected(auth: AuthToken) -> impl Responder {
    let AuthToken(claims) = auth;
    let identity = claims.identity.as_ref().expect("token must carry identity");
    HttpResponse::Ok().json(serde_json::json!({
        "external_id": identity.external_id,
        "email": identity.email,
    }))
}

fn build_engine() -> AkApiEngine {
    Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .jwt_secret(b"integration-test-secret-at-least-32-bytes-long!")
        .build()
}

fn set_cookie_value(resp: &actix_web::dev::ServiceResponse, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let (key, value) = raw.split_once(';').unwrap_or((raw, "")).0.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
}

#[actix_web::test]
async fn protected_route_rejects_request_without_bearer_token() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope_stateless()),
    )
    .await;

    let req = test::TestRequest::get().uri("/protected").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn stateless_login_callback_issues_a_working_bearer_token() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope_stateless()),
    )
    .await;

    let login_req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status(), StatusCode::FOUND);
    let location = login_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let csrf_state = location.rsplit('=').next().unwrap().to_string();
    let ak_state_cookie = set_cookie_value(&login_resp, "ak_state").unwrap();

    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=valid-code&state={csrf_state}"
        ))
        .cookie(actix_web::cookie::Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(callback_resp.status(), StatusCode::OK);
    let token_body: serde_json::Value = test::read_body_json(callback_resp).await;
    let access_token = token_body["access_token"]
        .as_str()
        .expect("callback must return an access_token")
        .to_string();
    assert_eq!(token_body["token_type"], "Bearer");

    let protected_req = test::TestRequest::get()
        .uri("/protected")
        .insert_header((header::AUTHORIZATION, format!("Bearer {access_token}")))
        .to_request();
    let protected_resp = test::call_service(&app, protected_req).await;
    assert_eq!(protected_resp.status(), StatusCode::OK);
    let json: serde_json::Value = test::read_body_json(protected_resp).await;
    assert_eq!(json["external_id"], "user-42");
    assert_eq!(json["email"], "user@example.com");
}

#[actix_web::test]
async fn protected_route_rejects_garbage_bearer_token() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope_stateless()),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-real-jwt"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
