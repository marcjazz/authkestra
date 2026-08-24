//! Integration tests for the Axum adapter's stateless (JWT/token-based)
//! wiring: `Engine::axum_router_stateless()` and the `AuthToken` extractor.
//!
//! Mirrors `engine_session_integration.rs` but exercises the `AkApiEngine`
//! (token-only) typestate instead of `AkWebAppEngine`, so the callback
//! returns a JSON body containing a JWT rather than setting a session
//! cookie, and the protected route is guarded by `Authorization: Bearer`
//! instead of a session cookie.

use async_trait::async_trait;
use authkestra_axum::{AuthToken, AxumState, AxumStatelessExt};
use authkestra_engine::auth::{
    AuthError, Identity, OAuthProvider, OAuthToken, Provider, ProviderConfig,
};
use authkestra_engine::flow::{Engine, OAuth2Flow};
use authkestra_engine::AkApiEngine;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use std::collections::HashMap;
use tower::ServiceExt;
use tower_cookies::CookieManagerLayer;

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

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkApiEngine,
}

async fn protected(AuthToken(claims): AuthToken) -> impl IntoResponse {
    let identity = claims.identity.as_ref().expect("token must carry identity");
    Json(serde_json::json!({
        "external_id": identity.external_id,
        "email": identity.email,
    }))
}

fn build_app() -> Router {
    let engine = Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .jwt_secret(b"integration-test-secret-at-least-32-bytes-long!")
        .build();
    let state = AppState {
        auth: engine.clone(),
    };

    Router::new()
        .route("/protected", get(protected))
        .merge(engine.axum_router_stateless())
        .layer(CookieManagerLayer::new())
        .with_state(state)
}

fn set_cookie_value(resp: &axum::response::Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let (key, value) = raw.split_once(';').unwrap_or((raw, "")).0.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn protected_route_rejects_request_without_bearer_token() {
    let app = build_app();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stateless_login_callback_issues_a_working_bearer_token() {
    let app = build_app();

    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login/mock")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    let location = login_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let csrf_state = location.rsplit('=').next().unwrap().to_string();
    let ak_state_cookie = set_cookie_value(&login_resp, "ak_state").unwrap();

    let callback_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/callback/mock?code=valid-code&state={csrf_state}"
                ))
                .header(header::COOKIE, format!("ak_state={ak_state_cookie}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback_resp.status(), StatusCode::OK);
    let token_body = body_json(callback_resp).await;
    let access_token = token_body["access_token"]
        .as_str()
        .expect("callback must return an access_token")
        .to_string();
    assert_eq!(token_body["token_type"], "Bearer");

    let protected_resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(protected_resp.status(), StatusCode::OK);
    let json = body_json(protected_resp).await;
    assert_eq!(json["external_id"], "user-42");
    assert_eq!(json["email"], "user@example.com");
}

#[tokio::test]
async fn protected_route_rejects_garbage_bearer_token() {
    let app = build_app();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, "Bearer not-a-real-jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
