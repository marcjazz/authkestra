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

// --- Stateless callback failure diagnosis (#353) ---
//
// These exist for this adapter specifically. `authkestra-axum` routes both
// its session and JWT callbacks through one `finalize_callback_erased`, so a
// single test covers the state-cookie failures for both. This crate holds two
// copies of that block — one per callback — so the stateless copy needs its
// own tests, and would otherwise be the half that drifts.

/// Accumulates emitted `tracing` output so a test can assert on it.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Drives the stateless callback carrying `state_cookie` (if any).
async fn stateless_callback_with_state(state_cookie: Option<&str>) -> (StatusCode, String) {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope_stateless()),
    )
    .await;

    let mut req =
        test::TestRequest::get().uri("/auth/callback/mock?code=valid-code&state=whatever");
    if let Some(cookie) = state_cookie {
        req = req.cookie(actix_web::cookie::Cookie::new("ak_state", cookie));
    }
    let resp = test::call_service(&app, req.to_request()).await;

    let status = resp.status();
    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    (status, logs)
}

#[actix_web::test]
async fn a_stateless_callback_with_no_state_cookie_says_so() {
    let (status, logs) = stateless_callback_with_state(None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        logs.contains("carries no state cookie"),
        "an absent state cookie should be named as such; got:\n{logs}"
    );
    assert!(
        !logs.contains("could not be decrypted"),
        "an absent cookie must not be reported as an undecryptable one:\n{logs}"
    );
}

/// The rotated-key shape, on the stateless path.
#[actix_web::test]
async fn a_stateless_callback_whose_state_cookie_will_not_decrypt_says_so() {
    let (status, logs) = stateless_callback_with_state(Some("not-a-valid-encrypted-state")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        logs.contains("could not be decrypted"),
        "an unreadable state cookie should be named as such; got:\n{logs}"
    );
    assert!(
        logs.contains("state encryption key"),
        "the log should point at key rotation, which is the usual cause; got:\n{logs}"
    );
}

/// The third failure mode on the stateless path: state validated, provider
/// refused the code. The session path has an equivalent test already; this
/// copy of the block needs its own, which is the cost of duplicating it.
#[actix_web::test]
async fn a_stateless_callback_whose_code_exchange_fails_says_so() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope_stateless()),
    )
    .await;

    // A real login, so the state cookie and CSRF value genuinely agree and
    // the request reaches the exchange rather than failing before it.
    let login_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/login/mock")
            .to_request(),
    )
    .await;
    let ak_state = set_cookie_value(&login_resp, "ak_state").expect("login sets ak_state");
    let csrf_state = login_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .and_then(|l| l.split("state=").nth(1))
        .expect("the redirect carries a state parameter")
        .to_string();

    // The mock provider accepts only "valid-code".
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/auth/callback/mock?code=wrong-code&state={csrf_state}"
            ))
            .cookie(actix_web::cookie::Cookie::new("ak_state", ak_state))
            .to_request(),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(
        logs.contains("code exchange failed after state validation"),
        "a provider refusal must be distinguishable from a state failure; got:\n{logs}"
    );
    assert!(
        !logs.contains("carries no state cookie") && !logs.contains("could not be decrypted"),
        "the state checked out, so neither state failure should be reported:\n{logs}"
    );
}
