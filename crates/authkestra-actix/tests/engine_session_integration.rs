//! Integration tests for the Actix adapter's stateful (session-based) wiring.
//!
//! Mirrors `authkestra-axum`'s `engine_session_integration.rs`: a real
//! `actix_web::App` is built with `Engine::actix_scope()` and driven through
//! `actix_web::test::call_service`, asserting on actual HTTP responses
//! rather than calling engine internals directly. See that file's module doc
//! for the rationale (adapter-level regressions — `app_data` wiring,
//! `configure_authkestra`, `AuthSession` extraction, cookie handling — can't
//! be caught by `authkestra-engine`'s own unit tests).
//!
//! The OAuth provider is a fully in-process mock (no network, no wiremock),
//! matching the axum test's approach.

use actix_web::{
    cookie::Cookie,
    http::{header, StatusCode},
    test, web, App, HttpResponse, Responder,
};
use async_trait::async_trait;
use authkestra_actix::{ActixExt, ActixState, AuthSession};
use authkestra_engine::auth::{
    AuthError, Identity, OAuthProvider, OAuthToken, Provider, ProviderConfig, Session, SessionStore,
};
use authkestra_engine::flow::{Engine, OAuth2Flow};
use authkestra_engine::{AkWebAppEngine, SessionConfig};
use std::collections::HashMap;
use std::sync::Mutex;

/// A deterministic, in-process stand-in for a real OAuth2 provider. Only
/// `"valid-code"` exchanges successfully.
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
        // OAuth2Flow::finalize_login rejects the exchange if the identity
        // doesn't echo back the nonce it generated.
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

/// A minimal in-memory `SessionStore`, independent of
/// `authkestra_engine::store::memory::MemoryStore` (which sits behind the
/// `memory` feature) so this test only needs the features it declares via
/// `required-features` in `Cargo.toml`.
#[derive(Default)]
struct TestSessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

#[async_trait]
impl SessionStore for TestSessionStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}

#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
}

async fn protected(session: AuthSession) -> impl Responder {
    let AuthSession(session) = session;
    HttpResponse::Ok().json(serde_json::json!({
        "external_id": session.identity.external_id,
        "email": session.identity.email,
        "provider": session.identity.provider_id,
    }))
}

fn build_engine() -> AkWebAppEngine {
    let session_store: std::sync::Arc<dyn SessionStore> =
        std::sync::Arc::new(TestSessionStore::default());
    Engine::builder()
        .provider(OAuth2Flow::new(MockOAuthProvider))
        .session_store(session_store)
        .session_config(SessionConfig {
            // Tests talk plain HTTP; a `Secure` cookie would never
            // round-trip back to the server.
            secure: false,
            ..Default::default()
        })
        .build()
}

/// Extracts the value of the first `Set-Cookie` header matching `name`.
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
async fn protected_route_rejects_request_without_session_cookie() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let req = test::TestRequest::get().uri("/protected").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn full_login_callback_session_and_logout_round_trip() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    // 1. Login initiates the flow: a redirect to the provider, plus an
    //    encrypted `ak_state` CSRF cookie the callback must see again.
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
    assert!(
        location.starts_with("https://mock.example.com/authorize?state="),
        "unexpected redirect location: {location}"
    );
    let csrf_state = location.rsplit('=').next().unwrap().to_string();
    let ak_state_cookie =
        set_cookie_value(&login_resp, "ak_state").expect("login must set the ak_state CSRF cookie");

    // 2. Callback: present the CSRF cookie, the matching `state`, and a code
    //    the mock provider accepts.
    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=valid-code&state={csrf_state}"
        ))
        .cookie(Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;
    assert_eq!(callback_resp.status(), StatusCode::SEE_OTHER);

    let session_cookie = set_cookie_value(&callback_resp, "authkestra_session")
        .expect("a successful callback must set the session cookie");

    // 3. The protected route now succeeds and returns the identity that came
    //    back from the (mock) provider.
    let protected_req = test::TestRequest::get()
        .uri("/protected")
        .cookie(Cookie::new("authkestra_session", session_cookie.clone()))
        .to_request();
    let protected_resp = test::call_service(&app, protected_req).await;
    assert_eq!(protected_resp.status(), StatusCode::OK);
    let json: serde_json::Value = test::read_body_json(protected_resp).await;
    assert_eq!(json["external_id"], "user-42");
    assert_eq!(json["email"], "user@example.com");
    assert_eq!(json["provider"], "mock");

    // 4. Logout deletes the session server-side...
    let logout_req = test::TestRequest::get()
        .uri("/auth/logout")
        .cookie(Cookie::new("authkestra_session", session_cookie.clone()))
        .to_request();
    let logout_resp = test::call_service(&app, logout_req).await;
    assert_eq!(logout_resp.status(), StatusCode::SEE_OTHER);

    // 5. ...so presenting the very same session cookie again is rejected.
    let after_logout_req = test::TestRequest::get()
        .uri("/protected")
        .cookie(Cookie::new("authkestra_session", session_cookie))
        .to_request();
    let after_logout_resp = test::call_service(&app, after_logout_req).await;
    assert_eq!(after_logout_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn callback_rejects_mismatched_csrf_state() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let login_req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let ak_state_cookie = set_cookie_value(&login_resp, "ak_state").unwrap();

    // The `state` query param doesn't match the one encrypted into the
    // `ak_state` cookie: this must be treated as a CSRF failure.
    let callback_req = test::TestRequest::get()
        .uri("/auth/callback/mock?code=valid-code&state=not-the-real-state")
        .cookie(Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;

    assert_eq!(callback_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn callback_rejects_missing_csrf_cookie() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    // No `ak_state` cookie at all.
    let callback_req = test::TestRequest::get()
        .uri("/auth/callback/mock?code=valid-code&state=whatever")
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;

    assert_eq!(callback_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn callback_rejects_provider_exchange_failure() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .route("/protected", web::get().to(protected))
            .service(engine.actix_scope()),
    )
    .await;

    let login_req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    let location = login_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let csrf_state = location.rsplit('=').next().unwrap().to_string();
    let ak_state_cookie = set_cookie_value(&login_resp, "ak_state").unwrap();

    // A code the mock provider doesn't recognize as valid.
    let callback_req = test::TestRequest::get()
        .uri(&format!(
            "/auth/callback/mock?code=wrong-code&state={csrf_state}"
        ))
        .cookie(Cookie::new("ak_state", ak_state_cookie))
        .to_request();
    let callback_resp = test::call_service(&app, callback_req).await;

    assert_eq!(callback_resp.status(), StatusCode::UNAUTHORIZED);
}

/// An unregistered provider is a client error, and the body that names it must
/// not be sniffable as HTML.
///
/// The actix adapter has always answered 404 here — issue #320 was that axum
/// answered 500 for the same request. What was missing on this side is the
/// content type: `HttpResponseBuilder::body` sets none, and a typeless response
/// echoing a URL-decoded path segment is sniffed as HTML by browsers, which
/// makes this message a reflected-XSS sink reachable from a plain link.
#[actix_web::test]
async fn an_unknown_provider_is_not_found_and_not_sniffable() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    // A payload that is inert as text and executable as HTML.
    let req = test::TestRequest::get()
        .uri("/auth/login/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
        .expect("a body echoing a path segment must declare its content type");
    assert!(
        content_type.starts_with("text/plain"),
        "the 404 body must be text/plain, got {content_type:?}"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff"),
        "without nosniff a browser may still sniff the echoed name as HTML"
    );
}

/// The 404 body echoes the provider name, so the reflection has to be bounded.
/// `authkestra-axum` bounds it identically; this is the test that keeps the two
/// in step, rather than a pair of doc comments asserting it.
#[actix_web::test]
async fn a_long_provider_name_is_truncated_in_the_body() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    let long = "a".repeat(5_000);
    let req = test::TestRequest::get()
        .uri(&format!("/auth/login/{long}"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = test::read_body(resp).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body.len() < 200,
        "the body reflected {} bytes: {body:.120?}",
        body.len()
    );
    assert!(
        body.contains('\u{2026}'),
        "truncation should be visible: {body:?}"
    );
}

/// The login redirect is a 303, matching `authkestra-axum`.
///
/// This adapter answered 302 until the parity sweep: the same request produced
/// a different status code depending on which adapter an application happened
/// to be built on, which is the class of divergence issue #320 was filed about.
/// Every route here is a GET, so both codes send the browser to the same place
/// — but 303 says "fetch the other resource with GET" without relying on the
/// method-rewriting that made 302 ambiguous in the first place.
///
/// The axum suite pins the same code in
/// `a_registered_provider_still_redirects`. Both are needed: a comment saying
/// the adapters agree is not a thing that can fail.
#[actix_web::test]
async fn the_login_redirect_is_a_see_other_like_axum() {
    let engine = build_engine();
    let state = AppState {
        auth: engine.clone(),
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| state.configure_authkestra(cfg))
            .service(engine.actix_scope()),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/auth/login/mock")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        resp.headers().contains_key(header::LOCATION),
        "a redirect must carry a Location header"
    );
}
