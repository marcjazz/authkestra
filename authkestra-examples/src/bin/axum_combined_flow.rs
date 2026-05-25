//! # Axum Combined Flow Example
//!
//! This example demonstrates how `AuthEngine` and `AuthEngineGuard` work together.
//! - `AuthEngine` handles the high-level OAuth2 login flow and session management.
//! - `AuthEngineGuard` provides a flexible way to protect routes using various strategies,
//!   including the sessions created by `AuthEngine`.
//!
//! This separation of concerns allows you to:
//! 1. Use `AuthEngine` for complex login flows (OAuth2, OIDC, etc.).
//! 2. Use `AuthEngineGuard` to protect your API with multiple methods (Sessions, API Keys, JWTs)
//!    in a unified way.

use async_trait::async_trait;
use authkestra::flow::{AuthEngine, OAuth2Flow};
use authkestra_axum::{Auth, AuthkestraAxumExt};
use authkestra_engine::error::AuthError;
use authkestra_engine::state::Identity;
use authkestra_engine::strategy::{SessionProvider, SessionStrategy};
use authkestra_engine::SessionConfig;
use authkestra_engine::{HasSessionStoreMarker, SessionStoreState};
use authkestra_providers_github::GithubProvider;
use authkestra_resource::AuthEngineGuard;
use authkestra_session::SessionStore;
use authkestra_session_memory::MemoryStore;
use axum::{
    extract::{FromRef, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

/// 1. Implement `SessionProvider` for our `SessionStore`.
///
/// This bridges the gap between `authkestra-session` and `authkestra-core` strategies.
struct MySessionProvider {
    store: Arc<dyn SessionStore>,
}

#[async_trait]
impl SessionProvider for MySessionProvider {
    type Identity = Identity;

    async fn load_session(&self, session_id: &str) -> Result<Option<Self::Identity>, AuthError> {
        let session = self.store.load_session(session_id).await?;
        Ok(session.map(|s| s.identity))
    }
}

/// 2. Define our Application State.
///
/// It includes both `AuthEngine` (for flows) and `AuthEngineGuard` (for route protection).
#[derive(Clone)]
struct AppState {
    auth_engine: AuthEngine<HasSessionStoreMarker>,
    guard: Arc<AuthEngineGuard<Identity>>,
}

// Implement FromRef for AuthEngineState compatibility if needed,
// but here we use our own AppState.
impl FromRef<AppState> for AuthEngine<HasSessionStoreMarker> {
    fn from_ref(state: &AppState) -> Self {
        state.auth_engine.clone()
    }
}

impl FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.auth_engine.session_config.clone()
    }
}

impl FromRef<AppState> for Result<Arc<dyn SessionStore>, authkestra_axum::AuthEngineAxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.auth_engine.session_store.get_store())
    }
}

impl FromRef<AppState> for Arc<AuthEngineGuard<Identity>> {
    fn from_ref(state: &AppState) -> Self {
        state.guard.clone()
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();

    // 3. Configure AuthEngine (The Flow Manager)
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    let mut builder = AuthEngine::builder();

    // Add GitHub provider if configured
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID"),
        std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET"),
    ) {
        let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());
        let provider = GithubProvider::new(client_id, client_secret, redirect_uri);
        builder = builder.provider(OAuth2Flow::new(provider));
    }

    let auth_engine = builder
        .session_store(session_store.clone())
        .session_config(SessionConfig {
            secure: false, // For local development
            ..Default::default()
        })
        .build();

    // 4. Configure Guard (The Access Guard)
    // We use a SessionStrategy that looks for the same cookie AuthEngine uses.
    let guard = AuthEngineGuard::<Identity>::builder()
        .strategy(SessionStrategy::new(
            MySessionProvider {
                store: session_store,
            },
            &auth_engine.session_config.cookie_name,
        ))
        .build();

    let state = AppState {
        auth_engine: auth_engine.clone(),
        guard: Arc::new(guard),
    };

    // 5. Build the Axum Router
    let app = Router::new()
        .route("/", get(index))
        // Use the unified `Auth<Identity>` extractor provided by `authkestra-axum`.
        // This extractor uses the `AuthEngineGuard` in the state.
        .route("/protected", get(protected))
        // Merge AuthEngine's login/callback/logout routes
        .merge(auth_engine.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Combined Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let mut html = String::from("<h1>AuthEngine Combined Example</h1>");
    html.push_str(
        "<p>This example shows AuthEngine handling login and Guard protecting routes.</p>",
    );

    if state.auth_engine.providers.contains_key("github") {
        html.push_str("<p><a href=\"/auth/github?scope=user:email&success_url=/protected\">Login with GitHub</a></p>");
    } else {
        html.push_str(
            "<p><i>GitHub provider not configured. Set AUTHKESTRA_GITHUB_CLIENT_ID/SECRET.</i></p>",
        );
    }

    Html(html)
}

/// Protected route using the unified `Auth` extractor.
/// This route is protected by the `AuthEngineGuard` we configured in `main`.
async fn protected(Auth(identity): Auth<Identity>) -> impl IntoResponse {
    format!(
        "<h1>Protected Area</h1>\
          <p>Hello, {}!</p>\
          <p>Your External ID: {}</p>\
          <p>Provider: {}</p>\
          <a href=\"/auth/logout\">Logout</a>",
        identity.username.unwrap_or_else(|| "Unknown".to_string()),
        identity.external_id,
        identity.provider_id,
    )
}
