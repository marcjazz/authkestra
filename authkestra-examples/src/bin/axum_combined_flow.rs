//! # Axum Combined Flow Example
//!
//! This example demonstrates how `Authkestra` and `AuthGuard` work together.
//! - `Authkestra` handles the high-level OAuth2 login flow and session management.
//! - `AuthGuard` provides a flexible way to protect routes using various strategies,
//!   including the sessions created by `Authkestra`.
//!
//! This separation of concerns allows you to:
//! 1. Use `Authkestra` for complex login flows (OAuth2, OIDC, etc.).
//! 2. Use `AuthGuard` to protect your API with multiple methods (Sessions, API Keys, JWTs)
//!    in a unified way.

use async_trait::async_trait;
use authkestra::flow::{Authkestra, OAuth2Flow};
use authkestra_axum::{Auth, AuthkestraAxumExt, SessionConfig};
use authkestra_core::error::AuthError;
use authkestra_core::state::Identity;
use authkestra_core::strategy::{SessionProvider, SessionStrategy};
use authkestra_flow::{HasSessionStoreMarker, SessionStoreState};
use authkestra_guard::AuthGuard;
use authkestra_providers_github::GithubProvider;
use authkestra_session::{MemoryStore, SessionStore};
use axum::{
    extract::{FromRef, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;

/// 1. Implement `SessionProvider` for our `SessionStore`.
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
/// It includes both `Authkestra` (for flows) and `AuthGuard` (for route protection).
#[derive(Clone)]
struct AppState {
    authkestra: Authkestra<HasSessionStoreMarker>,
    guard: Arc<AuthGuard<Identity>>,
}

// Implement FromRef for AuthkestraState compatibility if needed,
// but here we use our own AppState.
impl FromRef<AppState> for Authkestra<HasSessionStoreMarker> {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra.clone()
    }
}

impl FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra.session_config.clone()
    }
}

impl FromRef<AppState> for Result<Arc<dyn SessionStore>, authkestra_axum::AuthkestraAxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.authkestra.session_store.get_store())
    }
}

impl FromRef<AppState> for Arc<AuthGuard<Identity>> {
    fn from_ref(state: &AppState) -> Self {
        state.guard.clone()
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();

    // 3. Configure Authkestra (The Flow Manager)
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    let mut builder = Authkestra::builder();

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

    let authkestra = builder
        .session_store(session_store.clone())
        .session_config(SessionConfig {
            secure: false, // For local development
            ..Default::default()
        })
        .build();

    // 4. Configure Guard (The Access Guard)
    // We use a SessionStrategy that looks for the same cookie Authkestra uses.
    let guard = AuthGuard::<Identity>::builder()
        .strategy(SessionStrategy::new(
            MySessionProvider {
                store: session_store,
            },
            &authkestra.session_config.cookie_name,
        ))
        .build();

    let state = AppState {
        authkestra: authkestra.clone(),
        guard: Arc::new(guard),
    };

    // 5. Build the Axum Router
    let app = Router::new()
        .route("/", get(index))
        // Use the unified `Auth<Identity>` extractor provided by `authkestra-axum`.
        // This extractor uses the `AuthGuard` in the state.
        .route("/protected", get(protected))
        // Merge Authkestra's login/callback/logout routes
        .merge(authkestra.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Combined Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let mut html = String::from("<h1>Authkestra Combined Example</h1>");
    html.push_str(
        "<p>This example shows Authkestra handling login and Guard protecting routes.</p>",
    );

    if state.authkestra.providers.contains_key("github") {
        html.push_str("<p><a href=\"/auth/github?scope=user:email&success_url=/protected\">Login with GitHub</a></p>");
    } else {
        html.push_str(
            "<p><i>GitHub provider not configured. Set AUTHKESTRA_GITHUB_CLIENT_ID/SECRET.</i></p>",
        );
    }

    Html(html)
}

/// Protected route using the unified `Auth` extractor.
/// This route is protected by the `AuthGuard` we configured in `main`.
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
