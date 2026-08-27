//! # Axum + GitHub OAuth2 (stateful sessions)
//!
//! The golden path for a server-rendered web app: an [`Engine`] with an OAuth
//! provider *and* a session store. The callback creates a server-side session
//! and sets a cookie.
//!
//! ```sh
//! AUTHKESTRA_GITHUB_CLIENT_ID=... AUTHKESTRA_GITHUB_CLIENT_SECRET=... \
//!   cargo run -p authkestra --example axum_oauth2_github --all-features
//! ```
//!
//! Register `http://localhost:3000/auth/callback/github` as the OAuth callback
//! on GitHub — that is the path [`AxumExt::axum_router`] actually wires. Set
//! `PORT` to bind elsewhere; the default redirect URI follows it.

use authkestra::Authkestra;
use authkestra_axum::{AuthSession, AxumError, AxumExt, AxumState};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{AkWebAppEngine, OAuth2Flow, SessionConfig, SessionStore};
use authkestra_providers::github::GithubProvider;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
}

#[tokio::main]
async fn main() {
    // `RUST_LOG=authkestra=debug` surfaces the engine's own instrumentation.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    dotenvy::dotenv().ok();

    let port = port_from_env();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| format!("http://localhost:{port}/auth/callback/github"));

    let github_provider = github_provider(client_id, client_secret, redirect_uri);

    // `SessionStore` is a trait: swap `MemoryStore` for `RedisStore` or
    // `SqlKvStore` without touching anything below this line.
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    let engine = Authkestra::builder()
        .provider(OAuth2Flow::new(github_provider))
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // plain HTTP for local development
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: engine.clone(),
    };

    let app = Router::new()
        .route("/api/user", get(get_user))
        .route("/api/providers", get(list_providers))
        .merge(engine.axum_router())
        .fallback_service(ServeDir::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/static"
        )))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%port, "Axum GitHub OAuth2 listening on http://localhost:{port}");
    tracing::info!("start the flow at http://localhost:{port}/auth/login/github");
    axum::serve(listener, app).await.unwrap();
}

/// Builds the provider, redirecting to a mock server when the e2e harness has
/// set `AUTHKESTRA_GITHUB_BASE_URL`. Real deployments never set these.
fn github_provider(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
) -> GithubProvider {
    match std::env::var("AUTHKESTRA_GITHUB_BASE_URL") {
        Ok(base_url) => {
            let api_url =
                std::env::var("AUTHKESTRA_GITHUB_API_URL").unwrap_or_else(|_| base_url.clone());
            tracing::warn!(%base_url, "using overridden GitHub endpoints (test mode)");
            GithubProvider::new(client_id, client_secret, redirect_uri).with_test_urls(
                format!("{base_url}/login/oauth/authorize"),
                format!("{base_url}/login/oauth/access_token"),
                format!("{api_url}/user"),
            )
        }
        Err(_) => GithubProvider::new(client_id, client_secret, redirect_uri),
    }
}

/// Returns the session identity, or 401 when there is no valid session.
async fn get_user(session: Result<AuthSession, AxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => {
            tracing::debug!(user = %session.identity.external_id, "session resolved");
            (
                StatusCode::OK,
                Json(json!({
                    "id": session.identity.external_id,
                    "username": session.identity.username,
                    "email": session.identity.email,
                    "provider": session.identity.provider_id,
                })),
            )
        }
        Err(err) => {
            tracing::debug!(%err, "no valid session on request");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Not authenticated" })),
            )
        }
    }
}

/// Lists the registered OAuth providers so the bundled static page can render
/// a login button per provider.
async fn list_providers(State(state): State<AppState>) -> impl IntoResponse {
    let providers: Vec<&String> = state.auth.providers.keys().collect();
    Json(json!({ "providers": providers }))
}

/// Bind port, overridable via `PORT` so several examples (and the e2e test
/// harness, which passes a port it has already confirmed to be free) can run
/// without colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}
