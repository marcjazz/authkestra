//! # Axum Basic Setup — the smallest useful `Engine`
//!
//! The "golden path" starting point (RFC-001): build an [`Engine`] with
//! [`Authkestra::builder()`], hand it a [`SessionStore`], and let
//! [`AxumExt::axum_router`] wire the `/auth/*` routes for you.
//!
//! No OAuth provider is registered here on purpose — this example is about the
//! *session* half of the engine. See `axum_oauth2_github.rs` for the same
//! wiring with a provider attached.
//!
//! ```sh
//! cargo run -p authkestra --example axum_basic_setup --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 3000.

use authkestra::Authkestra;
use authkestra_axum::{AuthSession, AxumError, AxumExt, AxumState};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig, SessionStore};
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

/// `AkWebAppEngine` is the alias for a session-configured engine. Using the
/// alias (rather than spelling out the typestate generics) keeps the compile
/// error legible when a required builder call is missing.
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

    // 1. Pick a storage backend. `SessionStore` is a trait, so swapping
    //    `MemoryStore` for `RedisStore` or `SqlKvStore` is a one-line change
    //    (see `axum_session_redis.rs` / `axum_sql_store.rs`).
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    // 2. Build the engine. The typestate builder only exposes session APIs
    //    once `session_store` has been supplied.
    let engine = Authkestra::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // plain HTTP for local development
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: engine.clone(),
    };

    // 3. Merge the engine's routes into your own router.
    let app = Router::new()
        .route("/api/user", get(get_user))
        .route("/api/providers", get(list_providers))
        .merge(engine.axum_router())
        .fallback_service(ServeDir::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/static"
        )))
        // The engine reads and writes cookies, so the cookie layer must wrap
        // the merged routes.
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let port = port_from_env();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%port, "Axum basic setup listening on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}

/// Returns the session identity, or 401 when there is no valid session.
///
/// Returning a real 401 (rather than a 200 carrying an `error` field) is what
/// lets `examples/static/index.html` tell the two states apart.
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

/// Lists the OAuth providers registered on the engine so the bundled static
/// page can render one login button per provider. Empty for this example.
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
