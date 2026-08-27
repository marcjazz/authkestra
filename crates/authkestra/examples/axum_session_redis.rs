//! # Axum + Redis session store
//!
//! `axum_basic_setup.rs` with one line changed: `MemoryStore` becomes
//! `RedisStore`. Everything downstream — the builder call, the state struct,
//! the router, the extractors — is untouched, which is the payoff of defining
//! storage as the [`SessionStore`] trait rather than a concrete type.
//!
//! ```sh
//! REDIS_URL=redis://127.0.0.1/ \
//!   cargo run -p authkestra --example axum_session_redis --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 3000.

use authkestra_axum::{AuthSession, AxumError, AxumExt, AxumState};
use authkestra_engine::store::redis::RedisStore;
use authkestra_engine::{AkWebAppEngine, Engine, SessionConfig, SessionStore};
use axum::{
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

    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");

    // The key prefix namespaces this app's sessions so one Redis instance can
    // back several stores (see `axum_op_server.rs`, which does exactly that).
    let session_store: Arc<dyn SessionStore> = Arc::new(
        RedisStore::new(&redis_url, "authkestra_example".into())
            .expect("failed to connect to Redis"),
    );

    let engine = Engine::builder()
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
        .merge(engine.axum_router())
        .fallback_service(ServeDir::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/static"
        )))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let port = port_from_env();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%port, "Axum Redis session example listening on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}

/// Returns the session identity, or 401 when there is no valid session.
async fn get_user(session: Result<AuthSession, AxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => {
            tracing::debug!(user = %session.identity.external_id, "session resolved from Redis");
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

/// Bind port, overridable via `PORT` so several examples can run without
/// colliding on 3000.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000)
}
