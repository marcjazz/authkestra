// The derive delegates to `SqlKvStore`, which is deprecated *for OP-specific
// data* but remains the supported choice for generic KV/session storage — the
// only thing it is used for here. The attribute cannot distinguish the two.
#![allow(deprecated)]
//! # Axum + the `KvStore` derive macro
//!
//! Same engine wiring as `axum_sql_store.rs`, but the session store is your
//! own newtype rather than authkestra's. `#[derive(KvStore)]` generates the
//! whole data-layer trait impl by delegating to the wrapped store, so a
//! custom store costs one line instead of a screen of boilerplate.
//!
//! Use this when you want your own type (for a custom table name, extra
//! instrumentation, or a differently-shaped backend) without reimplementing
//! [`SessionStore`] by hand.
//!
//! ```sh
//! cargo run -p authkestra --example axum_data_layer_macros --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 3000.

use authkestra_axum::{AuthSession, AxumError, AxumExt, AxumState};
use authkestra_engine::store::sql::SqlKvStore;
use authkestra::Authkestra;
use authkestra_engine::{AkWebAppEngine, SessionConfig, SessionStore};
use authkestra_macros::KvStore;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

// ============================================================================
// 1. Zero-boilerplate data layer
// ============================================================================

/// A custom session store. The derive forwards every `KvStore` method to the
/// wrapped `SqlKvStore`, and the blanket impl in `authkestra-engine` turns any
/// `KvStore` into a [`SessionStore`].
#[derive(KvStore)]
pub struct MySqliteSessionStore(SqlKvStore<sqlx::Sqlite>);

// ============================================================================
// 2. Zero-boilerplate state extraction
// ============================================================================

/// `AxumState` generates the `FromRef` impls the extractors need.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
}

// ============================================================================
// 3. Application setup
// ============================================================================

#[tokio::main]
async fn main() {
    // `RUST_LOG=authkestra=debug` surfaces the engine's own instrumentation.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("failed to connect to SQLite");

    // This example picks a non-default table name to show that the newtype
    // controls the schema, so it creates the table itself rather than calling
    // `SqlKvStore::migrate()` (which targets `authkestra_kv`).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_sessions (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at DATETIME NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("failed to create session table");

    let session_store = MySqliteSessionStore(SqlKvStore::with_table_name(
        pool,
        "user_sessions".to_string(),
    ));
    let session_store: Arc<dyn SessionStore> = Arc::new(session_store);

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

    let app = Router::new()
        .route("/api/user", get(get_user))
        .merge(engine.axum_router::<AppState>())
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

    tracing::info!(%port, "Axum data-layer macros example listening on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}

/// Returns the session identity, or 401 when there is no valid session.
///
/// Present so the bundled static page has an endpoint to poll — it also proves
/// the derived store round-trips a session.
async fn get_user(session: Result<AuthSession, AxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => {
            tracing::debug!(user = %session.identity.external_id, "session resolved from derived store");
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
