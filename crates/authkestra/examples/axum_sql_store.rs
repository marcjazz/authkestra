// `SqlKvStore` is deprecated *for OP-specific data* (use `SqlxOpStore` for
// that — see `axum_op_server_sqlx.rs`), but is still the supported choice for
// generic KV/session storage, which is all this example uses it for. The
// deprecation attribute cannot distinguish the two, hence the blanket allow.
#![allow(deprecated)]
//! # Axum + SQL session store (SQLite)
//!
//! `axum_basic_setup.rs` with `MemoryStore` swapped for `SqlKvStore`, plus the
//! one extra step SQL needs: `migrate()` to create the backing table.
//!
//! ```sh
//! cargo run -p authkestra --example axum_sql_store --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 3000.

use authkestra::Authkestra;
use authkestra_axum::{AuthSession, AxumError, AxumExt, AxumState};
use authkestra_engine::store::sql::SqlKvStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig, SessionStore};
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

    // 1. Connect. In-memory keeps the example dependency-free; a real app
    //    would pass a file path or a Postgres/MySQL URL here instead.
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("failed to create SQLite connection pool");

    let sql_store = SqlKvStore::new(pool);

    // 2. Create the `authkestra_kv` table and indexes. Idempotent, so calling
    //    it on every startup is safe — authkestra never assumes a schema it
    //    did not create.
    sql_store
        .migrate()
        .await
        .expect("failed to run database migrations");

    // 3. From here on it is identical to every other session example.
    let session_store: Arc<dyn SessionStore> = Arc::new(sql_store);

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

    tracing::info!(%port, "Axum SQL store example listening on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}

/// Returns the session identity, or 401 when there is no valid session.
async fn get_user(session: Result<AuthSession, AxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => {
            tracing::debug!(user = %session.identity.external_id, "session resolved from SQL");
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
