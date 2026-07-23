//! # Axum Data Layer Macros Example
//!
//! This example demonstrates how to use the `AuthkestraKvStore`
//! derive macro to eliminate SQL boilerplate.
//!
//! By wrapping a `sqlx::Pool` in a tuple struct and decorating it with the macros,
//! it automatically generates the implementations for the data layer traits by delegating
//! to the internal unified `SqlKvStore`.

use authkestra::flow::AkBase;
use authkestra_axum::{AkAxumError, AkAxumExt, AuthSession, AuthkestraState};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::{Configured, SessionConfig};
use authkestra_macros::AuthkestraKvStore;
use axum::Router;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

// ============================================================================
// 1. Zero-Boilerplate Data Layer
// ============================================================================

/// A custom session store derived via macro, wrapping an existing KvStore implementation.
/// The macro delegates all KvStore methods to the internal `SqlKvStore`.
#[derive(AuthkestraKvStore)]
pub struct MySqliteSessionStore(authkestra_engine::store::sql::SqlKvStore<sqlx::Sqlite>);

// ============================================================================
// 2. Zero-Boilerplate Application State Extraction
// ============================================================================

/// The AuthkestraState macro generates all the axum FromRef implementations.
#[derive(Clone, AuthkestraState)]
struct AppState {
    // Automatically extracts SessionStore and SessionConfig
    #[authkestra(engine)]
    auth: AkBase<Configured<Arc<dyn SessionStore>>, authkestra_engine::Missing>,
}

// ============================================================================
// 3. Application Setup
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize an in-memory database
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    // Because the derive macro uses the internal `SqlKvStore` implementation,
    // we must ensure the schema exists.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_sessions (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at DATETIME NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Initialize our generated stores
    let sql_store = authkestra_engine::store::sql::SqlKvStore::with_table_name(
        pool,
        "user_sessions".to_string(),
    );
    let session_store = MySqliteSessionStore(sql_store);

    let session_store_arc: Arc<dyn SessionStore> = Arc::new(session_store);

    let auth_engine = AkBase::builder()
        .session_store(session_store_arc)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: auth_engine.clone(),
    };

    let app = Router::new()
        .fallback_service(ServeDir::new("authkestra-examples/static"))
        .merge(auth_engine.axum_router::<AppState>())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum Data Layer Macros Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
