//! # Axum SQL Store Example
//!
//! This example demonstrates how to use `SqlKvStore` (with SQLite) as a session store with Axum.
//! It also demonstrates how to manage the database table lifecycle by calling `.migrate().await`.

use authkestra::flow::Engine;
use authkestra_axum::{AuthSession, AxumError, AxumExt, AxumState};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::store::sql::SqlKvStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig};
use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

/// Engine state with support for session only.
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
}

#[tokio::main]
async fn main() {
    // 1. Create a SQLite connection pool.
    // For this example, we use an in-memory database to avoid needing local setup,
    // but in a real app, this would be a file path (e.g. "sqlite://session.db")
    // or a Postgres/MySQL URL.
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to create SQLite connection pool");

    // 2. Initialize the SqlKvStore with the pool.
    let sql_store = SqlKvStore::new(pool);

    // 3. Migrate the database.
    // This explicitly creates the `authkestra_kv` table and indexes if they do not exist.
    // It is fully idempotent, so you can call it safely on every startup.
    sql_store
        .migrate()
        .await
        .expect("Failed to run database migrations");

    // 4. Wrap the store in an Arc and provide it to the Engine.
    let session_store: Arc<dyn SessionStore> = Arc::new(sql_store);

    let auth_engine = Engine::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // For local development
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: auth_engine.clone(),
    };

    let app = Router::new()
        .fallback_service(ServeDir::new("authkestra-examples/static"))
        .route("/api/user", get(get_user))
        .merge(auth_engine.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum SQL Store Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_user(session: Result<AuthSession, AxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => Json(json!({
            "id": session.identity.external_id,
            "username": session.identity.username,
            "email": session.identity.email,
            "provider": session.identity.provider_id,
        })),
        Err(_) => Json(json!({ "error": "Not authenticated" })),
    }
}
