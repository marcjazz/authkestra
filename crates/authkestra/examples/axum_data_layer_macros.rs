//! # Axum Data Layer Macros Example
//!
//! This example demonstrates how to use the `AuthkestraKvStore` and `AuthkestraRepository`
//! derive macros to eliminate SQL boilerplate.
//!
//! By wrapping a `sqlx::Pool` in a tuple struct and decorating it with the macros,
//! it automatically generates the implementations for the data layer traits by delegating
//! to the internal unified `SqlKvStore`.

use authkestra::flow::AuthEngine;
use authkestra_axum::{AuthSession, AuthkestraAxumError, AuthkestraAxumExt, AuthkestraState};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::store::Repository;
use authkestra_engine::{Configured, SessionConfig};
use authkestra_macros::{AuthkestraKvStore, AuthkestraRepository};
use axum::{
    extract::State,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

// ============================================================================
// 1. Zero-Boilerplate Data Layer
// ============================================================================

/// A custom session store derived via macro.
#[derive(AuthkestraKvStore)]
#[authkestra(table = "user_sessions")]
pub struct MySqliteSessionStore(sqlx::SqlitePool);

/// A custom repository derived via macro.
/// For simplicity, the macro serializes entities as JSON into the KV table.
#[derive(AuthkestraRepository)]
#[authkestra(table = "users")]
pub struct MySqliteUserRepo(sqlx::SqlitePool);

// Define a simple user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
}

// ============================================================================
// 2. Zero-Boilerplate Application State Extraction
// ============================================================================

/// The AuthkestraState macro generates all the axum FromRef implementations.
#[derive(Clone, AuthkestraState)]
struct AppState {
    // Automatically extracts SessionStore and SessionConfig
    #[authkestra(engine)]
    auth: AuthEngine<Configured<Arc<dyn SessionStore>>, authkestra_engine::Missing>,

    // Extracted directly as State<Arc<dyn Repository>>
    #[authkestra(store)]
    repo: Arc<dyn Repository<UserEntity, String>>,
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

    // Initialize our generated stores
    let session_store = MySqliteSessionStore(pool.clone());
    let user_repo = MySqliteUserRepo(pool.clone());

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

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let session_store_arc: Arc<dyn SessionStore> = Arc::new(session_store);

    let auth_engine = AuthEngine::builder()
        .session_store(session_store_arc)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: auth_engine.clone(),
        repo: Arc::new(user_repo),
    };

    let app = Router::new()
        .fallback_service(ServeDir::new("authkestra-examples/static"))
        .route("/api/user", get(get_user))
        .route("/api/user/:id", post(create_user))
        .merge(auth_engine.axum_router::<AppState>())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum Data Layer Macros Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_user(
    State(repo): State<Arc<dyn Repository<UserEntity, String>>>,
    session: Result<AuthSession, AuthkestraAxumError>,
) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => {
            // Find user in DB using our macro-derived repository
            match repo.find_by_id(&session.identity.external_id).await {
                Ok(Some(user)) => Json(json!({ "status": "found", "user": user })),
                _ => Json(json!({ "status": "not_found in DB" })),
            }
        }
        Err(_) => Json(json!({ "error": "Not authenticated" })),
    }
}

async fn create_user(
    State(repo): State<Arc<dyn Repository<UserEntity, String>>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Note: the save method on our macro is currently a stub in this simplified example
    match repo
        .save(&UserEntity {
            id: id.clone(),
            name: "Test User".to_string(),
        })
        .await
    {
        Ok(_) => Json(json!({ "status": "created" })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}
