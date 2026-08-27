//! # Axum OP Server Example with Native SqlxOpStore
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Axum.
//! It uses the batteries-included `SqlxOpStore` for a production-ready relational database schema.
//!
//! Unlike `axum_op_server.rs` (which composes four `KvStore`s), `SqlxOpStore`
//! is a single normalised schema with foreign keys and `ON DELETE CASCADE` —
//! prefer it for OP data; `SqlKvStore` is deprecated for this purpose.
//!
//! ```sh
//! cargo run -p authkestra --example axum_op_server_sqlx --all-features
//! ```
//!
//! Set `PORT` to bind somewhere other than 8080; `issuer` follows it, because
//! relying parties resolve `/.well-known/openid-configuration` against the
//! issuer URL and a mismatch breaks discovery.
use authkestra_axum::{AxumState, OpExt};
use authkestra_engine::store::memory::MemoryStore;
use authkestra::Authkestra;
use authkestra_engine::{AkEngine, SessionConfig, SessionStore, TokenManager};
use authkestra_op::config::OpConfig;
use authkestra_op::sqlx_store::SqlxOpStore;
use axum::Router;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkEngine,

    #[authkestra(store)]
    op_store: Arc<dyn authkestra_op::OpStore>,

    #[authkestra(store)]
    config: OpConfig,
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

    let port = port_from_env();
    let issuer = format!("http://localhost:{port}");

    // The token manager's `iss` claim must equal `OpConfig::issuer` below, or
    // relying parties will reject every id_token this OP mints.
    let token_manager = Arc::new(TokenManager::new(
        b"my-super-secret-key-that-is-32bytes-long",
        Some(issuer.clone()),
    ));

    // Create a SQLite connection pool (in-memory for the example, but can be a file path)
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Use the batteries-included native SQL store (SqlxOpStore)
    // This provides a highly opinionated schema with cascading deletes and strict relational integrity
    let sqlx_store = SqlxOpStore::<sqlx::Sqlite>::new(pool.clone());

    // Automatically run schema migrations to create the required tables
    sqlx_store.migrate().await.unwrap();

    // Seed a demo OAuth client. `ClientStore` is read-only by design —
    // registration is the deployment's business — so the example writes the
    // row directly. `redirect_uris` is the *relying party's* callback, not
    // this server's.
    sqlx::query(
        "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind("test-client")
    .bind(None::<String>)
    .bind(true)
    .bind(sqlx::types::Json(vec!["http://localhost:3000/auth/callback/github"]))
    .bind(sqlx::types::Json(vec!["authorization_code"]))
    .bind(sqlx::types::Json(vec!["openid", "profile"]))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .execute(&pool)
    .await
    .unwrap();

    let op_store: Arc<dyn authkestra_op::OpStore> = Arc::new(sqlx_store);

    // Only the OP data lives in SQL here; the end-user login session can use
    // any `SessionStore`, so the example keeps that part dependency-free.
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
    let session_config = SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };

    let auth = Authkestra::builder()
        .session_store(session_store)
        .session_config(session_config)
        .token_manager(token_manager)
        .build();

    let state = AppState {
        auth,
        op_store,
        config: OpConfig {
            issuer: issuer.clone(),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            access_token_ttl_secs: 3600,
            authorization_code_ttl_secs: 600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: true,
        },
    };

    let app = Router::new()
        .merge(state.op_axum_router())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind example server");

    tracing::info!(%issuer, "Axum OP server (SqlxOpStore) listening on {issuer}");
    tracing::info!("discovery: {issuer}/.well-known/openid-configuration");
    axum::serve(listener, app).await.unwrap();
}

/// Bind port, overridable via `PORT`. Defaults to 8080 so an OP and a relying
/// party (which the other examples run on 3000) can be started side by side.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
}
