//! # Axum OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Axum.
use authkestra_engine::store::KvStore;

use authkestra_axum::OpExt;
use authkestra_engine::store::sql::SqlKvStore;
use authkestra_engine::{AkEngine, TokenManager};
use authkestra_op::{client::ClientRegistration, config::OpConfig};
use axum::Router;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

use authkestra_axum::AxumState;

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
    let token_manager = Arc::new(TokenManager::new(
        b"my-super-secret-key-that-is-32bytes-long",
        Some("issuer".to_string()),
    ));

    // Create a SQLite connection pool (in-memory for the example, but can be a file path)
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // TIP: authkestra uses traits (like `KvStore<T>`) for storage.
    // This makes it easy to swap out backends! You could easily swap `SqlKvStore`
    // with `RedisStore` or `MemoryStore` simply by changing the struct instantiated here.

    let clients = SqlKvStore::with_table_name(pool.clone(), "op_clients".into());
    clients.migrate().await.unwrap();
    clients
        .set(
            "test-client",
            ClientRegistration {
                client_id: "test-client".to_string(),
                client_secret_hash: None,
                redirect_uris: vec!["http://localhost:3000/callback".to_string()],
                require_pkce: true,
                scopes: vec!["openid".to_string(), "profile".to_string()],
                grant_types: vec![authkestra_op::client::GrantType::AuthorizationCode],
                allowed_audiences: vec![],
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let auth_codes = SqlKvStore::with_table_name(pool.clone(), "op_auth_codes".into());
    auth_codes.migrate().await.unwrap();
    let refresh_tokens = SqlKvStore::with_table_name(pool.clone(), "op_refresh_tokens".into());
    refresh_tokens.migrate().await.unwrap();
    let device_codes = SqlKvStore::with_table_name(pool.clone(), "op_device_codes".into());
    device_codes.migrate().await.unwrap();

    let op_store: Arc<dyn authkestra_op::OpStore> =
        Arc::new(authkestra_op::store::CompositeOpStore::new(
            clients,
            auth_codes,
            refresh_tokens,
            device_codes,
        ));

    // TIP: authkestra uses traits (like `SessionStore`) for storage.
    // This makes it easy to swap out backends! You could easily replace `MemoryStore`
    // with `SqlKvStore` or `RedisStore` simply by changing the struct instantiated here.
    let session_store: Arc<dyn authkestra_engine::auth::SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::new());
    let session_config = authkestra_engine::SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };

    let auth = authkestra_engine::Engine::builder()
        .session_store(session_store)
        .session_config(session_config)
        .token_manager(token_manager)
        .build();

    let state = AppState {
        auth,
        op_store,
        config: OpConfig {
            issuer: "http://localhost:3000".to_string(),
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

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Axum OP Server running on http://localhost:8080");
    axum::serve(listener, app).await.unwrap();
}
