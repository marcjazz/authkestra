//! # Actix OP Server Example with Native SqlxOpStore
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Actix.
//! It uses the batteries-included `SqlxOpStore` for a production-ready relational database schema.
use actix_web::{App, HttpServer};
use authkestra::flow::Engine;
use authkestra_actix::{ActixState, OpExt};
use authkestra_op::client::{ClientRegistration, ClientStore};
use authkestra_op::sqlx_store::SqlxOpStore;
use authkestra_op::store::OpStore;

use authkestra_engine::TokenManager;
use authkestra_op::config::OpConfig;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: authkestra_engine::AkEngine,

    #[authkestra(store)]
    op_store: Arc<dyn authkestra_op::OpStore>,

    #[authkestra(store)]
    config: OpConfig,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let token_manager = Arc::new(TokenManager::new(
        b"my-super-secret-key-that-is-32bytes-long",
        Some("issuer".to_string()),
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

    // Seed a dummy OAuth client directly using sqlx
    sqlx::query(
        "INSERT INTO authkestra_oauth_clients (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) 
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind("test-client")
    .bind(None::<String>)
    .bind(true)
    .bind(sqlx::types::Json(vec!["http://localhost:3000/callback"]))
    .bind(sqlx::types::Json(vec!["authorization_code"]))
    .bind(sqlx::types::Json(vec!["openid", "profile"]))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .execute(&pool)
    .await
    .unwrap();

    let op_store: Arc<dyn authkestra_op::OpStore> = Arc::new(sqlx_store);

    let config = OpConfig {
        issuer: "http://localhost:8080".to_string(),
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
    };

    let auth = Engine::builder()
        .session_store(Arc::new(
            authkestra_engine::store::memory::MemoryStore::new(),
        ))
        .session_config(authkestra_engine::SessionConfig {
            cookie_name: "authkestra_sid".to_string(),
            ..Default::default()
        })
        .token_manager(token_manager)
        .build();

    let app_state = AppState {
        auth,
        op_store,
        config,
    };
    println!("🚀 Actix OP Server running on http://localhost:8080");
    HttpServer::new(move || {
        let state = app_state.clone();
        let config_state = state.clone();
        App::new()
            .app_data(actix_web::web::Data::new(state.clone()))
            .configure(move |cfg| config_state.configure_authkestra(cfg))
            .service(state.op_actix_scope())
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
