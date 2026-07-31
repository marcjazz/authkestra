//! # Actix OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Actix.
//! This example uses `RedisStore` for both the engine session and the OP data.
//!
//! To run this example, you'll need:
//! - A running Redis instance
//! - `REDIS_URL` environment variable (e.g., `redis://127.0.0.1/`)
use authkestra_engine::store::KvStore;

use actix_web::{App, HttpServer};
use authkestra_actix::{ActixState, OpExt};
use authkestra_engine::flow::Engine;
use authkestra_engine::store::redis::RedisStore;
use authkestra_engine::{SessionConfig, TokenManager};
use authkestra_op::{client::ClientRegistration, config::OpConfig};
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
    dotenvy::dotenv().ok();
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");

    let token_manager = Arc::new(TokenManager::new(
        b"my-super-secret-key-that-is-32bytes-long",
        Some("issuer".to_string()),
    ));

    // Open a single Redis client and share it across all stores via different key prefixes.
    // This avoids opening multiple TCP connections to Redis.
    let redis_client = redis::Client::open(redis_url.as_str()).expect("Failed to connect to Redis");

    let clients = RedisStore::with_client(redis_client.clone(), "op_clients".into());
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
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let auth_codes = RedisStore::with_client(redis_client.clone(), "op_codes".into());
    let refresh_tokens = RedisStore::with_client(redis_client.clone(), "op_refresh".into());
    let device_codes = RedisStore::with_client(redis_client.clone(), "op_device".into());

    let op_store: Arc<dyn authkestra_op::OpStore> =
        Arc::new(authkestra_op::store::CompositeOpStore::new(
            clients,
            auth_codes,
            refresh_tokens,
            device_codes,
        ));

    let session_store: Arc<dyn authkestra_engine::auth::SessionStore> = Arc::new(
        RedisStore::with_client(redis_client, "engine_session".into()),
    );

    let session_config = SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };

    let auth = Engine::builder()
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

    println!("🚀 Actix OP Server running on http://localhost:8080");
    HttpServer::new(move || {
        let s = state.clone();
        let s2 = s.clone();
        App::new()
            .app_data(actix_web::web::Data::new(s.clone()))
            .configure(move |cfg| s.configure_authkestra(cfg))
            .service(s2.op_actix_scope())
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
