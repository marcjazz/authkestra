//! # Axum OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Axum.
use authkestra_engine::store::KvStore;

use authkestra_axum::AuthEngineAxumOpExt;
use authkestra_engine::{AuthEngine, Configured, TokenManager};
use authkestra_op::{client::ClientRegistration, config::OpConfig};
use axum::Router;
use std::sync::Arc;

use authkestra_axum::AuthkestraState;

#[derive(Clone, AuthkestraState)]
struct AppState {
    #[authkestra(engine)]
    authkestra: AuthEngine<
        Configured<Arc<dyn authkestra_engine::auth::SessionStore>>,
        Configured<Arc<TokenManager>>,
    >,

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

    let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
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
    let op_store: Arc<dyn authkestra_op::OpStore> = Arc::new(authkestra_op::store::CompositeOpStore::new(
        clients,
        authkestra_engine::store::memory::MemoryStore::<authkestra_op::code::AuthorizationCode>::new(),
        authkestra_engine::store::memory::MemoryStore::<authkestra_op::refresh::RefreshToken>::new(),
        authkestra_engine::store::memory::MemoryStore::<authkestra_op::device::DeviceCodeSession>::new(),
    ));

    let session_store: Arc<dyn authkestra_engine::auth::SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::new());
    let session_config = authkestra_engine::SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };

    let authkestra = authkestra_engine::AuthEngine::builder()
        .session_store(session_store)
        .session_config(session_config)
        .token_manager(token_manager)
        .build();

    let state = AppState {
        authkestra,
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
