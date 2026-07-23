//! # Actix OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Actix.
use authkestra_engine::store::KvStore;

use actix_web::{App, HttpServer};
use authkestra_actix::AuthEngineActixOpExt;
use authkestra_engine::TokenManager;
use authkestra_op::{
    client::ClientRegistration,
    config::OpConfig,
};
use std::sync::Arc;

struct AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    let session_store: Arc<dyn authkestra_engine::auth::SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::new());
    let session_config = authkestra_engine::SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };



    println!("🚀 Actix OP Server running on http://localhost:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(token_manager.clone()))
            .app_data(actix_web::web::Data::new(op_store.clone()))
            .app_data(actix_web::web::Data::new(config.clone()))
            .app_data(actix_web::web::Data::new(session_store.clone()))
            .app_data(actix_web::web::Data::new(session_config.clone()))
            .service(AppState.op_actix_scope())
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
