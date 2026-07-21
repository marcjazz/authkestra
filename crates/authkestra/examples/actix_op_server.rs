//! # Actix OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Actix.

use actix_web::{App, HttpServer};
use authkestra_actix::AuthEngineActixOpExt;
use authkestra_engine::TokenManager;
use authkestra_op::{
    client::{ClientRegistration, ClientStore, InMemoryClientStore},
    code::{AuthorizationCodeStore, InMemoryAuthorizationCodeStore},
    config::OpConfig,
    refresh::{InMemoryRefreshTokenStore, RefreshTokenStore},
};
use std::sync::Arc;

struct AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let token_manager = Arc::new(TokenManager::new(
        b"my-super-secret-key-that-is-32bytes-long",
        Some("issuer".to_string()),
    ));

    let clients = InMemoryClientStore::new();
    clients.register(ClientRegistration {
        client_id: "test-client".to_string(),
        client_secret_hash: None,
        redirect_uris: vec!["http://localhost:8080/callback".to_string()],
        require_pkce: true,
        scopes: vec!["openid".to_string(), "profile".to_string()],
        grant_types: vec![authkestra_op::client::GrantType::AuthorizationCode],
    });
    let clients: Arc<dyn ClientStore> = Arc::new(clients);

    let codes: Arc<dyn AuthorizationCodeStore> = Arc::new(InMemoryAuthorizationCodeStore::new());
    let refresh_tokens: Arc<dyn RefreshTokenStore> = Arc::new(InMemoryRefreshTokenStore::new());

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
            .app_data(actix_web::web::Data::new(clients.clone()))
            .app_data(actix_web::web::Data::new(codes.clone()))
            .app_data(actix_web::web::Data::new(refresh_tokens.clone()))
            .app_data(actix_web::web::Data::new(config.clone()))
            .app_data(actix_web::web::Data::new(session_store.clone()))
            .app_data(actix_web::web::Data::new(session_config.clone()))
            .service(AppState.op_actix_scope())
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
