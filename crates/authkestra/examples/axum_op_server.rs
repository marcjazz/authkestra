//! # Axum OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Axum.

use authkestra_axum::{AuthEngineAxumError, AuthEngineAxumOpExt};
use authkestra_engine::TokenManager;
use authkestra_op::{
    client::{ClientRegistration, ClientStore, InMemoryClientStore},
    code::{AuthorizationCodeStore, InMemoryAuthorizationCodeStore},
    config::OpConfig,
    refresh::{InMemoryRefreshTokenStore, RefreshTokenStore},
};
use axum::{extract::FromRef, Router};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    token_manager: Arc<TokenManager>,
    clients: Arc<dyn ClientStore>,
    codes: Arc<dyn AuthorizationCodeStore>,
    config: OpConfig,
    session_store: Arc<dyn authkestra_engine::auth::SessionStore>,
    session_config: authkestra_engine::SessionConfig,
    refresh_tokens: Arc<dyn RefreshTokenStore>,
}

impl FromRef<AppState> for Arc<TokenManager> {
    fn from_ref(app_state: &AppState) -> Arc<TokenManager> {
        app_state.token_manager.clone()
    }
}

impl FromRef<AppState> for Result<Arc<TokenManager>, AuthEngineAxumError> {
    fn from_ref(app_state: &AppState) -> Result<Arc<TokenManager>, AuthEngineAxumError> {
        Ok(app_state.token_manager.clone())
    }
}

impl FromRef<AppState> for Arc<dyn ClientStore> {
    fn from_ref(app_state: &AppState) -> Arc<dyn ClientStore> {
        app_state.clients.clone()
    }
}

impl FromRef<AppState> for Result<Arc<dyn ClientStore>, AuthEngineAxumError> {
    fn from_ref(app_state: &AppState) -> Result<Arc<dyn ClientStore>, AuthEngineAxumError> {
        Ok(app_state.clients.clone())
    }
}

impl FromRef<AppState> for Arc<dyn AuthorizationCodeStore> {
    fn from_ref(app_state: &AppState) -> Arc<dyn AuthorizationCodeStore> {
        app_state.codes.clone()
    }
}

impl FromRef<AppState> for Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError> {
    fn from_ref(
        app_state: &AppState,
    ) -> Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError> {
        Ok(app_state.codes.clone())
    }
}

impl FromRef<AppState> for OpConfig {
    fn from_ref(app_state: &AppState) -> OpConfig {
        app_state.config.clone()
    }
}

impl FromRef<AppState> for Result<Arc<dyn RefreshTokenStore>, AuthEngineAxumError> {
    fn from_ref(app_state: &AppState) -> Result<Arc<dyn RefreshTokenStore>, AuthEngineAxumError> {
        Ok(app_state.refresh_tokens.clone())
    }
}

impl FromRef<AppState>
    for Result<Arc<dyn authkestra_engine::auth::SessionStore>, AuthEngineAxumError>
{
    fn from_ref(state: &AppState) -> Self {
        Ok(state.session_store.clone())
    }
}

impl FromRef<AppState> for authkestra_engine::SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.session_config.clone()
    }
}

#[tokio::main]
async fn main() {
    let token_manager = Arc::new(TokenManager::new(
        b"my-super-secret-key-that-is-32bytes-long",
        Some("issuer".to_string()),
    ));

    let clients = InMemoryClientStore::new();
    clients.register(ClientRegistration {
        client_id: "test-client".to_string(),
        client_secret_hash: None,
        redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        require_pkce: true,
        scopes: vec!["openid".to_string(), "profile".to_string()],
        grant_types: vec![authkestra_op::client::GrantType::AuthorizationCode],
    });
    let clients: Arc<dyn ClientStore> = Arc::new(clients);

    let codes: Arc<dyn AuthorizationCodeStore> = Arc::new(InMemoryAuthorizationCodeStore::new());
    let refresh_tokens: Arc<dyn RefreshTokenStore> = Arc::new(InMemoryRefreshTokenStore::new());

    let session_store: Arc<dyn authkestra_engine::auth::SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::new());
    let session_config = authkestra_engine::SessionConfig {
        cookie_name: "authkestra_sid".to_string(),
        ..Default::default()
    };

    let state = AppState {
        token_manager,
        clients,
        codes,
        refresh_tokens,
        session_store,
        session_config,
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
        },
    };

    let app = Router::new()
        .merge(state.op_axum_router())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Axum OP Server running on http://localhost:8080");
    axum::serve(listener, app).await.unwrap();
}
