//! # Actix OP Server Example
//!
//! This example demonstrates setting up an OpenID Connect Provider using authkestra-op and Actix.
use authkestra_engine::store::KvStore;

use actix_web::{App, HttpServer};
use authkestra::flow::Engine;
use authkestra_actix::{ActixState, OpExt};
use authkestra_engine::store::sql::SqlKvStore;
use authkestra_op::store::OpStore;
use authkestra_op::client::ClientStore;
use authkestra_op::code::AuthorizationCodeStore;
use authkestra_op::refresh::RefreshTokenStore;
use authkestra_op::device::DeviceCodeStore;

use authkestra_engine::TokenManager;
use authkestra_op::{client::ClientRegistration, config::OpConfig};
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


// -------------------------------------------------------------------------
// CUSTOM GRANT TYPE EXAMPLE
// We wrap `CompositeOpStore` so we can override `handle_custom_grant`.
// -------------------------------------------------------------------------
struct MyCustomOpStore<C, A, R, D> {
    inner: authkestra_op::store::CompositeOpStore<C, A, R, D>,
}

#[async_trait::async_trait]
impl<C: ClientStore + Send + Sync, A: Send + Sync, R: Send + Sync, D: Send + Sync> ClientStore for MyCustomOpStore<C, A, R, D> {
    async fn find_client(&self, client_id: &str) -> Result<Option<authkestra_op::client::ClientRegistration>, authkestra_op::error::OpError> {
        self.inner.find_client(client_id).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: AuthorizationCodeStore + Send + Sync, R: Send + Sync, D: Send + Sync> AuthorizationCodeStore for MyCustomOpStore<C, A, R, D> {
    async fn store_code(&self, code: authkestra_op::code::AuthorizationCode) -> Result<(), authkestra_op::error::OpError> {
        self.inner.store_code(code).await
    }
    async fn consume_code(&self, code: &str) -> Result<Option<authkestra_op::code::AuthorizationCode>, authkestra_op::error::OpError> {
        self.inner.consume_code(code).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: RefreshTokenStore + Send + Sync, D: Send + Sync> RefreshTokenStore for MyCustomOpStore<C, A, R, D> {
    async fn store_token(&self, token: authkestra_op::refresh::RefreshToken) -> Result<(), authkestra_op::error::OpError> {
        self.inner.store_token(token).await
    }
    async fn consume_token(&self, token: &str) -> Result<Option<authkestra_op::refresh::RefreshToken>, authkestra_op::error::OpError> {
        self.inner.consume_token(token).await
    }
    async fn get_token(&self, token: &str) -> Result<Option<authkestra_op::refresh::RefreshToken>, authkestra_op::error::OpError> {
        self.inner.get_token(token).await
    }
    async fn revoke_token(&self, token: &str) -> Result<(), authkestra_op::error::OpError> {
        self.inner.revoke_token(token).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: Send + Sync, D: DeviceCodeStore + Send + Sync> DeviceCodeStore for MyCustomOpStore<C, A, R, D> {
    async fn store_device_code(&self, session: authkestra_op::device::DeviceCodeSession) -> Result<(), authkestra_op::error::OpError> {
        self.inner.store_device_code(session).await
    }
    async fn get_device_code(&self, device_code: &str) -> Result<Option<authkestra_op::device::DeviceCodeSession>, authkestra_op::error::OpError> {
        self.inner.get_device_code(device_code).await
    }
    async fn get_by_user_code(&self, user_code: &str) -> Result<Option<authkestra_op::device::DeviceCodeSession>, authkestra_op::error::OpError> {
        self.inner.get_by_user_code(user_code).await
    }
    async fn update_device_code(&self, session: authkestra_op::device::DeviceCodeSession) -> Result<(), authkestra_op::error::OpError> {
        self.inner.update_device_code(session).await
    }
    async fn delete_device_code(&self, device_code: &str) -> Result<(), authkestra_op::error::OpError> {
        self.inner.delete_device_code(device_code).await
    }
    async fn consume_device_code(&self, device_code: &str) -> Result<Option<authkestra_op::device::DeviceCodeSession>, authkestra_op::error::OpError> {
        self.inner.consume_device_code(device_code).await
    }
}

#[async_trait::async_trait]
impl<C: ClientStore + Send + Sync, A: AuthorizationCodeStore + Send + Sync, R: RefreshTokenStore + Send + Sync, D: DeviceCodeStore + Send + Sync> OpStore for MyCustomOpStore<C, A, R, D> {
    async fn handle_custom_grant(
        &self,
        grant_type: &str,
        _req: authkestra_op::handlers::token::TokenRequest,
        client_id: String,
        _client: authkestra_op::client::ClientRegistration,
        _config: &authkestra_op::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<authkestra_op::handlers::token::TokenResponse, authkestra_op::handlers::token::TokenErrorResponse> {
        if grant_type == "urn:example:custom" {
            // Demonstration: blindly issue a token!
            let access_token = tokens.issue_client_token(&client_id, 3600, None, None).unwrap();
            return Ok(authkestra_op::handlers::token::TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
                refresh_token: None,
                id_token: None,
                scope: None,
            });
        }
        
        Err(authkestra_op::handlers::token::TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Unsupported custom grant".to_string(),
        })
    }
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
                grant_types: vec![authkestra_op::client::GrantType::AuthorizationCode, authkestra_op::client::GrantType::Custom("urn:example:custom".to_string())],
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
        Arc::new(MyCustomOpStore { inner: authkestra_op::store::CompositeOpStore::new(
            clients,
            auth_codes,
            refresh_tokens,
            device_codes,
        )});

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

    // TIP: authkestra uses traits (like `SessionStore`) for storage.
    // This makes it easy to swap out backends! You could easily replace `MemoryStore`
    // with `SqlKvStore` or `RedisStore` simply by changing the struct instantiated here.
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
