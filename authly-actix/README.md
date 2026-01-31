# authly-actix

Actix-web integration for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate provides Actix-web specific extractors and utilities to integrate the `authly` authentication framework into Actix applications.

## Features

- **Extractors**: Easily access validated sessions or JWT claims in your request handlers.
- **OAuth2 Helpers**: Streamlined functions for initiating login, handling callbacks, and logging out.
- **Session Management**: Integration with `authly-session` for server-side session storage.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-actix = "0.1.0"
authly-session = "0.1.0"
authly-token = "0.1.0"
actix-web = "4"
```

### Extractors

#### `AuthSession`

Extracts a validated session from a cookie. Requires `Arc<dyn SessionStore>` and `SessionConfig` to be registered in `app_data`.

```rust
use authly_actix::AuthSession;
use actix_web::{get, HttpResponse};

#[get("/profile")]
async fn profile(auth: AuthSession) -> HttpResponse {
    let session = auth.0;
    HttpResponse::Ok().json(session.identity)
}
```

#### `AuthToken`

Extracts and validates a JWT from the `Authorization: Bearer <token>` header. Requires `Arc<TokenManager>` to be registered in `app_data`.

```rust
use authly_actix::AuthToken;
use actix_web::{get, HttpResponse};

#[get("/api/data")]
async fn protected_api(token: AuthToken) -> HttpResponse {
    let claims = token.0;
    HttpResponse::Ok().json(claims)
}
```

### OAuth2 Helpers

The crate provides helpers to manage the OAuth2 flow lifecycle.

```rust
use authly_actix::{initiate_oauth_login, handle_oauth_callback, logout, SessionConfig, OAuthCallbackParams};
use actix_web::{web, HttpRequest, HttpResponse, get};
use std::sync::Arc;

// 1. Initiate Login
#[get("/login")]
async fn login(flow: web::Data<OAuth2Flow>, config: web::Data<SessionConfig>) -> HttpResponse {
    initiate_oauth_login(&flow, &config, &["user:email"])
}

// 2. Handle Callback
#[get("/callback")]
async fn callback(
    req: HttpRequest,
    params: web::Query<OAuthCallbackParams>,
    flow: web::Data<OAuth2Flow>,
    store: web::Data<Arc<dyn SessionStore>>,
    config: web::Data<SessionConfig>,
) -> Result<HttpResponse, actix_web::Error> {
    handle_oauth_callback(
        req,
        &flow,
        params.into_inner(),
        store.get_ref().clone(),
        config.get_ref().clone(),
        "/dashboard"
    ).await
}

// 3. Logout
#[get("/logout")]
async fn sign_out(
    req: HttpRequest,
    store: web::Data<Arc<dyn SessionStore>>,
    config: web::Data<SessionConfig>,
) -> Result<HttpResponse, actix_web::Error> {
    logout(req, store.get_ref().clone(), config.get_ref().clone(), "/").await
}
```

### Setup

To use the extractors and helpers, you must configure your Actix app with the necessary data:

```rust
use actix_web::{web, App, HttpServer};
use authly_actix::SessionConfig;
use authly_session::MemoryStore;
use authly_token::TokenManager;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::new());
    let token_manager = Arc::new(TokenManager::new("your-secret".to_string()));
    let session_config = SessionConfig::default();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(session_store.clone()))
            .app_data(web::Data::new(token_manager.clone()))
            .app_data(web::Data::new(session_config.clone()))
            // ... routes
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
