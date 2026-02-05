# authkestra-actix

Actix-web integration for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides Actix-web specific extractors and utilities to integrate the `authkestra` authentication framework into Actix applications.

## Features

- **Extractors**: Easily access validated sessions or JWT claims in your request handlers.
- **OAuth2 Helpers**: Streamlined functions for initiating login, handling callbacks, and logging out.
- **Session Management**: Integration with `authkestra-session` for server-side session storage.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-actix = "0.1.0"
authkestra-session = "0.1.0"
authkestra-token = "0.1.0"
actix-web = "4"
```

### Extractors

#### `AuthSession`

Extracts a validated session from a cookie. Requires `Arc<dyn SessionStore>` and `SessionConfig` to be registered in `app_data`.

```rust
use authkestra_actix::AuthSession;
use actix_web::{get, HttpResponse};

#[get("/profile")]
async fn profile(AuthSession(session): AuthSession) -> HttpResponse {
    HttpResponse::Ok().json(session.identity)
}
```

#### `AuthToken`

Extracts and validates a JWT from the `Authorization: Bearer <token>` header. Requires `Arc<TokenManager>` to be registered in `app_data`.

```rust
use authkestra_actix::AuthToken;
use actix_web::{get, HttpResponse};

#[get("/api/data")]
async fn protected_api(AuthToken(claims): AuthToken) -> HttpResponse {
    HttpResponse::Ok().json(claims)
}
```

#### `Jwt<T>` (Offline Validation)

Extracts and validates a JWT against a remote JWKS (e.g., Google, Auth0). Requires `Arc<JwksCache>` and `jsonwebtoken::Validation` to be registered in `app_data`.

```rust
use authkestra_actix::Jwt;
use authkestra_token::offline_validation::JwksCache;
use actix_web::{get, HttpResponse, web};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct MyClaims {
    sub: String,
    // ...
}

#[get("/api/external")]
async fn external_api(Jwt(claims): Jwt<MyClaims>) -> HttpResponse {
    HttpResponse::Ok().json(claims)
}
```

### OAuth2 Helpers

The crate provides helpers to manage the OAuth2 flow lifecycle.

#### SPA vs Server-Side Rendering

For **SPA (Single Page Application)** use cases where you want to receive a JWT on the frontend:
1. The `redirect_uri` in your OAuth provider configuration should point to a **frontend route** (e.g., `https://myapp.com/callback`).
2. Your frontend route should extract the `code` and `state` from the URL.
3. The frontend then performs a **POST** (or GET) request to your backend's callback endpoint (e.g., `/api/auth/callback`) with these parameters.
4. The backend uses `handle_oauth_callback_jwt` to exchange the code for a JWT and returns it to the frontend.

```rust
use authkestra_actix::{initiate_oauth_login, handle_oauth_callback, logout, SessionConfig, OAuthCallbackParams};
use actix_web::{web, HttpRequest, HttpResponse, get};
use std::sync::Arc;

// 1. Initiate Login
#[get("/login")]
async fn login(flow: web::Data<OAuth2Flow>, config: web::Data<SessionConfig>) -> HttpResponse {
    initiate_oauth_login(&flow, &config, &["user:email"])
}

// 2. Handle Callback (Server-Side Session)
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
use authkestra_actix::SessionConfig;
use authkestra_session::MemoryStore;
use authkestra_token::TokenManager;
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

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
