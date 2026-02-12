# authkestra-axum

Axum integration for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides Axum-specific extractors and helpers to easily integrate the `authkestra` authentication framework into Axum applications.

## Features

- **Extractors**:
  - `Auth<I>`: Unified extractor that uses a configured `Authenticator` to validate the request.
  - `AuthSession`: Extracts a validated session from cookies.
  - `AuthToken`: Extracts and validates a JWT from the `Authorization: Bearer` header.
- **OAuth Helpers**:
  - `initiate_oauth_login`: Generates authorization URLs and handles CSRF protection.
  - `handle_oauth_callback`: Finalizes OAuth login and creates a server-side session.
  - `handle_oauth_callback_jwt`: Finalizes OAuth login and returns a JWT.
- **Offline Validation**:
  - `Jwt<T>`: Extractor for validating JWTs from external OIDC providers using JWKS.
- **Session Management**:
  - `logout`: Clears the session cookie and removes it from the store.
  - `SessionConfig`: Customizable session settings (cookie name, secure, http_only, etc.).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-axum = "0.1.1"
tower-cookies = "0.10" # Required for session support
```

### Example: Unified Authentication (Chained Strategies)

The `Auth<I>` extractor allows you to use a central `Authenticator` that can try multiple authentication methods in order.

```rust
use axum::{routing::get, Router, extract::FromRef};
use authkestra_axum::Auth;
use authkestra_core::strategy::{Authenticator, TokenStrategy, SessionStrategy};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct User { id: String }

#[derive(Clone)]
struct AppState {
    authenticator: Arc<Authenticator<User>>,
}

impl FromRef<AppState> for Arc<Authenticator<User>> {
    fn from_ref(state: &AppState) -> Self {
        state.authenticator.clone()
    }
}

async fn protected_handler(Auth(user): Auth<User>) -> String {
    format!("Welcome, user {}!", user.id)
}

fn app() -> Router {
    let authenticator = Authenticator::builder()
        .with_strategy(TokenStrategy::new(jwt_validator))
        .with_strategy(SessionStrategy::new(session_store, "session_cookie"))
        .build();

    let state = AppState {
        authenticator: Arc::new(authenticator),
    };

    Router::new()
        .route("/protected", get(protected_handler))
        .with_state(state)
}
```

### Example: Session-based Authentication

```rust
use axum::{routing::get, Router, extract::State};
use authkestra_axum::{AuthSession, SessionConfig, initiate_oauth_login, handle_oauth_callback};
use authkestra_session::SessionStore;
use tower_cookies::CookieManagerLayer;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    session_store: Arc<dyn SessionStore>,
    session_config: SessionConfig,
    // ... other state like OAuth flows
}

// Implement FromRef for the extractors to work
impl axum::extract::FromRef<AppState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.session_store.clone()
    }
}

impl axum::extract::FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.session_config.clone()
    }
}

async fn protected_handler(AuthSession(session): AuthSession) -> String {
    format!("Welcome back, {}!", session.identity.username.unwrap_or_default())
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/protected", get(protected_handler))
        // The CookieManagerLayer is required for AuthSession and OAuth helpers
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
```

### Example: JWT-based Authentication

```rust
use authkestra_axum::AuthToken;
use authkestra_token::TokenManager;
use std::sync::Arc;

// Ensure Arc<TokenManager> is available in your State via FromRef

async fn api_handler(AuthToken(claims): AuthToken) -> String {
    format!("Hello user with ID: {}", claims.sub)
}
```

### Offline Validation

For validating tokens from external providers (like Google or Auth0) using their JWKS endpoint:

```rust
use authkestra_axum::Jwt;
use authkestra_token::offline_validation::JwksCache;
use jsonwebtoken::Validation;
use std::sync::Arc;
use serde::Deserialize;

#[derive(Deserialize)]
struct MyClaims {
    sub: String,
}

// Ensure Arc<JwksCache> and Validation are available in your State via FromRef

async fn external_api_handler(Jwt(claims): Jwt<MyClaims>) -> String {
    format!("Hello external user: {}", claims.sub)
}
```

### SPA vs Server-Side Rendering

For **SPA (Single Page Application)** use cases where you want to receive a JWT on the frontend:
1. The `redirect_uri` in your OAuth provider configuration should point to a **frontend route** (e.g., `https://myapp.com/callback`).
2. Your frontend route should extract the `code` and `state` from the URL.
3. The frontend then performs a **POST** (or GET) request to your backend's callback endpoint (e.g., `/api/auth/callback`) with these parameters.
4. The backend uses `handle_oauth_callback_jwt` to exchange the code for a JWT and returns it to the frontend.

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
