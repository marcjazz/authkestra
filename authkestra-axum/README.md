# authkestra-axum

Axum integration for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides Axum-specific extractors and helpers to easily integrate the `authkestra` authentication framework into Axum applications.

## Features

- **Extractors**:
  - `AuthSession`: Extracts a validated session from cookies.
  - `AuthToken`: Extracts and validates a JWT from the `Authorization: Bearer` header.
- **OAuth Helpers**:
  - `initiate_oauth_login`: Generates authorization URLs and handles CSRF protection.
  - `handle_oauth_callback`: Finalizes OAuth login and creates a server-side session.
  - `handle_oauth_callback_jwt`: Finalizes OAuth login and returns a JWT.
- **Session Management**:
  - `logout`: Clears the session cookie and removes it from the store.
  - `SessionConfig`: Customizable session settings (cookie name, secure, http_only, etc.).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-axum = "0.1.0"
tower-cookies = "0.10" # Required for session support
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

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
