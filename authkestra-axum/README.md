# authkestra-axum

Axum integration for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides Axum-specific extractors and helpers to easily integrate the `authkestra` authentication framework into Axum applications.

## Features

- **Extractors**:
  - `Auth<I>`: Unified extractor that uses a configured `AuthkestraGuard` to validate the request.
  - `AuthSession`: Extracts a validated session from cookies.
  - `AuthToken`: Extracts and validates a JWT from the `Authorization: Bearer` header.
- **OAuth Helpers**:
  - `initiate_oauth_login`: Generates authorization URLs and handles CSRF protection.
  - `handle_oauth_callback`: Finalizes OAuth login and creates a server-side session.
  - `handle_oauth_callback_jwt`: Finalizes OAuth login and returns a JWT.
- **Offline Validation**:
  - `Jwt<T>`: Extractor for validating JWTs from external OIDC providers using JWKS (via `authkestra-guard`).
- **Session Management**:
  - `logout`: Clears the session cookie and removes it from the store.
  - `SessionConfig`: Customizable session settings (cookie name, secure, http_only, etc.).
- **Macros**:
  - `AuthkestraFromRef`: Automatically generate `FromRef` implementations for your application state.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-axum = { version = "0.1.2", features = ["macros"] }
tower-cookies = "0.10" # Required for session support
```

### Quick Start with AuthkestraFromRef (Recommended)

The easiest way to integrate Authkestra with custom Axum state is using the `AuthkestraFromRef` macro:

```rust
use axum::{routing::get, Router};
use authkestra_axum::{AuthSession, AuthkestraFromRef};
use authkestra::flow::Authkestra;
use authkestra_flow::{Configured, Missing};
use authkestra_session::SessionStore;
use tower_cookies::CookieManagerLayer;
use std::sync::Arc;

#[derive(Clone, AuthkestraFromRef)]
struct AppState {
    #[authkestra]
    auth: Authkestra<Configured<Arc<dyn SessionStore>>, Missing>,
    // other fields...
}

async fn protected_handler(AuthSession(session): AuthSession) -> String {
    format!("Welcome back, {}!", session.identity.username.unwrap_or_default())
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/protected", get(protected_handler))
        .layer(CookieManagerLayer::new())
        .with_state(state)
}
```

### Manual Integration

If you prefer not to use the macro or need more control, you can manually implement the required traits:

```rust
use axum::{routing::get, Router, extract::FromRef};
use authkestra_axum::{AuthSession, SessionConfig, AuthkestraAxumError};
use authkestra_session::SessionStore;
use tower_cookies::CookieManagerLayer;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    session_store: Arc<dyn SessionStore>,
    session_config: SessionConfig,
}

impl FromRef<AppState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.session_store.clone()
    }
}

impl FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.session_config.clone()
    }
}
```

### Example: Unified Authentication (Chained Strategies)

The `Auth<I>` extractor allows you to use a central `AuthkestraGuard` that can try multiple authentication methods in order.

```rust
use axum::{routing::get, Router, extract::FromRef};
use authkestra_axum::Auth;
use authkestra_guard::{AuthkestraGuard, AuthPolicy};
use authkestra_guard::jwt::JwtStrategy;
use authkestra_session::SessionStrategy;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct User { id: String }

#[derive(Clone)]
struct AppState {
    guard: Arc<AuthkestraGuard<User>>,
}

impl FromRef<AppState> for Arc<AuthkestraGuard<User>> {
    fn from_ref(state: &AppState) -> Self {
        state.guard.clone()
    }
}

async fn protected_handler(Auth(user): Auth<User>) -> String {
    format!("Welcome, user {}!", user.id)
}
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
