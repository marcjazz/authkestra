# authkestra-axum

Axum integration for the [authkestra](https://github.com/marcjazz/authkestra) authentication framework.

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-axum = { version = "0.1.1", features = ["macros"] }
tower-cookies = "0.11" # Required for session support
```

### Quick Start with Derive Macro (Recommended)

The easiest way to integrate Authkestra with custom Axum state is using the `#[derive(AuthkestraFromRef)]` macro:

```rust
use axum::{routing::get, Router};
use authkestra_axum::{AuthSession, AuthkestraFromRef};
use authkestra::flow::Authkestra;
use authkestra_flow::{Configured, Missing};
use authkestra_session::SessionStore;
use tower_cookies::CookieManagerLayer;
use std::sync::Arc;
use sqlx::PgPool; // Assuming you use sqlx for database access

#[derive(Clone, AuthkestraFromRef)]
struct AppState {
    #[authkestra]
    auth: Authkestra<Configured<Arc<dyn SessionStore>>, Missing>,
    db_pool: Arc<PgPool>,
    // ... other application state
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

The macro automatically generates all required `FromRef` implementations, eliminating approximately 30 lines of boilerplate code.

### Manual Integration (Advanced)

If you prefer not to use the macro or need more control, you can manually implement the required traits:

```rust
use axum::{routing::get, Router, extract::State};
use authkestra_axum::{AuthSession, SessionConfig, AuthkestraAxumError};
use authkestra_session::SessionStore;
use tower_cookies::CookieManagerLayer;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    session_store: Arc<dyn SessionStore>,
    session_config: SessionConfig,
    // ... other state
}

// Implement FromRef for the extractors to work
impl axum::extract::FromRef<AppState> for Result<Arc<dyn SessionStore>, AuthkestraAxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.session_store.clone())
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
```

## 🚀 Features

- **Session Extractor**: Easily access the current user's session via `AuthSession(session)`.
- **JWT Extractor**: Validate and extract JWT claims with `AuthToken(claims)`.
- **Unified Auth Extractor**: Use `Auth(identity)` to support multiple authentication strategies (Session, JWT, etc.) via `AuthkestraGuard`.
- **OAuth Helpers**: Simplified handlers for initiating OAuth flows and handling callbacks.
- **Framework Native**: Built on top of Axum's `FromRequestParts` for idiomatic integration.

## 📜 License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
