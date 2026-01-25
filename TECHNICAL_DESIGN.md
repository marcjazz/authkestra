# Authly Technical Design Document

This document outlines the architecture for `authly`, a modular, framework-agnostic authentication workspace for Rust.

## 1. Directory Structure

The project will use a standard Cargo workspace layout to ensure separation of concerns and parallel compilation.

```text
authly/
├── Cargo.toml              # Workspace root
├── authly-core/            # Shared traits and types (Zero-dependency mostly)
│   ├── Cargo.toml
│   └── src/lib.rs
├── authly-flow/            # OAuth2/OIDC flow logic (State machines, URL building)
│   ├── Cargo.toml
│   └── src/lib.rs
├── authly-session/         # Session abstraction (Stores, Cookie handling)
│   ├── Cargo.toml
│   └── src/lib.rs
├── authly-token/           # Token operations (JWT, Paseto)
│   ├── Cargo.toml
│   └── src/lib.rs
├── authly-providers-discord/ # Discord specific implementation
│   ├── Cargo.toml
│   └── src/lib.rs
├── authly-providers-github/ # GitHub specific implementation
│   ├── Cargo.toml
│   └── src/lib.rs
├── authly-providers-google/ # Google specific implementation
│   ├── Cargo.toml
│   └── src/lib.rs
└── authly-axum/            # Axum integration (Extractors, Middlewares)
    ├── Cargo.toml
    └── src/lib.rs
```

## 2. Crate Definitions

| Crate | Responsibility | Key Dependencies |
|-------|----------------|------------------|
| **`authly-core`** | Defines the foundational traits (`OAuthProvider`, `CredentialsProvider`, `SessionStore`) and types (`AuthError`, `Identity`). Must remain stable. | `serde`, `thiserror`, `chrono`, `async-trait` |
| **`authly-flow`** | Implements standard authentication flows (e.g., OAuth2 Authorization Code). Pure logic, no HTTP server code. | `authly-core`, `oauth2` (optional), `url` |
| **`authly-session`** | Manages session persistence and retrieval. Defines the `Session` struct and `SessionStore` trait. Includes memory/redis/sqlx impls. | `authly-core`, `uuid`, `sqlx` (optional) |
| **`authly-token`** | Handles stateless auth (JWT/PASETO). Issuing and validating tokens. | `authly-core`, `jsonwebtoken` |
| **`authly-providers-github`** | Implements `authly-core::OAuthProvider` for GitHub. Handles specific user profile parsing. | `authly-core`, `reqwest`, `serde_json` |
| **`authly-providers-google`** | Implements `authly-core::OAuthProvider` for Google. | `authly-core`, `reqwest`, `serde_json` |
| **`authly-providers-discord`** | Implements `authly-core::OAuthProvider` for Discord. | `authly-core`, `reqwest`, `serde_json` |
| **`authly-axum`** | Provides `FromRequest` implementations (Extractors) and helpers for Axum. Glue code only. | `authly-core`, `authly-session`, `axum`, `tower-cookies` |

## 3. API Design

The core philosophy is **Explicit Control Flow**. We avoid "magic" middleware that injects data into request extensions implicitly. Instead, we use extractors that explicitly require dependencies.

### `authly-core`

```rust
// authly-core/src/lib.rs

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A unified identity structure returned by all providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub provider_id: String, // e.g., "github"
    pub external_id: String, // e.g., "12345"
    pub email: Option<String>,
    pub username: Option<String>,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Invalid code")]
    InvalidCode,
    #[error("Network error")]
    Network,
    // ...
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Helper to get the authorization URL.
    fn get_authorization_url(&self, state: &str, scopes: &[&str]) -> String;
    
    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(&self, code: &str) -> Result<Identity, AuthError>;
}

/// Trait for a Credentials-based provider (e.g., Email/Password).
#[async_trait]
pub trait CredentialsProvider: Send + Sync {
    type Credentials;
    
    /// Validate credentials and return an Identity.
    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError>;
}
```

### `authly-flow`

```rust
// authly-flow/src/lib.rs

use authly_core::{OAuthProvider, Identity, AuthError, CredentialsProvider};

/// Orchestrates the Authorization Code flow.
pub struct OAuth2Flow<P: OAuthProvider> {
    provider: P,
}

impl<P: OAuthProvider> OAuth2Flow<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Generates the redirect URL and CSRF state.
    pub fn initiate_login(&self) -> (String, String) {
        let state = uuid::Uuid::new_v4().to_string();
        let url = self.provider.get_authorization_url(&state, &[]);
        (url, state)
    }

    /// Completes the flow by exchanging the code.
    pub async fn finalize_login(&self, code: &str, _state: &str) -> Result<Identity, AuthError> {
        self.provider.exchange_code_for_identity(code).await
    }
}

/// Orchestrates a direct credentials flow.
pub struct CredentialsFlow<P: CredentialsProvider> {
    provider: P,
}

impl<P: CredentialsProvider> CredentialsFlow<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub async fn authenticate(&self, creds: P::Credentials) -> Result<Identity, AuthError> {
        self.provider.authenticate(creds).await
    }
}
```

### `authly-session`

```rust
// authly-session/src/lib.rs

use async_trait::async_trait;
use authly_core::Identity;

#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub identity: Identity,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn load(&self, id: &str) -> Result<Option<Session>, authly_core::AuthError>;
    async fn save(&self, session: &Session) -> Result<(), authly_core::AuthError>;
    async fn delete(&self, id: &str) -> Result<(), authly_core::AuthError>;
}

#### SQL Support (`sqlx`)

When the `store-sqlx` feature is enabled (along with `postgres`, `mysql`, or `sqlite`), a `SqlStore` is available.

**Schema:**

```sql
CREATE TABLE authly_sessions (
    id VARCHAR(128) PRIMARY KEY,
    provider_id VARCHAR(255) NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    username VARCHAR(255),
    claims TEXT NOT NULL, -- JSON serialized string of additional attributes
    expires_at TIMESTAMP NOT NULL -- TIMESTAMPTZ for Postgres, INTEGER for Sqlite
);
CREATE INDEX idx_authly_sessions_expires_at ON authly_sessions(expires_at);
CREATE INDEX idx_authly_sessions_provider ON authly_sessions(provider_id, external_id);
```

**Usage Example (Postgres):**

```rust
use authly_session::SqlStore;
use sqlx::postgres::PgPool;

let pool = PgPool::connect("postgres://localhost/auth").await?;
let store = SqlStore::new(pool);
```

### `authly-axum`

Integration is done via **State** and **Extractors**.

```rust
// authly-axum/src/lib.rs

use axum::{
    async_trait,
    extract::{FromRequestParts, FromRef},
    http::{request::Parts, StatusCode},
};
use authly_session::{Session, SessionStore};
use std::sync::Arc;

/// The extractor for a validated session.
/// If session is missing or invalid, this fails (returns 401/302).
pub struct AuthSession(pub Session);

/// State trait to ensure the application state has what we need.
pub trait HasSessionStore {
    fn session_store(&self) -> Arc<dyn SessionStore>;
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    // We require the AppState to implement HasSessionStore
    Arc<dyn SessionStore>: FromRef<S>, 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = <Arc<dyn SessionStore> as FromRef<S>>::from_ref(state);
        
        // 1. Extract cookie from `parts.headers`
        // 2. Call store.load(session_id)
        // 3. Return AuthSession(session) or error
        
        // Mock implementation:
        Err((StatusCode::UNAUTHORIZED, "Login required"))
    }
}
```

## 4. Data Flow: Login with GitHub

1.  **Start Login**:
    *   User hits `GET /auth/github`.
    *   Handler: `github_login_handler`.
    *   Action: Calls `flow.start()`. Generates `state` and `redirect_url`.
    *   Response: Redirects browser to GitHub. (Optional: Store `state` in a cookie/cache for CSRF protection).

2.  **User Approves**:
    *   GitHub redirects user to `GET /auth/github/callback?code=xyz&state=abc`.

3.  **Callback Processing**:
    *   Handler: `github_callback_handler`.
    *   Input: `Query<CallbackParams>` (Axum extractor).
    *   Action:
        1.  Calls `flow.finish(code, state)`.
        2.  `flow` calls `GithubProvider::exchange(code)`.
        3.  `GithubProvider` makes HTTP request to GitHub API to get Token and User Profile.
        4.  Returns `Identity`.
    *   Session Creation:
        1.  Handler takes `Identity`.
        2.  Calls `session_store.save(new_session)`.
        3.  Sets a `Set-Cookie` header with the session ID.

4.  **Protected Route Access**:
    *   User hits `GET /dashboard`.
    *   Handler signature: `async fn dashboard(AuthSession(session): AuthSession)`.
    *   **Axum Extractor logic**:
        1.  Reads Cookie.
        2.  Hits `SessionStore` (Redis/Memory).
        3.  Deserializes `Session`.
        4.  Handler executes with valid `session`.

This architecture ensures that the "magic" is contained within explicitly typed extractors, and the business logic (`authly-flow`) is separated from the transport layer (`authly-axum`).

## 5. Comparison with JS Frameworks

| Feature | Auth.js / Passport.js | Authly (Rust) |
|---------|-----------------------|---------------|
| **Type Safety** | Primarily runtime-based or loose TS types | Compile-time enforced traits and enums |
| **Control Flow** | Implicit (Middleware/Plugins) | Explicit (Handlers/Extractors) |
| **Customization** | Configuration objects | Trait implementations |
| **Registry** | Global runtime strategy registry | Explicit dependency injection via Axum State |
| **Concurrency** | Single-threaded Event Loop | Multi-threaded async (Tokio) |

Authly favors the "Service" pattern over the "Middleware" pattern, making dependencies explicit and easy to test.
