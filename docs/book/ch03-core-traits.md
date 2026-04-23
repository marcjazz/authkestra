# Chapter 3: Core Traits

To keep Authkestra extensible, we rely heavily on traits. These traits define the boundaries between the core engine and external implementations (like a Redis session store or a GitHub OAuth provider). In our roadmap to building a "primitive factory", defining strict, normalized interfaces (`Authenticator`, `Provider`, `PolicyEngine`) is crucial to avoid "auth spaghetti" where plugins duplicate logic or create security holes.

## Draft Implementations

### AuthMethod

```rust
use async_trait::async_trait;

#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// Returns a unique identifier for this method (e.g., "oauth2", "credentials")
    fn id(&self) -> &str;

    /// Process an incoming request and potentially yield an Identity
    async fn authenticate(&self, context: &AuthContext) -> Result<Identity, AuthError>;
}
```

### SessionStore

```rust
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn save_session(&self, session_id: &str, identity: &Identity) -> Result<(), SessionError>;
    async fn get_session(&self, session_id: &str) -> Result<Option<Identity>, SessionError>;
    async fn destroy_session(&self, session_id: &str) -> Result<(), SessionError>;
}
```

### Provider

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    async fn get_authorization_url(&self) -> String;
    async fn exchange_code(&self, code: &str) -> Result<TokenSet, ProviderError>;
}
```

### Architectural Decisions & Future Direction

- **`async_trait` Dependency:** While native AFIT is stable, enforcing `Send` bounds (which web frameworks like Axum strictly require) in public traits without `async_trait` can lead to complex and ugly bounds (`impl Future<Output = ...> + Send`). For now, `#[async_trait]` provides a cleaner DX for contributors. We abstract this carefully so it can be migrated to native AFIT when the `Send` bound ergonomics improve in Rust.
- **Context Object (`AuthContext`):** `AuthContext` must be absolutely framework-agnostic. It should wrap the standard `http::Request<()>` parts (headers, URI, query params). Coupling the core engine to Axum or Actix types immediately kills the modularity of the framework.
