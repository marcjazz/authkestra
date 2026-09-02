# Chapter 3: Core Traits

To keep Authkestra extensible and future-proof, we rely on strict, framework-agnostic traits. These
define the "contracts" between the engine and its pluggable extensions.

> **Status:** the traits in "Core Runtime Traits" below are the ones that exist today in
> `authkestra-engine`, transcribed from `crates/authkestra-engine/src/auth/mod.rs` and
> `src/flow/mod.rs`. The "Planned" section at the end describes traits that are **not implemented**
> — do not write code against them. `cargo doc -p authkestra-engine --open` is always the
> authority.

## Core Runtime Traits

### `Provider` (Identity Sources)

An external identity source (e.g., Google, GitHub). Providers are primarily configuration and
mapping, with zero business logic. Note that `config` is `async` — a provider may need to consult a
discovery document to answer it.

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    /// Returns the provider configuration.
    async fn config(&self) -> ProviderConfig;
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Provider {
    /// Get the provider identifier. This is what the `{provider}` path
    /// segment of `/auth/login/{provider}` is matched against.
    fn provider_id(&self) -> &str;

    /// Build the authorization URL.
    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_challenge: Option<&str>,
        nonce: Option<&str>,
    ) -> String;

    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError>;

    /// Refresh an access token. Defaulted: returns `AuthError::Provider`
    /// for providers that do not support it.
    async fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError>;

    /// Revoke an access token. Defaulted, same as above.
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;
}
```

The `nonce` parameters carry the OIDC `nonce` through the authorization request and back into ID
token validation; a plain OAuth2 provider ignores them.

### `AuthMethod`

The base trait for any authentication mechanism (WebAuthn, TOTP, credentials). Everything except
`name` and `authenticate` is defaulted, so a minimal method implements two functions.

```rust
#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// The name this method is registered under, e.g. `"webauthn"`, `"totp"`.
    fn name(&self) -> &str;

    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError>;

    /// Whether this user has enrolled in this method. Defaults to `false`.
    async fn has_enrolled(&self, user_id: &str) -> Result<bool, AuthError>;

    /// Whether this method is itself MFA-equivalent, so the engine will not
    /// prompt for a second factor after it. Defaults to `false`.
    fn is_mfa_equivalent(&self) -> bool;

    /// Optional downcast used by `Engine::start_webauthn`.
    #[cfg(feature = "webauthn")]
    fn as_webauthn_starter(&self) -> Option<&dyn WebAuthnStarter>;
}
```

Register a method as a primary credential with `EngineBuilder::with_auth_method(...)`, or as a
step-up factor only with `EngineBuilder::with_mfa_method(...)`. The convenience wrappers
`with_totp(store)` and `with_webauthn(webauthn, store)` register those two as *primary* methods.

### `Flow` (Protocol Orchestration)

`Flow` orchestrates the steps of a protocol — the OAuth2 authorization code flow, the device
authorization grant, and so on. `Engine::builder().provider(...)` takes a `Flow`, which is why an
`OAuthProvider` is wrapped in `OAuth2Flow::new(provider)` before registration.

```rust
#[async_trait]
pub trait Flow: Send + Sync {
    /// Unique identifier for this flow.
    fn id(&self) -> &str;

    /// Execute the flow with the given context.
    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError>;
}

pub enum FlowResult {
    Complete(Identity),
    Redirect(String),
    Pending,
}
```

Shipped implementations: `OAuth2Flow`, `ClientCredentialsFlow`, `DeviceFlow`.

### Storage traits

Persistence is expressed as small key-value contracts rather than a schema (see Chapter 2):

```rust
#[async_trait]
pub trait KvStore<T>: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError>;
    async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// Atomically fetch-and-remove. Required for anything single-use
/// (authorization codes, device codes, enrolment challenges).
#[async_trait]
pub trait AtomicConsume<T>: KvStore<T> {
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError>;
}

/// Atomically insert only if the key is absent — the shape a replay guard
/// needs for a caller-supplied key such as a DPoP proof's `jti`.
#[async_trait]
pub trait AtomicInsert<T>: KvStore<T> { /* ... */ }

/// A primary key plus a secondary lookup index, maintained together.
#[async_trait]
pub trait IndexedKvStore<T>: KvStore<T> {
    async fn set_indexed(
        &self,
        primary_key: &str,
        secondary_key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError>;
    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<T>, StoreError>;
}
```

`SessionStore` sits on top of these, and there is a **blanket impl** of `SessionStore` for any
`KvStore<Session>` — so implementing `KvStore` gets you a session store for free, which is exactly
how `MemoryStore`, `RedisStore` and `SqlKvStore` all qualify:

```rust
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError>;
    async fn save_session(&self, session: &Session) -> Result<(), AuthError>;
    async fn delete_session(&self, id: &str) -> Result<(), AuthError>;
}
```

### `AuthenticationStrategy` (resource-server side)

The chain a `Guard` runs over an incoming request. It lives in `authkestra_engine::auth::strategy`
(re-exported at the crate root, so `authkestra_engine::strategy::AuthenticationStrategy` also
resolves) and is consumed by `authkestra-resource`:

```rust
#[async_trait]
pub trait AuthenticationStrategy<I>: Send + Sync {
    /// `Ok(None)` means "no credentials of my kind here, try the next
    /// strategy"; `Err` fails the whole chain.
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError>;
}
```

Because it only ever sees `http::request::Parts`, a strategy cannot inspect the request *body* —
which is why device-bound signatures (whose `bdh` check hashes the body) are wired as adapter
middleware instead. See Chapter 6.

## Planned traits — not implemented

The following appeared in earlier drafts of this book as if they existed. They do **not** exist in
the codebase today; they are roadmap items from RFC-002. Nothing in `authkestra-engine` defines
them, and no feature flag enables them.

- **`TokenService`** — a PQC-ready abstraction over token issuance and verification, defined to
  accept the multi-kilobyte signatures of ML-DSA (FIPS 204). Today, token issuance is the concrete
  `authkestra_engine::token::TokenManager`, which is not generic over signature size and supports
  the classical `jsonwebtoken` algorithm set only.
- **`SignalReceiver`** — ingestion of Shared Signals Framework / CAEP security event tokens for
  continuous access evaluation. Roadmap Phase 3; there is no SSF receiver, transmitter, or event
  type in the workspace.
- **`PolicyEngine`** — see Chapter 5, which is likewise a design sketch rather than a description
  of shipped code.
