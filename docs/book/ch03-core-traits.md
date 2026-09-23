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

The base trait for any authentication mechanism (WebAuthn, TOTP, magic links, OTP codes, recovery
codes). Everything except `name` and `authenticate` is defaulted, so a minimal method implements
two functions.

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

Shipped implementations: `WebAuthnAuthMethod` and `TotpAuthMethod` (above), plus three passwordless
methods added in v0.13.0, each behind its own feature flag and each registered through the generic
`with_auth_method(...)` — there is no dedicated convenience wrapper for these three:

- `MagicLinkAuthMethod` (feature `magic-link`) — `mint(subject, ttl, binding)` hands back a
  one-time link secret; `authenticate()` consumes it exactly once. See
  `docs/rfc-010-magic-link.md`.
- `OtpAuthMethod` (feature `otp`) — `mint(subject, ttl, channel, max_attempts)` issues a short
  numeric code against an attempt budget, with an opt-in per-subject resend cooldown via
  `OtpAuthMethod::with_resend_cooldown`. See `docs/rfc-011-otp.md`.
- `RecoveryCodeAuthMethod` (feature `recovery-codes`) — a look-up secret authenticator (NIST SP
  800-63B §5.1.2), not TOTP-specific; `generate()` returns a fresh set of codes, replacing any
  existing one. See `docs/rfc-012-recovery-codes.md`.

Magic link and OTP both override `has_enrolled` to always return `false` — the same value the
trait's own default gives, but stated explicitly rather than inherited, because neither has an
enrolment ceremony to report on and leaving it implicit would read as an oversight rather than a
decision. Recovery codes are the exception: they *do* enrol, so `has_enrolled` reflects whether the
account currently holds any live, unredeemed code. All three leave `is_mfa_equivalent` at the
trait's `false` default — none of them is worth as much as primary-plus-step-up when used alone.

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

    /// Like `execute`, but also given the raw transport facts of the inbound
    /// request (`RequestParts`: method, URI, headers, raw body bytes).
    /// Defaulted to ignore them and delegate to `execute`, so this method
    /// costs existing implementors nothing. A protocol whose security model
    /// depends on the exact request bytes — GNAP key proofing (RFC 9635
    /// §7.3) is the motivating case — overrides it instead.
    async fn execute_with_parts(
        &self,
        ctx: FlowContext,
        parts: RequestParts<'_>,
    ) -> Result<FlowResult, AuthError> { /* defaults to `self.execute(ctx)` */ }
}

#[non_exhaustive]
pub enum FlowResult {
    Complete(Identity),
    Redirect(String),
    Pending,
    /// A protocol response that is a JSON document rather than a redirect or
    /// a bare identity — e.g. a GNAP grant response (RFC 9635 §3), which may
    /// carry `continue` + `interact` + `access_token` + `subject`
    /// simultaneously.
    Document(serde_json::Value),
}
```

`FlowContext` also gained a `body: Option<serde_json::Value>` field (for protocols that speak JSON
end-to-end, like GNAP) and a `FlowContext::new(state, params)` constructor — it is
`#[non_exhaustive]` with no public fields-only constructor otherwise, so this is the supported way
to build one outside `authkestra-engine`'s own tests.

Shipped implementations: `OAuth2Flow`, `ClientCredentialsFlow`, `DeviceFlow`. Only `OAuth2Flow`
actually implements the `Flow` trait itself today; `ClientCredentialsFlow` and `DeviceFlow` expose
their own inherent async methods instead (see `crates/authkestra-engine/examples/client_credentials.rs`
and `examples/device_flow.rs`). None of the three needed any change to keep compiling against the
additions above — see `docs/rfc-004-gnap-flow.md` for the full design rationale and what is still
deliberately not implemented (a GNAP grant endpoint itself).

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

/// Atomically decrement a counter. The third atomic primitive, for a budget
/// (e.g. OTP's remaining verification attempts) that must not be
/// read-modify-written back under concurrent callers.
#[async_trait]
pub trait AtomicDecrement<T>: KvStore<T> { /* ... */ }

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
how `MemoryStore` and `RedisStore` both qualify:

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
- **`SignalReceiver`** — no such trait exists in `authkestra-engine`, and none is planned there.
  This is narrower than it used to be: `authkestra-ssf` is a real, published crate that ingests and
  validates Shared Signals Framework security event tokens (RFC 8417) into typed CAEP 1.0 events,
  receiver-side, via its own `SetHandler` trait. What is still missing is the *transmitter* side
  (this service emitting SETs of its own) and any wiring from a received event to revoking or
  attenuating a live session — see `docs/roadmap.md` §2.
- **`PolicyEngine`** — no such trait exists in `authkestra-engine` either. `authkestra-policy` is
  likewise a real, published crate — a working Cedar evaluator — but an unwired proof of concept:
  nothing in the engine calls it yet. See Chapter 5, and `docs/roadmap.md` §2.
