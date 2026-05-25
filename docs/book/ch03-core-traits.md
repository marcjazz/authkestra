# Chapter 3: Core Traits

To keep Authkestra extensible and future-proof, we rely on strict, framework-agnostic traits. These define the "contracts" between the engine and its pluggable extensions.

## Core Runtime Traits

### `Provider` (Identity Sources)
An external identity source (e.g., Google, GitHub). Providers are primarily configuration and mapping, with zero business logic.

```rust
pub trait Provider: Send + Sync {
    /// Returns the provider configuration.
    fn config(&self) -> ProviderConfig;
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Provider {
    /// Get the provider identifier.
    fn provider_id(&self) -> &str;

    /// Helper to get the authorization URL.
    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_challenge: Option<&str>,
    ) -> String;

    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError>;
}
```

### `AuthMethod`
The base trait for any authentication mechanism (WebAuthn, Magic Link, Credentials).

```rust
#[async_trait]
pub trait AuthMethod: Send + Sync {
    fn id(&self) -> &str;
    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError>;
}
```

### `Flow` (Protocol Orchestration)
The `Flow` trait is designed to handle multi-step protocols like OAuth 2.1 and the next-gen **GNAP**. 

Unlike legacy systems that assume a linear redirect-based flow, the `Flow` trait supports **intent-based negotiation** and asynchronous interaction modes (e.g., polling for device approval).

```rust
#[async_trait]
pub trait Flow: Send + Sync {
    /// Execute a step in the protocol flow
    async fn next_step(&self, context: FlowContext) -> Result<FlowResult, AuthError>;
}
```

## Future-Proofing for Cryptography

### `TokenService`
The `TokenService` trait must handle the transition to **Post-Quantum Cryptography (PQC)**. It is defined to accept arbitrary signature sizes, accommodating the multi-kilobyte signatures required by **ML-DSA**.

```rust
pub trait TokenService: Send + Sync {
    fn issue(&self, identity: &Identity) -> Result<String, AuthError>;
    fn verify(&self, token: &str) -> Result<Identity, AuthError>;
}
```

## Continuous Trust Traits

### `SignalReceiver` (SSF/CAEP)
A new trait in the engine layer that allows Authkestra to ingest real-time security events via the **Shared Signals Framework**.

```rust
#[async_trait]
pub trait SignalReceiver: Send + Sync {
    /// Process an incoming Security Event Token (SET)
    async fn handle_signal(&self, signal: SecurityEvent) -> Result<(), AuthError>;
}
```
