# authkestra-core

Core traits and data structures for the [authkestra](https://github.com/marcjazz/authkestra) ecosystem.

This crate provides the foundational types and traits used across the `authkestra` framework, ensuring a consistent API for authentication providers, session stores, and identity management.

## Features

- `Identity` structure for unified user information across different providers.
- `OAuthToken` structure for standard OAuth2 token responses.
- `OAuthProvider` trait for implementing OAuth2-compatible authentication providers.
- `CredentialsProvider` trait for password-based or custom credential authentication.
- `AuthenticationStrategy` trait for implementing modular authentication strategies.
- `UserMapper` trait for mapping provider identities to local application users.
- `pkce` module for Proof Key for Code Exchange support.
- Standard `AuthError` enum for consistent error handling.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-core = "0.1.1"
```

### Core Traits

#### OAuthProvider

The `OAuthProvider` trait defines the interface for OAuth2 providers. It includes methods for generating authorization URLs and exchanging codes for identities.

```rust
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_challenge: Option<&str>,
    ) -> String;

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError>;

    // Optional methods for token management
    async fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError>;
    async fn revoke_token(&self, token: &str) -> Result<(), AuthError>;
}
```

#### CredentialsProvider

The `CredentialsProvider` trait is used for non-OAuth authentication methods, such as email/password.

```rust
#[async_trait]
pub trait CredentialsProvider: Send + Sync {
    type Credentials;

    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError>;
}
```

### Authentication Strategies

The `strategy` module provides the `AuthenticationStrategy` trait, which allows for implementing modular authentication methods (e.g., Token, Session, Basic).

While `authkestra-flow` handles the high-level login flows (OAuth2, OIDC), `AuthGuard` (from `authkestra-guard`) is used to protect your API routes by validating incoming requests against one or more strategies.

#### Relationship with `Authkestra`

`AuthGuard` (from `authkestra-guard`) and `Authkestra` (from `authkestra-flow`) are designed to be used together but remain decoupled:

- **`Authkestra`**: Manages the **Login Flow** (e.g., redirecting to GitHub, handling the callback, creating a session).
- **`AuthGuard`**: Manages **Access Control** (e.g., checking if a request has a valid session cookie or API key).

By keeping them separate, you can use `Authkestra` to log users in via OAuth2, and then use `AuthGuard` to protect your API using both those sessions AND static API keys or JWTs.

#### UserMapper

The `UserMapper` trait allows you to bridge the gap between a provider's `Identity` and your application's local user model.

```rust
#[async_trait]
pub trait UserMapper: Send + Sync {
    type LocalUser: Send + Sync;

    async fn map_user(&self, identity: &Identity) -> Result<Self::LocalUser, AuthError>;
}
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace. `authkestra` is a modular, framework-agnostic authentication orchestration system for Rust.
