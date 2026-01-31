# authly-axum

Axum integration for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate provides Axum-specific extractors and helpers to easily integrate the `authly` authentication framework into Axum applications.

## Features

- Extractors for `AuthSession`.
- Helpers for initiating OAuth logins and handling callbacks.
- Session configuration with secure cookie defaults.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-axum = "0.1.0"
```

### Example

```rust
use axum::{routing::get, Router};
use authly_axum::{AuthSession, HasSessionStore};

async fn protected_handler(AuthSession(session): AuthSession) -> String {
    format!("Welcome back, {}!", session.identity.username.unwrap_or_default())
}

fn app() -> Router {
    // ... setup state with SessionStore and OAuthProvider
    Router::new().route("/protected", get(protected_handler))
}
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
