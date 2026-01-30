# authly-providers-google

Google OAuth2 provider for [authly-rs](https://github.com/marcorichetta/authly-rs).

This crate provides a concrete implementation of the `OAuthProvider` trait for Google, allowing easy integration of Google authentication into your application.

## Features

- Authorization Code exchange for Google identities.
- Token refresh support.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-providers-google = "0.1.0"
```

### Example

```rust
use authly_providers_google::GoogleProvider;

let provider = GoogleProvider::new(
    "CLIENT_ID".to_string(),
    "CLIENT_SECRET".to_string(),
    "http://localhost:3000/auth/callback/google".to_string(),
);
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcorichetta/authly-rs) workspace.
