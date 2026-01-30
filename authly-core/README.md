# authly-core

Core traits and data structures for the [authly-rs](https://github.com/marcorichetta/authly-rs) ecosystem.

This crate provides the foundational types and traits used across the `authly` framework, ensuring a consistent API for authentication providers, session stores, and identity management.

## Features

- `Identity` structure for unified user information.
- `OAuthProvider` trait for implementing new OAuth2 providers.
- `CredentialsProvider` trait for password-based auth.
- `UserMapper` trait for mapping identities to local database users.
- Standard `AuthError` types.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-core = "0.1.0"
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcorichetta/authly-rs) workspace. `authly` is a modular, framework-agnostic authentication orchestration system for Rust.
