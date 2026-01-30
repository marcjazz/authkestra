# authly-oidc

OpenID Connect (OIDC) implementation for [authly-rs](https://github.com/marcorichetta/authly-rs).

This crate provides OIDC support for the `authly` framework, including discovery, JWKS handling, and ID token validation.

## Features

- OIDC Discovery.
- JWKS (JSON Web Key Set) fetching and caching.
- ID Token verification.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-oidc = "0.1.0"
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcorichetta/authly-rs) workspace.
