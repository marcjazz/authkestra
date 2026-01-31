# authly-providers-github

GitHub OAuth2 provider for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate provides a concrete implementation of the `OAuthProvider` trait for GitHub, allowing easy integration of GitHub authentication into your application.

## Features

- Authorization Code exchange for GitHub identities.
- Token refresh support.
- Token revocation support.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-providers-github = "0.1.0"
```

### Example

```rust
use authly_providers_github::GitHubProvider;

let provider = GitHubProvider::new(
    "CLIENT_ID".to_string(),
    "CLIENT_SECRET".to_string(),
    "http://localhost:3000/auth/callback/github".to_string(),
);
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
