# authly-providers-github

GitHub OAuth2 provider for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate provides a concrete implementation of the `OAuthProvider` trait for GitHub, allowing easy integration of GitHub authentication into your application.

## Features

- Authorization Code exchange for GitHub identities.
- Token refresh support (GitHub requires specific App settings for this).
- Token revocation support.
- Automatic mapping of GitHub user profiles to `Identity`.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-providers-github = "0.1.0"
authly-core = "0.1.0"
```

### Example

```rust
use authly_providers_github::GithubProvider;
use authly_core::OAuthProvider;

#[tokio::main]
async fn main() {
    let provider = GithubProvider::new(
        "CLIENT_ID".to_string(),
        "CLIENT_SECRET".to_string(),
        "http://localhost:3000/auth/callback/github".to_string(),
    );

    // Generate the authorization URL
    let state = "random_state_string";
    let scopes = vec!["user:email", "read:user"];
    let auth_url = provider.get_authorization_url(state, &scopes, None);
    
    println!("Redirect user to: {}", auth_url);
}
```

## Configuration

The `GithubProvider` can be further configured:

```rust
let provider = GithubProvider::new(client_id, client_secret, redirect_uri)
    .with_authorization_url("https://github.com/login/oauth/authorize".to_string());
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
