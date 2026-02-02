# authkestra-providers-google

Google OAuth2 provider for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides a concrete implementation of the `OAuthProvider` trait for Google, allowing easy integration of Google authentication into your application.

## Features

- **Authorization Code Flow**: Standard OAuth2 flow for Google identities.
- **PKCE Support**: Secure authentication with Proof Key for Code Exchange.
- **Token Refresh**: Support for refreshing access tokens using refresh tokens.
- **Token Revocation**: Support for revoking access tokens.
- **Identity Mapping**: Automatically fetches and maps Google user profile information (sub, email, name, picture, etc.).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-providers-google = "0.1.0"
authkestra-core = "0.1.0"
```

### Example

```rust
use authkestra_providers_google::GoogleProvider;
use authkestra_core::OAuthProvider;

#[tokio::main]
async fn main() {
    let provider = GoogleProvider::new(
        "CLIENT_ID".to_string(),
        "CLIENT_SECRET".to_string(),
        "http://localhost:3000/auth/callback/google".to_string(),
    );

    // 1. Generate authorization URL
    let state = "random_state";
    let scopes = vec!["openid", "email", "profile"];
    let auth_url = provider.get_authorization_url(state, &scopes, None);
    println!("Redirect user to: {}", auth_url);

    // 2. After callback, exchange code for identity and tokens
    // let (identity, token) = provider.exchange_code_for_identity("CODE_FROM_CALLBACK", None).await.unwrap();

    // println!("User ID: {}", identity.external_id);
    // println!("Email: {:?}", identity.email);
}
```

### Default Scopes

If no scopes are provided to `get_authorization_url`, the provider defaults to:

- `openid`
- `email`
- `profile`

### Identity Mapping

The provider maps the following Google user info fields to the `Identity` struct:

| Google Field     | Identity Field                 |
| ---------------- | ------------------------------ |
| `sub`            | `external_id`                  |
| `email`          | `email`                        |
| `name`           | `username`                     |
| `picture`        | `attributes["picture"]`        |
| `email_verified` | `attributes["email_verified"]` |
| `locale`         | `attributes["locale"]`         |

## Testing

You can override the default Google endpoints for testing purposes using `with_test_urls`:

```rust
let provider = GoogleProvider::new(id, secret, redirect)
    .with_test_urls(
        "http://localhost/auth".into(),
        "http://localhost/token".into(),
        "http://localhost/userinfo".into(),
        "http://localhost/revoke".into(),
    );
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
