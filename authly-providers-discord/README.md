# authly-providers-discord

Discord OAuth2 provider for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate provides a concrete implementation of the `OAuthProvider` trait for Discord, allowing easy integration of Discord authentication into your application.

## Features

- Authorization Code exchange for Discord identities.
- PKCE support.
- Token refresh support.
- Token revocation support.
- Automatic mapping of Discord user profiles to `Identity`.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-providers-discord = "0.1.0"
```

### Example

```rust
use authly_providers_discord::DiscordProvider;
use authly_core::OAuthProvider;

#[tokio::main]
async fn main() {
    let provider = DiscordProvider::new(
        "CLIENT_ID".to_string(),
        "CLIENT_SECRET".to_string(),
        "http://localhost:3000/auth/callback/discord".to_string(),
    );

    // Generate authorization URL
    let auth_url = provider.get_authorization_url("state", &["identify", "email"], None);
    println!("Authorize at: {}", auth_url);

    // After receiving the code in your callback:
    // let (identity, token) = provider.exchange_code_for_identity("CODE", None).await.unwrap();
}
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
