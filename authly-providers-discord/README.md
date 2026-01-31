# authly-providers-discord

Discord OAuth2 provider for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate provides a concrete implementation of the `OAuthProvider` trait for Discord, allowing easy integration of Discord authentication into your application.

## Features

- Authorization Code exchange for Discord identities.
- Token refresh support.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-providers-discord = "0.1.0"
```

### Example

```rust
use authly_providers_discord::DiscordProvider;

let provider = DiscordProvider::new(
    "CLIENT_ID".to_string(),
    "CLIENT_SECRET".to_string(),
    "http://localhost:3000/auth/callback/discord".to_string(),
);
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
