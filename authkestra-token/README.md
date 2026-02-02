# authkestra-token

JWT and token utilities for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides JWT signing, verification, and token abstraction for use within the `authkestra` framework. It supports both symmetric (HS256) token management and asynchronous offline validation using JWKS.

## Features

- **Token Management**: Issue and validate user-centric or machine-to-machine (M2M) tokens using symmetric keys.
- **Offline Validation**: Validate JWTs against remote JWK Sets (JWKS) with built-in caching and automatic refresh.
- **Flexible Claims**: Standard OpenID Connect claims with support for custom fields and integrated `authkestra-core` Identity.
- **Async Ready**: Offline validation is built on `tokio` and `reqwest`.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-token = "0.1.0"
```

### Basic Token Management (Symmetric)

```rust
use authkestra_token::TokenManager;
use authkestra_core::Identity;

let secret = b"your-256-bit-secret";
let manager = TokenManager::new(secret, Some("https://your-issuer.com".to_string()));

// Issue a user token
let identity = Identity {
    external_id: "user_123".to_string(),
    display_name: Some("John Doe".to_string()),
    email: Some("john@example.com".to_string()),
};
let token = manager.issue_user_token(identity, 3600, None).unwrap();

// Validate a token
let claims = manager.validate_token(&token).unwrap();
```

### Offline Validation (JWKS)

```rust
use authkestra_token::offline_validation::{JwksCache, validate_jwt};
use jsonwebtoken::Validation;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let jwks_uri = "https://www.googleapis.com/oauth2/v3/certs".to_string();
    let cache = JwksCache::new(jwks_uri, Duration::from_secs(3600)).await.unwrap();
    
    let validation = Validation::default();
    let token = "your.jwt.token";
    
    match validate_jwt(token, &cache, &validation).await {
        Ok(claims) => println!("Valid token for: {:?}", claims.sub),
        Err(e) => eprintln!("Validation failed: {}", e),
    }
}
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
