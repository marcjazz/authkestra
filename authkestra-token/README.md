# authkestra-token

JWT and token utilities for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides JWT signing and token abstraction for use within the `authkestra` framework. It focuses on symmetric (HS256) token management.

> **Note**: Offline validation (JWKS) has been moved to [`authkestra-guard`](../authkestra-guard/README.md).

## Features

- **Token Management**: Issue and validate user-centric or machine-to-machine (M2M) tokens using symmetric keys.
- **Flexible Claims**: Standard OpenID Connect claims with support for custom fields and integrated `authkestra-core` Identity.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-token = "0.1.1"
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

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
