# authkestra-guard

Authentication guard and strategies for the `authkestra` framework.

This crate provides the `AuthGuard`, a flexible orchestrator for multiple authentication strategies, and built-in strategies like JWT offline validation.

## Features

- `AuthGuard`: Orchestrate multiple authentication strategies with different policies (`FirstSuccess`, `AllSuccess`, `FailFast`).
- `JwtStrategy`: Offline validation of JWT tokens using JWKS or local keys.
- Extensible: Implement the `AuthenticationStrategy` trait from `authkestra-core` to create custom strategies.

## Usage

### Using AuthGuard

```rust
use authkestra_guard::{AuthGuard, AuthPolicy};
use authkestra_guard::jwt::JwtStrategy;

// Create a guard with a JWT strategy
let guard = AuthGuard::builder()
    .strategy(JwtStrategy::new(validation_config))
    .policy(AuthPolicy::FirstSuccess)
    .build();

// Authenticate a request
let result = guard.authenticate(&request_parts).await?;
```

### JWT Offline Validation

The `JwtStrategy` (previously in `authkestra-token`) allows for efficient local validation of tokens.

```rust
use authkestra_guard::jwt::{JwtStrategy, ValidationConfig};

let config = ValidationConfig::builder()
    .issuer("https://example.com")
    .audience("my-app")
    .jwks_url("https://example.com/.well-known/jwks.json")
    .build();

let strategy = JwtStrategy::new(config);
```

## Related Crates

- `authkestra-core`: Core traits and error types.
- `authkestra-axum`: Axum extractors and middleware.
- `authkestra-actix`: Actix-web extractors and middleware.
