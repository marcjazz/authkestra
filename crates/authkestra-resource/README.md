# authkestra-resource

Resource server enforcement and validation for the `authkestra` framework.

This crate focuses strictly on validation and enforcement (middleware/extractors), providing tools to secure resource servers.

## Features

- `AkResourceGuard`: A flexible orchestrator for multiple authentication strategies.
- JWT Validation: Offline validation of JWT tokens using JWKS or local keys.
- Framework Agnostic: Core logic remains independent of web frameworks.

## Usage

### Using AkResourceGuard

```rust
use authkestra_resource::{AkResourceGuard, AuthPolicy};
use authkestra_resource::jwt::JwtStrategy;

// Create a guard with a JWT strategy
let guard = AkResourceGuard::builder()
    .strategy(JwtStrategy::new(validation_config))
    .policy(AuthPolicy::FirstSuccess)
    .build();

// Authenticate a request
let result = guard.authenticate(&request_parts).await?;
```

### JWT Offline Validation

The `authkestra-resource` crate allows for efficient local validation of tokens.

```rust
use authkestra_resource::jwt::{JwtStrategy, ValidationConfig};

let config = ValidationConfig::builder()
    .issuer("https://example.com")
    .audience("my-app")
    .jwks_url("https://example.com/.well-known/jwks.json")
    .build();

let strategy = JwtStrategy::new(config);
```

## Related Crates

- `authkestra-engine`: Foundational types and the AkBase orchestrator.
- `authkestra-axum`: Axum extractors and middleware.
- `authkestra-actix`: Actix-web extractors and middleware.
