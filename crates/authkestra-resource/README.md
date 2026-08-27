# authkestra-resource

Resource server enforcement and validation for the `authkestra` framework.

This crate focuses strictly on validation and enforcement (middleware/extractors), providing tools to secure resource servers.

## Features

- `Guard`: A flexible orchestrator for multiple authentication strategies.
- JWT Validation: Offline validation of JWT tokens using JWKS or local keys.
- Framework Agnostic: Core logic remains independent of web frameworks.

## Usage

### Using Guard

```rust
use authkestra_resource::{Guard, AuthPolicy};
use authkestra_resource::jwt::JwtStrategy;

// Create a guard with a JWT strategy
let guard = Guard::builder()
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

### Trusting several issuers

One verifier can accept tokens from several issuers, each with its own JWKS
endpoint. The token's `iss` claim selects which JWKS verifies it:

```rust
use authkestra_resource::jwt::{JwtStrategy, ValidationConfig};

let config = ValidationConfig::builder()
    .trusted_issuer("https://tenant-a.example", "https://tenant-a.example/.well-known/jwks.json")
    .trusted_issuer("https://tenant-b.example", "https://tenant-b.example/.well-known/jwks.json")
    .audience("my-app")
    .build();

let strategy = JwtStrategy::new(config);
```

An `iss` that is not in the trust map is rejected: there is deliberately no
fallback endpoint, because a default JWKS for unknown issuers is issuer
confusion. A token with no `iss` at all is rejected too, since nothing names a
key. For issuers that are only known at runtime, implement `JwksResolver` and
pass it to `JwtStrategy::with_resolver` — the same rule applies, an
implementation must reject issuers it does not recognise.

## Related Crates

- `authkestra-engine`: Foundational types and the Engine orchestrator.
- `authkestra-axum`: Axum extractors and middleware.
- `authkestra-actix`: Actix-web extractors and middleware.
