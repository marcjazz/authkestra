---
title: Resource Server
description: Protecting your APIs with Authkestra using OIDC discovery.
---

Authkestra isn't just for logging users in; you can also use it to build an **OAuth2 Resource Server** to protect your internal APIs using tokens (like JWTs) issued by an external provider (like Google or Auth0).

## What is a Resource Server?

According to [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1), a Resource Server is the server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.

To securely validate an external JWT, the Resource Server must verify the cryptographic signature using the external provider's public keys (JWKS, defined in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)).

## Building with Authkestra Guard

Authkestra provides the `authkestra-resource` crate, which features a `Guard` and a `JwtStrategy` that automatically caches and refreshes external JWKS.

### 1. Configure the Strategy

First, we set up the `ValidationConfig` and point it to the issuer's JWKS URL. The strategy will automatically fetch and cache the public keys in the background to eliminate per-request latency.

```rust
use authkestra_resource::{jwt::JwtStrategy, jwt::ValidationConfig, Guard};

let issuer = "https://accounts.google.com".to_string();

let validation_config = ValidationConfig::builder()
    .jwks_url(format!("{}/.well-known/jwks.json", issuer))
    .issuer(issuer)
    .build();

// UserIdentity is your custom struct that implements Deserialize
let jwt_strategy = JwtStrategy::<UserIdentity>::new(validation_config);
```

### 2. Flexible Strategy Chaining

A core feature of Authkestra is **Flexible Chaining**. What if you want to support *multiple* types of authentication on the same endpoint? For instance, accepting an OIDC JWT *or* a custom API key? 

The `Guard` builder allows you to chain multiple strategies together. The request will pass if *any* of the chained strategies successfully validate it.

```rust
use authkestra_axum::AxumState;
use std::sync::Arc;

// We chain the JWT strategy alongside an API Key strategy!
let guard = Guard::builder()
    .strategy(jwt_strategy)
    .strategy(ApiKeyStrategy::new(...))
    .build();

#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(store)]
    guard: Arc<Guard<UserIdentity>>,
}
```

### 3. Protect Endpoints

Now you can use the `Auth` extractor in your handlers. If the incoming request satisfies any of the chained strategies in your Guard, it is deserialized into your `UserIdentity` struct!

```rust
use authkestra_axum::Auth;
use axum::response::{IntoResponse, Json};

async fn protected(Auth(user): Auth<UserIdentity>) -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "Access granted via Resource Server Strategy!",
        "user": user,
    }))
}
```
