---
title: OIDC Client
description: Using the generic OpenID Connect client with Authkestra.
---

Authkestra provides a generic OpenID Connect (OIDC) client that automatically discovers endpoints and keys from any OIDC-compliant provider and background-caches discovery documents.

## Prerequisites

To use the OIDC client, enable the `oidc` feature on the `authkestra` crate.

```toml
[dependencies]
authkestra = { version = "0.3", features = ["oidc"] }
```

## Configuring the OIDC Provider

Instantiate `OidcProvider` directly by pointing it to the issuer URL. The client automatically fetches and caches `/.well-known/openid-configuration` to discover authorization and token endpoints.

```rust
use authkestra::Authkestra;
use authkestra::oidc::OidcProvider;
use authkestra::store::memory::MemoryStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Perform discovery automatically
    let oidc_provider = OidcProvider::discover(
        "CLIENT_ID".to_string(),
        "CLIENT_SECRET".to_string(),
        "http://localhost:3000/auth/callback/oidc".to_string(),
        "https://accounts.google.com".to_string(), // Issuer URL
    ).await?;

    let auth_engine = Authkestra::builder()
        .provider(oidc_provider)
        .session_store(Arc::new(MemoryStore::default()))
        .build();

    Ok(())
}
```

*(Note: If you are building a Resource Server that needs to validate incoming JWTs against an external OIDC provider, refer to the **Resource Server** guide for information on OIDC Discovery caching and JWKS validation).*
