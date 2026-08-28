---
title: OIDC Client
description: Using the generic OpenID Connect client with Authkestra.
---

Authkestra provides a generic OpenID Connect (OIDC) client that automatically discovers endpoints and keys from any OIDC-compliant provider and background-caches discovery documents.

## Prerequisites

To use the OIDC client, enable the `oidc` feature on the `authkestra` crate.

```toml
[dependencies]
authkestra = { version = "0.6", features = ["oidc", "session"] }
authkestra-engine = { version = "0.6", features = ["session", "memory"] }
```

## Configuring the OIDC Provider

Instantiate `OidcProvider` directly by pointing it to the issuer URL. The client automatically fetches and caches `/.well-known/openid-configuration` to discover authorization and token endpoints.

```rust
use authkestra::Authkestra;
use authkestra::oidc::OidcProvider;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::{OAuth2Flow, SessionStore};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Perform discovery automatically
    let oidc_provider = OidcProvider::discover(
        "CLIENT_ID".to_string(),
        "CLIENT_SECRET".to_string(),
        "http://localhost:3000/auth/callback/oidc".to_string(),
        "https://accounts.google.com", // Issuer URL (&str)
        // Fallback refresh interval, used when the discovery response carries
        // no usable `Cache-Control: max-age`.
        Duration::from_secs(3600),
    ).await?;

    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());

    let auth_engine = Authkestra::builder()
        .provider(OAuth2Flow::new(oidc_provider))
        .session_store(session_store)
        .build();

    Ok(())
}
```

A runnable version (using Google as the issuer) lives in the repository:

```bash
cargo run -p authkestra --example axum_oidc_google --all-features
```

*(Note: If you are building a Resource Server that needs to validate incoming JWTs against an external OIDC provider, refer to the **Resource Server** guide for information on OIDC Discovery caching and JWKS validation).*
