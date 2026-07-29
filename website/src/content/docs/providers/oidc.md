---
title: OIDC Client
description: Using the generic OpenID Connect client with Authkestra.
---

Authkestra provides a generic OpenID Connect (OIDC) client that can automatically discover endpoints and keys from any OIDC-compliant provider.

## Prerequisites

To use the OIDC client, you must enable the `oidc` feature on the `authkestra` crate.

```toml
[dependencies]
authkestra = { version = "0.2.4", features = ["oidc"] }
```

## Configuring the OIDC Provider

You can instantiate the `OidcProvider` directly by pointing it to the issuer URL. The client will automatically fetch the `/.well-known/openid-configuration` to determine the authorization and token endpoints.

```rust
use authkestra_oidc::OidcProvider;

// This performs discovery automatically!
let provider = OidcProvider::discover(
    "CLIENT_ID".to_string(),
    "CLIENT_SECRET".to_string(),
    "http://localhost:3000/auth/callback/my-oidc".to_string(),
    "https://accounts.google.com".to_string(), // The issuer URL
).await.unwrap();
```

*(Note: If you are building a Resource Server that needs to validate incoming JWTs against an external OIDC provider, refer to the **Resource Server** page for information on OIDC Discovery caching).*
