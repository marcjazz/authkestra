---
title: OpenID Provider (OP) Server
description: Building your own identity provider with Authkestra.
---

Beyond consuming identities, Authkestra allows you to *become* the identity provider using the `authkestra-op` crate. This allows you to build your own service similar to **Keycloak** or **Auth0**.

## What is an OpenID Provider?

An OpenID Provider (OP) is an OAuth 2.0 Authorization Server capable of authenticating End-Users and providing claims to a Relying Party (RP). We strictly implement [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

## Required Storage

To run an OP Server, you need to persist four specific types of records. 

1. **Clients**: The applications (Relying Parties) that are allowed to authenticate users against your server. Each client has a `client_id` and authorized `redirect_uris`.
2. **Auth Codes**: Short-lived, single-use codes issued after a user logs in. The client exchanges this code for the actual tokens.
3. **Refresh Tokens**: Long-lived tokens used by clients to fetch new Access Tokens without forcing the user to log in again.
4. **Device Codes**: Used for the OAuth 2.0 Device Authorization Grant (e.g., logging in on a Smart TV).

Authkestra provides a generic `KvStore` trait to persist these using SQLx (`SqlKvStore`). Check the `op_server.rs` example in the repository for the database wiring code.

## Documenting `OpConfig`

The behavior of your OpenID Provider is entirely driven by `OpConfig`. When building the state, you must configure this struct to declare what your server supports.

```rust
use authkestra_op::config::OpConfig;

let config = OpConfig {
    // The canonical base URL of your OP Server. Used in JWT `iss` claims.
    issuer: "http://localhost:3000".to_string(),
    
    // The scopes this server grants (must include "openid" for OIDC)
    scopes_supported: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
    
    // The authorization flows supported. "code" enables the Authorization Code flow.
    response_types_supported: vec!["code".to_string()],
    
    // The token endpoints supported. 
    grant_types_supported: vec!["authorization_code".to_string()],
    
    // Cryptographic signing algorithm for issued ID tokens
    id_token_signing_alg: "RS256".to_string(),
    
    // Lifespans for issued tokens
    access_token_ttl_secs: 3600,
    authorization_code_ttl_secs: 600,
    device_code_ttl_secs: 600,
    
    // Feature flags
    token_exchange_enabled: true,
};
```

## Wiring the OP Endpoints

Once your stores and config are built, you wire the server routes using `op_axum_router()` (or `op_actix_router()`).

```rust
use authkestra_axum::OpExt;
use axum::Router;

// `op_axum_router()` automatically wires standard OIDC server endpoints!
let app = Router::new().merge(state.op_axum_router()).with_state(state);
```

### What Endpoints are Exposed?

Unlike a standard OAuth client router, `op_axum_router()` exposes the endpoints that *other* applications will call to authenticate against you:

1. **`GET /.well-known/openid-configuration`**: The OIDC Discovery endpoint. Relying Parties fetch this to discover your supported scopes and keys.
2. **`GET /jwks`**: Exposes the public keys used to sign your JWTs so Resource Servers can validate them.
3. **`GET /authorize`**: The endpoint users are redirected to when they want to log in.
4. **`POST /token`**: The endpoint clients call to exchange an authorization code or refresh token for a new Access/ID Token.
