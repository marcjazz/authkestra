---
title: OpenID Provider (OP) Server
description: Building your own identity provider with Authkestra.
---

Beyond consuming identities, Authkestra allows you to *become* the identity provider using the `authkestra-op` crate. This allows you to build your own service similar to **Keycloak** or **Auth0**.

## What is an OpenID Provider?

An OpenID Provider (OP) is an OAuth 2.0 Authorization Server capable of authenticating End-Users and providing claims to a Relying Party (RP). We strictly implement [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

## Prerequisites

Because OP Servers are an advanced use case, the OP logic is not included in the default `authkestra` facade crate. You must include the `authkestra-op` crate directly and explicitly enable the `op` feature on your chosen web framework adapter.

```toml
[dependencies]
authkestra-op = "0.2.2"
authkestra-axum = { version = "0.2.1", features = ["op"] }
# Or if using Actix:
# authkestra-actix = { version = "0.2.1", features = ["op"] }
```

## The OpStore Interface

To run an OP Server, you need to persist four specific types of records: Clients, Auth Codes, Refresh Tokens, and Device Codes. 

In Authkestra, this is handled through the unified `OpStore` supertrait. `OpStore` aggregates the four granular storage traits:

```rust
pub trait OpStore:
    ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
}
```

You can implement `OpStore` directly on a single monolithic database struct (e.g., your main Postgres pool struct). Alternatively, if you want to use different backends for different types of data (e.g., config for clients, Redis for codes), you can use the `CompositeOpStore` helper to delegate to four individual store implementations:

```rust
use authkestra_op::store::CompositeOpStore;

let op_store = CompositeOpStore::new(
    client_store, // e.g., PostgreSQL for persistent clients
    auth_code_store, // e.g., Redis for short-lived codes
    refresh_token_store,
    device_code_store,
);
```

> [!TIP]
> **Implementing Custom Stores:** If you build your own combined store type (e.g. `struct MyCustomStore { ... }`), you must explicitly implement the `OpStore` trait for it (`impl OpStore for MyCustomStore {}`). This is a minor breaking change from `0.2.1` where a blanket implementation was provided, which was removed to allow for overriding the `handle_custom_grant` method.

Check the `op_server.rs` example in the repository for full database wiring code.

## Supported Grant Types

Authkestra's OP server is fully featured and natively supports the following OAuth 2.0 / OIDC grant types. When registering clients (via your `ClientStore`), you assign them a list of `GrantType` enum variants they are permitted to use:

1. **Authorization Code** (`GrantType::AuthorizationCode`): The standard interactive OIDC login flow. Used by web applications and mobile apps to securely acquire tokens after user authentication.
2. **Client Credentials** (`GrantType::ClientCredentials`): Server-to-server machine authentication. Used when a backend service needs to access an API on its own behalf.
3. **Refresh Token** (`GrantType::RefreshToken`): Allows clients to exchange a long-lived refresh token for a new short-lived access token without requiring user interaction.
4. **Device Code** (`GrantType::DeviceCode`): The OAuth 2.0 Device Authorization Grant (RFC 8628). Used for input-constrained devices like Smart TVs or CLI tools where the user authenticates on a secondary device (e.g., their smartphone).
5. **Token Exchange** (`GrantType::TokenExchange`): The OAuth 2.0 Token Exchange grant (RFC 8693). Allows a resource server to impersonate or delegate permissions by exchanging an incoming access token for a new token targeting a downstream service.

## Supported Algorithms & Scopes

It is important to distinguish between what the Authkestra framework *can* do and what you, the developer, *choose* to enable via your OP configuration.

### Signing Algorithms

Authkestra uses the underlying `jsonwebtoken` crate, which provides robust support for modern cryptographic signing algorithms (including `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `EdDSA`, etc.). 

However, when configuring your OP server, **you must choose an asymmetric algorithm** (like `RS256`). Authkestra intentionally rejects symmetric algorithms (like `HS256`) for OpenID Providers. This is a strict security requirement: Resource Servers and Relying Parties must be able to verify your tokens using public keys exposed at your `/jwks` endpoint without ever knowing your private signing secret.

### Scopes

Authkestra is entirely **scope-agnostic**. The framework does not hardcode what scopes mean. 

If you want to be OpenID Connect compliant, you simply add `"openid"`, `"profile"`, and `"email"` to your configuration. But you are completely free to invent custom scopes for your own APIs (e.g., `"billing:read"`, `"admin:write"`, `"devices:provision"`).

The relationship works like this:
1. **Global Capability**: You define all possible scopes your server understands in `OpConfig.scopes_supported`.
2. **Client Restriction**: When creating a `ClientRegistration` in your database, you give that client a subset of those scopes.
3. **User Delegation**: When a user logs in, the `/authorize` flow ensures the requested scopes do not exceed what the client is permitted to ask for.

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

## Custom Grant Types

Beyond the built-in grant types, Authkestra allows you to implement custom extension grants (e.g. for custom legacy flows, SSO tokens from third parties, etc).

To support a custom grant type:

1. Add it to your client's authorized grants using the `Custom(String)` variant:
   ```rust
   use authkestra_op::client::GrantType;

   client.grant_types = vec![GrantType::Custom("urn:my:custom:grant".to_string())];
   ```
2. Implement your own `OpStore` and override the `handle_custom_grant` method. By default, `handle_custom_grant` returns an `unsupported_grant_type` error, meaning it is safely backwards compatible for users leveraging `CompositeOpStore`.
   ```rust
   use authkestra_op::store::OpStore;
   use authkestra_op::handlers::token::{TokenRequest, TokenResponse, TokenErrorResponse};

   #[async_trait::async_trait]
   impl OpStore for MyCustomOpStore {
       // ... other store methods ...

       async fn handle_custom_grant(
           &self,
           grant_type: &str,
           req: TokenRequest,
           client_id: String,
           client: authkestra_op::client::ClientRegistration,
           config: &authkestra_op::config::OpConfig,
           tokens: &authkestra_engine::token::TokenManager,
       ) -> Result<TokenResponse, TokenErrorResponse> {
           if grant_type == "urn:my:custom:grant" {
               // Perform custom validation here...
               
               // Issue the token!
               let access_token = tokens.issue_client_token(&client_id, 3600, None, None).unwrap();
               return Ok(TokenResponse {
                   access_token,
                   token_type: "Bearer".to_string(),
                   expires_in: 3600,
                   refresh_token: None,
                   id_token: None,
                   scope: None,
               });
           }
           
           Err(TokenErrorResponse {
               error: "unsupported_grant_type".to_string(),
               error_description: "Unsupported custom grant".to_string(),
           })
       }
   }
   ```

Authkestra's token endpoint automatically intercepts any unknown grant type, checks if the client is authorized to use `GrantType::Custom(grant_type_string)`, and if so, safely forwards it to your `handle_custom_grant` implementation.

## Custom Claims

When building a full Identity Provider, you often need to attach domain-specific data to your tokens (e.g., `role`, `project_id`, or `billing_tier`). This aligns with custom claim mappers found in enterprise systems like Keycloak or Auth0.

Authkestra's core `TokenManager` natively supports injecting custom claims via the `*_with_extra` suite of methods. You simply provide a `HashMap<String, serde_json::Value>` containing your extra claims when minting tokens:

```rust
use std::collections::HashMap;
use serde_json::json;

let mut extra_claims = HashMap::new();
extra_claims.insert("org_id".to_string(), json!("org-123"));
extra_claims.insert("role".to_string(), json!("admin"));

// Issue an ID Token with standard claims AND your custom claims appended
let id_token = token_manager.issue_id_token_with_extra(
    identity,
    "client-1",
    Some("nonce123".to_string()),
    3600,
    extra_claims
)?;
```

*(Note: When calling `issue_id_token_with_extra`, an explicit `nonce` argument will always take precedence over a `"nonce"` key provided in the `extra_claims` map).*

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
