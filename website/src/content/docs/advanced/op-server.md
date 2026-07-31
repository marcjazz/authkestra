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
authkestra-op = "0.2.3"
authkestra-axum = { version = "0.2.5", features = ["op"] }
# Or if using Actix:
# authkestra-actix = { version = "0.2.5", features = ["op"] }
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
> **Implementing Custom Stores:** If you build your own combined store type (e.g. `struct MyCustomStore { ... }`), you must explicitly implement the `OpStore` trait for it (`impl OpStore for MyCustomStore {}`). This is a minor breaking change from `0.2.3` where a blanket implementation was provided, which was removed to allow for overriding the `handle_custom_grant` method.

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

## Building the OP State

The behavior of your OpenID Provider is entirely driven by `OpConfig`. When building the state, you must configure this struct to declare what your server supports.

```rust
use authkestra_op::config::OpConfig;
use authkestra_op::Op;

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
    
    // Endpoint locations
    authorization_endpoint: "http://localhost:3000/authorize".to_string(),
    token_endpoint: "http://localhost:3000/token".to_string(),
    userinfo_endpoint: "http://localhost:3000/userinfo".to_string(),
    jwks_uri: "http://localhost:3000/jwks.json".to_string(),
};

let op = Op::builder()
    .engine(auth_engine) // Assumes an Engine with SessionStore and TokenManager
    .config(config)
    .store(op_store)
    .build();
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

## Device/Service Attestation Issuance

Beyond issuing OIDC tokens to a browser-based Relying Party, `authkestra-op` can also act as the **Issuer** in a device-bound-signature authentication scheme: it mints short-lived **attestations** — JWS tokens carrying a `cnf.jkt` claim (the SHA-256 thumbprint of a JWK) bound to a public key that a device or backend service generated locally and never shares. An attestation alone proves nothing; a verifier must additionally see a per-request signature made with the corresponding private key. This is the Issuer-side counterpart to `authkestra-devsig`'s request verification (see the mdBook chapter on adapters for that side).

Attestations are deliberately **short-lived** rather than the long-lived, hard-to-revoke tokens common to plain bearer auth: a compromised or revoked device's exposure window is bounded by `attestation_ttl_secs`, not by however long a refresh token happens to live. Renewal is silent — the caller re-proves possession of the same key well before expiry (recommended at `attestation_reissue_after_secs`), so there is no user-facing re-login and no second factor required beyond continuity of the key itself.

The ceremony is three HTTP calls (see the updated endpoint list below):

1. The caller generates an asymmetric keypair locally (EC P-256, ideally hardware-backed — Secure Enclave / StrongBox / Keystore) and calls `POST /enrol` with its public JWK and a second-factor proof (SMS/TOTP for a device; an out-of-band admin approval or bootstrap secret for a service principal). The OP verifies the factor and returns a single-use challenge.
2. The caller signs the challenge with its private key and calls `POST /enrol/complete`. The OP verifies the signature, computes `cnf.jkt` from the *enrolled* key (never from client input), and mints the attestation.
3. Before the attestation expires, the caller silently re-proves possession via `POST /reissue`, which itself returns a fresh challenge to complete through the same `/enrol/complete` endpoint — no second factor needed, since continuity of the key stands in for it.

Configure the ceremony with `AttestationConfig`, and implement a `SecondFactorVerifier` (mandatory) plus, optionally, an `AttestationStatusProvider` that can refuse re-issuance for a revoked principal or refresh its attributes:

```rust
use async_trait::async_trait;
use authkestra_op::attestation::{
    AttestationConfig, PrincipalType, SecondFactorProof, SecondFactorVerifier,
};
use authkestra_op::OpError;

let attestation_config = AttestationConfig {
    attestation_ttl_secs: 86_400,           // 24h attestation lifetime
    attestation_reissue_after_secs: 43_200, // recommend silent renewal at 12h
    challenge_ttl_secs: 300,                // 5 minutes to complete a challenge
};

struct SmsOrBootstrapVerifier;

#[async_trait]
impl SecondFactorVerifier for SmsOrBootstrapVerifier {
    async fn verify(
        &self,
        subject: &str,
        principal_type: PrincipalType,
        proof: &SecondFactorProof,
    ) -> Result<(), OpError> {
        // Verify `proof.value` against whatever second factor fits
        // `principal_type` — an SMS/TOTP code for a device, or an
        // out-of-band approval / one-time bootstrap secret for a service.
        // `authkestra-op` treats `proof` as opaque and never interprets it
        // itself.
        todo!()
    }
}
```

The three routes are wired through a router split from the standard OIDC surface, so an application that only wants plain OIDC never has to supply attestation-specific dependencies just to keep compiling:

```rust
use authkestra_axum::op::{OpExt, OpState};
use axum::Router;

let app = Router::new()
    .merge(op.op_axum_router())              // /authorize, /token, /userinfo, ...
    .merge(op.op_axum_attestation_router())  // /enrol, /enrol/complete, /reissue
    .with_state(OpState(op));
```

Actix wires the same three routes via `OpExt::op_actix_scope()`, resolving `EnrolmentChallengeStore`, `SecondFactorVerifier`, `TokenManager`, and `AttestationConfig` from `app_data` the same way the rest of the OP server's dependencies are resolved.

See `crates/authkestra/examples/axum/op_server_attestation.rs` and `crates/authkestra/examples/actix/op_server_attestation.rs` in the repository for a runnable, end-to-end walkthrough of enrolment and re-issuance (no external services required — the challenge store is an in-memory `MemoryStore`), or the step-by-step [Device Attestation guide](/guides/device-attestation/) for a narrated version of the same flow.

## Wiring the OP Endpoints

Once your stores and config are built, you wire the server routes using `op_axum_router()` (or `op_actix_router()`).

```rust
use authkestra_axum::op::{OpExt, OpState};
use axum::Router;

// `op_axum_router()` automatically wires standard OIDC server endpoints!
let app = Router::new().merge(op.op_axum_router()).with_state(OpState(op));
```

### What Endpoints are Exposed?

Unlike a standard OAuth client router, `op_axum_router()` exposes the endpoints that *other* applications will call to authenticate against you:

1. **`GET /.well-known/openid-configuration`**: The OIDC Discovery endpoint. Relying Parties fetch this to discover your supported scopes and keys.
2. **`GET /jwks`**: Exposes the public keys used to sign your JWTs so Resource Servers can validate them.
3. **`GET /authorize`**: The endpoint users are redirected to when they want to log in.
4. **`POST /token`**: The endpoint clients call to exchange an authorization code or refresh token for a new Access/ID Token.

If you also merge `op_axum_attestation_router()` (or wire `op_actix_scope()`), three more endpoints are exposed for the device/service attestation ceremony described above:

5. **`POST /enrol`**: Validates the caller's public key and second factor, and issues a single-use proof-of-possession challenge.
6. **`POST /enrol/complete`**: Consumes the challenge, verifies the signature was produced by the enrolled key, and mints the attestation.
7. **`POST /reissue`**: Silently renews a near-expiry attestation by re-proving possession of the same key.
