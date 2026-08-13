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
authkestra-op = "0.4.0"
authkestra-axum = { version = "0.4", features = ["op"] }
# Or if using Actix:
# authkestra-actix = { version = "0.4", features = ["op"] }
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

:::tip[Overriding Refresh Token Logic]
The `OpStore` interface allows overriding `handle_refresh_token` for custom refresh token rotation or revocation policies. When the `openid` scope is requested during the refresh flow, Authkestra automatically issues an updated `id_token` alongside the new access token.
:::

Check the [op_server.rs](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/op_server.rs) example in the repository for full database wiring code.

## Supported Grant Types

Authkestra's OP server natively supports the following OAuth 2.0 / OIDC grant types:

1. **Authorization Code** (`GrantType::AuthorizationCode`): The standard interactive OIDC login flow.
2. **Client Credentials** (`GrantType::ClientCredentials`): Server-to-server machine authentication.
3. **Refresh Token** (`GrantType::RefreshToken`): Allows clients to exchange a refresh token for new tokens (with automatic `id_token` issuance when `openid` scope is active).
4. **Device Code** (`GrantType::DeviceCode`): The OAuth 2.0 Device Authorization Grant (RFC 8628).
5. **Token Exchange** (`GrantType::TokenExchange`): The OAuth 2.0 Token Exchange grant (RFC 8693).

## Supported Algorithms & Scopes

### Signing Algorithms

Authkestra uses `jsonwebtoken` and `sha2`/`ed25519-dalek` to provide robust support for modern cryptographic signing algorithms:
- `RS256`, `RS384`, `RS512` (RSA)
- `ES256`, `ES384` (ECDSA)
- `EdDSA` / `Ed25519` (Octet Key Pair)

When configuring your OP server, **you must choose an asymmetric algorithm** (such as `RS256` or `EdDSA`). Authkestra intentionally rejects symmetric algorithms (`HS256`) for OP servers so Resource Servers can verify tokens via the public `/jwks` endpoint.

### Scopes

Authkestra is entirely **scope-agnostic**. To be OpenID Connect compliant, include `"openid"`, `"profile"`, and `"email"` in `OpConfig.scopes_supported`.

## Building the OP State

The behavior of your OpenID Provider is driven by `OpConfig`:

```rust
use authkestra_op::config::OpConfig;
use authkestra_op::Op;

let config = OpConfig {
    issuer: "http://localhost:3000".to_string(),
    scopes_supported: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
    response_types_supported: vec!["code".to_string()],
    grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
    id_token_signing_alg: "EdDSA".to_string(), // Supports RS256, ES256, EdDSA, etc.
};

let op = Op::builder()
    .engine(auth_engine)
    .config(config)
    .store(op_store)
    .build();
```

## Custom Grant Types

Beyond built-in grant types, Authkestra allows extension grants by adding `GrantType::Custom("urn:my:grant".into())` to client registrations and overriding `handle_custom_grant` on your `OpStore`.

## Wiring the OP Endpoints

Wire server routes using `op_axum_router()` or `op_actix_router()`:

```rust
use authkestra_axum::op::{OpExt, OpState};
use axum::Router;

let app = Router::new().merge(op.op_axum_router()).with_state(OpState(op));
```

Exposed endpoints:
1. **`GET /.well-known/openid-configuration`**: OIDC Discovery endpoint.
2. **`GET /jwks`**: Public key set (supports RSA, ECDSA, and Ed25519 / OKP keys).
3. **`GET /authorize`**: Authorization endpoint.
4. **`POST /token`**: Token exchange endpoint (code, refresh token, client credentials, etc.).
