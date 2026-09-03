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
authkestra-op = "0.7"
authkestra-axum = { version = "0.7", features = ["op"] }
# Or if using Actix:
# authkestra-actix = { version = "0.7", features = ["op"] }
```

## The OpStore Interface

To run an OP Server, you need to persist four specific types of records: Clients, Auth Codes, Refresh Tokens, and Device Codes. 

In Authkestra, this is handled through the unified `OpStore` supertrait. `OpStore` aggregates the four granular storage traits, and adds a handful of **defaulted** methods on top:

```rust
pub trait OpStore:
    ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
    // All defaulted — override only what you need.
    async fn record_client_assertion_jti(&self, jti: &str, expires_at: DateTime<Utc>)
        -> Result<bool, OpError>;      // RFC 7523 private_key_jwt replay guard
    async fn check_and_record_dpop_jti(&self, jti: &str, expires_at: DateTime<Utc>)
        -> Result<bool, OpError>;      // RFC 9449 DPoP proof replay guard
    async fn handle_custom_grant(/* ... */) -> Result<TokenResponse, TokenErrorResponse>;
    async fn handle_refresh_token(/* ... */) -> Result<TokenResponse, TokenErrorResponse>;
}
```

:::caution[The two replay guards default to *refusing*]
`record_client_assertion_jti` and `check_and_record_dpop_jti` are defaulted so that adding replay
tracking did not break every existing `OpStore` — but their defaults **reject every assertion and
every proof**. That is deliberate: a `private_key_jwt` or DPoP deployment without single-use `jti`
tracking would let a captured assertion or proof stay replayable for its whole lifetime, which is
strictly worse than not offering the feature. If you enable either mechanism you *must* wire a real
store, or every such request will be refused.
:::

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

`CompositeOpStore` carries two further, optional slots for the replay guards above — supply them
with `.with_client_assertion_store(...)` and `.with_dpop_replay_store(...)`. Left unset they resolve
to `NoClientAssertionStore` / `NoDpopReplayStore`, which are the fail-closed defaults described in
the caution box.

:::tip[Overriding Refresh Token Logic]
The `OpStore` interface allows overriding `handle_refresh_token` for custom refresh token rotation or revocation policies. When the `openid` scope is requested during the refresh flow, Authkestra automatically issues an updated `id_token` alongside the new access token.
:::

Check the [axum_op_server.rs](https://github.com/marcjazz/authkestra/blob/main/crates/authkestra/examples/axum_op_server.rs)
example in the repository for full database wiring code (`cargo run -p authkestra --example
axum_op_server --all-features`); `actix_op_server.rs` is the Actix counterpart.

## Supported Grant Types

Authkestra's OP server natively supports the following OAuth 2.0 / OIDC grant types:

1. **Authorization Code** (`GrantType::AuthorizationCode`): The standard interactive OIDC login flow.
2. **Client Credentials** (`GrantType::ClientCredentials`): Server-to-server machine authentication.
3. **Refresh Token** (`GrantType::RefreshToken`): Allows clients to exchange a refresh token for new tokens (with automatic `id_token` issuance when `openid` scope is active).
4. **Device Code** (`GrantType::DeviceCode`): The OAuth 2.0 Device Authorization Grant (RFC 8628).
5. **Token Exchange** (`GrantType::TokenExchange`): The OAuth 2.0 Token Exchange grant (RFC 8693). Gated behind `OpConfig.token_exchange_enabled`, which defaults to `false` so delegation endpoints are never exposed by accident.

## Supported Algorithms & Scopes

### Signing Algorithms

Authkestra uses `jsonwebtoken` and `sha2`/`ed25519-dalek` to provide robust support for modern cryptographic signing algorithms:
- `RS256`, `RS384`, `RS512` (RSA)
- `ES256`, `ES384` (ECDSA)
- `EdDSA` / `Ed25519` (Octet Key Pair)

When configuring your OP server, **you must choose an asymmetric algorithm** (such as `RS256` or `EdDSA`). Authkestra intentionally rejects symmetric algorithms (`HS256`) for OP servers so Resource Servers can verify tokens via the public `/jwks.json` endpoint.

### Scopes

Authkestra is entirely **scope-agnostic**. To be OpenID Connect compliant, include `"openid"`, `"profile"`, and `"email"` in `OpConfig.scopes_supported`.

## Building the OP State

The behavior of your OpenID Provider is driven by `OpConfig`:

```rust
use authkestra_op::config::OpConfig;
use authkestra_op::Op;

let config = OpConfig {
    // No trailing slash — the discovery/JWKS URLs are built by appending to this.
    issuer: "http://localhost:3000".to_string(),
    scopes_supported: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
    response_types_supported: vec!["code".to_string()],
    grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
    id_token_signing_alg: "EdDSA".to_string(), // Supports RS256, ES256, EdDSA, etc.
    authorization_code_ttl_secs: 60,           // RFC-003 §7 recommends ≤ 60
    access_token_ttl_secs: 3600,
    device_code_ttl_secs: 600,
    token_exchange_enabled: false,             // RFC 8693, off by default
};

let op = Op::builder()
    .engine(auth_engine)
    .config(config)
    // `.store()` takes `Arc<dyn OpStore>`, not a bare store — wrap it.
    .store(Arc::new(op_store))
    .build();
```

:::caution
`OpConfig` has no `Default` impl, so every field above is required. The four TTL/toggle fields
are easy to miss when copying an older snippet — a struct literal that omits them will not
compile.
:::

## Custom Grant Types

Beyond built-in grant types, Authkestra allows extension grants by adding `GrantType::Custom("urn:my:grant".into())` to client registrations and overriding `handle_custom_grant` on your `OpStore`.

## Wiring the OP Endpoints

Wire server routes using `op_axum_router()` (Axum) or `op_actix_scope()` (Actix-web):

```rust
use authkestra_axum::op::{OpExt, OpState};
use axum::Router;

let app = Router::new()
    .merge(op.op_axum_router())
    .with_state(OpState(op));
```

```rust
// Actix returns a `Scope`; `configure_op` registers the OP's pieces as app data.
use authkestra_actix::op::{OpActixExt, OpExt};

App::new()
    .configure(|cfg| { cfg.configure_op(op.clone()); })
    .service(op.op_actix_scope())
```

Exposed endpoints:
1. **`GET /.well-known/openid-configuration`**: OIDC Discovery endpoint.
2. **`GET /jwks.json`**: Public key set (supports RSA, ECDSA, and Ed25519 / OKP keys).
3. **`GET /authorize`**: Authorization endpoint.
4. **`POST /token`**: Token endpoint (code, refresh token, client credentials, device code, token exchange).
5. **`GET`/`POST /userinfo`**: UserInfo endpoint.
6. **`POST /device_authorization`**: Device Authorization Grant endpoint (RFC 8628).
7. **`POST /device/verify`**: Verification endpoint where the user submits their `user_code`.

The device/service attestation routes (`POST /enrol`, `POST /enrol/complete`, `POST /reissue`)
are deliberately **not** part of `op_axum_router()`. On Axum they live in a separate
`op_axum_attestation_router()`, so an application that only wants the standard OIDC surface is
not forced to supply attestation-specific dependencies just to compile:

```rust
let app = Router::new()
    .merge(op.op_axum_router())
    .merge(op.op_axum_attestation_router())
    .with_state(state);
```

On Actix, `op_actix_scope()` wires all of them together and resolves each attestation dependency
from `app_data`, leaving the optional `AttestationStatusProvider` as `None` when it is absent.

## Device/Service Attestation Issuance

Beyond the standard OIDC surface, `authkestra-op` can issue **device/service attestations**:
short-lived, `cnf.jkt`-bound JWS tokens that let a mobile device or a backend service prove
possession of a key it enrolled. This is the *issuing* side of device-bound signature
authentication; the verifying side is [`authkestra-devsig`](/providers/device-signatures/). A
step-by-step client walkthrough lives in the [Device Attestation guide](/guides/device-attestation/).

### The three routes

| Route | Purpose |
| --- | --- |
| `POST /enrol` | Validate the caller's public key and second factor, then issue a single-use proof-of-possession challenge. |
| `POST /enrol/complete` | Consume the challenge, verify the signature came from the enrolled key, compute `cnf.jkt` from that key (never from caller input), and mint the attestation. |
| `POST /reissue` | Silently renew a near-expiry attestation by re-proving possession of the same key. No second factor — continuity of the key stands in for it. |

### `AttestationConfig`

`AttestationConfig` is `#[non_exhaustive]`, so build it with `new()` (or `Default`) and adjust the
fields you care about — a struct literal will not compile from outside the crate. The defaults are
24h / 12h / 5min:

```rust
use authkestra_op::attestation::AttestationConfig;

let mut attestation_config = AttestationConfig::new();
attestation_config.attestation_ttl_secs = 86_400;           // how long an attestation is valid
attestation_config.attestation_reissue_after_secs = 43_200; // returned as `reissue_after`
attestation_config.challenge_ttl_secs = 300;                // a PoP nonce, not a session
```

### The two pluggable hooks

`authkestra-op` deliberately hardcodes neither a telecom integration nor an attribute/revocation
store, so the host application supplies both:

- **`SecondFactorVerifier`** (required to enrol) — verifies whatever `SecondFactorProof`
  (`{ kind, value }`, opaque to the OP) the caller submits at enrolment. An SMS/TOTP check for a
  device; an out-of-band admin approval or one-time bootstrap secret for a service principal,
  which has no phone to text. Any `Err` surfaces as `OpError::SecondFactorFailed`, so log your own
  specifics rather than leaking them into the response.

  ```rust
  #[async_trait::async_trait]
  impl SecondFactorVerifier for MyVerifier {
      async fn verify(
          &self,
          subject: &str,
          principal_type: PrincipalType,
          proof: &SecondFactorProof,
      ) -> Result<(), OpError> { /* ... */ }
  }
  ```

- **`AttestationStatusProvider`** (optional) — consulted at re-issuance. Return
  `Ok(Some(attributes))` to renew with (possibly updated) attributes, or `Ok(None)` to refuse a
  revoked principal, which fails with `OpError::PrincipalRevoked`. **If you do not configure one,
  re-issuance copies the previous attestation's attributes forward unchanged** — so an application
  that revokes devices out-of-band needs this hook, or a revoked device keeps renewing.

The challenge store is an `EnrolmentChallengeStore`, which has a blanket impl over any
`KvStore` + `AtomicConsume` backend — the same mechanism session and OP data already use, so
memory/Redis/SQL all work unchanged.

### Wiring

```rust
let op = Op::builder()
    .engine(engine)
    .config(op_config)
    .store(Arc::new(op_store))
    .challenge_store(Arc::new(MemoryStore::<EnrolmentChallenge>::new()))
    .second_factor_verifier(Arc::new(MyVerifier))
    .attestation_config(AttestationConfig::new())
    // .status_provider(Arc::new(MyStatusProvider)) // optional
    .build();

// Axum: a router separate from op_axum_router(), so an OIDC-only app never has to
// supply attestation dependencies just to compile.
let app: axum::Router<()> = op
    .op_axum_attestation_router()
    .with_state(authkestra_axum::op::OpState(op));
```

On Actix there is no split: `op_actix_scope()` wires the standard endpoints and the three
attestation routes together, resolving each dependency from `app_data`.

Runnable end-to-end versions (server plus a client that enrols and then re-issues, no external
services needed):

```bash
cargo run -p authkestra --example axum_op_server_attestation --features full
cargo run -p authkestra --example actix_op_server_attestation --features full
```
