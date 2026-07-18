# RFC-003: OpenID Provider (OP) Support

## 1. Summary

This RFC proposes adding OpenID Provider (OP) capability to Authkestra: the
ability for an application built on Authkestra to *issue* tokens and run the
authorization code grant, rather than only consuming an external IdP as a
relying party (RP). This is the feature that makes RFC-001's stated goal of
"standalone server deployment (similar to Keycloak)" concretely true.

## 2. Motivation

Today, `authkestra-oidc` and `authkestra-providers-*` only implement the RP
side: discovering an external provider's metadata, redirecting to its
`/authorize`, exchanging codes at its `/token`, and validating its JWKS.
There is no code anywhere in the workspace that *serves* those endpoints.

Without OP support, Authkestra can protect an application (resource server)
or log a user in via Google/GitHub/etc, but it cannot itself be the identity
source for other applications — e.g. a company wanting one login for
multiple internal services, or an app wanting to offer "Sign in with
<product>" to third parties. Adding OP support turns Authkestra from an
auth *client* toolkit into a full auth *platform*, matching the RFC-001
Layer 4 vision (Admin API, dashboard) which needs something to administer.

## 3. Non-goals

- Dynamic client registration (RFC 7591) — clients are registered out of
  band (config, DB migration, or future admin API) for the first version.
- A consent screen UI — the authorize handler exposes a hook/callback for
  the host application to render consent; Authkestra does not ship UI.
- GNAP — tracked separately per the roadmap; this RFC is OAuth 2.1/OIDC
  Core only.

## 4. Prerequisite: asymmetric token signing

`TokenManager` (in `authkestra-engine/src/token/mod.rs`) currently signs
exclusively with `Algorithm::HS256` over a symmetric secret
(`EncodingKey::from_secret`). This is appropriate when the same process (or
a set of processes that share the secret out of band) both issues and
validates tokens — the current resource-server use case.

It does not work for an OP: external relying parties must be able to verify
an ID token's signature *without* knowing your signing secret, via a
published public key (the JWKS endpoint). This requires:

- `TokenService`/`TokenManager` gaining an asymmetric mode (`RS256` to
  start — reuses the existing `jsonwebtoken` dependency and matches what
  `authkestra-resource`'s `Jwk::to_decoding_key` already expects on the
  *consuming* side, since it currently only supports RSA components).
- A `kid` (key ID) on issued tokens' JWT header so the JWKS endpoint can
  publish multiple keys during rotation and clients can select the right
  one.
- Key rotation is out of scope for the first version but the `kid` field
  must exist from the start — retrofitting it later is a breaking change
  to every issued token.

This is scoped as its own PR (`OP.0a`) landing before `OP.2` (JWKS
endpoint), since the JWKS endpoint has nothing meaningful to publish
otherwise.

## 5. Target architecture

New crate: **`authkestra-op`** (Layer 2: Extensions, alongside
`authkestra-oidc`, `authkestra-session-*`). Kept separate from
`authkestra-oidc` because that crate's identity is "RP that consumes an
external OP" — merging OP logic in would make `Provider` and `OidcProvider`
ambiguous (yours vs. someone else's).

```
authkestra-op/
├── src/
│   ├── lib.rs
│   ├── client.rs        # ClientRegistration, ClientStore trait
│   ├── code.rs           # AuthorizationCode, AuthorizationCodeStore trait
│   ├── config.rs         # OpConfig (issuer, supported scopes/response types)
│   └── handlers/          # framework-agnostic handler *logic*, returns
│                           # plain structs/Results — adapters wrap these
│       ├── discovery.rs   # GET /.well-known/openid-configuration
│       ├── jwks.rs        # GET /jwks.json
│       ├── authorize.rs   # GET /authorize
│       ├── token.rs       # POST /token
│       └── userinfo.rs    # GET /userinfo
```

`authkestra-axum` and `authkestra-actix` each get a new `op` feature flag
exposing a router/scope that wires the framework-agnostic handler logic to
each framework's request/response types — mirroring how `guard`/`session`/
`flow` are already feature-gated today.

## 6. Core types (sketch)

```rust
/// A registered OAuth2/OIDC client application.
pub struct ClientRegistration {
    pub client_id: String,
    pub client_secret_hash: String, // never store plaintext
    pub redirect_uris: Vec<String>, // exact-match only; no wildcard/prefix matching
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
}

/// An issued authorization code, pending exchange at /token.
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,     // PKCE, mandatory for public clients
    pub code_challenge_method: Option<String>,
    pub identity: Identity,                 // re-uses authkestra_engine::Identity
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used: bool,                         // single-use enforcement
}

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError>;
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError>;
    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError>;
    // consume_code MUST be atomic (check `used`, mark used, return) to prevent
    // code-replay races — this is the single highest-value correctness
    // property in the whole OP and should have a dedicated test.
}
```

Both traits mirror the existing `SessionStore` pattern (async trait,
pluggable backends, in-memory implementation ships first).

## 7. Security notes (non-exhaustive, expand during implementation)

- `redirect_uri` at `/authorize` and `/token` must be validated by **exact
  string match** against the client's registered URIs — no partial or
  prefix matching. This is the single most common OAuth implementation bug
  (open redirect).
- PKCE (`code_challenge`/`code_verifier`) is mandatory for public clients
  and recommended for all clients, per OAuth 2.1.
- Authorization codes are single-use and short-lived (recommend ≤60s); the
  `AuthorizationCodeStore::consume_code` atomicity requirement above exists
  specifically to prevent replay.
- Client secrets are never stored or logged in plaintext — hash at
  registration time, compare hashes at `/token`.

## 8. Migration impact

- `authkestra-engine`: `TokenService`/`TokenManager` gain asymmetric signing
  (prerequisite, `OP.0a`).
- `authkestra-resource`: `Jwk` struct gains `Serialize` (today it's
  `Deserialize`-only, built for consuming someone else's JWKS) so `OP.2` can
  reuse it to publish rather than duplicating the type.
- New crate `authkestra-op`.
- `authkestra-axum`, `authkestra-actix`: new `op` feature flag.

## 9. Timeline (see companion PR plan for full sequencing)

- **OP.0a**: Asymmetric (RS256) signing in `TokenService`, with `kid`.
- **OP.0 / OP.1**: Crate skeleton + `ClientStore`/`AuthorizationCodeStore`
  traits + in-memory impls.
- **OP.2**: Discovery + JWKS endpoints (lowest risk, no user input).
- **OP.3 / OP.4**: `/authorize` and `/token` (authorization code + PKCE).
- **OP.5**: `/userinfo`.
- **OP.6**: Axum/Actix adapter wiring + examples.
- **OP.7** (follow-up): client_credentials/refresh_token grants at `/token`.
