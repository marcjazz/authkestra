//! Cached Issuer JWKS lookup (attestation trust needs `jwks.get(att.claims.iss, att.header.kid)`).
//!
//! ## Why this is a small hand-rolled cache instead of `authkestra_resource::jwt::JwksCache`
//!
//! The obvious move is to reuse `authkestra_resource::jwt::JwksCache` — it already exists, is
//! already depended on by `authkestra-oidc`, and this crate should not reimplement JWKS
//! fetching/rotation from scratch. Read against the real, current source
//! (`crates/authkestra-resource/src/jwt.rs`) rather than assumed, it turns out not to be a
//! drop-in fit here, for two independent reasons:
//!
//! 1. **It is a network-fetching cache with no seed/construct-from-memory path.**
//!    `JwksCache::new(jwks_uri, refresh_interval)` only ever populates itself by calling
//!    `Jwks::fetch(jwks_uri)` — a live `reqwest::get` — inside `refresh()`/`get_jwks()`. There is
//!    no constructor that accepts an in-memory key set. That is exactly right for the
//!    OAuth/OIDC resource-server case it was built for (a real Issuer is always reachable at a
//!    real URL), but this crate's test suite has no live Issuer (`authkestra-op`'s enrolment/
//!    attestation-minting side is tracked separately in authkestra#136) and mints test
//!    attestations directly — exercising the real cache in every test would mean standing up a
//!    mock HTTP server (`wiremock`, already a dev-dependency of `authkestra-resource` for exactly
//!    this reason) for each one.
//! 2. **It stores `authkestra_engine::token::jwk::Jwk`, which is hard-coded RSA-only** —
//!    `to_decoding_key()` explicitly errors on any non-RSA `kty`. That happens not to bite the
//!    attestation side specifically (the attestation is always RS256 per its wire format), but
//!    consuming it would still mean converting its `Jwk` type at the boundary for no benefit,
//!    and this crate needs `jsonwebtoken::jwk::Jwk` directly anyway for the *signature* side
//!    (the device key, which is EC — see `signature.rs` — and which that wrapper cannot
//!    represent at all).
//!
//! So: a minimal in-memory `(issuer, kid) -> Jwk` cache, populated via [`IssuerJwks::insert`].
//! A production integration wraps this with a periodic refresh task against each trusted
//! issuer's published JWKS endpoint — `authkestra_resource::jwt::Jwks::fetch` is a perfectly
//! reasonable way to do the HTTP part of that — and calls `insert` on every refresh. That
//! refresh loop is deliberately not implemented in this crate: it is integration plumbing, not
//! part of the verification algorithm, and belongs next to whatever task-spawning convention the
//! embedding application already uses (the framework integration in `axum_integration.rs` takes
//! an `Arc<IssuerJwks>` for exactly this reason — the caller owns the refresh lifecycle).

use std::collections::HashMap;

use jsonwebtoken::jwk::Jwk;
use tokio::sync::RwLock;

/// An in-memory cache of Issuer public keys, keyed by `(issuer, kid)`.
///
/// This is the "one cached public JWKS" that makes verification self-contained — no per-request
/// network call. It performs no network I/O itself; callers populate it via
/// [`IssuerJwks::insert`], however they choose to fetch and refresh keys.
#[derive(Default)]
pub struct IssuerJwks {
    keys: RwLock<HashMap<(String, String), Jwk>>,
}

impl IssuerJwks {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Registers (or replaces) the key published by `issuer` under `kid`.
    pub async fn insert(&self, issuer: impl Into<String>, kid: impl Into<String>, jwk: Jwk) {
        let mut keys = self.keys.write().await;
        keys.insert((issuer.into(), kid.into()), jwk);
    }

    /// Looks up the key published by `issuer` under `kid`. Returns `None` on a cache miss;
    /// callers map that to [`crate::VerifyError::UnknownKid`].
    pub async fn get(&self, issuer: &str, kid: &str) -> Option<Jwk> {
        let keys = self.keys.read().await;
        keys.get(&(issuer.to_string(), kid.to_string())).cloned()
    }
}
