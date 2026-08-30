use async_trait::async_trait;
use authkestra_engine::{
    error::AuthError,
    strategy::{utils, AuthenticationStrategy},
    token::{
        cert_binding::{constant_time_eq, x5t_s256_thumbprint, ClientCertificateDer},
        Claims,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::request::Parts;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during offline validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Key not found in JWKS")]
    KeyNotFound,
    #[error(
        "Token is missing a 'kid' header, which is required by this JWKS cache's strict validation policy"
    )]
    MissingKid,
    #[error("Token issuer {0:?} is not in the configured trust map; no JWKS is trusted for it")]
    UntrustedIssuer(String),
    #[error(
        "Token carries no string 'iss' claim, which is required to resolve a signing key when more than one issuer is trusted"
    )]
    MissingIssuer,
    #[error("PASETO error: {0}")]
    Paseto(String),
    #[error("Discovery error: {0}")]
    Discovery(#[from] AuthError),
    #[error("Validation error: {0}")]
    Validation(String),
}

pub use authkestra_engine::token::jwk::Jwk;

#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub async fn fetch(jwks_uri: &str) -> Result<Self, ValidationError> {
        let client = reqwest::Client::new();
        let jwks = client.get(jwks_uri).send().await?.json::<Jwks>().await?;
        Ok(jwks)
    }

    pub fn find_key(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(id) => self.keys.iter().find(|k| k.kid.as_deref() == Some(id)),
            None => self.keys.first(),
        }
    }
}

#[non_exhaustive]
pub struct JwksCache {
    jwks_uri: String,
    jwks: RwLock<Option<(Jwks, Instant)>>,
    ttl: Duration,
    require_kid: bool,
}

impl JwksCache {
    pub fn new(jwks_uri: String, refresh_interval: Duration) -> Self {
        Self {
            jwks_uri,
            jwks: RwLock::new(None),
            ttl: refresh_interval,
            require_kid: false,
        }
    }

    /// When set to `true`, tokens presented without a `kid` header will be rejected
    /// with [`ValidationError::MissingKid`] instead of silently falling back to the
    /// first key in the JWKS. This guards against key-confusion when the JWKS holds
    /// more than one key (e.g. during rotation).
    ///
    /// Defaults to `false` to preserve today's permissive fallback behavior.
    pub fn require_kid(mut self, value: bool) -> Self {
        self.require_kid = value;
        self
    }

    pub async fn get_jwks(&self) -> Result<Jwks, ValidationError> {
        {
            let read_guard = self.jwks.read().await;
            if let Some((jwks, last_updated)) = read_guard.as_ref() {
                if last_updated.elapsed() < self.ttl {
                    return Ok(jwks.clone());
                }
            }
        }

        self.refresh().await
    }

    pub async fn get_key(&self, kid: Option<&str>) -> Result<Option<Jwk>, ValidationError> {
        if kid.is_none() && self.require_kid {
            return Err(ValidationError::MissingKid);
        }

        let jwks = self.get_jwks().await?;
        if let Some(key) = jwks.find_key(kid) {
            return Ok(Some(key.clone()));
        }

        // If key not found, try refreshing once in case of rotation
        let jwks = self.refresh().await?;
        Ok(jwks.find_key(kid).cloned())
    }

    pub async fn refresh(&self) -> Result<Jwks, ValidationError> {
        let mut write_guard = self.jwks.write().await;
        let jwks = Jwks::fetch(&self.jwks_uri).await?;
        *write_guard = Some((jwks.clone(), Instant::now()));
        Ok(jwks)
    }
}

/// Resolves *which* JWKS a token must be verified against, from the token's own
/// `iss` claim.
///
/// This is the seam that lets one resource server trust several issuers (issue
/// #243). `JwtStrategy` uses a built-in implementation for the two configured
/// shapes — [`SingleJwksResolver`] for the classic one-issuer/one-JWKS setup and
/// [`IssuerTrustMap`] for a fixed set of issuers — and
/// [`JwtStrategy::with_resolver`] accepts any other implementation, which is
/// what issuers discovered at runtime (per-tenant, from a registry) need.
///
/// # Security contract for implementors
///
/// An implementation MUST return an error for an issuer it does not recognise.
/// It must **never** fall back to some default JWKS for an unknown `iss`: that
/// turns multi-issuer support into issuer confusion, because any issuer whose
/// keys the fallback endpoint publishes could then mint tokens claiming to come
/// from any other issuer.
///
/// Returning `Arc<JwksCache>` rather than a borrow is deliberate: a dynamic
/// resolver needs to hand out caches it created and stored behind its own lock,
/// which it cannot do by reference.
#[async_trait]
pub trait JwksResolver: Send + Sync {
    /// Resolve the JWKS cache for `issuer`, the token's *not yet verified* `iss`
    /// claim (`None` when the token carries no usable string `iss`).
    async fn resolve(&self, issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError>;
}

/// A [`JwksResolver`] that always resolves to a single JWKS, whatever the token
/// claims as its `iss`.
///
/// This is the pre-#243 behaviour and what `JwtStrategy::new` uses when no trust
/// map is configured: enforcing `iss` (if configured at all) is left entirely to
/// `Validation::set_issuer`, exactly as before. It is only safe *because* there
/// is one endpoint and therefore nothing to confuse — do not reuse it as the
/// default arm of a multi-issuer resolver.
#[non_exhaustive]
pub struct SingleJwksResolver {
    cache: Arc<JwksCache>,
}

impl SingleJwksResolver {
    /// Wrap an existing cache as a resolver.
    pub fn new(cache: Arc<JwksCache>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl JwksResolver for SingleJwksResolver {
    async fn resolve(&self, _issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError> {
        Ok(self.cache.clone())
    }
}

/// A fixed trust map of `iss` -> [`JwksCache`], for a resource server that
/// accepts tokens from a known set of issuers.
///
/// Lookup is exact-match on the `iss` string and has **no default arm**: an
/// unknown issuer yields [`ValidationError::UntrustedIssuer`] and a token with
/// no `iss` yields [`ValidationError::MissingIssuer`]. Each issuer keeps its own
/// cache, so JWKS fetching, TTL and rotation-triggered refresh stay per-endpoint
/// while remaining managed by this crate rather than duplicated by the caller.
///
/// A `BTreeMap` (rather than a `HashMap`) is used so the derived accepted-issuer
/// list handed to `Validation::set_issuer` — and anything logged from it — has a
/// stable order, which keeps failures reproducible.
#[derive(Default)]
#[non_exhaustive]
pub struct IssuerTrustMap {
    caches: BTreeMap<String, Arc<JwksCache>>,
}

impl IssuerTrustMap {
    /// Create an empty trust map. An empty map trusts nobody and rejects every
    /// token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `issuer`, verifying its tokens against `cache`.
    pub fn with_issuer(mut self, issuer: impl Into<String>, cache: Arc<JwksCache>) -> Self {
        self.caches.insert(issuer.into(), cache);
        self
    }

    /// The issuers this map trusts, in sorted order.
    pub fn issuers(&self) -> impl Iterator<Item = &str> {
        self.caches.keys().map(String::as_str)
    }
}

impl FromIterator<(String, Arc<JwksCache>)> for IssuerTrustMap {
    fn from_iter<T: IntoIterator<Item = (String, Arc<JwksCache>)>>(iter: T) -> Self {
        Self {
            caches: iter.into_iter().collect(),
        }
    }
}

#[async_trait]
impl JwksResolver for IssuerTrustMap {
    async fn resolve(&self, issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError> {
        let Some(issuer) = issuer else {
            tracing::warn!("rejecting token with no 'iss' claim: cannot select a signing key");
            return Err(ValidationError::MissingIssuer);
        };

        match self.caches.get(issuer) {
            Some(cache) => {
                tracing::debug!(issuer, "resolved JWKS for token issuer");
                Ok(cache.clone())
            }
            None => {
                // Deliberately no fallback: see the `JwksResolver` security contract.
                tracing::warn!(issuer, "rejecting token from an issuer that is not trusted");
                Err(ValidationError::UntrustedIssuer(issuer.to_string()))
            }
        }
    }
}

/// Configuration for JWT validation.
///
/// Construct this via [`ValidationConfig::builder`]. The type is
/// `#[non_exhaustive]` so that adding a validation knob is a non-breaking
/// change: `jwks_url` has no meaningful default (the builder panics if it is
/// unset), so there is deliberately no `Default` impl to spread from, which
/// left struct-literal construction as the only alternative to the builder —
/// and that made every new field a downstream compile error. `require_kid`
/// (PR #110) and `require_cert_binding` (PR #231, issue #224) were both added
/// that way already; see issue #247. Fields stay `pub` for reading and for
/// post-build mutation.
#[non_exhaustive]
pub struct ValidationConfig {
    pub jwks_url: String,
    pub refresh_interval: Duration,
    pub issuer: Option<String>,
    pub audience: Vec<String>,
    pub algorithms: Vec<Algorithm>,
    pub require_kid: bool,
    /// When `true`, enforce RFC 8705 §3.1 certificate binding: a token
    /// carrying a `cnf.x5t#S256` claim is only accepted if the same
    /// certificate (by SHA-256 thumbprint) was presented on the connection
    /// used to redeem it, and is rejected outright if no certificate was
    /// presented at all. Off by default for backward compatibility — with
    /// this `false`, a certificate-bound token is still accepted as a plain
    /// bearer token, same as before this option existed. See
    /// [`JwtStrategy`] and issue #224.
    pub require_cert_binding: bool,
    /// When `true`, enforce RFC 9449 DPoP key binding: a token carrying a
    /// `cnf.jkt` claim is only accepted if the request presents a `DPoP`
    /// header whose proof verifies for the same key, binds (`ath`) to
    /// *this* access token, and hasn't been seen before (tracked via
    /// [`JwtStrategy::with_dpop_replay_store`]). Off by default for
    /// backward compatibility — with this `false`, a DPoP-bound token is
    /// still accepted as a plain bearer token, same as before this option
    /// existed. Mirrors [`ValidationConfig::require_cert_binding`]'s
    /// design exactly: a token that carries *no* `cnf.jkt` at all is not
    /// DPoP-bound and this check is a no-op for it, regardless of this
    /// setting. See [`JwtStrategy`] and issue #274.
    ///
    /// Deliberately does **not** check `htm`/`htu`: unlike an authorization
    /// server's single, statically-known `/token` endpoint, a resource
    /// server protects many routes and commonly sits behind a reverse
    /// proxy or load balancer, where the exact absolute URL a client used
    /// isn't always reliably reconstructible from the request alone. Key
    /// binding, `ath`, and `jti` replay tracking together still mean a
    /// captured proof cannot be reused for a different token, or reused at
    /// all — see `authkestra_engine::token::dpop::verify_dpop_proof`'s doc
    /// comment on its `expected_htu: None` case for the full reasoning.
    pub require_dpop: bool,
    /// Trust map of `iss` -> JWKS endpoint, for a resource server that accepts
    /// tokens from several issuers. Empty by default, which keeps the
    /// single-issuer `jwks_url` path unchanged. When non-empty, an `iss` absent
    /// from this map is rejected outright and never falls back to `jwks_url`.
    /// See [`IssuerTrustMap`] and issue #243.
    pub trusted_issuers: BTreeMap<String, String>,
}

impl ValidationConfig {
    /// Create a new builder for `ValidationConfig`.
    pub fn builder() -> ValidationConfigBuilder {
        ValidationConfigBuilder::default()
    }
}

/// A builder for configuring JWT validation.
#[derive(Default)]
#[non_exhaustive]
pub struct ValidationConfigBuilder {
    jwks_url: Option<String>,
    refresh_interval: Option<Duration>,
    issuer: Option<String>,
    audience: Vec<String>,
    algorithms: Vec<Algorithm>,
    require_kid: bool,
    require_cert_binding: bool,
    require_dpop: bool,
    trusted_issuers: BTreeMap<String, String>,
}

impl ValidationConfigBuilder {
    /// Set the JWKS URL.
    ///
    /// Required unless at least one [`trusted_issuer`](Self::trusted_issuer) is
    /// configured, in which case each issuer brings its own endpoint and this
    /// one applies only to the issuer named by [`issuer`](Self::issuer).
    pub fn jwks_url(mut self, jwks_url: impl Into<String>) -> Self {
        self.jwks_url = Some(jwks_url.into());
        self
    }

    /// Set the refresh interval for the JWKS cache.
    pub fn refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = Some(interval);
        self
    }

    /// Set the expected issuer for the single JWKS set with
    /// [`jwks_url`](Self::jwks_url).
    ///
    /// This is the one-issuer form and is unchanged. Combined with
    /// [`trusted_issuer`](Self::trusted_issuer) entries it simply becomes one
    /// more entry of the trust map (`issuer` -> `jwks_url`).
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Trust `issuer` and verify its tokens against the JWKS published at
    /// `jwks_url`. May be called several times to trust several issuers; a
    /// repeated issuer replaces its previous endpoint.
    ///
    /// Once any entry is present the verifier is in multi-issuer mode: the
    /// token's `iss` claim selects the JWKS, an `iss` outside this map is
    /// rejected with [`ValidationError::UntrustedIssuer`], and a token with no
    /// `iss` at all is rejected with [`ValidationError::MissingIssuer`]. There
    /// is deliberately no fallback endpoint — see [`JwksResolver`].
    pub fn trusted_issuer(
        mut self,
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> Self {
        self.trusted_issuers.insert(issuer.into(), jwks_url.into());
        self
    }

    /// Trust several `(issuer, jwks_url)` pairs at once. Equivalent to calling
    /// [`trusted_issuer`](Self::trusted_issuer) for each pair.
    pub fn trusted_issuers(
        mut self,
        entries: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.trusted_issuers.extend(
            entries
                .into_iter()
                .map(|(issuer, url)| (issuer.into(), url.into())),
        );
        self
    }

    /// Add an expected audience. May be called multiple times to accept tokens scoped to
    /// any one of several audiences. Kept for backward compatibility with single-audience
    /// configuration; prefer [`ValidationConfigBuilder::audiences`] when adding more than one.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience.push(audience.into());
        self
    }

    /// Add multiple expected audiences at once. A token is accepted if its `aud` claim
    /// matches ANY of the configured audiences (e.g. a token valid for both a web app and
    /// a mobile client, or a gateway service that accepts several downstream audiences).
    pub fn audiences(mut self, audiences: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.audience.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Set the allowed algorithms.
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// When `true`, reject tokens that omit a `kid` header instead of silently falling back
    /// to the first key in the JWKS. Off by default for backward compatibility. See
    /// [`JwksCache::require_kid`].
    pub fn require_kid(mut self, value: bool) -> Self {
        self.require_kid = value;
        self
    }

    /// When `true`, enforce RFC 8705 §3.1 certificate binding. See
    /// [`ValidationConfig::require_cert_binding`]. Off by default.
    pub fn require_cert_binding(mut self, value: bool) -> Self {
        self.require_cert_binding = value;
        self
    }

    /// When `true`, enforce RFC 9449 DPoP key binding. See
    /// [`ValidationConfig::require_dpop`]. Off by default. A deployment
    /// enabling this should also call
    /// [`JwtStrategy::with_dpop_replay_store`] — without one, the
    /// fail-closed [`crate::dpop::NoDpopReplayStore`] default refuses every
    /// DPoP-bound token outright.
    pub fn require_dpop(mut self, value: bool) -> Self {
        self.require_dpop = value;
        self
    }

    /// Build a `ValidationConfig`.
    ///
    /// # Panics
    ///
    /// Panics if neither a [`jwks_url`](Self::jwks_url) nor any
    /// [`trusted_issuer`](Self::trusted_issuer) was set, since there would then
    /// be no key material at all. A trust-map-only config leaves `jwks_url`
    /// empty; an empty `jwks_url` is never fetched from, it just means "no
    /// single-issuer endpoint".
    pub fn build(self) -> ValidationConfig {
        let jwks_url = match self.jwks_url {
            Some(jwks_url) => jwks_url,
            None => {
                assert!(
                    !self.trusted_issuers.is_empty(),
                    "JWKS URL must be set for ValidationConfig (or at least one trusted_issuer)"
                );
                String::new()
            }
        };

        ValidationConfig {
            jwks_url,
            refresh_interval: self
                .refresh_interval
                .unwrap_or_else(|| Duration::from_secs(3600)),
            issuer: self.issuer,
            audience: self.audience,
            algorithms: if self.algorithms.is_empty() {
                vec![Algorithm::RS256]
            } else {
                self.algorithms
            },
            require_kid: self.require_kid,
            require_cert_binding: self.require_cert_binding,
            require_dpop: self.require_dpop,
            trusted_issuers: self.trusted_issuers,
        }
    }
}

/// A JWT authentication strategy that performs offline JWT validation using JWKS.
#[non_exhaustive]
pub struct JwtStrategy<I> {
    resolver: Box<dyn JwksResolver>,
    validation: Validation,
    require_cert_binding: bool,
    require_dpop: bool,
    dpop_replay_store: Arc<dyn crate::dpop::DpopReplayStore>,
    _marker: std::marker::PhantomData<I>,
}

impl<I> JwtStrategy<I> {
    /// Create a new `JwtStrategy` with the given `ValidationConfig`.
    ///
    /// With an empty [`ValidationConfig::trusted_issuers`] this is the classic
    /// single-issuer verifier and behaves exactly as it did before #243: one
    /// JWKS at `jwks_url`, and `iss` checked only if `issuer` was set.
    ///
    /// With a non-empty trust map it becomes a multi-issuer verifier — see
    /// [`ValidationConfigBuilder::trusted_issuer`].
    pub fn new(config: ValidationConfig) -> Self {
        let resolver = build_resolver(&config);
        Self {
            resolver,
            validation: build_validation(&config, !config.trusted_issuers.is_empty()),
            require_cert_binding: config.require_cert_binding,
            require_dpop: config.require_dpop,
            dpop_replay_store: Arc::new(crate::dpop::NoDpopReplayStore),
            _marker: std::marker::PhantomData,
        }
    }

    /// Create a `JwtStrategy` that resolves signing keys through a
    /// caller-supplied [`JwksResolver`], for issuers that are not known up front
    /// (per-tenant, fetched from a registry, ...).
    ///
    /// `config`'s `jwks_url` and `trusted_issuers` are ignored — the resolver
    /// owns key resolution entirely — but the rest of the config still applies,
    /// including the accepted-`iss` set fed to `Validation`. Note that if
    /// `config` names no issuers at all, `iss` is not checked by `Validation`
    /// and the resolver alone is the trust decision, so it must reject unknown
    /// issuers rather than defaulting.
    pub fn with_resolver(config: ValidationConfig, resolver: Box<dyn JwksResolver>) -> Self {
        Self {
            resolver,
            // Unconditionally multi-issuer: supplying your own resolver *is* the
            // multi-issuer case, whether or not a static trust map accompanies it.
            validation: build_validation(&config, true),
            require_cert_binding: config.require_cert_binding,
            require_dpop: config.require_dpop,
            dpop_replay_store: Arc::new(crate::dpop::NoDpopReplayStore),
            _marker: std::marker::PhantomData,
        }
    }

    /// Supplies the [`crate::dpop::DpopReplayStore`] this strategy checks
    /// DPoP proof `jti`s against, replacing the fail-closed
    /// [`crate::dpop::NoDpopReplayStore`] default.
    ///
    /// Only meaningful alongside [`ValidationConfig::require_dpop`] — without
    /// it, no token ever reaches the DPoP check this store backs, so a
    /// deployment that calls this but not `require_dpop` sees no effect.
    pub fn with_dpop_replay_store(mut self, store: Arc<dyn crate::dpop::DpopReplayStore>) -> Self {
        self.dpop_replay_store = store;
        self
    }
}

/// Builds the key-resolution half of a [`JwtStrategy`] from a config.
///
/// The two shapes are kept apart on purpose: with no trust map the resolver is
/// the identity-like [`SingleJwksResolver`], so the pre-#243 path keeps byte-for-byte
/// the same behaviour (including "no `iss` configured" meaning "`iss` not checked").
fn build_resolver(config: &ValidationConfig) -> Box<dyn JwksResolver> {
    let cache_for = |jwks_url: &str| {
        Arc::new(
            JwksCache::new(jwks_url.to_string(), config.refresh_interval)
                .require_kid(config.require_kid),
        )
    };

    if config.trusted_issuers.is_empty() {
        return Box::new(SingleJwksResolver::new(cache_for(&config.jwks_url)));
    }

    let mut caches: BTreeMap<String, Arc<JwksCache>> = config
        .trusted_issuers
        .iter()
        .map(|(issuer, jwks_url)| (issuer.clone(), cache_for(jwks_url)))
        .collect();

    // The single-issuer pair is folded in as one more trust-map entry, which is
    // what makes `issuer` + `jwks_url` "the one-entry case" rather than a second,
    // parallel mechanism. Without an `issuer` to name it, a `jwks_url` cannot be
    // folded in at all: using it as a default arm is exactly the issuer confusion
    // the trust map exists to prevent, so it is dropped loudly instead.
    match &config.issuer {
        Some(issuer) if !config.jwks_url.is_empty() => {
            caches
                .entry(issuer.clone())
                .or_insert_with(|| cache_for(&config.jwks_url));
        }
        None if !config.jwks_url.is_empty() => {
            tracing::warn!(
                jwks_url = %config.jwks_url,
                "ignoring jwks_url: with a trusted_issuers map configured and no issuer naming it, \
                 it could only act as a fallback for untrusted issuers, which is never allowed"
            );
        }
        _ => {}
    }

    Box::new(caches.into_iter().collect::<IssuerTrustMap>())
}

/// Builds the claim-validation half of a [`JwtStrategy`] from a config.
fn build_validation(config: &ValidationConfig, multi_issuer: bool) -> Validation {
    let mut validation = Validation::new(config.algorithms[0]);
    validation.algorithms = config.algorithms.clone();

    // `set_issuer` has always taken a slice; the pre-#243 config simply had no
    // way to express more than one name. Every trusted issuer goes in, so a
    // token verified with issuer B's key still has to *say* it came from B.
    let mut accepted_issuers: Vec<&String> = config.trusted_issuers.keys().collect();
    // The `!jwks_url.is_empty()` condition mirrors `build_resolver` exactly. Both
    // must agree on whether `config.issuer` is a resolvable issuer: `build_resolver`
    // folds it into the trust map only when there is a `jwks_url` for it, so adding
    // it here unconditionally would leave `Validation` accepting a name the resolver
    // can never resolve. That is fail-closed (the resolver errors first), but a
    // backstop widened past the thing it backstops is not one you want to keep —
    // and the same `Validation` is handed to third-party resolvers. Raised in
    // review of #243.
    if let Some(issuer) = config
        .issuer
        .as_ref()
        .filter(|issuer| !config.trusted_issuers.contains_key(*issuer))
        .filter(|_| !config.jwks_url.is_empty())
    {
        accepted_issuers.push(issuer);
    }

    if !accepted_issuers.is_empty() {
        validation.set_issuer(&accepted_issuers);
    }

    // In multi-issuer mode `iss` selects the key. In single-issuer mode, we now also
    // strictly require the `iss` claim if an issuer was configured, closing the legacy
    // laxity where an `iss`-less token was accepted.
    if multi_issuer || !accepted_issuers.is_empty() {
        validation.required_spec_claims.insert("iss".to_string());
    }

    if !config.audience.is_empty() {
        validation.set_audience(&config.audience);
    }

    validation
}

#[async_trait]
impl<I> AuthenticationStrategy<I> for JwtStrategy<I>
where
    I: for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(token) = utils::extract_bearer_token(&parts.headers) {
            // Resolve once and reuse the same cache below: which JWKS applies is
            // a property of the token, so re-resolving for the `cnf` re-decode
            // could only introduce a discrepancy.
            let cache = match resolve_cache(token, self.resolver.as_ref()).await {
                Ok(cache) => cache,
                Err(
                    e @ (ValidationError::InvalidToken(_)
                    | ValidationError::Jwt(_)
                    | ValidationError::UntrustedIssuer(_)
                    | ValidationError::MissingIssuer),
                ) => {
                    tracing::debug!(error = %e, "could not read or trust the token's issuer; no identity");
                    return Ok(None);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not resolve a JWKS for the token's issuer; rejecting token");
                    return Err(AuthError::Token(e.to_string()));
                }
            };

            match validate_jwt_generic::<I>(token, &cache, &self.validation).await {
                Ok(claims) => {
                    if self.require_cert_binding || self.require_dpop {
                        // Re-decode as `CnfClaim` to read `cnf` regardless of
                        // what identity type `I` the caller asked for — `I`
                        // is not required to expose `cnf` itself, so this
                        // can't be read off of `claims` above. The token was
                        // already fully verified by the decode above; this
                        // second decode reuses the same cache/validation and
                        // cannot itself fail differently, short of key
                        // rotation racing between the two calls, which is
                        // treated the same as any other verification
                        // failure: reject. Shared between both checks below
                        // since a token can carry both `cnf.x5t#S256` and
                        // `cnf.jkt` at once (RFC 9449 §6.1).
                        let cnf_claim = match validate_jwt_generic::<CnfClaim>(
                            token,
                            &cache,
                            &self.validation,
                        )
                        .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to re-decode token while checking cnf-based binding");
                                return Ok(None);
                            }
                        };

                        if self.require_cert_binding {
                            let cert_der = parts
                                .extensions
                                .get::<ClientCertificateDer>()
                                .map(|c| c.0.as_slice());

                            if let Err(e) = verify_cert_binding(cert_der, cnf_claim.cnf.as_ref()) {
                                tracing::warn!(error = %e, "RFC 8705 certificate-binding check failed; rejecting token");
                                return Ok(None);
                            }
                        }

                        if self.require_dpop {
                            let dpop_header = match extract_dpop_header(&parts.headers) {
                                Ok(h) => h,
                                Err(e) => {
                                    tracing::warn!(error = %e, "malformed DPoP header; rejecting token");
                                    return Ok(None);
                                }
                            };

                            if let Err(e) = verify_dpop_binding(
                                dpop_header,
                                parts.method.as_str(),
                                token,
                                cnf_claim.cnf.as_ref(),
                                self.dpop_replay_store.as_ref(),
                            )
                            .await
                            {
                                tracing::warn!(error = %e, "RFC 9449 DPoP binding check failed; rejecting token");
                                return Ok(None);
                            }
                        }
                    }
                    Ok(Some(claims))
                }
                Err(ValidationError::InvalidToken(_)) | Err(ValidationError::Jwt(_)) => Ok(None),
                Err(e) => Err(AuthError::Token(e.to_string())),
            }
        } else {
            Ok(None)
        }
    }
}

/// The subset of a token's claims this crate needs to check RFC 8705
/// certificate binding — just the `cnf` confirmation claim, decoded
/// independently of whatever identity type `I` a `JwtStrategy<I>` caller
/// asked for.
#[derive(Debug, Deserialize)]
struct CnfClaim {
    #[serde(default)]
    cnf: Option<serde_json::Value>,
}

/// Verifies RFC 8705 §3.1 certificate binding for a decoded token's `cnf`
/// claim.
///
/// - If the token carries no `cnf.x5t#S256` claim at all, it is not
///   certificate-bound; this always succeeds (nothing to check).
/// - If it does, `cert_der` — the DER bytes of the certificate presented on
///   the current connection, if any — must be present and its SHA-256
///   thumbprint must match, in constant time. A certificate-bound token is
///   **never** accepted as a plain bearer token: an absent certificate is
///   rejected exactly like a mismatched one.
pub fn verify_cert_binding(
    cert_der: Option<&[u8]>,
    cnf: Option<&serde_json::Value>,
) -> Result<(), ValidationError> {
    let expected = cnf.and_then(|v| v.get("x5t#S256")).and_then(|v| v.as_str());

    match (cert_der, expected) {
        (Some(cert_der), Some(expected)) => {
            let actual = x5t_s256_thumbprint(cert_der);
            if constant_time_eq(&actual, expected) {
                Ok(())
            } else {
                Err(ValidationError::InvalidToken(
                    "presented mTLS client certificate does not match the token's cnf.x5t#S256"
                        .to_string(),
                ))
            }
        }
        (None, Some(_)) => Err(ValidationError::InvalidToken(
            "token is certificate-bound (cnf.x5t#S256) but no client certificate was presented"
                .to_string(),
        )),
        (_, None) => Ok(()),
    }
}

/// Reads the request's `DPoP` header (RFC 9449 §4.1: exactly one is
/// expected). Returns `Ok(None)` if it's absent, `Ok(Some(value))` if
/// exactly one occurrence is present and valid ASCII, or `Err` in two
/// cases refused outright rather than tolerated: more than one occurrence
/// (ambiguous which is authoritative — a proxy bug or smuggling attempt
/// could produce this) and a value that isn't valid ASCII (treating it as
/// "no header" would silently accept as a plain bearer token what the
/// client believes is sender-constrained). Mirrors the identical helper in
/// `authkestra-axum`/`authkestra-actix`'s `/token` handlers.
fn extract_dpop_header(headers: &http::HeaderMap) -> Result<Option<&str>, ValidationError> {
    let mut dpop_headers = headers.get_all("DPoP").iter();
    match (dpop_headers.next(), dpop_headers.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(ValidationError::InvalidToken(
            "multiple DPoP headers were presented".to_string(),
        )),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| {
            ValidationError::InvalidToken("DPoP header value is not valid ASCII".to_string())
        }),
    }
}

/// RFC 9449 §4.2's `ath` claim is `base64url(SHA256(access_token))` — the
/// exact same computation `x5t_s256_thumbprint` already does, just over the
/// access token's UTF-8 bytes instead of a certificate's DER bytes. Reusing
/// it avoids a second three-line SHA-256-then-base64url helper for an
/// identical operation.
fn compute_ath(access_token: &str) -> String {
    x5t_s256_thumbprint(access_token.as_bytes())
}

/// Verifies RFC 9449 DPoP key binding for a decoded token's `cnf` claim.
///
/// - If the token carries no `cnf.jkt` claim at all, it is not DPoP-bound;
///   this always succeeds (nothing to check) — mirrors
///   [`verify_cert_binding`]'s identical "absent means not bound" shape.
/// - If it does, `dpop_header` must be present, and the proof it contains
///   must: verify (signature, `typ`, freshness), bind to `access_token` via
///   `ath`, and carry the same key as `cnf.jkt`. `htu` is deliberately not
///   checked — see [`ValidationConfig::require_dpop`]'s doc comment.
/// - Finally, the proof's `jti` is checked and recorded via
///   `replay_store`: a DPoP-bound token is **never** accepted with a reused
///   proof, and a proof that can't be recorded at all (e.g. no replay store
///   configured) is refused rather than let through unchecked.
pub async fn verify_dpop_binding(
    dpop_header: Option<&str>,
    htm: &str,
    access_token: &str,
    cnf: Option<&serde_json::Value>,
    replay_store: &dyn crate::dpop::DpopReplayStore,
) -> Result<(), ValidationError> {
    let Some(expected_jkt) = cnf.and_then(|v| v.get("jkt")).and_then(|v| v.as_str()) else {
        return Ok(());
    };

    let Some(proof) = dpop_header else {
        return Err(ValidationError::InvalidToken(
            "token is DPoP-bound (cnf.jkt) but no DPoP proof was presented".to_string(),
        ));
    };

    let ath = compute_ath(access_token);
    let verified = authkestra_engine::token::dpop::verify_dpop_proof(
        proof,
        htm,
        None,
        Some(&ath),
        chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS),
    )
    .map_err(|e| ValidationError::InvalidToken(format!("invalid DPoP proof: {e}")))?;

    if !constant_time_eq(&verified.jkt, expected_jkt) {
        return Err(ValidationError::InvalidToken(
            "DPoP proof key does not match the token's cnf.jkt".to_string(),
        ));
    }

    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(crate::dpop::DPOP_PROOF_MAX_AGE_SECS);
    match replay_store
        .check_and_record_dpop_jti(&verified.jti, expires_at)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(ValidationError::InvalidToken(
            "DPoP proof has already been used".to_string(),
        )),
        Err(e) => Err(e),
    }
}

/// Reads the `iss` claim out of a JWT payload **without verifying the
/// signature**, returning `None` if there is no `iss` or it is not a string.
///
/// Only ever used to *select* which key to verify with, never to make a trust
/// decision on its own. That is safe because the value is re-checked after
/// verification: the payload this reads is the same signature-covered payload
/// `decode` parses, and `Validation`'s accepted-issuer set (populated from the
/// trust map by [`build_validation`]) rejects the token if its `iss` is not one
/// of the trusted names. So an attacker choosing `iss` only chooses which
/// issuer's key their signature must satisfy.
///
/// The payload is decoded by hand rather than via `jsonwebtoken`'s
/// signature-disabled decode path, which would need a dummy key and a second
/// `Validation` whose knobs could drift from the real one.
fn unverified_issuer(token: &str) -> Result<Option<String>, ValidationError> {
    let mut segments = token.split('.');
    let payload = match (segments.next(), segments.next(), segments.next()) {
        (Some(_), Some(payload), Some(_)) => payload,
        _ => {
            return Err(ValidationError::InvalidToken(
                "token is not a well-formed JWS compact serialization".to_string(),
            ))
        }
    };
    // Reject a fourth segment explicitly. Without this, `h.p1.p2.s` yields `p1`
    // here while `jsonwebtoken` (two `rsplitn(2, '.')` passes) reads `p2` as the
    // payload — so the issuer used to *select* a key and the claims that get
    // *validated* would come from different segments. That disagreement is the
    // classic select-one-key/validate-another setup. It is fail-closed today only
    // by accident (`decode_header` receives `"h.p1"`, whose `.` base64 rejects),
    // which is not a property worth resting on. Raised in review of #243.
    if segments.next().is_some() {
        return Err(ValidationError::InvalidToken(
            "token has more than three segments; a JWS compact serialization has exactly three"
                .to_string(),
        ));
    }

    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|e| {
        ValidationError::InvalidToken(format!("token payload is not valid base64url: {e}"))
    })?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).map_err(|e| {
        ValidationError::InvalidToken(format!("token payload is not a JSON object: {e}"))
    })?;

    Ok(claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string))
}

/// Resolves the JWKS cache a token must be verified against, from its own `iss`.
async fn resolve_cache(
    token: &str,
    resolver: &dyn JwksResolver,
) -> Result<Arc<JwksCache>, ValidationError> {
    let issuer = unverified_issuer(token)?;
    resolver.resolve(issuer.as_deref()).await
}

/// Validates a JWT, resolving the JWKS to verify it against from the token's
/// `iss` claim via `resolver`.
///
/// This is the multi-issuer counterpart of [`validate_jwt_generic`], for callers
/// that verify tokens outside a [`JwtStrategy`]. `validation` must still carry
/// the accepted-issuer set (see [`ValidationConfigBuilder::trusted_issuer`]):
/// the resolver decides *which key*, `validation` decides *which names are
/// acceptable*, and both must agree for a token to be accepted.
pub async fn validate_jwt_with_resolver<T>(
    token: &str,
    resolver: &dyn JwksResolver,
    validation: &Validation,
) -> Result<T, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    let cache = resolve_cache(token, resolver).await?;
    validate_jwt_generic::<T>(token, &cache, validation).await
}

/// Validates a JWT against the cached JWKS.
pub async fn validate_jwt(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<Claims, ValidationError> {
    validate_jwt_generic::<Claims>(token, cache, validation).await
}

/// Validates a JWT against the cached JWKS with generic claims.
pub async fn validate_jwt_generic<T>(
    token: &str,
    cache: &JwksCache,
    validation: &Validation,
) -> Result<T, ValidationError>
where
    T: for<'de> Deserialize<'de>,
{
    let header = decode_header(token)?;
    let kid = header.kid.as_deref();

    let jwk = cache
        .get_key(kid)
        .await?
        .ok_or(ValidationError::KeyNotFound)?;

    let decoding_key = jwk.to_decoding_key()?;
    let token_data = decode::<T>(token, &decoding_key, validation)?;

    Ok(token_data.claims)
}

/// Validates a PASETO V4 Local/Public token.
/// Note: This implementation assumes V4 Public for parity with JWKS-like usage if applicable,
/// but PASETO usually handles its own keying. This is a placeholder for the requested logic.
pub async fn validate_paseto(_token: &str, _key: &[u8]) -> Result<Claims, ValidationError> {
    // PASETO validation logic using the `paseto` crate
    // For now, returning an error as PASETO JWKS integration is non-standard
    Err(ValidationError::Paseto(
        "PASETO validation not yet fully implemented with JWKS".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cnf_with_thumbprint(thumbprint: &str) -> serde_json::Value {
        serde_json::json!({ "x5t#S256": thumbprint })
    }

    #[test]
    fn accepts_when_no_cnf_claim_present_regardless_of_certificate() {
        // Not a certificate-bound token: nothing to check, with or without a
        // presented certificate.
        assert!(verify_cert_binding(None, None).is_ok());
        assert!(verify_cert_binding(Some(b"some-cert"), None).is_ok());
    }

    #[test]
    fn accepts_matching_certificate() {
        let cert_der = b"a fake DER-encoded certificate for testing";
        let thumbprint = x5t_s256_thumbprint(cert_der);
        let cnf = cnf_with_thumbprint(&thumbprint);

        assert!(verify_cert_binding(Some(cert_der), Some(&cnf)).is_ok());
    }

    #[test]
    fn rejects_mismatched_certificate() {
        let bound_cert = b"the certificate the token was actually bound to";
        let presented_cert = b"a different certificate presented on this connection";
        let thumbprint = x5t_s256_thumbprint(bound_cert);
        let cnf = cnf_with_thumbprint(&thumbprint);

        let err = verify_cert_binding(Some(presented_cert), Some(&cnf))
            .expect_err("a mismatched certificate must be rejected");
        assert!(matches!(err, ValidationError::InvalidToken(_)));
    }

    #[test]
    fn rejects_absent_certificate_for_a_certificate_bound_token() {
        let bound_cert = b"the certificate the token was actually bound to";
        let thumbprint = x5t_s256_thumbprint(bound_cert);
        let cnf = cnf_with_thumbprint(&thumbprint);

        // No certificate at all was presented on this connection.
        let err = verify_cert_binding(None, Some(&cnf)).expect_err(
            "a certificate-bound token must never be accepted with no certificate presented",
        );
        assert!(matches!(err, ValidationError::InvalidToken(_)));
    }

    #[test]
    fn accepts_when_cnf_is_present_but_has_no_x5t_s256_member() {
        // A `cnf` claim using a different confirmation method (e.g. `jkt`
        // for a key-bound token) is not an `x5t#S256` binding — but is
        // handled as "no certificate-binding claim" here, not "invalid",
        // since this function only speaks RFC 8705's `x5t#S256` shape.
        let cnf = serde_json::json!({ "jkt": "some-other-thumbprint" });
        assert!(verify_cert_binding(None, Some(&cnf)).is_ok());
        assert!(verify_cert_binding(Some(b"cert"), Some(&cnf)).is_ok());
    }

    /// Builds a JWS-shaped string with an arbitrary (unsigned) payload — enough
    /// for the pre-verification `iss` read, which never looks at the signature.
    fn token_with_payload(payload: serde_json::Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
            URL_SAFE_NO_PAD.encode(b"not-a-real-signature"),
        )
    }

    #[test]
    fn reads_the_issuer_out_of_an_unverified_payload() {
        let token =
            token_with_payload(serde_json::json!({ "iss": "https://a.example", "sub": "u" }));
        assert_eq!(
            unverified_issuer(&token).unwrap().as_deref(),
            Some("https://a.example")
        );
    }

    #[test]
    fn reports_no_issuer_when_the_claim_is_absent_or_not_a_string() {
        let no_iss = token_with_payload(serde_json::json!({ "sub": "u" }));
        assert_eq!(unverified_issuer(&no_iss).unwrap(), None);

        // RFC 7519 `iss` is a StringOrURI. `jsonwebtoken` tolerates an array
        // here, but an array names no single key to verify with, so it is
        // treated as "no issuer" and rejected by the resolver rather than
        // silently resolving to one of its members.
        let array_iss = token_with_payload(serde_json::json!({ "iss": ["a", "b"] }));
        assert_eq!(unverified_issuer(&array_iss).unwrap(), None);
    }

    #[test]
    fn rejects_a_token_that_is_not_a_well_formed_jws() {
        assert!(matches!(
            unverified_issuer("not.a-jwt"),
            Err(ValidationError::InvalidToken(_))
        ));
        assert!(matches!(
            unverified_issuer("aaa.!!!not-base64!!!.ccc"),
            Err(ValidationError::InvalidToken(_))
        ));
    }

    #[tokio::test]
    async fn trust_map_rejects_unknown_and_missing_issuers_without_falling_back() {
        let known = Arc::new(JwksCache::new(
            "https://a.example/jwks.json".to_string(),
            Duration::from_secs(60),
        ));
        let map = IssuerTrustMap::new().with_issuer("https://a.example", known);

        assert!(map.resolve(Some("https://a.example")).await.is_ok());
        assert!(matches!(
            map.resolve(Some("https://evil.example")).await,
            Err(ValidationError::UntrustedIssuer(iss)) if iss == "https://evil.example"
        ));
        assert!(matches!(
            map.resolve(None).await,
            Err(ValidationError::MissingIssuer)
        ));
    }

    // --- DPoP (RFC 9449) key binding — authkestra#274 Phase C ---

    mod dpop_binding_tests {
        use super::*;
        use crate::dpop::{DpopJtiRecord, NoDpopReplayStore};
        use authkestra_engine::store::memory::MemoryStore;
        use ed25519_dalek::{Signer, SigningKey};

        fn b64(bytes: &[u8]) -> String {
            URL_SAFE_NO_PAD.encode(bytes)
        }
        fn b64_json(v: &serde_json::Value) -> String {
            b64(serde_json::to_vec(v).unwrap().as_slice())
        }

        /// Builds a real, genuinely Ed25519-signed DPoP proof. Mirrors
        /// `authkestra_engine::token::dpop`'s own (private) `ProofBuilder`
        /// test helper — re-authored here since that one isn't reachable
        /// across the crate boundary.
        struct DpopProofBuilder {
            signing_key: SigningKey,
            jti: String,
            ath: Option<String>,
        }

        impl DpopProofBuilder {
            fn with_key_seed(seed: u8, jti: &str) -> Self {
                Self {
                    signing_key: SigningKey::from_bytes(&[seed; 32]),
                    jti: jti.to_string(),
                    ath: None,
                }
            }

            fn with_ath(mut self, ath: &str) -> Self {
                self.ath = Some(ath.to_string());
                self
            }

            fn jwk(&self) -> serde_json::Value {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": b64(self.signing_key.verifying_key().as_bytes()),
                })
            }

            fn expected_jkt(&self) -> String {
                authkestra_engine::token::dpop::compute_jwk_thumbprint(
                    &serde_json::from_value(self.jwk()).unwrap(),
                )
                .unwrap()
            }

            fn build(&self) -> String {
                let header = serde_json::json!({
                    "typ": "dpop+jwt",
                    "alg": "EdDSA",
                    "jwk": self.jwk(),
                });
                let mut payload = serde_json::json!({
                    "htm": "GET",
                    "htu": "https://resource.example.com/protected",
                    "iat": chrono::Utc::now().timestamp(),
                    "jti": self.jti,
                });
                if let Some(ath) = &self.ath {
                    payload["ath"] = serde_json::Value::String(ath.clone());
                }
                let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
                let signature = self.signing_key.sign(signing_input.as_bytes());
                format!("{signing_input}.{}", b64(&signature.to_bytes()))
            }
        }

        fn cnf_with_jkt(jkt: &str) -> serde_json::Value {
            serde_json::json!({ "jkt": jkt })
        }

        #[tokio::test]
        async fn accepts_when_no_cnf_jkt_present() {
            // Not a DPoP-bound token: nothing to check, with or without a
            // presented proof, and even with the fail-closed default store
            // wired — it must never be consulted for a token that isn't
            // DPoP-bound in the first place.
            assert!(
                verify_dpop_binding(None, "GET", "token", None, &NoDpopReplayStore)
                    .await
                    .is_ok()
            );
            assert!(verify_dpop_binding(
                Some("some-proof"),
                "GET",
                "token",
                Some(&serde_json::json!({ "x5t#S256": "unrelated" })),
                &NoDpopReplayStore,
            )
            .await
            .is_ok());
        }

        #[tokio::test]
        async fn accepts_a_valid_proof_bound_to_this_token() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            let builder = DpopProofBuilder::with_key_seed(11, "jti-1")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            verify_dpop_binding(
                Some(&builder.build()),
                "GET",
                access_token,
                Some(&cnf),
                &store,
            )
            .await
            .expect("a valid proof, bound to this token, for the cnf.jkt key must be accepted");
        }

        #[tokio::test]
        async fn rejects_a_missing_dpop_header_for_a_bound_token() {
            let builder = DpopProofBuilder::with_key_seed(11, "jti-2");
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(None, "GET", "token", Some(&cnf), &NoDpopReplayStore)
                .await
                .expect_err("a DPoP-bound token presented with no proof must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_proof_for_a_different_key_than_cnf_jkt() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            let ath = x5t_s256_thumbprint(access_token.as_bytes());

            // `cnf.jkt` names the key from seed 11; the presented proof is
            // genuinely signed, just by a different key (seed 22).
            let bound = DpopProofBuilder::with_key_seed(11, "jti-3");
            let presented = DpopProofBuilder::with_key_seed(22, "jti-3").with_ath(&ath);
            let cnf = cnf_with_jkt(&bound.expected_jkt());

            let err = verify_dpop_binding(
                Some(&presented.build()),
                "GET",
                access_token,
                Some(&cnf),
                &store,
            )
            .await
            .expect_err("a proof for a different key than cnf.jkt must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_proof_bound_to_a_different_access_token() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let builder = DpopProofBuilder::with_key_seed(11, "jti-4")
                .with_ath(&x5t_s256_thumbprint(b"a-completely-different-token"));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(
                Some(&builder.build()),
                "GET",
                "the-actual-access-token",
                Some(&cnf),
                &store,
            )
            .await
            .expect_err("a proof whose ath binds a different access token must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_replayed_proof() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            let builder = DpopProofBuilder::with_key_seed(11, "jti-5")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());
            let proof = builder.build();

            verify_dpop_binding(Some(&proof), "GET", access_token, Some(&cnf), &store)
                .await
                .expect("first presentation of a fresh proof must succeed");

            let err = verify_dpop_binding(Some(&proof), "GET", access_token, Some(&cnf), &store)
                .await
                .expect_err("replaying the same proof must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn fails_closed_without_a_replay_store_wired() {
            let access_token = "the-access-token-string";
            let builder = DpopProofBuilder::with_key_seed(11, "jti-6")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(
                Some(&builder.build()),
                "GET",
                access_token,
                Some(&cnf),
                &NoDpopReplayStore,
            )
            .await
            .expect_err("no replay store is wired; an otherwise-valid proof must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        #[tokio::test]
        async fn rejects_a_proof_for_the_wrong_method() {
            let store = MemoryStore::<DpopJtiRecord>::new();
            let access_token = "the-access-token-string";
            // `DpopProofBuilder::build` always signs "GET" as `htm`.
            let builder = DpopProofBuilder::with_key_seed(11, "jti-7")
                .with_ath(&x5t_s256_thumbprint(access_token.as_bytes()));
            let cnf = cnf_with_jkt(&builder.expected_jkt());

            let err = verify_dpop_binding(
                Some(&builder.build()),
                "POST",
                access_token,
                Some(&cnf),
                &store,
            )
            .await
            .expect_err("a proof signed for a different HTTP method must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }
    }

    mod dpop_header_tests {
        use super::{extract_dpop_header, ValidationError};

        #[test]
        fn no_header_is_none() {
            let headers = http::HeaderMap::new();
            assert_eq!(extract_dpop_header(&headers).unwrap(), None);
        }

        #[test]
        fn exactly_one_header_is_returned() {
            let mut headers = http::HeaderMap::new();
            headers.insert("DPoP", http::HeaderValue::from_static("proof-value"));
            assert_eq!(extract_dpop_header(&headers).unwrap(), Some("proof-value"));
        }

        /// RFC 9449 §4.1 expects exactly one `DPoP` header; a duplicate is
        /// refused outright rather than silently resolved by picking one.
        #[test]
        fn two_headers_are_rejected() {
            let mut headers = http::HeaderMap::new();
            headers.append("DPoP", http::HeaderValue::from_static("first"));
            headers.append("DPoP", http::HeaderValue::from_static("second"));
            let err =
                extract_dpop_header(&headers).expect_err("a duplicate header must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }

        /// A header value that isn't valid ASCII must be refused, not
        /// silently treated as "no header present".
        #[test]
        fn non_ascii_header_is_rejected() {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "DPoP",
                http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
            );
            let err =
                extract_dpop_header(&headers).expect_err("a non-ASCII header must be refused");
            assert!(matches!(err, ValidationError::InvalidToken(_)));
        }
    }
}
