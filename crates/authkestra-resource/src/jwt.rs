use async_trait::async_trait;
use authkestra_engine::{
    error::AuthError,
    strategy::{utils, AuthenticationStrategy},
    token::{
        cert_binding::{constant_time_eq, x5t_s256_thumbprint, ClientCertificateDer},
        Claims,
    },
};
use http::request::Parts;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
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
    #[error("PASETO error: {0}")]
    Paseto(String),
    #[error("Discovery error: {0}")]
    Discovery(#[from] AuthError),
    #[error("Validation error: {0}")]
    Validation(String),
}

pub use authkestra_engine::token::jwk::Jwk;

#[derive(Debug, Clone, Deserialize)]
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

/// A builder for configuring offline JWT validation.
/// Configuration for JWT validation.
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
}

impl ValidationConfig {
    /// Create a new builder for `ValidationConfig`.
    pub fn builder() -> ValidationConfigBuilder {
        ValidationConfigBuilder::default()
    }
}

/// A builder for configuring JWT validation.
#[derive(Default)]
pub struct ValidationConfigBuilder {
    jwks_url: Option<String>,
    refresh_interval: Option<Duration>,
    issuer: Option<String>,
    audience: Vec<String>,
    algorithms: Vec<Algorithm>,
    require_kid: bool,
    require_cert_binding: bool,
}

impl ValidationConfigBuilder {
    /// Set the JWKS URL.
    pub fn jwks_url(mut self, jwks_url: impl Into<String>) -> Self {
        self.jwks_url = Some(jwks_url.into());
        self
    }

    /// Set the refresh interval for the JWKS cache.
    pub fn refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = Some(interval);
        self
    }

    /// Set the expected issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
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

    /// Build a `ValidationConfig`.
    pub fn build(self) -> ValidationConfig {
        ValidationConfig {
            jwks_url: self
                .jwks_url
                .expect("JWKS URL must be set for ValidationConfig"),
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
        }
    }
}

/// A JWT authentication strategy that performs offline JWT validation using JWKS.
pub struct JwtStrategy<I> {
    cache: JwksCache,
    validation: Validation,
    require_cert_binding: bool,
    _marker: std::marker::PhantomData<I>,
}

impl<I> JwtStrategy<I> {
    /// Create a new `JwtStrategy` with the given `ValidationConfig`.
    pub fn new(config: ValidationConfig) -> Self {
        let cache = JwksCache::new(config.jwks_url, config.refresh_interval)
            .require_kid(config.require_kid);
        let mut validation = Validation::new(config.algorithms[0]);
        validation.algorithms = config.algorithms;

        if let Some(iss) = config.issuer {
            validation.set_issuer(&[iss]);
        }

        if !config.audience.is_empty() {
            validation.set_audience(&config.audience);
        }

        Self {
            cache,
            validation,
            require_cert_binding: config.require_cert_binding,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<I> AuthenticationStrategy<I> for JwtStrategy<I>
where
    I: for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    async fn authenticate(&self, parts: &Parts) -> Result<Option<I>, AuthError> {
        if let Some(token) = utils::extract_bearer_token(&parts.headers) {
            match validate_jwt_generic::<I>(token, &self.cache, &self.validation).await {
                Ok(claims) => {
                    if self.require_cert_binding {
                        // Re-decode as `CnfClaim` to read `cnf.x5t#S256`
                        // regardless of what identity type `I` the caller
                        // asked for — `I` is not required to expose `cnf`
                        // itself, so this can't be read off of `claims`
                        // above. The token was already fully verified by the
                        // decode above; this second decode reuses the same
                        // cache/validation and cannot itself fail
                        // differently, short of key rotation racing between
                        // the two calls, which is treated the same as any
                        // other verification failure: reject.
                        let cnf_claim = match validate_jwt_generic::<CnfClaim>(
                            token,
                            &self.cache,
                            &self.validation,
                        )
                        .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to re-decode token while checking RFC 8705 certificate binding");
                                return Ok(None);
                            }
                        };

                        let cert_der = parts
                            .extensions
                            .get::<ClientCertificateDer>()
                            .map(|c| c.0.as_slice());

                        if let Err(e) = verify_cert_binding(cert_der, cnf_claim.cnf.as_ref()) {
                            tracing::warn!(error = %e, "RFC 8705 certificate-binding check failed; rejecting token");
                            return Ok(None);
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
}
