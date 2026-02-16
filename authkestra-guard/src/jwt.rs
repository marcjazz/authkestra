use async_trait::async_trait;
use authkestra_core::{
    error::AuthError,
    strategy::{utils, AuthenticationStrategy},
};
use http::request::Parts;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
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
    #[error("PASETO error: {0}")]
    Paseto(String),
    #[error("Discovery error: {0}")]
    Discovery(#[from] AuthError),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Standard claims for JWT/PASETO validation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<usize>,
    pub nbf: Option<usize>,
    pub iat: Option<usize>,
    pub jti: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: String,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

impl Jwk {
    pub fn to_decoding_key(&self) -> Result<DecodingKey, ValidationError> {
        if self.kty != "RSA" {
            return Err(ValidationError::Validation(
                "Only RSA keys are supported currently".to_string(),
            ));
        }

        let n = self.n.as_ref().ok_or_else(|| {
            ValidationError::Validation("Missing 'n' component in JWK".to_string())
        })?;
        let e = self.e.as_ref().ok_or_else(|| {
            ValidationError::Validation("Missing 'e' component in JWK".to_string())
        })?;

        DecodingKey::from_rsa_components(n, e).map_err(ValidationError::Jwt)
    }
}

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
}

impl JwksCache {
    pub fn new(jwks_uri: String, refresh_interval: Duration) -> Self {
        Self {
            jwks_uri,
            jwks: RwLock::new(None),
            ttl: refresh_interval,
        }
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
    pub audience: Option<String>,
    pub algorithms: Vec<Algorithm>,
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
    audience: Option<String>,
    algorithms: Vec<Algorithm>,
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

    /// Set the expected audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the allowed algorithms.
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
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
        }
    }
}

/// A JWT authentication strategy that performs offline JWT validation using JWKS.
pub struct JwtStrategy<I> {
    cache: JwksCache,
    validation: Validation,
    _marker: std::marker::PhantomData<I>,
}

impl<I> JwtStrategy<I> {
    /// Create a new `JwtStrategy` with the given `ValidationConfig`.
    pub fn new(config: ValidationConfig) -> Self {
        let cache = JwksCache::new(config.jwks_url, config.refresh_interval);
        let mut validation = Validation::new(config.algorithms[0]);
        validation.algorithms = config.algorithms;

        if let Some(iss) = config.issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(aud) = config.audience {
            validation.set_audience(&[aud]);
        }

        Self {
            cache,
            validation,
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
                Ok(claims) => Ok(Some(claims)),
                Err(ValidationError::InvalidToken(_)) | Err(ValidationError::Jwt(_)) => Ok(None),
                Err(e) => Err(AuthError::Token(e.to_string())),
            }
        } else {
            Ok(None)
        }
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
