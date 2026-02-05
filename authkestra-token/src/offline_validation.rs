use authkestra_core::{AuthError, ProviderMetadata};
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

        DecodingKey::from_rsa_components(n, e).map_err(|e| ValidationError::Jwt(e))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub async fn fetch(jwks_uri: &str, client: &reqwest::Client) -> Result<Self, ValidationError> {
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
    http_client: reqwest::Client,
    jwks: RwLock<Option<(Jwks, Instant)>>,
    ttl: Duration,
}

impl JwksCache {
    pub fn new(jwks_uri: String, http_client: reqwest::Client) -> Self {
        Self {
            jwks_uri,
            http_client,
            jwks: RwLock::new(None),
            ttl: Duration::from_secs(3600), // 1 hour default TTL
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
        let jwks = Jwks::fetch(&self.jwks_uri, &self.http_client).await?;
        *write_guard = Some((jwks.clone(), Instant::now()));
        Ok(jwks)
    }
}

pub struct OidcValidator {
    metadata: ProviderMetadata,
    jwks_cache: JwksCache,
}

impl OidcValidator {
    /// Creates a new validator by performing discovery.
    /// This is suitable for offline validation where client credentials are not required.
    pub async fn discover(issuer_url: &str) -> Result<Self, ValidationError> {
        let client = reqwest::Client::new();
        let metadata = ProviderMetadata::discover(issuer_url, &client).await?;
        let jwks_cache = JwksCache::new(metadata.jwks_uri.clone(), client.clone());
        Ok(Self {
            metadata,
            jwks_cache,
        })
    }

    pub async fn validate_id_token<T>(
        &self,
        id_token: &str,
        audience: &str,
    ) -> Result<T, ValidationError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let header = decode_header(id_token)
            .map_err(|e| ValidationError::Validation(format!("Invalid ID Token header: {}", e)))?;

        let jwk = self
            .jwks_cache
            .get_key(header.kid.as_deref())
            .await?
            .ok_or_else(|| {
                ValidationError::Validation("No matching key found in JWKS".to_string())
            })?;

        let decoding_key = jwk.to_decoding_key()?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.metadata.issuer));
        validation.set_audience(std::slice::from_ref(&audience));

        let token_data = decode::<T>(id_token, &decoding_key, &validation).map_err(|e| {
            ValidationError::Validation(format!("ID Token validation failed: {}", e))
        })?;

        Ok(token_data.claims)
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
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
