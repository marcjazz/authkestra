use crate::auth::{error::AuthError, state::Identity};
use async_trait::async_trait;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Interface for issuing and verifying tokens.
/// This can be implemented by JWT-based services, opaque token services, etc.
#[async_trait]
pub trait TokenService: Send + Sync {
    /// Issues a new token for the given identity.
    async fn issue(&self, identity: &Identity, expires_in_secs: u64) -> Result<String, AuthError>;

    /// Verifies a token and returns the associated identity.
    async fn verify(&self, token: &str) -> Result<Identity, AuthError>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    // Standard OIDC claims
    pub iss: Option<String>,
    pub sub: String,
    pub aud: Option<String>,
    pub exp: usize,
    pub iat: usize,
    pub nbf: Option<usize>,
    pub jti: Option<String>,

    // Authkestra-specific core fields
    pub scope: Option<String>,
    /// Optional identity data for user-centric tokens.
    /// If None, this is likely a machine-to-machine token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,

    // Isolated custom claims
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Clone)]
pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: Option<String>,
}

impl TokenManager {
    pub fn new(secret: &[u8], issuer: Option<String>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer,
        }
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Issues a token for a user identity.
    pub fn issue_user_token(
        &self,
        identity: Identity,
        expires_in_secs: u64,
        scope: Option<String>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub: identity.external_id.clone(),
            aud: None,
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope,
            identity: Some(identity),
            extra: HashMap::new(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues a machine-to-machine (M2M) token for a client.
    pub fn issue_client_token(
        &self,
        client_id: &str,
        expires_in_secs: u64,
        scope: Option<String>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub: client_id.to_string(),
            aud: None,
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope,
            identity: None,
            extra: HashMap::new(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::Token(e.to_string()))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl TokenService for TokenManager {
    async fn issue(&self, identity: &Identity, expires_in_secs: u64) -> Result<String, AuthError> {
        self.issue_user_token(identity.clone(), expires_in_secs, None)
    }

    async fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        let claims = self.validate_token(token)?;
        claims
            .identity
            .ok_or_else(|| AuthError::Token("No identity in token".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::state::Identity;
    use std::collections::HashMap;

    #[test]
    fn test_claims_serialization() {
        let mut extra = HashMap::new();
        extra.insert(
            "custom".to_string(),
            serde_json::Value::String("value".to_string()),
        );

        let claims = Claims {
            iss: Some("issuer".to_string()),
            sub: "user123".to_string(),
            aud: Some("audience".to_string()),
            exp: 1000,
            iat: 500,
            nbf: Some(500),
            jti: Some("jti".to_string()),
            scope: Some("openid profile".to_string()),
            identity: Some(Identity {
                provider_id: "google".to_string(),
                external_id: "user123".to_string(),
                email: Some("user@example.com".to_string()),
                username: Some("user".to_string()),
                attributes: HashMap::new(),
            }),
            extra,
        };

        let serialized = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.iss, claims.iss);
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.extra.get("custom").unwrap(), "value");
    }

    #[test]
    fn test_token_manager_issuance() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager.issue_user_token(identity, 3600, None).unwrap();
        let claims = manager.validate_token(&token).unwrap();

        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.sub, "user123");
        assert!(claims.jti.is_some());
        assert!(claims.nbf.is_some());
    }
}
