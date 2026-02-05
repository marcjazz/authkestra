pub mod offline_validation;

pub use offline_validation::{validate_jwt, validate_jwt_generic, JwksCache, OidcValidator};

use authkestra_core::{AuthError, Identity};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub scope: Option<String>,
    /// Optional identity data for user-centric tokens.
    /// If None, this is likely a machine-to-machine token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    /// Additional custom claims.
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

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
            sub: identity.external_id.clone(),
            exp: expiration,
            iat: now,
            iss: self.issuer.clone(),
            aud: None,
            scope,
            identity: Some(identity),
            custom: HashMap::new(),
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
            sub: client_id.to_string(),
            exp: expiration,
            iat: now,
            iss: self.issuer.clone(),
            aud: None,
            scope,
            identity: None,
            custom: HashMap::new(),
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
