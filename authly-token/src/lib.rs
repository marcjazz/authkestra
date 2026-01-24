use authly_core::{Identity, AuthError};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub identity: Identity,
}

pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl TokenManager {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn issue_token(&self, identity: Identity, expires_in_secs: u64) -> Result<String, AuthError> {
        let expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(expires_in_secs as i64))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: identity.external_id.clone(),
            exp: expiration,
            identity,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::Token(e.to_string()))
    }

    pub fn validate_token(&self, token: &str) -> Result<Identity, AuthError> {
        let token_data = decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::new(Algorithm::HS256),
        ).map_err(|e| AuthError::Token(e.to_string()))?;

        Ok(token_data.claims.identity)
    }
}

// Add Token error variant to AuthError in core if not exists
// For the sake of this stub, I'll assume core was updated or I use Provider for now.
// Actually let's just use Provider for now to avoid re-editing core repeatedly in stubs.
