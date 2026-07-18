use crate::auth::error::AuthError;
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: String,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

impl Jwk {
    pub fn to_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        if self.kty != "RSA" {
            return Err(AuthError::Token(
                "Only RSA keys are supported currently".to_string(),
            ));
        }

        let n = self
            .n
            .as_ref()
            .ok_or_else(|| AuthError::Token("Missing 'n' component in JWK".to_string()))?;
        let e = self
            .e
            .as_ref()
            .ok_or_else(|| AuthError::Token("Missing 'e' component in JWK".to_string()))?;

        DecodingKey::from_rsa_components(n, e).map_err(|e| AuthError::Token(e.to_string()))
    }
}
