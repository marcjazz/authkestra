use authkestra_engine::token::jwk::Jwk;
use serde::{Deserialize, Serialize};

/// The JSON Web Key Set (JWKS) response format.
/// Served at `/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    /// The array of JWKs.
    pub keys: Vec<Jwk>,
}

impl JwksResponse {
    /// Creates a new JWKS response from an optional JWK.
    /// If the token manager does not have a public key (e.g., symmetric only),
    /// the keys array will be empty.
    pub fn new(jwk: Option<Jwk>) -> Self {
        Self {
            keys: jwk.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use authkestra_engine::store::KvStore;
    use super::*;

    #[test]
    fn test_jwks_response_empty() {
        let response = JwksResponse::new(None);
        assert!(response.keys.is_empty());
    }

    #[test]
    fn test_jwks_response_with_key() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            kid: Some("123".to_string()),
            n: Some("abc".to_string()),
            e: Some("AQAB".to_string()),
        };
        let response = JwksResponse::new(Some(jwk.clone()));
        assert_eq!(response.keys.len(), 1);
        assert_eq!(response.keys[0].kid.as_deref(), Some("123"));
    }
}
