use authkestra_engine::token::jwk::Jwk;
use serde::{Deserialize, Serialize};

/// The JSON Web Key Set (JWKS) response format.
/// Served at `/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JwksResponse {
    /// The array of JWKs.
    pub keys: Vec<Jwk>,
}

impl JwksResponse {
    /// Creates a new JWKS response from any iterable of JWKs.
    ///
    /// This accepts anything implementing `IntoIterator<Item = Jwk>`, so a
    /// single `Option<Jwk>` (e.g. from `TokenManager::public_jwk`) still
    /// works unchanged, while callers managing their own key history (e.g.
    /// host apps rotating keys and wanting to keep the previous "stale" key
    /// published alongside the new "active" one) can pass in a `Vec<Jwk>` or
    /// any other collection of keys.
    ///
    /// If no keys are provided (e.g. the token manager does not have a
    /// public key, such as symmetric-only setups), the keys array will be
    /// empty.
    pub fn new(keys: impl IntoIterator<Item = Jwk>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {

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
            crv: None,
            x: None,
        };
        let response = JwksResponse::new(Some(jwk.clone()));
        assert_eq!(response.keys.len(), 1);
        assert_eq!(response.keys[0].kid.as_deref(), Some("123"));
    }

    #[test]
    fn test_jwks_response_with_multiple_keys() {
        let jwk1 = Jwk {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            kid: Some("key-1".into()),
            n: Some("n1".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
        };
        let jwk2 = Jwk {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            kid: Some("key-2".into()),
            n: Some("n2".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
        };
        let response = JwksResponse::new(vec![jwk1, jwk2]);
        assert_eq!(response.keys.len(), 2);
        assert_eq!(response.keys[0].kid.as_deref(), Some("key-1"));
        assert_eq!(response.keys[1].kid.as_deref(), Some("key-2"));
    }
}
