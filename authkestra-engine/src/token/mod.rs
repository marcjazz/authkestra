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
    kid: Option<String>,
    alg: Algorithm,
    public_jwk: Option<crate::token::jwk::Jwk>,
}

impl TokenManager {
    /// Creates a TokenManager for symmetric signing (HS256).
    pub fn new(secret: &[u8], issuer: Option<String>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer,
            kid: None,
            alg: Algorithm::HS256,
            public_jwk: None,
        }
    }

    /// Creates a TokenManager for asymmetric signing (RS256).
    /// `private_key_pem` must be a valid RSA private key in PEM format.
    /// OP/external verification should use this path; internal resource servers
    /// can continue to use `new` (HS256).
    pub fn new_asymmetric(
        private_key_pem: &[u8],
        issuer: Option<String>,
        kid: Option<String>,
    ) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| AuthError::Token(e.to_string()))?;
        let decoding_key = DecodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|_| AuthError::Token("Invalid PEM UTF-8".into()))?;

        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem_str))
            .map_err(|e| AuthError::Token(format!("Failed to parse RSA key: {}", e)))?;

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use rsa::traits::PublicKeyParts;

        let n = URL_SAFE_NO_PAD.encode(rsa_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(rsa_key.e().to_bytes_be());

        let kid_val = kid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let jwk = crate::token::jwk::Jwk {
            kid: Some(kid_val.clone()),
            kty: "RSA".to_string(),
            alg: Some("RS256".to_string()),
            n: Some(n),
            e: Some(e),
        };

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
            kid: Some(kid_val),
            alg: Algorithm::RS256,
            public_jwk: Some(jwk),
        })
    }

    pub fn public_jwk(&self) -> Option<crate::token::jwk::Jwk> {
        self.public_jwk.clone()
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

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues an OIDC-conformant ID token.
    pub fn issue_id_token(
        &self,
        identity: Identity,
        client_id: &str,
        nonce: Option<String>,
        expires_in_secs: u64,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;

        let mut claims = Claims {
            iss: self.issuer.clone(),
            sub: identity.external_id.clone(),
            aud: Some(client_id.to_string()),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope: None,
            identity: Some(identity),
            extra: HashMap::new(),
        };

        if let Some(n) = nonce {
            claims.extra.insert("nonce".to_string(), serde_json::Value::String(n));
        }

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
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

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(self.alg);
        validation.validate_aud = false; // Don't strictly validate audience by default here
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

    #[test]
    fn test_token_manager_asymmetric_issuance() {
        let pem = b"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA5hJIcQ+2rxMz
VM8ZH5WAmguCr0xmNDAdy0IzzsUeFLG7BebB7izOkU36J4t8t5tUaQwrBMnx2Fvt
VqJjbdE242UDpvWF/8m9zJ2HR5298cbwT5cGMKLB0HWzDMahugs+Bbh2lCgwyLZk
Tr3Diwxp5SwFew/Wb+Ke9cNG9Hu5IFH3BCuJ839d9hfqisIeYrBPfb52xxckM37R
7zSGu/eDP/HZAeLkQuptZJW4A3u7xni14u4qyqXDqsHsYFNgJaxMSAwWgBRY6HNu
TnvBArTXCiVfL+F73B2L6mdYr64g+QS9nK9v97MlJu/E3mSduz54pren4mpCHc9m
/S2+VjCZAgMBAAECggEAASC9qQbGnL7XuExRDOIn/m4bWx92ehjo0lCTibhpY3LW
umbSbpfbhmmuSj3CjW9VZsaM3hBTgSjoTX72lbY/eIUXD7c0memUK5pV4XcEIrQw
AZlPIye6ckx4I7ZGnKasO8FoAel9dd7DXw36AuBK3LBzJwtzkEFsBc0e3/wixqmG
UJBbbt/+5ya7CxyjuePaQhKtkLD5R6DpvN2XnCYq5nHJNJdvSVg1pOzsTHYIf+Ee
2Rz42fGsfFKqeEQCcBFRZaGb/ELeP4c6UZdktZAvmHb1p1fursVZc6X9JXmiJ2OJ
Kv2H2tMKuysP8L0fXFOMgkH2SVt6rcdHkO6xhlhWsQKBgQDqR8rAJeEE5BFoXA8T
VVW6CLMlW51x4ey7PEGOaYh39dTG2Q+GZQBZ9G+SZk3f5Y85UCACSyc//4qaz/c3
0nWsegZ+JPyymmuc79wzIAFFvXB7pL6wyn0Ed1P620kOZTtA8iBcXrsuxL+KP7iu
MXfWmU1QiZpbndILtyDnY+70uwKBgQDSyCljWkydQCaPU+fiAXLxP8CvcJTSSNQD
mVUlwJ+OpHnU+Alsi1rBavMgUtLlYbFqzH7NmYrLC8Yadq3ZOwLt0VEK0r8qstAL
7QCDUD2WNuQjpZupRnXuMUl3iXB96i2gb+VQKGuUAJvVWjdIbYa4+Gu+sBMfcDcX
dBihDLuEuwKBgAgX4tEwfc2Fc3R/eaXZVNTQaB/qQk4k1+C//CPHUYeTXn5gEUE7
S//PiesszZPmgkQgmHp7zidP1KH0fT3Yb2g97ut8q54f54fMYXcCrAiUusYKsuu4
kwkMdkI8QRHWPW3I74VBYIYFFfjYqrCZ1OH8+cbGeiagFRmCggh8U0zxAoGAVW3u
6Ge22Z0gg8LcHsu7jG/sZq7Ygool8/d3fT+e669Z+ak2GJo6hF4WgClRdMqtn72W
PzpV+ImjFyK2v26dd0n48MwN0v56N/ss1Av3iiRhPtlmR6tZLNspDZvUzhPVvkrb
xCs9vtSoVEamVWKe0eVNthGjDoDqs0TInq2MavUCgYB6REavSJs/CLkSS7iimjxZ
G7g5YQi9/p1lXLOEUDiwEmvRr0XTwzzxUsIc535IXhh/ZUYpthenW+qBBzn85pEC
TowIqciHu5redqlQ8rITA8/AOY98vaDIhppDg1rfpnHHaZHFbXD/keYAEbhBtbvf
a0QMqKUcs8+YTy5R5K6qtw==
-----END PRIVATE KEY-----";

        let manager = TokenManager::new_asymmetric(
            pem,
            Some("issuer".to_string()),
            Some("my-kid-123".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager.issue_user_token(identity, 3600, None).unwrap();

        // Decode directly via jsonwebtoken to prove independent verification
        let jwk = manager.public_jwk().unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("my-kid-123"));

        let decoding_key = jwk.to_decoding_key().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["issuer"]);

        let token_data =
            jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.header.kid.as_deref(), Some("my-kid-123"));
    }

    #[test]
    fn test_issue_id_token() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_id_token(
                identity,
                "client-1",
                Some("nonce123".to_string()),
                3600,
            )
            .unwrap();

        let claims = manager.validate_token(&token).unwrap();

        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.aud, Some("client-1".to_string()));
        assert_eq!(claims.extra.get("nonce").unwrap(), "nonce123");
    }
}
pub mod jwk;
