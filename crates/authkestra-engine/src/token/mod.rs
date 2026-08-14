use crate::auth::{error::AuthError, state::Identity};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The `aud` (audience) claim, per RFC 7519 §4.1.3: either a single
/// case-sensitive string, or a JSON array of such strings.
///
/// `#[serde(untagged)]` tries variants in declaration order on
/// deserialization, so a bare JSON string matches [`Audience::Single`]
/// first, and only a JSON array falls through to [`Audience::Multiple`].
/// Serialization is not affected by declaration order — each variant
/// serializes as its own shape — so a token minted with a single audience
/// still serializes as a bare string, not a one-element array, matching
/// every token this crate has ever issued.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /// True if `value` is present in this audience, whichever shape it was
    /// deserialized from. This is the "matches ANY" membership test that
    /// replaces exact-string-equality comparisons against `aud`.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::Single(s) => s == value,
            Audience::Multiple(values) => values.iter().any(|s| s == value),
        }
    }
}

impl From<String> for Audience {
    fn from(value: String) -> Self {
        Audience::Single(value)
    }
}

impl From<&str> for Audience {
    fn from(value: &str) -> Self {
        Audience::Single(value.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    // Standard OIDC claims
    pub iss: Option<String>,
    pub sub: String,
    pub aud: Option<Audience>,
    pub exp: usize,
    pub iat: usize,
    pub nbf: Option<usize>,
    pub jti: Option<String>,

    // Engine-specific core fields
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
            crv: None,
            x: None,
        };

        // The decoding key must come from the PUBLIC half. `DecodingKey::from_rsa_pem`
        // expects a public-key PEM; handed a private one it still constructs, but every
        // later `validate_token` fails with `InvalidSignature`. Deriving it from the JWK
        // we just built keeps both halves provably in sync with what `/jwks` publishes.
        let decoding_key = jwk.to_decoding_key()?;

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
            kid: Some(kid_val),
            alg: Algorithm::RS256,
            public_jwk: Some(jwk),
        })
    }

    /// Creates a TokenManager for asymmetric signing with Ed25519 (EdDSA).
    /// `private_key_pem` must be a valid Ed25519 private key in PKCS#8 PEM
    /// format (`-----BEGIN PRIVATE KEY-----`), e.g. as produced by
    /// `openssl genpkey -algorithm ed25519`.
    ///
    /// Mirrors `new_asymmetric` (RS256): OP/external verification should use
    /// this path when downstream resource servers require EdDSA-signed
    /// tokens; internal resource servers can continue to use `new` (HS256).
    /// The published JWK (`public_jwk`) is the OKP shape from RFC 8037, so
    /// pair this with #188 (`Jwk`'s OKP support) to publish a verifiable
    /// `/jwks.json` for the resulting deployment.
    pub fn new_ed25519(
        private_key_pem: &[u8],
        issuer: Option<String>,
        kid: Option<String>,
    ) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_ed_pem(private_key_pem)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|_| AuthError::Token("Invalid PEM UTF-8".into()))?;

        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem_str)
            .map_err(|e| AuthError::Token(format!("Failed to parse Ed25519 key: {}", e)))?;

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

        let kid_val = kid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let jwk = crate::token::jwk::Jwk {
            kid: Some(kid_val.clone()),
            kty: "OKP".to_string(),
            alg: Some("EdDSA".to_string()),
            n: None,
            e: None,
            crv: Some("Ed25519".to_string()),
            x: Some(x),
        };

        // Same rationale as `new_asymmetric`: derive the decoding key from
        // the JWK we just built (the public half) rather than from the
        // private PEM, so both provably agree with what `/jwks` publishes.
        // See the regression note on that constructor and the test below
        // named after it.
        let decoding_key = jwk.to_decoding_key()?;

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer,
            kid: Some(kid_val),
            alg: Algorithm::EdDSA,
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
        aud: Option<String>,
    ) -> Result<String, AuthError> {
        self.issue_user_token_with_extra(identity, expires_in_secs, scope, aud, HashMap::new())
    }

    /// Issues a token for a user identity, stamping the given `extra` claims
    /// onto the token in addition to the standard/core claims.
    ///
    /// This lets a host application (e.g. a resource server built on top of
    /// this engine) attach domain-specific claims — such as `api_key_id`,
    /// `project_id`, or `roles` — so downstream consumers (an API gateway or
    /// authorization proxy) can read them directly off the token without a
    /// database round-trip. Keys in `extra` take precedence over any
    /// same-named field set elsewhere in `extra` by this method; they cannot
    /// override the top-level standard claims (`sub`, `aud`, `exp`, etc.)
    /// since those are not part of the flattened map.
    pub fn issue_user_token_with_extra(
        &self,
        identity: Identity,
        expires_in_secs: u64,
        scope: Option<String>,
        aud: Option<String>,
        extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub: identity.external_id.clone(),
            aud: aud.map(Audience::from),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope,
            identity: Some(identity),
            extra,
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
        self.issue_id_token_with_extra(identity, client_id, nonce, expires_in_secs, HashMap::new())
    }

    /// Issues an OIDC-conformant ID token, stamping the given `extra` claims
    /// onto the token in addition to the standard/core claims.
    ///
    /// `nonce` is a reserved claim key: `extra` is merged into the token
    /// first, then the explicit `nonce` parameter is applied on top. So if
    /// `nonce` is `Some(_)`, it always wins over any `"nonce"` entry passed
    /// in `extra`. If `nonce` is `None`, an `extra["nonce"]` value (if any)
    /// is left as-is. This preserves OIDC `nonce` semantics — it reflects
    /// what the client sent in the authorization request — and keeps it from
    /// being accidentally clobbered by unrelated custom claims.
    pub fn issue_id_token_with_extra(
        &self,
        identity: Identity,
        client_id: &str,
        nonce: Option<String>,
        expires_in_secs: u64,
        extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;

        let mut claims = Claims {
            iss: self.issuer.clone(),
            sub: identity.external_id.clone(),
            aud: Some(Audience::from(client_id)),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope: None,
            identity: Some(identity),
            extra,
        };

        if let Some(n) = nonce {
            claims
                .extra
                .insert("nonce".to_string(), serde_json::Value::String(n));
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
        aud: Option<String>,
    ) -> Result<String, AuthError> {
        self.issue_client_token_with_extra(client_id, expires_in_secs, scope, aud, HashMap::new())
    }

    /// Issues a machine-to-machine (M2M) token for a client, stamping the
    /// given `extra` claims onto the token in addition to the standard/core
    /// claims. See [`Self::issue_user_token_with_extra`] for the rationale.
    pub fn issue_client_token_with_extra(
        &self,
        client_id: &str,
        expires_in_secs: u64,
        scope: Option<String>,
        aud: Option<String>,
        extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let expiration = now + expires_in_secs as usize;

        let claims = Claims {
            iss: self.issuer.clone(),
            sub: client_id.to_string(),
            aud: aud.map(Audience::from),
            exp: expiration,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope,
            identity: None,
            extra,
        };

        let mut header = Header::new(self.alg);
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    /// Issues a token with an explicit `typ` header and no `aud`, for
    /// callers minting something that is not a standard OIDC ID/access/user
    /// token and needs its own wire-format `typ` so verifiers can tell it
    /// apart from those (e.g. `authkestra-op`'s device/service attestations,
    /// whose contract requires `typ: "webank-attest+jws"` rather than the
    /// default `"JWT"`). Additive alongside the `issue_*_token*` family
    /// above; those are unchanged.
    pub fn issue_custom_token(
        &self,
        sub: String,
        expires_in_secs: u64,
        typ: &str,
        extra: HashMap<String, serde_json::Value>,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            iss: self.issuer.clone(),
            sub,
            aud: None,
            exp: now + expires_in_secs as usize,
            iat: now,
            nbf: Some(now),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            scope: None,
            identity: None,
            extra,
        };

        let mut header = Header::new(self.alg);
        header.typ = Some(typ.to_string());
        if let Some(ref kid) = self.kid {
            header.kid = Some(kid.clone());
        }

        encode(&header, &claims, &self.encoding_key).map_err(|e| AuthError::Token(e.to_string()))
    }

    pub fn validate_token(
        &self,
        token: &str,
        expected_aud: Option<&str>,
    ) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(self.alg);
        if let Some(aud) = expected_aud {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::Token(e.to_string()))?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::auth::state::Identity;
    use std::collections::HashMap;

    /// Throwaway RSA-2048 private key, test-only.
    const TEST_RSA_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
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

    /// Throwaway Ed25519 private key (PKCS#8 PEM), test-only. Generated with
    /// `openssl genpkey -algorithm ed25519`.
    const TEST_ED25519_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKIPR2jojpdobYr1M/pjIRuMONpZGYQ+y5yxSqKX9T9/
-----END PRIVATE KEY-----";

    /// A second, distinct throwaway Ed25519 private key, test-only — used to
    /// prove a token signed by one key is rejected by another key's manager.
    const TEST_ED25519_PRIVATE_KEY_PEM_B: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPlsnSfvh53rJ+Tlbo8e7cgq2mIkWQ1NCM5paVeinUh8
-----END PRIVATE KEY-----";

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
            aud: Some(Audience::from("audience")),
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

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.sub, "user123");
        assert!(claims.jti.is_some());
        assert!(claims.nbf.is_some());
    }

    #[test]
    fn test_token_manager_asymmetric_issuance() {
        let manager = TokenManager::new_asymmetric(
            TEST_RSA_PRIVATE_KEY_PEM,
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

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

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

    /// Regression test for the asymmetric decoding key being derived from the
    /// private half instead of the public one.
    ///
    /// `test_token_manager_asymmetric_issuance` above verifies via the
    /// published JWK, which exercises `Jwk::to_decoding_key` rather than the
    /// manager's own `decoding_key` — so it stays green either way. This one
    /// goes through `validate_token`, which is the path `/reissue` and
    /// `/userinfo` actually take.
    #[test]
    fn test_asymmetric_manager_validates_its_own_tokens() {
        let manager = TokenManager::new_asymmetric(
            TEST_RSA_PRIVATE_KEY_PEM,
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

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, Some("issuer".to_string()));

        // Same round trip for the attestation shape `/reissue` presents.
        let attestation = manager
            .issue_custom_token(
                "device-1".to_string(),
                60,
                "webank-attest+jws",
                HashMap::new(),
            )
            .unwrap();

        let attest_claims = manager.validate_token(&attestation, None).unwrap();
        assert_eq!(attest_claims.sub, "device-1");
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
            .issue_id_token(identity, "client-1", Some("nonce123".to_string()), 3600)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(claims.iss, Some("issuer".to_string()));
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.aud, Some(Audience::from("client-1")));
        assert_eq!(claims.extra.get("nonce").unwrap(), "nonce123");
    }
    #[test]
    fn test_token_manager_audience_validation() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        // Issue token for "client-1"
        let token = manager
            .issue_id_token(identity, "client-1", None, 3600)
            .unwrap();

        // Validate with correct audience
        let claims = manager.validate_token(&token, Some("client-1")).unwrap();
        assert_eq!(claims.aud, Some(Audience::from("client-1")));

        // Validate with incorrect audience (should fail)
        let err = manager
            .validate_token(&token, Some("client-2"))
            .unwrap_err();
        assert!(err.to_string().contains("InvalidAudience"));
    }

    #[test]
    fn test_issue_custom_token_sets_typ_and_no_aud() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert("cnf".to_string(), serde_json::json!({"jkt": "abc"}));

        let token = manager
            .issue_custom_token("device-1".to_string(), 60, "webank-attest+jws", extra)
            .unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("webank-attest+jws"));

        let claims = manager.validate_token(&token, None).unwrap();
        assert_eq!(claims.sub, "device-1");
        assert_eq!(claims.aud, None);
        assert_eq!(claims.extra.get("cnf").unwrap()["jkt"], "abc");
    }

    #[test]
    fn test_issue_user_token_with_extra_round_trips_custom_claims() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert("api_key_id".to_string(), serde_json::json!("key-abc"));
        extra.insert("project_id".to_string(), serde_json::json!("proj-42"));

        let token = manager
            .issue_user_token_with_extra(identity, 3600, None, None, extra)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("api_key_id"),
            Some(&serde_json::json!("key-abc"))
        );
        assert_eq!(
            claims.extra.get("project_id"),
            Some(&serde_json::json!("proj-42"))
        );
    }

    #[test]
    fn test_issue_user_token_wrapper_still_has_empty_extra() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert!(claims.extra.is_empty());
    }

    #[test]
    fn test_issue_client_token_with_extra_round_trips_custom_claims() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let mut extra = HashMap::new();
        extra.insert("roles".to_string(), serde_json::json!(["admin", "billing"]));

        let token = manager
            .issue_client_token_with_extra("client-1", 3600, None, None, extra)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("roles"),
            Some(&serde_json::json!(["admin", "billing"]))
        );
    }

    #[test]
    fn test_issue_client_token_wrapper_still_has_empty_extra() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let token = manager
            .issue_client_token("client-1", 3600, None, None)
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert!(claims.extra.is_empty());
    }

    #[test]
    fn test_issue_id_token_with_extra_round_trips_custom_claims() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert("org_id".to_string(), serde_json::json!("org-7"));

        let token = manager
            .issue_id_token_with_extra(
                identity,
                "client-1",
                Some("nonce123".to_string()),
                3600,
                extra,
            )
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("org_id"),
            Some(&serde_json::json!("org-7"))
        );
        assert_eq!(
            claims.extra.get("nonce"),
            Some(&serde_json::json!("nonce123"))
        );
    }

    #[test]
    fn test_issue_id_token_with_extra_explicit_nonce_wins_over_extra_nonce() {
        // Documents the precedence chosen in `issue_id_token_with_extra`:
        // the explicit `nonce` parameter always overrides a `"nonce"` entry
        // supplied via `extra`.
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let mut extra = HashMap::new();
        extra.insert(
            "nonce".to_string(),
            serde_json::json!("attacker-supplied-nonce"),
        );

        let token = manager
            .issue_id_token_with_extra(
                identity,
                "client-1",
                Some("real-nonce".to_string()),
                3600,
                extra,
            )
            .unwrap();
        let claims = manager.validate_token(&token, None).unwrap();

        assert_eq!(
            claims.extra.get("nonce"),
            Some(&serde_json::json!("real-nonce"))
        );
    }

    #[test]
    fn test_token_manager_ed25519_issuance() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some("my-ed25519-kid"));
    }

    /// Proves #187 and #188 actually compose end-to-end: mint a token with
    /// the Ed25519 constructor, then verify it using ONLY the decoding key
    /// derived from the published JWK (the OKP shape `/jwks.json` would
    /// serve) — not the manager's own internal decoding key. This is the
    /// round trip a real resource server performs against a real JWKS
    /// endpoint.
    #[test]
    fn test_ed25519_token_round_trips_via_published_jwk() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let jwk = manager.public_jwk().unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("my-ed25519-kid"));

        let decoding_key = jwk.to_decoding_key().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["issuer"]);

        let token_data =
            jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "user123");
        assert_eq!(token_data.header.kid.as_deref(), Some("my-ed25519-kid"));
    }

    /// Same shape as `test_asymmetric_manager_validates_its_own_tokens`
    /// (RS256): goes through `validate_token`, the path `/reissue` and
    /// `/userinfo` actually take, rather than the published-JWK path above.
    #[test]
    fn test_ed25519_manager_validates_its_own_tokens() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, Some("issuer".to_string()));
    }

    /// `public_jwk()` for an Ed25519 manager must emit spec-correct OKP JSON
    /// (RFC 8037 §2): `kty: "OKP"`, `crv: "Ed25519"`, `x` present and
    /// base64url-encoded to exactly 32 bytes, and no stray RSA fields (`n`,
    /// `e`) on the wire.
    #[test]
    fn test_ed25519_public_jwk_is_spec_correct_okp_json() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let jwk = manager.public_jwk().unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.alg.as_deref(), Some("EdDSA"));
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.n.is_none());
        assert!(jwk.e.is_none());

        let x = jwk.x.as_ref().expect("OKP JWK must have 'x'");
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let decoded = URL_SAFE_NO_PAD
            .decode(x)
            .expect("'x' must be valid base64url (unpadded)");
        assert_eq!(decoded.len(), 32, "Ed25519 public key must be 32 bytes");

        let value = serde_json::to_value(&jwk).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("kty").unwrap(), "OKP");
        assert_eq!(obj.get("crv").unwrap(), "Ed25519");
        assert_eq!(obj.get("alg").unwrap(), "EdDSA");
        assert!(obj.contains_key("x"));
        assert!(
            !obj.contains_key("n"),
            "OKP JWK must not serialize the RSA 'n' field, got: {}",
            value
        );
        assert!(
            !obj.contains_key("e"),
            "OKP JWK must not serialize the RSA 'e' field, got: {}",
            value
        );
    }

    /// Same spec-correctness check for the RSA shape, unchanged by the OKP
    /// addition: no stray `crv`/`x` fields on the wire.
    #[test]
    fn test_rsa_public_jwk_still_omits_okp_fields() {
        let manager = TokenManager::new_asymmetric(
            TEST_RSA_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-kid-123".to_string()),
        )
        .unwrap();

        let jwk = manager.public_jwk().unwrap();
        let value = serde_json::to_value(&jwk).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("kty").unwrap(), "RSA");
        assert!(obj.contains_key("n"));
        assert!(obj.contains_key("e"));
        assert!(
            !obj.contains_key("crv"),
            "RSA JWK must not serialize the OKP 'crv' field, got: {}",
            value
        );
        assert!(
            !obj.contains_key("x"),
            "RSA JWK must not serialize the OKP 'x' field, got: {}",
            value
        );
    }

    /// Wrong-key rejection: a token signed by one Ed25519 manager must be
    /// rejected when verified against a *different* Ed25519 manager's
    /// published JWK — proving the JWKS round trip actually checks the
    /// signature rather than trivially accepting any well-formed EdDSA JWT.
    #[test]
    fn test_ed25519_token_rejected_by_wrong_key_jwk() {
        let signer = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("kid-a".to_string()),
        )
        .unwrap();
        let other = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM_B,
            Some("issuer".to_string()),
            Some("kid-b".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = signer.issue_user_token(identity, 3600, None, None).unwrap();

        // Verifying with the signer's own manager still works.
        assert!(signer.validate_token(&token, None).is_ok());

        // Verifying with a different key's manager must fail.
        let err = other.validate_token(&token, None).unwrap_err();
        assert!(err.to_string().contains("InvalidSignature"));

        // Same result going through the published-JWK path a real resource
        // server would use.
        let wrong_jwk = other.public_jwk().unwrap();
        let decoding_key = wrong_jwk.to_decoding_key().unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["issuer"]);
        let err = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap_err();
        assert_eq!(
            err.kind(),
            &jsonwebtoken::errors::ErrorKind::InvalidSignature
        );
    }

    /// A tampered payload (claims byte flipped after signing, signature
    /// left as-is) must be rejected, whichever algorithm signed it —
    /// guards against a validator that only checks structural shape.
    #[test]
    fn test_ed25519_tampered_token_rejected() {
        let manager = TokenManager::new_ed25519(
            TEST_ED25519_PRIVATE_KEY_PEM,
            Some("issuer".to_string()),
            Some("my-ed25519-kid".to_string()),
        )
        .unwrap();

        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_user_token(identity, 3600, None, None)
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Corrupt a single character in the base64url payload segment.
        let mut payload = parts[1].to_string();
        let last = payload.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        payload.push(replacement);
        parts[1] = &payload;
        let tampered = parts.join(".");

        let err = manager.validate_token(&tampered, None).unwrap_err();
        assert!(
            err.to_string().contains("InvalidSignature") || err.to_string().contains("Json"),
            "unexpected error for tampered token: {err}"
        );
    }

    /// #206 repro: a stock Keycloak realm with two `oidc-audience-mapper`
    /// entries mints `"aud"` as a JSON array (RFC 7519 §4.1.3 allows this).
    /// `validate_token` calls `jsonwebtoken::decode::<Claims>`, which
    /// deserializes the payload into `Claims` before any of
    /// `jsonwebtoken`'s own validation runs — so this fails at
    /// deserialization, not at a validation check, and `expected_aud: None`
    /// (which turns `Validation::validate_aud` off) makes no difference.
    #[test]
    fn test_validate_token_accepts_array_aud() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));

        let raw_claims = serde_json::json!({
            "iss": "issuer",
            "sub": "user123",
            "aud": ["client-1", "client-2"],
            "exp": (chrono::Utc::now().timestamp() as usize) + 3600,
            "iat": chrono::Utc::now().timestamp() as usize,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &raw_claims,
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let claims = manager
            .validate_token(&token, None)
            .expect("multi-audience subject token must deserialize");
        let aud = claims.aud.expect("aud claim must be present");
        assert!(aud.contains("client-1"));
        assert!(aud.contains("client-2"));
        assert!(!aud.contains("client-3"));
    }

    /// Companion to `test_validate_token_accepts_array_aud`: a subject token
    /// with a plain string `aud` (the shape every token this crate has ever
    /// issued) must keep working exactly as before the `Audience` enum was
    /// introduced.
    #[test]
    fn test_validate_token_still_accepts_string_aud() {
        let manager = TokenManager::new(b"secret", Some("issuer".to_string()));
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };

        let token = manager
            .issue_id_token(identity, "client-1", None, 3600)
            .unwrap();

        let claims = manager.validate_token(&token, None).unwrap();
        let aud = claims.aud.expect("aud claim must be present");
        assert!(aud.contains("client-1"));
        assert!(!aud.contains("client-2"));
    }

    /// Serialization symmetry guarantee: a single audience must still
    /// serialize as a bare JSON string, not a one-element array, so every
    /// token this crate has ever issued (and any consumer relying on that
    /// shape) is unaffected by `Audience` gaining array support.
    #[test]
    fn test_audience_single_round_trips_as_bare_string() {
        let single = Audience::Single("client-1".to_string());
        let serialized = serde_json::to_string(&single).unwrap();
        assert_eq!(serialized, "\"client-1\"");

        let deserialized: Audience = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, single);

        let multiple = Audience::Multiple(vec!["client-1".to_string(), "client-2".to_string()]);
        let serialized_multi = serde_json::to_string(&multiple).unwrap();
        assert_eq!(serialized_multi, "[\"client-1\",\"client-2\"]");

        let deserialized_multi: Audience = serde_json::from_str(&serialized_multi).unwrap();
        assert_eq!(deserialized_multi, multiple);
    }
}
pub mod jwk;
