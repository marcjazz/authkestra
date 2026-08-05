use crate::auth::{error::AuthError, state::Identity};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

        // The decoding key MUST be derived from the public half (`n`, `e`),
        // never from the private key PEM: `DecodingKey::from_rsa_pem`
        // expects a PUBLIC key PEM, and handing it a private key silently
        // produces a key that cannot verify what `encoding_key` above just
        // signed (jsonwebtoken#180 upstream in this crate's terms — see
        // https://github.com/marcjazz/authkestra/issues/180). `n`/`e` are
        // already computed for the JWK a few lines below, so this reuses
        // them rather than re-deriving anything.
        let decoding_key = DecodingKey::from_rsa_components(&n, &e)
            .map_err(|e| AuthError::Token(e.to_string()))?;

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
            aud,
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
            aud: Some(client_id.to_string()),
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
            aud,
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

    /// Regression test for #180: an asymmetric `TokenManager` must be able
    /// to verify the tokens it just signed, via its OWN `validate_token`
    /// (not by round-tripping through the published JWK, which is the path
    /// `test_token_manager_asymmetric_issuance` above exercises and which
    /// stayed green throughout #180 — it is a genuinely independent
    /// verifier, unaffected by `decoding_key` being built from the wrong
    /// key half). Before the fix, `decoding_key` was built with
    /// `DecodingKey::from_rsa_pem(private_key_pem)` — a PRIVATE key handed
    /// to an API that expects a PUBLIC one — so every call here failed with
    /// `InvalidRsaKey`/`InvalidSignature` regardless of `exp`. This is
    /// exactly the path `handle_reissue_start` (`authkestra-op`) and
    /// `handle_userinfo` call.
    #[test]
    fn asymmetric_manager_can_verify_the_tokens_it_just_signed() {
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
            Some("kid-1".to_string()),
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

        let claims = manager
            .validate_token(&token, None)
            .expect("the manager must be able to verify a token it just signed");
        assert_eq!(claims.sub, "user123");
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
        assert_eq!(claims.aud, Some("client-1".to_string()));
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
        assert_eq!(claims.aud, Some("client-1".to_string()));

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
}
pub mod jwk;
