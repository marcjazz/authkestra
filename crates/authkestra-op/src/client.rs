use crate::error::OpError;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// OAuth2/OIDC grant types a client may be permitted to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantType {
    /// Standard authorization code grant (with or without PKCE).
    AuthorizationCode,
    /// Refresh token grant.
    RefreshToken,
    /// Client credentials grant (machine-to-machine). See RFC-003 §9, `OP.7`.
    ClientCredentials,
    /// Device Code grant (RFC 8628).
    DeviceCode,
    /// Token Exchange grant (RFC 8693).
    TokenExchange,
    /// A custom grant type.
    Custom(String),
}

impl Serialize for GrantType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            GrantType::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            GrantType::Custom(custom) => custom,
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for GrantType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "authorization_code" => GrantType::AuthorizationCode,
            "refresh_token" => GrantType::RefreshToken,
            "client_credentials" => GrantType::ClientCredentials,
            "urn:ietf:params:oauth:grant-type:device_code" => GrantType::DeviceCode,
            "urn:ietf:params:oauth:grant-type:token-exchange" => GrantType::TokenExchange,
            _ => GrantType::Custom(s),
        })
    }
}

/// The single client-authentication method a client is bound to at the token
/// endpoint (OIDC Core §9 / RFC 7591 `token_endpoint_auth_method`).
///
/// A registration names **one** method and the token endpoint accepts only
/// that one. This is not pedantry: a client that may authenticate *either*
/// with a shared secret *or* with a signed assertion is only ever as strong
/// as the weaker of the two, so an attacker holding the leaked secret of a
/// `private_key_jwt` client could simply present it instead and never touch
/// the private key. Binding the registration to one method removes that
/// downgrade entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// Shared secret presented in the HTTP `Authorization: Basic` header.
    ClientSecretBasic,
    /// Shared secret presented as the `client_secret` form field.
    ClientSecretPost,
    /// A JWT assertion signed by the client's private key and verified
    /// against [`ClientRegistration::jwks`] (RFC 7523 §2.2). See
    /// [`crate::client_assertion`].
    PrivateKeyJwt,
    /// No client authentication at all — public clients only, where PKCE
    /// rather than a credential is what protects the exchange.
    #[serde(rename = "none")]
    NoAuth,
}

/// A registered OAuth2/OIDC client application.
///
/// `redirect_uris` are matched **exactly** (no prefix/wildcard matching) —
/// see RFC-003 §7. This is the single most important invariant in this
/// type; do not relax it for convenience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    /// Public client identifier.
    pub client_id: String,
    /// Hash of the client secret. Never store or log the plaintext secret.
    /// `None` for public clients (e.g. SPAs, native apps using PKCE).
    pub client_secret_hash: Option<String>,
    /// Exact-match redirect URIs this client is permitted to use.
    pub redirect_uris: Vec<String>,
    /// Grant types this client is permitted to use.
    pub grant_types: Vec<GrantType>,
    /// Scopes this client is permitted to request.
    pub scopes: Vec<String>,
    /// Retained for wire/storage compatibility, but no longer consulted:
    /// PKCE is mandatory for every client on the authorization code grant,
    /// unconditionally, per OAuth 2.1 §4.1 (authkestra#273) — both
    /// `handlers::authorize` and `handlers::token` enforce it regardless of
    /// this value.
    pub require_pkce: bool,
    /// Downstream audiences (resources) this client is permitted to target
    /// during token exchange.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// The client-authentication method this client is bound to at `/token`.
    ///
    /// `None` means the registration predates this field. Such a client keeps
    /// exactly the historical behaviour — a shared secret if
    /// `client_secret_hash` is set, no authentication otherwise — and is
    /// **never** accepted via `private_key_jwt`, which has to be opted into
    /// explicitly. Enforcement lives in `handlers::token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    /// The client's public keys as an inline JWK Set (`{"keys": [...]}`) —
    /// the public half of the keypair used for `private_key_jwt`. There is
    /// deliberately no `jwks_uri` counterpart; see the module docs of
    /// [`crate::client_assertion`] for why.
    ///
    /// Kept as raw JSON rather than a typed `JwkSet` for the same reason
    /// `attestation::EnrolmentChallenge::public_jwk` is: a typed parse
    /// silently drops members it has no field for — including a smuggled
    /// private `d` — so the raw value is re-validated from scratch at every
    /// use through `attestation::parse_public_jwk`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
}

impl ClientRegistration {
    /// Returns true if `redirect_uri` exactly matches one of this client's
    /// registered URIs. Intentionally a plain `==` comparison — no
    /// normalization, no prefix matching.
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == redirect_uri)
    }

    /// Checks if the client is allowed to use a specific grant type.
    pub fn allows_grant_type(&self, grant_type: &GrantType) -> bool {
        self.grant_types.contains(grant_type)
    }

    /// Verifies the provided secret against the stored argon2 hash in constant time.
    pub fn verify_secret(&self, secret: &str) -> bool {
        if let Some(hash_str) = &self.client_secret_hash {
            let parsed_hash = match PasswordHash::new(hash_str) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse client secret hash");
                    return false;
                }
            };
            Argon2::default()
                .verify_password(secret.as_bytes(), &parsed_hash)
                .is_ok()
        } else {
            // No secret stored means public client; shouldn't be used for confidential flows
            false
        }
    }
}

/// Storage interface for registered clients.
///
/// Mirrors the existing `SessionStore` pattern in `authkestra-engine`:
/// async trait, pluggable backends, in-memory implementation ships first.
#[async_trait]
pub trait ClientStore: Send + Sync {
    /// Look up a client by its `client_id`. Returns `Ok(None)` (not an
    /// error) if the client does not exist — callers map that to
    /// `OpError::UnknownClient`.
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError>;
}

use authkestra_engine::store::KvStore;

#[async_trait]
impl<S> ClientStore for S
where
    S: KvStore<ClientRegistration>,
{
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
        tracing::trace!(client_id, "looking up client");
        self.get(client_id).await.map_err(|e| {
            tracing::error!(error = %e, "failed to lookup client");
            OpError::Storage
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        PasswordHasher,
    };

    #[test]
    fn test_verify_secret_valid() {
        let password = b"super_secret";
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password, &salt)
            .unwrap()
            .to_string();

        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: Some(password_hash),
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        assert!(client.verify_secret("super_secret"));
    }

    #[test]
    fn test_verify_secret_invalid() {
        let password = b"super_secret";
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password, &salt)
            .unwrap()
            .to_string();

        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: Some(password_hash),
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        assert!(!client.verify_secret("wrong_secret"));
    }

    #[test]
    fn test_verify_secret_public_client() {
        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        assert!(!client.verify_secret("some_secret"));
    }

    #[test]
    fn test_grant_type_serialization() {
        let client = ClientRegistration {
            client_id: "test".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![
                GrantType::ClientCredentials,
                GrantType::AuthorizationCode,
                GrantType::Custom("my_custom_grant".to_string()),
            ],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        };

        let serialized = serde_json::to_string(&client).unwrap();
        let deserialized: ClientRegistration = serde_json::from_str(&serialized).unwrap();

        assert_eq!(client.grant_types, deserialized.grant_types);
        assert!(serialized.contains("\"client_credentials\""));
        assert!(serialized.contains("\"authorization_code\""));
        assert!(serialized.contains("\"my_custom_grant\""));
    }
}
