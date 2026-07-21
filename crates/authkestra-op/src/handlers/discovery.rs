use serde::{Deserialize, Serialize};

/// OpenID Connect Discovery metadata document.
/// Served at `/.well-known/openid-configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    /// The OP's Issuer identifier.
    pub issuer: String,
    /// URL of the OP's OAuth 2.0 Authorization Endpoint.
    pub authorization_endpoint: String,
    /// URL of the OP's OAuth 2.0 Token Endpoint.
    pub token_endpoint: String,
    /// URL of the OP's JSON Web Key Set document.
    pub jwks_uri: String,
    /// URL of the OP's UserInfo Endpoint.
    pub userinfo_endpoint: Option<String>,
    /// JSON array containing a list of the OAuth 2.0 scope values that this server supports.
    pub scopes_supported: Vec<String>,
    /// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
    pub response_types_supported: Vec<String>,
    /// JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
    pub response_modes_supported: Vec<String>,
    /// JSON array containing a list of the OAuth 2.0 grant type values that this OP supports.
    pub grant_types_supported: Vec<String>,
    /// JSON array containing a list of the Subject Identifier types that this OP supports.
    pub subject_types_supported: Vec<String>,
    /// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply.
    pub claims_supported: Vec<String>,
}

use crate::config::OpConfig;

impl OidcDiscovery {
    /// Creates a discovery document reflecting the provided OP configuration.
    pub fn from_config(config: &OpConfig) -> Self {
        Self {
            issuer: config.issuer.clone(),
            authorization_endpoint: config.authorization_endpoint(),
            token_endpoint: config.token_endpoint(),
            jwks_uri: config.jwks_url(),
            userinfo_endpoint: Some(config.userinfo_endpoint()),
            scopes_supported: config.scopes_supported.clone(),
            response_types_supported: config.response_types_supported.clone(),
            response_modes_supported: vec!["query".to_string()],
            grant_types_supported: config.grant_types_supported.clone(),
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec![config.id_token_signing_alg.clone()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "none".to_string(), // For public clients (PKCE)
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "name".to_string(),
                "email".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_from_config() {
        let config = OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
        };

        let doc = OidcDiscovery::from_config(&config);

        assert_eq!(doc.issuer, "https://auth.example.com");
        assert_eq!(
            doc.authorization_endpoint,
            "https://auth.example.com/authorize"
        );
        assert_eq!(doc.token_endpoint, "https://auth.example.com/token");
        assert_eq!(doc.jwks_uri, "https://auth.example.com/jwks.json");
        assert_eq!(
            doc.userinfo_endpoint,
            Some("https://auth.example.com/userinfo".to_string())
        );

        assert_eq!(doc.scopes_supported.len(), 2);
        assert!(doc.response_types_supported.contains(&"code".to_string()));
        assert!(doc
            .grant_types_supported
            .contains(&"authorization_code".to_string()));
        assert!(!doc
            .grant_types_supported
            .contains(&"client_credentials".to_string()));
        assert!(doc
            .id_token_signing_alg_values_supported
            .contains(&"RS256".to_string()));
    }
}
