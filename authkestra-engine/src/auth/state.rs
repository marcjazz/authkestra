use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A unified identity structure returned by all providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The provider identifier (e.g., "github", "google")
    pub provider_id: String,
    /// The unique ID of the user within the provider's system
    pub external_id: String,
    /// The user's email address, if available and authorized
    pub email: Option<String>,
    /// The user's username or display name, if available
    pub username: Option<String>,
    /// Additional provider-specific attributes
    pub attributes: HashMap<String, String>,
}

/// Represents the tokens returned by an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// The access token used for API requests
    pub access_token: String,
    /// The type of token (usually "Bearer")
    pub token_type: String,
    /// Seconds until the access token expires
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// The refresh token used to obtain new access tokens
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The scopes granted by the user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The OIDC ID Token
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}
