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

/// Intermediate state for OAuth2/OIDC flows, stored in an encrypted cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2State {
    /// CSRF protection state parameter
    pub state: String,
    /// OIDC nonce to prevent replay attacks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// PKCE code verifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    /// Optional redirect URL to go back to after flow completion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_url: Option<String>,
    /// The provider identifier
    pub provider_id: String,
    /// Expiration timestamp (seconds since epoch)
    pub expires_at: i64,
}

impl OAuth2State {
    /// Encrypts the state into a base64-encoded string.
    pub fn encrypt(&self, key: &[u8; 32]) -> Result<String, crate::auth::error::AuthError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let json = serde_json::to_vec(self).map_err(|e| {
            crate::auth::error::AuthError::Token(format!("Failed to serialize state: {e}"))
        })?;

        let ciphertext = cipher
            .encrypt(&nonce, json.as_slice())
            .map_err(|e| crate::auth::error::AuthError::Token(format!("Encryption failed: {e}")))?;

        let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            combined,
        ))
    }

    /// Decrypts the state from a base64-encoded string.
    pub fn decrypt(encoded: &str, key: &[u8; 32]) -> Result<Self, crate::auth::error::AuthError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let combined = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|e| {
                crate::auth::error::AuthError::Token(format!("Failed to decode base64 state: {e}"))
            })?;

        if combined.len() < 12 {
            return Err(crate::auth::error::AuthError::Token(
                "Invalid encrypted state".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce_arr: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
            crate::auth::error::AuthError::Token("Invalid nonce length".to_string())
        })?;
        let nonce = Nonce::from(nonce_arr);
        let cipher = Aes256Gcm::new(key.into());

        let decrypted = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| crate::auth::error::AuthError::Token(format!("Decryption failed: {e}")))?;

        let state: Self = serde_json::from_slice(&decrypted).map_err(|e| {
            crate::auth::error::AuthError::Token(format!("Failed to deserialize state: {e}"))
        })?;

        if chrono::Utc::now().timestamp() > state.expires_at {
            return Err(crate::auth::error::AuthError::Token(
                "State expired".to_string(),
            ));
        }

        Ok(state)
    }
}
