use crate::auth::error::AuthError;
use async_trait::async_trait;

/// Pluggable storage backend for user credentials (Passwords, Passkeys, TOTP keys).
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Save a generic credential serialized as a JSON Value mapped to a user and credential type.
    async fn save_credential(
        &self,
        user_id: &str,
        cred_type: &str,
        data: serde_json::Value,
    ) -> Result<(), AuthError>;

    /// Retrieve all credentials of a specific type mapped to a user.
    async fn get_credentials(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> Result<Vec<serde_json::Value>, AuthError>;

    /// Update transient fields of an existing credential (e.g. signature counter).
    async fn update_credential(
        &self,
        credential_id: &str,
        data: serde_json::Value,
    ) -> Result<(), AuthError>;
}
