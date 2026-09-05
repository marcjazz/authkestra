use crate::auth::error::AuthError;
use async_trait::async_trait;

/// Pluggable storage backend for user credentials (Passwords, Passkeys, TOTP keys).
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Save a generic credential serialized as a JSON Value mapped to a user and credential type.
    ///
    /// The `credential_id` (or `id`) field of `data`, when present, identifies the credential:
    /// an implementation is expected to *replace* an existing credential stored under the same
    /// id rather than store a second copy alongside it. Callers rely on this to rotate a
    /// credential without a window in which the user has none — TOTP re-enrollment writes the
    /// new secret under a stable id before retiring the old ones. A store that appends instead
    /// will keep serving the superseded credential from [`Self::get_credentials`].
    ///
    /// Credentials with no id are always appended.
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

    /// Delete a specific credential by its id for a user and credential type.
    ///
    /// Returns `Ok(true)` if the credential existed and was deleted,
    /// `Ok(false)` if the credential did not exist,
    /// and `Err(AuthError::Unsupported)` if the store does not implement deletion.
    ///
    /// The default implementation returns `Err(AuthError::Unsupported)`.
    /// Out-of-tree stores that cannot implement deletion will receive an error
    /// rather than a silent no-op, making revocation failures visible to the caller.
    async fn delete_credential(
        &self,
        user_id: &str,
        cred_type: &str,
        credential_id: &str,
    ) -> Result<bool, AuthError> {
        let _ = (user_id, cred_type, credential_id);
        Err(AuthError::Unsupported)
    }

    /// Delete all credentials of a specific type for a user.
    ///
    /// Returns `Ok(n)` where `n` is the number of credentials deleted (0 if none existed),
    /// and `Err(AuthError::Unsupported)` if the store does not implement deletion.
    ///
    /// The default implementation returns `Err(AuthError::Unsupported)`.
    /// Out-of-tree stores that cannot implement deletion will receive an error
    /// rather than a silent no-op, making revocation failures visible to the caller.
    async fn delete_credentials(&self, user_id: &str, cred_type: &str) -> Result<u64, AuthError> {
        let _ = (user_id, cred_type);
        Err(AuthError::Unsupported)
    }
}
