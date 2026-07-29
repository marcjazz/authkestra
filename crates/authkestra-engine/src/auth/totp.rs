use crate::auth::{
    error::AuthError,
    AuthInput,
    AuthMethod,
    CredentialStore,
    state::Identity,
};
use async_trait::async_trait;
use totp_rs::{Algorithm, TOTP};

/// TOTP authentication method.
pub struct TotpAuthMethod<S: CredentialStore> {
    store: S,
}

impl<S: CredentialStore> TotpAuthMethod<S> {
    /// Create a new `TotpAuthMethod` with the given CredentialStore.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Helper to generate a new TOTP secret and return the Base32 secret and registration URI (e.g. for QR codes).
    pub async fn register_totp(
        &self,
        user_id: &str,
        issuer: &str,
        account_name: &str,
    ) -> Result<(String, String), AuthError> {
        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = secret.to_string(); // Base32 encoded secret

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().map_err(|e| AuthError::Internal(e.to_string()))?,
            Some(issuer.to_string()),
            account_name.to_string(),
        ).map_err(|e| AuthError::Internal(e.to_string()))?;

        let url = totp.get_url();

        // Save Base32 secret to store
        let val = serde_json::Value::String(secret_b32.clone());
        self.store.save_credential(user_id, "totp", val).await?;

        Ok((secret_b32, url))
    }
}

#[async_trait]
impl<S: CredentialStore> AuthMethod for TotpAuthMethod<S> {
    fn name(&self) -> &str {
        "totp"
    }

    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::Totp { user_id, code } = input else {
            return Err(AuthError::InvalidInput);
        };

        let creds = self.store.get_credentials(&user_id, "totp").await?;
        let Some(secret_val) = creds.first() else {
            return Err(AuthError::Credentials("TOTP not registered for this user".into()));
        };

        let secret_b32 = secret_val.as_str()
            .ok_or_else(|| AuthError::Internal("Invalid stored TOTP secret".to_string()))?;

        let secret = totp_rs::Secret::Encoded(secret_b32.to_string());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().map_err(|e| AuthError::Internal(e.to_string()))?,
            None,
            "".to_string(),
        ).map_err(|e| AuthError::Internal(e.to_string()))?;

        if totp.check_current(&code).unwrap_or(false) {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: user_id.clone(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            })
        } else {
            Err(AuthError::Credentials("Invalid TOTP code".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockStore {
        creds: Mutex<HashMap<String, Vec<serde_json::Value>>>,
    }

    #[async_trait]
    impl CredentialStore for MockStore {
        async fn save_credential(&self, user_id: &str, cred_type: &str, data: serde_json::Value) -> Result<(), AuthError> {
            let key = format!("{user_id}:{cred_type}");
            self.creds.lock().unwrap().entry(key).or_default().push(data);
            Ok(())
        }

        async fn get_credentials(&self, user_id: &str, cred_type: &str) -> Result<Vec<serde_json::Value>, AuthError> {
            let key = format!("{user_id}:{cred_type}");
            Ok(self.creds.lock().unwrap().get(&key).cloned().unwrap_or_default())
        }

        async fn update_credential(&self, _credential_id: &str, _data: serde_json::Value) -> Result<(), AuthError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_totp_flow() {
        let store = MockStore { creds: Mutex::new(HashMap::new()) };
        let totp_method = TotpAuthMethod::new(store);

        // Register a TOTP key for user
        let (secret_b32, uri) = totp_method.register_totp("user123", "Authkestra", "user123").await.unwrap();
        assert!(!secret_b32.is_empty());
        assert!(uri.contains("otpauth://totp/"));

        // Get the current TOTP code using the totp crate
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(secret_b32).to_bytes().unwrap(),
            None,
            "".to_string(),
        ).unwrap();
        let code = totp.generate_current().unwrap();

        // Verify successful auth
        let identity = totp_method.authenticate(AuthInput::Totp {
            user_id: "user123".to_string(),
            code: code.clone(),
        }).await.unwrap();

        assert_eq!(identity.external_id, "user123");

        // Verify failure on wrong code
        let err = totp_method.authenticate(AuthInput::Totp {
            user_id: "user123".to_string(),
            code: "000000".to_string(),
        }).await;
        assert!(err.is_err());
    }
}
