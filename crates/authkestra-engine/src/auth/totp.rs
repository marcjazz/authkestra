use crate::auth::{error::AuthError, state::Identity, AuthInput, AuthMethod, CredentialStore};
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
        let secret_b32 = match secret.to_encoded() {
            totp_rs::Secret::Encoded(s) => s,
            _ => unreachable!(),
        }; // Base32 encoded secret
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            Some(issuer.to_string()),
            account_name.to_string(),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        let url = totp.get_url();

        // Save Base32 secret to store
        let credential_id = uuid::Uuid::new_v4().to_string();

        let val = serde_json::json!({
            "credential_id": credential_id,
            "secret": secret_b32.clone(),
            "last_used_step": 0
        });
        self.store.save_credential(user_id, "totp", val).await?;

        Ok((secret_b32, url))
    }
}

#[async_trait]
impl<S: CredentialStore> AuthMethod for TotpAuthMethod<S> {
    fn name(&self) -> &str {
        "totp"
    }

    async fn has_enrolled(&self, user_id: &str) -> Result<bool, AuthError> {
        let creds = self.store.get_credentials(user_id, "totp").await?;
        Ok(!creds.is_empty())
    }

    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::Totp { user_id, code } = input else {
            return Err(AuthError::InvalidInput);
        };

        let creds = self.store.get_credentials(&user_id, "totp").await?;
        let Some(secret_val) = creds.first() else {
            return Err(AuthError::Credentials(
                "TOTP not registered for this user".into(),
            ));
        };

        // secret_val could be a string (old implementation backward compatibility) or an object
        let (secret_b32, credential_id, last_used_step) = if let Some(s) = secret_val.as_str() {
            (s.to_string(), None, 0)
        } else if let Some(obj) = secret_val.as_object() {
            let secret = obj
                .get("secret")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let cred_id = obj
                .get("credential_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let step = obj
                .get("last_used_step")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            (secret, cred_id, step)
        } else {
            return Err(AuthError::Internal(
                "Invalid stored TOTP secret format".to_string(),
            ));
        };

        if secret_b32.is_empty() {
            return Err(AuthError::Internal(
                "Invalid stored TOTP secret".to_string(),
            ));
        }

        let secret = totp_rs::Secret::Encoded(secret_b32.clone());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            None,
            "".to_string(),
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;

        // Time calculations for replay protection
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .as_secs();

        let basestep = t / totp.step - (totp.skew as u64);
        let mut matched_step = None;
        for i in 0..(totp.skew as u16) * 2 + 1 {
            let step = basestep + (i as u64);
            let step_time = step * totp.step;
            if totp.generate(step_time) == code && step > last_used_step {
                matched_step = Some(step);
                break;
            }
        }

        if let Some(step) = matched_step {
            if let Some(cred_id) = credential_id {
                let update_data = serde_json::json!({
                    "last_used_step": step
                });
                if let Err(e) = self.store.update_credential(&cred_id, update_data).await {
                    tracing::error!(
                        error = %e,
                        user_id = %user_id,
                        credential_id = %cred_id,
                        "Failed to update TOTP last_used_step in the credential store"
                    );
                    return Err(AuthError::Internal(
                        "Failed to persist security state".into(),
                    ));
                }
            }

            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: user_id.clone(),
                email: None,
                username: None,
                attributes: std::collections::HashMap::new(),
            })
        } else {
            Err(AuthError::Credentials(
                "Invalid or replayed TOTP code".into(),
            ))
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
        async fn save_credential(
            &self,
            user_id: &str,
            cred_type: &str,
            data: serde_json::Value,
        ) -> Result<(), AuthError> {
            let key = format!("{user_id}:{cred_type}");
            self.creds
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push(data);
            Ok(())
        }

        async fn get_credentials(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> Result<Vec<serde_json::Value>, AuthError> {
            let key = format!("{user_id}:{cred_type}");
            Ok(self
                .creds
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default())
        }

        async fn update_credential(
            &self,
            credential_id: &str,
            data: serde_json::Value,
        ) -> Result<(), AuthError> {
            let mut creds = self.creds.lock().unwrap();
            for val_list in creds.values_mut() {
                for val in val_list.iter_mut() {
                    if let Some(obj) = val.as_object_mut() {
                        if obj.get("credential_id").and_then(|v| v.as_str()) == Some(credential_id)
                        {
                            if let Some(update_obj) = data.as_object() {
                                for (k, v) in update_obj {
                                    obj.insert(k.clone(), v.clone());
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_totp_flow() {
        let store = MockStore {
            creds: Mutex::new(HashMap::new()),
        };
        let totp_method = TotpAuthMethod::new(store);

        // Register a TOTP key for user
        let (secret_b32, uri) = totp_method
            .register_totp("user123", "Engine", "user123")
            .await
            .unwrap();
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
        )
        .unwrap();
        let code = totp.generate_current().unwrap();

        // Verify successful auth
        let identity = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code.clone(),
            })
            .await
            .unwrap();

        assert_eq!(identity.external_id, "user123");

        // Verify failure on wrong code
        let err = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: "000000".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Credentials(_)));

        // Verify replay protection (re-submitting the exact same valid code should fail)
        let replay_err = totp_method
            .authenticate(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: code.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(replay_err, AuthError::Credentials(_)));
    }
}
