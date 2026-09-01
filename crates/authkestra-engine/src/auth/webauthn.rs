use crate::auth::{error::AuthError, state::Identity, AuthInput, AuthMethod, CredentialStore};
use async_trait::async_trait;
use std::sync::Arc;
use webauthn_rs::prelude::*;

/// WebAuthn Passkeys authentication method.
#[non_exhaustive]
pub struct WebAuthnAuthMethod<S: CredentialStore> {
    webauthn: Arc<Webauthn>,
    store: S,
}

impl<S: CredentialStore> WebAuthnAuthMethod<S> {
    /// Create a new `WebAuthnAuthMethod` with a WebAuthn config and a CredentialStore.
    pub fn new(webauthn: Arc<Webauthn>, store: S) -> Self {
        Self { webauthn, store }
    }

    /// Helper to generate a registration challenge.
    pub fn start_register(
        &self,
        user_id: &str,
        username: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), AuthError> {
        let user_unique_id = Uuid::parse_str(user_id).unwrap_or_else(|_| Uuid::new_v4());

        self.webauthn
            .start_passkey_registration(user_unique_id, username, username, None)
            .map_err(|e| AuthError::Internal(format!("WebAuthn registration failed to start: {e}")))
    }

    /// Helper to finalize passkey registration and return the serialized Passkey to store.
    pub async fn finish_register(
        &self,
        user_id: &str,
        reg_response: RegisterPublicKeyCredential,
        state: PasskeyRegistration,
    ) -> Result<Passkey, AuthError> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg_response, &state)
            .map_err(|e| {
                AuthError::Credentials(format!("WebAuthn registration verification failed: {e}"))
            })?;

        let val = serde_json::to_value(&passkey)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize passkey: {e}")))?;

        self.store.save_credential(user_id, "webauthn", val).await?;
        Ok(passkey)
    }

    /// Helper to finalize passkey authentication
    pub fn finish_authentication(
        &self,
        auth_response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<webauthn_rs::prelude::AuthenticationResult, AuthError> {
        self.webauthn
            .finish_passkey_authentication(auth_response, state)
            .map_err(|e| AuthError::Credentials(format!("WebAuthn authentication failed: {e}")))
    }
}

impl<S: CredentialStore + 'static> crate::auth::WebAuthnStarter for WebAuthnAuthMethod<S> {
    fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), AuthError> {
        self.webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|e| AuthError::Internal(format!("WebAuthn auth failed to start: {e}")))
    }
}

#[async_trait]
impl<S: CredentialStore + 'static> AuthMethod for WebAuthnAuthMethod<S> {
    fn name(&self) -> &str {
        "webauthn"
    }

    fn as_webauthn_starter(&self) -> Option<&dyn crate::auth::WebAuthnStarter> {
        Some(self)
    }

    fn is_mfa_equivalent(&self) -> bool {
        true
    }

    async fn has_enrolled(&self, user_id: &str) -> Result<bool, AuthError> {
        let creds = self.store.get_credentials(user_id, "webauthn").await?;
        Ok(!creds.is_empty())
    }

    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::WebAuthnAuthentication {
            user_id,
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            auth_state_json,
        } = input
        else {
            return Err(AuthError::InvalidInput);
        };

        let auth_state_json = auth_state_json.ok_or_else(|| {
            AuthError::Credentials("Missing authentication state from session".into())
        })?;

        let auth_state: PasskeyAuthentication = serde_json::from_str(&auth_state_json)
            .map_err(|e| AuthError::Internal(format!("Invalid authentication state: {e}")))?;

        let auth_response_json = serde_json::json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "authenticatorData": authenticator_data,
                "signature": signature,
                "userHandle": user_handle,
            }
        });

        let auth_response: PublicKeyCredential = serde_json::from_value(auth_response_json)
            .map_err(|e| AuthError::Internal(format!("Failed to parse credential: {e}")))?;

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let cred_id_bytes = URL_SAFE_NO_PAD
            .decode(&credential_id)
            .map_err(|_| AuthError::InvalidInput)?;

        // Retrieve credentials mapped to the user
        let creds_data = self.store.get_credentials(&user_id, "webauthn").await?;

        let mut target_passkey: Option<Passkey> = None;
        for c_val in creds_data {
            let passkey: Passkey = serde_json::from_value(c_val)
                .map_err(|e| AuthError::Internal(format!("Failed to deserialize passkey: {e}")))?;

            if passkey.cred_id().as_ref() == cred_id_bytes {
                target_passkey = Some(passkey);
                break;
            }
        }

        let Some(passkey) = target_passkey else {
            return Err(AuthError::Credentials(
                "Passkey not found for this user".into(),
            ));
        };

        // Cryptographically verify the signature
        let auth_result = self.finish_authentication(&auth_response, &auth_state)?;

        // Update the credential signature counter
        // `update_credential` needs the passkey (which contains the updated counter)
        // Since `finish_passkey_authentication` updates the counter in the `auth_result.passkey`? No, wait.
        // Let's check webauthn-rs to see what `finish_authentication` returns, or if `passkey` itself needs to be updated.
        // Actually, webauthn-rs `AuthenticationResult` usually contains the updated passkey which must be saved.
        // We'll update it by converting to JSON and saving it back.
        let mut updated_passkey = passkey.clone();
        updated_passkey.update_credential(&auth_result);

        let updated_val = serde_json::to_value(&updated_passkey).map_err(|e| {
            AuthError::Internal(format!("Failed to serialize updated passkey: {e}"))
        })?;

        // We need the credential_id to update, we can use the base64 string
        if let Err(e) = self
            .store
            .update_credential(&credential_id, updated_val)
            .await
        {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                credential_id = %credential_id,
                "Failed to update WebAuthn signature counter in the credential store"
            );
            return Err(AuthError::Internal(
                "Failed to persist security state".into(),
            ));
        }

        Ok(Identity {
            provider_id: "webauthn".to_string(),
            external_id: user_id.clone(),
            email: None,
            username: Some("passkey_user".to_string()),
            attributes: std::collections::HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::WebAuthnStarter;
    use std::sync::Arc;

    struct DummyCredentialStore;
    #[async_trait]
    impl CredentialStore for DummyCredentialStore {
        async fn save_credential(
            &self,
            _user: &str,
            _type: &str,
            _cred: serde_json::Value,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        async fn get_credentials(
            &self,
            _user: &str,
            _type: &str,
        ) -> Result<Vec<serde_json::Value>, AuthError> {
            Ok(vec![])
        }
        async fn update_credential(
            &self,
            _id: &str,
            _cred: serde_json::Value,
        ) -> Result<(), AuthError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_webauthn_auth_method() {
        let site_url = Url::parse("http://localhost").unwrap();
        let builder = WebauthnBuilder::new("localhost", &site_url).unwrap();
        let webauthn = Arc::new(builder.build().unwrap());
        let store = DummyCredentialStore;

        let method = WebAuthnAuthMethod::new(webauthn, store);

        assert_eq!(method.name(), "webauthn");
        assert!(method.is_mfa_equivalent());
        assert!(method.as_webauthn_starter().is_some());

        let enrolled = method.has_enrolled("user-1").await.unwrap();
        assert!(!enrolled);

        let (challenge, _passkey_reg) = method.start_register("user-1", "user-1").unwrap();
        assert_eq!(challenge.public_key.rp.id, "localhost");

        let _ = method.start_authentication(&[]).unwrap();

        let invalid_input = method
            .authenticate(AuthInput::Password {
                identifier: "a".into(),
                password: "b".into(),
            })
            .await;
        assert!(matches!(invalid_input, Err(AuthError::InvalidInput)));
    }
}
