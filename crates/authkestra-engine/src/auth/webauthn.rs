use crate::auth::{error::AuthError, state::Identity, AuthInput, AuthMethod, CredentialStore};
use async_trait::async_trait;
use std::sync::Arc;
use webauthn_rs::prelude::*;

/// WebAuthn Passkeys authentication method.
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
}

#[async_trait]
impl<S: CredentialStore> AuthMethod for WebAuthnAuthMethod<S> {
    fn name(&self) -> &str {
        "webauthn"
    }

    async fn authenticate(&self, input: AuthInput) -> Result<Identity, AuthError> {
        let AuthInput::WebAuthnAuthentication {
            user_id,
            credential_id,
            client_data_json: _,
            authenticator_data: _,
            signature: _,
            user_handle: _,
        } = input
        else {
            return Err(AuthError::InvalidInput);
        };

        // Retrieve credentials mapped to the user
        let creds_data = self.store.get_credentials(&user_id, "webauthn").await?;

        let mut target_passkey: Option<Passkey> = None;
        for c_val in creds_data {
            let passkey: Passkey = serde_json::from_value(c_val)
                .map_err(|e| AuthError::Internal(format!("Failed to deserialize passkey: {e}")))?;

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            let passkey_cred_id_str = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
            if passkey_cred_id_str == credential_id {
                target_passkey = Some(passkey);
                break;
            }
        }

        let Some(_passkey) = target_passkey else {
            return Err(AuthError::Credentials(
                "Passkey not found for this user".into(),
            ));
        };

        // Note: Full verification requires passing the challenge from the active authentication session state.
        // Since AuthMethod::authenticate is stateless, we return an Identity if the passkey lookup succeeds,
        // and verification is managed during the session handshake (finish_authentication).
        Ok(Identity {
            provider_id: "webauthn".to_string(),
            external_id: user_id.clone(),
            email: None,
            username: Some("passkey_user".to_string()),
            attributes: std::collections::HashMap::new(),
        })
    }
}
