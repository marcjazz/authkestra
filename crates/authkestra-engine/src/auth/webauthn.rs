use crate::auth::{error::AuthError, state::Identity, AuthInput, AuthMethod, CredentialStore};
use async_trait::async_trait;
use std::sync::Arc;
use webauthn_rs::prelude::*;

/// Namespace for authkestra-derived WebAuthn user handles.
///
/// This is `uuid5(NAMESPACE_URL, "https://authkestra.dev/webauthn/user-handle")`,
/// so the value is reproducible outside Rust and will never change.
pub const USER_HANDLE_NAMESPACE: Uuid = Uuid::from_u128(0xef84b322_b2dd_5ab4_aea2_8221f829229e);

/// Derive a stable WebAuthn user handle from an application user id.
///
/// The user handle (`user.id` in `PublicKeyCredentialCreationOptions`) is baked
/// into the credential by the authenticator at registration time and returned as
/// `response.userHandle` by discoverable ("usernameless") sign-in. It must
/// therefore be stable for the lifetime of the account and resolvable back to
/// exactly one user, which rules out generating a fresh value per registration.
///
/// The rule is deterministic and total:
///
/// * a `user_id` that already parses as a UUID is returned unchanged, so
///   applications with UUID user ids keep byte-identical handles;
/// * anything else (CUID, ULID, prefixed id, integer, email) is hashed into a
///   version 5 UUID over [`USER_HANDLE_NAMESPACE`].
///
/// Because it is UUIDv5, an application can reproduce the same handle in any
/// language to build its own handle-to-user index for discoverable login.
///
/// ```
/// use authkestra_engine::auth::webauthn::derive_user_handle;
///
/// // A UUID user id is passed through untouched.
/// let uuid_id = "67e55044-10b1-426f-9247-bb680e5fe0c8";
/// assert_eq!(derive_user_handle(uuid_id).to_string(), uuid_id);
///
/// // A non-UUID id yields the same handle every time.
/// let cuid = "clh3k2j1x0000qwer1234asdf";
/// assert_eq!(derive_user_handle(cuid), derive_user_handle(cuid));
///
/// // Different ids yield different handles.
/// assert_ne!(derive_user_handle("user-a"), derive_user_handle("user-b"));
/// ```
#[must_use]
pub fn derive_user_handle(user_id: &str) -> Uuid {
    Uuid::parse_str(user_id)
        .unwrap_or_else(|_| Uuid::new_v5(&USER_HANDLE_NAMESPACE, user_id.as_bytes()))
}

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
    ///
    /// The WebAuthn user handle is derived from `user_id` with
    /// [`derive_user_handle`], which is stable across calls. Use
    /// [`WebAuthnAuthMethod::start_register_with_handle`] when the application
    /// allocates handles itself, or when the display name differs from the
    /// username (this method passes `username` for both).
    pub fn start_register(
        &self,
        user_id: &str,
        username: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), AuthError> {
        self.start_register_with_handle(derive_user_handle(user_id), username, username)
    }

    /// Helper to generate a registration challenge for an explicit user handle.
    ///
    /// `handle` becomes `user.id` in the returned
    /// `PublicKeyCredentialCreationOptions`. The authenticator stores it inside
    /// the credential and returns it as `response.userHandle` on every later
    /// assertion, so it MUST be stable for the lifetime of the account and MUST
    /// map back to exactly one user. Prefer this method when the application
    /// keeps its own handle-to-user index; otherwise use
    /// [`WebAuthnAuthMethod::start_register`], which derives a stable handle
    /// from the user id.
    pub fn start_register_with_handle(
        &self,
        handle: Uuid,
        username: &str,
        display_name: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), AuthError> {
        tracing::debug!(user_handle = %handle, username, "starting WebAuthn registration");

        self.webauthn
            .start_passkey_registration(handle, username, display_name, None)
            .map_err(|e| {
                tracing::warn!(error = %e, user_handle = %handle, "WebAuthn registration failed to start");
                AuthError::Internal(format!("WebAuthn registration failed to start: {e}"))
            })
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
        async fn delete_credential(
            &self,
            _user: &str,
            _type: &str,
            _credential_id: &str,
        ) -> Result<bool, AuthError> {
            Ok(false)
        }
        async fn delete_credentials(&self, _user: &str, _type: &str) -> Result<u64, AuthError> {
            Ok(0)
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

    #[test]
    fn derive_user_handle_is_stable_for_a_non_uuid_id() {
        // A CUID, which is what many applications actually use for user ids.
        let cuid = "clh3k2j1x0000qwer1234asdf";

        let first = derive_user_handle(cuid);
        let second = derive_user_handle(cuid);

        assert_eq!(
            first, second,
            "the same non-UUID user id must always derive the same handle"
        );
        assert_eq!(first.get_version_num(), 5, "handle must be a UUIDv5");
    }

    #[test]
    fn derive_user_handle_separates_distinct_ids() {
        assert_ne!(
            derive_user_handle("clh3k2j1x0000qwer1234asdf"),
            derive_user_handle("clh3k2j1x0000qwer1234asdg"),
            "distinct user ids must not collide onto one handle"
        );
    }

    #[test]
    fn derive_user_handle_passes_uuid_ids_through_unchanged() {
        let id = "67e55044-10b1-426f-9247-bb680e5fe0c8";

        assert_eq!(
            derive_user_handle(id),
            Uuid::parse_str(id).unwrap(),
            "an id that is already a UUID must be used verbatim"
        );
    }

    #[test]
    fn derive_user_handle_matches_the_documented_namespace() {
        // Pins the derivation rule: changing the namespace or the hash would
        // orphan every passkey already registered under a derived handle.
        assert_eq!(
            USER_HANDLE_NAMESPACE.to_string(),
            "ef84b322-b2dd-5ab4-aea2-8221f829229e"
        );
        assert_eq!(
            derive_user_handle("clh3k2j1x0000qwer1234asdf").to_string(),
            "ed6b6951-8a79-5ac9-a322-471f5427dc08"
        );
    }

    #[test]
    fn start_register_emits_a_stable_user_handle_for_a_non_uuid_id() {
        let site_url = Url::parse("http://localhost").unwrap();
        let webauthn = Arc::new(
            WebauthnBuilder::new("localhost", &site_url)
                .unwrap()
                .build()
                .unwrap(),
        );
        let method = WebAuthnAuthMethod::new(webauthn, DummyCredentialStore);

        let cuid = "clh3k2j1x0000qwer1234asdf";
        let (first, _) = method.start_register(cuid, "ada").unwrap();
        let (second, _) = method.start_register(cuid, "ada").unwrap();

        assert_eq!(
            first.public_key.user.id, second.public_key.user.id,
            "two registrations for one user must share a user handle"
        );
        assert_eq!(
            first.public_key.user.id.as_ref(),
            derive_user_handle(cuid).as_bytes(),
            "the challenge must carry the derived handle"
        );

        let (other, _) = method
            .start_register("clh3k2j1x0000qwer1234asdg", "grace")
            .unwrap();
        assert_ne!(
            first.public_key.user.id, other.public_key.user.id,
            "distinct users must not share a user handle"
        );
    }

    #[test]
    fn start_register_with_handle_uses_the_caller_handle_and_display_name() {
        let site_url = Url::parse("http://localhost").unwrap();
        let webauthn = Arc::new(
            WebauthnBuilder::new("localhost", &site_url)
                .unwrap()
                .build()
                .unwrap(),
        );
        let method = WebAuthnAuthMethod::new(webauthn, DummyCredentialStore);

        let handle = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        let (challenge, _) = method
            .start_register_with_handle(handle, "ada", "Ada Lovelace")
            .unwrap();

        assert_eq!(challenge.public_key.user.id.as_ref(), handle.as_bytes());
        assert_eq!(challenge.public_key.user.name, "ada");
        assert_eq!(challenge.public_key.user.display_name, "Ada Lovelace");
    }
}
