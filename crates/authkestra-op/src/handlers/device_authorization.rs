
use crate::config::OpConfig;
use crate::device::{DeviceCodeSession, DeviceCodeStatus};
use crate::store::OpStore;
use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Request payload for the device authorization endpoint.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// The client identifier.
    pub client_id: Option<String>,
    /// The requested scope.
    pub scope: Option<String>,
}

/// Response payload for a successful device authorization request.
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,
    /// The end-user verification code.
    pub user_code: String,
    /// The end-user verification URI on the authorization server.
    pub verification_uri: String,
    /// A verification URI that includes the user_code (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// The lifetime in seconds of the device_code and user_code.
    pub expires_in: u64,
    /// The minimum amount of time in seconds that the client SHOULD wait between polling requests.
    pub interval: u64,
}

/// Response payload for an error in the device authorization endpoint.
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationErrorResponse {
    /// A single ASCII error code.
    pub error: String,
    /// Human-readable text providing additional information.
    pub error_description: String,
}

/// Handles a device authorization request.
pub async fn handle_device_authorization(
    req: DeviceAuthorizationRequest,
    auth_header: Option<&str>,
    config: &OpConfig,
    op_store: &dyn OpStore,
) -> Result<DeviceAuthorizationResponse, DeviceAuthorizationErrorResponse> {
    let mut client_id = req.client_id.clone();

    // Try extract basic auth
    if let Some(auth) = auth_header {
        if let Some(stripped) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(stripped) {
                if let Ok(creds) = String::from_utf8(decoded) {
                    if let Some((id, _)) = creds.split_once(':') {
                        client_id = Some(id.to_string());
                    }
                }
            }
        }
    }

    let client_id = match client_id {
        Some(id) => id,
        None => {
            return Err(DeviceAuthorizationErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
    };

    let client = match op_store.find_client(&client_id).await {
        Ok(Some(c)) => c,
        _ => {
            return Err(DeviceAuthorizationErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
    };

    if !client.allows_grant_type(crate::client::GrantType::DeviceCode) {
        return Err(DeviceAuthorizationErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client not authorized for device flow".to_string(),
        });
    }

    let scope = req.scope.unwrap_or_default();

    // Generate codes
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    let device_code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);

    // Simple 8-character alphanumeric string
    let user_code = uuid::Uuid::new_v4().to_string()[0..8].to_uppercase();

    let session = DeviceCodeSession {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: client_id.clone(),
        scope,
        expires_at: Utc::now() + Duration::seconds(config.device_code_ttl_secs as i64),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };

    if op_store.store_device_code(session).await.is_err() {
        return Err(DeviceAuthorizationErrorResponse {
            error: "server_error".to_string(),
            error_description: "Internal server error".to_string(),
        });
    }

    Ok(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri: config.device_verification_uri(),
        verification_uri_complete: None,
        expires_in: config.device_code_ttl_secs,
        interval: 5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, GrantType};
    use authkestra_engine::store::KvStore;

    use crate::device::DeviceCodeStatus;
    use crate::handlers::token::{handle_token, TokenRequest};

    use authkestra_engine::auth::state::Identity;
    use authkestra_engine::token::TokenManager;
    use std::collections::HashMap;

    fn test_config() -> OpConfig {
        OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        }
    }

    #[tokio::test]
    async fn test_device_authorization_flow() {
        let config = test_config();
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        let devices = authkestra_engine::store::memory::MemoryStore::<
            crate::device::DeviceCodeSession,
        >::new();
        let refresh_tokens =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let tokens = TokenManager::new(b"super_secret_key_that_is_long_enough_for_hmac", None);

        clients
            .set(
                "device_client",
                ClientRegistration {
                    client_id: "device_client".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::DeviceCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        // 1. Initiate device flow
        let req = DeviceAuthorizationRequest {
            client_id: Some("device_client".to_string()),
            scope: Some("openid".to_string()),
        };

        let res = handle_device_authorization(
            req,
            None,
            &config,
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh_tokens.clone(),
                devices.clone(),
            ),
        )
        .await
        .unwrap();

        let device_code = res.device_code.clone();
        let user_code = res.user_code.clone();

        // 2. Poll /token while pending
        let token_req = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            code: None,
            device_code: Some(device_code.clone()),
            redirect_uri: None,
            client_id: Some("device_client".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            actor_token: None,
            actor_token_type: None,
            audience: None,
            requested_token_type: None,
            subject_token: None,
            subject_token_type: None,
        };

        let token_res = handle_token(
            token_req.clone(),
            None,
            &config,
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh_tokens.clone(),
                devices.clone(),
            ),
            &tokens,
        )
        .await;

        let err = token_res.unwrap_err();
        assert_eq!(err.error, "authorization_pending");

        // 3. Simulate user approval
        let mut session = devices
            .get_device_code(&device_code)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.user_code, user_code);

        session.status = DeviceCodeStatus::Approved(Identity {
            provider_id: "test".to_string(),
            external_id: "user123".to_string(),
            username: Some("user123".to_string()),
            email: None,
            attributes: HashMap::new(),
        });
        devices.update_device_code(session).await.unwrap();

        // 4. Poll /token again (should succeed)
        let token_res_success = handle_token(
            token_req,
            None,
            &config,
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh_tokens.clone(),
                devices.clone(),
            ),
            &tokens,
        )
        .await
        .unwrap();

        assert_eq!(token_res_success.token_type, "Bearer");
        assert!(token_res_success.id_token.is_some());
    }
}
