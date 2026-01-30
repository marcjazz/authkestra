use authly_core::{AuthError, OAuthToken};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

/// Represents the response from the device authorization endpoint.
/// Defined in RFC 8628 Section 3.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,
    /// The end-user verification code.
    pub user_code: String,
    /// The end-user verification URI on the authorization server.
    pub verification_uri: String,
    /// A verification URI that includes the "user_code" (or other information)
    /// to optimize the end-user interaction.
    pub verification_uri_complete: Option<String>,
    /// The lifetime in seconds of the "device_code" and "user_code".
    pub expires_in: u64,
    /// The minimum amount of time in seconds that the client SHOULD wait
    /// between polling requests to the token endpoint.
    pub interval: Option<u64>,
}

/// Orchestrates the Device Authorization Flow (RFC 8628).
pub struct DeviceFlow {
    client_id: String,
    device_authorization_url: String,
    token_url: String,
    http_client: reqwest::Client,
}

impl DeviceFlow {
    /// Creates a new `DeviceFlow` instance.
    pub fn new(
        client_id: String,
        device_authorization_url: String,
        token_url: String,
    ) -> Self {
        Self {
            client_id,
            device_authorization_url,
            token_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Initiates the device authorization request.
    /// Returns a `DeviceAuthorizationResponse` which contains the codes and URIs
    /// to be displayed to the user.
    pub async fn initiate_device_authorization(
        &self,
        scopes: &[&str],
    ) -> Result<DeviceAuthorizationResponse, AuthError> {
        let scope_param = scopes.join(" ");

        let response = self
            .http_client
            .post(&self.device_authorization_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", &self.client_id),
                ("scope", &scope_param),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::Provider(format!(
                "Device authorization request failed: {}",
                error_text
            )));
        }

        response
            .json::<DeviceAuthorizationResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse device authorization response: {}", e)))
    }

    /// Polls the token endpoint until an access token is granted or an error occurs.
    /// This function respects the `interval` specified by the provider and handles
    /// common device flow errors like `authorization_pending` and `slow_down`.
    pub async fn poll_for_token(
        &self,
        device_code: &str,
        interval: Option<u64>,
    ) -> Result<OAuthToken, AuthError> {
        let mut current_interval = interval.unwrap_or(5);

        loop {
            let response = self
                .http_client
                .post(&self.token_url)
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", &self.client_id),
                    ("device_code", &device_code.to_string()),
                    ("grant_type", &"urn:ietf:params:oauth:grant-type:device_code".to_string()),
                ])
                .send()
                .await
                .map_err(|_| AuthError::Network)?;

            let status = response.status();
            
            if status.is_success() {
                return response
                    .json::<OAuthToken>()
                    .await
                    .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {}", e)));
            } else {
                let error_resp: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|_| AuthError::Provider("Failed to parse error response".into()))?;
                
                let error = error_resp["error"].as_str().unwrap_or("unknown_error");

                match error {
                    "authorization_pending" => {
                        // Keep polling
                    }
                    "slow_down" => {
                        current_interval += 5;
                    }
                    "access_denied" => {
                        return Err(AuthError::Provider("Access denied by user".into()));
                    }
                    "expired_token" => {
                        return Err(AuthError::Provider("Device code expired".into()));
                    }
                    _ => {
                        return Err(AuthError::Provider(format!("Token polling failed: {}", error)));
                    }
                }
            }

            sleep(Duration::from_secs(current_interval)).await;
        }
    }
}
