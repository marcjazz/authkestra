use authkestra_core::{error::AuthError, state::OAuthToken};

/// Orchestrates the Client Credentials Flow (RFC 6749 Section 4.4).
///
/// This flow is used by clients to obtain an access token outside of the context
/// of a user. This is typically used for client-to-client communication.
pub struct ClientCredentialsFlow {
    client_id: String,
    client_secret: String,
    token_url: String,
    http_client: reqwest::Client,
}

impl ClientCredentialsFlow {
    /// Creates a new `ClientCredentialsFlow` instance.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client ID assigned to the client.
    /// * `client_secret` - The client secret assigned to the client.
    /// * `token_url` - The URL of the token endpoint.
    pub fn new(client_id: String, client_secret: String, token_url: String) -> Self {
        Self {
            client_id,
            client_secret,
            token_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Obtains an access token using the client credentials.
    ///
    /// # Arguments
    ///
    /// * `scopes` - An optional list of scopes to request.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `OAuthToken` if successful, or an `AuthError` otherwise.
    pub async fn get_token(&self, scopes: Option<&[&str]>) -> Result<OAuthToken, AuthError> {
        let mut params = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];

        let scope_str;
        if let Some(s) = scopes {
            scope_str = s.join(" ");
            params.push(("scope", &scope_str));
        }

        let response = self
            .http_client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|_| AuthError::Network)?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::Provider(format!(
                "Token request failed: {error_text}"
            )));
        }

        response
            .json::<OAuthToken>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {e}")))
    }
}
