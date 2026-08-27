use crate::auth::{error::AuthError, state::OAuthToken};
use crate::client_assertion::{self, CLIENT_ASSERTION_TYPE_JWT_BEARER};
use jsonwebtoken::{Algorithm, EncodingKey};

/// How a `ClientCredentialsFlow` authenticates itself to the token endpoint.
///
/// An enum rather than a trait object: there are exactly two RFC-defined
/// shapes this flow speaks (a shared secret, or a self-signed assertion), and
/// both need direct access to this struct's private fields (`client_id`,
/// `token_url`) to do their job — an `AuthMethod`-style trait would need to
/// hand those back in, for no abstraction benefit over a closed enum only
/// this module matches on.
enum ClientAuth {
    /// `client_secret_post` (RFC 6749 §2.3.1): the shared secret is sent as
    /// a form parameter alongside the request.
    Secret(String),
    /// `private_key_jwt` (RFC 7523 §2.2): no shared secret is sent at all —
    /// instead, a freshly minted assertion proves possession of the private
    /// half of a key the authorization server already has the public half
    /// of. See [`crate::client_assertion::mint_client_assertion`].
    PrivateKeyJwt {
        encoding_key: EncodingKey,
        alg: Algorithm,
        /// Stamped onto the assertion's header `kid`, if the server needs
        /// it to select among several registered keys. `None` is valid only
        /// when the server has exactly one registered key for this client —
        /// see `authkestra_op::client_assertion::select_key`.
        kid: Option<String>,
    },
}

/// Orchestrates the Client Credentials Flow (RFC 6749 Section 4.4).
///
/// This flow is used by clients to obtain an access token outside of the context
/// of a user. This is typically used for client-to-client communication.
#[non_exhaustive]
pub struct ClientCredentialsFlow {
    client_id: String,
    auth: ClientAuth,
    token_url: String,
    http_client: reqwest::Client,
}

impl ClientCredentialsFlow {
    /// Creates a new `ClientCredentialsFlow` instance authenticating with a
    /// shared `client_secret` (RFC 6749 §2.3.1).
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client ID assigned to the client.
    /// * `client_secret` - The client secret assigned to the client.
    /// * `token_url` - The URL of the token endpoint.
    pub fn new(client_id: String, client_secret: String, token_url: String) -> Self {
        Self {
            client_id,
            auth: ClientAuth::Secret(client_secret),
            token_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Creates a new `ClientCredentialsFlow` instance authenticating with
    /// `private_key_jwt` (RFC 7523 §2.2) instead of a shared secret.
    ///
    /// Use this when the client cannot hold a shared secret at all — e.g. a
    /// backend service that only ever authenticates from a keystore holding
    /// an asymmetric keypair, with just the public half registered against
    /// this `client_id` at the authorization server. `get_token` mints a
    /// fresh assertion JWT (`iss`/`sub` = `client_id`, `aud` = `token_url`, a
    /// new `jti`, and `exp` bounded by
    /// [`crate::client_assertion::MAX_CLIENT_ASSERTION_LIFETIME_SECS`]) on
    /// every call and sends it as `client_assertion` alongside
    /// `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
    /// in place of `client_secret`.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client ID assigned to the client.
    /// * `signing_key` - The private key to sign assertions with. Must match
    ///   `alg` (e.g. an Ed25519 key for [`Algorithm::EdDSA`]).
    /// * `alg` - The signature algorithm `signing_key` signs with. This
    ///   crate's own OP (`authkestra_op::client_assertion`) derives the
    ///   algorithm it will accept from the client's *registered public key*,
    ///   never from this header, so `alg` here must agree with whatever key
    ///   type was registered.
    /// * `token_url` - The URL of the token endpoint; also the `aud` claim
    ///   minted into every assertion.
    pub fn new_private_key_jwt(
        client_id: String,
        signing_key: EncodingKey,
        alg: Algorithm,
        token_url: String,
    ) -> Self {
        Self {
            client_id,
            auth: ClientAuth::PrivateKeyJwt {
                encoding_key: signing_key,
                alg,
                kid: None,
            },
            token_url,
            http_client: reqwest::Client::new(),
        }
    }

    /// Stamps `kid` onto the header of every assertion minted by
    /// `private_key_jwt` authentication, so a server with several keys
    /// registered for this client can tell which one signed it (see
    /// `authkestra_op::client_assertion::select_key`).
    ///
    /// A no-op when this flow was constructed via [`Self::new`] — there is
    /// no assertion to stamp a `kid` onto when authenticating with a shared
    /// secret.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        if let ClientAuth::PrivateKeyJwt { kid: slot, .. } = &mut self.auth {
            *slot = Some(kid.into());
        }
        self
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
    #[tracing::instrument(skip(self, scopes), fields(client_id = %self.client_id))]
    pub async fn get_token(&self, scopes: Option<&[&str]>) -> Result<OAuthToken, AuthError> {
        let mut params: Vec<(&str, String)> = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", self.client_id.clone()),
        ];

        match &self.auth {
            ClientAuth::Secret(secret) => {
                tracing::debug!("authenticating with client_secret_post");
                params.push(("client_secret", secret.clone()));
            }
            ClientAuth::PrivateKeyJwt {
                encoding_key,
                alg,
                kid,
            } => {
                tracing::debug!("authenticating with private_key_jwt; minting a fresh assertion");
                let assertion = client_assertion::mint_client_assertion(
                    &self.client_id,
                    &self.token_url,
                    encoding_key,
                    *alg,
                    kid.as_deref(),
                    client_assertion::MAX_CLIENT_ASSERTION_LIFETIME_SECS,
                )
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to mint private_key_jwt client assertion");
                    e
                })?;
                params.push((
                    "client_assertion_type",
                    CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string(),
                ));
                params.push(("client_assertion", assertion));
            }
        }

        if let Some(s) = scopes {
            params.push(("scope", s.join(" ")));
        }

        let response = self
            .http_client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "network error requesting token");
                AuthError::Network
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            tracing::warn!(error = %error_text, "token request failed");
            return Err(AuthError::Provider(format!(
                "Token request failed: {error_text}"
            )));
        }

        response.json::<OAuthToken>().await.map_err(|e| {
            tracing::error!(error = %e, "failed to parse token response");
            AuthError::Provider(format!("Failed to parse token response: {e}"))
        })
    }
}
