use crate::client::{ClientRegistration, GrantType, TokenEndpointAuthMethod};
use crate::client_assertion::{
    peek_client_assertion_subject, verify_client_assertion, CLIENT_ASSERTION_TYPE_JWT_BEARER,
};
use crate::config::OpConfig;
use crate::error::OpError;
use crate::refresh::RefreshToken;
use crate::store::OpStore;
use authkestra_engine::token::TokenManager;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Request payload for the token endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct TokenRequest {
    /// OAuth2 grant type.
    pub grant_type: String,
    /// The authorization code received from the authorization endpoint.
    pub code: Option<String>,
    /// The device code received from the device authorization endpoint.
    pub device_code: Option<String>,
    /// The redirect URI used in the authorization request.
    pub redirect_uri: Option<String>,
    /// The client identifier (can also be provided via Basic Auth).
    pub client_id: Option<String>,
    /// The client secret (can also be provided via Basic Auth).
    pub client_secret: Option<String>,
    /// The PKCE code verifier used if a challenge was provided.
    pub code_verifier: Option<String>,
    /// The requested scope.
    pub scope: Option<String>,
    /// The refresh token (for refresh_token grant type).
    pub refresh_token: Option<String>,

    // Token Exchange fields (RFC 8693)
    /// The subject token being exchanged.
    pub subject_token: Option<String>,
    /// An identifier that indicates the type of the security token in the `subject_token` parameter.
    pub subject_token_type: Option<String>,
    /// The actor token being used for delegation.
    pub actor_token: Option<String>,
    /// An identifier that indicates the type of the security token in the `actor_token` parameter.
    pub actor_token_type: Option<String>,
    /// An identifier for the type of the requested security token.
    pub requested_token_type: Option<String>,
    /// The logical name of the target service where the client intends to use the requested security token.
    pub audience: Option<String>,

    // Asymmetric client authentication (RFC 7523 §2.2)
    /// The JWT the client signed with its own private key to authenticate
    /// itself. See [`crate::client_assertion`].
    pub client_assertion: Option<String>,
    /// Must be
    /// [`crate::client_assertion::CLIENT_ASSERTION_TYPE_JWT_BEARER`] when
    /// `client_assertion` is present.
    pub client_assertion_type: Option<String>,
}

/// Success response for the token endpoint.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: String,
    /// The type of the token, typically "Bearer".
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// The ID token, if `openid` scope was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The refresh token, if `offline_access` was requested or using refresh grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The scope of the granted tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Error response for the token endpoint.
#[derive(Debug, Serialize)]
pub struct TokenErrorResponse {
    /// The OAuth2 error code.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: String,
}

/// Processes a token exchange request (`/token` endpoint).
///
/// This handles different OAuth2 grant types such as `authorization_code`,
/// `client_credentials`, and `refresh_token`, issuing appropriate access tokens,
/// ID tokens, and refresh tokens based on the request and client configuration.
#[allow(clippy::too_many_arguments)]
pub async fn handle_token(
    req: TokenRequest,
    auth_header: Option<&str>,
    config: &OpConfig,
    op_store: &dyn OpStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    tracing::debug!(grant_type = %req.grant_type, "Processing token exchange request");

    // 0. Work out which credential — if any — the request presents.
    let credential = extract_credential(
        req.client_secret.as_deref(),
        req.client_assertion.as_deref(),
        req.client_assertion_type.as_deref(),
        auth_header,
    )?;

    let client_id = match resolve_client_id(req.client_id.as_deref(), &credential) {
        Some(id) => id,
        None => {
            tracing::warn!("Missing client_id in token request");
            return Err(TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
    };

    // 1. Client validation
    let client = match op_store.find_client(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!(client_id = %client_id, "Unknown client ID during token exchange");
            return Err(TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error finding client");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    // 2. Client authentication, against the one method this client is bound
    //    to. A credential of a different kind is a failure and never a
    //    fallback — see `authenticate_client`.
    if let Err(e) = authenticate_client(&client, &credential, config, op_store).await {
        tracing::warn!(client_id = %client_id, error = %e, "Client authentication failed");
        return Err(TokenErrorResponse {
            error: "invalid_client".to_string(),
            error_description: "Client authentication failed".to_string(),
        });
    }

    match req.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code(req, client_id, client, config, op_store, tokens).await
        }
        "client_credentials" => {
            handle_client_credentials(req, client_id, client, config, tokens).await
        }
        "refresh_token" => {
            // Routed through the `OpStore` seam (mirrors `handle_custom_grant`)
            // so an integrator can substitute its own refresh handling —
            // e.g. to re-mint an `id_token` or apply a custom rotation
            // policy — without forking this crate. The default
            // implementation reproduces the built-in behavior below via
            // `default_handle_refresh_token`.
            op_store
                .handle_refresh_token(req, client_id, client, config, tokens)
                .await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code(req, client_id, client, config, op_store, tokens).await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            // Routed through the `OpStore` seam (mirrors `handle_refresh_token`)
            // so an integrator can stamp custom claims onto the exchanged
            // token, or issue an id_token differently, without forking this
            // crate. The default implementation reproduces the built-in
            // behavior below via `default_handle_token_exchange`.
            op_store
                .handle_token_exchange(req, client_id, client, config, tokens)
                .await
        }
        _ => {
            if !client.allows_grant_type(&crate::client::GrantType::Custom(req.grant_type.clone()))
            {
                tracing::warn!(client_id = %client_id, grant_type = %req.grant_type, "Client not authorized for custom grant");
                return Err(TokenErrorResponse {
                    error: "unauthorized_client".to_string(),
                    error_description: "Client is not authorized to use this grant type"
                        .to_string(),
                });
            }

            // Forward any other grant type to the custom grant handler
            op_store
                .handle_custom_grant(
                    &req.grant_type,
                    req.clone(),
                    client_id,
                    client,
                    config,
                    tokens,
                )
                .await
        }
    }
}

/// The one credential a token request presents, and where it came from.
///
/// One value rather than a handful of `Option`s, so that "presented two
/// credentials" is a case the code has to answer explicitly instead of an
/// undocumented precedence order — and so the transport (`Basic` header vs
/// request body) survives long enough to be checked against what the client
/// registered.
#[derive(Debug)]
pub(crate) enum PresentedCredential {
    /// A shared secret in the `Authorization: Basic` header. Carries the
    /// `client_id` too, since that header is where it came from.
    SecretBasic { client_id: String, secret: String },
    /// A shared secret in the `client_secret` form field.
    SecretPost { secret: String },
    /// A JWT assertion signed by the client's own private key (RFC 7523).
    Assertion(String),
    /// No credential at all: a public client, or an unauthenticated request.
    NoCredential,
}

/// Extracts the credential the request presents, refusing more than one.
///
/// RFC 6749 §2.3 forbids a client from using more than one authentication
/// method in a single request, and RFC 7521 §4.2 repeats it for assertions.
/// Accepting several and picking a winner by precedence is exactly how a
/// downgrade slips in — an attacker holding a leaked secret appends it to a
/// request and the weaker credential wins — so this is a hard error.
///
/// Note that `client_id` is not a credential: sending it in the body
/// alongside a `Basic` header, or alongside an assertion, is fine.
pub(crate) fn extract_credential(
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
    auth_header: Option<&str>,
) -> Result<PresentedCredential, TokenErrorResponse> {
    let basic = auth_header
        .and_then(|auth| auth.strip_prefix("Basic "))
        .and_then(|stripped| {
            base64::engine::general_purpose::STANDARD
                .decode(stripped)
                .ok()
        })
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|creds| {
            creds
                .split_once(':')
                .map(|(id, secret)| (id.to_string(), secret.to_string()))
        });

    // An empty `client_secret=` form field is not a presented credential; some
    // HTTP clients emit one for an absent value.
    let post = client_secret
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let assertion = match client_assertion {
        Some(assertion) => match client_assertion_type {
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) => Some(assertion.to_string()),
            _ => {
                tracing::warn!(
                    "client_assertion presented with a missing or unsupported \
                     client_assertion_type"
                );
                return Err(TokenErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: format!(
                        "client_assertion_type must be {CLIENT_ASSERTION_TYPE_JWT_BEARER}"
                    ),
                });
            }
        },
        None => None,
    };

    let presented =
        u8::from(basic.is_some()) + u8::from(post.is_some()) + u8::from(assertion.is_some());
    if presented > 1 {
        tracing::warn!(
            presented,
            "token request presents more than one client authentication method"
        );
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Only one client authentication method may be used per request"
                .to_string(),
        });
    }

    Ok(match (basic, post, assertion) {
        (Some((client_id, secret)), _, _) => PresentedCredential::SecretBasic { client_id, secret },
        (_, Some(secret), _) => PresentedCredential::SecretPost { secret },
        (_, _, Some(assertion)) => PresentedCredential::Assertion(assertion),
        (None, None, None) => PresentedCredential::NoCredential,
    })
}

/// Works out which client the request claims to be.
///
/// With an assertion and no `client_id` parameter — which RFC 7521 §4.2 makes
/// optional — the `sub` is read out of the *unverified* assertion. That is
/// safe because it only chooses which registration to verify against: the
/// assertion must then be signed by that client's registered key, and its
/// `iss`/`sub` re-checked against that client's `client_id`. Naming someone
/// else's `client_id` here just picks the key the forgery will fail against.
pub(crate) fn resolve_client_id(
    req_client_id: Option<&str>,
    credential: &PresentedCredential,
) -> Option<String> {
    match credential {
        PresentedCredential::SecretBasic { client_id, .. } => Some(client_id.clone()),
        PresentedCredential::Assertion(assertion) => req_client_id
            .map(|s| s.to_string())
            .or_else(|| peek_client_assertion_subject(assertion)),
        _ => req_client_id.map(|s| s.to_string()),
    }
}

/// Authenticates the client against the single method its registration names.
///
/// The shape of this match is the security property: a registration binds one
/// method, and a credential of any other kind is rejected outright rather than
/// verified on its own merits. Without that, a `private_key_jwt` client whose
/// (unused, perhaps long-forgotten) secret leaked could be impersonated with
/// that secret, and a `client_secret_*` client with a stale registered key
/// could be impersonated with an assertion — a downgrade in both directions.
///
/// `token_endpoint_auth_method: None` is the pre-existing behaviour for
/// registrations that predate the field, preserved exactly: a stored secret
/// hash means a secret is required (from either transport, since those
/// registrations never said which), and no stored hash means no client
/// authentication. Such a registration is never accepted via
/// `private_key_jwt` — asymmetric authentication has to be opted into.
pub(crate) async fn authenticate_client(
    client: &ClientRegistration,
    credential: &PresentedCredential,
    config: &OpConfig,
    op_store: &dyn OpStore,
) -> Result<(), OpError> {
    use PresentedCredential as Cred;
    use TokenEndpointAuthMethod as Method;

    match (client.token_endpoint_auth_method, credential) {
        (Some(Method::PrivateKeyJwt), Cred::Assertion(assertion)) => {
            // RFC 7523 §3 accepts the token endpoint URL as `aud`; OIDC Core
            // §9 also allows the issuer identifier, and real clients emit
            // both.
            let verified = verify_client_assertion(
                assertion,
                client,
                &[config.token_endpoint(), config.issuer.clone()],
            )?;

            // Spending the `jti` is what turns a captured assertion from a
            // bearer credential valid for its whole lifetime into a
            // single-use one.
            if !op_store
                .record_client_assertion_jti(&verified.jti, verified.expires_at)
                .await?
            {
                tracing::warn!(
                    client_id = %client.client_id,
                    "client assertion jti has already been spent — replay refused"
                );
                return Err(OpError::ClientAssertionReplayed);
            }

            tracing::info!(
                client_id = %client.client_id,
                "client authenticated via private_key_jwt"
            );
            Ok(())
        }
        (Some(Method::ClientSecretBasic), Cred::SecretBasic { secret, .. })
        | (Some(Method::ClientSecretPost), Cred::SecretPost { secret }) => {
            if client.verify_secret(secret) {
                Ok(())
            } else {
                Err(OpError::InvalidClientCredentials)
            }
        }
        (Some(Method::NoAuth), Cred::NoCredential) => Ok(()),

        // Registered for one method, presenting another — including the right
        // secret over the wrong transport, which OIDC Core §9 treats as two
        // distinct methods.
        (Some(_), _) => Err(OpError::AuthMethodNotPermitted),

        // --- Registrations predating `token_endpoint_auth_method` ---
        (None, Cred::Assertion(_)) => Err(OpError::AuthMethodNotPermitted),
        (None, Cred::SecretBasic { secret, .. }) | (None, Cred::SecretPost { secret }) => {
            if client.client_secret_hash.is_none() {
                // Public client: a secret it never registered is ignored, as
                // it always has been.
                Ok(())
            } else if client.verify_secret(secret) {
                Ok(())
            } else {
                Err(OpError::InvalidClientCredentials)
            }
        }
        (None, Cred::NoCredential) => {
            if client.client_secret_hash.is_some() {
                Err(OpError::InvalidClientCredentials)
            } else {
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_device_code(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    op_store: &dyn OpStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::device::DeviceCodeStatus;

    if !client.allows_grant_type(&GrantType::DeviceCode) {
        tracing::warn!(client_id = %client_id, "Client not authorized for device_code grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use device_code grant type".to_string(),
        });
    }

    let device_code_str = match req.device_code.as_deref() {
        Some(c) => c,
        None => {
            tracing::warn!("Missing device_code in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "device_code is required".to_string(),
            });
        }
    };

    let session = match op_store.get_device_code(device_code_str).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid device code".to_string(),
            });
        }
        Err(_) => {
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    if session.client_id != client_id {
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Device code issued to a different client".to_string(),
        });
    }

    if session.is_expired(Utc::now()) {
        return Err(TokenErrorResponse {
            error: "expired_token".to_string(),
            error_description: "Device code expired".to_string(),
        });
    }

    match session.status {
        DeviceCodeStatus::Pending => {
            let now = Utc::now();
            let mut updated = session.clone();
            updated.last_polled_at = Some(now);
            let _ = op_store.store_device_code(updated).await;

            if let Some(last_poll) = session.last_polled_at {
                if now < last_poll + chrono::Duration::seconds(5) {
                    return Err(TokenErrorResponse {
                        error: "slow_down".to_string(),
                        error_description: "Polling too frequently".to_string(),
                    });
                }
            }

            Err(TokenErrorResponse {
                error: "authorization_pending".to_string(),
                error_description: "User has not yet approved the request".to_string(),
            })
        }
        DeviceCodeStatus::Denied | DeviceCodeStatus::Approved(_) => {
            // Atomically consume to prevent race conditions
            let consumed = match op_store.consume_device_code(device_code_str).await {
                Ok(Some(s)) => s,
                _ => {
                    return Err(TokenErrorResponse {
                        error: "invalid_grant".to_string(),
                        error_description: "Device code is invalid or already consumed".to_string(),
                    });
                }
            };

            if let DeviceCodeStatus::Approved(identity) = consumed.status {
                let expires_in = config.access_token_ttl_secs;
                let scope_opt = if session.scope.is_empty() {
                    None
                } else {
                    Some(session.scope.clone())
                };

                let access_token = match tokens.issue_user_token(
                    identity.clone(),
                    expires_in,
                    scope_opt.clone(),
                    Some(client_id.clone()),
                ) {
                    Ok(t) => t,
                    Err(_) => {
                        return Err(TokenErrorResponse {
                            error: "server_error".to_string(),
                            error_description: "Failed to issue access token".to_string(),
                        });
                    }
                };

                let id_token = if session.scope.contains("openid") {
                    match tokens.issue_id_token(identity.clone(), &client_id, None, expires_in) {
                        Ok(t) => Some(t),
                        Err(_) => {
                            return Err(TokenErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "Failed to issue ID token".to_string(),
                            });
                        }
                    }
                } else {
                    None
                };

                let mut issued_refresh_token = None;
                if session.scope.contains("offline_access") {
                    let refresh_val = uuid::Uuid::new_v4().to_string();
                    let rt = RefreshToken {
                        token: refresh_val.clone(),
                        client_id: client_id.clone(),
                        identity,
                        scope: session.scope,
                        expires_at: Utc::now() + chrono::Duration::days(30),
                    };
                    if op_store.store_token(rt).await.is_ok() {
                        issued_refresh_token = Some(refresh_val);
                    }
                }

                Ok(TokenResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in,
                    id_token,
                    refresh_token: issued_refresh_token,
                    scope: scope_opt,
                })
            } else {
                Err(TokenErrorResponse {
                    error: "access_denied".to_string(),
                    error_description: "User denied the request".to_string(),
                })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_authorization_code(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    op_store: &dyn OpStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    if !client.allows_grant_type(&GrantType::AuthorizationCode) {
        tracing::warn!(client_id = %client_id, "Client not authorized for authorization_code grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use authorization_code grant type"
                .to_string(),
        });
    }

    let code_str = req.code.as_ref().unwrap();
    let req_redirect_uri = req.redirect_uri.as_deref().unwrap_or("");

    // 3. Consume the code atomically
    let auth_code = match op_store.consume_code(code_str).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!("Invalid or expired authorization code");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Authorization code is invalid or already used".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error consuming authorization code");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    // Check expiration explicitly just in case the store didn't
    if chrono::Utc::now() > auth_code.expires_at {
        tracing::warn!("Authorization code expired");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code has expired".to_string(),
        });
    }

    // 4. Validate code was issued to this client
    if auth_code.client_id != client_id {
        tracing::warn!(
            expected_client = %auth_code.client_id,
            actual_client = %client_id,
            "Client ID mismatch during token exchange"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code was not issued to this client".to_string(),
        });
    }

    // 5. Validate redirect_uri matches
    if auth_code.redirect_uri != req_redirect_uri {
        tracing::warn!(
            expected_uri = %auth_code.redirect_uri,
            actual_uri = %req_redirect_uri,
            "Redirect URI mismatch during token exchange"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Redirect URI does not match the one used during authorization"
                .to_string(),
        });
    }

    // 6. PKCE Enforcement
    if let Some(challenge) = &auth_code.code_challenge {
        let verifier = req.code_verifier.as_deref().unwrap_or("");
        if verifier.is_empty() {
            tracing::warn!("Missing code_verifier for PKCE-secured code");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "code_verifier is required".to_string(),
            });
        }

        let method = auth_code.code_challenge_method.as_deref().unwrap_or("");
        if method != "S256" {
            tracing::error!(
                method = %method,
                "Unsupported PKCE challenge method in stored authorization code. Only S256 is allowed."
            );
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Unsupported PKCE challenge method".to_string(),
            });
        }

        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, verifier.as_bytes());
        let hash = hasher.finalize();
        let computed_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        if computed_challenge != *challenge {
            tracing::warn!("PKCE S256 code challenge mismatch");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "code_verifier is invalid".to_string(),
            });
        }
    } else if client.require_pkce {
        tracing::warn!("PKCE was required by client config but code lacks challenge");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "PKCE is required".to_string(),
        });
    }

    // 7. Issue tokens
    let expires_in = config.access_token_ttl_secs;
    let scope_opt = if auth_code.scope.is_empty() {
        None
    } else {
        Some(auth_code.scope.clone())
    };

    let access_token = match tokens.issue_user_token(
        auth_code.identity.clone(),
        expires_in,
        scope_opt.clone(),
        Some(client_id.clone()),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    let id_token = if auth_code.scope.contains("openid") {
        match tokens.issue_id_token(
            auth_code.identity.clone(),
            &client_id,
            auth_code.nonce.clone(),
            expires_in,
        ) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    // Issue refresh token if requested
    let mut issued_refresh_token = None;
    if auth_code.scope.contains("offline_access") {
        let refresh_val = uuid::Uuid::new_v4().to_string();
        let rt_model = RefreshToken {
            token: refresh_val.clone(),
            client_id: client_id.clone(),
            identity: auth_code.identity.clone(),
            scope: auth_code.scope.clone(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        };
        if let Err(e) = op_store.store_token(rt_model.clone()).await {
            tracing::error!(error = ?e, "Failed to store refresh token");
            // Non-fatal, just don't return a refresh token
        } else {
            issued_refresh_token = Some(refresh_val);
        }
    }

    tracing::info!(
        client_id = %client_id,
        "Successfully exchanged authorization code for tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
        refresh_token: issued_refresh_token,
        scope: scope_opt,
    })
}

async fn handle_client_credentials(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    if !client.allows_grant_type(&GrantType::ClientCredentials) {
        tracing::warn!(client_id = %client_id, "Client not authorized for client_credentials grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use client_credentials grant type"
                .to_string(),
        });
    }

    let expires_in = config.access_token_ttl_secs;
    let requested_scope = req.scope.clone();
    // Validate that requested scopes are allowed for this client
    if let Some(ref scopes) = requested_scope {
        let requested: Vec<&str> = scopes.split_whitespace().collect();
        for s in requested {
            if !client.scopes.contains(&s.to_string()) {
                tracing::warn!(client_id = %client_id, scope = %s, "Client requested unauthorized scope");
                return Err(TokenErrorResponse {
                    error: "invalid_scope".to_string(),
                    error_description: format!("Scope {} is not allowed for this client", s),
                });
            }
        }
    }

    let access_token = match tokens.issue_client_token(
        &client_id,
        expires_in,
        requested_scope.clone(),
        Some(client_id.clone()),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token for client credentials");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    tracing::info!(
        client_id = %client_id,
        "Successfully issued tokens for client credentials grant"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token: None, // client credentials does not issue ID tokens
        refresh_token: None,
        scope: requested_scope,
    })
}

#[allow(clippy::too_many_arguments)]
/// The built-in `refresh_token` grant handling.
///
/// This is the default body for [`crate::store::OpStore::handle_refresh_token`]
/// — split out as a free function so the trait's default method can call it
/// without duplicating the logic, while `handle_token` reaches it exclusively
/// through the trait method (so an override actually takes effect).
pub(crate) async fn default_handle_refresh_token<S: OpStore + ?Sized>(
    req: TokenRequest,
    client_id: String,
    client: ClientRegistration,
    config: &OpConfig,
    op_store: &S,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    if !client.allows_grant_type(&GrantType::RefreshToken) {
        tracing::warn!(client_id = %client_id, "Client not authorized for refresh_token grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use refresh_token grant type"
                .to_string(),
        });
    }

    let refresh_token_str = match req.refresh_token.as_deref() {
        Some(t) => t,
        None => {
            tracing::warn!("Missing refresh_token in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "refresh_token is required".to_string(),
            });
        }
    };

    let old_rt = match op_store.consume_token(refresh_token_str).await {
        Ok(Some(rt)) => rt,
        Ok(None) => {
            tracing::warn!("Invalid refresh token (possibly replayed)");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Invalid refresh token".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Failed to consume refresh token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    if old_rt.client_id != client_id {
        tracing::warn!("Refresh token issued to a different client");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Invalid refresh token".to_string(),
        });
    }

    if chrono::Utc::now() > old_rt.expires_at {
        tracing::warn!("Refresh token expired");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Refresh token expired".to_string(),
        });
    }

    let new_refresh_val = uuid::Uuid::new_v4().to_string();
    let new_rt = RefreshToken {
        token: new_refresh_val.clone(),
        client_id: client_id.clone(),
        identity: old_rt.identity.clone(),
        scope: old_rt.scope.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(30),
    };

    if let Err(e) = op_store.store_token(new_rt).await {
        tracing::error!(error = ?e, "Failed to store new refresh token");
    }

    let expires_in = config.access_token_ttl_secs;
    let scope_opt = if old_rt.scope.is_empty() {
        None
    } else {
        Some(old_rt.scope.clone())
    };

    let access_token = match tokens.issue_user_token(
        old_rt.identity.clone(),
        expires_in,
        scope_opt.clone(),
        Some(client_id.clone()),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to issue access token");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Failed to generate token".to_string(),
            });
        }
    };

    // Per OIDC Core §12.2, an id_token MAY be re-minted on refresh; a client
    // that never requested `openid` gets none, mirroring how
    // `handle_authorization_code` gates `issue_id_token` on the same scope
    // check. Refresh tokens don't carry a `nonce` (only auth codes do,
    // reflecting the original `/authorize` request) — Core §12.2 lists
    // `nonce` as OPTIONAL on a refreshed id_token, so omitting it is
    // conformant, not a shortcut.
    let id_token = if old_rt.scope.contains("openid") {
        match tokens.issue_id_token(old_rt.identity.clone(), &client_id, None, expires_in) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    tracing::info!(
        client_id = %client_id,
        "Successfully refreshed tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
        refresh_token: Some(new_refresh_val),
        scope: scope_opt,
    })
}

/// The built-in `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)
/// grant handling.
///
/// This is the default body for [`crate::store::OpStore::handle_token_exchange`]
/// — split out as a free function so the trait's default method can call it
/// without duplicating the logic, while `handle_token` reaches it exclusively
/// through the trait method (so an override actually takes effect).
pub(crate) async fn default_handle_token_exchange(
    req: TokenRequest,
    client_id: String,
    client: crate::client::ClientRegistration,
    config: &OpConfig,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::client::GrantType;
    use authkestra_engine::token::Claims;

    if !config.token_exchange_enabled {
        tracing::warn!("Token exchange is disabled globally");
        return Err(TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Token exchange is not enabled on this authorization server"
                .to_string(),
        });
    }

    if !client.allows_grant_type(&GrantType::TokenExchange) {
        tracing::warn!(client_id = %client_id, "Client not authorized for token_exchange grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use token_exchange grant type"
                .to_string(),
        });
    }

    if req.actor_token.is_some() || req.actor_token_type.is_some() {
        tracing::warn!("Delegation (actor_token) is not supported");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "actor_token is not supported".to_string(),
        });
    }

    let subject_token_type = req.subject_token_type.as_deref().unwrap_or("");
    if subject_token_type != "urn:ietf:params:oauth:token-type:access_token"
        && subject_token_type != "urn:ietf:params:oauth:token-type:id_token"
    {
        tracing::warn!(subject_token_type = %subject_token_type, "Unsupported subject_token_type");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Unsupported subject_token_type".to_string(),
        });
    }

    let requested_token_type = req
        .requested_token_type
        .as_deref()
        .unwrap_or("urn:ietf:params:oauth:token-type:access_token");
    if requested_token_type != "urn:ietf:params:oauth:token-type:access_token"
        && requested_token_type != "urn:ietf:params:oauth:token-type:id_token"
    {
        tracing::warn!(requested_token_type = %requested_token_type, "Unsupported requested_token_type");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description:
                "Unsupported requested_token_type. Only access_token and id_token are supported."
                    .to_string(),
        });
    }

    let subject_token_str = match req.subject_token.as_deref() {
        Some(t) => t,
        None => {
            tracing::warn!("Missing subject_token in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "subject_token is required".to_string(),
            });
        }
    };

    let claims: Claims = match tokens.validate_token(subject_token_str, None) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = ?e, "Failed to validate subject_token");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "subject_token is invalid".to_string(),
            });
        }
    };

    // Audience Binding: this client must be a member of the subject token's
    // `aud` claim, which per RFC 7519 §4.1.3 may be a single string or an
    // array of strings (e.g. a Keycloak realm with multiple
    // `oidc-audience-mapper` entries). `azp` is not read here — this crate's
    // `Claims` has no such field, and there is no dedicated `azp` check.
    let is_intended_aud = claims
        .aud
        .as_ref()
        .is_some_and(|aud| aud.contains(&client_id));
    if !is_intended_aud {
        tracing::warn!(
            client_id = %client_id,
            "Client is not authorized to exchange this token"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Client is not authorized to exchange this token".to_string(),
        });
    }

    // Determine the resource audience for the new token
    let new_aud = if let Some(requested_aud) = req.audience {
        if !client.allowed_audiences.contains(&requested_aud) {
            tracing::warn!(
                client_id = %client_id,
                audience = %requested_aud,
                "Requested audience is not allowed for this client"
            );
            return Err(TokenErrorResponse {
                error: "invalid_target".to_string(),
                error_description: "Requested audience is not allowed".to_string(),
            });
        }
        Some(requested_aud)
    } else {
        Some(config.issuer.clone())
    };

    // Scope narrowing logic
    let original_scope = claims.scope.unwrap_or_default();
    let original_scopes: Vec<&str> = original_scope.split_whitespace().collect();
    let requested_scope = req.scope.unwrap_or_default();
    let requested_scopes: Vec<&str> = if requested_scope.is_empty() {
        original_scopes.clone()
    } else {
        requested_scope.split_whitespace().collect()
    };

    let mut intersected_scopes = Vec::new();
    for s in requested_scopes {
        if original_scopes.contains(&s) && client.scopes.contains(&s.to_string()) {
            intersected_scopes.push(s.to_string());
        }
    }

    // If a scope was requested but intersection is empty, it's an error.
    if !requested_scope.is_empty() && intersected_scopes.is_empty() {
        tracing::warn!("Requested scope resulted in empty intersection");
        return Err(TokenErrorResponse {
            error: "invalid_scope".to_string(),
            error_description: "Requested scope is invalid, unknown, or malformed".to_string(),
        });
    }

    let final_scope_str = if intersected_scopes.is_empty() {
        None
    } else {
        Some(intersected_scopes.join(" "))
    };

    let identity = match claims.identity {
        Some(id) => id,
        None => {
            tracing::warn!("subject_token does not contain an identity");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "subject_token is missing identity".to_string(),
            });
        }
    };

    let expires_in = config.access_token_ttl_secs;
    let granted_openid = final_scope_str
        .as_deref()
        .is_some_and(|s| s.split_whitespace().any(|scope| scope == "openid"));

    // Per OIDC Core §12.2 / RFC 8693 §2.1, an id_token accompanies the
    // access token when the `openid` scope is in the final granted scope —
    // mirroring how `handle_authorization_code` and
    // `default_handle_refresh_token` gate `issue_id_token` on the same
    // check. `requested_token_type: id_token` is a client signal that it
    // wants one, but the crate's `TokenResponse` always carries an
    // `access_token`; id_token issuance itself stays scope-gated so it does
    // not depend on which requested_token_type value was sent. No nonce is
    // reflected, since RFC 8693 exchange requests don't carry one.
    let id_token = if granted_openid {
        match tokens.issue_id_token(identity.clone(), &client_id, None, expires_in) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token during exchange");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    let access_token =
        match tokens.issue_user_token(identity, expires_in, final_scope_str.clone(), new_aud) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue access token during exchange");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate token".to_string(),
                });
            }
        };

    tracing::info!(
        client_id = %client_id,
        "Successfully exchanged token"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
        refresh_token: None,
        scope: final_scope_str,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, GrantType};
    use crate::code::{AuthorizationCode, AuthorizationCodeStore};

    use crate::refresh::{RefreshToken, RefreshTokenStore};
    use authkestra_engine::auth::state::Identity;
    use authkestra_engine::store::KvStore;
    use authkestra_engine::token::TokenManager;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    pub(crate) fn test_config(token_exchange_enabled: bool) -> OpConfig {
        OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "custom".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled,
        }
    }

    pub(crate) fn test_tokens() -> TokenManager {
        TokenManager::new(b"super_secret_key_that_is_long_enough_for_hmac", None)
    }

    fn test_identity() -> Identity {
        Identity {
            provider_id: "test".to_string(),
            external_id: "user123".to_string(),
            username: Some("user123".to_string()),
            email: None,
            attributes: HashMap::new(),
        }
    }

    fn issue_subject_token(
        tokens: &TokenManager,
        client_id: &str,
        scope: Option<String>,
    ) -> String {
        tokens
            .issue_user_token(test_identity(), 3600, scope, Some(client_id.to_string()))
            .unwrap()
    }

    /// Like `issue_subject_token`, but mints a subject token whose `aud`
    /// claim is a JSON array (RFC 7519 §4.1.3), the shape a stock Keycloak
    /// realm with multiple `oidc-audience-mapper` entries produces. Built by
    /// hand with `jsonwebtoken::encode` because `TokenManager`'s issuance
    /// methods only ever emit a single-string `aud`. The signing secret
    /// below must match `test_tokens()`'s so `TokenManager::validate_token`
    /// can verify the result.
    fn issue_subject_token_multi_aud(audiences: &[&str], scope: Option<String>) -> String {
        let now = chrono::Utc::now().timestamp() as usize;
        let raw_claims = serde_json::json!({
            "sub": "user123",
            "aud": audiences,
            "exp": now + 3600,
            "iat": now,
            "scope": scope,
            "identity": {
                "provider_id": "test",
                "external_id": "user123",
                "email": null,
                "username": "user123",
                "attributes": {}
            }
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &raw_claims,
            &jsonwebtoken::EncodingKey::from_secret(
                b"super_secret_key_that_is_long_enough_for_hmac",
            ),
        )
        .unwrap()
    }

    // --- Pre-existing restored tests ---

    #[tokio::test]
    async fn test_invalid_grant_type() {
        let req = TokenRequest {
            grant_type: "invalid".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "unauthorized_client");
    }

    #[tokio::test]
    async fn test_authorization_code_grant_rejected_when_client_not_granted() {
        // `client1` is registered without `authorization_code` in its
        // `grant_types` — unlike `handle_device_code`,
        // `handle_client_credentials`, `default_handle_refresh_token`, and
        // `default_handle_token_exchange`, `handle_authorization_code` must
        // reject this the same way, before ever looking up a code.
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("some-code".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::ClientCredentials],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
        assert_eq!(
            err.error_description,
            "Client is not authorized to use authorization_code grant type"
        );
    }

    #[tokio::test]
    async fn test_successful_exchange_with_pkce() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let verifier = "test_verifier";
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code(AuthorizationCode {
                code: "code1".to_string(),
                client_id: "client1".to_string(),
                redirect_uri: "https://cb".to_string(),
                identity: test_identity(),
                scope: "openid".to_string(),
                nonce: None,
                expires_at: Utc::now() + Duration::minutes(5),
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_string()),
                used: false,
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: Some(verifier.to_string()),
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_pkce_verifier() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code(AuthorizationCode {
                code: "code1".to_string(),
                client_id: "client1".to_string(),
                redirect_uri: "https://cb".to_string(),
                identity: test_identity(),
                scope: "openid".to_string(),
                nonce: None,
                expires_at: Utc::now() + Duration::minutes(5),
                code_challenge: Some("valid_challenge".to_string()),
                code_challenge_method: Some("S256".to_string()),
                used: false,
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: Some("wrong_verifier".to_string()),
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_redirect_uri_mismatch() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code(AuthorizationCode {
                code: "code1".to_string(),
                client_id: "client1".to_string(),
                redirect_uri: "https://cb".to_string(),
                identity: test_identity(),
                scope: "".to_string(),
                nonce: None,
                expires_at: Utc::now() + Duration::minutes(5),
                code_challenge: None,
                code_challenge_method: None,
                used: false,
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://wrong".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_reject_plain_pkce_method() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        codes
            .store_code(AuthorizationCode {
                code: "code1".to_string(),
                client_id: "client1".to_string(),
                redirect_uri: "https://cb".to_string(),
                identity: test_identity(),
                scope: "".to_string(),
                nonce: None,
                expires_at: Utc::now() + Duration::minutes(5),
                code_challenge: Some("challenge".to_string()),
                code_challenge_method: Some("plain".to_string()),
                used: false,
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code1".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: Some("challenge".to_string()),
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                codes.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert_eq!(res.unwrap_err().error, "server_error");
    }

    #[tokio::test]
    async fn test_client_credentials() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::ClientCredentials],
                    scopes: vec!["custom".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let req = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: Some("custom".to_string()),
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_refresh_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::RefreshToken],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();
        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken {
                token: "rt1".to_string(),
                client_id: "client1".to_string(),
                identity: test_identity(),
                scope: "openid".to_string(),
                expires_at: Utc::now() + Duration::days(1),
            })
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: Some("rt1".to_string()),
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };
        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens()
        )
        .await;
        assert!(res.is_ok());
        assert!(res.unwrap().refresh_token.is_some());
    }

    // --- OpStore::handle_refresh_token override seam (issue #189) ---

    /// A minimal `OpStore` wrapper that delegates every method to an inner
    /// `OpStore` except `handle_refresh_token`, which it overrides with a
    /// canned response. Proves the override actually reaches the dispatch
    /// site in `handle_token`, not just that the trait compiles.
    struct OverridingRefreshStore<Inner> {
        inner: Inner,
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::client::ClientStore for OverridingRefreshStore<Inner> {
        async fn find_client(
            &self,
            client_id: &str,
        ) -> Result<Option<ClientRegistration>, OpError> {
            self.inner.find_client(client_id).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::code::AuthorizationCodeStore for OverridingRefreshStore<Inner> {
        async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
            self.inner.store_code(code).await
        }

        async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
            self.inner.consume_code(code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> RefreshTokenStore for OverridingRefreshStore<Inner> {
        async fn store_token(&self, token: RefreshToken) -> Result<(), OpError> {
            self.inner.store_token(token).await
        }

        async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
            self.inner.get_token(token).await
        }

        async fn revoke_token(&self, token: &str) -> Result<(), OpError> {
            self.inner.revoke_token(token).await
        }

        async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
            self.inner.consume_token(token).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::device::DeviceCodeStore for OverridingRefreshStore<Inner> {
        async fn store_device_code(
            &self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), OpError> {
            self.inner.store_device_code(session).await
        }

        async fn get_device_code(
            &self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, OpError> {
            self.inner.get_device_code(device_code).await
        }

        async fn get_by_user_code(
            &self,
            user_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, OpError> {
            self.inner.get_by_user_code(user_code).await
        }

        async fn update_device_code(
            &self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), OpError> {
            self.inner.update_device_code(session).await
        }

        async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
            self.inner.delete_device_code(device_code).await
        }

        async fn consume_device_code(
            &self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, OpError> {
            self.inner.consume_device_code(device_code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> OpStore for OverridingRefreshStore<Inner> {
        async fn handle_refresh_token(
            &self,
            _req: TokenRequest,
            _client_id: String,
            _client: ClientRegistration,
            _config: &OpConfig,
            _tokens: &TokenManager,
        ) -> Result<TokenResponse, TokenErrorResponse> {
            Ok(TokenResponse {
                access_token: "overridden-access-token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 42,
                id_token: Some("overridden-id-token".to_string()),
                refresh_token: Some("overridden-refresh-token".to_string()),
                scope: Some("overridden-scope".to_string()),
            })
        }
    }

    fn refresh_test_client() -> ClientRegistration {
        ClientRegistration {
            client_id: "client1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec![],
            grant_types: vec![GrantType::RefreshToken],
            scopes: vec![],
            require_pkce: false,
            allowed_audiences: vec![],
            token_endpoint_auth_method: None,
            jwks: None,
        }
    }

    fn refresh_test_req(refresh_token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: Some(refresh_token.to_string()),
            subject_token: None,
            subject_token_type: None,
            device_code: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        }
    }

    #[tokio::test]
    async fn test_refresh_token_is_overridable_by_op_store() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let store =
            OverridingRefreshStore {
                inner:
                    crate::store::CompositeOpStore::new(
                        clients,
                        authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                        authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                        authkestra_engine::store::memory::MemoryStore::<
                            crate::device::DeviceCodeSession,
                        >::new(),
                    ),
            };

        // Deliberately a token no store has ever issued: if dispatch fell
        // through to the built-in handler instead of the override, this
        // would fail closed with `invalid_grant`, not succeed.
        let req = refresh_test_req("no-such-token");

        let res = handle_token(req, None, &test_config(false), &store, &test_tokens()).await;

        let resp =
            res.expect("the override should have been invoked instead of the built-in handler");
        assert_eq!(resp.access_token, "overridden-access-token");
        assert_eq!(resp.id_token.as_deref(), Some("overridden-id-token"));
        assert_eq!(
            resp.refresh_token.as_deref(),
            Some("overridden-refresh-token")
        );
    }

    #[tokio::test]
    async fn test_refresh_token_default_behavior_is_unchanged_without_override() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken {
                token: "rt-default".to_string(),
                client_id: "client1".to_string(),
                identity: test_identity(),
                // Non-openid scope: the built-in handler's `id_token: None`
                // is a fixed point here regardless of whether a later change
                // teaches it to issue one for the `openid` scope.
                scope: "profile".to_string(),
                expires_at: Utc::now() + Duration::days(1),
            })
            .await
            .unwrap();

        // A store that does NOT override `handle_refresh_token` — this is
        // the compatibility guarantee: it must behave identically to before
        // the trait method existed.
        let res = handle_token(
            refresh_test_req("rt-default"),
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(resp.scope.as_deref(), Some("profile"));
        assert_eq!(resp.id_token, None);
        assert_ne!(resp.refresh_token.as_deref(), Some("rt-default"));
        // The old refresh token was consumed (single-use rotation).
        assert!(refresh.get_token("rt-default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_unknown_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("does-not-exist"),
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_expired_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        // `store_token` derives the underlying KV TTL from `expires_at`, so
        // an already-past `expires_at` would get evicted at the storage
        // layer before the handler's own expiry check ever runs. Write
        // through `set` directly with a real TTL so the token is still
        // present, and the handler's `Utc::now() > expires_at` check
        // (`handlers/token.rs`, `default_handle_refresh_token`) is what
        // rejects it.
        refresh
            .set(
                "rt-expired",
                RefreshToken {
                    token: "rt-expired".to_string(),
                    client_id: "client1".to_string(),
                    identity: test_identity(),
                    scope: "profile".to_string(),
                    expires_at: Utc::now() - Duration::minutes(1),
                },
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-expired"),
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &test_tokens(),
        )
        .await;

        let err = res.unwrap_err();
        assert_eq!(err.error, "invalid_grant");
        assert_eq!(err.error_description, "Refresh token expired");
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_replay_of_a_rotated_token() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken {
                token: "rt-once".to_string(),
                client_id: "client1".to_string(),
                identity: test_identity(),
                scope: "profile".to_string(),
                expires_at: Utc::now() + Duration::days(1),
            })
            .await
            .unwrap();

        let store = crate::store::CompositeOpStore::new(
            clients,
            authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
            refresh,
            authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
        );
        let tokens = test_tokens();

        let first = handle_token(
            refresh_test_req("rt-once"),
            None,
            &test_config(false),
            &store,
            &tokens,
        )
        .await;
        assert!(first.is_ok());

        // Replaying the now-rotated token must fail, not succeed a second
        // time.
        let second = handle_token(
            refresh_test_req("rt-once"),
            None,
            &test_config(false),
            &store,
            &tokens,
        )
        .await;
        assert_eq!(second.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_issues_id_token_when_openid_scope_present() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken {
                token: "rt-openid".to_string(),
                client_id: "client1".to_string(),
                identity: test_identity(),
                scope: "openid profile".to_string(),
                expires_at: Utc::now() + Duration::days(1),
            })
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-openid"),
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert!(
            resp.id_token.is_some(),
            "openid scope should get a refreshed id_token"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_omits_id_token_without_openid_scope() {
        let clients = authkestra_engine::store::memory::MemoryStore::<ClientRegistration>::new();
        clients
            .set(
                "client1",
                refresh_test_client(),
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let refresh =
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new();
        refresh
            .store_token(RefreshToken {
                token: "rt-no-openid".to_string(),
                client_id: "client1".to_string(),
                identity: test_identity(),
                scope: "profile".to_string(),
                expires_at: Utc::now() + Duration::days(1),
            })
            .await
            .unwrap();

        let res = handle_token(
            refresh_test_req("rt-no-openid"),
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                refresh,
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &test_tokens(),
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(
            resp.id_token, None,
            "no openid scope should mean no id_token, same as before this feature existed"
        );
    }

    // --- OpStore::handle_token_exchange override seam (issue #204) ---

    /// A minimal `OpStore` wrapper that delegates every method to an inner
    /// `OpStore` except `handle_token_exchange`, which it overrides with a
    /// canned response. Proves the override actually reaches the dispatch
    /// site in `handle_token`, not just that the trait compiles.
    struct OverridingTokenExchangeStore<Inner> {
        inner: Inner,
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::client::ClientStore for OverridingTokenExchangeStore<Inner> {
        async fn find_client(
            &self,
            client_id: &str,
        ) -> Result<Option<ClientRegistration>, OpError> {
            self.inner.find_client(client_id).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::code::AuthorizationCodeStore for OverridingTokenExchangeStore<Inner> {
        async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
            self.inner.store_code(code).await
        }

        async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
            self.inner.consume_code(code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> RefreshTokenStore for OverridingTokenExchangeStore<Inner> {
        async fn store_token(&self, token: RefreshToken) -> Result<(), OpError> {
            self.inner.store_token(token).await
        }

        async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
            self.inner.get_token(token).await
        }

        async fn revoke_token(&self, token: &str) -> Result<(), OpError> {
            self.inner.revoke_token(token).await
        }

        async fn consume_token(&self, token: &str) -> Result<Option<RefreshToken>, OpError> {
            self.inner.consume_token(token).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> crate::device::DeviceCodeStore for OverridingTokenExchangeStore<Inner> {
        async fn store_device_code(
            &self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), OpError> {
            self.inner.store_device_code(session).await
        }

        async fn get_device_code(
            &self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, OpError> {
            self.inner.get_device_code(device_code).await
        }

        async fn get_by_user_code(
            &self,
            user_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, OpError> {
            self.inner.get_by_user_code(user_code).await
        }

        async fn update_device_code(
            &self,
            session: crate::device::DeviceCodeSession,
        ) -> Result<(), OpError> {
            self.inner.update_device_code(session).await
        }

        async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
            self.inner.delete_device_code(device_code).await
        }

        async fn consume_device_code(
            &self,
            device_code: &str,
        ) -> Result<Option<crate::device::DeviceCodeSession>, OpError> {
            self.inner.consume_device_code(device_code).await
        }
    }

    #[async_trait::async_trait]
    impl<Inner: OpStore> OpStore for OverridingTokenExchangeStore<Inner> {
        async fn handle_token_exchange(
            &self,
            _req: TokenRequest,
            _client_id: String,
            _client: ClientRegistration,
            _config: &OpConfig,
            _tokens: &TokenManager,
        ) -> Result<TokenResponse, TokenErrorResponse> {
            Ok(TokenResponse {
                access_token: "overridden-tx-access-token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 42,
                id_token: Some("overridden-tx-id-token".to_string()),
                refresh_token: None,
                scope: Some("overridden-scope".to_string()),
            })
        }
    }

    #[tokio::test]
    async fn test_token_exchange_is_overridable_by_op_store() {
        let tokens = test_tokens();
        // A subject_token this store's dispatch would reject outright if it
        // ever reached the built-in handler (feature disabled below): if
        // dispatch fell through to `default_handle_token_exchange` instead
        // of the override, this would fail closed with
        // `unsupported_grant_type`, not succeed.
        let subject_token = issue_subject_token(&tokens, "client1", None);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let store =
            OverridingTokenExchangeStore {
                inner:
                    crate::store::CompositeOpStore::new(
                        clients,
                        authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                        authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                        authkestra_engine::store::memory::MemoryStore::<
                            crate::device::DeviceCodeSession,
                        >::new(),
                    ),
            };

        let res = handle_token(
            default_tx_req(&subject_token),
            None,
            // Token exchange disabled globally: the built-in handler would
            // refuse with `unsupported_grant_type` before doing anything
            // else, so a success proves the override intercepted the call
            // before that built-in check ever ran.
            &test_config(false),
            &store,
            &tokens,
        )
        .await;

        let resp =
            res.expect("the override should have been invoked instead of the built-in handler");
        assert_eq!(resp.access_token, "overridden-tx-access-token");
        assert_eq!(resp.id_token.as_deref(), Some("overridden-tx-id-token"));
        assert_eq!(resp.scope.as_deref(), Some("overridden-scope"));
    }

    #[tokio::test]
    async fn test_token_exchange_default_behavior_is_unchanged_without_override() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        // A store that does NOT override `handle_token_exchange` — this is
        // the compatibility guarantee: it must behave identically to before
        // the trait method existed.
        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients,
                authkestra_engine::store::memory::MemoryStore::<AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(resp.scope.as_deref(), Some("profile"));
        assert_eq!(resp.id_token, None);
        assert_eq!(resp.refresh_token, None);
    }

    // --- Token Exchange DoD Tests ---

    fn default_tx_req(subject_token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            device_code: None,
            subject_token: Some(subject_token.to_string()),
            subject_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        }
    }

    #[tokio::test]
    async fn test_tx_cross_client_rejection() {
        let tokens = test_tokens();
        // Issued to 'client2'
        let subject_token = issue_subject_token(&tokens, "client2", None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    /// #206: a subject token whose `aud` is a JSON array must exchange
    /// successfully when the requesting client_id is *any one* of the
    /// listed audiences, not just when it's the sole audience.
    #[tokio::test]
    async fn test_tx_multi_audience_subject_token_allowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token_multi_aud(&["client1", "client2"], None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert!(
            res.is_ok(),
            "client1 is a member of the array aud, exchange should succeed: {res:?}"
        );
    }

    /// #206 companion: when the requesting client_id is absent from the
    /// subject token's array `aud`, exchange must still be rejected —
    /// membership, not mere array-shape acceptance, is the check.
    #[tokio::test]
    async fn test_tx_multi_audience_subject_token_disallowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token_multi_aud(&["client2", "client3"], None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_tx_scope_escalation_narrow() {
        let tokens = test_tokens();
        let subject_token =
            issue_subject_token(&tokens, "client1", Some("scopeA scopeB".to_string()));
        let mut req = default_tx_req(&subject_token);
        req.scope = Some("scopeA scopeC".to_string()); // requesting scopeC which token doesn't have

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["scopeA".to_string(), "scopeC".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        let res = res.unwrap();
        // Should only grant scopeA
        assert_eq!(res.scope.unwrap(), "scopeA");
    }

    #[tokio::test]
    async fn test_tx_zero_overlap_reject() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("scopeA".to_string()));
        let mut req = default_tx_req(&subject_token);
        req.scope = Some("scopeB".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["scopeB".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_scope");
    }

    #[tokio::test]
    async fn test_tx_feature_disabled() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(false),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_tx_actor_token_rejected() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.actor_token = Some("some_actor_token".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn test_tx_subject_token_type_invalid() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.subject_token_type = Some("urn:ietf:params:oauth:token-type:saml2".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn test_tx_requested_token_type_invalid() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.requested_token_type = Some("urn:ietf:params:oauth:token-type:saml2".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_request");
    }

    #[tokio::test]
    async fn test_tx_audience_allowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.audience = Some("serviceA".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec!["serviceA".to_string()],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert!(res.is_ok());
        let claim = tokens
            .validate_token(&res.unwrap().access_token, None)
            .unwrap();
        assert!(claim.aud.unwrap().contains("serviceA"));
    }

    #[tokio::test]
    async fn test_tx_audience_disallowed() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let mut req = default_tx_req(&subject_token);
        req.audience = Some("serviceB".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec!["serviceA".to_string()],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_target");
    }

    #[tokio::test]
    async fn test_tx_default_audience() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", None);
        let req = default_tx_req(&subject_token);
        // No audience requested

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert!(res.is_ok());
        let claim = tokens
            .validate_token(&res.unwrap().access_token, None)
            .unwrap();
        // default aud should be config.issuer
        assert!(claim.aud.unwrap().contains("https://auth.example.com"));
    }

    #[tokio::test]
    async fn test_tx_missing_identity_reject() {
        let tokens = test_tokens();
        // Issue token WITHOUT identity (using raw token creation or simulating it)
        // Since test_tokens().issue_user_token always embeds identity, we just simulate by passing a token with valid signature but no identity
        // Actually, we can just use `issue_client_token` which creates a token with no `identity` claim!
        let subject_token = tokens
            .issue_client_token("client2", 3600, None, Some("client1".to_string()))
            .unwrap();
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;
        assert_eq!(res.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_tx_issues_id_token_when_openid_scope_granted() {
        let tokens = test_tokens();
        let subject_token =
            issue_subject_token(&tokens, "client1", Some("openid profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["openid".to_string(), "profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;

        let resp = res.unwrap();
        assert!(
            resp.id_token.is_some(),
            "openid scope should get an id_token from the token-exchange grant, mirroring \
             handle_authorization_code and default_handle_refresh_token"
        );
    }

    #[tokio::test]
    async fn test_tx_omits_id_token_without_openid_scope() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("profile".to_string()));
        let req = default_tx_req(&subject_token);

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;

        let resp = res.unwrap();
        assert_eq!(
            resp.id_token, None,
            "no openid scope should mean no id_token, same as before this feature existed"
        );
    }

    #[tokio::test]
    async fn test_tx_requested_token_type_id_token_accepted() {
        let tokens = test_tokens();
        let subject_token = issue_subject_token(&tokens, "client1", Some("openid".to_string()));
        let mut req = default_tx_req(&subject_token);
        req.requested_token_type = Some("urn:ietf:params:oauth:token-type:id_token".to_string());

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::TokenExchange],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(
            ),
            ),
            &tokens
        )
        .await;

        assert!(
            res.is_ok(),
            "requested_token_type: id_token must be accepted per RFC 8693 §2.1, got {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_custom_grant_fallback() {
        let tokens = test_tokens();
        let req = TokenRequest {
            grant_type: "urn:custom:grant".to_string(),
            code: None,
            device_code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    grant_types: vec![GrantType::Custom("urn:custom:grant".to_string())],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        // With the default implementation, custom grants should return unsupported_grant_type
        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        assert_eq!(res.unwrap_err().error, "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_custom_grant_unauthorized() {
        let tokens = test_tokens();
        let req = TokenRequest {
            grant_type: "urn:custom:grant".to_string(),
            code: None,
            device_code: None,
            redirect_uri: None,
            client_id: Some("client1".to_string()),
            client_secret: None,
            code_verifier: None,
            scope: None,
            refresh_token: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client1",
                ClientRegistration {
                    client_id: "client1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec![],
                    // Crucially, this client is NOT authorized for the custom grant type
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let res = handle_token(
            req,
            None,
            &test_config(true),
            &crate::store::CompositeOpStore::new(
                clients.clone(),
                authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
            &tokens,
        )
        .await;

        let err = res.unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
    }
}

#[cfg(test)]
mod device_tests;

#[cfg(test)]
mod client_auth_tests;
