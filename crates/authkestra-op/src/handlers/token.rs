use crate::client::ClientStore;
use crate::code::AuthorizationCodeStore;
use crate::config::OpConfig;
use crate::refresh::{RefreshToken, RefreshTokenStore};
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
pub async fn handle_token(
    req: TokenRequest,
    auth_header: Option<&str>,
    config: &OpConfig,
    clients: &dyn ClientStore,
    codes: &dyn AuthorizationCodeStore,
    refresh_tokens: &dyn RefreshTokenStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    tracing::debug!(grant_type = %req.grant_type, "Processing token exchange request");

    // 0. Extract client credentials
    let mut req_client_id = req.client_id.clone();
    let mut req_client_secret = req.client_secret.clone();

    if let Some(auth) = auth_header {
        if let Some(stripped) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(stripped) {
                if let Ok(creds) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = creds.split_once(':') {
                        req_client_id = Some(id.to_string());
                        req_client_secret = Some(secret.to_string());
                    }
                }
            }
        }
    }

    let client_id = match req_client_id {
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
    let client = match clients.find_client(&client_id).await {
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

    // Verify secret if provided (required for confidential clients)
    if client.client_secret_hash.is_some() {
        let provided_secret = req_client_secret.as_deref().unwrap_or("");
        if !client.verify_secret(provided_secret) {
            tracing::warn!(client_id = %client_id, "Invalid client secret");
            return Err(TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
    }

    match req.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code(
                req,
                client_id,
                client,
                config,
                codes,
                refresh_tokens,
                tokens,
            )
            .await
        }
        "client_credentials" => {
            handle_client_credentials(req, client_id, client, config, tokens).await
        }
        "refresh_token" => {
            handle_refresh_token(req, client_id, client, config, refresh_tokens, tokens).await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            handle_token_exchange(req, client_id, client, config, tokens).await
        }
        _ => {
            tracing::warn!(grant_type = %req.grant_type, "Unsupported grant type");
            Err(TokenErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: "Unsupported grant type".to_string(),
            })
        }
    }
}

async fn handle_authorization_code(
    req: TokenRequest,
    client_id: String,
    client: crate::client::ClientRegistration,
    config: &OpConfig,
    codes: &dyn AuthorizationCodeStore,
    refresh_tokens: &dyn RefreshTokenStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    let req_code = req.code.as_deref().unwrap_or("");
    let req_redirect_uri = req.redirect_uri.as_deref().unwrap_or("");

    // 3. Consume the code atomically
    let auth_code = match codes.consume_code(req_code).await {
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
        let rt = RefreshToken {
            token: refresh_val.clone(),
            client_id: client_id.clone(),
            identity: auth_code.identity.clone(),
            scope: auth_code.scope.clone(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        };
        if let Err(e) = refresh_tokens.store_token(rt).await {
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
    client: crate::client::ClientRegistration,
    config: &OpConfig,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::client::GrantType;

    if !client.allows_grant_type(GrantType::ClientCredentials) {
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

async fn handle_refresh_token(
    req: TokenRequest,
    client_id: String,
    client: crate::client::ClientRegistration,
    config: &OpConfig,
    refresh_tokens: &dyn RefreshTokenStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::client::GrantType;

    if !client.allows_grant_type(GrantType::RefreshToken) {
        tracing::warn!(client_id = %client_id, "Client not authorized for refresh_token grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use refresh_token grant type"
                .to_string(),
        });
    }

    let req_refresh_token = match req.refresh_token.as_deref() {
        Some(t) => t,
        None => {
            tracing::warn!("Missing refresh_token in request");
            return Err(TokenErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "refresh_token is required".to_string(),
            });
        }
    };

    let rt = match refresh_tokens.consume_token(req_refresh_token).await {
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

    if rt.client_id != client_id {
        tracing::warn!("Refresh token issued to a different client");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Invalid refresh token".to_string(),
        });
    }

    if chrono::Utc::now() > rt.expires_at {
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
        identity: rt.identity.clone(),
        scope: rt.scope.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(30),
    };

    if let Err(e) = refresh_tokens.store_token(new_rt).await {
        tracing::error!(error = ?e, "Failed to store new refresh token");
    }

    let expires_in = config.access_token_ttl_secs;
    let scope_opt = if rt.scope.is_empty() {
        None
    } else {
        Some(rt.scope.clone())
    };

    let access_token = match tokens.issue_user_token(
        rt.identity.clone(),
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

    tracing::info!(
        client_id = %client_id,
        "Successfully refreshed tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token: None, // usually id_token is not issued on refresh unless openid scope is present, simplify for now
        refresh_token: Some(new_refresh_val),
        scope: scope_opt,
    })
}

async fn handle_token_exchange(
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

    if !client.allows_grant_type(GrantType::TokenExchange) {
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
    if requested_token_type != "urn:ietf:params:oauth:token-type:access_token" {
        tracing::warn!(requested_token_type = %requested_token_type, "Unsupported requested_token_type");
        return Err(TokenErrorResponse {
            error: "invalid_request".to_string(),
            error_description: "Unsupported requested_token_type. Only access_token is supported."
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

    // Audience Binding: either the subject token was issued TO this client (azp or aud = client_id)
    // or this client is in the intended audience.
    let is_intended_aud = claims.aud.as_deref() == Some(client_id.as_str());
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
        id_token: None,
        refresh_token: None,
        scope: final_scope_str,
    })
}
