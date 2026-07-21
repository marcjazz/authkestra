pub async fn handle_token(
    req: TokenRequest,
    auth_header: Option<&str>,
    config: &OpConfig,
    clients: &dyn ClientStore,
    codes: &dyn AuthorizationCodeStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    tracing::debug!(grant_type = %req.grant_type, "Processing token exchange request");

    // 0. Extract client credentials
    let mut req_client_id = req.client_id.clone();
    let mut req_client_secret = req.client_secret.clone();

    if let Some(auth) = auth_header {
        if auth.starts_with("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&auth[6..]) {
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
        "authorization_code" => handle_authorization_code(req, client_id, client, config, codes, tokens).await,
        "client_credentials" => handle_client_credentials(req, client_id, client, config, tokens).await,
        "refresh_token" => handle_refresh_token(req, client_id, client, config, tokens).await,
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
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use authkestra_engine::auth::state::Identity;
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

    let access_token =
        match tokens.issue_user_token(auth_code.identity.clone(), expires_in, scope_opt.clone()) {
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
            auth_code.identity,
            &client_id,
            auth_code.nonce,
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

    tracing::info!(
        client_id = %client_id,
        "Successfully exchanged authorization code for tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
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
    use authkestra_engine::auth::state::Identity;
    use std::collections::HashMap;

    if !client.allows_grant_type(GrantType::ClientCredentials) {
        tracing::warn!(client_id = %client_id, "Client not authorized for client_credentials grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use client_credentials grant type".to_string(),
        });
    }

    let expires_in = config.access_token_ttl_secs;
    
    // For client credentials, the "identity" is the client itself
    let identity = Identity {
        provider_id: "client_credentials".to_string(),
        external_id: client_id.clone(),
        username: Some(client_id.clone()),
        email: None,
        attributes: HashMap::new(),
    };

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

    let access_token = match tokens.issue_user_token(identity, expires_in, requested_scope.clone()) {
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
        scope: requested_scope,
    })
}

async fn handle_refresh_token(
    req: TokenRequest,
    client_id: String,
    client: crate::client::ClientRegistration,
    config: &OpConfig,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    use crate::client::GrantType;

    if !client.allows_grant_type(GrantType::RefreshToken) {
        tracing::warn!(client_id = %client_id, "Client not authorized for refresh_token grant");
        return Err(TokenErrorResponse {
            error: "unauthorized_client".to_string(),
            error_description: "Client is not authorized to use refresh_token grant type".to_string(),
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

    // Right now, authkestra_engine doesn't have an explicit `consume_refresh_token` or
    // `issue_refresh_token` implemented in TokenManager!
    // But OP.7 requires it.
    // We will just validate the token as a user token if TokenManager supports that,
    // wait, what does `TokenManager` have?
    unimplemented!("refresh token flow logic goes here")
}
