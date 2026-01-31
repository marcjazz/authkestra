use authly_core::{pkce::Pkce, Identity, OAuthProvider, OAuthToken};
use authly_flow::OAuth2Flow;
use authly_session::{Session, SessionStore};
use authly_token::TokenManager;
use axum::{
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};
use std::sync::Arc;
use tower_cookies::{cookie::SameSite, Cookie, Cookies};

#[derive(serde::Deserialize)]
pub struct OAuthCallbackParams {
    pub code: String,
    pub state: String,
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
    pub path: String,
    pub max_age: Option<chrono::Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "authly_session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
        }
    }
}

impl SessionConfig {
    pub fn create_cookie<'a>(&self, value: String) -> Cookie<'a> {
        let mut cookie = Cookie::new(self.cookie_name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);
        cookie.set_same_site(self.same_site);
        if let Some(max_age) = self.max_age {
            cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::seconds(
                max_age.num_seconds(),
            )));
        }
        cookie
    }
}

/// Helper to initiate the OAuth2 login flow.
///
/// This generates the authorization URL and sets a CSRF state cookie.
pub fn initiate_oauth_login<P, M>(
    flow: &OAuth2Flow<P, M>,
    session_config: &SessionConfig,
    cookies: &Cookies,
    scopes: &[&str],
) -> Redirect
where
    P: OAuthProvider,
    M: authly_core::UserMapper,
{
    let pkce = Pkce::new();
    let (url, csrf_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    let cookie_name = format!("authly_flow_{}", csrf_state);

    let mut cookie = Cookie::new(cookie_name, pkce.code_verifier);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(session_config.secure);
    // Set a reasonable expiry for the flow (e.g., 15 minutes)
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));

    cookies.add(cookie);

    Redirect::to(&url)
}

/// Internal helper to finalize the OAuth flow by validating state and exchanging the code.
async fn finalize_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    session_config: &SessionConfig,
    cookies: &Cookies,
    params: &OAuthCallbackParams,
) -> Result<(Identity, OAuthToken), (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let cookie_name = format!("authly_flow_{}", params.state);

    let pkce_verifier = cookies
        .get(&cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "CSRF validation failed or session expired".to_string(),
            )
        })?;

    // Remove cookie after use
    let mut remove_cookie = Cookie::new(cookie_name, "");
    remove_cookie.set_path("/");
    remove_cookie.set_secure(session_config.secure);
    cookies.remove(remove_cookie);

    let (identity, token, _local_user) = flow
        .finalize_login(
            &params.code,
            &params.state,
            &params.state, // We use the state itself as expected_state because finding the cookie proves it's ours
            Some(&pkce_verifier),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("Authentication failed: {}", e),
            )
        })?;

    Ok((identity, token))
}

/// Helper to handle the OAuth2 callback and create a server-side session.
pub async fn handle_oauth_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let (mut identity, token) = finalize_callback(flow, &config, &cookies, &params).await?;

    // Store tokens in identity attributes for convenience
    identity
        .attributes
        .insert("access_token".to_string(), token.access_token);

    if let Some(expires_in) = token.expires_in {
        let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;
        identity
            .attributes
            .insert("expires_at".to_string(), expires_at.to_string());
    }

    if let Some(rt) = token.refresh_token {
        identity.attributes.insert("refresh_token".to_string(), rt);
    }

    let session_duration = config.max_age.unwrap_or(chrono::Duration::hours(24));
    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        identity,
        expires_at: chrono::Utc::now() + session_duration,
    };

    store.save_session(&session).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to save session: {}", e),
        )
    })?;

    let cookie = config.create_cookie(session.id);
    cookies.add(cookie);

    Ok(Redirect::to(success_url).into_response())
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
pub async fn handle_oauth_callback_jwt<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    token_manager: Arc<TokenManager>,
    expires_in_secs: u64,
    config: &SessionConfig,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let (identity, _token) = finalize_callback(flow, config, &cookies, &params).await?;

    let jwt = token_manager
        .issue_user_token(identity, expires_in_secs, None)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token error: {}", e),
            )
        })?;

    Ok(Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": expires_in_secs
    })))
}

/// Helper to handle logout by deleting the session from the store and clearing the cookie.
///
/// Returns a redirect to the specified URL.
pub async fn logout(
    cookies: Cookies,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    redirect_to: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = cookies
        .get(&config.cookie_name)
        .map(|c| c.value().to_string());

    if let Some(id) = session_id {
        store
            .delete_session(&id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let mut cookie = config.create_cookie("".to_string());
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::ZERO));
    cookies.remove(cookie);

    Ok(Redirect::to(redirect_to))
}

#[derive(Debug)]
pub enum AuthlyAxumError {
    Unauthorized(String),
    Internal(String),
}

impl IntoResponse for AuthlyAxumError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AuthlyAxumError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AuthlyAxumError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, message).into_response()
    }
}

pub async fn get_session(
    store: &Arc<dyn SessionStore>,
    config: &SessionConfig,
    cookies: &Cookies,
) -> Result<Session, AuthlyAxumError> {
    let session_id = cookies
        .get(&config.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| AuthlyAxumError::Unauthorized("Missing session cookie".to_string()))?;

    let session = store
        .load_session(&session_id)
        .await
        .map_err(|e| AuthlyAxumError::Internal(e.to_string()))?
        .ok_or_else(|| AuthlyAxumError::Unauthorized("Invalid session".to_string()))?;

    Ok(session)
}

pub async fn get_token(
    parts: &Parts,
    token_manager: &TokenManager,
) -> Result<authly_token::Claims, AuthlyAxumError> {
    let auth_header = parts.headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AuthlyAxumError::Unauthorized("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AuthlyAxumError::Unauthorized("Invalid Authorization header".to_string()));
    }

    let token = &auth_header[7..];
    let claims = token_manager.validate_token(token)
        .map_err(|e| AuthlyAxumError::Unauthorized(format!("Invalid token: {}", e)))?;

    Ok(claims)
}
