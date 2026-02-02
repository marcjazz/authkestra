pub use authkestra_core::SessionConfig;
use authkestra_core::{pkce::Pkce, Identity, OAuthProvider, OAuthToken, Session, SessionStore};
use authkestra_flow::{Authkestra, ErasedOAuthFlow, OAuth2Flow};
use authkestra_token::TokenManager;
use axum::{
    extract::{FromRef, Path, Query, State},
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

#[derive(serde::Deserialize)]
pub struct OAuthLoginParams {
    pub scope: Option<String>,
    pub success_url: Option<String>,
}

pub fn to_axum_same_site(ss: authkestra_core::SameSite) -> SameSite {
    match ss {
        authkestra_core::SameSite::Lax => SameSite::Lax,
        authkestra_core::SameSite::Strict => SameSite::Strict,
        authkestra_core::SameSite::None => SameSite::None,
    }
}

pub fn create_axum_cookie<'a>(config: &SessionConfig, value: String) -> Cookie<'a> {
    let mut cookie = Cookie::new(config.cookie_name.clone(), value);
    cookie.set_path(config.path.clone());
    cookie.set_secure(config.secure);
    cookie.set_http_only(config.http_only);
    cookie.set_same_site(to_axum_same_site(config.same_site));
    if let Some(max_age) = config.max_age {
        cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::seconds(
            max_age.num_seconds(),
        )));
    }
    cookie
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
    M: authkestra_core::UserMapper,
{
    let pkce = Pkce::new();
    let (url, csrf_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    let cookie_name = format!("authkestra_flow_{}", csrf_state);

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
async fn finalize_callback_erased(
    flow: &dyn ErasedOAuthFlow,
    session_config: &SessionConfig,
    cookies: &Cookies,
    params: &OAuthCallbackParams,
) -> Result<(Identity, OAuthToken), (StatusCode, String)> {
    let cookie_name = format!("authkestra_flow_{}", params.state);

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

    let (identity, token) = flow
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

/// Internal helper to finalize the OAuth flow by validating state and exchanging the code.
async fn finalize_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    session_config: &SessionConfig,
    cookies: &Cookies,
    params: &OAuthCallbackParams,
) -> Result<(Identity, OAuthToken), (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authkestra_core::UserMapper + Send + Sync,
{
    finalize_callback_erased(flow, session_config, cookies, params).await
}

/// Helper to handle the OAuth2 callback and create a server-side session.
pub async fn handle_oauth_callback_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (mut identity, token) = finalize_callback_erased(flow, &config, &cookies, &params).await?;

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

    let cookie = create_axum_cookie(&config, session.id);
    cookies.add(cookie);

    Ok(Redirect::to(success_url).into_response())
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
    M: authkestra_core::UserMapper + Send + Sync,
{
    handle_oauth_callback_erased(flow, cookies, params, store, config, success_url).await
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
    M: authkestra_core::UserMapper + Send + Sync,
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

    let mut cookie = create_axum_cookie(&config, "".to_string());
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::ZERO));
    cookies.remove(cookie);

    Ok(Redirect::to(redirect_to))
}

pub async fn axum_login_handler<S>(
    Path(provider): Path<String>,
    State(state): State<S>,
    Query(params): Query<OAuthLoginParams>,
    cookies: Cookies,
) -> impl IntoResponse
where
    S: Clone + Send + Sync + 'static,
    Authkestra: axum::extract::FromRef<S>,
    SessionConfig: axum::extract::FromRef<S>,
{
    let authkestra = Authkestra::from_ref(&state);
    let session_config = SessionConfig::from_ref(&state);
    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => return (StatusCode::NOT_FOUND, "Provider not found").into_response(),
    };

    let scopes_str = params.scope.unwrap_or_default();
    let scopes: Vec<&str> = scopes_str.split_whitespace().collect();

    let pkce = Pkce::new();
    let (url, csrf_state) = flow.initiate_login(&scopes, Some(&pkce.code_challenge));

    let cookie_name = format!("authkestra_flow_{}", csrf_state);

    let mut cookie = Cookie::new(cookie_name, pkce.code_verifier);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(session_config.secure);
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));

    cookies.add(cookie);

    if let Some(success_url) = params.success_url {
        let mut cookie = Cookie::new(format!("authkestra_success_{}", csrf_state), success_url);
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_secure(session_config.secure);
        cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));
        cookies.add(cookie);
    }

    Redirect::to(&url).into_response()
}

pub async fn axum_callback_handler<S>(
    Path(provider): Path<String>,
    State(state): State<S>,
    Query(params): Query<OAuthCallbackParams>,
    cookies: Cookies,
) -> impl IntoResponse
where
    S: Clone + Send + Sync + 'static,
    Authkestra: axum::extract::FromRef<S>,
    SessionConfig: axum::extract::FromRef<S>,
    Arc<dyn SessionStore>: axum::extract::FromRef<S>,
{
    let authkestra = Authkestra::from_ref(&state);
    let session_config = SessionConfig::from_ref(&state);
    let session_store = Arc::<dyn SessionStore>::from_ref(&state);

    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => return (StatusCode::NOT_FOUND, "Provider not found").into_response(),
    };

    let success_url_cookie_name = format!("authkestra_success_{}", params.state);
    let success_url = cookies
        .get(&success_url_cookie_name)
        .map(|c| c.value().to_string())
        .unwrap_or_else(|| "/".to_string());

    if let Some(_cookie) = cookies.get(&success_url_cookie_name) {
        let mut remove_cookie = Cookie::new(success_url_cookie_name, "");
        remove_cookie.set_path("/");
        remove_cookie.set_secure(session_config.secure);
        cookies.remove(remove_cookie);
    }

    handle_oauth_callback_erased(
        flow.as_ref(),
        cookies,
        params,
        session_store,
        session_config,
        &success_url,
    )
    .await
    .into_response()
}

pub async fn axum_logout_handler<S>(State(state): State<S>, cookies: Cookies) -> impl IntoResponse
where
    S: Clone + Send + Sync + 'static,
    SessionConfig: axum::extract::FromRef<S>,
    Arc<dyn SessionStore>: axum::extract::FromRef<S>,
{
    let session_config = SessionConfig::from_ref(&state);
    let session_store = Arc::<dyn SessionStore>::from_ref(&state);

    logout(cookies, session_store, session_config, "/").await
}

#[derive(Debug)]
pub enum AuthkestraAxumError {
    Unauthorized(String),
    Internal(String),
}

impl IntoResponse for AuthkestraAxumError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AuthkestraAxumError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AuthkestraAxumError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, message).into_response()
    }
}

pub async fn get_session(
    store: &Arc<dyn SessionStore>,
    config: &SessionConfig,
    cookies: &Cookies,
) -> Result<Session, AuthkestraAxumError> {
    let session_id = cookies
        .get(&config.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| AuthkestraAxumError::Unauthorized("Missing session cookie".to_string()))?;

    let session = store
        .load_session(&session_id)
        .await
        .map_err(|e| AuthkestraAxumError::Internal(e.to_string()))?
        .ok_or_else(|| AuthkestraAxumError::Unauthorized("Invalid session".to_string()))?;

    Ok(session)
}

pub async fn get_token(
    parts: &Parts,
    token_manager: &TokenManager,
) -> Result<authkestra_token::Claims, AuthkestraAxumError> {
    let auth_header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            AuthkestraAxumError::Unauthorized("Missing Authorization header".to_string())
        })?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AuthkestraAxumError::Unauthorized(
            "Invalid Authorization header".to_string(),
        ));
    }

    let token = &auth_header[7..];
    let claims = token_manager
        .validate_token(token)
        .map_err(|e| AuthkestraAxumError::Unauthorized(format!("Invalid token: {}", e)))?;

    Ok(claims)
}
