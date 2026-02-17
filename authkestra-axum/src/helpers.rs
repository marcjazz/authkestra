use authkestra_core::{
    pkce::Pkce,
    state::{Identity, OAuthToken},
};
#[cfg(all(feature = "flow", not(feature = "session")))]
use authkestra_flow::SessionConfig;
#[cfg(feature = "flow")]
use authkestra_flow::{Authkestra, ErasedOAuthFlow, OAuth2Flow};
#[cfg(feature = "session")]
pub use authkestra_session::{Session, SessionConfig, SessionStore};
#[cfg(feature = "token")]
use authkestra_token::TokenManager;
#[cfg(feature = "token")]
use axum::Json;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use std::sync::Arc;
#[cfg(any(feature = "flow", feature = "session"))]
use tower_cookies::cookie::SameSite;
#[cfg(any(feature = "flow", feature = "session"))]
use tower_cookies::{Cookie, Cookies};

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

#[cfg(any(feature = "flow", feature = "session"))]
pub fn to_axum_same_site(ss: authkestra_core::SameSite) -> SameSite {
    match ss {
        authkestra_core::SameSite::Lax => SameSite::Lax,
        authkestra_core::SameSite::Strict => SameSite::Strict,
        authkestra_core::SameSite::None => SameSite::None,
    }
}

#[cfg(feature = "session")]
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
#[cfg(feature = "flow")]
pub fn initiate_oauth_login(
    flow: &dyn ErasedOAuthFlow,
    cookies: &Cookies,
    scopes: &[&str],
) -> Redirect {
    let pkce = Pkce::new();
    let (url, csrf_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    let cookie_name = format!("authkestra_flow_{csrf_state}");

    let mut cookie = Cookie::new(cookie_name, pkce.code_verifier);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(true);
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));

    cookies.add(cookie);

    Redirect::to(&url)
}

/// Internal helper to finalize the OAuth flow by validating state and exchanging the code.
#[cfg(feature = "flow")]
async fn finalize_callback_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: &Cookies,
    params: &OAuthCallbackParams,
) -> Result<(Identity, OAuthToken), (StatusCode, String)> {
    let state = &params.state;
    let cookie_name = format!("authkestra_flow_{state}");

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
    remove_cookie.set_secure(true);

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
                format!("Authentication failed: {e}"),
            )
        })?;

    Ok((identity, token))
}

/// Helper to handle the OAuth2 callback and create a server-side session.
#[cfg(all(feature = "flow", feature = "session"))]
pub async fn handle_oauth_callback_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (mut identity, token) = finalize_callback_erased(flow, &cookies, &params).await?;

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
            format!("Failed to save session: {e}"),
        )
    })?;

    let cookie = create_axum_cookie(&config, session.id);
    cookies.add(cookie);

    Ok(Redirect::to(success_url).into_response())
}

/// Helper to handle the OAuth2 callback and create a server-side session.
#[cfg(all(feature = "flow", feature = "session"))]
pub async fn handle_oauth_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: authkestra_core::OAuthProvider + Send + Sync,
    M: authkestra_core::UserMapper + Send + Sync,
{
    handle_oauth_callback_erased(flow, cookies, params, store, config, success_url).await
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(all(feature = "flow", feature = "token"))]
pub async fn handle_oauth_callback_jwt_erased(
    flow: &dyn ErasedOAuthFlow,
    cookies: Cookies,
    params: OAuthCallbackParams,
    token_manager: Arc<TokenManager>,
    expires_in_secs: u64,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (identity, _token) = finalize_callback_erased(flow, &cookies, &params).await?;

    let jwt = token_manager
        .issue_user_token(identity, expires_in_secs, None)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token error: {e}"),
            )
        })?;

    Ok(Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": expires_in_secs
    })))
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(all(feature = "flow", feature = "token"))]
pub async fn handle_oauth_callback_jwt<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: Cookies,
    params: OAuthCallbackParams,
    token_manager: Arc<TokenManager>,
    expires_in_secs: u64,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: authkestra_core::OAuthProvider + Send + Sync,
    M: authkestra_core::UserMapper + Send + Sync,
{
    handle_oauth_callback_jwt_erased(flow, cookies, params, token_manager, expires_in_secs).await
}

/// Helper to handle logout by deleting the session from the store and clearing the cookie.
///
/// Returns a redirect to the specified URL.
#[cfg(feature = "session")]
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

#[cfg(feature = "flow")]
pub async fn axum_login_handler<AppState, S, T>(
    Path(provider): Path<String>,
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(params): Query<OAuthLoginParams>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AuthkestraAxumError>
where
    AppState: Clone + Send + Sync + 'static,
    Authkestra<S, T>: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let authkestra = Authkestra::<S, T>::from_ref(&state);

    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Err(AuthkestraAxumError::Internal(
                "Provider not found".to_string(),
            ));
        }
    };

    let scopes_str = params.scope.unwrap_or_default();
    let scopes: Vec<&str> = scopes_str
        .split(|c: char| [' ', ','].contains(&c))
        .filter(|s| !s.is_empty())
        .collect();

    let pkce = Pkce::new();
    let (url, csrf_state) = flow.initiate_login(&scopes, Some(&pkce.code_challenge));

    let cookie_name = format!("authkestra_flow_{csrf_state}");
    let mut cookie = Cookie::new(cookie_name, pkce.code_verifier);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(true);
    cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));
    cookies.add(cookie);

    if let Some(success_url) = params.success_url {
        let success_cookie_name = format!("authkestra_success_{csrf_state}");
        let mut success_cookie = Cookie::new(success_cookie_name, success_url);
        success_cookie.set_path("/");
        success_cookie.set_http_only(true);
        success_cookie.set_same_site(SameSite::Lax);
        success_cookie.set_secure(true);
        success_cookie.set_max_age(Some(tower_cookies::cookie::time::Duration::minutes(15)));
        cookies.add(success_cookie);
    }

    Ok(Redirect::to(&url))
}

#[cfg(all(feature = "flow", feature = "session"))]
pub async fn axum_callback_handler<AppState, S, T>(
    Path(provider): Path<String>,
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(params): Query<OAuthCallbackParams>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AuthkestraAxumError>
where
    AppState: Clone + Send + Sync + 'static,
    Authkestra<S, T>: axum::extract::FromRef<AppState>,
    SessionConfig: axum::extract::FromRef<AppState>,
    Result<Arc<dyn SessionStore>, AuthkestraAxumError>: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let authkestra = Authkestra::<S, T>::from_ref(&state);
    let session_config = SessionConfig::from_ref(&state);
    let session_store = <Result<Arc<dyn SessionStore>, AuthkestraAxumError>>::from_ref(&state)?;

    let flow: &Arc<dyn ErasedOAuthFlow> = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Err(AuthkestraAxumError::Internal(
                "Provider not found".to_string(),
            ));
        }
    };

    let state = &params.state;
    let success_url_cookie_name = format!("authkestra_success_{state}");
    let success_url = cookies
        .get(&success_url_cookie_name)
        .map(|c| c.value().to_string())
        .unwrap_or_else(|| "/".to_string());

    if let Some(_cookie) = cookies.get(&success_url_cookie_name) {
        let mut remove_cookie = Cookie::new(success_url_cookie_name, "");
        remove_cookie.set_path("/");
        remove_cookie.set_secure(true);
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
    .map_err(|(status, msg)| {
        if status == StatusCode::UNAUTHORIZED {
            AuthkestraAxumError::Unauthorized(msg)
        } else {
            AuthkestraAxumError::Internal(msg)
        }
    })
}

#[cfg(all(feature = "flow", feature = "session"))]
pub async fn axum_logout_handler<AppState, S, T>(
    axum::extract::State(state): axum::extract::State<AppState>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AuthkestraAxumError>
where
    AppState: Clone + Send + Sync + 'static,
    SessionConfig: axum::extract::FromRef<AppState>,
    Result<Arc<dyn SessionStore>, AuthkestraAxumError>: axum::extract::FromRef<AppState>,
{
    use axum::extract::FromRef;
    let session_config = SessionConfig::from_ref(&state);
    let session_store = <Result<Arc<dyn SessionStore>, AuthkestraAxumError>>::from_ref(&state)?;

    logout(cookies, session_store, session_config, "/")
        .await
        .map_err(|(status, msg)| {
            if status == StatusCode::UNAUTHORIZED {
                AuthkestraAxumError::Unauthorized(msg)
            } else {
                AuthkestraAxumError::Internal(msg)
            }
        })
}

#[derive(Debug)]
pub enum AuthkestraAxumError {
    Unauthorized(String),
    Internal(String),
    /// A required component (e.g., SessionManager, TokenManager) is missing
    ComponentMissing(String),
}

impl IntoResponse for AuthkestraAxumError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AuthkestraAxumError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AuthkestraAxumError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AuthkestraAxumError::ComponentMissing(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, message).into_response()
    }
}

#[cfg(feature = "session")]
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

#[cfg(feature = "token")]
pub async fn get_token(
    parts: &axum::http::request::Parts,
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
        .map_err(|e| AuthkestraAxumError::Unauthorized(format!("Invalid token: {e}")))?;

    Ok(claims)
}
