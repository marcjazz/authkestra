#[cfg(any(feature = "flow", feature = "session", feature = "token"))]
use actix_web::{cookie::Cookie, http::header, web, HttpRequest, HttpResponse};
#[cfg(feature = "flow")]
use authkestra_engine::pkce::Pkce;
#[cfg(all(feature = "flow", not(feature = "session")))]
use authkestra_engine::SessionConfig;
#[cfg(feature = "flow")]
use authkestra_engine::{state::OAuth2State, AuthEngine, ErasedOAuthFlow, OAuth2Flow};
#[cfg(feature = "session")]
pub use authkestra_session::{Session, SessionConfig, SessionStore};
use std::sync::Arc;

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

#[cfg(feature = "session")]
pub fn to_actix_same_site(ss: authkestra_engine::SameSite) -> actix_web::cookie::SameSite {
    match ss {
        authkestra_engine::SameSite::Lax => actix_web::cookie::SameSite::Lax,
        authkestra_engine::SameSite::Strict => actix_web::cookie::SameSite::Strict,
        authkestra_engine::SameSite::None => actix_web::cookie::SameSite::None,
    }
}

#[cfg(feature = "session")]
pub fn create_actix_cookie<'a>(config: &SessionConfig, value: String) -> Cookie<'a> {
    let mut builder = Cookie::build(config.cookie_name.clone(), value)
        .path(config.path.clone())
        .secure(config.secure)
        .http_only(config.http_only)
        .same_site(to_actix_same_site(config.same_site));

    if let Some(max_age) = config.max_age {
        builder = builder.max_age(actix_web::cookie::time::Duration::seconds(
            max_age.num_seconds(),
        ));
    }
    builder.finish()
}

/// Helper to initiate the OAuth2 login flow.
///
/// This generates the authorization URL and sets a CSRF state cookie.
#[cfg(feature = "flow")]
pub fn initiate_oauth_login<P, M>(
    flow: &OAuth2Flow<P, M>,
    scopes: &[&str],
    config: &SessionConfig,
    success_url: Option<String>,
) -> HttpResponse
where
    P: authkestra_engine::OAuthProvider + 'static,
    M: authkestra_engine::UserMapper + 'static,
{
    initiate_oauth_login_erased(flow, scopes, config, success_url)
}

#[cfg(feature = "flow")]
pub fn initiate_oauth_login_erased(
    flow: &dyn ErasedOAuthFlow,
    scopes: &[&str],
    config: &SessionConfig,
    success_url: Option<String>,
) -> HttpResponse {
    let pkce = Pkce::new();
    let (url, mut auth_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    auth_state.code_verifier = Some(pkce.code_verifier);
    auth_state.success_url = success_url;

    let encrypted = auth_state
        .encrypt(&config.state_encryption_key)
        .expect("Failed to encrypt OAuth state");

    let cookie_name = "ak_state";

    let cookie = Cookie::build(cookie_name, encrypted)
        .path("/")
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .secure(true)
        .max_age(actix_web::cookie::time::Duration::minutes(15))
        .finish();

    HttpResponse::Found()
        .insert_header((header::LOCATION, url))
        .cookie(cookie)
        .finish()
}

/// Helper to handle the OAuth2 callback and create a server-side session.
#[cfg(all(feature = "flow", feature = "session"))]
pub async fn handle_oauth_callback<P, M>(
    req: HttpRequest,
    flow: &OAuth2Flow<P, M>,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<HttpResponse, actix_web::Error>
where
    P: authkestra_engine::OAuthProvider + Send + Sync + 'static,
    M: authkestra_engine::UserMapper + Send + Sync + 'static,
{
    handle_oauth_callback_erased(req, flow, params, store, config, success_url).await
}

#[cfg(all(feature = "flow", feature = "session"))]
pub async fn handle_oauth_callback_erased(
    req: HttpRequest,
    flow: &dyn ErasedOAuthFlow,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    _success_url: &str,
) -> Result<HttpResponse, actix_web::Error> {
    let cookie_name = "ak_state";
    let encrypted_state = req
        .cookie(cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            actix_web::error::ErrorUnauthorized("CSRF validation failed or session expired")
        })?;

    let expected_state = OAuth2State::decrypt(&encrypted_state, &config.state_encryption_key)
        .map_err(|e| actix_web::error::ErrorUnauthorized(format!("Invalid state cookie: {e}")))?;

    // Exchange code
    let (mut identity, token) = flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
        .map_err(|e| actix_web::error::ErrorUnauthorized(format!("Authentication failed: {e}")))?;

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
        actix_web::error::ErrorInternalServerError(format!("Failed to save session: {e}"))
    })?;

    let cookie = create_actix_cookie(&config, session.id);

    // Remove the flow cookie
    let remove_cookie = Cookie::build(cookie_name, "")
        .path("/")
        .secure(true)
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .finish();

    let final_success_url = expected_state
        .success_url
        .unwrap_or_else(|| "/".to_string());

    Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, final_success_url))
        .cookie(cookie)
        .cookie(remove_cookie)
        .finish())
}

#[cfg(feature = "flow")]
pub async fn actix_login_handler<S, T>(
    path: web::Path<String>,
    authkestra: web::Data<AuthEngine<S, T>>,
    params: web::Query<OAuthLoginParams>,
) -> impl actix_web::Responder {
    let provider = path.into_inner();
    let flow = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return HttpResponse::NotFound().body(format!("Provider {provider} not found"));
        }
    };

    let scopes_str = params.scope.clone().unwrap_or_default();
    let scopes: Vec<&str> = scopes_str
        .split(|c: char| [' ', ','].contains(&c))
        .filter(|s| !s.is_empty())
        .collect();

    initiate_oauth_login_erased(
        flow.as_ref(),
        &scopes,
        &authkestra.session_config,
        params.success_url.clone(),
    )
}

#[cfg(all(feature = "flow", feature = "session"))]
pub async fn actix_callback_handler<S, T>(
    req: HttpRequest,
    path: web::Path<String>,
    authkestra: web::Data<AuthEngine<S, T>>,
    params: web::Query<OAuthCallbackParams>,
) -> actix_web::Result<impl actix_web::Responder>
where
    S: authkestra_engine::SessionStoreState,
{
    let provider = path.into_inner();
    let flow = match authkestra.providers.get(&provider) {
        Some(f) => f,
        None => {
            return Ok(HttpResponse::NotFound().body(format!("Provider {provider} not found")));
        }
    };

    let callback_params = params.into_inner();

    let response = handle_oauth_callback_erased(
        req,
        flow.as_ref(),
        callback_params,
        authkestra.session_store.get_store(),
        authkestra.session_config.clone(),
        "",
    )
    .await?;

    Ok(response)
}

#[cfg(all(feature = "flow", feature = "session"))]
pub async fn actix_logout_handler<S, T>(
    req: HttpRequest,
    authkestra: web::Data<AuthEngine<S, T>>,
) -> actix_web::Result<impl actix_web::Responder>
where
    S: authkestra_engine::SessionStoreState,
{
    logout(
        req,
        authkestra.session_store.get_store(),
        authkestra.session_config.clone(),
        "/",
    )
    .await
}

/// Helper to handle logout by deleting the session from the store and clearing the cookie.
#[cfg(feature = "session")]
pub async fn logout(
    req: HttpRequest,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    redirect_to: &str,
) -> Result<HttpResponse, actix_web::Error> {
    let session_id = req
        .cookie(&config.cookie_name)
        .map(|c| c.value().to_string());

    if let Some(id) = session_id {
        store
            .delete_session(&id)
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    }

    let remove_cookie = create_actix_cookie(&config, "".to_string());

    Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, redirect_to))
        .cookie(remove_cookie)
        .finish())
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(all(feature = "flow", feature = "token"))]
pub async fn handle_oauth_callback_jwt_erased(
    flow: &dyn ErasedOAuthFlow,
    req: &HttpRequest,
    params: OAuthCallbackParams,
    token_manager: Arc<authkestra_engine::TokenManager>,
    expires_in_secs: u64,
    config: SessionConfig,
) -> Result<HttpResponse, actix_web::Error> {
    let cookie_name = "ak_state";

    let encrypted_state = req
        .cookie(cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            actix_web::error::ErrorUnauthorized("CSRF validation failed or session expired")
        })?;

    let expected_state = OAuth2State::decrypt(&encrypted_state, &config.state_encryption_key)
        .map_err(|e| actix_web::error::ErrorUnauthorized(format!("Invalid state cookie: {e}")))?;

    // Exchange code
    let (identity, _token) = flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
        .map_err(|e| actix_web::error::ErrorUnauthorized(format!("Authentication failed: {e}")))?;

    let jwt = token_manager
        .issue_user_token(identity, expires_in_secs, None)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Token error: {e}")))?;

    let mut res = HttpResponse::Ok();

    // Remove the flow cookie
    let remove_cookie = Cookie::build(cookie_name, "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .secure(true)
        .finish();

    res.cookie(remove_cookie);

    Ok(res.json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": expires_in_secs
    })))
}

/// Helper to handle the OAuth2 callback and return a JWT for stateless auth.
#[cfg(all(feature = "flow", feature = "token"))]
pub async fn handle_oauth_callback_jwt<P, M>(
    flow: &OAuth2Flow<P, M>,
    req: &HttpRequest,
    params: OAuthCallbackParams,
    token_manager: Arc<authkestra_engine::TokenManager>,
    expires_in_secs: u64,
    config: SessionConfig,
) -> Result<HttpResponse, actix_web::Error>
where
    P: authkestra_engine::OAuthProvider + Send + Sync + 'static,
    M: authkestra_engine::UserMapper + Send + Sync + 'static,
{
    handle_oauth_callback_jwt_erased(flow, req, params, token_manager, expires_in_secs, config)
        .await
}
