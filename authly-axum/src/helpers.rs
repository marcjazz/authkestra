use authly_core::{Identity, OAuthProvider, OAuthToken};
use authly_flow::OAuth2Flow;
use authly_session::{Session, SessionStore};
use authly_token::TokenManager;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use std::sync::Arc;
use tower_cookies::{Cookies, Cookie, cookie::SameSite};

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
    cookies: &Cookies,
    scopes: &[&str],
) -> Redirect
where
    P: OAuthProvider,
    M: authly_core::UserMapper,
{
    let (url, csrf_state) = flow.initiate_login(scopes);

    let mut cookie = Cookie::new("oauth_state", csrf_state);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);

    cookies.add(cookie);

    Redirect::to(&url)
}

/// Internal helper to finalize the OAuth flow by validating state and exchanging the code.
async fn finalize_callback<P, M>(
    flow: &OAuth2Flow<P, M>,
    cookies: &Cookies,
    params: &OAuthCallbackParams,
) -> Result<(Identity, OAuthToken), (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let expected_state = cookies
        .get("oauth_state")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    // Remove the state cookie after use
    let mut remove_cookie = Cookie::new("oauth_state", "");
    remove_cookie.set_path("/");
    cookies.remove(remove_cookie);

    let (identity, token, _local_user) = flow
        .finalize_login(&params.code, &params.state, &expected_state)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Authentication failed: {}", e)))?;

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
    let (mut identity, token) = finalize_callback(flow, &cookies, &params).await?;

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

    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        identity,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
    };

    store
        .save_session(&session)
        .await
        .map_err(|e| {
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
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let (identity, _token) = finalize_callback(flow, &cookies, &params).await?;

    let jwt = token_manager
        .issue_token(identity, expires_in_secs)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Token error: {}", e)))?;

    Ok(Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": expires_in_secs
    })))
}
