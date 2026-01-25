use actix_web::{http::header, cookie::Cookie, HttpResponse, HttpRequest};
use authly_core::{pkce::Pkce, OAuthProvider};
use authly_flow::OAuth2Flow;
use authly_session::{Session, SessionStore};
use std::sync::Arc;

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
    pub same_site: actix_web::cookie::SameSite,
    pub path: String,
    pub max_age: Option<chrono::Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "authly_session".to_string(),
            secure: true,
            http_only: true,
            same_site: actix_web::cookie::SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
        }
    }
}

impl SessionConfig {
    pub fn create_cookie<'a>(&self, value: String) -> Cookie<'a> {
        let mut builder = Cookie::build(self.cookie_name.clone(), value)
            .path(self.path.clone())
            .secure(self.secure)
            .http_only(self.http_only)
            .same_site(self.same_site);
        
        if let Some(max_age) = self.max_age {
            builder = builder.max_age(actix_web::cookie::time::Duration::seconds(
                max_age.num_seconds(),
            ));
        }
        builder.finish()
    }
}

/// Helper to initiate the OAuth2 login flow.
///
/// This generates the authorization URL and sets a CSRF state cookie.
pub fn initiate_oauth_login<P, M>(
    flow: &OAuth2Flow<P, M>,
    scopes: &[&str],
) -> HttpResponse
where
    P: OAuthProvider,
    M: authly_core::UserMapper,
{
    let pkce = Pkce::new();
    let (url, csrf_state) = flow.initiate_login(scopes, Some(&pkce.code_challenge));

    let cookie_name = format!("authly_flow_{}", csrf_state);

    let cookie = Cookie::build(cookie_name, pkce.code_verifier)
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
pub async fn handle_oauth_callback<P, M>(
    req: HttpRequest,
    flow: &OAuth2Flow<P, M>,
    params: OAuthCallbackParams,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    success_url: &str,
) -> Result<HttpResponse, actix_web::Error>
where
    P: OAuthProvider + Send + Sync,
    M: authly_core::UserMapper + Send + Sync,
{
    let cookie_name = format!("authly_flow_{}", params.state);
    let pkce_verifier = req.cookie(&cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("CSRF validation failed or session expired"))?;

    // Exchange code
    let (mut identity, token, _local_user) = flow
        .finalize_login(
            &params.code,
            &params.state,
            &params.state, // We use the state itself as expected_state
            Some(&pkce_verifier),
        )
        .await
        .map_err(|e| actix_web::error::ErrorUnauthorized(format!("Authentication failed: {}", e)))?;

    // Store tokens in identity attributes for convenience
    identity.attributes.insert("access_token".to_string(), token.access_token);
    if let Some(expires_in) = token.expires_in {
        let expires_at = chrono::Utc::now().timestamp() + expires_in as i64;
        identity.attributes.insert("expires_at".to_string(), expires_at.to_string());
    }
    if let Some(rt) = token.refresh_token {
        identity.attributes.insert("refresh_token".to_string(), rt);
    }
    println!("Created identity: {:?}", identity);

    let session_duration = config.max_age.unwrap_or(chrono::Duration::hours(24));
    let session = Session {
        id: uuid::Uuid::new_v4().to_string(),
        identity,
        expires_at: chrono::Utc::now() + session_duration,
    };

    store.save_session(&session).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to save session: {}", e)))?;

    let cookie = config.create_cookie(session.id);
    
    // Remove the flow cookie
    let remove_cookie = Cookie::build(cookie_name, "")
        .path("/")
        .secure(true)
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .finish();

    Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, success_url))
        .cookie(cookie)
        .cookie(remove_cookie)
        .finish())
}

/// Helper to handle logout by deleting the session from the store and clearing the cookie.
pub async fn logout(
    req: HttpRequest,
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    redirect_to: &str,
) -> Result<HttpResponse, actix_web::Error> {
    let session_id = req.cookie(&config.cookie_name)
        .map(|c| c.value().to_string());

    if let Some(id) = session_id {
        store.delete_session(&id).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    }

    let mut remove_cookie = config.create_cookie("".to_string());
    remove_cookie.set_max_age(Some(actix_web::cookie::time::Duration::ZERO));

    Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, redirect_to))
        .cookie(remove_cookie)
        .finish())
}
