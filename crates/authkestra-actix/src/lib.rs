#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use actix_web::{dev::Payload, http::header, web, Error, FromRequest, HttpRequest};
#[cfg(feature = "session")]
pub use authkestra_engine::auth::{Session, SessionStore};
#[cfg(all(feature = "flow", feature = "session"))]
pub use authkestra_engine::SessionStoreState;
#[cfg(feature = "token")]
pub use authkestra_engine::TokenManager;
#[cfg(all(feature = "flow", feature = "token"))]
pub use authkestra_engine::TokenManagerState;
#[cfg(all(feature = "flow", any(feature = "session", feature = "token")))]
pub use authkestra_engine::Missing;
#[cfg(feature = "flow")]
pub use authkestra_engine::{Engine, SessionConfig};
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use futures::future::LocalBoxFuture;
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use std::sync::Arc;

pub mod helpers;

#[cfg(feature = "op")]
pub mod op;

#[cfg(feature = "macros")]
pub use authkestra_macros::ActixState;

#[cfg(feature = "flow")]
pub use helpers::actix_login_handler;
#[cfg(all(feature = "flow", feature = "session"))]
pub use helpers::{actix_callback_handler, actix_logout_handler};

#[cfg(feature = "op")]
pub use op::OpExt;

#[cfg(feature = "flow")]
pub trait ActixExt<S, T> {
    fn actix_scope(&self) -> actix_web::Scope;
}

#[cfg(feature = "flow")]
#[cfg(all(feature = "flow", feature = "session"))]
impl<S, T> ActixExt<S, T> for Engine<S, T>
where
    S: Clone + SessionStoreState + 'static,
    T: Clone + 'static,
{
    fn actix_scope(&self) -> actix_web::Scope {
        let mut scope = web::scope("/auth");

        scope = scope.route(
            "/login/{provider}",
            web::get().to(actix_login_handler::<S, T>),
        );
        scope = scope.route(
            "/callback/{provider}",
            web::get().to(actix_callback_handler::<S, T>),
        );
        scope = scope.route("/logout", web::get().to(actix_logout_handler::<S, T>));

        scope
    }
}

/// The extractor for a validated session.
#[cfg(feature = "session")]
pub struct AuthSession(pub Session);

#[cfg(all(feature = "flow", feature = "session"))]
impl FromRequest for AuthSession {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let store = req.app_data::<web::Data<Arc<dyn SessionStore>>>().cloned();

        let config = req.app_data::<web::Data<SessionConfig>>().cloned();

        let session_id = req
            .cookie(
                config
                    .as_ref()
                    .map(|c| c.cookie_name.as_str())
                    .unwrap_or("authkestra_session"),
            )
            .map(|c| c.value().to_string());

        Box::pin(async move {
            tracing::debug!("extracting AuthSession from actix request");
            let store = store.ok_or_else(|| {
                tracing::error!("SessionStore not configured in actix app data");
                actix_web::error::ErrorInternalServerError("SessionStore not configured")
            })?;
            let _config = config.ok_or_else(|| {
                tracing::error!("SessionConfig not configured in actix app data");
                actix_web::error::ErrorInternalServerError("SessionConfig not configured")
            })?;

            let session_id = session_id.ok_or_else(|| {
                tracing::warn!("missing session cookie in request");
                actix_web::error::ErrorUnauthorized("Missing session cookie")
            })?;

            let session = store
                .get_ref()
                .load_session(&session_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to load session from store");
                    actix_web::error::ErrorInternalServerError(e.to_string())
                })?
                .ok_or_else(|| {
                    tracing::warn!("session not found or invalid");
                    actix_web::error::ErrorUnauthorized("Invalid session")
                })?;

            tracing::info!(session_id = %session.id, user_id = %session.identity.external_id, "successfully extracted actix AuthSession");
            Ok(AuthSession(session))
        })
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
#[cfg(feature = "token")]
pub struct AuthToken(pub authkestra_engine::Claims);

#[cfg(all(feature = "flow", feature = "token"))]
impl FromRequest for AuthToken {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token_manager = req.app_data::<web::Data<Arc<TokenManager>>>().cloned();

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Box::pin(async move {
            tracing::debug!("extracting AuthToken from actix request");
            let token_manager = token_manager.ok_or_else(|| {
                tracing::error!("Token manager not configured in actix app data");
                actix_web::error::ErrorInternalServerError("Token manager not configured")
            })?;
            let auth_header = auth_header.ok_or_else(|| {
                tracing::warn!("missing Authorization header in actix request");
                actix_web::error::ErrorUnauthorized("Missing Authorization header")
            })?;

            if !auth_header.starts_with("Bearer ") {
                tracing::warn!("invalid Authorization header format in actix request");
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Authorization header",
                ));
            }

            let token = &auth_header[7..];
            let claims = token_manager
                .get_ref()
                .validate_token(token, None)
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to validate token");
                    actix_web::error::ErrorUnauthorized(format!("Invalid token: {e}"))
                })?;

            tracing::info!("successfully extracted and validated actix AuthToken");
            Ok(AuthToken(claims))
        })
    }
}

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `jsonwebtoken::Validation`.
#[cfg(feature = "resource")]
pub struct Jwt<T>(pub T);

#[cfg(feature = "resource")]
impl<T> FromRequest for Jwt<T>
where
    T: for<'de> serde::Deserialize<'de> + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let cache = req
            .app_data::<web::Data<Arc<authkestra_resource::jwt::JwksCache>>>()
            .cloned();
        let validation = req
            .app_data::<web::Data<jsonwebtoken::Validation>>()
            .cloned();

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Box::pin(async move {
            tracing::debug!("extracting Jwt from actix request");
            let cache = cache.ok_or_else(|| {
                tracing::error!("JwksCache not configured in actix app data");
                actix_web::error::ErrorInternalServerError("JwksCache not configured")
            })?;
            let validation = validation.ok_or_else(|| {
                tracing::error!("jsonwebtoken::Validation not configured in actix app data");
                actix_web::error::ErrorInternalServerError(
                    "jsonwebtoken::Validation not configured",
                )
            })?;
            let auth_header = auth_header.ok_or_else(|| {
                tracing::warn!("missing Authorization header in actix request");
                actix_web::error::ErrorUnauthorized("Missing Authorization header")
            })?;

            if !auth_header.starts_with("Bearer ") {
                tracing::warn!("invalid Authorization header format in actix request");
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Authorization header",
                ));
            }

            let token = &auth_header[7..];
            let claims =
                authkestra_resource::jwt::validate_jwt_generic::<T>(token, &cache, &validation)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "failed to validate generic jwt");
                        actix_web::error::ErrorUnauthorized(format!("Invalid token: {e}"))
                    })?;

            tracing::info!("successfully extracted and validated actix Jwt");
            Ok(Jwt(claims))
        })
    }
}

/// A unified extractor for authentication.
///
/// It uses the `Guard` from the application state to validate the request.
#[cfg(feature = "resource")]
pub struct Auth<I>(pub I);

#[cfg(feature = "resource")]
impl<I> FromRequest for Auth<I>
where
    I: Send + Sync + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let guard = req
            .app_data::<web::Data<Arc<authkestra_resource::Guard<I>>>>()
            .cloned();

        let req_clone = req.clone();

        Box::pin(async move {
            tracing::debug!("extracting generic Auth from actix request via Guard");
            let guard = guard.ok_or_else(|| {
                tracing::error!("Guard not configured in actix app data");
                actix_web::error::ErrorInternalServerError("Guard not configured")
            })?;

            // Convert actix HttpRequest to http::request::Parts (http 1.0)
            let mut builder = http::Request::builder()
                .method(req_clone.method().as_str())
                .uri(req_clone.uri().to_string());
            for (name, val) in req_clone.headers() {
                if let (Ok(name), Ok(val)) = (
                    http::HeaderName::from_bytes(name.as_str().as_bytes()),
                    http::HeaderValue::from_bytes(val.as_bytes()),
                ) {
                    builder = builder.header(name, val);
                }
            }
            let http_req = builder.body(()).map_err(|e| {
                tracing::error!("failed to build http request parts: {e}");
                actix_web::error::ErrorInternalServerError("Failed to build request parts")
            })?;
            let (parts, _) = http_req.into_parts();

            match guard.authenticate(&parts).await {
                Ok(Some(identity)) => {
                    tracing::info!("successfully authenticated request via Guard");
                    Ok(Auth(identity))
                }
                Ok(None) => {
                    tracing::warn!("authentication failed: no identity returned");
                    Err(actix_web::error::ErrorUnauthorized("Authentication failed"))
                }
                Err(e) => {
                    tracing::error!(error = %e, "internal error during authentication");
                    Err(actix_web::error::ErrorInternalServerError(e.to_string()))
                }
            }
        })
    }
}
