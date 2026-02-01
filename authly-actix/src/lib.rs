use actix_web::{dev::Payload, http::header, web, Error, FromRequest, HttpRequest};
use authly_core::{Session, SessionStore, SessionConfig};
use authly_flow::Authly;
use authly_token::TokenManager;
use futures::future::LocalBoxFuture;
use std::sync::Arc;

pub mod helpers;
pub use helpers::*;

pub trait AuthlyActixExt {
    fn actix_scope(&self) -> actix_web::Scope;
}

impl AuthlyActixExt for Authly {
    fn actix_scope(&self) -> actix_web::Scope {
        web::scope("/auth")
            .route("/{provider}", web::get().to(actix_login_handler))
            .route("/{provider}/callback", web::get().to(actix_callback_handler))
            .route("/logout", web::get().to(actix_logout_handler))
    }
}

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

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
                    .unwrap_or("authly_session"),
            )
            .map(|c| c.value().to_string());

        Box::pin(async move {
            let store = store.ok_or_else(|| {
                actix_web::error::ErrorInternalServerError("SessionStore not configured")
            })?;
            let _config = config.ok_or_else(|| {
                actix_web::error::ErrorInternalServerError("SessionConfig not configured")
            })?;

            let session_id = session_id
                .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing session cookie"))?;

            let session = store
                .get_ref()
                .load_session(&session_id)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?
                .ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid session"))?;

            Ok(AuthSession(session))
        })
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
pub struct AuthToken(pub authly_token::Claims);

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
            let token_manager = token_manager.ok_or_else(|| {
                actix_web::error::ErrorInternalServerError("TokenManager not configured")
            })?;
            let auth_header = auth_header.ok_or_else(|| {
                actix_web::error::ErrorUnauthorized("Missing Authorization header")
            })?;

            if !auth_header.starts_with("Bearer ") {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Authorization header",
                ));
            }

            let token = &auth_header[7..];
            let claims = token_manager.get_ref().validate_token(token).map_err(|e| {
                actix_web::error::ErrorUnauthorized(format!("Invalid token: {}", e))
            })?;

            Ok(AuthToken(claims))
        })
    }
}
