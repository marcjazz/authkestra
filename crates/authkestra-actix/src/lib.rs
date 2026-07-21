#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use actix_web::{dev::Payload, http::header, web, Error, FromRequest, HttpRequest};
#[cfg(all(feature = "flow", feature = "session"))]
pub use authkestra_engine::SessionStoreState;
#[cfg(feature = "token")]
pub use authkestra_engine::TokenManager;
#[cfg(all(feature = "flow", feature = "token"))]
pub use authkestra_engine::TokenManagerState;
#[cfg(feature = "flow")]
pub use authkestra_engine::{AuthEngine, SessionConfig};
#[cfg(all(feature = "flow", any(feature = "session", feature = "token")))]
pub use authkestra_engine::{Configured, Missing};
#[cfg(feature = "session")]
pub use authkestra_session::{Session, SessionStore};
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use futures::future::LocalBoxFuture;
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use std::sync::Arc;

pub mod helpers;

#[cfg(feature = "op")]
pub mod op;

#[cfg(feature = "flow")]
pub use helpers::actix_login_handler;
#[cfg(all(feature = "flow", feature = "session"))]
pub use helpers::{actix_callback_handler, actix_logout_handler};

#[cfg(all(feature = "flow", feature = "session"))]
pub use AuthEngineActixExt as AuthkestraActixExt;

#[cfg(feature = "op")]
pub use op::AuthEngineActixOpExt;

#[cfg(feature = "flow")]
pub trait AuthEngineActixExt<S, T> {
    fn actix_scope(&self) -> actix_web::Scope;
}

#[cfg(feature = "flow")]
#[cfg(all(feature = "flow", feature = "session"))]
impl<S, T> AuthEngineActixExt<S, T> for AuthEngine<S, T>
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
        let store = req
            .app_data::<web::Data<Arc<dyn SessionStore>>>()
            .cloned()
            .or_else(|| {
                req.app_data::<web::Data<AuthEngine<Configured<Arc<dyn SessionStore>>, Missing>>>()
                    .map(|a| web::Data::new(a.session_store.get_store()))
            })
            .or_else(|| {
                #[cfg(feature = "token")]
                {
                    req.app_data::<web::Data<
                        AuthEngine<
                            Configured<Arc<dyn SessionStore>>,
                            Configured<Arc<TokenManager>>,
                        >,
                    >>()
                    .map(|a| web::Data::new(a.session_store.get_store()))
                }
                #[cfg(not(feature = "token"))]
                {
                    None
                }
            });

        let config = req
            .app_data::<web::Data<SessionConfig>>()
            .cloned()
            .or_else(|| {
                req.app_data::<web::Data<
                    AuthEngine<authkestra_engine::Configured<Arc<dyn SessionStore>>, Missing>,
                >>()
                .map(|a| web::Data::new(a.session_config.clone()))
            })
            .or_else(|| {
                #[cfg(feature = "token")]
                {
                    req.app_data::<web::Data<
                        AuthEngine<
                            Configured<Arc<dyn SessionStore>>,
                            Configured<Arc<TokenManager>>,
                        >,
                    >>()
                    .map(|a| web::Data::new(a.session_config.clone()))
                }
                #[cfg(not(feature = "token"))]
                {
                    None
                }
            });

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
        let token_manager = req
            .app_data::<web::Data<Arc<TokenManager>>>()
            .cloned()
            .or_else(|| {
                req.app_data::<web::Data<AuthEngine<Missing, Configured<Arc<TokenManager>>>>>()
                    .map(|a| web::Data::new(a.token_manager.get_manager()))
            })
            .or_else(|| {
                #[cfg(feature = "session")]
                {
                    req.app_data::<web::Data<
                        AuthEngine<
                            Configured<Arc<dyn SessionStore>>,
                            Configured<Arc<TokenManager>>,
                        >,
                    >>()
                    .map(|a| web::Data::new(a.token_manager.get_manager()))
                }
                #[cfg(not(feature = "session"))]
                {
                    None
                }
            });

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
