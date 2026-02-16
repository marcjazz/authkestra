#[cfg(any(feature = "session", feature = "token", feature = "guard"))]
use actix_web::{dev::Payload, http::header, web, Error, FromRequest, HttpRequest};
#[cfg(all(feature = "flow", feature = "session"))]
pub use authkestra_flow::SessionStoreState;
#[cfg(all(feature = "flow", feature = "token"))]
pub use authkestra_flow::TokenManagerState;
#[cfg(feature = "flow")]
pub use authkestra_flow::{Authkestra, SessionConfig};
#[cfg(all(feature = "flow", any(feature = "session", feature = "token")))]
pub use authkestra_flow::{Configured, Missing};
#[cfg(feature = "session")]
pub use authkestra_session::{Session, SessionStore};
#[cfg(feature = "token")]
pub use authkestra_token::TokenManager;
#[cfg(any(feature = "session", feature = "token", feature = "guard"))]
use futures::future::LocalBoxFuture;
#[cfg(any(feature = "session", feature = "token", feature = "guard"))]
use std::sync::Arc;

pub mod helpers;
pub use helpers::*;

#[cfg(feature = "flow")]
pub trait AuthkestraActixExt<S, T> {
    fn actix_scope(&self) -> actix_web::Scope;
}

#[cfg(feature = "flow")]
#[cfg(all(feature = "flow", feature = "session"))]
impl<S, T> AuthkestraActixExt<S, T> for Authkestra<S, T>
where
    S: Clone + SessionStoreState + 'static,
    T: Clone + 'static,
{
    fn actix_scope(&self) -> actix_web::Scope {
        let mut scope = web::scope("/auth");

        scope = scope.route("/{provider}", web::get().to(actix_login_handler::<S, T>));
        scope = scope.route(
            "/{provider}/callback",
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
                req.app_data::<web::Data<Authkestra<Configured<Arc<dyn SessionStore>>, Missing>>>()
                    .and_then(|a| {
                        #[cfg(feature = "session")]
                        {
                            Some(web::Data::new(a.session_store.get_store()))
                        }
                        #[cfg(not(feature = "session"))]
                        {
                            let _ = a;
                            None
                        }
                    })
            })
            .or_else(|| {
                #[cfg(feature = "token")]
                {
                    req.app_data::<web::Data<
                        Authkestra<
                            Configured<Arc<dyn SessionStore>>,
                            Configured<Arc<TokenManager>>,
                        >,
                    >>()
                    .and_then(|a| {
                        #[cfg(feature = "session")]
                        {
                            Some(web::Data::new(a.session_store.get_store()))
                        }
                        #[cfg(not(feature = "session"))]
                        {
                            let _ = a;
                            None
                        }
                    })
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
                    Authkestra<authkestra_flow::Configured<Arc<dyn SessionStore>>, Missing>,
                >>()
                .map(|a| web::Data::new(a.session_config.clone()))
            })
            .or_else(|| {
                #[cfg(feature = "token")]
                {
                    req.app_data::<web::Data<
                        Authkestra<
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
#[cfg(feature = "token")]
pub struct AuthToken(pub authkestra_token::Claims);

#[cfg(all(feature = "flow", feature = "token"))]
impl FromRequest for AuthToken {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token_manager = req
            .app_data::<web::Data<Arc<TokenManager>>>()
            .cloned()
            .or_else(|| {
                req.app_data::<web::Data<Authkestra<Missing, Configured<Arc<TokenManager>>>>>()
                    .and_then(|a| {
                        #[cfg(feature = "token")]
                        {
                            Some(web::Data::new(a.token_manager.get_manager()))
                        }
                        #[cfg(not(feature = "token"))]
                        {
                            let _ = a;
                            None
                        }
                    })
            })
            .or_else(|| {
                #[cfg(feature = "session")]
                {
                    req.app_data::<web::Data<
                        Authkestra<
                            Configured<Arc<dyn SessionStore>>,
                            Configured<Arc<TokenManager>>,
                        >,
                    >>()
                    .and_then(|a| {
                        #[cfg(feature = "token")]
                        {
                            Some(web::Data::new(a.token_manager.get_manager()))
                        }
                        #[cfg(not(feature = "token"))]
                        {
                            let _ = a;
                            None
                        }
                    })
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
            let token_manager = token_manager.ok_or_else(|| {
                actix_web::error::ErrorInternalServerError("Token manager not configured")
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

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `jsonwebtoken::Validation`.
#[cfg(feature = "guard")]
pub struct Jwt<T>(pub T);

#[cfg(feature = "guard")]
impl<T> FromRequest for Jwt<T>
where
    T: for<'de> serde::Deserialize<'de> + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let cache = req
            .app_data::<web::Data<Arc<authkestra_guard::jwt::JwksCache>>>()
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
            let cache = cache.ok_or_else(|| {
                actix_web::error::ErrorInternalServerError("JwksCache not configured")
            })?;
            let validation = validation.ok_or_else(|| {
                actix_web::error::ErrorInternalServerError(
                    "jsonwebtoken::Validation not configured",
                )
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
            let claims =
                authkestra_guard::jwt::validate_jwt_generic::<T>(token, &cache, &validation)
                    .await
                    .map_err(|e| {
                        actix_web::error::ErrorUnauthorized(format!("Invalid token: {}", e))
                    })?;

            Ok(Jwt(claims))
        })
    }
}
