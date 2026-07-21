use actix_web::{web, HttpRequest, HttpResponse, Responder};
use authkestra_engine::TokenManager;
use authkestra_op::{
    client::ClientStore,
    code::AuthorizationCodeStore,
    config::OpConfig,
    handlers::{
        authorize::{handle_authorize, AuthorizeOutcome, AuthorizeRequest},
        discovery::OidcDiscovery,
        jwks::JwksResponse,
        token::{handle_token, TokenRequest},
        userinfo::{handle_userinfo, UserInfoErrorResponse, UserInfoRequest},
    },
};
use std::sync::Arc;

pub async fn actix_jwks_handler(token_manager: web::Data<Arc<TokenManager>>) -> impl Responder {
    tracing::debug!("Handling JWKS request (actix)");
    let resp = JwksResponse::new(token_manager.public_jwk());
    HttpResponse::Ok().json(resp)
}

pub async fn actix_discovery_handler(config: web::Data<OpConfig>) -> impl Responder {
    tracing::debug!("Handling OIDC discovery request (actix)");
    let resp = OidcDiscovery::from_config(config.get_ref());
    HttpResponse::Ok().json(resp)
}

pub async fn actix_authorize_handler(
    clients: web::Data<Arc<dyn ClientStore>>,
    codes: web::Data<Arc<dyn AuthorizationCodeStore>>,
    config: web::Data<OpConfig>,
    auth_session: Option<crate::AuthSession>,
    req: web::Query<AuthorizeRequest>,
) -> actix_web::HttpResponse {
    tracing::debug!(client_id = %req.client_id, "Handling OP authorize request (actix)");
    let identity = match auth_session {
        Some(session) => session.0.identity,
        None => {
            tracing::info!("Unauthenticated user on /authorize, redirecting to /login");
            let login_url = String::from("/login");
            // NOTE: We omit return_to encoding to avoid adding urlencoding dependency for now.
            // login_url.push_str(&format!("?return_to=/authorize?..."));
            return actix_web::HttpResponse::Found()
                .insert_header(("Location", login_url))
                .finish();
        }
    };

    match handle_authorize(
        req.into_inner(),
        identity,
        config.get_ref(),
        clients.get_ref().as_ref(),
        codes.get_ref().as_ref(),
    )
    .await
    {
        AuthorizeOutcome::Redirect(url) => HttpResponse::Found()
            .insert_header(("Location", url))
            .finish(),
        AuthorizeOutcome::DirectError(err) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": err.to_string()
        })),
    }
}

pub async fn actix_token_handler(
    req: web::Form<TokenRequest>,
    clients: web::Data<Arc<dyn ClientStore>>,
    codes: web::Data<Arc<dyn AuthorizationCodeStore>>,
    tokens: web::Data<Arc<TokenManager>>,
    config: web::Data<OpConfig>,
) -> impl Responder {
    tracing::debug!(grant_type = %req.grant_type, "Handling OP token request (actix)");
    let req_with_auth = req.into_inner();

    match handle_token(
        req_with_auth,
        config.get_ref(),
        clients.get_ref().as_ref(),
        codes.get_ref().as_ref(),
        tokens.get_ref().as_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" => actix_web::http::StatusCode::UNAUTHORIZED,
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(err)
        }
    }
}

pub async fn actix_userinfo_handler(
    http_req: HttpRequest,
    config: web::Data<OpConfig>,
    tokens: web::Data<Arc<TokenManager>>,
) -> impl Responder {
    tracing::debug!("Handling OP userinfo request (actix)");
    let auth_header = match http_req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) if h.starts_with("Bearer ") => h,
        _ => {
            return HttpResponse::Unauthorized()
                .insert_header(("WWW-Authenticate", "Bearer"))
                .json(UserInfoErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Missing or invalid Authorization header".to_string(),
                });
        }
    };

    let req = UserInfoRequest {
        access_token: auth_header[7..].to_string(),
    };

    match handle_userinfo(req, config.get_ref(), tokens.get_ref().as_ref()).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_token" => actix_web::http::StatusCode::UNAUTHORIZED,
                "insufficient_scope" => actix_web::http::StatusCode::FORBIDDEN,
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(err)
        }
    }
}

pub trait AuthEngineActixOpExt {
    fn op_actix_scope(&self) -> actix_web::Scope;
}

impl<T> AuthEngineActixOpExt for T {
    fn op_actix_scope(&self) -> actix_web::Scope {
        web::scope("")
            .route("/jwks.json", web::get().to(actix_jwks_handler))
            .route(
                "/.well-known/openid-configuration",
                web::get().to(actix_discovery_handler),
            )
            .route("/authorize", web::get().to(actix_authorize_handler))
            .route("/token", web::post().to(actix_token_handler))
            .route("/userinfo", web::get().to(actix_userinfo_handler))
            .route("/userinfo", web::post().to(actix_userinfo_handler))
    }
}
