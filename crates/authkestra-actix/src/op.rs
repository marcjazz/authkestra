use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use authkestra_engine::token::cert_binding::ClientCertificateDer;
use authkestra_engine::TokenManager;
use authkestra_op::{
    attestation::{
        AttestationConfig, AttestationStatusProvider, EnrolmentChallengeStore, SecondFactorVerifier,
    },
    config::OpConfig,
    handlers::{
        authorize::{handle_authorize, AuthorizeOutcome, AuthorizeRequest},
        device_authorization::{handle_device_authorization, DeviceAuthorizationRequest},
        discovery::OidcDiscovery,
        enrolment::{
            handle_complete_challenge, handle_enrol_start, handle_reissue_start,
            CompleteChallengeRequest, EnrolStartRequest, ReissueStartRequest,
        },
        jwks::JwksResponse,
        token::{handle_token_with_client_cert, TokenRequest},
        userinfo::{handle_userinfo, UserInfoErrorResponse, UserInfoRequest},
    },
    OpError,
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
    op_store: web::Data<Arc<dyn authkestra_op::OpStore>>,
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
        op_store.get_ref().as_ref(),
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

pub async fn actix_device_authorization_handler(
    http_req: HttpRequest,
    req: web::Form<DeviceAuthorizationRequest>,
    op_store: web::Data<Arc<dyn authkestra_op::OpStore>>,
    config: web::Data<OpConfig>,
) -> impl Responder {
    tracing::debug!("Handling OP device authorization request (actix)");

    let auth_header = http_req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match handle_device_authorization(
        req.into_inner(),
        auth_header,
        config.get_ref(),
        op_store.get_ref().as_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" | "unauthorized_client" => {
                    actix_web::http::StatusCode::UNAUTHORIZED
                }
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(err)
        }
    }
}

/// Handler for the token endpoint.
///
/// Certificate binding (RFC 8705, issue #224): this crate does not
/// terminate mTLS itself. `client_cert_der` below is only ever `Some` if a
/// host application's own middleware/acceptor inserted a
/// `ClientCertificateDer` into the actix request's extension map ahead of
/// this handler — see `ClientCertificateDer`'s doc comment.
#[allow(clippy::too_many_arguments)]
pub async fn actix_token_handler(
    http_req: HttpRequest,
    req: web::Form<TokenRequest>,
    op_store: web::Data<Arc<dyn authkestra_op::OpStore>>,
    tokens: web::Data<Arc<TokenManager>>,
    config: web::Data<OpConfig>,
) -> impl Responder {
    tracing::debug!(grant_type = %req.grant_type, "Handling OP token request (actix)");

    let auth_header = http_req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let client_cert_der = http_req
        .extensions()
        .get::<ClientCertificateDer>()
        .map(|c| c.0.clone());

    match handle_token_with_client_cert(
        req.into_inner(),
        auth_header,
        config.get_ref(),
        op_store.get_ref().as_ref(),
        tokens.get_ref().as_ref(),
        client_cert_der.as_deref(),
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
                .json(UserInfoErrorResponse::new("invalid_request".to_string(), "Missing or invalid Authorization header".to_string(),
                ));
        }
    };

    let req = UserInfoRequest::new(auth_header[7..].to_string(),
    );

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

pub async fn actix_device_verify_handler(
    req: web::Form<authkestra_op::handlers::device_verify::DeviceVerifyRequest>,
    op_store: web::Data<Arc<dyn authkestra_op::OpStore>>,
    auth_session: Option<crate::AuthSession>,
) -> actix_web::HttpResponse {
    tracing::debug!("Handling OP device verify request (actix)");
    let identity = match auth_session {
        Some(session) => session.0.identity,
        None => {
            tracing::info!("Unauthenticated user on /device/verify, redirecting to /login");
            let login_url = String::from("/login");
            return actix_web::HttpResponse::Found()
                .insert_header(("Location", login_url))
                .finish();
        }
    };

    match authkestra_op::handlers::device_verify::handle_device_verify(
        req.into_inner(),
        identity,
        op_store.get_ref().as_ref(),
    )
    .await
    {
        Ok(resp) => actix_web::HttpResponse::Ok().json(resp),
        Err(err) => actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": err.to_string()
        })),
    }
}

/// Maps an `OpError` from the attestation ceremony to an HTTP status and an
/// OAuth2-shaped `{error, error_description}` body, matching the style the
/// other OP handlers in this file already use for their own error enums.
fn attestation_error_response(err: OpError) -> HttpResponse {
    let status = match &err {
        OpError::BadJwk(_) | OpError::BadAlg(_) => actix_web::http::StatusCode::BAD_REQUEST,
        OpError::InvalidChallenge
        | OpError::ChallengeSignatureInvalid
        | OpError::AttestationInvalid
        | OpError::KeyNotBound
        | OpError::SecondFactorFailed => actix_web::http::StatusCode::UNAUTHORIZED,
        OpError::PrincipalRevoked => actix_web::http::StatusCode::FORBIDDEN,
        _ => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code = match &err {
        OpError::PrincipalRevoked => "access_denied",
        OpError::BadJwk(_) | OpError::BadAlg(_) => "invalid_request",
        _ if status == actix_web::http::StatusCode::INTERNAL_SERVER_ERROR => "server_error",
        _ => "invalid_grant",
    };
    HttpResponse::build(status).json(serde_json::json!({
        "error": code,
        "error_description": err.to_string(),
    }))
}

/// Handler for beginning device/service enrolment (spec §5.6 steps 1-3).
pub async fn actix_enrol_start_handler(
    req: web::Json<EnrolStartRequest>,
    second_factor: web::Data<Arc<dyn SecondFactorVerifier>>,
    challenges: web::Data<Arc<dyn EnrolmentChallengeStore>>,
    config: web::Data<AttestationConfig>,
) -> impl Responder {
    tracing::debug!(principal_type = ?req.principal_type, "Handling OP enrol start request (actix)");
    match handle_enrol_start(
        req.into_inner(),
        second_factor.get_ref().as_ref(),
        challenges.get_ref().as_ref(),
        config.get_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => attestation_error_response(err),
    }
}

/// Handler for beginning re-issuance of a near-expiry attestation (ADR 0014
/// decision point 6). `AttestationStatusProvider` is optional: an app that
/// has not registered one simply gets `None` here (same `Option<T>`
/// extractor pattern already used for `crate::AuthSession` above), and
/// re-issuance falls back to copying the previous `att` claim forward — see
/// `handle_reissue_start`'s docs.
pub async fn actix_reissue_start_handler(
    req: web::Json<ReissueStartRequest>,
    tokens: web::Data<Arc<TokenManager>>,
    status_provider: Option<web::Data<Arc<dyn AttestationStatusProvider>>>,
    challenges: web::Data<Arc<dyn EnrolmentChallengeStore>>,
    config: web::Data<AttestationConfig>,
) -> impl Responder {
    tracing::debug!("Handling OP re-issuance start request (actix)");
    let status_provider = status_provider.as_ref().map(|d| d.get_ref().as_ref());

    match handle_reissue_start(
        req.into_inner(),
        tokens.get_ref().as_ref(),
        status_provider,
        challenges.get_ref().as_ref(),
        config.get_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => attestation_error_response(err),
    }
}

/// Handler completing either an enrolment or a re-issuance ceremony — the
/// same operation either way (see `handle_complete_challenge`'s docs).
pub async fn actix_complete_challenge_handler(
    req: web::Json<CompleteChallengeRequest>,
    challenges: web::Data<Arc<dyn EnrolmentChallengeStore>>,
    tokens: web::Data<Arc<TokenManager>>,
    config: web::Data<AttestationConfig>,
) -> impl Responder {
    tracing::debug!("Handling OP enrolment/re-issuance completion request (actix)");
    match handle_complete_challenge(
        req.into_inner(),
        challenges.get_ref().as_ref(),
        tokens.get_ref().as_ref(),
        config.get_ref(),
    )
    .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(err) => attestation_error_response(err),
    }
}

pub trait OpExt {
    fn op_actix_scope(&self) -> actix_web::Scope;
}

impl<T> OpExt for T {
    fn op_actix_scope(&self) -> actix_web::Scope {
        web::scope("")
            .route("/jwks.json", web::get().to(actix_jwks_handler))
            .route(
                "/.well-known/openid-configuration",
                web::get().to(actix_discovery_handler),
            )
            .route("/authorize", web::get().to(actix_authorize_handler))
            .route(
                "/device_authorization",
                web::post().to(actix_device_authorization_handler),
            )
            .route("/token", web::post().to(actix_token_handler))
            .route("/userinfo", web::get().to(actix_userinfo_handler))
            .route("/userinfo", web::post().to(actix_userinfo_handler))
            .route(
                "/device/verify",
                web::post().to(actix_device_verify_handler),
            )
            .route("/enrol", web::post().to(actix_enrol_start_handler))
            .route(
                "/enrol/complete",
                web::post().to(actix_complete_challenge_handler),
            )
            .route("/reissue", web::post().to(actix_reissue_start_handler))
    }
}

use authkestra_engine::{Configured, Engine};
type CompleteOp = authkestra_op::Op<
    Engine<Configured<Arc<dyn crate::SessionStore>>, Configured<Arc<TokenManager>>>,
    Arc<dyn authkestra_op::OpStore>,
>;

pub trait OpActixExt {
    fn configure_op(self, op: CompleteOp) -> Self;
}

impl OpActixExt for &mut web::ServiceConfig {
    fn configure_op(self, op: CompleteOp) -> Self {
        self.app_data(web::Data::new(op.store.clone()))
            .app_data(web::Data::new(op.engine.token_manager.0.clone()))
            .app_data(web::Data::new(op.engine.session_store.0.clone()))
            .app_data(web::Data::new(op.engine.session_config.clone()))
            .app_data(web::Data::new(op.config.clone()));

        if let Some(cfg) = op.attestation_config {
            self.app_data(web::Data::new(cfg));
        }
        if let Some(store) = op.challenge_store {
            self.app_data(web::Data::new(store));
        }
        if let Some(verifier) = op.second_factor_verifier {
            self.app_data(web::Data::new(verifier));
        }
        if let Some(provider) = op.status_provider {
            self.app_data(web::Data::new(provider));
        }
        self
    }
}
