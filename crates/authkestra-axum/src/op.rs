use crate::AxumError;
use authkestra_engine::token::cert_binding::ClientCertificateDer;
use authkestra_engine::TokenManager;
use authkestra_op::{
    attestation::{
        AttestationConfig, AttestationStatusProvider, EnrolmentChallengeStore, SecondFactorVerifier,
    },
    config::OpConfig,
    handlers::{
        authorize::handle_authorize,
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
use axum::{
    extract::{Extension, Form, FromRef, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use std::sync::Arc;

/// Handler for the JWKS endpoint.
pub async fn axum_jwks_handler<AppState>(State(state): State<AppState>) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
{
    let token_manager = match <Result<Arc<TokenManager>, AxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    tracing::debug!("Handling JWKS request");
    (
        StatusCode::OK,
        Json(JwksResponse::new(token_manager.public_jwk())),
    )
        .into_response()
}

/// Handler for the OIDC discovery endpoint.
pub async fn axum_discovery_handler<AppState>(State(state): State<AppState>) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OIDC discovery request");
    let config = OpConfig::from_ref(&state);
    (StatusCode::OK, Json(OidcDiscovery::from_config(&config))).into_response()
}

/// Handler for the authorization endpoint.
/// Note: This is an initial implementation that directly calls `handle_authorize`.
/// In a real scenario, we might also need to extract the logged-in user from the session
/// and handle the consent screen redirect if identity is None.
pub async fn axum_authorize_handler<AppState>(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Query(req): Query<authkestra_op::handlers::authorize::AuthorizeRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn authkestra_op::OpStore>, AxumError>: FromRef<AppState>,
    Result<Arc<dyn crate::SessionStore>, AxumError>: FromRef<AppState>,
    authkestra_engine::SessionConfig: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!(client_id = %req.client_id, "Handling OP authorize request (axum)");
    let op_store = match <Result<Arc<dyn authkestra_op::OpStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let config = OpConfig::from_ref(&state);

    let session_store = match <Result<Arc<dyn crate::SessionStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let session_config = authkestra_engine::SessionConfig::from_ref(&state);

    let session_res = crate::helpers::get_session(&session_store, &session_config, &cookies).await;

    let identity = match session_res {
        Ok(s) => s.identity,
        Err(e) => {
            tracing::info!(error = ?e, "Unauthenticated user on /authorize, redirecting to /login");
            return Redirect::to("/login").into_response();
        }
    };

    match handle_authorize(req, identity, &config, op_store.as_ref()).await {
        authkestra_op::handlers::authorize::AuthorizeOutcome::Redirect(url) => {
            Redirect::to(&url).into_response()
        }
        authkestra_op::handlers::authorize::AuthorizeOutcome::DirectError(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": err.to_string()
            })),
        )
            .into_response(),
    }
}

/// Handler for the device authorization endpoint.
pub async fn axum_device_authorization_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn authkestra_op::OpStore>, AxumError>: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP device authorization request (axum)");
    let op_store = match <Result<Arc<dyn authkestra_op::OpStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let config = OpConfig::from_ref(&state);

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match handle_device_authorization(req, auth_header, &config, op_store.as_ref()).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" | "unauthorized_client" => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(err)).into_response()
        }
    }
}

/// Handler for the token endpoint.
///
/// `cert` is an RFC 8705 (§224) hook, not a TLS implementation: this crate
/// does not terminate mTLS itself, so `cert` is only ever `Some` if a host
/// application's own middleware/acceptor inserted a `ClientCertificateDer`
/// request extension ahead of this handler (e.g. an `axum-server` rustls
/// acceptor configured to require and expose client certificates, or a
/// trusted reverse-proxy header the host has already validated and decoded
/// to DER). See `ClientCertificateDer`'s doc comment.
pub async fn axum_token_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
    cert: Option<Extension<ClientCertificateDer>>,
    Form(req): Form<TokenRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn authkestra_op::OpStore>, AxumError>: FromRef<AppState>,
    Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!(grant_type = %req.grant_type, "Handling OP token request (axum)");
    let op_store = match <Result<Arc<dyn authkestra_op::OpStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let tokens = match <Result<Arc<TokenManager>, AxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let config = OpConfig::from_ref(&state);

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let client_cert_der = cert.map(|Extension(ClientCertificateDer(der))| der);

    // RFC 9449 — an ordinary header, unlike the mTLS certificate above:
    // `headers` already gives access to the whole map, no host-supplied
    // `Extension` plumbing needed.
    let dpop_header = headers.get("DPoP").and_then(|h| h.to_str().ok());

    match handle_token_with_client_cert(
        req,
        auth_header,
        &config,
        op_store.as_ref(),
        tokens.as_ref(),
        client_cert_der.as_deref(),
        dpop_header,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(err)).into_response()
        }
    }
}

/// Handler for the userinfo endpoint.
pub async fn axum_userinfo_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP userinfo request (axum)");
    let tokens = match <Result<Arc<TokenManager>, AxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let auth_header = match headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) if h.starts_with("Bearer ") => h,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer")],
                Json(UserInfoErrorResponse::new(
                    "invalid_request".to_string(),
                    "Missing or invalid Authorization header".to_string(),
                )),
            )
                .into_response();
        }
    };

    let req = UserInfoRequest::new(auth_header[7..].to_string());

    let config = OpConfig::from_ref(&state);

    match handle_userinfo(req, &config, tokens.as_ref()).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_token" => StatusCode::UNAUTHORIZED,
                "insufficient_scope" => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(err)).into_response()
        }
    }
}

/// Handler for the device verify endpoint.
pub async fn axum_device_verify_handler<AppState>(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Form(req): Form<authkestra_op::handlers::device_verify::DeviceVerifyRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn authkestra_op::OpStore>, AxumError>: FromRef<AppState>,
    Result<Arc<dyn crate::SessionStore>, AxumError>: FromRef<AppState>,
    authkestra_engine::SessionConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP device verify request (axum)");
    let op_store = match <Result<Arc<dyn authkestra_op::OpStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let session_store = match <Result<Arc<dyn crate::SessionStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let session_config = authkestra_engine::SessionConfig::from_ref(&state);

    let session_res = crate::helpers::get_session(&session_store, &session_config, &cookies).await;

    let identity = match session_res {
        Ok(s) => s.identity,
        Err(e) => {
            tracing::info!(error = ?e, "Unauthenticated user on /device/verify, redirecting to /login");
            return Redirect::to("/login").into_response();
        }
    };

    match authkestra_op::handlers::device_verify::handle_device_verify(
        req,
        identity,
        op_store.as_ref(),
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": err.to_string()
            })),
        )
            .into_response(),
    }
}

/// Maps an `OpError` from the attestation ceremony to an HTTP status and an
/// OAuth2-shaped `{error, error_description}` body, matching the style the
/// other OP handlers in this file already use for their own error enums.
fn attestation_error_response(err: OpError) -> Response {
    let status = match &err {
        OpError::BadJwk(_) | OpError::BadAlg(_) => StatusCode::BAD_REQUEST,
        OpError::InvalidChallenge
        | OpError::ChallengeSignatureInvalid
        | OpError::AttestationInvalid
        | OpError::KeyNotBound
        | OpError::SecondFactorFailed => StatusCode::UNAUTHORIZED,
        OpError::PrincipalRevoked => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code = match &err {
        OpError::PrincipalRevoked => "access_denied",
        OpError::BadJwk(_) | OpError::BadAlg(_) => "invalid_request",
        _ if status == StatusCode::INTERNAL_SERVER_ERROR => "server_error",
        _ => "invalid_grant",
    };
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": err.to_string(),
        })),
    )
        .into_response()
}

/// Handler for beginning device/service enrolment (spec §5.6 steps 1-3).
pub async fn axum_enrol_start_handler<AppState>(
    State(state): State<AppState>,
    Json(req): Json<EnrolStartRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn EnrolmentChallengeStore>, AxumError>: FromRef<AppState>,
    Result<Arc<dyn SecondFactorVerifier>, AxumError>: FromRef<AppState>,
    AttestationConfig: FromRef<AppState>,
{
    tracing::debug!(principal_type = ?req.principal_type, "Handling OP enrol start request (axum)");
    let challenges = match <Result<Arc<dyn EnrolmentChallengeStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let second_factor = match <Result<Arc<dyn SecondFactorVerifier>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let config = AttestationConfig::from_ref(&state);

    match handle_enrol_start(req, second_factor.as_ref(), challenges.as_ref(), &config).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => attestation_error_response(err),
    }
}

/// Handler for beginning re-issuance of a near-expiry attestation (ADR 0014
/// decision point 6). `AttestationStatusProvider` is optional at the type
/// level — a host application that has not configured one gets `None` from
/// `FromRef`, and re-issuance falls back to copying the previous `att`
/// claim forward (see `handle_reissue_start`'s docs).
pub async fn axum_reissue_start_handler<AppState>(
    State(state): State<AppState>,
    Json(req): Json<ReissueStartRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
    Option<Arc<dyn AttestationStatusProvider>>: FromRef<AppState>,
    Result<Arc<dyn EnrolmentChallengeStore>, AxumError>: FromRef<AppState>,
    AttestationConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP re-issuance start request (axum)");
    let tokens = match <Result<Arc<TokenManager>, AxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let status_provider = Option::<Arc<dyn AttestationStatusProvider>>::from_ref(&state);
    let challenges = match <Result<Arc<dyn EnrolmentChallengeStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let config = AttestationConfig::from_ref(&state);

    match handle_reissue_start(
        req,
        tokens.as_ref(),
        status_provider.as_deref(),
        challenges.as_ref(),
        &config,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => attestation_error_response(err),
    }
}

/// Handler completing either an enrolment or a re-issuance ceremony — the
/// same operation either way (see `handle_complete_challenge`'s docs).
pub async fn axum_complete_challenge_handler<AppState>(
    State(state): State<AppState>,
    Json(req): Json<CompleteChallengeRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn EnrolmentChallengeStore>, AxumError>: FromRef<AppState>,
    Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
    AttestationConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP enrolment/re-issuance completion request (axum)");
    let challenges = match <Result<Arc<dyn EnrolmentChallengeStore>, AxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let tokens = match <Result<Arc<TokenManager>, AxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let config = AttestationConfig::from_ref(&state);

    match handle_complete_challenge(req, challenges.as_ref(), tokens.as_ref(), &config).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => attestation_error_response(err),
    }
}

pub trait OpExt {
    fn op_axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Result<Arc<dyn authkestra_op::OpStore>, AxumError>: FromRef<AppState>,
        Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
        Result<Arc<dyn crate::SessionStore>, AxumError>: FromRef<AppState>,
        authkestra_engine::SessionConfig: FromRef<AppState>,
        OpConfig: FromRef<AppState>;

    /// Routes for the device/service attestation ceremony (`/enrol`,
    /// `/enrol/complete`, `/reissue` — spec §5.6/§5.6.1), split out from
    /// [`op_axum_router`](OpExt::op_axum_router) rather than folded into it.
    ///
    /// `AttestationConfig` is deliberately kept separate from `OpConfig`
    /// (see that type's doc comment) so this extension does not force every
    /// existing `op_axum_router()` call site to also grow
    /// `EnrolmentChallengeStore`/`SecondFactorVerifier`/
    /// `AttestationStatusProvider`/`AttestationConfig` just to keep
    /// compiling — an application that only wants the standard OIDC surface
    /// merges `op_axum_router()` alone; one that also wants device/service
    /// attestation merges this router too:
    ///
    /// ```rust,ignore
    /// let app = Router::new()
    ///     .merge(state.op_axum_router())
    ///     .merge(state.op_axum_attestation_router())
    ///     .with_state(state);
    /// ```
    fn op_axum_attestation_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Result<Arc<dyn EnrolmentChallengeStore>, AxumError>: FromRef<AppState>,
        Result<Arc<dyn SecondFactorVerifier>, AxumError>: FromRef<AppState>,
        Option<Arc<dyn AttestationStatusProvider>>: FromRef<AppState>,
        Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
        AttestationConfig: FromRef<AppState>;
}

// Implement for any type to allow standalone usage or usage with Engine.
impl<T> OpExt for T {
    fn op_axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Result<Arc<dyn authkestra_op::OpStore>, AxumError>: FromRef<AppState>,
        Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
        Result<Arc<dyn crate::SessionStore>, AxumError>: FromRef<AppState>,
        authkestra_engine::SessionConfig: FromRef<AppState>,
        OpConfig: FromRef<AppState>,
    {
        use axum::routing::{get, post};
        axum::Router::new()
            .route("/jwks.json", get(axum_jwks_handler::<AppState>))
            .route(
                "/.well-known/openid-configuration",
                get(axum_discovery_handler::<AppState>),
            )
            .route("/authorize", get(axum_authorize_handler::<AppState>))
            .route(
                "/device_authorization",
                post(axum_device_authorization_handler::<AppState>),
            )
            .route("/token", post(axum_token_handler::<AppState>))
            .route(
                "/userinfo",
                get(axum_userinfo_handler::<AppState>).post(axum_userinfo_handler::<AppState>),
            )
            .route(
                "/device/verify",
                post(axum_device_verify_handler::<AppState>),
            )
    }

    fn op_axum_attestation_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Result<Arc<dyn EnrolmentChallengeStore>, AxumError>: FromRef<AppState>,
        Result<Arc<dyn SecondFactorVerifier>, AxumError>: FromRef<AppState>,
        Option<Arc<dyn AttestationStatusProvider>>: FromRef<AppState>,
        Result<Arc<TokenManager>, AxumError>: FromRef<AppState>,
        AttestationConfig: FromRef<AppState>,
    {
        use axum::routing::post;
        axum::Router::new()
            .route("/enrol", post(axum_enrol_start_handler::<AppState>))
            .route(
                "/enrol/complete",
                post(axum_complete_challenge_handler::<AppState>),
            )
            .route("/reissue", post(axum_reissue_start_handler::<AppState>))
    }
}

use authkestra_engine::{Configured, Engine};
pub type CompleteOp = authkestra_op::Op<
    Engine<Configured<Arc<dyn crate::SessionStore>>, Configured<Arc<TokenManager>>>,
    Arc<dyn authkestra_op::OpStore>,
>;

/// A newtype wrapper around `CompleteOp` to implement `axum::extract::FromRef` and bypass orphan rules.
#[derive(Clone)]
pub struct OpState(pub CompleteOp);

impl FromRef<OpState> for Result<Arc<dyn authkestra_op::OpStore>, AxumError> {
    fn from_ref(state: &OpState) -> Self {
        Ok(state.0.store.clone())
    }
}

impl FromRef<OpState> for Result<Arc<TokenManager>, AxumError> {
    fn from_ref(state: &OpState) -> Self {
        Ok(state.0.engine.token_manager.0.clone())
    }
}

impl FromRef<OpState> for Result<Arc<dyn crate::SessionStore>, AxumError> {
    fn from_ref(state: &OpState) -> Self {
        Ok(state.0.engine.session_store.0.clone())
    }
}

impl FromRef<OpState> for authkestra_engine::SessionConfig {
    fn from_ref(state: &OpState) -> Self {
        state.0.engine.session_config.clone()
    }
}

impl FromRef<OpState> for OpConfig {
    fn from_ref(state: &OpState) -> Self {
        state.0.config.clone()
    }
}

impl FromRef<OpState> for AttestationConfig {
    fn from_ref(state: &OpState) -> Self {
        state
            .0
            .attestation_config
            .clone()
            .expect("AttestationConfig must be provided for attestation routes")
    }
}

impl FromRef<OpState> for Result<Arc<dyn EnrolmentChallengeStore>, AxumError> {
    fn from_ref(state: &OpState) -> Self {
        state
            .0
            .challenge_store
            .clone()
            .ok_or_else(|| AxumError::Internal("EnrolmentChallengeStore missing".to_string()))
    }
}

impl FromRef<OpState> for Result<Arc<dyn SecondFactorVerifier>, AxumError> {
    fn from_ref(state: &OpState) -> Self {
        state
            .0
            .second_factor_verifier
            .clone()
            .ok_or_else(|| AxumError::Internal("SecondFactorVerifier missing".to_string()))
    }
}

impl FromRef<OpState> for Option<Arc<dyn AttestationStatusProvider>> {
    fn from_ref(state: &OpState) -> Self {
        state.0.status_provider.clone()
    }
}
